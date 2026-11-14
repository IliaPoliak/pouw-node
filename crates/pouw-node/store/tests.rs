//! The contract tests of the store. `contract.rs` holds them once and they run on every
//! backend that is built in: the module of a backend defines `new_store` and the two
//! helpers that reach into its tables, then includes the file. What only one backend
//! can show, such as a restart, is in its module.

#[cfg(feature = "store-mem")]
mod on_memory {
    include!("contract.rs");

    fn new_store() -> crate::store::Store {
        crate::store::memory()
    }

    fn set_index_raw(
        store: &mut crate::store::Store,
        id: pouw_types::BlockId,
        entry: crate::store::schema::IndexEntry,
    ) {
        match store {
            crate::store::Store::Mem(mem) => crate::store::mem::set_index(mem, id, entry),
            #[cfg(feature = "rocksdb")]
            crate::store::Store::Rocks(_) => unreachable!("this is the memory store"),
        }
    }

    fn set_schema_version(store: &mut crate::store::Store, version: u32) {
        match store {
            crate::store::Store::Mem(mem) => mem.meta.schema_version = version,
            #[cfg(feature = "rocksdb")]
            crate::store::Store::Rocks(_) => unreachable!("this is the memory store"),
        }
    }

    #[test]
    fn the_memory_kind_opens_an_empty_store() {
        let store = store::open(
            crate::config::StoreKind::Memory,
            std::path::Path::new("unused"),
        )
        .unwrap();
        assert_eq!(store::tip(&store::read(&store).unwrap()).unwrap(), None);
    }
}

#[cfg(feature = "rocksdb")]
mod on_rocksdb {
    include!("contract.rs");

    use crate::config::StoreKind;

    /// A directory that does not exist yet, unique to this test run.
    fn temp_dir(name: &str) -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("pouw-store-{}-{name}-{n}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        dir
    }

    fn new_store() -> Store {
        store::open(StoreKind::Rocksdb, &temp_dir("contract")).unwrap()
    }

    fn set_index_raw(store: &mut Store, id: BlockId, entry: IndexEntry) {
        match store {
            Store::Rocks(db) => crate::store::rocks::set_index(db, id, entry).unwrap(),
            #[cfg(feature = "store-mem")]
            Store::Mem(_) => unreachable!("this is the RocksDB store"),
        }
    }

    fn set_schema_version(store: &mut Store, version: u32) {
        match store {
            Store::Rocks(db) => crate::store::rocks::set_schema_version(db, version).unwrap(),
            #[cfg(feature = "store-mem")]
            Store::Mem(_) => unreachable!("this is the RocksDB store"),
        }
    }

    fn open(dir: &std::path::Path) -> Store {
        store::open(StoreKind::Rocksdb, dir).unwrap()
    }

    #[test]
    fn the_rocksdb_kind_creates_the_directory_and_opens_an_empty_store() {
        let dir = temp_dir("fresh").join("nested").join("db");
        let store = open(&dir);
        assert_eq!(store::tip(&store::read(&store).unwrap()).unwrap(), None);
        assert!(dir.is_dir());
    }

    #[test]
    fn a_reopened_store_continues_from_the_last_block() {
        let dir = temp_dir("restart");
        let mut store = open(&dir);
        let genesis_id = connect_genesis(&mut store);
        let first = block(1, genesis_id, MINER, vec![transfer(1)]);
        put(&mut store, &first);
        let diff = credit(&store, MINER, 10);
        let tip = connect(&mut store, &first, &diff).unwrap();
        let miner_balance = balance(&store, &MINER);
        drop(store);

        let mut store = open(&dir);
        {
            let reader = store::read(&store).unwrap();
            assert_eq!(store::tip(&reader).unwrap(), Some(tip));
            assert_eq!(
                store::canonical_id(&reader, Height(0)).unwrap(),
                Some(genesis_id)
            );
            assert_eq!(
                store::canonical_id(&reader, Height(1)).unwrap(),
                Some(tip.id)
            );
            assert_eq!(
                store::header(&reader, &tip.id).unwrap(),
                Some(&first.header)
            );
            let stored = store::block(&reader, &tip.id).unwrap().unwrap();
            assert_eq!(store::decode(&stored).unwrap(), first);
            let location = store::tx_location(&reader, &txid(&transfer(1)))
                .unwrap()
                .unwrap();
            assert_eq!(location.block, tip.id);
            assert_eq!(location.height, Height(1));
        }
        assert_eq!(balance(&store, &MINER), miner_balance);

        let second = block(2, tip.id, MINER, vec![transfer(2)]);
        put(&mut store, &second);
        let diff = credit(&store, MINER, 10);
        let next = connect(&mut store, &second, &diff).unwrap();
        assert_eq!(next.height, Height(2));
    }

    #[test]
    fn a_block_disconnected_after_a_restart_restores_the_state() {
        let dir = temp_dir("undo");
        let mut store = open(&dir);
        let genesis_id = connect_genesis(&mut store);
        let first = block(1, genesis_id, MINER, vec![transfer(1)]);
        put(&mut store, &first);
        let diff = credit(&store, MINER, 10);
        connect(&mut store, &first, &diff).unwrap();
        let after_genesis = Amount(100);
        assert_eq!(balance(&store, &MINER), Some(Amount(110)));
        drop(store);

        let mut store = open(&dir);
        let parent = disconnect(&mut store, &first).unwrap();
        assert_eq!(parent.id, genesis_id);
        assert_eq!(balance(&store, &MINER), Some(after_genesis));
        drop(store);

        let store = open(&dir);
        let reader = store::read(&store).unwrap();
        assert_eq!(store::tip(&reader).unwrap().unwrap().id, genesis_id);
        assert_eq!(store::canonical_id(&reader, Height(1)).unwrap(), None);
        assert_eq!(
            store::tx_location(&reader, &txid(&transfer(1))).unwrap(),
            None
        );
        assert_eq!(balance_of(&reader), Some(after_genesis));
    }

    #[test]
    fn the_circuit_registry_survives_a_restart() {
        let dir = temp_dir("circuits");
        let mut store = open(&dir);
        let genesis_id = connect_genesis(&mut store);
        let entry = pouw_types::CircuitEntry {
            id: pouw_types::CircuitId(TxId(Hash32([7; 32]))),
            system: pouw_types::ProofSystem::Groth16,
            constraint_count: pouw_types::ConstraintCount(5),
            owner: MINER,
            registered_at: Height(1),
            verifying_key: Box::from([1, 2, 3]),
            circuit: Box::from([4, 5, 6]),
        };
        let diff = {
            let reader = store::read(&store).unwrap();
            let mut overlay = ChainState {
                base: &reader,
                diff: StateDiff::default(),
            };
            state::set_circuit(&mut overlay, entry.clone()).unwrap();
            overlay.diff
        };
        let first = block(1, genesis_id, MINER, vec![transfer(1)]);
        put(&mut store, &first);
        connect(&mut store, &first, &diff).unwrap();
        assert_eq!(
            store::read(&store).unwrap().circuit(&entry.id).unwrap(),
            Some(&entry)
        );
        drop(store);

        let mut store = open(&dir);
        assert_eq!(
            store::read(&store).unwrap().circuit(&entry.id).unwrap(),
            Some(&entry)
        );
        disconnect(&mut store, &first).unwrap();
        assert_eq!(
            store::read(&store).unwrap().circuit(&entry.id).unwrap(),
            None
        );
        drop(store);

        let store = open(&dir);
        assert_eq!(
            store::read(&store).unwrap().circuit(&entry.id).unwrap(),
            None
        );
    }

    #[test]
    fn headers_and_failed_marks_survive_a_restart() {
        let dir = temp_dir("headers");
        let mut store = open(&dir);
        let genesis_id = connect_genesis(&mut store);
        let side = block(1, genesis_id, MINER, vec![transfer(1)]);
        let side_id = put(&mut store, &side);
        store::mark_failed(&mut store, &side_id).unwrap();
        drop(store);

        let store = open(&dir);
        let reader = store::read(&store).unwrap();
        assert_eq!(
            store::header(&reader, &side_id).unwrap(),
            Some(&side.header)
        );
        assert!(entry(&store, &side_id).status.contains(Status::FAILED));
        assert!(entry(&store, &side_id).status.contains(Status::BODY_STORED));
    }

    #[test]
    fn a_store_of_another_schema_version_is_refused_after_a_reopen() {
        let dir = temp_dir("schema");
        let mut store = open(&dir);
        set_schema_version(&mut store, SCHEMA_VERSION.wrapping_add(1));
        drop(store);
        let error = store::open(StoreKind::Rocksdb, &dir).unwrap_err();
        assert!(matches!(error, StoreError::SchemaMismatch { .. }));
    }
}
