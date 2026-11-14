use pouw_consensus::{ChainState, StateDiff, StateView, state};
use pouw_crypto::{Address, Hash32, SigningKey};
use pouw_types::{
    Amount, Block, BlockHeader, BlockId, ChainId, CumWork, Height, Nonce, SignedTx, Target, TxBody,
    TxId, TxKind, U32, U64, U256, block_id, sign_body, txid,
};

use zerocopy::IntoBytes;

use crate::{
    store::{
        self, Store, StoreError,
        schema::{IndexEntry, SCHEMA_VERSION, Status},
    },
};

const MINER: Address = Address([9; 32]);

fn transfer(nonce: u64) -> SignedTx {
    let key = SigningKey::from_seed([1; 32]);
    sign_body(
        &TxBody {
            chain_id: ChainId(1),
            sender: key.address(),
            nonce: Nonce(nonce),
            fee: Amount(1),
            kind: TxKind::Transfer {
                to: Address([2; 32]),
                amount: Amount(3),
            },
        },
        &key,
    )
}

/// Target 2^255 - 1, the block work of which is 2.
const WORK_TWO: Target = Target([
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
]);

fn block(height: u64, parent: BlockId, miner: Address, txs: Vec<SignedTx>) -> Block {
    let mut block = Block {
        header: BlockHeader {
            version: U32::new(1),
            chain_id: U32::new(1),
            system_id: U64::new(0),
            height: U64::new(height),
            parent,
            timestamp: U64::new(height),
            miner,
            tx_root: Hash32::ZERO,
            target: WORK_TWO,
            nonce: U64::new(0),
        },
        txs,
        proof_txs: vec![],
    };
    block.header.tx_root = block.compute_tx_root();
    block
}

fn ids(block: &Block) -> Vec<TxId> {
    let mut txids = Vec::new();
    block.txids_into(&mut txids);
    txids
}

fn put(store: &mut Store, block: &Block) -> BlockId {
    let id = block_id(&block.header);
    store::put_header(store, &id, &block.header).unwrap();
    store::put_body(store, &id, &borsh::to_vec(block).unwrap()).unwrap();
    id
}

fn entry(store: &Store, id: &BlockId) -> IndexEntry {
    store::index(&store::read(store).unwrap(), id)
        .unwrap()
        .unwrap()
}

fn connect(
    store: &mut Store,
    block: &Block,
    diff: &StateDiff,
) -> Result<pouw_consensus::ChainTip, StoreError> {
    store::connect_block(store, &block_id(&block.header), &ids(block), diff)
}

fn disconnect(store: &mut Store, block: &Block) -> Result<pouw_consensus::ChainTip, StoreError> {
    store::disconnect_tip(store, &ids(block))
}

fn credit(store: &Store, address: Address, amount: u64) -> StateDiff {
    let reader = store::read(store).unwrap();
    let mut overlay = ChainState {
        base: &reader,
        diff: StateDiff::default(),
    };
    let mut account = overlay.account(&address).unwrap().unwrap_or_default();
    account.balance = Amount(account.balance.0.checked_add(amount).unwrap());
    state::set_account(&mut overlay, address, account).unwrap();
    overlay.diff
}

fn balance(store: &Store, address: &Address) -> Option<Amount> {
    let reader = store::read(store).unwrap();
    reader.account(address).unwrap().map(|a| a.balance)
}

fn connect_genesis(store: &mut Store) -> BlockId {
    let genesis = block(0, BlockId::ZERO, MINER, vec![]);
    let id = put(store, &genesis);
    let diff = credit(store, MINER, 100);
    connect(store, &genesis, &diff).unwrap();
    id
}

#[test]
fn three_blocks_connected_and_disconnected_restore_the_state() {
    let mut store = new_store();
    let genesis_id = connect_genesis(&mut store);
    let genesis_tip = store::tip(&store::read(&store).unwrap()).unwrap();
    let genesis_balance = balance(&store, &MINER);

    let mut prev = genesis_id;
    let mut blocks = Vec::new();
    for height in 1..=3 {
        let next = block(height, prev, MINER, vec![transfer(height)]);
        put(&mut store, &next);
        let diff = credit(&store, MINER, 10);
        let tip = connect(&mut store, &next, &diff).unwrap();
        blocks.push(next);
        assert_eq!(tip.height, Height(height));
        assert_eq!(tip.cumulative_work, CumWork(U256::from(2 * (height + 1))));
        prev = tip.id;
    }
    let included = transfer(2);
    {
        let reader = store::read(&store).unwrap();
        assert_eq!(
            store::tx_location(&reader, &txid(&included))
                .unwrap()
                .unwrap()
                .height,
            Height(2)
        );
    }
    assert_eq!(balance(&store, &MINER), Some(Amount(130)));

    for stored in blocks.iter().rev() {
        disconnect(&mut store, stored).unwrap();
    }
    let reader = store::read(&store).unwrap();
    assert_eq!(store::tip(&reader).unwrap(), genesis_tip);
    assert_eq!(balance_of(&reader), genesis_balance);
    assert_eq!(store::tx_location(&reader, &txid(&included)).unwrap(), None);
    assert_eq!(store::canonical_id(&reader, Height(1)).unwrap(), None);
    assert!(store::block(&reader, &prev).unwrap().is_some());
    assert_canonical_contiguous(&store);
    assert!(matches!(
        store::disconnect_tip(&mut store, &[]),
        Err(StoreError::GenesisDisconnect)
    ));
}

/// Heights 0 to the tip each have a connected block, and none lies above.
fn assert_canonical_contiguous(store: &Store) {
    let reader = store::read(store).unwrap();
    let tip = store::tip(&reader).unwrap().unwrap();
    let mut parent = BlockId::ZERO;
    for height in 0..=tip.height.0 {
        let id = store::canonical_id(&reader, Height(height))
            .unwrap()
            .expect("a canonical block at every height up to the tip");
        let stored = store::index(&reader, &id).unwrap().unwrap();
        assert_eq!(stored.height, U64::new(height));
        assert!(stored.status.contains(Status::CONNECTED));
        assert_eq!(store::header(&reader, &id).unwrap().unwrap().parent, parent);
        parent = id;
    }
    assert_eq!(parent, tip.id);
    assert_eq!(
        store::canonical_id(&reader, Height(tip.height.0.saturating_add(1))).unwrap(),
        None
    );
}

fn balance_of(reader: &store::Reader<'_>) -> Option<Amount> {
    reader.account(&MINER).unwrap().map(|a| a.balance)
}

#[test]
fn only_a_child_of_the_tip_connects() {
    let mut store = new_store();
    let genesis_id = connect_genesis(&mut store);
    let first = block(1, genesis_id, MINER, vec![]);
    let first_id = put(&mut store, &first);
    let second = block(2, first_id, MINER, vec![]);
    put(&mut store, &second);
    assert!(matches!(
        connect(&mut store, &second, &StateDiff::default()),
        Err(StoreError::NotChildOfTip { .. })
    ));
    assert!(matches!(
        store::connect_block(&mut store, &BlockId::ZERO, &[], &StateDiff::default()),
        Err(StoreError::UnknownBlock(_))
    ));
}

#[test]
fn the_first_block_must_be_a_genesis_block() {
    let mut store = new_store();
    let genesis = block(0, BlockId::ZERO, MINER, vec![]);
    put(&mut store, &genesis);
    let other = block(0, BlockId::ZERO, Address([4; 32]), vec![]);
    put(&mut store, &other);
    assert!(matches!(
        store::disconnect_tip(&mut store, &[]),
        Err(StoreError::EmptyChain)
    ));
    connect(&mut store, &genesis, &StateDiff::default()).unwrap();
    assert!(matches!(
        connect(&mut store, &other, &StateDiff::default()),
        Err(StoreError::NotChildOfTip { .. })
    ));
}

#[test]
fn a_header_with_an_unknown_parent_is_refused() {
    let mut store = new_store();
    let parent = BlockId(Hash32([5; 32]));
    let orphan = block(1, parent, MINER, vec![]);
    let id = block_id(&orphan.header);
    assert!(matches!(
        store::put_header(&mut store, &id, &orphan.header),
        Err(StoreError::Orphan { parent: found, .. }) if found == parent
    ));
    let reader = store::read(&store).unwrap();
    assert_eq!(store::index(&reader, &id).unwrap(), None);
    assert_eq!(store::header(&reader, &id).unwrap(), None);
}

#[test]
fn a_header_must_be_one_above_its_parent() {
    let mut store = new_store();
    let genesis_id = connect_genesis(&mut store);
    let skipping = block(2, genesis_id, MINER, vec![]);
    let id = block_id(&skipping.header);
    assert!(matches!(
        store::put_header(&mut store, &id, &skipping.header),
        Err(StoreError::HeightMismatch { .. })
    ));
}

#[test]
fn cumulative_work_accumulates_over_the_parent() {
    let mut store = new_store();
    let mut prev = BlockId::ZERO;
    for height in 0..4 {
        let next = block(height, prev, MINER, vec![]);
        prev = put(&mut store, &next);
        let stored = entry(&store, &prev);
        assert_eq!(stored.height, U64::new(height));
        assert_eq!(stored.work(), CumWork(U256::from(2 * (height + 1))));
        assert!(stored.status.contains(Status::HEADER_VALID));
    }
}

#[test]
fn a_body_needs_its_header_first() {
    let mut store = new_store();
    let genesis = block(0, BlockId::ZERO, MINER, vec![]);
    let id = block_id(&genesis.header);
    let bytes = borsh::to_vec(&genesis).unwrap();
    assert!(matches!(
        store::put_body(&mut store, &id, &bytes),
        Err(StoreError::NoHeader(found)) if found == id
    ));
    store::put_header(&mut store, &id, &genesis.header).unwrap();
    let reader = store::read(&store).unwrap();
    assert!(store::header(&reader, &id).unwrap().is_some());
    assert_eq!(store::block(&reader, &id).unwrap(), None);
    assert!(!entry(&store, &id).status.contains(Status::BODY_STORED));
    let other = block(0, BlockId::ZERO, Address([4; 32]), vec![]);
    assert!(matches!(
        store::put_body(&mut store, &id, &borsh::to_vec(&other).unwrap()),
        Err(StoreError::BodyHeaderMismatch(found)) if found == id
    ));
    store::put_body(&mut store, &id, &bytes).unwrap();
    assert!(entry(&store, &id).status.contains(Status::BODY_STORED));
}

#[test]
fn a_header_without_a_body_does_not_connect() {
    let mut store = new_store();
    let genesis = block(0, BlockId::ZERO, MINER, vec![]);
    let id = block_id(&genesis.header);
    store::put_header(&mut store, &id, &genesis.header).unwrap();
    assert!(matches!(
        connect(&mut store, &genesis, &StateDiff::default()),
        Err(StoreError::NoBody(found)) if found == id
    ));
}

#[test]
fn status_follows_connect_and_disconnect() {
    let mut store = new_store();
    let genesis_id = connect_genesis(&mut store);
    let first = block(1, genesis_id, MINER, vec![]);
    let id = put(&mut store, &first);
    store::mark_work_valid(&mut store, &id).unwrap();
    let before = entry(&store, &id).status;
    assert!(before.contains(Status::WORK_VALID));
    assert!(!before.contains(Status::CONNECTED));
    connect(&mut store, &first, &StateDiff::default()).unwrap();
    assert!(entry(&store, &id).status.contains(Status::CONNECTED));
    disconnect(&mut store, &first).unwrap();
    assert_eq!(entry(&store, &id).status, before);
}

#[test]
fn failed_status_reaches_a_child_and_blocks_connecting() {
    let mut store = new_store();
    let genesis_id = connect_genesis(&mut store);
    let first = block(1, genesis_id, MINER, vec![]);
    let first_id = put(&mut store, &first);
    store::mark_failed(&mut store, &first_id).unwrap();
    assert!(entry(&store, &first_id).status.contains(Status::FAILED));
    let child = block(2, first_id, MINER, vec![]);
    let child_id = put(&mut store, &child);
    assert!(entry(&store, &child_id).status.contains(Status::FAILED));
    let grandchild = block(3, child_id, MINER, vec![]);
    let grandchild_id = put(&mut store, &grandchild);
    assert!(
        entry(&store, &grandchild_id)
            .status
            .contains(Status::FAILED)
    );
    assert!(matches!(
        connect(&mut store, &first, &StateDiff::default()),
        Err(StoreError::Failed(found)) if found == first_id
    ));
    assert!(matches!(
        connect(&mut store, &child, &StateDiff::default()),
        Err(StoreError::Failed(found)) if found == child_id
    ));
}

#[test]
fn the_index_entry_has_a_fixed_layout() {
    let entry = IndexEntry::new(
        Height(0x0102),
        CumWork(U256::from(0x0304u64)),
        Status::HEADER_VALID.with(Status::CONNECTED),
    );
    let mut expected = [0u8; 41];
    expected[0] = 0x02;
    expected[1] = 0x01;
    expected[38] = 0x03;
    expected[39] = 0x04;
    expected[40] = 0b0000_1001;
    assert_eq!(entry.as_bytes(), expected);
}

#[test]
fn a_stale_diff_leaves_the_store_unchanged() {
    let mut store = new_store();
    let stale = credit(&store, MINER, 100);
    let genesis_id = connect_genesis(&mut store);
    let next = block(1, genesis_id, MINER, vec![transfer(1)]);
    put(&mut store, &next);
    assert!(matches!(
        connect(&mut store, &next, &stale),
        Err(StoreError::Diff(_))
    ));
    let reader = store::read(&store).unwrap();
    assert_eq!(store::tip(&reader).unwrap().unwrap().id, genesis_id);
    assert_eq!(
        store::tx_location(&reader, &txid(&transfer(1))).unwrap(),
        None
    );
    assert_eq!(store::canonical_id(&reader, Height(1)).unwrap(), None);
    assert_eq!(balance(&store, &MINER), Some(Amount(100)));
}

#[test]
fn a_reorg_switches_the_canonical_branch() {
    let mut store = new_store();
    let genesis_id = connect_genesis(&mut store);
    let other_miner = Address([8; 32]);
    let main = block(1, genesis_id, MINER, vec![transfer(1)]);
    let side = block(1, genesis_id, other_miner, vec![transfer(2)]);
    let main_id = put(&mut store, &main);
    let side_id = put(&mut store, &side);
    let diff = credit(&store, MINER, 10);
    connect(&mut store, &main, &diff).unwrap();

    disconnect(&mut store, &main).unwrap();
    let diff = credit(&store, other_miner, 10);
    let tip = connect(&mut store, &side, &diff).unwrap();

    assert_eq!(tip.id, side_id);
    let reader = store::read(&store).unwrap();
    assert_eq!(
        store::canonical_id(&reader, Height(1)).unwrap(),
        Some(side_id)
    );
    assert_eq!(
        store::tx_location(&reader, &txid(&transfer(1))).unwrap(),
        None
    );
    assert_eq!(
        store::tx_location(&reader, &txid(&transfer(2)))
            .unwrap()
            .map(|l| l.block),
        Some(side_id)
    );
    assert!(store::block(&reader, &main_id).unwrap().is_some());
    assert_eq!(balance(&store, &MINER), Some(Amount(100)));
    assert_eq!(balance(&store, &other_miner), Some(Amount(10)));
    assert!(!entry(&store, &main_id).status.contains(Status::CONNECTED));
    assert!(entry(&store, &side_id).status.contains(Status::CONNECTED));
    assert_canonical_contiguous(&store);
}

#[test]
fn borrowed_reads_equal_the_written_block() {
    let mut store = new_store();
    let written = block(0, BlockId::ZERO, MINER, vec![transfer(1), transfer(2)]);
    let id = put(&mut store, &written);
    assert_eq!(
        put(&mut store, &written),
        id,
        "storing twice is not an error"
    );

    let reader = store::read(&store).unwrap();
    assert_eq!(store::header(&reader, &id).unwrap(), Some(&written.header));
    let stored = store::block(&reader, &id).unwrap().unwrap();
    assert_eq!(stored.header, written.header);
    assert_eq!(store::decode(&stored).unwrap(), written);
    assert_eq!(stored.bytes.as_ref(), borsh::to_vec(&written).unwrap().as_slice());
    assert_eq!(store::block(&reader, &BlockId::ZERO).unwrap(), None);
    assert_eq!(store::header(&reader, &BlockId::ZERO).unwrap(), None);
}

#[test]
fn a_store_of_another_schema_version_is_refused() {
    let mut store = new_store();
    store::check_schema(&store).unwrap();
    set_schema_version(&mut store, SCHEMA_VERSION.wrapping_add(1));
    let error = store::check_schema(&store).unwrap_err();
    assert!(matches!(
        error,
        StoreError::SchemaMismatch { found, expected }
            if found == SCHEMA_VERSION.wrapping_add(1) && expected == SCHEMA_VERSION
    ));
    assert!(error.to_string().contains("schema version"));
}

#[test]
fn a_header_over_a_parent_at_the_last_height_is_refused() {
    let mut store = new_store();
    let genesis_id = connect_genesis(&mut store);
    let last = IndexEntry::new(Height(u64::MAX), CumWork::ZERO, Status::HEADER_VALID);
    set_index_raw(&mut store, genesis_id, last);
    let child = block(u64::MAX, genesis_id, MINER, vec![]);
    let id = block_id(&child.header);
    assert!(matches!(
        store::put_header(&mut store, &id, &child.header),
        Err(StoreError::HeightOverflow(parent)) if parent == genesis_id
    ));
}
