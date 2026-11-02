//! The node key: an Ed25519 key pair that names the node on the network. Its public half
//! is the libp2p peer id. The key lives in [`KEY_FILE`] of the data directory, so a node
//! keeps its peer id across restarts. Two nodes that share a data directory share an
//! identity, so each node of one machine needs its own `POUW_DATA_DIR`.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use libp2p::identity::{DecodingError, Keypair};
use thiserror::Error;

/// Name of the key file inside the data directory. Its content is the protobuf encoding
/// of the key pair, readable by the owner only.
pub const KEY_FILE: &str = "node.key";

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("node key file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The file exists but is not a key. It is never overwritten: a node that silently
    /// changed its peer id would be a different node.
    #[error("node key file {path} does not hold a key: {source}")]
    Decode {
        path: PathBuf,
        #[source]
        source: DecodingError,
    },
    #[error("cannot encode the node key: {0}")]
    Encode(#[source] DecodingError),
}

/// Reads the key of the node from `data_dir`, or makes one and saves it there when the
/// file does not exist yet. Creates the directory when needed.
pub fn load_or_create(data_dir: &Path) -> Result<Keypair, IdentityError> {
    let path = data_dir.join(KEY_FILE);
    match fs::read(&path) {
        Ok(bytes) => Keypair::from_protobuf_encoding(&bytes)
            .map_err(|source| IdentityError::Decode { path, source }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => create(data_dir, path),
        Err(source) => Err(IdentityError::Io { path, source }),
    }
}

fn create(data_dir: &Path, path: PathBuf) -> Result<Keypair, IdentityError> {
    let key = Keypair::generate_ed25519();
    let bytes = key.to_protobuf_encoding().map_err(IdentityError::Encode)?;
    fs::create_dir_all(data_dir).map_err(|source| IdentityError::Io {
        path: data_dir.to_owned(),
        source,
    })?;
    write_private(&path, &bytes).map_err(|source| IdentityError::Io { path, source })?;
    Ok(key)
}

/// Writes a new file that only its owner can read. Fails when the file exists, so two
/// nodes that start at once cannot overwrite each other's key.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pouw-key-{}-{test}", std::process::id()));
        drop(fs::remove_dir_all(&dir));
        dir
    }

    #[test]
    fn the_first_start_makes_a_key_and_the_next_start_reads_it() {
        let dir = temp_dir("reload");
        let first = load_or_create(&dir).unwrap();
        assert!(dir.join(KEY_FILE).is_file());
        let second = load_or_create(&dir).unwrap();
        assert_eq!(first.public().to_peer_id(), second.public().to_peer_id());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn two_data_directories_give_two_identities() {
        let (a, b) = (temp_dir("two-a"), temp_dir("two-b"));
        let key_a = load_or_create(&a).unwrap();
        let key_b = load_or_create(&b).unwrap();
        assert_ne!(key_a.public().to_peer_id(), key_b.public().to_peer_id());
        fs::remove_dir_all(&a).unwrap();
        fs::remove_dir_all(&b).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_key_file_is_private_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("mode");
        load_or_create(&dir).unwrap();
        let mode = fs::metadata(dir.join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_file_that_is_not_a_key_is_an_error_and_is_kept() {
        let dir = temp_dir("garbage");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(KEY_FILE), b"not a key").unwrap();
        let error = load_or_create(&dir).unwrap_err();
        assert!(matches!(error, IdentityError::Decode { .. }));
        assert_eq!(fs::read(dir.join(KEY_FILE)).unwrap(), b"not a key");
        fs::remove_dir_all(&dir).unwrap();
    }
}
