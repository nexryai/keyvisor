//! SSH-agent service support.
//!
//! This crate owns persistence and bounded SSH-agent protocol framing.
//! Persisted records contain public metadata and TPM-wrapped object blobs only.
//! PINs and plaintext private parameters are never accepted here.

use std::{
    fmt, fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use keyvisor_core::{KeyAlgorithm, KeyId, KeySummary, KeyUsePolicy};
use keyvisor_tpm::TpmObject;

pub mod config;
pub mod history;
pub mod protocol;

const MAGIC: &[u8; 8] = b"KEYVSR\x00\x01";
const MAX_TEXT_LEN: usize = 4 * 1024;
const MAX_BLOB_LEN: usize = 1024 * 1024;

/// A complete reloadable TPM-backed key record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredKey {
    pub summary: KeySummary,
    pub object: TpmObject,
}

/// Failures while validating or persisting key metadata.
#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    InvalidRecord,
    RecordTooLarge,
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "key store I/O failed: {error}"),
            Self::InvalidRecord => formatter.write_str("stored key metadata is invalid"),
            Self::RecordTooLarge => formatter.write_str("stored key metadata exceeds its limit"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidRecord | Self::RecordTooLarge => None,
        }
    }
}

impl From<io::Error> for StoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Directory-backed store for TPM-wrapped keys.
#[derive(Clone, Debug)]
pub struct KeyStore {
    directory: PathBuf,
}

impl KeyStore {
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    /// Atomically writes one record with owner-only permissions.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if validation, serialization, or filesystem
    /// operations fail.
    pub fn save(&self, key: &StoredKey) -> Result<(), StoreError> {
        validate_record(key)?;
        let bytes = encode(key)?;
        ensure_private_directory(&self.directory)?;

        let destination = self.path_for(&key.summary.id);
        let mut temporary = None;
        // `create_new` makes a pre-created symlink or colliding temporary name
        // fail instead of allowing an attacker to redirect the write.
        for attempt in 0..100_u8 {
            let candidate = self.directory.join(format!(
                ".{}.{}.{}.tmp",
                file_stem(&key.summary.id),
                std::process::id(),
                attempt
            ));
            match create_private_file(&candidate) {
                Ok(file) => {
                    temporary = Some((candidate, file));
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(StoreError::Io(error)),
            }
        }

        let (temporary_path, mut file) = temporary.ok_or_else(|| {
            StoreError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate a temporary key record",
            ))
        })?;

        let write_result = (|| {
            // Durability requires syncing the contents before rename and the
            // directory after rename; otherwise power loss can expose a
            // partially committed key record.
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary_path, &destination)?;
            sync_directory(&self.directory)?;
            Ok::<(), io::Error>(())
        })();

        if write_result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        write_result.map_err(StoreError::Io)
    }

    /// Loads and validates one record.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the record is missing, malformed, or cannot
    /// be read.
    pub fn load(&self, id: &KeyId) -> Result<StoredKey, StoreError> {
        let bytes = fs::read(self.path_for(id))?;
        decode(&bytes)
    }

    /// Loads every validated record in stable identifier order.
    ///
    /// A missing store is an empty store. Malformed `.key` entries fail the
    /// operation rather than silently hiding corrupted or tampered metadata.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the directory cannot be read or any key
    /// record is not a regular, valid file.
    pub fn list(&self) -> Result<Vec<StoredKey>, StoreError> {
        let entries = match fs::read_dir(&self.directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(StoreError::Io(error)),
        };
        let mut keys = Vec::new();
        for entry in entries {
            let entry = entry?;
            if entry.path().extension().and_then(|value| value.to_str()) != Some("key") {
                continue;
            }
            if !entry.file_type()?.is_file() {
                return Err(StoreError::InvalidRecord);
            }
            // One malformed record fails the whole listing. Silently skipping
            // it could hide tampering and create a misleading agent identity
            // set.
            keys.push(decode(&fs::read(entry.path())?)?);
        }
        keys.sort_by(|left, right| left.summary.id.as_str().cmp(right.summary.id.as_str()));
        Ok(keys)
    }

    /// Removes one wrapped key record.
    ///
    /// This does not change TPM ownership or evict persistent TPM objects:
    /// Keyvisor children are reloadable blobs, so removing the record makes
    /// that key unavailable to the agent.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the identifier is invalid, the target is not
    /// a regular record, or the filesystem operation fails.
    pub fn delete(&self, id: &KeyId) -> Result<(), StoreError> {
        if id.as_str().is_empty() || id.as_str().len() > MAX_TEXT_LEN {
            return Err(StoreError::InvalidRecord);
        }
        let path = self.path_for(id);
        if !fs::symlink_metadata(&path)?.file_type().is_file() {
            return Err(StoreError::InvalidRecord);
        }
        fs::remove_file(path)?;
        sync_directory(&self.directory)?;
        Ok(())
    }

    fn path_for(&self, id: &KeyId) -> PathBuf {
        // Hex encoding prevents an identifier from becoming a path separator
        // or selecting data outside the key-store directory.
        self.directory.join(format!("{}.key", file_stem(id)))
    }
}

fn validate_record(key: &StoredKey) -> Result<(), StoreError> {
    if key.summary.id.as_str().is_empty()
        || key.summary.name.is_empty()
        || key.summary.id.as_str().len() > MAX_TEXT_LEN
        || key.summary.name.len() > MAX_TEXT_LEN
        || key.summary.public_key.is_empty()
        || key.summary.public_key.len() > MAX_BLOB_LEN
        || key.object.public.is_empty()
        || key.object.public.len() > MAX_BLOB_LEN
        || key.object.wrapped_private.is_empty()
        || key.object.wrapped_private.len() > MAX_BLOB_LEN
        || key.object.parent_name.is_empty()
        || key.object.parent_name.len() > MAX_BLOB_LEN
        || key.summary.use_policy != key.object.use_policy
    {
        return Err(StoreError::InvalidRecord);
    }
    Ok(())
}

fn encode(key: &StoredKey) -> Result<Vec<u8>, StoreError> {
    let mut output = Vec::new();
    output.extend_from_slice(MAGIC);
    push_bytes(
        &mut output,
        key.summary.id.as_str().as_bytes(),
        MAX_TEXT_LEN,
    )?;
    push_bytes(&mut output, key.summary.name.as_bytes(), MAX_TEXT_LEN)?;
    output.push(algorithm_tag(key.summary.algorithm));
    output.push(policy_tag(key.summary.use_policy));
    push_bytes(&mut output, &key.summary.public_key, MAX_BLOB_LEN)?;
    push_bytes(&mut output, &key.object.public, MAX_BLOB_LEN)?;
    push_bytes(&mut output, &key.object.wrapped_private, MAX_BLOB_LEN)?;
    push_bytes(&mut output, &key.object.parent_name, MAX_BLOB_LEN)?;
    Ok(output)
}

fn decode(bytes: &[u8]) -> Result<StoredKey, StoreError> {
    let mut input = bytes;
    if take(&mut input, MAGIC.len())? != MAGIC {
        return Err(StoreError::InvalidRecord);
    }

    let id = read_text(&mut input)?;
    let name = read_text(&mut input)?;
    let algorithm = match take_byte(&mut input)? {
        1 => KeyAlgorithm::EcdsaNistP256,
        _ => return Err(StoreError::InvalidRecord),
    };
    let use_policy = read_policy(take_byte(&mut input)?)?;
    let public_key = read_bytes(&mut input, MAX_BLOB_LEN)?;
    let public = read_bytes(&mut input, MAX_BLOB_LEN)?;
    let wrapped_private = read_bytes(&mut input, MAX_BLOB_LEN)?;
    let parent_name = read_bytes(&mut input, MAX_BLOB_LEN)?;
    if !input.is_empty() {
        return Err(StoreError::InvalidRecord);
    }

    let key = StoredKey {
        summary: KeySummary {
            id: KeyId::new(id),
            name,
            algorithm,
            use_policy,
            public_key,
        },
        object: TpmObject {
            public,
            wrapped_private,
            parent_name,
            use_policy,
        },
    };
    validate_record(&key)?;
    Ok(key)
}

fn push_bytes(output: &mut Vec<u8>, bytes: &[u8], limit: usize) -> Result<(), StoreError> {
    if bytes.len() > limit {
        return Err(StoreError::RecordTooLarge);
    }
    let length = u32::try_from(bytes.len()).map_err(|_| StoreError::RecordTooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn read_text(input: &mut &[u8]) -> Result<String, StoreError> {
    let bytes = read_bytes(input, MAX_TEXT_LEN)?;
    String::from_utf8(bytes).map_err(|_| StoreError::InvalidRecord)
}

fn read_bytes(input: &mut &[u8], limit: usize) -> Result<Vec<u8>, StoreError> {
    let length_bytes: [u8; 4] = take(input, 4)?
        .try_into()
        .map_err(|_| StoreError::InvalidRecord)?;
    let length = usize::try_from(u32::from_be_bytes(length_bytes))
        .map_err(|_| StoreError::RecordTooLarge)?;
    if length > limit {
        return Err(StoreError::RecordTooLarge);
    }
    Ok(take(input, length)?.to_vec())
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], StoreError> {
    if input.len() < length {
        return Err(StoreError::InvalidRecord);
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}

fn take_byte(input: &mut &[u8]) -> Result<u8, StoreError> {
    Ok(take(input, 1)?[0])
}

const fn algorithm_tag(algorithm: KeyAlgorithm) -> u8 {
    match algorithm {
        KeyAlgorithm::EcdsaNistP256 => 1,
    }
}

const fn policy_tag(policy: KeyUsePolicy) -> u8 {
    match policy {
        KeyUsePolicy::NoPin => 1,
        KeyUsePolicy::TpmPin => 2,
    }
}

const fn read_policy(tag: u8) -> Result<KeyUsePolicy, StoreError> {
    match tag {
        1 => Ok(KeyUsePolicy::NoPin),
        2 => Ok(KeyUsePolicy::TpmPin),
        _ => Err(StoreError::InvalidRecord),
    }
}

fn file_stem(id: &KeyId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(id.as_str().len() * 2);
    for byte in id.as_str().as_bytes() {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(unix)]
fn ensure_private_directory(directory: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    match fs::symlink_metadata(directory) {
        Ok(metadata) if !metadata.file_type().is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "key store path is not a directory",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(directory)?;
        }
        Err(error) => return Err(error),
    }
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn ensure_private_directory(directory: &Path) -> io::Result<()> {
    fs::create_dir_all(directory)
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
}

fn sync_directory(directory: &Path) -> io::Result<()> {
    fs::File::open(directory)?.sync_all()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{KeyStore, StoreError, StoredKey};
    use keyvisor_core::{KeyAlgorithm, KeyId, KeySummary, KeyUsePolicy};
    use keyvisor_tpm::TpmObject;

    fn fixture(id: &str) -> StoredKey {
        StoredKey {
            summary: KeySummary {
                id: KeyId::new(id),
                name: "Work key".to_owned(),
                algorithm: KeyAlgorithm::EcdsaNistP256,
                use_policy: KeyUsePolicy::TpmPin,
                public_key: vec![1, 2, 3],
            },
            object: TpmObject {
                public: vec![4, 5],
                wrapped_private: vec![6, 7, 8],
                parent_name: vec![9, 10],
                use_policy: KeyUsePolicy::TpmPin,
            },
        }
    }

    fn temporary_directory() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "keyvisor-store-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock must follow Unix epoch")
                .as_nanos()
        ))
    }

    #[test]
    fn saves_and_loads_wrapped_key_metadata() {
        let directory = temporary_directory();
        let store = KeyStore::new(&directory);
        let key = fixture("key/with unsafe filename");

        store.save(&key).expect("save test record");
        assert_eq!(store.load(&key.summary.id).expect("load test record"), key);

        let entries = fs::read_dir(&directory)
            .expect("read store directory")
            .collect::<Result<Vec<_>, _>>()
            .expect("read store entries");
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].file_name().to_string_lossy().contains('/'));

        fs::remove_dir_all(directory).expect("remove test store");
    }

    #[test]
    fn rejects_mismatched_policy() {
        let directory = temporary_directory();
        let store = KeyStore::new(&directory);
        let mut key = fixture("policy-mismatch");
        key.object.use_policy = KeyUsePolicy::NoPin;

        assert!(matches!(store.save(&key), Err(StoreError::InvalidRecord)));
        assert!(!directory.exists());
    }

    #[test]
    fn debug_output_redacts_wrapped_private_blob() {
        let key = fixture("debug");
        let debug = format!("{key:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("6, 7, 8"));
    }

    #[cfg(unix)]
    #[test]
    fn saved_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let directory = temporary_directory();
        let store = KeyStore::new(&directory);
        let key = fixture("permissions");
        store.save(&key).expect("save test record");

        let entry = fs::read_dir(&directory)
            .expect("read store directory")
            .next()
            .expect("store has one record")
            .expect("read store entry");
        assert_eq!(
            entry
                .metadata()
                .expect("read record metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&directory)
                .expect("read directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        fs::remove_dir_all(directory).expect("remove test store");
    }

    #[test]
    fn lists_records_in_stable_identifier_order() {
        let directory = temporary_directory();
        let store = KeyStore::new(&directory);
        let later = fixture("z-key");
        let earlier = fixture("a-key");
        store.save(&later).expect("save later record");
        store.save(&earlier).expect("save earlier record");

        let listed = store.list().expect("list test records");
        assert_eq!(listed, [earlier, later]);

        fs::remove_dir_all(directory).expect("remove test store");
    }

    #[test]
    fn listing_fails_closed_for_a_corrupted_record() {
        let directory = temporary_directory();
        let store = KeyStore::new(&directory);
        let key = fixture("corrupted");
        store.save(&key).expect("save record before corruption");
        let record_path = fs::read_dir(&directory)
            .expect("read store directory")
            .next()
            .expect("store has one record")
            .expect("read store entry")
            .path();
        let mut bytes = fs::read(&record_path).expect("read encoded record");
        bytes[0] ^= 0xff;
        fs::write(&record_path, bytes).expect("corrupt encoded record");

        // Listing must surface corruption instead of hiding the affected key.
        // A partial identity set could otherwise make tampering look like an
        // ordinary user deletion.
        assert!(matches!(store.list(), Err(StoreError::InvalidRecord)));

        fs::remove_dir_all(directory).expect("remove test store");
    }

    #[cfg(unix)]
    #[test]
    fn listing_rejects_symlinked_key_records() {
        use std::os::unix::fs::symlink;

        let directory = temporary_directory();
        let store = KeyStore::new(&directory);
        let key = fixture("symlink-target");
        store.save(&key).expect("save symlink target");
        let real_record = fs::read_dir(&directory)
            .expect("read store directory")
            .next()
            .expect("store has one record")
            .expect("read store entry")
            .path();
        symlink(&real_record, directory.join("alias.key")).expect("create record symlink");

        // Following a `.key` symlink would let another filesystem location
        // supply agent metadata after directory validation. Only regular files
        // directly owned by the store are accepted.
        assert!(matches!(store.list(), Err(StoreError::InvalidRecord)));

        fs::remove_dir_all(directory).expect("remove test store");
    }

    #[test]
    fn deletes_only_the_selected_wrapped_record() {
        let directory = temporary_directory();
        let store = KeyStore::new(&directory);
        let removed = fixture("remove");
        let retained = fixture("retain");
        store.save(&removed).expect("save removed record");
        store.save(&retained).expect("save retained record");

        store
            .delete(&removed.summary.id)
            .expect("delete selected record");
        assert!(store.load(&removed.summary.id).is_err());
        assert_eq!(
            store
                .load(&retained.summary.id)
                .expect("load retained record"),
            retained
        );

        fs::remove_dir_all(directory).expect("remove test store");
    }
}
