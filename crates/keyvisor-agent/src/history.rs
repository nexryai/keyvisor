//! Bounded, privacy-preserving signing history.

use std::{
    fmt, fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use keyvisor_core::{KeyId, KeyUsePolicy};

const MAGIC: &[u8; 8] = b"KEYHST\x00\x01";
const MAX_ENTRIES: usize = 200;
const MAX_TEXT_LEN: usize = 4 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryOutcome {
    Succeeded,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryEntry {
    pub timestamp_seconds: u64,
    pub key_id: KeyId,
    pub key_name: String,
    pub use_policy: KeyUsePolicy,
    pub outcome: HistoryOutcome,
}

#[derive(Debug)]
pub enum HistoryError {
    Io(io::Error),
    InvalidData,
}

impl fmt::Display for HistoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "history I/O failed: {error}"),
            Self::InvalidData => formatter.write_str("signing history is invalid"),
        }
    }
}

impl std::error::Error for HistoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidData => None,
        }
    }
}

impl From<io::Error> for HistoryError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Debug)]
pub struct HistoryStore {
    path: PathBuf,
}

impl HistoryStore {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Appends an entry and retains only the newest 200 events.
    ///
    /// # Errors
    ///
    /// Returns [`HistoryError`] if existing data is invalid or an atomic write
    /// cannot be completed.
    pub fn append(&self, entry: HistoryEntry) -> Result<(), HistoryError> {
        validate_entry(&entry)?;
        // Rewriting is acceptable because the history is deliberately small;
        // it keeps the format simple and every update atomic.
        let mut entries = self.list()?;
        entries.push(entry);
        if entries.len() > MAX_ENTRIES {
            entries.drain(..entries.len() - MAX_ENTRIES);
        }
        self.save(&entries)
    }

    /// Loads history in oldest-to-newest order.
    ///
    /// # Errors
    ///
    /// Returns [`HistoryError`] if the record cannot be read or validated.
    pub fn list(&self) -> Result<Vec<HistoryEntry>, HistoryError> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(HistoryError::Io(error)),
        };
        if !metadata.file_type().is_file() {
            return Err(HistoryError::InvalidData);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            // Key names and use times are not secret key material, but they are
            // still private account metadata and must not be group-readable.
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(HistoryError::InvalidData);
            }
        }
        decode(&fs::read(&self.path)?)
    }

    fn save(&self, entries: &[HistoryEntry]) -> Result<(), HistoryError> {
        let parent = self.path.parent().ok_or(HistoryError::InvalidData)?;
        ensure_private_directory(parent)?;
        let bytes = encode(entries)?;
        let (temporary, mut file) = create_temporary_file(parent)?;
        let write_result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, &self.path)?;
            fs::File::open(parent)?.sync_all()
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        write_result.map_err(HistoryError::Io)
    }
}

fn create_temporary_file(parent: &Path) -> io::Result<(PathBuf, fs::File)> {
    for attempt in 0..100_u8 {
        let path = parent.join(format!(".history.{}.{}.tmp", std::process::id(), attempt));
        match create_private_file(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "cannot allocate a unique history temporary file",
    ))
}

fn validate_entry(entry: &HistoryEntry) -> Result<(), HistoryError> {
    if entry.key_id.as_str().is_empty()
        || entry.key_id.as_str().len() > MAX_TEXT_LEN
        || entry.key_name.is_empty()
        || entry.key_name.len() > MAX_TEXT_LEN
    {
        return Err(HistoryError::InvalidData);
    }
    Ok(())
}

fn encode(entries: &[HistoryEntry]) -> Result<Vec<u8>, HistoryError> {
    if entries.len() > MAX_ENTRIES {
        return Err(HistoryError::InvalidData);
    }
    let mut output = Vec::new();
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(
        &u32::try_from(entries.len())
            .map_err(|_| HistoryError::InvalidData)?
            .to_be_bytes(),
    );
    for entry in entries {
        validate_entry(entry)?;
        output.extend_from_slice(&entry.timestamp_seconds.to_be_bytes());
        push_text(&mut output, entry.key_id.as_str())?;
        push_text(&mut output, &entry.key_name)?;
        output.push(match entry.use_policy {
            KeyUsePolicy::NoPin => 1,
            KeyUsePolicy::TpmPin => 2,
        });
        output.push(match entry.outcome {
            HistoryOutcome::Succeeded => 1,
            HistoryOutcome::Failed => 2,
        });
    }
    Ok(output)
}

fn decode(bytes: &[u8]) -> Result<Vec<HistoryEntry>, HistoryError> {
    let mut input = bytes;
    if take(&mut input, MAGIC.len())? != MAGIC {
        return Err(HistoryError::InvalidData);
    }
    let count = usize::try_from(read_u32(&mut input)?).map_err(|_| HistoryError::InvalidData)?;
    if count > MAX_ENTRIES {
        return Err(HistoryError::InvalidData);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let timestamp_bytes: [u8; 8] = take(&mut input, 8)?
            .try_into()
            .map_err(|_| HistoryError::InvalidData)?;
        let key_id = KeyId::new(read_text(&mut input)?);
        let key_name = read_text(&mut input)?;
        let use_policy = match take(&mut input, 1)?[0] {
            1 => KeyUsePolicy::NoPin,
            2 => KeyUsePolicy::TpmPin,
            _ => return Err(HistoryError::InvalidData),
        };
        let outcome = match take(&mut input, 1)?[0] {
            1 => HistoryOutcome::Succeeded,
            2 => HistoryOutcome::Failed,
            _ => return Err(HistoryError::InvalidData),
        };
        let entry = HistoryEntry {
            timestamp_seconds: u64::from_be_bytes(timestamp_bytes),
            key_id,
            key_name,
            use_policy,
            outcome,
        };
        validate_entry(&entry)?;
        entries.push(entry);
    }
    if !input.is_empty() {
        return Err(HistoryError::InvalidData);
    }
    Ok(entries)
}

fn push_text(output: &mut Vec<u8>, value: &str) -> Result<(), HistoryError> {
    if value.len() > MAX_TEXT_LEN {
        return Err(HistoryError::InvalidData);
    }
    output.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| HistoryError::InvalidData)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn read_text(input: &mut &[u8]) -> Result<String, HistoryError> {
    let length = usize::try_from(read_u32(input)?).map_err(|_| HistoryError::InvalidData)?;
    if length > MAX_TEXT_LEN {
        return Err(HistoryError::InvalidData);
    }
    String::from_utf8(take(input, length)?.to_vec()).map_err(|_| HistoryError::InvalidData)
}

fn read_u32(input: &mut &[u8]) -> Result<u32, HistoryError> {
    let bytes: [u8; 4] = take(input, 4)?
        .try_into()
        .map_err(|_| HistoryError::InvalidData)?;
    Ok(u32::from_be_bytes(bytes))
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], HistoryError> {
    if input.len() < length {
        return Err(HistoryError::InvalidData);
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}

#[cfg(unix)]
fn ensure_private_directory(directory: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    match fs::symlink_metadata(directory) {
        Ok(metadata) if !metadata.file_type().is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "history directory is not a directory",
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

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use keyvisor_core::{KeyId, KeyUsePolicy};

    use super::{HistoryEntry, HistoryOutcome, HistoryStore, MAX_ENTRIES};

    fn temporary_path() -> std::path::PathBuf {
        std::env::temp_dir()
            .join(format!(
                "keyvisor-history-test-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("clock follows Unix epoch")
                    .as_nanos()
            ))
            .join("history.bin")
    }

    fn entry(index: u64) -> HistoryEntry {
        HistoryEntry {
            timestamp_seconds: index,
            key_id: KeyId::new(format!("id-{index}")),
            key_name: format!("Key {index}"),
            use_policy: KeyUsePolicy::TpmPin,
            outcome: HistoryOutcome::Succeeded,
        }
    }

    #[test]
    fn persists_and_bounds_history() {
        let path = temporary_path();
        let store = HistoryStore::new(&path);
        for index in 0..u64::try_from(MAX_ENTRIES + 3).expect("test count fits") {
            store.append(entry(index)).expect("append history");
        }
        let entries = store.list().expect("load history");
        assert_eq!(entries.len(), MAX_ENTRIES);
        assert_eq!(entries[0].timestamp_seconds, 3);
        assert_eq!(
            entries
                .last()
                .expect("history has entries")
                .timestamp_seconds,
            u64::try_from(MAX_ENTRIES + 2).expect("test count fits")
        );
        fs::remove_dir_all(path.parent().expect("history path has parent"))
            .expect("remove history test directory");
    }

    #[cfg(unix)]
    #[test]
    fn history_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let path = temporary_path();
        HistoryStore::new(&path)
            .append(entry(1))
            .expect("append history");
        assert_eq!(
            fs::metadata(&path)
                .expect("history metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().expect("history path has parent"))
                .expect("history directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        fs::remove_dir_all(path.parent().expect("history path has parent"))
            .expect("remove history test directory");
    }

    #[test]
    fn rejects_truncated_history() {
        let path = temporary_path();
        fs::create_dir_all(path.parent().expect("history path has parent"))
            .expect("create history test directory");
        fs::write(&path, b"KEYHST").expect("write truncated history");
        assert!(store_for(&path).list().is_err());
        fs::remove_dir_all(path.parent().expect("history path has parent"))
            .expect("remove history test directory");
    }

    fn store_for(path: &std::path::Path) -> HistoryStore {
        HistoryStore::new(path)
    }
}
