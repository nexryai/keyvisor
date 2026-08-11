//! Owner-only, non-secret CLI configuration.

use std::{
    fmt, fs,
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const MAGIC: &str = "KEYVISOR-CONFIG-1";
const DEFAULT_AUTHORIZATION_TIMEOUT_SECONDS: u64 = 120;
const MIN_AUTHORIZATION_TIMEOUT_SECONDS: u64 = 10;
const MAX_AUTHORIZATION_TIMEOUT_SECONDS: u64 = 120;

/// Non-secret behavior settings shared by the CLI and agent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    pub authorization_timeout_seconds: u64,
    pub history_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            authorization_timeout_seconds: DEFAULT_AUTHORIZATION_TIMEOUT_SECONDS,
            history_enabled: true,
        }
    }
}

impl Config {
    /// Returns a setting using its stable CLI representation.
    #[must_use]
    pub fn get(self, name: &str) -> Option<String> {
        match name {
            "authorization-timeout-seconds" => Some(self.authorization_timeout_seconds.to_string()),
            "history-enabled" => Some(self.history_enabled.to_string()),
            _ => None,
        }
    }

    /// Updates one documented setting.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidValue`] for an unknown setting or a value
    /// outside its accepted range.
    pub fn set(&mut self, name: &str, value: &str) -> Result<(), ConfigError> {
        match name {
            "authorization-timeout-seconds" => {
                let seconds = value
                    .parse::<u64>()
                    .map_err(|_| ConfigError::InvalidValue)?;
                if !(MIN_AUTHORIZATION_TIMEOUT_SECONDS..=MAX_AUTHORIZATION_TIMEOUT_SECONDS)
                    .contains(&seconds)
                {
                    return Err(ConfigError::InvalidValue);
                }
                self.authorization_timeout_seconds = seconds;
            }
            "history-enabled" => {
                self.history_enabled = match value {
                    "true" => true,
                    "false" => false,
                    _ => return Err(ConfigError::InvalidValue),
                };
            }
            _ => return Err(ConfigError::InvalidValue),
        }
        Ok(())
    }
}

/// Persistent configuration errors.
#[derive(Debug)]
pub enum ConfigError {
    Io(io::Error),
    InvalidData,
    InvalidValue,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "configuration I/O failed: {error}"),
            Self::InvalidData => formatter.write_str("configuration data is invalid"),
            Self::InvalidValue => formatter.write_str("configuration setting or value is invalid"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<io::Error> for ConfigError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Loads and atomically saves Keyvisor configuration.
#[derive(Clone, Debug)]
pub struct ConfigStore {
    path: PathBuf,
}

impl ConfigStore {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Loads the configuration or returns defaults when no file exists.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when an existing file is unsafe or malformed.
    pub fn load(&self) -> Result<Config, ConfigError> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Config::default()),
            Err(error) => return Err(ConfigError::Io(error)),
        };
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(ConfigError::InvalidData);
        }
        parse(&fs::read_to_string(&self.path)?)
    }

    /// Saves configuration with owner-only permissions and an atomic rename.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the directory is unsafe or persistence fails.
    pub fn save(&self, config: Config) -> Result<(), ConfigError> {
        let parent = self.path.parent().ok_or(ConfigError::InvalidData)?;
        ensure_private_directory(parent)?;
        let (temporary, mut file) = create_temporary_file(parent)?;
        let result = (|| {
            writeln!(file, "{MAGIC}")?;
            writeln!(
                file,
                "authorization-timeout-seconds={}",
                config.authorization_timeout_seconds
            )?;
            writeln!(file, "history-enabled={}", config.history_enabled)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, &self.path)?;
            fs::File::open(parent)?.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.map_err(ConfigError::Io)
    }
}

fn create_temporary_file(parent: &Path) -> Result<(PathBuf, fs::File), ConfigError> {
    for attempt in 0..100_u8 {
        let path = parent.join(format!(".config.{}.{}.tmp", std::process::id(), attempt));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(ConfigError::Io(error)),
        }
    }
    Err(ConfigError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "cannot allocate a unique configuration temporary file",
    )))
}

fn parse(contents: &str) -> Result<Config, ConfigError> {
    let mut lines = contents.lines();
    if lines.next() != Some(MAGIC) {
        return Err(ConfigError::InvalidData);
    }
    let mut config = Config::default();
    let mut timeout_seen = false;
    let mut history_seen = false;
    for line in lines {
        let (name, value) = line.split_once('=').ok_or(ConfigError::InvalidData)?;
        match name {
            "authorization-timeout-seconds" if !timeout_seen => timeout_seen = true,
            "history-enabled" if !history_seen => history_seen = true,
            _ => return Err(ConfigError::InvalidData),
        }
        config
            .set(name, value)
            .map_err(|_| ConfigError::InvalidData)?;
    }
    if !timeout_seen || !history_seen {
        return Err(ConfigError::InvalidData);
    }
    Ok(config)
}

fn ensure_private_directory(path: &Path) -> Result<(), ConfigError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
                return Err(ConfigError::InvalidData);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Err(error) => return Err(ConfigError::Io(error)),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Config, ConfigStore};
    use std::{fs, time::SystemTime};

    fn test_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "keyvisor-config-test-{}-{:?}/config",
            std::process::id(),
            SystemTime::now()
        ))
    }

    #[test]
    fn defaults_and_round_trip() {
        let path = test_path();
        let store = ConfigStore::new(&path);
        assert_eq!(store.load().expect("load defaults"), Config::default());
        let mut config = Config::default();
        config
            .set("authorization-timeout-seconds", "45")
            .expect("set timeout");
        config.set("history-enabled", "false").expect("set history");
        store.save(config).expect("save config");
        assert_eq!(store.load().expect("reload config"), config);
        fs::remove_dir_all(path.parent().expect("config has parent"))
            .expect("remove test directory");
    }

    #[test]
    fn rejects_unsafe_values() {
        let mut config = Config::default();
        assert!(config.set("authorization-timeout-seconds", "9").is_err());
        assert!(config.set("history-enabled", "yes").is_err());
        assert!(config.set("unknown", "value").is_err());
    }
}
