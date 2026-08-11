//! Command-line management for TPM-backed Keyvisor keys.

use std::{
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    os::unix::net::UnixStream,
    path::PathBuf,
    time::Duration,
};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use keyvisor_agent::{
    KeyStore, StoredKey,
    config::{Config, ConfigStore},
    history::{HistoryOutcome, HistoryStore},
};
use keyvisor_core::{KeyAlgorithm, KeyUsePolicy};
use keyvisor_tpm::{EsapiTpm, TpmAuthorization, TpmSigner};
use rustix::process::geteuid;
use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const MAX_PIN_BYTES: usize = 64;
const MAX_CONTROL_LINE_BYTES: u64 = 16 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("keyvisor: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [flag] if flag == "--version" || flag == "-V" => {
            println!("keyvisor {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        [] => {
            print_help();
            Ok(())
        }
        [flag] if flag == "--help" || flag == "-h" => {
            print_help();
            Ok(())
        }
        [group, rest @ ..] if group == "key" => run_key(rest),
        [group, rest @ ..] if group == "config" => run_config(rest),
        [group, rest @ ..] if group == "agent" => run_agent(rest),
        [command, rest @ ..] if command == "history" => run_history(rest),
        [command, rest @ ..] if command == "authorize" => run_authorize(rest),
        _ => Err(String::from("unknown command; run `keyvisor --help`")),
    }
}

fn print_help() {
    println!(
        "Keyvisor — TPM-backed SSH key management\n\n\
Usage:\n  \
  keyvisor key create --name NAME --authorization none|pin [--yes] [--pin-stdin]\n  \
  keyvisor key list [--format human|tsv]\n  \
  keyvisor key show ID\n  \
  keyvisor key delete ID [--yes]\n  \
  keyvisor config list\n  \
  keyvisor config get NAME\n  \
  keyvisor config set NAME VALUE\n  \
  keyvisor agent status\n  \
  keyvisor history [--format human|tsv]\n  \
  keyvisor authorize [REQUEST_ID] [--pin-stdin]"
    );
}

fn run_key(arguments: &[OsString]) -> Result<(), String> {
    match arguments {
        [command, rest @ ..] if command == "create" => create_key(rest),
        [command, rest @ ..] if command == "list" => list_keys(rest),
        [command, id] if command == "show" => show_key(id),
        [command, rest @ ..] if command == "delete" => delete_key(rest),
        _ => Err(String::from("invalid key command; run `keyvisor --help`")),
    }
}

fn create_key(arguments: &[OsString]) -> Result<(), String> {
    let mut name = None;
    let mut policy = None;
    let mut confirmed = false;
    let mut pin_stdin = false;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].to_str() {
            Some("--name") if index + 1 < arguments.len() => {
                name = Some(
                    os_text(&arguments[index + 1], "key name")?
                        .trim()
                        .to_owned(),
                );
                index += 2;
            }
            Some("--authorization") if index + 1 < arguments.len() => {
                policy = Some(match arguments[index + 1].to_str() {
                    Some("none") => KeyUsePolicy::NoPin,
                    Some("pin") => KeyUsePolicy::TpmPin,
                    _ => return Err(String::from("authorization must be `none` or `pin`")),
                });
                index += 2;
            }
            Some("--yes") => {
                confirmed = true;
                index += 1;
            }
            Some("--pin-stdin") => {
                pin_stdin = true;
                index += 1;
            }
            _ => return Err(String::from("invalid key create arguments")),
        }
    }
    let name = name.ok_or_else(|| String::from("--name is required"))?;
    if name.is_empty() || name.len() > 4 * 1024 {
        return Err(String::from("key name must be between 1 and 4096 bytes"));
    }
    let policy = policy.ok_or_else(|| String::from("--authorization is required"))?;
    if policy == KeyUsePolicy::NoPin && !confirmed {
        eprintln!(
            "No-PIN keys allow any process with access to SSH_AUTH_SOCK to request signatures."
        );
        require_confirmation("Create this no-PIN key? [y/N] ")?;
    }
    if policy == KeyUsePolicy::NoPin && pin_stdin {
        return Err(String::from(
            "--pin-stdin is valid only for PIN-protected keys",
        ));
    }

    let pin = if policy == KeyUsePolicy::TpmPin {
        let (first, second) = if pin_stdin {
            let stdin = io::stdin();
            let mut input = stdin.lock();
            (
                read_pin_line(&mut input, "PIN")?,
                read_pin_line(&mut input, "PIN confirmation")?,
            )
        } else {
            (
                read_secret_from_tty("TPM PIN: ")?,
                read_secret_from_tty("Confirm TPM PIN: ")?,
            )
        };
        if first.as_slice() != second.as_slice() {
            return Err(String::from("PIN confirmation does not match"));
        }
        first
    } else {
        Zeroizing::new(Vec::new())
    };
    let authorization = match policy {
        KeyUsePolicy::NoPin => TpmAuthorization::None,
        KeyUsePolicy::TpmPin => TpmAuthorization::Pin(&pin),
    };
    let mut tpm =
        EsapiTpm::connect_default().map_err(|error| format!("cannot open the TPM: {error}"))?;
    let (summary, object) = tpm
        .generate(&name, KeyAlgorithm::EcdsaNistP256, authorization)
        .map_err(|error| format!("cannot generate the TPM key: {error}"))?;
    let id = summary.id.as_str().to_owned();
    KeyStore::new(store_directory()?)
        .save(&StoredKey { summary, object })
        .map_err(|error| format!("cannot persist the wrapped TPM key: {error}"))?;
    println!("{id}");
    Ok(())
}

fn list_keys(arguments: &[OsString]) -> Result<(), String> {
    let format = parse_format(arguments)?;
    let keys = KeyStore::new(store_directory()?)
        .list()
        .map_err(|error| format!("cannot list keys: {error}"))?;
    if format == OutputFormat::Tsv {
        println!("KEYVISOR-KEYS-1");
        println!("id\tname\tauthorization\tfingerprint");
        for key in keys {
            println!(
                "{}\t{}\t{}\t{}",
                key.summary.id.as_str(),
                escape_tsv(&key.summary.name),
                policy_name(key.summary.use_policy),
                fingerprint(&key.summary.public_key)
            );
        }
    } else if keys.is_empty() {
        println!("No keys.");
    } else {
        for key in keys {
            println!(
                "{}  {}  {}  {}",
                key.summary.id.as_str(),
                key.summary.name,
                policy_name(key.summary.use_policy),
                fingerprint(&key.summary.public_key)
            );
        }
    }
    Ok(())
}

fn show_key(id: &OsString) -> Result<(), String> {
    let id = os_text(id, "key identifier")?;
    let key = find_key(id)?;
    println!("ID: {}", key.summary.id.as_str());
    println!("Name: {}", key.summary.name);
    println!("Algorithm: ecdsa-sha2-nistp256");
    println!("Authorization: {}", policy_name(key.summary.use_policy));
    println!("Fingerprint: {}", fingerprint(&key.summary.public_key));
    println!(
        "Public key: ecdsa-sha2-nistp256 {} {}",
        STANDARD.encode(&key.summary.public_key),
        key.summary.name
    );
    Ok(())
}

fn delete_key(arguments: &[OsString]) -> Result<(), String> {
    let (id, confirmed) = match arguments {
        [id] => (id, false),
        [id, flag] if flag == "--yes" => (id, true),
        _ => return Err(String::from("usage: keyvisor key delete ID [--yes]")),
    };
    let id = os_text(id, "key identifier")?;
    let key = find_key(id)?;
    if !confirmed {
        require_confirmation(&format!("Delete key “{}”? [y/N] ", key.summary.name))?;
    }
    KeyStore::new(store_directory()?)
        .delete(&key.summary.id)
        .map_err(|error| format!("cannot delete key: {error}"))
}

fn find_key(id: &str) -> Result<StoredKey, String> {
    KeyStore::new(store_directory()?)
        .list()
        .map_err(|error| format!("cannot list keys: {error}"))?
        .into_iter()
        .find(|key| key.summary.id.as_str() == id)
        .ok_or_else(|| format!("key `{id}` was not found"))
}

fn run_config(arguments: &[OsString]) -> Result<(), String> {
    let store = ConfigStore::new(config_path()?);
    match arguments {
        [command] if command == "list" => {
            print_config(store.load().map_err(|error| error.to_string())?);
            Ok(())
        }
        [command, name] if command == "get" => {
            let name = os_text(name, "setting name")?;
            let value = store
                .load()
                .map_err(|error| error.to_string())?
                .get(name)
                .ok_or_else(|| format!("unknown setting `{name}`"))?;
            println!("{value}");
            Ok(())
        }
        [command, name, value] if command == "set" => {
            let name = os_text(name, "setting name")?;
            let value = os_text(value, "setting value")?;
            let mut config = store.load().map_err(|error| error.to_string())?;
            config.set(name, value).map_err(|error| error.to_string())?;
            store.save(config).map_err(|error| error.to_string())?;
            println!("{name}={value}");
            Ok(())
        }
        _ => Err(String::from(
            "invalid config command; run `keyvisor --help`",
        )),
    }
}

fn print_config(config: Config) {
    println!(
        "authorization-timeout-seconds={}",
        config.authorization_timeout_seconds
    );
    println!("history-enabled={}", config.history_enabled);
}

fn run_agent(arguments: &[OsString]) -> Result<(), String> {
    if arguments != [OsString::from("status")] {
        return Err(String::from("usage: keyvisor agent status"));
    }
    let mut stream = connect_control()?;
    stream.write_all(b"STATUS\n").map_err(control_io)?;
    let line = read_control_line(&mut stream)?;
    if line == "OK running" {
        println!("running");
        Ok(())
    } else {
        Err(control_error(&line))
    }
}

fn run_history(arguments: &[OsString]) -> Result<(), String> {
    let format = parse_format(arguments)?;
    let entries = HistoryStore::new(history_path()?)
        .list()
        .map_err(|error| error.to_string())?;
    if format == OutputFormat::Tsv {
        println!("KEYVISOR-HISTORY-1");
        println!("timestamp\tkey-id\tkey-name\tauthorization\toutcome");
        for entry in entries {
            println!(
                "{}\t{}\t{}\t{}\t{}",
                entry.timestamp_seconds,
                entry.key_id.as_str(),
                escape_tsv(&entry.key_name),
                policy_name(entry.use_policy),
                outcome_name(entry.outcome)
            );
        }
    } else if entries.is_empty() {
        println!("No signing history.");
    } else {
        for entry in entries {
            println!(
                "{}  {}  {}  {}  {}",
                entry.timestamp_seconds,
                entry.key_id.as_str(),
                entry.key_name,
                policy_name(entry.use_policy),
                outcome_name(entry.outcome)
            );
        }
    }
    Ok(())
}

fn run_authorize(arguments: &[OsString]) -> Result<(), String> {
    let mut id = None;
    let mut pin_stdin = false;
    for argument in arguments {
        if argument == "--pin-stdin" {
            pin_stdin = true;
        } else if id.is_none() {
            id = Some(os_text(argument, "request identifier")?.to_owned());
        } else {
            return Err(String::from(
                "usage: keyvisor authorize [REQUEST_ID] [--pin-stdin]",
            ));
        }
    }
    let Some(id) = id else {
        return list_authorization_requests();
    };
    let pin = if pin_stdin {
        read_pin_line(&mut io::stdin().lock(), "PIN")?
    } else {
        read_secret_from_tty("TPM PIN: ")?
    };
    let mut stream = connect_control()?;
    writeln!(stream, "AUTHORIZE {id} {}", pin.len()).map_err(control_io)?;
    stream.write_all(&pin).map_err(control_io)?;
    stream.flush().map_err(control_io)?;
    let line = read_control_line(&mut stream)?;
    if line == "OK authorized" {
        println!("authorized {id}");
        Ok(())
    } else {
        Err(control_error(&line))
    }
}

fn list_authorization_requests() -> Result<(), String> {
    let mut stream = connect_control()?;
    stream.write_all(b"LIST\n").map_err(control_io)?;
    let header = read_control_line(&mut stream)?;
    let count = header
        .strip_prefix("OK KEYVISOR-PENDING-1 ")
        .ok_or_else(|| control_error(&header))?
        .parse::<usize>()
        .map_err(|_| String::from("agent returned an invalid request count"))?;
    if count == 0 {
        println!("No pending authorization requests.");
        return Ok(());
    }
    for _ in 0..count {
        let line = read_control_line(&mut stream)?;
        let (id, name) = line
            .split_once('\t')
            .ok_or_else(|| String::from("agent returned an invalid authorization request"))?;
        println!("{id}  {}", decode_hex_text(name)?);
    }
    Ok(())
}

fn connect_control() -> Result<UnixStream, String> {
    let path = control_socket_path()?;
    let metadata =
        fs::symlink_metadata(&path).map_err(|error| format!("agent is not running: {error}"))?;
    if !metadata.file_type().is_socket() {
        return Err(String::from("control socket path is not a Unix socket"));
    }
    if metadata.permissions().mode() & 0o777 != 0o600 || metadata.uid() != geteuid().as_raw() {
        return Err(String::from(
            "control socket must be owned by the current user with mode 0600",
        ));
    }
    let stream = UnixStream::connect(&path)
        .map_err(|error| format!("cannot connect to the agent control socket: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(control_io)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(control_io)?;
    Ok(stream)
}

fn read_control_line(stream: &mut UnixStream) -> Result<String, String> {
    let mut bytes = Vec::new();
    while bytes.len() as u64 <= MAX_CONTROL_LINE_BYTES {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).map_err(control_io)?;
        if byte[0] == b'\n' {
            return String::from_utf8(bytes)
                .map_err(|_| String::from("agent returned non-UTF-8 control data"));
        }
        bytes.push(byte[0]);
    }
    Err(String::from("agent returned an invalid control response"))
}

fn control_error(line: &str) -> String {
    line.strip_prefix("ERR ")
        .unwrap_or("invalid response from agent")
        .to_owned()
}

#[allow(clippy::needless_pass_by_value)]
fn control_io(error: io::Error) -> String {
    format!("control protocol I/O failed: {error}")
}

fn read_secret_from_tty(prompt: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|error| format!("cannot open the controlling terminal: {error}"))?;
    tty.write_all(prompt.as_bytes())
        .and_then(|()| tty.flush())
        .map_err(|error| format!("cannot write PIN prompt: {error}"))?;
    let original = tcgetattr(&tty).map_err(|error| format!("cannot inspect terminal: {error}"))?;
    let mut hidden = original.clone();
    hidden.local_modes.remove(LocalModes::ECHO);
    tcsetattr(&tty, OptionalActions::Flush, &hidden)
        .map_err(|error| format!("cannot disable terminal echo: {error}"))?;
    let result = read_pin_line(&mut BufReader::new(&tty), "PIN");
    let restore = tcsetattr(&tty, OptionalActions::Flush, &original)
        .map_err(|error| format!("cannot restore terminal echo: {error}"));
    let newline = tty.write_all(b"\n").map_err(|error| error.to_string());
    restore?;
    newline?;
    result
}

fn read_pin_line(reader: &mut impl BufRead, label: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut pin = Zeroizing::new(Vec::new());
    reader
        .take(u64::try_from(MAX_PIN_BYTES + 2).expect("PIN bound fits u64"))
        .read_until(b'\n', &mut pin)
        .map_err(|error| format!("cannot read {label}: {error}"))?;
    if pin.last() == Some(&b'\n') {
        pin.pop();
    }
    if pin.last() == Some(&b'\r') {
        pin.pop();
    }
    if !(6..=MAX_PIN_BYTES).contains(&pin.len()) {
        pin.zeroize();
        return Err(format!(
            "{label} must be between 6 and {MAX_PIN_BYTES} bytes"
        ));
    }
    Ok(pin)
}

fn require_confirmation(prompt: &str) -> Result<(), String> {
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|error| format!("confirmation requires a terminal: {error}"))?;
    tty.write_all(prompt.as_bytes())
        .and_then(|()| tty.flush())
        .map_err(|error| format!("cannot write confirmation prompt: {error}"))?;
    let mut answer = String::new();
    BufReader::new(tty)
        .read_line(&mut answer)
        .map_err(|error| format!("cannot read confirmation: {error}"))?;
    if matches!(answer.trim(), "y" | "Y" | "yes" | "YES") {
        Ok(())
    } else {
        Err(String::from("operation cancelled"))
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OutputFormat {
    Human,
    Tsv,
}

fn parse_format(arguments: &[OsString]) -> Result<OutputFormat, String> {
    match arguments {
        [] => Ok(OutputFormat::Human),
        [flag, value] if flag == "--format" && value == "human" => Ok(OutputFormat::Human),
        [flag, value] if flag == "--format" && value == "tsv" => Ok(OutputFormat::Tsv),
        _ => Err(String::from("format must be `human` or `tsv`")),
    }
}

fn policy_name(policy: KeyUsePolicy) -> &'static str {
    match policy {
        KeyUsePolicy::NoPin => "none",
        KeyUsePolicy::TpmPin => "pin",
    }
}

fn outcome_name(outcome: HistoryOutcome) -> &'static str {
    match outcome {
        HistoryOutcome::Succeeded => "succeeded",
        HistoryOutcome::Failed => "failed",
    }
}

fn fingerprint(public_key: &[u8]) -> String {
    format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(Sha256::digest(public_key))
    )
}

fn escape_tsv(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

fn decode_hex_text(value: &str) -> Result<String, String> {
    if !value.len().is_multiple_of(2) {
        return Err(String::from("agent returned invalid key-name encoding"));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        bytes.push((high << 4) | low);
    }
    String::from_utf8(bytes).map_err(|_| String::from("agent returned an invalid key name"))
}

fn hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(String::from("agent returned invalid key-name encoding")),
    }
}

fn os_text<'a>(value: &'a OsString, label: &str) -> Result<&'a str, String> {
    value
        .to_str()
        .ok_or_else(|| format!("{label} is not valid UTF-8"))
}

fn data_directory() -> Result<PathBuf, String> {
    if let Some(data_home) = env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(data_home).join("me.nexryai.keyvisor"));
    }
    home_directory().map(|home| home.join(".local/share/me.nexryai.keyvisor"))
}

fn config_path() -> Result<PathBuf, String> {
    if let Some(config_home) = env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(config_home).join("me.nexryai.keyvisor/config"));
    }
    home_directory().map(|home| home.join(".config/me.nexryai.keyvisor/config"))
}

fn home_directory() -> Result<PathBuf, String> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| String::from("HOME is not set; cannot locate Keyvisor data"))
}

fn store_directory() -> Result<PathBuf, String> {
    data_directory().map(|path| path.join("keys"))
}

fn history_path() -> Result<PathBuf, String> {
    data_directory().map(|path| path.join("history.bin"))
}

fn control_socket_path() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("KEYVISOR_CONTROL_SOCKET").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    let runtime =
        env::var_os("XDG_RUNTIME_DIR").ok_or_else(|| String::from("XDG_RUNTIME_DIR is not set"))?;
    Ok(PathBuf::from(runtime).join("keyvisor/control.sock"))
}

#[cfg(test)]
mod tests {
    use super::{OutputFormat, decode_hex_text, escape_tsv, parse_format, read_pin_line};
    use std::{ffi::OsString, io::Cursor};

    #[test]
    fn parses_versioned_output_format() {
        assert!(matches!(parse_format(&[]), Ok(OutputFormat::Human)));
        assert!(matches!(
            parse_format(&[OsString::from("--format"), OsString::from("tsv")]),
            Ok(OutputFormat::Tsv)
        ));
    }

    #[test]
    fn bounds_and_strips_pin_input() {
        let mut input = Cursor::new(b"123456\n");
        assert_eq!(
            read_pin_line(&mut input, "PIN")
                .expect("valid PIN")
                .as_slice(),
            b"123456"
        );
        let mut short = Cursor::new(b"123\n");
        assert!(read_pin_line(&mut short, "PIN").is_err());
    }

    #[test]
    fn decodes_control_names_and_escapes_tsv() {
        assert_eq!(decode_hex_text("4b6579").expect("decode name"), "Key");
        assert_eq!(escape_tsv("a\tb\n"), "a\\tb\\n");
    }
}
