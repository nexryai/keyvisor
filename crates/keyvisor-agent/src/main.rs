//! Keyvisor SSH agent process entry point.
//!
//! The `generate` command and the SSH-agent socket keep TPM access in this
//! process. The service supports native systemd socket activation.

use std::{
    env,
    ffi::OsString,
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use glib::prelude::ToVariant;
use keyvisor_agent::{
    KeyStore, StoredKey,
    history::{HistoryEntry, HistoryOutcome, HistoryStore},
    protocol::{
        AgentRequest, MAX_PACKET_LENGTH, ecdsa_signature_response, failure_response,
        identities_response, parse_request,
    },
};
use keyvisor_core::{KeyAlgorithm, KeyUsePolicy};
use keyvisor_tpm::{EsapiTpm, TpmAuthorization, TpmSigner};
use listenfd::ListenFd;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const MAX_PIN_BYTES: usize = 64;
const MAX_CONNECTIONS: usize = 16;
const PIN_PROMPT_TIMEOUT: Duration = Duration::from_mins(2);
const DBUS_NAME: &str = "me.nexryai.keyvisor.Agent";
const DBUS_PATH: &str = "/me/nexryai/keyvisor/Agent";
const DBUS_INTERFACE: &str = "me.nexryai.keyvisor.Agent1";
const DBUS_ERROR: &str = "me.nexryai.keyvisor.Agent.Error";
const DBUS_XML: &str = r#"
<node>
  <interface name="me.nexryai.keyvisor.Agent1">
    <method name="ListKeys">
      <arg name="keys" type="a(sssay)" direction="out"/>
    </method>
    <method name="GetHistory">
      <arg name="entries" type="a(tssss)" direction="out"/>
    </method>
    <method name="DeleteKey">
      <arg name="id" type="s" direction="in"/>
    </method>
    <signal name="KeysChanged"/>
    <signal name="HistoryChanged">
      <arg name="timestamp" type="t"/>
      <arg name="key_id" type="s"/>
      <arg name="key_name" type="s"/>
      <arg name="policy" type="s"/>
      <arg name="outcome" type="s"/>
    </signal>
  </interface>
</node>
"#;

fn main() {
    if let Err(message) = run() {
        eprintln!("keyvisor-agent: {message}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments == [OsString::from("--version")] {
        println!("keyvisor-agent {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if arguments.is_empty() || arguments == [OsString::from("serve")] {
        let socket_path = default_socket_path()?;
        return serve(&socket_path);
    }
    if arguments == [OsString::from("list")] {
        return list_keys();
    }
    if let [command, id] = arguments.as_slice()
        && command == "delete"
    {
        return delete_key(id);
    }

    let request = parse_generate_request(&arguments)?;
    let pin = read_pin(request.use_policy)?;
    let authorization = match request.use_policy {
        KeyUsePolicy::NoPin => TpmAuthorization::None,
        KeyUsePolicy::TpmPin => TpmAuthorization::Pin(&pin),
    };

    let mut tpm =
        EsapiTpm::connect_default().map_err(|error| format!("cannot open the TPM: {error}"))?;
    let (summary, object) = tpm
        .generate(&request.name, KeyAlgorithm::EcdsaNistP256, authorization)
        .map_err(|error| format!("cannot generate the TPM key: {error}"))?;
    let id = summary.id.as_str().to_owned();
    KeyStore::new(default_store_directory()?)
        .save(&StoredKey { summary, object })
        .map_err(|error| format!("cannot persist the wrapped TPM key: {error}"))?;

    println!("{id}");
    Ok(())
}

fn list_keys() -> Result<(), String> {
    let keys = KeyStore::new(default_store_directory()?)
        .list()
        .map_err(|error| format!("cannot list wrapped TPM keys: {error}"))?;
    let stdout = io::stdout();
    let mut output = io::BufWriter::new(stdout.lock());
    writeln!(output, "KEYVISOR-LIST-1")
        .map_err(|error| format!("cannot write key list: {error}"))?;
    for key in keys {
        let policy = match key.summary.use_policy {
            KeyUsePolicy::NoPin => "none",
            KeyUsePolicy::TpmPin => "pin",
        };
        writeln!(
            output,
            "{}\t{}\t{}\t{}",
            key.summary.id.as_str(),
            policy,
            hex(key.summary.name.as_bytes()),
            hex(&key.summary.public_key),
        )
        .map_err(|error| format!("cannot write key list: {error}"))?;
    }
    output
        .flush()
        .map_err(|error| format!("cannot flush key list: {error}"))
}

fn delete_key(id: &OsString) -> Result<(), String> {
    let id = id
        .to_str()
        .ok_or_else(|| String::from("key identifier is not valid UTF-8"))?;
    KeyStore::new(default_store_directory()?)
        .delete(&keyvisor_core::KeyId::new(id))
        .map_err(|error| format!("cannot delete the wrapped TPM key: {error}"))
}

fn serve(socket_path: &Path) -> Result<(), String> {
    let parent = socket_path
        .parent()
        .ok_or_else(|| String::from("agent socket path has no parent directory"))?;
    ensure_private_directory(parent)
        .map_err(|error| format!("cannot prepare the agent socket directory: {error}"))?;
    let (listener, _socket_guard) = activated_or_bound_listener(socket_path)?;
    let runtime = Arc::new(AgentRuntime {
        store: KeyStore::new(default_store_directory()?),
        tpm: Mutex::new(None),
        history: Mutex::new(HistoryStore::new(default_history_path()?)),
        events: ManagementEvents::new(),
    });
    spawn_management_service(Arc::clone(&runtime))?;
    let limiter = Arc::new(ConnectionLimiter::new(MAX_CONNECTIONS));

    for connection in listener.incoming() {
        match connection {
            Ok(mut stream) => {
                let permit = limiter.acquire();
                let runtime = Arc::clone(&runtime);
                let spawn = thread::Builder::new()
                    .name(String::from("keyvisor-client"))
                    .spawn(move || {
                        let _permit = permit;
                        if let Err(error) = serve_connection(&mut stream, &runtime) {
                            eprintln!("keyvisor-agent: client connection ended: {error}");
                        }
                    });
                if let Err(error) = spawn {
                    eprintln!("keyvisor-agent: cannot start a client worker: {error}");
                }
            }
            Err(error) => eprintln!("keyvisor-agent: cannot accept a client: {error}"),
        }
    }
    Ok(())
}

fn activated_or_bound_listener(path: &Path) -> Result<(UnixListener, Option<SocketGuard>), String> {
    let mut inherited = ListenFd::from_env();
    if inherited.len() > 1 {
        return Err(String::from(
            "systemd passed more than one socket; refusing ambiguous activation",
        ));
    }
    if let Some(listener) = inherited
        .take_unix_listener(0)
        .map_err(|error| format!("cannot accept the activated Unix socket: {error}"))?
    {
        // Socket activation is not trusted implicitly. Validate both the
        // address and owner-only mode before accepting SSH requests on an
        // inherited descriptor.
        let address = listener
            .local_addr()
            .map_err(|error| format!("cannot inspect the activated Unix socket: {error}"))?;
        if address.as_pathname() != Some(path) {
            return Err(String::from(
                "activated Unix socket does not match KEYVISOR_AGENT_SOCKET",
            ));
        }
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect the activated Unix socket: {error}"))?;
        if !metadata.file_type().is_socket() || metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(String::from(
                "activated Unix socket must be a mode 0600 socket",
            ));
        }
        return Ok((listener, None));
    }

    let listener = bind_socket(path)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect the agent socket: {error}"))?;
    Ok((
        listener,
        Some(SocketGuard {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        }),
    ))
}

struct AgentRuntime {
    store: KeyStore,
    tpm: Mutex<Option<EsapiTpm>>,
    history: Mutex<HistoryStore>,
    events: ManagementEvents,
}

struct ManagementEvents {
    // The session bus authenticates the desktop user. Only public metadata and
    // result events are emitted on this connection; PINs, wrapped blobs, and
    // SSH payloads never enter the management API.
    connection: Mutex<Option<gio::DBusConnection>>,
}

impl ManagementEvents {
    const fn new() -> Self {
        Self {
            connection: Mutex::new(None),
        }
    }

    fn set_connection(&self, connection: gio::DBusConnection) {
        if let Ok(mut current) = self.connection.lock() {
            *current = Some(connection);
        }
    }

    fn clear_connection(&self) {
        if let Ok(mut current) = self.connection.lock() {
            *current = None;
        }
    }

    fn history_changed(&self, entry: &HistoryEntry) {
        self.emit(
            "HistoryChanged",
            &(
                entry.timestamp_seconds,
                entry.key_id.as_str(),
                entry.key_name.as_str(),
                policy_name(entry.use_policy),
                outcome_name(entry.outcome),
            )
                .to_variant(),
        );
    }

    fn keys_changed(&self) {
        self.emit("KeysChanged", &().to_variant());
    }

    fn emit(&self, signal: &str, parameters: &glib::Variant) {
        let connection = self
            .connection
            .lock()
            .ok()
            .and_then(|connection| connection.clone());
        if let Some(connection) = connection
            && let Err(error) =
                connection.emit_signal(None, DBUS_PATH, DBUS_INTERFACE, signal, Some(parameters))
        {
            eprintln!("keyvisor-agent: cannot emit {signal}: {error}");
        }
    }
}

fn spawn_management_service(runtime: Arc<AgentRuntime>) -> Result<(), String> {
    thread::Builder::new()
        .name(String::from("keyvisor-dbus"))
        .spawn(move || {
            // Management UI is optional. Losing D-Bus must not stop identity
            // enumeration or no-PIN signing on the SSH agent socket.
            if let Err(error) = run_management_service(&runtime) {
                eprintln!("keyvisor-agent: management API unavailable: {error}");
            }
        })
        .map(|_| ())
        .map_err(|error| format!("cannot start the management API worker: {error}"))
}

fn run_management_service(runtime: &Arc<AgentRuntime>) -> Result<(), String> {
    let context = glib::MainContext::new();
    context
        .with_thread_default(|| {
            let connection = gio::bus_get_sync(gio::BusType::Session, None::<&gio::Cancellable>)
                .map_err(|error| format!("cannot connect to the session bus: {error}"))?;
            let node = gio::DBusNodeInfo::for_xml(DBUS_XML)
                .map_err(|error| format!("invalid management API definition: {error}"))?;
            let interface = node
                .lookup_interface(DBUS_INTERFACE)
                .ok_or_else(|| String::from("management interface definition is missing"))?;
            let method_runtime = Arc::clone(runtime);
            let _registration = connection
                .register_object(DBUS_PATH, &interface)
                .method_call(move |_, sender, _, _, method, parameters, invocation| {
                    if sender.is_none() {
                        invocation.return_dbus_error(
                            DBUS_ERROR,
                            "anonymous management calls are not accepted",
                        );
                        return;
                    }
                    dispatch_management_call(&method_runtime, method, &parameters, invocation);
                })
                .build()
                .map_err(|error| format!("cannot export the management object: {error}"))?;
            let acquired_runtime = Arc::clone(runtime);
            let lost_runtime = Arc::clone(runtime);
            let _owner = gio::bus_own_name_on_connection(
                &connection,
                DBUS_NAME,
                gio::BusNameOwnerFlags::NONE,
                move |connection, _| {
                    acquired_runtime.events.set_connection(connection);
                },
                move |_, _| {
                    lost_runtime.events.clear_connection();
                },
            );
            glib::MainLoop::new(Some(&context), false).run();
            Ok::<(), String>(())
        })
        .map_err(|error| format!("cannot acquire the D-Bus main context: {error}"))?
}

fn dispatch_management_call(
    runtime: &AgentRuntime,
    method: &str,
    parameters: &glib::Variant,
    invocation: gio::DBusMethodInvocation,
) {
    // Keep this API intentionally narrower than the SSH agent and TPM APIs:
    // it exposes display-safe metadata plus explicit record deletion only.
    let result = match method {
        "ListKeys" => runtime
            .store
            .list()
            .map_err(|error| error.to_string())
            .map(|keys| {
                let keys = keys
                    .into_iter()
                    .map(|key| {
                        (
                            key.summary.id.as_str().to_owned(),
                            key.summary.name,
                            policy_name(key.summary.use_policy).to_owned(),
                            key.summary.public_key,
                        )
                    })
                    .collect::<Vec<_>>();
                (keys,).to_variant()
            }),
        "GetHistory" => runtime
            .history
            .lock()
            .map_err(|_| String::from("signing history state is unavailable"))
            .and_then(|history| history.list().map_err(|error| error.to_string()))
            .map(|entries| {
                let entries = entries
                    .into_iter()
                    .map(|entry| {
                        (
                            entry.timestamp_seconds,
                            entry.key_id.as_str().to_owned(),
                            entry.key_name,
                            policy_name(entry.use_policy).to_owned(),
                            outcome_name(entry.outcome).to_owned(),
                        )
                    })
                    .collect::<Vec<_>>();
                (entries,).to_variant()
            }),
        "DeleteKey" => parameters
            .get::<(String,)>()
            .ok_or_else(|| String::from("invalid DeleteKey parameters"))
            .and_then(|(id,)| {
                runtime
                    .store
                    .delete(&keyvisor_core::KeyId::new(id))
                    .map_err(|error| error.to_string())
            })
            .map(|()| {
                runtime.events.keys_changed();
                ().to_variant()
            }),
        _ => Err(format!("unknown management method {method}")),
    };

    match result {
        Ok(value) => invocation.return_value(Some(&value)),
        Err(error) => invocation.return_dbus_error(DBUS_ERROR, &error),
    }
}

const fn policy_name(policy: KeyUsePolicy) -> &'static str {
    match policy {
        KeyUsePolicy::NoPin => "none",
        KeyUsePolicy::TpmPin => "pin",
    }
}

const fn outcome_name(outcome: HistoryOutcome) -> &'static str {
    match outcome {
        HistoryOutcome::Succeeded => "succeeded",
        HistoryOutcome::Failed => "failed",
    }
}

impl AgentRuntime {
    fn handle(&self, packet: &[u8], cancellation: &RequestCancellation) -> Result<Vec<u8>, String> {
        cancellation.check()?;
        match parse_request(packet).map_err(|error| error.to_string())? {
            AgentRequest::RequestIdentities => {
                let summaries = self
                    .store
                    .list()
                    .map_err(|error| error.to_string())?
                    .into_iter()
                    .map(|key| key.summary)
                    .collect::<Vec<_>>();
                identities_response(&summaries).map_err(|error| error.to_string())
            }
            AgentRequest::Sign {
                public_key,
                data,
                flags,
            } => {
                if flags != 0 {
                    return Err(String::from("unsupported SSH signature flags"));
                }
                let key = self
                    .store
                    .list()
                    .map_err(|error| error.to_string())?
                    .into_iter()
                    .find(|key| key.summary.public_key == public_key)
                    .ok_or_else(|| String::from("requested identity is unknown"))?;
                let result = self.sign_with_key(&key, data, cancellation);
                self.record_history(
                    &key,
                    if result.is_ok() {
                        HistoryOutcome::Succeeded
                    } else {
                        HistoryOutcome::Failed
                    },
                );
                result
            }
        }
    }

    fn sign_with_key(
        &self,
        key: &StoredKey,
        data: &[u8],
        cancellation: &RequestCancellation,
    ) -> Result<Vec<u8>, String> {
        let digest = Sha256::digest(data);
        // Prompt before taking the TPM mutex so another client can enumerate
        // identities or complete its authorization while the user is typing.
        let pin = match key.summary.use_policy {
            KeyUsePolicy::NoPin => Zeroizing::new(Vec::new()),
            KeyUsePolicy::TpmPin => prompt_for_pin(&key.summary.name, cancellation)?,
        };
        cancellation.check()?;
        let authorization = match key.summary.use_policy {
            KeyUsePolicy::NoPin => TpmAuthorization::None,
            KeyUsePolicy::TpmPin => TpmAuthorization::Pin(&pin),
        };

        let mut tpm = self
            .tpm
            .lock()
            .map_err(|_| String::from("TPM signer state is unavailable"))?;
        if tpm.is_none() {
            *tpm = Some(
                EsapiTpm::connect_default()
                    .map_err(|error| format!("cannot open the TPM: {error}"))?,
            );
        }
        let signer = tpm
            .as_mut()
            .ok_or_else(|| String::from("TPM signer did not initialize"))?;
        let signature = signer
            .sign(&key.object, &digest, authorization)
            .map_err(|error| format!("TPM signing failed: {error}"))?;
        // ESAPI signing is synchronous and cannot be interrupted safely.
        // Discard its result if the requesting client disconnected meanwhile.
        cancellation.check()?;
        ecdsa_signature_response(&signature).map_err(|error| error.to_string())
    }

    fn record_history(&self, key: &StoredKey, outcome: HistoryOutcome) {
        // Record only which key was requested and the outcome. The signed
        // bytes and their digest are intentionally absent from this structure.
        let timestamp_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let entry = HistoryEntry {
            timestamp_seconds,
            key_id: key.summary.id.clone(),
            key_name: key.summary.name.clone(),
            use_policy: key.summary.use_policy,
            outcome,
        };
        let result = self
            .history
            .lock()
            .map_err(|_| String::from("signing history state is unavailable"))
            .and_then(|history| {
                history
                    .append(entry.clone())
                    .map_err(|error| error.to_string())
            });
        match result {
            Ok(()) => self.events.history_changed(&entry),
            Err(error) => {
                eprintln!("keyvisor-agent: could not record signing history: {error}");
            }
        }
    }
}

fn serve_connection(stream: &mut UnixStream, runtime: &AgentRuntime) -> Result<(), String> {
    let timeout = Some(Duration::from_secs(15));
    stream
        .set_read_timeout(timeout)
        .map_err(|error| format!("cannot set read timeout: {error}"))?;
    stream
        .set_write_timeout(timeout)
        .map_err(|error| format!("cannot set write timeout: {error}"))?;

    loop {
        let Some(length) = read_packet_length(stream)? else {
            return Ok(());
        };
        if length == 0 || length > MAX_PACKET_LENGTH {
            let _ = stream.write_all(&failure_response());
            return Err(String::from("invalid SSH agent packet length"));
        }

        let mut packet = vec![0_u8; length];
        stream
            .read_exact(&mut packet)
            .map_err(|error| format!("cannot read SSH agent packet: {error}"))?;
        let monitor = RequestMonitor::start(stream)?;
        let response = runtime
            .handle(&packet, monitor.cancellation())
            .unwrap_or_else(|_| failure_response());
        drop(monitor);
        stream
            .write_all(&response)
            .map_err(|error| format!("cannot write SSH agent response: {error}"))?;
    }
}

struct RequestCancellation {
    cancelled: AtomicBool,
}

impl RequestCancellation {
    const fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
        }
    }

    fn check(&self) -> Result<(), String> {
        if self.cancelled.load(Ordering::Relaxed) {
            Err(String::from("SSH client disconnected"))
        } else {
            Ok(())
        }
    }
}

struct RequestMonitor {
    cancellation: Arc<RequestCancellation>,
    stopped: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl RequestMonitor {
    fn start(stream: &UnixStream) -> Result<Self, String> {
        let monitored_stream = stream
            .try_clone()
            .map_err(|error| format!("cannot monitor the SSH client: {error}"))?;
        let cancellation = Arc::new(RequestCancellation::new());
        let stopped = Arc::new(AtomicBool::new(false));
        let thread_cancellation = Arc::clone(&cancellation);
        let thread_stopped = Arc::clone(&stopped);
        let worker = thread::Builder::new()
            .name(String::from("keyvisor-client-monitor"))
            .spawn(move || {
                let timeout = Timespec {
                    tv_sec: 0,
                    tv_nsec: 50_000_000,
                };
                let mut descriptors = [PollFd::new(
                    &monitored_stream,
                    PollFlags::HUP | PollFlags::ERR,
                )];
                // Watch only terminal events. Reading or polling for normal
                // input here could consume a pipelined request, while RDHUP
                // would incorrectly cancel clients that only half-close writes.
                while !thread_stopped.load(Ordering::Relaxed) {
                    match poll(&mut descriptors, Some(&timeout)) {
                        Ok(0) => {}
                        Ok(_) => {
                            let events = descriptors[0].revents();
                            if events.intersects(PollFlags::HUP | PollFlags::ERR) {
                                thread_cancellation.cancelled.store(true, Ordering::Relaxed);
                                return;
                            }
                            descriptors[0].clear_revents();
                        }
                        Err(_) => {
                            thread_cancellation.cancelled.store(true, Ordering::Relaxed);
                            return;
                        }
                    }
                }
            })
            .map_err(|error| format!("cannot start the SSH client monitor: {error}"))?;
        Ok(Self {
            cancellation,
            stopped,
            worker: Some(worker),
        })
    }

    fn cancellation(&self) -> &RequestCancellation {
        &self.cancellation
    }
}

impl Drop for RequestMonitor {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct ConnectionLimiter {
    maximum: usize,
    active: Mutex<usize>,
    available: Condvar,
}

impl ConnectionLimiter {
    const fn new(maximum: usize) -> Self {
        Self {
            maximum,
            active: Mutex::new(0),
            available: Condvar::new(),
        }
    }

    fn acquire(self: &Arc<Self>) -> ConnectionPermit {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *active >= self.maximum {
            active = self
                .available
                .wait(active)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        *active += 1;
        ConnectionPermit {
            limiter: Arc::clone(self),
        }
    }
}

struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let mut active = self
            .limiter
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *active = active.saturating_sub(1);
        self.limiter.available.notify_one();
    }
}

fn read_packet_length(stream: &mut UnixStream) -> Result<Option<usize>, String> {
    let mut bytes = [0_u8; 4];
    match stream.read(&mut bytes[..1]) {
        Ok(0) => return Ok(None),
        Ok(1) => {}
        Ok(_) => unreachable!("one-byte read returned more than one byte"),
        Err(error) => return Err(format!("cannot read SSH agent packet length: {error}")),
    }
    stream
        .read_exact(&mut bytes[1..])
        .map_err(|error| format!("cannot read SSH agent packet length: {error}"))?;
    usize::try_from(u32::from_be_bytes(bytes))
        .map(Some)
        .map_err(|_| String::from("SSH agent packet length does not fit this platform"))
}

fn bind_socket(path: &Path) -> Result<UnixListener, String> {
    match UnixListener::bind(path) {
        Ok(listener) => finish_socket_bind(path, listener),
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
            let metadata = fs::symlink_metadata(path)
                .map_err(|inspect| format!("cannot inspect existing agent socket: {inspect}"))?;
            if !metadata.file_type().is_socket() {
                return Err(String::from(
                    "agent socket path exists and is not a Unix socket",
                ));
            }
            if UnixStream::connect(path).is_ok() {
                return Err(String::from("another Keyvisor agent is already running"));
            }
            fs::remove_file(path)
                .map_err(|remove| format!("cannot remove stale agent socket: {remove}"))?;
            finish_socket_bind(
                path,
                UnixListener::bind(path)
                    .map_err(|bind| format!("cannot bind the agent socket: {bind}"))?,
            )
        }
        Err(error) => Err(format!("cannot bind the agent socket: {error}")),
    }
}

fn finish_socket_bind(path: &Path, listener: UnixListener) -> Result<UnixListener, String> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("cannot protect the agent socket: {error}"))?;
    Ok(listener)
}

fn ensure_private_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "agent socket directory must already be private",
                ));
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        }
        Err(error) => Err(error),
    }
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        // Match device and inode so shutdown cannot unlink a replacement file
        // that appeared at the same pathname after the original bind.
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

struct GenerateRequest {
    name: String,
    use_policy: KeyUsePolicy,
}

fn parse_generate_request(arguments: &[OsString]) -> Result<GenerateRequest, String> {
    if arguments.len() != 5
        || arguments[0] != "generate"
        || arguments[1] != "--name"
        || arguments[3] != "--authorization"
    {
        return Err(String::from(
            "usage: keyvisor-agent generate --name NAME --authorization none|pin",
        ));
    }

    let name = arguments[2]
        .to_str()
        .ok_or_else(|| String::from("key name is not valid UTF-8"))?
        .trim()
        .to_owned();
    if name.is_empty() || name.len() > 4 * 1024 {
        return Err(String::from("key name must be between 1 and 4096 bytes"));
    }

    let use_policy = match arguments[4].to_str() {
        Some("none") => KeyUsePolicy::NoPin,
        Some("pin") => KeyUsePolicy::TpmPin,
        _ => return Err(String::from("authorization must be either none or pin")),
    };
    Ok(GenerateRequest { name, use_policy })
}

fn read_pin(use_policy: KeyUsePolicy) -> Result<Zeroizing<Vec<u8>>, String> {
    if use_policy == KeyUsePolicy::NoPin {
        return Ok(Zeroizing::new(Vec::new()));
    }

    let mut pin = Zeroizing::new(Vec::new());
    io::stdin()
        .take(u64::try_from(MAX_PIN_BYTES + 1).expect("PIN limit fits u64"))
        .read_to_end(&mut pin)
        .map_err(|error| format!("cannot read PIN from stdin: {error}"))?;
    if !(6..=MAX_PIN_BYTES).contains(&pin.len()) {
        return Err(format!("PIN must be between 6 and {MAX_PIN_BYTES} bytes"));
    }
    Ok(pin)
}

fn prompt_for_pin(
    key_name: &str,
    cancellation: &RequestCancellation,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let helper =
        env::var_os("KEYVISOR_PIN_HELPER_PATH").unwrap_or_else(|| OsString::from("keyvisor"));
    let mut child = Command::new(helper)
        .args(["--authorize", key_name])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| String::from("cannot start the TPM PIN prompt"))?;
    // The helper returns the PIN through a private pipe, never an argument,
    // environment variable, log message, or persistent desktop setting.
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| String::from("TPM PIN prompt has no private output pipe"))?;
    let deadline = Instant::now() + PIN_PROMPT_TIMEOUT;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| String::from("cannot wait for the TPM PIN prompt"))?
        {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(String::from("TPM PIN entry timed out"));
        }
        if cancellation.check().is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(String::from(
                "TPM PIN entry cancelled because the SSH client disconnected",
            ));
        }
        thread::sleep(Duration::from_millis(50));
    };
    if !status.success() {
        return Err(String::from("TPM PIN entry was cancelled"));
    }
    cancellation.check()?;
    let mut pin = Zeroizing::new(Vec::new());
    // Read one byte beyond the accepted maximum so oversized helper output is
    // rejected instead of silently truncated into a different PIN.
    stdout
        .take(u64::try_from(MAX_PIN_BYTES + 1).expect("PIN limit fits u64"))
        .read_to_end(&mut pin)
        .map_err(|_| String::from("cannot read the TPM PIN prompt result"))?;
    if !(6..=MAX_PIN_BYTES).contains(&pin.len()) {
        return Err(String::from("TPM PIN prompt returned an invalid value"));
    }
    Ok(pin)
}

fn default_store_directory() -> Result<PathBuf, String> {
    default_data_directory().map(|path| path.join("keys"))
}

fn default_history_path() -> Result<PathBuf, String> {
    default_data_directory().map(|path| path.join("history.bin"))
}

fn default_data_directory() -> Result<PathBuf, String> {
    if let Some(data_home) = env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(data_home).join("me.nexryai.keyvisor"));
    }

    let home = env::var_os("HOME").ok_or_else(|| {
        String::from("neither XDG_DATA_HOME nor HOME is set; cannot locate the key store")
    })?;
    Ok(PathBuf::from(home)
        .join(".local/share")
        .join("me.nexryai.keyvisor"))
}

fn default_socket_path() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("KEYVISOR_AGENT_SOCKET").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    let runtime_directory = env::var_os("XDG_RUNTIME_DIR").ok_or_else(|| {
        String::from("XDG_RUNTIME_DIR is not set; cannot locate the agent socket")
    })?;
    Ok(PathBuf::from(runtime_directory)
        .join("keyvisor")
        .join("agent.sock"))
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsString,
        net::Shutdown,
        os::unix::net::UnixStream,
        thread,
        time::{Duration, Instant},
    };

    use keyvisor_core::KeyUsePolicy;

    use super::{RequestMonitor, parse_generate_request};

    #[test]
    fn parses_pin_generate_request() {
        let arguments = [
            OsString::from("generate"),
            OsString::from("--name"),
            OsString::from("Work"),
            OsString::from("--authorization"),
            OsString::from("pin"),
        ];
        let request = parse_generate_request(&arguments).expect("parse request");
        assert_eq!(request.name, "Work");
        assert_eq!(request.use_policy, KeyUsePolicy::TpmPin);
    }

    #[test]
    fn rejects_unknown_authorization() {
        let arguments = [
            OsString::from("generate"),
            OsString::from("--name"),
            OsString::from("Work"),
            OsString::from("--authorization"),
            OsString::from("prompt"),
        ];
        assert!(parse_generate_request(&arguments).is_err());
    }

    #[test]
    fn detects_client_disconnect() {
        let (server, client) = UnixStream::pair().expect("create Unix socket pair");
        let monitor = RequestMonitor::start(&server).expect("start client monitor");
        drop(client);
        let deadline = Instant::now() + Duration::from_secs(1);
        while monitor.cancellation().check().is_ok() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(monitor.cancellation().check().is_err());
    }

    #[test]
    fn permits_client_write_half_close() {
        let (server, client) = UnixStream::pair().expect("create Unix socket pair");
        let monitor = RequestMonitor::start(&server).expect("start client monitor");
        client
            .shutdown(Shutdown::Write)
            .expect("half-close client write side");
        thread::sleep(Duration::from_millis(100));
        assert!(monitor.cancellation().check().is_ok());
    }
}
