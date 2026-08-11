//! Keyvisor SSH agent process entry point.
//!
//! The process exposes the SSH-agent socket and a separate owner-only control
//! socket for terminal authorization. It supports native systemd activation.

use std::{
    collections::HashMap,
    env,
    ffi::OsString,
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, SyncSender, TryRecvError},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use keyvisor_agent::{
    KeyStore, StoredKey,
    config::ConfigStore,
    history::{HistoryEntry, HistoryOutcome, HistoryStore},
    protocol::{
        AgentRequest, MAX_PACKET_LENGTH, ecdsa_signature_response, failure_response,
        identities_response, parse_request,
    },
};
use keyvisor_core::KeyUsePolicy;
use keyvisor_tpm::{EsapiTpm, TpmAuthorization, TpmSigner};
use listenfd::ListenFd;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::{net::sockopt::socket_peercred, process::geteuid};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const MAX_PIN_BYTES: usize = 64;
const MAX_CONNECTIONS: usize = 16;
const MAX_CONTROL_LINE_BYTES: u64 = 16 * 1024;
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

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
    Err(String::from("usage: keyvisor-agent [serve|--version]"))
}

fn serve(socket_path: &Path) -> Result<(), String> {
    let parent = socket_path
        .parent()
        .ok_or_else(|| String::from("agent socket path has no parent directory"))?;
    ensure_private_directory(parent)
        .map_err(|error| format!("cannot prepare the agent socket directory: {error}"))?;
    let (listener, _socket_guard) = activated_or_bound_listener(socket_path)?;
    let control_path = default_control_socket_path()?;
    let (control_listener, control_guard) = bind_guarded_socket(&control_path)?;
    let config = ConfigStore::new(default_config_path()?)
        .load()
        .map_err(|error| format!("cannot load configuration: {error}"))?;
    let runtime = Arc::new(AgentRuntime {
        store: KeyStore::new(default_store_directory()?),
        tpm: Mutex::new(None),
        history: Mutex::new(HistoryStore::new(default_history_path()?)),
        history_enabled: config.history_enabled,
        authorization_timeout: Duration::from_secs(config.authorization_timeout_seconds),
        authorizations: Mutex::new(HashMap::new()),
    });
    spawn_control_service(control_listener, control_guard, Arc::clone(&runtime))?;
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
        if !metadata.file_type().is_socket()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.uid() != geteuid().as_raw()
        {
            return Err(String::from(
                "activated Unix socket must be owner-owned with mode 0600",
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
    history_enabled: bool,
    authorization_timeout: Duration,
    authorizations: Mutex<HashMap<String, PendingAuthorization>>,
}

struct PendingAuthorization {
    key_name: String,
    sender: SyncSender<Zeroizing<Vec<u8>>>,
}

fn spawn_control_service(
    listener: UnixListener,
    socket_guard: SocketGuard,
    runtime: Arc<AgentRuntime>,
) -> Result<(), String> {
    thread::Builder::new()
        .name(String::from("keyvisor-control"))
        .spawn(move || {
            let _socket_guard = socket_guard;
            let limiter = Arc::new(ConnectionLimiter::new(MAX_CONNECTIONS));
            for connection in listener.incoming() {
                match connection {
                    Ok(mut stream) => {
                        let permit = limiter.acquire();
                        let runtime = Arc::clone(&runtime);
                        let spawn = thread::Builder::new()
                            .name(String::from("keyvisor-control-client"))
                            .spawn(move || {
                                let _permit = permit;
                                if let Err(error) = serve_control_connection(&mut stream, &runtime)
                                {
                                    let _ = writeln!(stream, "ERR {error}");
                                }
                            });
                        if let Err(error) = spawn {
                            eprintln!("keyvisor-agent: cannot start a control worker: {error}");
                        }
                    }
                    Err(error) => {
                        eprintln!("keyvisor-agent: cannot accept a control client: {error}");
                    }
                }
            }
        })
        .map(|_| ())
        .map_err(|error| format!("cannot start the control service: {error}"))
}

fn serve_control_connection(stream: &mut UnixStream, runtime: &AgentRuntime) -> Result<(), String> {
    let credentials = socket_peercred(&*stream)
        .map_err(|error| format!("cannot authenticate control peer: {error}"))?;
    if credentials.uid != geteuid() {
        return Err(String::from("control peer is not the agent owner"));
    }
    let timeout = Some(Duration::from_secs(5));
    stream.set_read_timeout(timeout).map_err(control_io)?;
    stream.set_write_timeout(timeout).map_err(control_io)?;
    let mut reader = BufReader::new(&mut *stream);
    let command = read_control_line(&mut reader)?;
    match command.as_str() {
        "STATUS" => writeln!(reader.get_mut(), "OK running").map_err(control_io),
        "LIST" => {
            let pending = runtime
                .authorizations
                .lock()
                .map_err(|_| String::from("authorization state is unavailable"))?
                .iter()
                .map(|(id, request)| (id.clone(), request.key_name.clone()))
                .collect::<Vec<_>>();
            writeln!(reader.get_mut(), "OK KEYVISOR-PENDING-1 {}", pending.len())
                .map_err(control_io)?;
            for (id, key_name) in pending {
                writeln!(reader.get_mut(), "{id}\t{}", hex(key_name.as_bytes()))
                    .map_err(control_io)?;
            }
            Ok(())
        }
        _ if command.starts_with("AUTHORIZE ") => {
            let mut fields = command.split_ascii_whitespace();
            if fields.next() != Some("AUTHORIZE") {
                return Err(String::from("invalid authorization command"));
            }
            let id = fields
                .next()
                .ok_or_else(|| String::from("missing request identifier"))?;
            let length = fields
                .next()
                .ok_or_else(|| String::from("missing PIN length"))?
                .parse::<usize>()
                .map_err(|_| String::from("invalid PIN length"))?;
            if fields.next().is_some() || !(6..=MAX_PIN_BYTES).contains(&length) {
                return Err(String::from("invalid authorization command"));
            }
            let mut pin = Zeroizing::new(vec![0_u8; length]);
            reader
                .read_exact(&mut pin)
                .map_err(|error| format!("cannot read authorization value: {error}"))?;
            let request = runtime
                .authorizations
                .lock()
                .map_err(|_| String::from("authorization state is unavailable"))?
                .remove(id)
                .ok_or_else(|| String::from("authorization request is not pending"))?;
            request
                .sender
                .send(pin)
                .map_err(|_| String::from("authorization request is no longer active"))?;
            writeln!(reader.get_mut(), "OK authorized").map_err(control_io)
        }
        _ => Err(String::from("unknown control command")),
    }
}

fn read_control_line(reader: &mut impl BufRead) -> Result<String, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_CONTROL_LINE_BYTES + 1)
        .read_until(b'\n', &mut bytes)
        .map_err(control_io)?;
    if bytes.last() != Some(&b'\n') || bytes.len() as u64 > MAX_CONTROL_LINE_BYTES {
        return Err(String::from("invalid control command"));
    }
    bytes.pop();
    String::from_utf8(bytes).map_err(|_| String::from("control command is not UTF-8"))
}

#[allow(clippy::needless_pass_by_value)]
fn control_io(error: io::Error) -> String {
    format!("control protocol I/O failed: {error}")
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
            KeyUsePolicy::TpmPin => self.request_pin(&key.summary.name, cancellation)?,
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
        if !self.history_enabled {
            return;
        }
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
        if let Err(error) = result {
            eprintln!("keyvisor-agent: could not record signing history: {error}");
        }
    }

    fn request_pin(
        &self,
        key_name: &str,
        cancellation: &RequestCancellation,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let sequence = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let id = format!("{:x}-{sequence:016x}", std::process::id());
        let (sender, receiver) = mpsc::sync_channel(1);
        self.authorizations
            .lock()
            .map_err(|_| String::from("authorization state is unavailable"))?
            .insert(
                id.clone(),
                PendingAuthorization {
                    key_name: key_name.to_owned(),
                    sender,
                },
            );

        // A graphical user session gets a GNOME pinentry prompt automatically.
        // Otherwise the request stays available to `keyvisor authorize` in a
        // terminal. Only the opaque ID and key name leave this process; the SSH
        // payload is never sent over the control channel.
        let mut graphical_authorizer = start_graphical_authorizer(&id);
        let deadline = Instant::now() + self.authorization_timeout;
        let result = loop {
            match receiver.try_recv() {
                Ok(pin) => break Ok(pin),
                Err(TryRecvError::Disconnected) => {
                    break Err(String::from("authorization request was cancelled"));
                }
                Err(TryRecvError::Empty) => {}
            }
            if let Some(child) = graphical_authorizer.as_mut()
                && child.try_wait().ok().flatten().is_some()
            {
                graphical_authorizer = None;
            }
            if Instant::now() >= deadline {
                break Err(String::from("TPM PIN entry timed out"));
            }
            if cancellation.check().is_err() {
                break Err(String::from(
                    "TPM PIN entry cancelled because the SSH client disconnected",
                ));
            }
            thread::sleep(Duration::from_millis(50));
        };
        if let Ok(mut pending) = self.authorizations.lock() {
            pending.remove(&id);
        }
        stop_graphical_authorizer(graphical_authorizer);
        result
    }
}

fn start_graphical_authorizer(id: &str) -> Option<Child> {
    if !graphical_session_available() {
        return None;
    }
    let executable = env::current_exe().ok()?.with_file_name("keyvisor");
    Command::new(executable)
        .args(["authorize", id, "--pinentry"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()
}

fn graphical_session_available() -> bool {
    env::var_os("WAYLAND_DISPLAY").is_some_and(|value| !value.is_empty())
        || env::var_os("DISPLAY").is_some_and(|value| !value.is_empty())
}

fn stop_graphical_authorizer(child: Option<Child>) {
    if let Some(mut child) = child {
        if child.try_wait().ok().flatten().is_none() {
            let _ = child.kill();
        }
        let _ = child.wait();
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

fn bind_guarded_socket(path: &Path) -> Result<(UnixListener, SocketGuard), String> {
    let parent = path
        .parent()
        .ok_or_else(|| String::from("control socket path has no parent directory"))?;
    ensure_private_directory(parent)
        .map_err(|error| format!("cannot prepare the control socket directory: {error}"))?;
    let listener = bind_socket(path)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect the control socket: {error}"))?;
    Ok((
        listener,
        SocketGuard {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    ))
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

fn default_store_directory() -> Result<PathBuf, String> {
    default_data_directory().map(|path| path.join("keys"))
}

fn default_history_path() -> Result<PathBuf, String> {
    default_data_directory().map(|path| path.join("history.bin"))
}

fn default_config_path() -> Result<PathBuf, String> {
    if let Some(config_home) = env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(config_home).join("me.nexryai.keyvisor/config"));
    }
    let home = env::var_os("HOME")
        .ok_or_else(|| String::from("HOME is not set; cannot locate configuration"))?;
    Ok(PathBuf::from(home).join(".config/me.nexryai.keyvisor/config"))
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

fn default_control_socket_path() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("KEYVISOR_CONTROL_SOCKET").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    let runtime_directory = env::var_os("XDG_RUNTIME_DIR").ok_or_else(|| {
        String::from("XDG_RUNTIME_DIR is not set; cannot locate the control socket")
    })?;
    Ok(PathBuf::from(runtime_directory)
        .join("keyvisor")
        .join("control.sock"))
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
        net::Shutdown,
        os::unix::net::UnixStream,
        thread,
        time::{Duration, Instant},
    };

    use super::RequestMonitor;

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
