#![cfg(unix)]

//! End-to-end tests for the security boundary exposed through `SSH_AUTH_SOCK`.
//!
//! Each test starts an isolated TPM simulator and the real agent executable.
//! The tests intentionally exercise process, socket, persistence, and TPM
//! boundaries together instead of replacing them with in-process mocks.

use std::{
    fs,
    io::{BufRead, Read, Write},
    net::TcpListener,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use keyvisor_agent::KeyStore;
use keyvisor_core::{KeyAlgorithm, KeyUsePolicy};
use keyvisor_tpm::{EsapiTpm, TpmAuthorization, TpmSigner};

struct TestEnvironment {
    swtpm: Child,
    agent: Option<Child>,
    root: PathBuf,
    tcti: String,
}

impl TestEnvironment {
    fn start() -> Self {
        let root = std::env::temp_dir().join(format!(
            "keyvisor-agent-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock must follow Unix epoch")
                .as_nanos()
        ));
        let state = root.join("swtpm");
        fs::create_dir_all(&state).expect("create swtpm state");
        let (server_port, control_port) = unused_port_pair();
        let mut swtpm = Command::new("swtpm")
            .args([
                "socket",
                "--tpm2",
                "--tpmstate",
                &format!("dir={}", state.display()),
                "--server",
                &format!("type=tcp,port={server_port}"),
                "--ctrl",
                &format!("type=tcp,port={control_port}"),
                "--flags",
                "not-need-init,startup-clear",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start swtpm");
        let tcti = format!("swtpm:host=127.0.0.1,port={server_port}");

        for _ in 0..100 {
            if EsapiTpm::connect(&tcti).is_ok() {
                return Self {
                    swtpm,
                    agent: None,
                    root,
                    tcti,
                };
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = swtpm.kill();
        let _ = swtpm.wait();
        panic!("swtpm did not become ready");
    }

    fn data_home(&self) -> PathBuf {
        self.root.join("data")
    }

    fn socket_path(&self) -> PathBuf {
        self.root.join("runtime/keyvisor/agent.sock")
    }

    fn control_path(&self) -> PathBuf {
        self.root.join("runtime/keyvisor/control.sock")
    }

    fn generate(&self, name: &str, authorization: &str, pin: &[u8]) {
        let authorization = match authorization {
            "none" => TpmAuthorization::None,
            "pin" => TpmAuthorization::Pin(pin),
            _ => panic!("unexpected test authorization"),
        };
        let mut tpm = EsapiTpm::connect(&self.tcti).expect("connect generation TPM");
        let (summary, object) = tpm
            .generate(name, KeyAlgorithm::EcdsaNistP256, authorization)
            .expect("generate test key");
        KeyStore::new(store_directory(&self.data_home()))
            .save(&keyvisor_agent::StoredKey { summary, object })
            .expect("persist test key");
    }

    fn start_agent(&mut self) -> UnixStream {
        let socket_path = self.socket_path();
        self.agent = Some(
            Command::new(env!("CARGO_BIN_EXE_keyvisor-agent"))
                .arg("serve")
                .env("TPM2TOOLS_TCTI", &self.tcti)
                .env("XDG_DATA_HOME", self.data_home())
                .env("XDG_CONFIG_HOME", self.root.join("config"))
                .env("KEYVISOR_AGENT_SOCKET", &socket_path)
                .env("KEYVISOR_CONTROL_SOCKET", self.control_path())
                .env_remove("DISPLAY")
                .env_remove("WAYLAND_DISPLAY")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("start agent"),
        );

        for _ in 0..100 {
            if let Ok(stream) = UnixStream::connect(&socket_path) {
                return stream;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("agent socket did not become ready");
    }

    fn openssh_command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        // Limit the external client to this test's socket so a developer's
        // desktop agent can never satisfy the test accidentally.
        command.env("SSH_AUTH_SOCK", self.socket_path());
        command
    }

    fn delete(&self, id: &str) {
        KeyStore::new(store_directory(&self.data_home()))
            .delete(&keyvisor_core::KeyId::new(id))
            .expect("delete test key");
    }

    fn authorize_pending(&self, pin: &[u8]) {
        let mut request_id = None;
        for _ in 0..100 {
            if let Ok(mut stream) = UnixStream::connect(self.control_path()) {
                stream.write_all(b"LIST\n").expect("list pending requests");
                let mut reader = std::io::BufReader::new(stream);
                let mut header = String::new();
                reader.read_line(&mut header).expect("read pending header");
                if header == "OK KEYVISOR-PENDING-1 1\n" {
                    let mut request = String::new();
                    reader
                        .read_line(&mut request)
                        .expect("read pending request");
                    request_id = Some(
                        request
                            .split_once('\t')
                            .expect("pending request fields")
                            .0
                            .to_owned(),
                    );
                    break;
                }
            }
            thread::sleep(Duration::from_millis(20));
        }
        let id = request_id.expect("pending authorization appears");

        let mut approval = UnixStream::connect(self.control_path()).expect("connect approval");
        writeln!(approval, "AUTHORIZE {id} {}", pin.len()).expect("write approval header");
        approval.write_all(pin).expect("write approval PIN");
        let mut response = String::new();
        std::io::BufReader::new(approval)
            .read_line(&mut response)
            .expect("read approval response");
        assert_eq!(response, "OK authorized\n");
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        if let Some(mut agent) = self.agent.take() {
            let _ = agent.kill();
            let _ = agent.wait();
        }
        let _ = self.swtpm.kill();
        let _ = self.swtpm.wait();
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn unused_port_pair() -> (u16, u16) {
    for _ in 0..100 {
        let server = TcpListener::bind(("127.0.0.1", 0)).expect("reserve swtpm server port");
        let server_port = server.local_addr().expect("server address").port();
        let Some(control_port) = server_port.checked_add(1) else {
            continue;
        };
        if let Ok(control) = TcpListener::bind(("127.0.0.1", control_port)) {
            // Dropping both reservations immediately before spawning swtpm
            // leaves a small race, but selecting adjacent free ports matches
            // the simulator's server/control interface requirement.
            drop(control);
            drop(server);
            return (server_port, control_port);
        }
    }
    panic!("could not reserve adjacent swtpm ports");
}

fn send_request(stream: &mut UnixStream, payload: &[u8]) -> Vec<u8> {
    stream
        .write_all(
            &u32::try_from(payload.len())
                .expect("test packet fits")
                .to_be_bytes(),
        )
        .expect("write request length");
    stream.write_all(payload).expect("write request payload");

    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .expect("read response length");
    let mut response =
        vec![0_u8; usize::try_from(u32::from_be_bytes(length)).expect("response length fits")];
    stream
        .read_exact(&mut response)
        .expect("read response payload");
    response
}

fn push_string(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .expect("test string fits")
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
}

fn sign_request(public_key: &[u8]) -> Vec<u8> {
    let mut request = vec![13];
    push_string(&mut request, public_key);
    push_string(&mut request, b"bounded SSH challenge");
    request.extend_from_slice(&0_u32.to_be_bytes());
    request
}

fn store_directory(data_home: &Path) -> PathBuf {
    data_home.join("me.nexryai.keyvisor/keys")
}

#[test]
fn serves_identities_and_signs_with_both_authorization_modes() {
    let mut environment = TestEnvironment::start();
    environment.generate("Automation", "none", b"");
    environment.generate("Interactive", "pin", b"123456");

    let store = KeyStore::new(store_directory(&environment.data_home()));
    let keys = store.list().expect("load generated test keys");
    assert_eq!(keys.len(), 2);
    let no_pin = keys
        .iter()
        .find(|key| key.summary.use_policy == KeyUsePolicy::NoPin)
        .expect("no-PIN key exists");
    let pin = keys
        .iter()
        .find(|key| key.summary.use_policy == KeyUsePolicy::TpmPin)
        .expect("PIN key exists");

    let mut stream = environment.start_agent();
    // SSH_AUTH_SOCK is a same-user security boundary. A group- or
    // world-accessible socket would allow unintended local clients to sign.
    assert_eq!(
        fs::symlink_metadata(environment.socket_path())
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    // The hand-written protocol request checks the exact identity response
    // type and count independently of OpenSSH's friendlier output.
    let identities = send_request(&mut stream, &[11]);
    assert_eq!(identities[0], 12);
    assert_eq!(&identities[1..5], &2_u32.to_be_bytes());

    // The listening loop must continue serving a second client while the first
    // connection remains open, as happens with multiple terminal sessions.
    let mut concurrent =
        UnixStream::connect(environment.socket_path()).expect("open concurrent agent connection");
    let concurrent_identities = send_request(&mut concurrent, &[11]);
    assert_eq!(concurrent_identities[0], 12);
    assert_eq!(&concurrent_identities[1..5], &2_u32.to_be_bytes());

    // Both authorization policies reach the TPM signer. The PIN helper is used
    // only for the PIN-protected object and is never needed by the no-PIN key.
    let signature = send_request(&mut stream, &sign_request(&no_pin.summary.public_key));
    assert_eq!(signature[0], 14);

    let pin_public = pin.summary.public_key.clone();
    let socket_path = environment.socket_path();
    let signing = thread::spawn(move || {
        let mut pin_stream = UnixStream::connect(socket_path).expect("connect PIN signing client");
        send_request(&mut pin_stream, &sign_request(&pin_public))
    });
    for _ in 0..100 {
        if environment.control_path().exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    environment.authorize_pending(b"123456");
    let pin_signature = signing.join().expect("join PIN signing client");
    assert_eq!(pin_signature[0], 14);

    // Unsupported mutation requests and unknown public keys must not expand
    // the socket API or fall through to another signer.
    assert_eq!(send_request(&mut stream, &[17]), [5]);
    assert_eq!(
        send_request(&mut stream, &sign_request(b"unknown public key")),
        [5]
    );
    let mut unsupported_flags = sign_request(&no_pin.summary.public_key);
    *unsupported_flags
        .last_mut()
        .expect("sign request has flags") = 1;
    assert_eq!(send_request(&mut stream, &unsupported_flags), [5]);

    // Deleting a persisted key changes subsequent identity responses without
    // restarting the agent, so stale TPM objects are not advertised.
    environment.delete(pin.summary.id.as_str());
    assert_eq!(store.list().expect("list after delete").len(), 1);
    let identities_after_delete = send_request(&mut stream, &[11]);
    assert_eq!(&identities_after_delete[1..5], &1_u32.to_be_bytes());
}

#[test]
fn signs_and_verifies_with_openssh_clients() {
    let mut environment = TestEnvironment::start();
    environment.generate("OpenSSH interoperability", "none", b"");
    drop(environment.start_agent());

    let identities = environment
        .openssh_command("ssh-add")
        .arg("-L")
        .output()
        .expect("run ssh-add");
    assert!(
        identities.status.success(),
        "ssh-add rejected the agent response: {}",
        String::from_utf8_lossy(&identities.stderr)
    );
    let public_keys = String::from_utf8(identities.stdout).expect("ssh-add output is UTF-8");
    let public_key_lines = public_keys.lines().collect::<Vec<_>>();

    // This proves that a stock OpenSSH parser accepts the identity framing and
    // the ECDSA public-key blob emitted by Keyvisor.
    assert_eq!(public_key_lines.len(), 1);
    assert!(
        public_key_lines[0].starts_with("ecdsa-sha2-nistp256 "),
        "unexpected OpenSSH identity: {}",
        public_key_lines[0]
    );

    let public_key_path = environment.root.join("openssh-test.pub");
    let payload_path = environment.root.join("openssh-payload");
    let allowed_signers_path = environment.root.join("allowed_signers");
    fs::write(&public_key_path, format!("{}\n", public_key_lines[0]))
        .expect("write OpenSSH public key");
    fs::write(
        &payload_path,
        b"Keyvisor OpenSSH interoperability payload\n",
    )
    .expect("write OpenSSH signing payload");
    fs::write(
        &allowed_signers_path,
        format!("keyvisor-test {}\n", public_key_lines[0]),
    )
    .expect("write OpenSSH allowed signers");

    let signed = environment
        .openssh_command("ssh-keygen")
        .args(["-Y", "sign", "-f"])
        .arg(&public_key_path)
        .args(["-n", "keyvisor-test"])
        .arg(&payload_path)
        .output()
        .expect("run OpenSSH signing client");
    assert!(
        signed.status.success(),
        "ssh-keygen could not sign through Keyvisor: {}",
        String::from_utf8_lossy(&signed.stderr)
    );

    let signature_path = PathBuf::from(format!("{}.sig", payload_path.display()));
    let payload = fs::File::open(&payload_path).expect("open signed payload");
    let verified = environment
        .openssh_command("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(&allowed_signers_path)
        .args(["-I", "keyvisor-test", "-n", "keyvisor-test", "-s"])
        .arg(&signature_path)
        .stdin(Stdio::from(payload))
        .output()
        .expect("run OpenSSH verification client");

    // Verification catches more than a successful agent response: it checks
    // the namespace-bound digest, curve, public key, and canonical SSH mpints.
    // A malformed TPM signature encoding therefore cannot pass this assertion.
    assert!(
        verified.status.success(),
        "ssh-keygen rejected the TPM signature: {}",
        String::from_utf8_lossy(&verified.stderr)
    );
}
