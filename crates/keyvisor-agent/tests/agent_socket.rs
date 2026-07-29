#![cfg(unix)]

//! End-to-end tests for the security boundary exposed through `SSH_AUTH_SOCK`.
//!
//! Each test starts an isolated TPM simulator and the real agent executable.
//! The tests intentionally exercise process, socket, persistence, and TPM
//! boundaries together instead of replacing them with in-process mocks.

use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use keyvisor_agent::KeyStore;
use keyvisor_core::KeyUsePolicy;
use keyvisor_tpm::EsapiTpm;

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

    fn pin_helper_path(&self) -> PathBuf {
        self.root.join("pin-helper")
    }

    fn write_pin_helper(&self, script: &str) {
        let path = self.pin_helper_path();
        fs::write(&path, script).expect("write PIN helper");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("protect PIN helper");
    }

    fn generate(&self, name: &str, authorization: &str, pin: &[u8]) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_keyvisor-agent"))
            .args(["generate", "--name", name, "--authorization", authorization])
            .env("TPM2TOOLS_TCTI", &self.tcti)
            .env("XDG_DATA_HOME", self.data_home())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start key generation");
        child
            .stdin
            .take()
            .expect("generation stdin")
            .write_all(pin)
            .expect("write test PIN");
        let output = child.wait_with_output().expect("wait for key generation");
        assert!(
            output.status.success(),
            "generation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        // Generation prints public metadata only. A non-empty result also
        // confirms that the CLI completed persistence after TPM generation.
        assert!(!output.stdout.is_empty());
    }

    fn start_agent(&mut self) -> UnixStream {
        let socket_path = self.socket_path();
        self.write_pin_helper("#!/bin/sh\nprintf '123456'\n");
        self.agent = Some(
            Command::new(env!("CARGO_BIN_EXE_keyvisor-agent"))
                .arg("serve")
                .env("TPM2TOOLS_TCTI", &self.tcti)
                .env("XDG_DATA_HOME", self.data_home())
                .env("KEYVISOR_AGENT_SOCKET", &socket_path)
                .env("KEYVISOR_PIN_HELPER_PATH", self.pin_helper_path())
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

    fn list_output(&self) -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_keyvisor-agent"))
            .arg("list")
            .env("XDG_DATA_HOME", self.data_home())
            .output()
            .expect("run key list command");
        assert!(
            output.status.success(),
            "listing failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("list output is UTF-8")
    }

    fn delete(&self, id: &str) {
        let output = Command::new(env!("CARGO_BIN_EXE_keyvisor-agent"))
            .args(["delete", id])
            .env("XDG_DATA_HOME", self.data_home())
            .output()
            .expect("run key delete command");
        assert!(
            output.status.success(),
            "deletion failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
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

    // The control command must expose both records without requiring TPM
    // authorization; only public material and policy metadata are listed.
    let listing = environment.list_output();
    assert_eq!(listing.lines().next(), Some("KEYVISOR-LIST-1"));
    assert_eq!(listing.lines().count(), 3);

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

    let pin_signature = send_request(&mut stream, &sign_request(&pin.summary.public_key));
    assert_eq!(pin_signature[0], 14);

    // A cancelled or failed PIN prompt must fail closed with the standard
    // agent failure response; retrying without authorization is forbidden.
    environment.write_pin_helper("#!/bin/sh\nexit 1\n");
    let refused = send_request(&mut stream, &sign_request(&pin.summary.public_key));
    assert_eq!(refused, [5]);

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
    assert_eq!(environment.list_output().lines().count(), 2);
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
