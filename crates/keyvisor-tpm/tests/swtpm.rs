use std::{
    fs,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, SystemTime},
};

use keyvisor_core::{KeyAlgorithm, KeyUsePolicy};
use keyvisor_tpm::{EsapiTpm, TpmAuthorization, TpmError, TpmSigner};

struct Swtpm {
    child: Child,
    state_dir: PathBuf,
    tcti: String,
}

impl Swtpm {
    fn start() -> Self {
        let state_dir = std::env::temp_dir().join(format!(
            "keyvisor-swtpm-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("system clock must follow the Unix epoch")
                .as_nanos()
        ));
        fs::create_dir(&state_dir).expect("failed to create swtpm state directory");

        let (server_port, control_port) = unused_port_pair();
        let child = Command::new("swtpm")
            .args([
                "socket",
                "--tpm2",
                "--tpmstate",
                &format!("dir={}", state_dir.display()),
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
            .expect("failed to start swtpm");

        Self {
            child,
            state_dir,
            tcti: format!("swtpm:host=127.0.0.1,port={server_port}"),
        }
    }

    fn connect(&self) -> EsapiTpm {
        for _ in 0..100 {
            if let Ok(tpm) = EsapiTpm::connect(&self.tcti) {
                return tpm;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("swtpm did not become ready");
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.state_dir);
    }
}

fn unused_port_pair() -> (u16, u16) {
    for _ in 0..100 {
        let server =
            TcpListener::bind(("127.0.0.1", 0)).expect("failed to reserve a local test port");
        let server_port = server
            .local_addr()
            .expect("test listener has no local address")
            .port();
        let Some(control_port) = server_port.checked_add(1) else {
            continue;
        };

        if let Ok(control) = TcpListener::bind(("127.0.0.1", control_port)) {
            drop(control);
            drop(server);
            return (server_port, control_port);
        }
    }

    panic!("could not reserve adjacent swtpm server and control ports");
}

#[test]
fn generates_reloads_and_signs_with_both_authorization_modes() {
    let swtpm = Swtpm::start();
    let mut tpm = swtpm.connect();
    let da_before = tpm
        .dictionary_attack_state()
        .expect("failed to read DA state");
    assert!(da_before.max_tries > 0);

    let (no_pin_summary, no_pin_object) = tpm
        .generate(
            "No PIN",
            KeyAlgorithm::EcdsaNistP256,
            TpmAuthorization::None,
        )
        .expect("failed to generate no-PIN key");
    assert_eq!(no_pin_summary.use_policy, KeyUsePolicy::NoPin);
    let algorithm = b"ecdsa-sha2-nistp256";
    assert_eq!(
        &no_pin_summary.public_key[4..4 + algorithm.len()],
        algorithm
    );
    assert_eq!(
        tpm.sign(&no_pin_object, &[0x42; 32], TpmAuthorization::None)
            .expect("failed to sign with no-PIN key")
            .len(),
        64
    );

    let (pin_summary, pin_object) = tpm
        .generate(
            "PIN",
            KeyAlgorithm::EcdsaNistP256,
            TpmAuthorization::Pin(b"123456"),
        )
        .expect("failed to generate PIN key");
    assert_eq!(pin_summary.use_policy, KeyUsePolicy::TpmPin);
    assert_eq!(
        tpm.sign(&pin_object, &[0x24; 32], TpmAuthorization::Pin(b"wrong")),
        Err(TpmError::AuthorizationFailed)
    );
    assert_eq!(
        tpm.sign(&pin_object, &[0x24; 32], TpmAuthorization::Pin(b"123456"))
            .expect("failed to sign with PIN key")
            .len(),
        64
    );

    let da_after = tpm
        .dictionary_attack_state()
        .expect("failed to read DA state after an incorrect PIN");
    assert!(da_after.failed_tries >= da_before.failed_tries);

    drop(tpm);
    let mut reconnected = swtpm.connect();
    assert_eq!(
        reconnected
            .sign(&no_pin_object, &[0x11; 32], TpmAuthorization::None)
            .expect("failed to sign after recreating the storage parent")
            .len(),
        64
    );
}
