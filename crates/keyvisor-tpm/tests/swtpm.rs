//! TPM integration tests against a disposable software TPM.
//!
//! These tests use the real TPM2-TSS/ESAPI command path. The simulator is not
//! evidence of physical anti-extraction properties, but it verifies object
//! templates, authorization policy, reload behavior, and TPM-produced
//! signatures without risking the host's dictionary-attack state.

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
            // swtpm requires separate adjacent server and control ports. Both
            // reservations are released only when the complete pair is known.
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

    // Reading DA properties is deliberately part of the public backend API.
    // Keyvisor may report these shared values but this test never modifies or
    // resets them, matching the physical-TPM safety rule.
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

    // The returned SSH blob must identify the only algorithm currently
    // supported by both the TPM template and the agent protocol.
    let algorithm = b"ecdsa-sha2-nistp256";
    assert_eq!(
        &no_pin_summary.public_key[4..4 + algorithm.len()],
        algorithm
    );

    // A 64-byte result proves that TPM2_Sign returned fixed-width P-256 r and
    // s components through the backend contract.
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

    // The incorrect PIN must be rejected by the TPM authorization command,
    // not retried as a no-PIN request or handled by a software signer.
    assert_eq!(
        tpm.sign(&pin_object, &[0x24; 32], TpmAuthorization::Pin(b"wrong")),
        Err(TpmError::AuthorizationFailed)
    );
    // Read the failure counter before a successful authorization, because TPM
    // implementations may reduce or clear that counter after a valid PIN.
    let da_after = tpm
        .dictionary_attack_state()
        .expect("failed to read DA state after an incorrect PIN");
    // swtpm versions differ in when they expose an incremented lockout
    // counter, so require that Keyvisor never lowered it and never changed the
    // administrator-owned lockout parameters.
    assert!(
        da_after.failed_tries >= da_before.failed_tries,
        "a sign attempt must never reset the shared DA counter"
    );
    assert_eq!(da_after.max_tries, da_before.max_tries);
    assert_eq!(
        da_after.recovery_time_seconds,
        da_before.recovery_time_seconds
    );
    assert_eq!(
        da_after.lockout_recovery_seconds,
        da_before.lockout_recovery_seconds
    );

    assert_eq!(
        tpm.sign(&pin_object, &[0x24; 32], TpmAuthorization::Pin(b"123456"))
            .expect("failed to sign with PIN key")
            .len(),
        64
    );

    drop(tpm);
    let mut reconnected = swtpm.connect();

    // Reconnection recreates the deterministic storage parent and loads only
    // the TPM-wrapped child. This guards against an accidental dependency on a
    // transient handle or in-memory private material.
    assert_eq!(
        reconnected
            .sign(&no_pin_object, &[0x11; 32], TpmAuthorization::None)
            .expect("failed to sign after recreating the storage parent")
            .len(),
        64
    );
}

#[test]
fn rejects_policy_downgrades_and_tampered_objects() {
    let swtpm = Swtpm::start();
    let mut tpm = swtpm.connect();

    // An explicitly selected PIN policy with an empty value must not silently
    // become the no-PIN policy, because those templates differ in `noDA`.
    assert_eq!(
        tpm.generate(
            "Empty PIN",
            KeyAlgorithm::EcdsaNistP256,
            TpmAuthorization::Pin(b""),
        ),
        Err(TpmError::InvalidAuthorization)
    );

    let (_, no_pin_object) = tpm
        .generate(
            "No PIN",
            KeyAlgorithm::EcdsaNistP256,
            TpmAuthorization::None,
        )
        .expect("generate no-PIN object");
    let (_, pin_object) = tpm
        .generate(
            "PIN",
            KeyAlgorithm::EcdsaNistP256,
            TpmAuthorization::Pin(b"123456"),
        )
        .expect("generate PIN object");

    // Authorization mode is persisted with the wrapped object and checked
    // before loading it. Callers cannot upgrade or downgrade policy per sign.
    assert_eq!(
        tpm.sign(
            &no_pin_object,
            &[0x11; 32],
            TpmAuthorization::Pin(b"123456"),
        ),
        Err(TpmError::InvalidAuthorization)
    );
    assert_eq!(
        tpm.sign(&pin_object, &[0x11; 32], TpmAuthorization::None),
        Err(TpmError::InvalidAuthorization)
    );

    // P-256/SHA-256 signing accepts exactly one 32-byte digest. Rejecting other
    // sizes prevents implicit hashing or truncation inside the TPM boundary.
    assert_eq!(
        tpm.sign(&no_pin_object, &[0x11; 31], TpmAuthorization::None),
        Err(TpmError::InvalidObject)
    );
    assert_eq!(
        tpm.sign(&no_pin_object, &[0x11; 33], TpmAuthorization::None),
        Err(TpmError::InvalidObject)
    );

    let mut foreign_parent = no_pin_object.clone();
    foreign_parent.parent_name[0] ^= 0xff;

    // A wrapped child is bound to its storage parent. Detecting the parent-name
    // mismatch before TPM2_Load gives corrupted or copied records a stable,
    // fail-closed result.
    assert_eq!(
        tpm.sign(&foreign_parent, &[0x11; 32], TpmAuthorization::None),
        Err(TpmError::InvalidObject)
    );

    let mut corrupted_public = no_pin_object;
    corrupted_public.public[0] ^= 0xff;

    // Persisted public bytes are host-controlled. Corruption must fail template
    // unmarshalling instead of pairing attacker-chosen metadata with the
    // TPM-wrapped private blob.
    assert_eq!(
        tpm.sign(&corrupted_public, &[0x11; 32], TpmAuthorization::None),
        Err(TpmError::InvalidObject)
    );
}
