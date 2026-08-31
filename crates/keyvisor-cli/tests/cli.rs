#![cfg(unix)]

//! End-to-end coverage for CLI key and configuration management.

use std::{
    fs,
    io::{BufRead, Read, Write},
    net::TcpListener,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use keyvisor_tpm::EsapiTpm;

#[cfg(target_os = "linux")]
#[test]
fn exec_refuses_ambiguous_concurrent_authorizations() {
    let root = std::env::temp_dir().join(format!(
        "keyvisor-exec-ambiguity-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock follows Unix epoch")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("create exec ambiguity test directory");
    let control = root.join("control.sock");
    let listener = UnixListener::bind(&control).expect("bind fake control socket");
    fs::set_permissions(&control, fs::Permissions::from_mode(0o600))
        .expect("protect fake control socket");
    let server = thread::spawn(move || {
        for count in [0, 2] {
            let (stream, _) = listener.accept().expect("accept list connection");
            let mut reader = std::io::BufReader::new(stream);
            let mut command = String::new();
            reader.read_line(&mut command).expect("read list command");
            assert_eq!(command, "LIST\n");
            writeln!(reader.get_mut(), "OK KEYVISOR-PENDING-1 {count}")
                .expect("write pending header");
            for request in 0..count {
                writeln!(reader.get_mut(), "request-{request}\t4b6579")
                    .expect("write pending request");
            }
        }
    });

    let output = Command::new(env!("CARGO_BIN_EXE_keyvisor"))
        .args([
            "exec",
            "--",
            "/bin/sh",
            "-c",
            "trap 'exit 0' TERM; while :; do sleep 0.02; done",
        ])
        .env("KEYVISOR_CONTROL_SOCKET", &control)
        .output()
        .expect("run exec wrapper with ambiguous requests");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("multiple authorization requests"));
    server.join().expect("join fake control server");
    fs::remove_dir_all(root).expect("remove exec ambiguity test directory");
}

#[cfg(target_os = "linux")]
#[test]
fn exec_forwards_signals_to_the_wrapped_command() {
    use rustix::process::{Pid, Signal, kill_process};

    let root = std::env::temp_dir().join(format!(
        "keyvisor-exec-signal-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock follows Unix epoch")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("create exec signal test directory");
    let ready = root.join("ready");
    let shell_command = format!(
        "trap 'exit 42' TERM; touch '{}'; while :; do sleep 0.02; done",
        ready.display()
    );
    let mut wrapped = Command::new(env!("CARGO_BIN_EXE_keyvisor"))
        .args(["exec", "--", "/bin/sh", "-c", &shell_command])
        .env("KEYVISOR_CONTROL_SOCKET", root.join("missing.sock"))
        .spawn()
        .expect("start exec wrapper for signal forwarding");
    for _ in 0..100 {
        if ready.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(ready.exists(), "wrapped command did not become ready");
    thread::sleep(Duration::from_millis(100));
    let pid = i32::try_from(wrapped.id())
        .ok()
        .and_then(Pid::from_raw)
        .expect("wrapper PID fits");
    kill_process(pid, Signal::TERM).expect("signal exec wrapper");
    let status = wrapped.wait().expect("wait for signalled exec wrapper");
    assert_eq!(status.code(), Some(42));
    fs::remove_dir_all(root).expect("remove exec signal test directory");
}

#[cfg(target_os = "linux")]
#[test]
fn exec_authorizes_from_its_terminal_and_preserves_command_status() {
    use rustix::pty::{OpenptFlags, grantpt, ioctl_tiocgptpeer, openpt, unlockpt};

    let root = std::env::temp_dir().join(format!(
        "keyvisor-exec-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock follows Unix epoch")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("create exec test directory");
    let control = root.join("control.sock");
    let completion = root.join("authorized");
    let listener = UnixListener::bind(&control).expect("bind fake control socket");
    fs::set_permissions(&control, fs::Permissions::from_mode(0o600))
        .expect("protect fake control socket");
    let completion_for_server = completion.clone();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept preflight connection");
        let mut reader = std::io::BufReader::new(stream);
        let mut command = String::new();
        reader.read_line(&mut command).expect("read preflight list");
        assert_eq!(command, "LIST\n");
        writeln!(reader.get_mut(), "OK KEYVISOR-PENDING-1 0")
            .expect("write empty preflight response");

        let (stream, _) = listener.accept().expect("accept pending connection");
        let mut reader = std::io::BufReader::new(stream);
        command.clear();
        reader.read_line(&mut command).expect("read pending list");
        assert_eq!(command, "LIST\n");
        writeln!(reader.get_mut(), "OK KEYVISOR-PENDING-1 1").expect("write pending header");
        writeln!(reader.get_mut(), "request-1\t486561646c657373204b6579")
            .expect("write pending request");

        let (stream, _) = listener.accept().expect("accept authorization connection");
        let mut reader = std::io::BufReader::new(stream);
        let mut header = String::new();
        reader
            .read_line(&mut header)
            .expect("read authorization header");
        assert_eq!(header, "AUTHORIZE request-1 6\n");
        let mut pin = [0_u8; 6];
        reader.read_exact(&mut pin).expect("read terminal PIN");
        assert_eq!(&pin, b"123456");
        writeln!(reader.get_mut(), "OK authorized").expect("approve request");
        fs::write(completion_for_server, b"authorized").expect("release wrapped command");
    });

    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)
        .expect("open pseudoterminal");
    grantpt(&master).expect("grant pseudoterminal");
    unlockpt(&master).expect("unlock pseudoterminal");
    let slave = ioctl_tiocgptpeer(&master, OpenptFlags::RDWR | OpenptFlags::CLOEXEC)
        .expect("open pseudoterminal slave");
    let slave = fs::File::from(slave);
    let shell_command = format!(
        "while test ! -e '{}'; do sleep 0.02; done; exit 23",
        completion.display()
    );
    let mut wrapped = Command::new("setsid")
        .args([
            "--wait",
            "--ctty",
            env!("CARGO_BIN_EXE_keyvisor"),
            "exec",
            "--",
            "/bin/sh",
            "-c",
            &shell_command,
        ])
        .env("KEYVISOR_CONTROL_SOCKET", &control)
        .stdin(slave.try_clone().expect("clone terminal input"))
        .stdout(slave.try_clone().expect("clone terminal output"))
        .stderr(slave)
        .spawn()
        .expect("start exec wrapper in a headless terminal");
    thread::sleep(Duration::from_millis(250));
    let mut master = fs::File::from(master);
    master.write_all(b"123456\n").expect("enter terminal PIN");

    let status = wrapped.wait().expect("wait for exec wrapper");
    assert_eq!(status.code(), Some(23));
    server.join().expect("join fake control server");
    fs::remove_dir_all(root).expect("remove exec test directory");
}

struct TestEnvironment {
    swtpm: Child,
    root: PathBuf,
    tcti: String,
}

#[test]
fn sends_pinentry_result_through_the_owner_only_control_socket() {
    let root = std::env::temp_dir().join(format!(
        "keyvisor-pinentry-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock follows Unix epoch")
            .as_nanos()
    ));
    let bin = root.join("bin");
    let runtime = root.join("runtime");
    fs::create_dir_all(&bin).expect("create fake binary directory");
    fs::create_dir_all(&runtime).expect("create fake runtime directory");
    let pinentry = bin.join("pinentry-gnome3");
    fs::write(
        &pinentry,
        "#!/bin/sh\nprintf 'OK synthetic pinentry\\n'\nwhile IFS= read -r command; do\n  case \"$command\" in\n    GETPIN) printf 'D synthetic%%2DPIN\\nOK\\n' ;;\n    *) printf 'OK\\n' ;;\n  esac\ndone\n",
    )
    .expect("write fake pinentry");
    fs::set_permissions(&pinentry, fs::Permissions::from_mode(0o700))
        .expect("protect fake pinentry");

    let control = runtime.join("control.sock");
    let listener = UnixListener::bind(&control).expect("bind fake control socket");
    fs::set_permissions(&control, fs::Permissions::from_mode(0o600))
        .expect("protect fake control socket");
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept pending-list connection");
        let mut reader = std::io::BufReader::new(stream);
        let mut command = String::new();
        reader.read_line(&mut command).expect("read list command");
        assert_eq!(command, "LIST\n");
        writeln!(reader.get_mut(), "OK KEYVISOR-PENDING-1 1").expect("write pending header");
        writeln!(reader.get_mut(), "request-1\t53796e746865746963").expect("write pending request");

        let (stream, _) = listener.accept().expect("accept CLI control connection");
        let mut reader = std::io::BufReader::new(stream);
        let mut header = String::new();
        reader
            .read_line(&mut header)
            .expect("read authorization header");
        assert_eq!(header, "AUTHORIZE request-1 13\n");
        let mut pin = [0_u8; 13];
        reader.read_exact(&mut pin).expect("read synthetic PIN");
        assert_eq!(&pin, b"synthetic-PIN");
        writeln!(reader.get_mut(), "OK authorized").expect("approve request");
    });

    let output = Command::new(env!("CARGO_BIN_EXE_keyvisor"))
        .args(["authorize", "request-1", "--pinentry"])
        .env("KEYVISOR_CONTROL_SOCKET", &control)
        .env("PATH", format!("{}:/usr/bin", bin.display()))
        .output()
        .expect("run graphical authorization CLI");
    assert!(
        output.status.success(),
        "authorization failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().expect("join fake control server");
    fs::remove_dir_all(root).expect("remove pinentry test directory");
}

impl TestEnvironment {
    fn start() -> Self {
        let root = std::env::temp_dir().join(format!(
            "keyvisor-cli-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock follows Unix epoch")
                .as_nanos()
        ));
        let state = root.join("swtpm");
        fs::create_dir_all(&state).expect("create simulator state");
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
                return Self { swtpm, root, tcti };
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = swtpm.kill();
        let _ = swtpm.wait();
        panic!("swtpm did not become ready");
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_keyvisor"));
        command
            .env("TPM2TOOLS_TCTI", &self.tcti)
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_RUNTIME_DIR", self.root.join("runtime"));
        command
    }

    fn output(&self, arguments: &[&str]) -> std::process::Output {
        self.command()
            .args(arguments)
            .output()
            .expect("run keyvisor CLI")
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        let _ = self.swtpm.kill();
        let _ = self.swtpm.wait();
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn unused_port_pair() -> (u16, u16) {
    for _ in 0..100 {
        let server = TcpListener::bind(("127.0.0.1", 0)).expect("reserve server port");
        let server_port = server.local_addr().expect("server address").port();
        let Some(control_port) = server_port.checked_add(1) else {
            continue;
        };
        if let Ok(control) = TcpListener::bind(("127.0.0.1", control_port)) {
            drop(control);
            drop(server);
            return (server_port, control_port);
        }
    }
    panic!("could not reserve adjacent swtpm ports");
}

#[test]
fn manages_configuration_and_tpm_keys_without_a_gui() {
    let environment = TestEnvironment::start();

    let defaults = environment.output(&["config", "list"]);
    assert!(defaults.status.success());
    assert!(String::from_utf8_lossy(&defaults.stdout).contains("history-enabled=true"));
    let changed = environment.output(&["config", "set", "authorization-timeout-seconds", "45"]);
    assert!(changed.status.success());
    let config_path = environment.root.join("config/me.nexryai.keyvisor/config");
    assert_eq!(
        fs::metadata(config_path)
            .expect("configuration metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let created = environment.output(&[
        "key",
        "create",
        "--name",
        "Automation",
        "--authorization",
        "none",
        "--yes",
    ]);
    assert!(
        created.status.success(),
        "creation failed: {}",
        String::from_utf8_lossy(&created.stderr)
    );
    let id = String::from_utf8(created.stdout)
        .expect("key ID is UTF-8")
        .trim()
        .to_owned();
    assert!(!id.is_empty());

    let mut pin_creation = environment
        .command()
        .args([
            "key",
            "create",
            "--name",
            "Interactive",
            "--authorization",
            "pin",
            "--pin-stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start PIN key creation");
    pin_creation
        .stdin
        .take()
        .expect("PIN input pipe")
        .write_all(b"123456\n123456\n")
        .expect("write test PINs");
    let pin_created = pin_creation
        .wait_with_output()
        .expect("wait for PIN creation");
    assert!(
        pin_created.status.success(),
        "PIN creation failed: {}",
        String::from_utf8_lossy(&pin_created.stderr)
    );

    let listing = environment.output(&["key", "list", "--format", "tsv"]);
    assert!(listing.status.success());
    let listing = String::from_utf8(listing.stdout).expect("listing is UTF-8");
    assert_eq!(listing.lines().next(), Some("KEYVISOR-KEYS-1"));
    assert_eq!(listing.lines().count(), 4);

    let shown = environment.output(&["key", "show", &id]);
    assert!(shown.status.success());
    assert!(String::from_utf8_lossy(&shown.stdout).contains("Public key: ecdsa-sha2-nistp256 "));

    let deleted = environment.output(&["key", "delete", &id, "--yes"]);
    assert!(deleted.status.success());
    let after = environment.output(&["key", "list", "--format", "tsv"]);
    assert_eq!(String::from_utf8_lossy(&after.stdout).lines().count(), 3);

    let history = environment.output(&["history", "--format", "tsv"]);
    assert!(history.status.success());
    assert_eq!(
        String::from_utf8_lossy(&history.stdout).lines().next(),
        Some("KEYVISOR-HISTORY-1")
    );
}
