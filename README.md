# Keyvisor

Keyvisor is a command-line SSH agent and key manager that keeps signing keys
protected by a TPM 2.0 device. It has no graphical interface or graphical
toolkit dependency. The compatibility-sensitive application ID remains
`me.nexryai.keyvisor`.

Keys are generated as fixed, non-migratable TPM objects. Keyvisor persists only
their public areas and TPM-wrapped private blobs; it has no software-key
fallback, private-key import, or private-key export path. Every SSH signature
is produced by the TPM.

At creation time, a key uses one of two authorization policies:

- **No PIN** permits unattended agent signing. The TPM object has an empty
  authorization value and is excluded from dictionary-attack counting.
- **TPM-protected PIN** requires authorization for each signature. Keyvisor
  does not persist or cache the PIN, and failed attempts are governed by the
  TPM's shared dictionary-attack policy.

## Install development dependencies

On Fedora, install Rust, TPM2-TSS, the software TPM used by tests, OpenSSH, and
the native build tools:

```sh
sudo dnf install \
  cargo clippy gcc openssh-clients pinentry-gnome3 pkgconf-pkg-config \
  rust rustfmt swtpm systemd tpm2-tss-devel
```

Keyvisor requires Rust 1.92 or newer. The integration tests start isolated
`swtpm` processes and never use the host's physical TPM.

On Fedora, add the account that runs Keyvisor to the `tss` group so it can use
the kernel TPM resource manager:

```sh
sudo usermod -aG tss "$USER"
```

Log out completely and log back in before continuing; opening another terminal
may not refresh supplementary groups. Verify both membership and device access:

```sh
id
ls -l /dev/tpm0 /dev/tpmrm0
test -r /dev/tpmrm0 && test -w /dev/tpmrm0
```

Keyvisor uses `/dev/tpmrm0` by default and never falls back automatically to the
raw, single-client `/dev/tpm0` device. `TPM2TOOLS_TCTI`, `TCTI`, and `TEST_TCTI`
remain explicit overrides for test simulators or unusual deployments. For
example, the following selects the same kernel resource manager explicitly:

```sh
export TPM2TOOLS_TCTI=device:/dev/tpmrm0
```

Do not run Keyvisor with `sudo`, which would create root-owned state, and do not
make `/dev/tpm0` or `/dev/tpmrm0` world-accessible. If `/dev/tpmrm0` does not
exist, inspect `sudo journalctl -k -b | grep -i tpm` and confirm that
`tpm2-tss` is installed before using a physical TPM.

RPM and COPR packaging additionally requires:

```sh
sudo dnf install copr-cli mock rpm-build rpmlint systemd-rpm-macros xz
```

## Build

```sh
cargo build --workspace
```

This produces `target/debug/keyvisor` and `target/debug/keyvisor-agent`.

## Manage keys

Create a no-PIN key for unattended signing:

```sh
keyvisor key create --name "Automation" --authorization none
```

Keyvisor displays the same-user socket risk and asks for confirmation. For
explicit automation, add `--yes`.

Create a TPM-PIN key:

```sh
keyvisor key create --name "Work" --authorization pin
```

The PIN and confirmation are read from `/dev/tty` with terminal echo disabled.
For a deliberately non-interactive workflow, `--pin-stdin` reads two
newline-terminated values from stdin. PINs are never accepted in arguments or
environment variables.

Inspect and remove keys:

```sh
keyvisor key list
keyvisor key show KEY_ID
keyvisor key delete KEY_ID
```

Deletion asks for confirmation unless `--yes` is supplied. `key list` supports
`--format tsv`; its first line is the schema identifier `KEYVISOR-KEYS-1`.
Human-readable output is the default. Requested data is written to stdout,
diagnostics to stderr, and commands return zero on success and nonzero on
failure or cancellation.

## Configure Keyvisor

```sh
keyvisor config list
keyvisor config get authorization-timeout-seconds
keyvisor config set authorization-timeout-seconds 60
keyvisor config set history-enabled false
```

Configuration is non-secret and stored atomically in an owner-only file below
`$XDG_CONFIG_HOME/me.nexryai.keyvisor`, falling back to
`~/.config/me.nexryai.keyvisor`. The authorization timeout accepts 10–120
seconds. Configuration cannot change or reset TPM dictionary-attack state.
Restart the agent after changing a setting.

## Run the agent

For a development session:

```sh
keyvisor-agent serve
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/keyvisor/agent.sock"
ssh-add -L
```

After installation, enable native socket activation:

```sh
systemctl --user enable --now me.nexryai.keyvisor-agent.socket
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/keyvisor/agent.sock"
```

The SSH socket and CLI control socket are created below
`$XDG_RUNTIME_DIR/keyvisor` with mode `0600` in a mode `0700` directory. The
control protocol validates the connecting process UID and never transports the
SSH signing payload.

For a TPM-PIN key, an SSH or Git operation waits for per-use authorization. In
a GNOME graphical session, the agent automatically opens the system-integrated
`pinentry-gnome3` dialog. It shows the key name and returns the PIN through the
standard Assuan pipe protocol. Keyvisor does not use Polkit itself because
Polkit authenticates OS privileges and cannot return a key-specific TPM PIN.

In a headless session, or when automatic graphical prompting is unavailable,
list the pending request in another terminal and approve its opaque ID:

```sh
keyvisor authorize
keyvisor authorize REQUEST_ID
```

The second command reads the PIN without echo and sends its short-lived value
over the owner-only local control socket. Requests time out according to
`authorization-timeout-seconds` and are cancelled when the SSH client
disconnects. Authorization is defense in depth against accidental use; it is
not a security boundary against code already running as the same user.

Interactive key creation also uses `pinentry-gnome3` automatically in a
graphical session, including its built-in confirmation field. Use `--terminal`
to force `/dev/tty`, `--pinentry` to require the GNOME dialog, or `--pin-stdin`
for an explicitly non-interactive input pipe. These options are mutually
exclusive.

Check agent status and inspect privacy-preserving signing history:

```sh
keyvisor agent status
keyvisor history
keyvisor history --format tsv
```

History contains timestamps, key metadata, authorization policy, and outcome,
never signed payloads. TSV history begins with `KEYVISOR-HISTORY-1`.

The agent uses `TPM2TOOLS_TCTI`, `TCTI`, or `TEST_TCTI` when set; otherwise it
opens `/dev/tpmrm0` explicitly. Wrapped key records are stored
below `$XDG_DATA_HOME/me.nexryai.keyvisor/keys`, falling back to
`~/.local/share/me.nexryai.keyvisor/keys`.

## Verify

```sh
cargo fmt --all -- --check
cargo test --locked --workspace --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

The agent suite also invokes installed `ssh-add` and `ssh-keygen` clients to
enumerate an identity, request a TPM-backed signature, and verify the resulting
SSHSIG. See [PLANS.md](PLANS.md) for the security model and remaining hardening
work.

## Fedora COPR

Build and upload a network-independent SRPM with:

```sh
./build-aux/srpm.sh dist
copr-cli build OWNER/keyvisor dist/keyvisor-0.1.0-1*.src.rpm
```

See [packaging/README.md](packaging/README.md) for clean `mock` builds and COPR
uploads, including Git-based builds from the COPR Web UI.
