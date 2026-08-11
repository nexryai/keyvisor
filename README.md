# Keyvisor

Keyvisor is a command-line SSH agent and key manager that keeps signing keys
protected by a TPM 2.0 device. Its compatibility-sensitive application ID is
`me.nexryai.keyvisor`.

The project is transitioning from GTK 4/Libadwaita to a CLI-only design. The
existing GUI is retired: it receives no new features and will be removed after
the CLI covers key management, agent status, signing history, and per-signature
authorization. The current source tree still contains transitional GUI code and
dependencies, so this document distinguishes commands that work today from the
target interface described in [PLANS.md](PLANS.md).

Keys are generated as fixed, non-migratable TPM objects. Keyvisor persists only
their public areas and TPM-wrapped private blobs; it has no software-key
fallback, private-key import, or private-key export path. Signing is performed
by the TPM.

At creation time, a key uses one of two authorization policies:

- **No PIN** permits unattended agent signing. The TPM object has an empty
  authorization value and is excluded from dictionary-attack counting.
- **TPM-protected PIN** requires authorization for each signature. Keyvisor
  does not persist or cache the PIN, and failed attempts are governed by the
  TPM's shared dictionary-attack policy.

The agent implements identity enumeration and ECDSA/SHA-256 signing over an
owner-only Unix socket. It supports native systemd socket activation and up to
16 concurrent SSH clients while serializing TPM access. Signing history records
only bounded metadata and outcomes, never the signed payload.

## Transition status

Some low-level management commands already exist on `keyvisor-agent`:

```text
keyvisor-agent generate --name NAME --authorization none|pin
keyvisor-agent list
keyvisor-agent delete ID
keyvisor-agent serve
```

These are transitional interfaces, not the final CLI contract. PIN input for
`generate --authorization pin` is read from stdin and must be supplied without
placing it in an argument, environment variable, shell history, or log.

The planned installed interface is a separate `keyvisor` command with key
create/list/show/delete, non-secret configuration, agent status, history, and
terminal authorization subcommands. Machine-readable output and exit behavior
will be versioned and documented before the GUI is removed. See
[PLANS.md](PLANS.md) for milestones and security requirements.

## Fedora development dependencies

The current transitional tree still builds the GUI, so GTK, Libadwaita, and
desktop metadata validators remain build dependencies until the GUI-removal
milestone lands:

```sh
sudo dnf install \
  appstream cargo clippy desktop-file-utils gcc gtk4-devel \
  libadwaita-devel meson openssh-clients pkgconf-pkg-config rust \
  rustfmt swtpm systemd tpm2-tss-devel
```

Keyvisor requires Rust 1.92 or newer. `swtpm` is required by the full-featured
workspace tests; the tests start an isolated temporary TPM and do not use the
host's physical TPM.

RPM and COPR packaging additionally requires:

```sh
sudo dnf install \
  copr-cli mock rpm-build rpmlint systemd-rpm-macros xz
```

Local `mock` builds require membership in the `mock` group. After running the
following command, log out and back in before invoking `mock`:

```sh
sudo usermod -aG mock "$USER"
```

## Run the current agent

Build and run the agent directly:

```sh
cargo build -p keyvisor-agent
target/debug/keyvisor-agent serve
```

In another shell, point OpenSSH clients at it:

```sh
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/keyvisor/agent.sock"
ssh-add -L
```

The agent uses `TPM2TOOLS_TCTI`, `TCTI`, or `TEST_TCTI` when set; otherwise it
opens the default TPM resource-manager device. Wrapped key records are stored
below `$XDG_DATA_HOME/me.nexryai.keyvisor/keys`, falling back to
`~/.local/share/me.nexryai.keyvisor/keys`.

After installation, enable socket activation with:

```sh
systemctl --user enable --now me.nexryai.keyvisor-agent.socket
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/keyvisor/agent.sock"
```

The socket unit starts the service on the first SSH client connection. Direct
`keyvisor-agent serve` remains available for development and environments
without systemd user services.

The current TPM-PIN signing path still invokes the retired GUI helper. It will
be replaced by the terminal authorization protocol in [PLANS.md](PLANS.md).
Until that replacement is implemented, a missing or cancelled helper fails the
signature request closed; there is no no-PIN or software-key fallback.

## Verify

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

The TPM integration test starts its own temporary `swtpm` and never touches a
physical TPM. The agent integration suite invokes installed `ssh-add` and
`ssh-keygen` clients to enumerate an identity, request a TPM-backed signature,
and verify the resulting SSHSIG.

GitHub Actions repeats formatting, Clippy, unit, `swtpm`, and OpenSSH checks in
a Fedora container.

## Fedora COPR

The current Fedora RPM and COPR packaging includes transitional GUI artifacts.
The GUI-removal milestone will reduce the package to the CLI, agent, systemd
units, licenses, and documentation.

Build and upload an SRPM with:

```sh
./build-aux/make-srpm.sh dist
copr-cli build OWNER/keyvisor dist/keyvisor-0.1.0-1*.src.rpm
```

See [packaging/README.md](packaging/README.md) for prerequisites, clean `mock`
builds, direct uploads, and COPR SCM configuration.
