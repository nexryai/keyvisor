# Keyvisor

Keyvisor is a GNOME SSH agent that keeps signing keys protected by the TPM.
Its application ID is `me.nexryai.keyvisor`.

The TPM generation/signing backend and a Libadwaita key-creation flow are now
implemented. Keys are generated as fixed, non-migratable TPM objects. Keyvisor
persists only their public areas and TPM-wrapped private blobs; there is no
software-key fallback.

At creation time, choose either:

- **No Authentication** for unattended agent signing. The TPM object uses an
  empty authorization value and is excluded from dictionary-attack counting.
- **TPM Rate-limited PIN** to require a PIN for each signature. The PIN is not
  stored, and failed attempts use the TPM's shared lockout policy.

The core SSH agent wire protocol is implemented: identity enumeration and
ECDSA/SHA-256 signing work over an owner-only Unix socket. TPM-PIN keys open a
fresh Libadwaita prompt for every signature; cancelling the prompt fails the
request. The GUI loads the real TPM-key list and shows authentication policy,
SHA-256 fingerprint, copyable OpenSSH public material, and a confirmed deletion
flow. A Signing Activity view and desktop notifications report successful and
failed requests without recording the signed payload. The agent supports native
systemd socket activation and up to 16 concurrent clients while serializing TPM
access.

The GUI follows GNOME navigation conventions: its key sidebar collapses into
page-based navigation below 700sp, Signing Activity opens in the main window,
and the primary menu provides Refresh, Keyboard Shortcuts, and About actions.
The current UI requires Libadwaita 1.8 or newer.

The agent exports a read-focused management interface on the authenticated
per-user session bus as `me.nexryai.keyvisor.Agent1`. It exposes public key
metadata, deletion, and the bounded activity history; it never transports PINs,
wrapped private blobs, or SSH signing payloads. The newest 200 activity entries
are stored in an owner-only `history.bin`.

## Fedora development dependencies

Install the Rust toolchain, GNOME development libraries, TPM2-TSS headers,
validators, and the software TPM used by the integration tests:

```sh
sudo dnf install \
  appstream cargo clippy desktop-file-utils gcc gtk4-devel \
  libadwaita-devel meson openssh-clients pkgconf-pkg-config rust \
  rustfmt swtpm systemd tpm2-tss-devel
```

Keyvisor requires Rust 1.92 or newer and Libadwaita 1.8 or newer. `swtpm` is
required by `cargo test --workspace --all-features`; the tests start an
isolated temporary TPM and do not use the host's physical TPM.

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

## Run the application

Build both processes so the GUI can start the agent helper, then point the
development build at it:

```sh
cargo build -p keyvisor-agent -p keyvisor-ui
KEYVISOR_AGENT_PATH=target/debug/keyvisor-agent cargo run -p keyvisor-ui
```

The agent uses `TPM2TOOLS_TCTI`, `TCTI`, or `TEST_TCTI` when set; otherwise it
opens the default TPM resource-manager device. Wrapped key records are stored
below `$XDG_DATA_HOME/me.nexryai.keyvisor/keys`, falling back to
`~/.local/share/me.nexryai.keyvisor/keys`.

For a development agent session:

```sh
KEYVISOR_PIN_HELPER_PATH=target/debug/keyvisor target/debug/keyvisor-agent serve
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/keyvisor/agent.sock"
ssh-add -L
```

The Meson install includes both executables and
`me.nexryai.keyvisor-agent.service`. After installation, the user service can
be enabled with:

```sh
systemctl --user enable --now me.nexryai.keyvisor-agent.socket
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/keyvisor/agent.sock"
```

The socket unit starts the service on the first SSH client connection. Direct
`keyvisor-agent serve` remains available for development and environments
without systemd user services. If an SSH client disconnects while its PIN
dialog is open, the agent closes the dialog and abandons the request. A
synchronous TPM command already in progress cannot be interrupted through
TPM2-TSS, so its result is discarded after the command returns.

## Verify

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

The TPM integration test starts its own temporary `swtpm` and never touches a
physical TPM.

See `PLASN.md` for the implementation plan and security model.

## Fedora COPR

Fedora RPM and COPR packaging is included. It produces a source RPM with a
locked vendor archive so the final build does not access the network:

```sh
./build-aux/make-srpm.sh dist
copr-cli build OWNER/keyvisor dist/keyvisor-0.1.0-1*.src.rpm
```

See `packaging/README.md` for prerequisites, clean `mock` builds, direct
uploads, and COPR SCM configuration.
