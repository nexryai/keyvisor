# Fedora COPR packaging

The repository builds an SRPM locally for direct upload to COPR. The packaging
script produces two deterministic source archives. The first contains
Keyvisor without the read-only `secretive/` reference tree. The second contains
all crates from `Cargo.lock`, including Cargo checksum metadata. The actual RPM
build is therefore offline and always uses the locked dependency graph.

## Local prerequisites

Install the packaging tools and native build dependencies:

```sh
sudo dnf install \
  cargo copr-cli gcc mock openssh-clients pkgconf-pkg-config \
  pinentry-gnome3 rpm-build rust swtpm systemd-rpm-macros tpm2-tss-devel xz
```

The account used for local `mock` builds must be in the `mock` group. Log out
and back in after adding it:

```sh
sudo usermod -aG mock "$USER"
```

## Build and inspect an SRPM

Run from the repository root:

```sh
./build-aux/srpm.sh dist
rpm -qpi dist/keyvisor-0.1.0-1*.src.rpm
```

Build it in a clean Fedora 44 chroot before uploading:

```sh
mock -r fedora-44-x86_64 \
  --rebuild dist/keyvisor-0.1.0-1*.src.rpm
```

The RPM test suite uses `swtpm`; it does not access the builder's physical TPM.

## Upload an SRPM directly

Download the API token from the COPR account page and save it as
`~/.config/copr`. Create the project once, replacing `OWNER` as appropriate:

```sh
copr-cli create keyvisor \
  --chroot fedora-44-x86_64 \
  --chroot fedora-rawhide-x86_64
copr-cli build OWNER/keyvisor dist/keyvisor-0.1.0-1*.src.rpm
```

For a project owned by the logged-in user, `keyvisor` can be used instead of
`OWNER/keyvisor`.

## Install from COPR

After a successful build:

```sh
sudo dnf copr enable OWNER/keyvisor
sudo dnf install keyvisor
systemctl --user enable --now me.nexryai.keyvisor-agent.socket
```

Set `SSH_AUTH_SOCK` for shells that should use Keyvisor:

```sh
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/keyvisor/agent.sock"
```

## Release checklist

- Keep `Version` synchronized in `Cargo.toml` and `keyvisor.spec`.
- Bump `Release` for packaging-only changes.
- Update `%changelog`.
- Commit `Cargo.lock`; never build a release with an unlocked dependency graph.
- Run `cargo fmt`, `cargo clippy`, and the workspace tests before building.
- Inspect the SRPM source list to confirm `secretive/` is absent.
- Build with `mock` for every enabled COPR architecture and Fedora release.
- Inspect the binary package to confirm it contains only the CLI, agent,
  systemd user units, licenses, and documentation.
