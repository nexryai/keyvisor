Name:           keyvisor
Version:        0.1.1
Release:        1%{?dist}
Summary:        Command-line TPM-backed SSH agent and key manager

# Keyvisor itself is MIT. The remaining terms cover statically linked Rust
# crates included in the binary package.
License:        MIT AND Apache-2.0 AND (Apache-2.0 WITH LLVM-exception) AND Unicode-3.0
Source0:        %{name}-%{version}.tar.xz
Source1:        %{name}-%{version}-vendor.tar.xz

# tss-esapi-sys 0.6 ships generated bindings for these Linux architectures.
ExclusiveArch:  x86_64 aarch64 armv7hl

BuildRequires:  cargo >= 1.92
BuildRequires:  rust >= 1.92
BuildRequires:  gcc
BuildRequires:  pkgconfig
BuildRequires:  pkgconfig(systemd)
BuildRequires:  pkgconfig(tss2-esys) >= 2.4.6
BuildRequires:  pkgconfig(tss2-mu) >= 2.4.6
BuildRequires:  pkgconfig(tss2-sys) >= 2.4.6
BuildRequires:  pkgconfig(tss2-tctildr) >= 2.4.6
BuildRequires:  systemd-rpm-macros
BuildRequires:  swtpm
BuildRequires:  openssh-clients

Recommends:     openssh-clients
Recommends:     pinentry-gnome3

%description
Keyvisor is a command-line SSH agent and key manager that creates ECDSA keys
inside a TPM 2.0 device and fixes them to that TPM. Private key parameters are
never exported from the TPM, and signing is performed with TPM2_Sign. Keys can
be configured for unattended use or protected by the TPM's rate-limited
authorization.

%prep
%autosetup -a 1
install -Dm0644 packaging/cargo-config.toml .cargo/config.toml

%build
export CARGO_HOME="%{_builddir}/keyvisor-cargo-home"
export CARGO_NET_OFFLINE=true
export CARGO_PROFILE_RELEASE_DEBUG=2
export CARGO_TARGET_DIR="%{_topdir}/cargo-target"
cargo build --locked --offline --workspace --release

%install
install -Dm0755 "%{_topdir}/cargo-target/release/keyvisor" \
    "%{buildroot}%{_bindir}/keyvisor"
install -Dm0755 "%{_topdir}/cargo-target/release/keyvisor-agent" \
    "%{buildroot}%{_bindir}/keyvisor-agent"
sed 's|@bindir@|%{_bindir}|' data/me.nexryai.keyvisor-agent.service.in \
    > me.nexryai.keyvisor-agent.service
install -Dm0644 me.nexryai.keyvisor-agent.service \
    "%{buildroot}%{_userunitdir}/me.nexryai.keyvisor-agent.service"
install -Dm0644 data/me.nexryai.keyvisor-agent.socket \
    "%{buildroot}%{_userunitdir}/me.nexryai.keyvisor-agent.socket"

%check
export CARGO_HOME="%{_builddir}/keyvisor-cargo-home"
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="%{_topdir}/cargo-target"
cargo test --locked --offline --workspace --all-features

%post
%systemd_user_post me.nexryai.keyvisor-agent.service me.nexryai.keyvisor-agent.socket

%preun
%systemd_user_preun me.nexryai.keyvisor-agent.service me.nexryai.keyvisor-agent.socket

%postun
%systemd_user_postun_with_restart me.nexryai.keyvisor-agent.service me.nexryai.keyvisor-agent.socket

%files
%license LICENSE
%doc README.md PLANS.md
%{_bindir}/keyvisor
%{_bindir}/keyvisor-agent
%{_userunitdir}/me.nexryai.keyvisor-agent.service
%{_userunitdir}/me.nexryai.keyvisor-agent.socket

%changelog
* Wed Aug 12 2026 nexryai <noreply@nexryai.me> - 0.1.1-1
- Default to the kernel TPM resource manager

* Wed Jul 29 2026 nexryai <noreply@nexryai.me> - 0.1.0-1
- Initial COPR package
