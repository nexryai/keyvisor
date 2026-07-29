Name:           keyvisor
Version:        0.1.0
Release:        1%{?dist}
Summary:        TPM-backed SSH agent and key manager for GNOME

# Keyvisor itself is MIT. The remaining terms cover statically linked Rust
# crates and the CC0 AppStream metadata included in the binary package.
License:        MIT AND Apache-2.0 AND (Apache-2.0 WITH LLVM-exception) AND Unicode-3.0 AND CC0-1.0
Source0:        %{name}-%{version}.tar.xz
Source1:        %{name}-%{version}-vendor.tar.xz

# tss-esapi-sys 0.6 ships generated bindings for these Linux architectures.
ExclusiveArch:  x86_64 aarch64 armv7hl

BuildRequires:  cargo >= 1.92
BuildRequires:  rust >= 1.92
BuildRequires:  gcc
BuildRequires:  meson >= 1.3.0
BuildRequires:  pkgconfig
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(gtk4) >= 4.10
BuildRequires:  pkgconfig(libadwaita-1) >= 1.8
BuildRequires:  pkgconfig(systemd)
BuildRequires:  pkgconfig(tss2-esys) >= 2.4.6
BuildRequires:  pkgconfig(tss2-mu) >= 2.4.6
BuildRequires:  pkgconfig(tss2-sys) >= 2.4.6
BuildRequires:  pkgconfig(tss2-tctildr) >= 2.4.6
BuildRequires:  desktop-file-utils
BuildRequires:  appstream
BuildRequires:  systemd-rpm-macros
BuildRequires:  swtpm

Recommends:     openssh-clients

%description
Keyvisor is a GNOME SSH agent and key manager that creates ECDSA keys inside a
TPM 2.0 device and fixes them to that TPM. Private key parameters are never
exported from the TPM, and signing is performed with TPM2_Sign. Keys can be
configured for unattended use or protected by the TPM's rate-limited
authorization.

%prep
%autosetup -a 1
install -Dm0644 packaging/cargo-config.toml .cargo/config.toml

%build
export CARGO_HOME="%{_builddir}/keyvisor-cargo-home"
export CARGO_NET_OFFLINE=true
export CARGO_PROFILE_RELEASE_DEBUG=2
export CARGO_TARGET_DIR="%{_topdir}/cargo-target"
%meson -Dcargo-profile=release
%meson_build

%install
%meson_install

%check
export CARGO_HOME="%{_builddir}/keyvisor-cargo-home"
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="%{_topdir}/cargo-target"
cargo test --locked --offline --workspace --all-features
desktop-file-validate \
    %{buildroot}%{_datadir}/applications/me.nexryai.keyvisor.desktop

%post
%systemd_user_post me.nexryai.keyvisor-agent.service me.nexryai.keyvisor-agent.socket

%preun
%systemd_user_preun me.nexryai.keyvisor-agent.service me.nexryai.keyvisor-agent.socket

%postun
%systemd_user_postun_with_restart me.nexryai.keyvisor-agent.service me.nexryai.keyvisor-agent.socket

%files
%license LICENSE
%doc README.md PLASN.md
%{_bindir}/keyvisor
%{_bindir}/keyvisor-agent
%{_datadir}/applications/me.nexryai.keyvisor.desktop
%{_datadir}/metainfo/me.nexryai.keyvisor.metainfo.xml
%{_datadir}/icons/hicolor/scalable/apps/me.nexryai.keyvisor.svg
%{_datadir}/icons/hicolor/symbolic/apps/me.nexryai.keyvisor-symbolic.svg
%{_userunitdir}/me.nexryai.keyvisor-agent.service
%{_userunitdir}/me.nexryai.keyvisor-agent.socket

%changelog
* Wed Jul 29 2026 Nexryai <noreply@nexryai.me> - 0.1.0-1
- Initial COPR package
