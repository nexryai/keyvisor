# Keyvisor implementation plan

## 1. Product direction

Keyvisor is a command-line SSH agent and key manager for TPM-backed signing
keys. The former graphical application has been removed completely. Key
creation, inspection, deletion, agent status, signing history, configuration,
and per-signature authorization are available through a `keyvisor` CLI suitable
for interactive use and shell automation.

The application ID remains `me.nexryai.keyvisor` for storage paths, systemd
units, and other compatibility-sensitive identifiers. It does not imply a
graphical application.

The workspace and packages contain no GUI crate, desktop entry, AppStream
desktop component, application icons, graphical toolkit dependency, or
UI-oriented D-Bus API.

## 2. Security boundary

The private key is generated inside the TPM as a non-migratable signing object.
For the first supported algorithm, Keyvisor creates an ECDSA NIST P-256 child
beneath a Keyvisor storage parent with:

- `fixedTPM`;
- `fixedParent`;
- `sensitiveDataOrigin`;
- `userWithAuth`;
- `signEncrypt`;
- no decrypt or duplication capability.

The host may persist `TPM2B_PUBLIC` and the encrypted/integrity-protected
`TPM2B_PRIVATE` blob produced by the TPM. That blob is not plaintext private key
material and is usable only through its TPM parent. Signing calls `TPM2_Sign`;
only the signature returns to Keyvisor. There is no software-key fallback and
no private-key import, export, duplication, or migration feature.

At key creation the user chooses one of two authorization modes:

- **No PIN** uses an empty object `authValue` and sets `noDA`. The agent can ask
  the TPM to sign without interactive authorization. The CLI must warn that any
  process able to use the user's agent socket can request signatures.
- **TPM-protected PIN** sets a non-empty object `authValue` and leaves `noDA`
  clear. TPM dictionary-attack protection counts failed authorization attempts
  and can refuse further attempts. Keyvisor requires the PIN for every
  signature and never persists or caches it.

PIN-bearing TPM commands use a salted HMAC session with command/response
parameter encryption rather than a plaintext password session. CLI PIN input
must come from a controlling terminal or another explicitly configured
owner-only helper, never command-line arguments or environment variables.
Keyvisor keeps owned PIN buffers short-lived and zeroizes them. A new terminal
authorization protocol uses an owner-only socket, validates peer credentials,
and exposes no SSH payload. Missing or invalid authorization fails closed; a
broader threat-model review remains part of release hardening.

Dictionary-attack counters and the `maxTries`, `recoveryTime`, and
`lockoutRecovery` parameters are TPM-wide state, not per-key settings. Keyvisor
may display the effective values but never calls
`TPM2_DictionaryAttackParameters` or resets lockout on a physical TPM.

The TPM protects extraction, but it does not identify which local process asked
the user's agent to sign. Socket ownership, peer credentials, request limits,
explicit per-use authorization, and a privacy-preserving history reduce misuse.
A CLI confirmation is defense in depth and is not protection against code
already running as the same user.

## 3. Target architecture

```text
ssh / git
    │ SSH agent protocol, $SSH_AUTH_SOCK
    ▼
keyvisor-agent ── owner-only control protocol ── keyvisor CLI
    │ sign                                  │ create
    └──────────────┬────────────────────────┘
                   ▼
             keyvisor-tpm ── TPM2-TSS ESAPI ── TPM 2.0
```

- `keyvisor-core` contains dependency-light domain types and protocol-neutral
  contracts.
- `keyvisor-tpm` is the only crate that talks to TPM2-TSS/ESAPI.
- `keyvisor-agent` owns SSH agent framing, request validation, socket lifecycle,
  signing history, and TPM signing operations. It runs as a socket-activated
  systemd user service or as a foreground process for development.
- `keyvisor-cli` provides the installed `keyvisor` command and contains no GUI
  toolkit dependency. It manages public metadata and asks `keyvisor-tpm` to
  generate TPM-resident signing objects, but it never performs SSH signing.

The agent socket lives below `$XDG_RUNTIME_DIR/keyvisor/agent.sock`, is owned by
the current user, and has mode `0600`. Any separate management or authorization
socket must have the same ownership guarantees, validate peer credentials, use
bounded messages and deadlines, and carry no SSH signing payload unless the
protocol explicitly requires and reviews it. PINs must never enter D-Bus,
persistent state, logs, command arguments, or environment variables.

Metadata lives below `$XDG_DATA_HOME/me.nexryai.keyvisor`. It contains names,
public keys, fingerprints, policy descriptors, TPM names, and TPM-wrapped
blobs. The directory is mode `0700`, records are mode `0600`, and writes use a
same-directory temporary file followed by an atomic rename. Signing history is
bounded and contains only timestamps, key identifiers/names, policy labels, and
outcomes—never request payloads.

## 4. CLI contract

The CLI provides these stable, scriptable command families:

```text
keyvisor key create
keyvisor key list
keyvisor key show ID
keyvisor key delete ID
keyvisor config list
keyvisor config get NAME
keyvisor config set NAME VALUE
keyvisor agent status
keyvisor history
keyvisor authorize REQUEST_ID
```

The following rules define the implemented CLI contract:

- human-readable output is the default and a versioned machine-readable format
  is available explicitly;
- destructive operations require an interactive confirmation unless an
  explicit automation flag is supplied;
- secrets are read without terminal echo and never accepted as arguments;
- stdout is reserved for requested data, while diagnostics go to stderr;
- success and common failure modes have documented, stable exit behavior;
- non-interactive use fails clearly when an operation requires a terminal;
- configuration and persistent data follow documented XDG paths, while
  documented environment variables select TPM and socket endpoints;
- configuration contains no PINs or other secrets, and it cannot alter or reset
  physical-TPM dictionary-attack parameters.

## 5. SSH protocol scope

The first release supports:

- `SSH2_AGENTC_REQUEST_IDENTITIES`;
- `SSH2_AGENTC_SIGN_REQUEST`;
- ECDSA P-256 keys exposed as `ecdsa-sha2-nistp256`;
- strict packet length limits and request timeouts.

Add/remove identity, smart-card, lock/unlock, and unknown extension requests
fail closed. RSA/SHA-2 may be added only after the ECDSA path and its encoding
tests are complete.

## 6. Milestones

### M0 — existing TPM and SSH foundation (implemented)

- [x] generate non-migratable P-256 signing objects in no-PIN and TPM-PIN modes;
- [x] use encrypted salted HMAC sessions and map authorization/lockout errors;
- [x] persist only validated public metadata and TPM-wrapped blobs;
- [x] implement bounded SSH agent framing, identity enumeration, and signing;
- [x] provide owner-only sockets and native systemd socket activation;
- [x] exercise TPM and OpenSSH paths with isolated `swtpm` instances.

### M1 — CLI management parity (implemented)

- [x] add a dependency-light `keyvisor-cli` crate producing `keyvisor`;
- [x] implement key create, list, show, and delete commands;
- [x] implement config list, get, and set commands for documented non-secret
  settings with atomic owner-only persistence;
- [x] implement agent status and bounded signing-history commands;
- [x] define human and versioned machine-readable output contracts;
- [x] read creation PINs from a terminal, confirm them, minimize copies, and
  zeroize owned buffers;
- [x] document shell setup, configuration precedence, exit behavior, and
  non-interactive limitations;
- [x] add focused CLI parsing, output, permission, and `swtpm` integration tests.

### M2 — terminal per-signature authorization (core implemented)

- [x] design an owner-only, peer-validated, bounded authorization protocol;
- [x] expose pending requests using opaque identifiers and non-sensitive key
  metadata, never raw SSH payloads;
- [x] implement `keyvisor authorize REQUEST_ID` with no-echo terminal PIN input;
- [x] enforce cancellation, client-disconnect propagation, and a configurable
  authorization deadline without caching a PIN;
- [x] ensure concurrent requests cannot authorize the wrong operation;
- [x] document that authorization is defense in depth against accidental use,
  not a boundary against same-user malware;
- [ ] test wrong/correct PINs, cancellation, timeouts, disconnects, concurrency,
  and dictionary-attack reporting with `swtpm`.

### M3 — GUI removal (complete)

- [x] remove `keyvisor-ui` from the workspace and source tree;
- [x] remove graphical toolkit and UI-only GLib/D-Bus dependencies;
- [x] remove the desktop entry, AppStream desktop component, application icons,
  screenshots, notifications, and GUI launch/install rules;
- [x] remove the UI-oriented D-Bus management API after CLI parity exists;
- [x] update Meson, RPM/COPR packaging, CI, and release artifacts to install
  only the CLI, agent, systemd units, licenses, and documentation;
- [x] verify that no GUI process or toolkit is required at build time or runtime.

### M4 — hardening and release

- [ ] add explicit negative duplication and full lockout/recovery tests;
- [ ] review the CLI/control-protocol threat model and dependencies;
- [ ] add fuzzing for SSH and control protocol parsers;
- [ ] audit logs and diagnostic paths for sensitive values;
- [ ] produce reproducible native packages and operator documentation.

## 7. Definition of done

Keyvisor's CLI transition is complete when the GUI crate and desktop artifacts
are gone, all supported management workflows are available through documented
CLI commands, TPM-PIN signatures have a tested terminal authorization path, and
packages require no graphical toolkit. Keyvisor is TPM-backed only when keys
are TPM-generated and fixed to this TPM and parent, every SSH signature is
produced by `TPM2_Sign`, unsupported requests fail closed, and no normal or
error path exposes plaintext private parameters.
