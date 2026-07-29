# Keyvisor implementation plan

The filename `PLASN.md` follows the requested project convention.

## 1. Product concept

Keyvisor brings Secretive's focused key-management model to GNOME:

- a compact key list on the left;
- clear agent health and setup state;
- a detail view containing fingerprints, the public key, and its path;
- one prominent action for creating a key;
- notifications and an inspectable activity history for signing requests.

The UI uses adaptive Libadwaita widgets and GNOME HIG patterns rather than
copying the macOS layout or visual styling.

## 2. Security boundary

The private key is generated inside the TPM as a non-migratable signing object.
For the first supported algorithm, Keyvisor will create an ECDSA NIST P-256
child beneath a Keyvisor storage parent with:

- `fixedTPM`;
- `fixedParent`;
- `sensitiveDataOrigin`;
- `userWithAuth`;
- `signEncrypt`;
- no decrypt or duplication capability.

The host may persist `TPM2B_PUBLIC` and the encrypted/integrity-protected
`TPM2B_PRIVATE` blob produced by the TPM. That blob is not plaintext private key
material and is usable only through its TPM parent. Signing calls TPM2_Sign;
only the signature returns to Keyvisor. There is no software-key fallback and
no private-key import/export feature.

At key creation the user chooses one of two authorization modes:

- **No PIN** uses an empty object `authValue` and sets `noDA`. The agent can ask
  the TPM to sign without an interactive authorization step. The UI must warn
  that any process able to use the user's agent socket can request signatures.
- **TPM-protected PIN** sets a non-empty object `authValue` and leaves `noDA`
  clear. TPM dictionary-attack protection therefore counts failed
  authorization attempts and can refuse further attempts. Keyvisor asks for
  this PIN for every signature and never persists or caches it.

PIN-bearing TPM commands use a salted HMAC session with command/response
parameter encryption rather than a plaintext password session. Keyvisor keeps
PIN buffers short-lived and zeroizes buffers it owns. Toolkit and operating
system copies are treated honestly in the threat model rather than claiming the
PIN never enters host memory.

Dictionary-attack counters and the `maxTries`, `recoveryTime`, and
`lockoutRecovery` parameters are TPM-wide state, not per-key settings. Keyvisor
reads and displays the effective values but never calls
`TPM2_DictionaryAttackParameters` or resets the lockout on a physical TPM.
Changing those values could affect disk encryption and unrelated TPM users.

The TPM protects extraction, but it does not identify which desktop process
asked the user's agent to sign. Socket ownership, peer credentials, request
rate limits, optional per-use confirmation, destination constraints, and an
audit history reduce misuse. UI confirmation alone is explicitly not claimed
to stop malware running as the same user.

## 3. Process architecture

```text
ssh / git
    │ SSH agent protocol, $SSH_AUTH_SOCK
    ▼
keyvisor-agent ── control/status API ── keyvisor-ui
    │
    │ generate, load, sign (public metadata out)
    ▼
keyvisor-tpm ── TPM2-TSS ESAPI ── TPM 2.0
```

- `keyvisor-agent` runs as a socket-activated systemd user service. It can also
  bind the same owner-only socket directly for development environments.
- Its Unix socket lives below `$XDG_RUNTIME_DIR/keyvisor/agent.sock`, is owned
  by the user, and has mode `0600`.
- `keyvisor-ui` is not required for identity enumeration or a no-PIN
  signature. A TPM-PIN signature activates the authorization UI through a
  narrow per-user control channel and fails closed if no prompt can be shown.
- Metadata lives below `$XDG_DATA_HOME/me.nexryai.keyvisor`; it contains names,
  public keys, fingerprints, policy descriptors, TPM names, and wrapped TPM
  blobs. A bounded history contains only timestamps, key identifiers/names,
  policy labels, and outcomes—never request payloads. The directory is mode
  `0700`, records are mode `0600`, and writes use a same-directory temporary
  file followed by an atomic rename.

## 4. SSH protocol scope

Phase one supports:

- `SSH2_AGENTC_REQUEST_IDENTITIES`;
- `SSH2_AGENTC_SIGN_REQUEST`;
- ECDSA P-256 keys exposed as `ecdsa-sha2-nistp256`;
- strict packet length limits and request timeouts.

Add/remove identity, smart-card, lock/unlock, and unknown extension requests
fail closed. RSA/SHA-2 can be added after the ECDSA path and its encoding tests
are complete.

## 5. GNOME UI

The main window is an adaptive `AdwNavigationSplitView`.

- Sidebar: TPM-backed keys, certificates later, and a visible agent status.
- The key collection uses Libadwaita's `navigation-sidebar` presentation, with
  the primary create action and standard main menu above it.
- Empty state: explains hardware-bound keys and offers “Create a Key”.
- Key detail: SHA-256 fingerprint, public key, public-key path, TPM state,
  policy, last use, copy actions, and destructive actions kept away from the
  primary flow.
- Creation dialog: name, algorithm, and confirmation policy with plain-language
  consequences.
- Authorization uses two HIG-style choice rows: “No PIN” and
  “TPM-protected PIN”. Selecting the latter reveals PIN and confirmation
  entries plus a warning that the lockout policy is TPM-wide. The primary
  action stays disabled until the PINs match. Displaying the current numeric DA
  state is still pending.
- An `AdwBreakpoint` collapses the split view below 700sp into native
  hierarchical navigation with back gestures and keyboard navigation.
- Signing activity is a page in that navigation hierarchy rather than a
  modal information dialog.
- The main menu provides Refresh, Signing Activity, Keyboard Shortcuts, and
  About Keyvisor using standard GNOME actions and dialogs.
- Icon-only controls have tooltips and explicit accessible names. Full
  screen-reader, High Contrast, and reduced-motion testing remains a release
  requirement.

The full-color icon uses a softly shaded, dimensional GNOME application-icon
language: a blue hardware-vault form with a gold keyhole. It is original artwork
and is paired with a monochrome symbolic icon.

## 6. Milestones

### M0 — initialization (complete)

- Cargo workspace and four crate boundaries;
- launchable GTK 4/Libadwaita application shell;
- application ID, desktop metadata, AppStream metadata, and SVG icons;
- security invariants and project plan;
- compile and metadata validation.

### M1 — TPM backend (implemented)

- [x] add the TPM2-TSS/ESAPI dependency;
- [x] create/load a deterministic Keyvisor storage parent without changing TPM
  ownership or allocating a persistent handle;
- [x] generate non-migratable P-256 signing objects in no-PIN and TPM-PIN
  modes;
- [x] use encrypted salted HMAC sessions and map TPM authorization/lockout
  errors;
- [x] read, but never modify, TPM dictionary-attack properties;
- [x] convert public areas and ECDSA signatures to SSH wire formats;
- [x] persist only validated public metadata and TPM-wrapped blobs;
- [x] exercise generation, wrong/correct PIN signing, no-PIN signing, DA state,
  and reconnect/reload through `swtpm`;
- [ ] add explicit negative duplication and full lockout/recovery tests.

### M2 — SSH agent (core path implemented)

- [x] expose a narrow `generate` command for the GUI; PIN input travels over a
  private stdin pipe rather than process arguments;
- [x] implement a 256 KiB-bounded protocol parser and serializer;
- [x] create a mode `0600` Unix socket below a mode `0700` runtime directory,
  with stale-socket checks and per-connection I/O timeouts;
- [x] implement identity enumeration and ECDSA/SHA-256 TPM signing;
- [x] prompt through a separate non-unique Libadwaita process for each
  TPM-PIN signature, with cancellation and no cache;
- [x] test malformed packets, no-PIN signing, PIN signing, prompt
  cancellation, and socket permissions end to end with `swtpm`;
- [x] accept a validated mode `0600` listener from native systemd socket
  activation;
- [x] serve up to 16 clients concurrently while serializing only TPM access;
- [x] enforce a two-minute PIN-prompt deadline;
- [x] propagate SSH client disconnection through PIN authorization and check it
  before and after synchronous TPM work. TPM2-TSS does not expose cancellation
  for an ESAPI command already executing, so a completed result is discarded.

### M3 — management API and GUI (substantially implemented)

- [x] authenticated per-user session D-Bus API for public key metadata,
  deletion, bounded history, and change signals;
- [x] HIG-style creation dialog with no-authentication and TPM-rate-limited PIN
  choices, confirmation validation, and asynchronous agent invocation;
- [x] HIG-style per-signature TPM PIN prompt;
- [x] live key list, authentication-policy details, SHA-256 fingerprints,
  OpenSSH public-key rendering, and clipboard actions;
- [x] destructive deletion confirmation and automatic list refresh;
- [x] visible socket-based agent state;
- [x] desktop request notifications and a privacy-preserving, owner-only
  activity history bounded to the newest 200 entries;
- [x] adaptive split-view collapse, standard primary menu, About and Keyboard
  Shortcuts dialogs, accessible icon-button names, and standard accelerators;
- [ ] full screen-reader, High Contrast, and reduced-motion tests.

### M4 — packaging and hardening

- [x] systemd user service and native socket-activation unit;
- [x] Fedora RPM spec, locked offline crate vendor archive, local SRPM helper,
  and COPR `make_srpm` SCM integration;
- [x] GitHub Actions checks formatting and lints, runs unit tests, exercises the
  TPM backend through isolated `swtpm` instances, and verifies agent
  interoperability with stock OpenSSH clients;
- environment setup helper;
- Flatpak feasibility review (TPM device and SSH socket access may favor native
  packaging);
- threat-model review, dependency audit, fuzzing, translations, help, and
  reproducible release builds.

## 7. Definition of done

Keyvisor is not “TPM-backed” merely because a blob is sealed. Completion
requires evidence that keys are TPM-generated, fixed to this TPM and parent,
all SSH signatures are produced by TPM2_Sign, unsupported requests fail closed,
and no normal or error path exposes plaintext private parameters.
