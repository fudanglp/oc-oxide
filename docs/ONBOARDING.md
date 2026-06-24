# Onboarding

This is the contributor orientation for oc-oxide. Use the root
[README.md](../README.md) for the project overview, and use
[ARCHITECTURE.md](ARCHITECTURE.md) for the workspace map and crate
responsibilities.

## Core Direction

- Use `libopenconnect` directly through Rust FFI.
- Do not implement an intermediate wrapper around the external `openconnect`
  CLI.
- Let `libopenconnect` own the VPN protocol engine: TLS negotiation,
  AnyConnect authentication exchange, CSTP, DTLS, packet loop, reconnect
  primitives, and TUN creation.
- Let Rust own auth UI events, session lifecycle, route policy, DNS policy,
  local bypass handling, IPC, diagnostics, config, desktop integration, and
  recovery.

## Non-Goals

- Do not reimplement AnyConnect/CSTP/DTLS in Rust.
- Do not automate SMS or out-of-band OTP reading.
- Do not store passwords, OTP values, cookies, private keys, or router
  credentials in repository files.
- Do not copy OpenProtect's GlobalProtect protocol/auth/HIP crates as
  dependencies.

## Contribution Boundaries

- Keep privileged TUN, route, DNS, polkit, and recovery work in
  `oc-oxide-daemon`.
- Keep the Tauri desktop app unprivileged; it should talk to the daemon over
  IPC for VPN control.
- Keep local profile TOML and GitHub Sync objects non-secret.
- Store optional VPN account passwords only in the OS keyring when the user
  opts in.
- Treat `vendor/openconnect` as upstream-owned source. oc-oxide-specific build
  logic, Rust bindings, and callback shims belong in
  `crates/oc-oxide-openconnect-sys`, not as direct edits to upstream files.

## Reference Material

Use these references when changing the tunnel or auth path:

- `vendor/openconnect`: vendored upstream OpenConnect source for builds and
  distribution.
- `vendor/openconnect/openconnect.h`: public `libopenconnect` API.
- `vendor/openconnect/main.c`: OpenConnect CLI flow reference for FFI ordering.
- `vendor/openconnect/auth.c`: auth form handling reference.
- `vendor/openconnect/script.c`: server-pushed config to environment mapping.
- [archive/ANYCONNECT_AUTH_AND_FAKE_IP_NOTES.md](archive/ANYCONNECT_AUTH_AND_FAKE_IP_NOTES.md):
  archived rationale for the observed auth flow and fake-ip bypass handling.

## Read Next

- [ARCHITECTURE.md](ARCHITECTURE.md) for crate boundaries and runtime model.
- [SECURITY_MODEL.md](SECURITY_MODEL.md) for privilege and secret handling.
- [DEVELOPMENT.md](DEVELOPMENT.md) for local build, test, and manual E2E.
- [DISTRIBUTION.md](DISTRIBUTION.md) for packaging and release artifacts.
