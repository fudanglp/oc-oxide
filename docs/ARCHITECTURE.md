# Architecture

oc-oxide is split into small crates with strict responsibilities. The key rule
is that only the tunnel crates know about `libopenconnect`; route, DNS, config,
IPC, sync, and UI logic operate on Rust-owned session/config snapshots.

## Workspace Layout

Current layout:

```text
apps/
  desktop/                 Tauri 2 + React desktop client

bins/
  oc-oxide-daemon/         privileged daemon and recovery owner
  ocx/                     developer CLI and IPC client

crates/
  oc-oxide-openconnect-sys raw libopenconnect bindings and C shims
  oc-oxide-tunnel          safe tunnel lifecycle wrapper
  oc-oxide-auth            typed OpenConnect auth prompt bridge
  oc-oxide-net             Linux TUN and route policy
  oc-oxide-dns             systemd-resolved DNS policy
  oc-oxide-policy          ordered apply/revert orchestration
  oc-oxide-config          non-secret profile config and keyring integration
  oc-oxide-sync            GitHub private repo profile synchronization model
  oc-oxide-ipc             daemon/client protocol
```

## Crate Responsibilities

### `oc-oxide-openconnect-sys`

Raw bindings to `libopenconnect`.

Responsibilities:

- Generate bindings from `openconnect.h`.
- Link to system or locally built `libopenconnect`.
- Provide C shims where Rust cannot directly express callback signatures, especially variadic progress callbacks.
- Expose raw OpenConnect types and functions only.

It should not contain VPN profile logic, route logic, DNS logic, or UI concepts.

### `oc-oxide-tunnel`

Safe Rust wrapper around the subset of `libopenconnect` needed by oc-oxide.

Responsibilities:

- Initialize SSL once.
- Create/free `openconnect_info`.
- Set protocol to AnyConnect.
- Parse/set server URL.
- Register callbacks for progress, auth form processing, certificate validation, and stats.
- Drive `openconnect_obtain_cookie`, `openconnect_make_cstp_connection`, `openconnect_setup_tun_device`, `openconnect_setup_dtls`, and `openconnect_mainloop`.
- Expose cancellation through `openconnect_setup_cmd_pipe`.
- Copy `oc_ip_info` into Rust-owned snapshots.
- Classify mainloop return codes into terminal/transient/local-cancel errors.

OpenProtect's `gp-tunnel` is the closest reference, but its protocol-specific methods must be replaced with AnyConnect equivalents.

### `oc-oxide-auth`

Bridge OpenConnect auth forms into Rust events.

Responsibilities:

- Convert `openconnect_process_auth_form_vfn` calls into typed auth prompts.
- Represent form fields: username, password, authgroup, OTP/token, hidden fields, selects, and buttons.
- Let a UI/IPC caller submit answers back to the tunnel thread.
- Avoid storing secrets in plain text longer than necessary.

This crate should not try to recreate the AnyConnect login HTTP flow with `reqwest`. Let `libopenconnect` run the protocol-specific flow.

### `oc-oxide-net`

Route and network policy engine.

Responsibilities:

- Discover pre-VPN default route and local gateway/interface.
- Configure TUN address, MTU, and link state through a Linux backend.
- Pin the VPN gateway outside the tunnel.
- Apply default or split route decisions.
- Add profile-selected local bypass routes when needed, for example `198.18.0.0/15` via local gateway on OpenClash fake-ip networks.
- Decide which server-pushed routes are safe to apply.
- Revert all applied state on disconnect.

The first Linux backend uses `rtnetlink` directly for default-route discovery,
TUN configuration, and route apply/revert. Human-readable `ip route` rendering
remains useful for dry-run output and tests, but it is not the privileged apply
path.

Some AnyConnect deployments do not provide useful `CISCO_SPLIT_INC` values, so naive `vpnc-script` behavior creates `default dev tun0`. oc-oxide should make this explicit and testable rather than inheriting shell script behavior.

Route mode and DNS mode remain internal policy fields for tests, smoke paths,
and future research. The daemon-managed product path uses one connected policy:
full route coverage and full DNS through the VPN, while preserving the VPN
gateway, detected local LAN, and explicit local bypass CIDRs. The archived
[policy design record](archive/POLICY_MODE_DESIGN.md) explains the
company/local/public traffic model behind this choice.

### `oc-oxide-dns`

DNS configuration for the tunnel lifetime.

Responsibilities:

- Apply server-pushed DNS servers.
- Apply search/routing domains.
- Support split DNS for `corp.example.test`.
- Support a full-DNS mode if needed.
- Revert DNS state on disconnect.
- Prefer system-native APIs where practical.

Initial Linux target:

- `systemd-resolved` via `resolvectl`.
- Fallbacks can be added later.

OpenProtect's `gp-dns` is a strong reference for config shape and apply/revert behavior.

### `oc-oxide-policy`

TUN, route, and DNS policy orchestration.

Responsibilities:

- Build reusable plans from copied tunnel metadata and profile-selected policy.
- Apply TUN config before routes and DNS.
- Roll back TUN if route apply fails.
- Roll back routes and TUN if DNS apply fails.
- Revert DNS before routes and TUN on disconnect.
- Keep ordering testable with injected network and DNS backends.

### `oc-oxide-config`

Persistent user and profile configuration.

Responsibilities:

- Read/write profile config from XDG config paths.
- Keep non-secret profile fields in TOML.
- Represent company resources separately from local environment exceptions.
- Store secrets in OS keyring only if the user opts in.
- Never write passwords or OTP values to repo files or logs.

### `oc-oxide-sync`

GitHub private-repository profile synchronization.

Responsibilities:

- Model manifest and profile JSON objects stored in the selected private repo.
- Keep the sync schema non-secret and narrower than local profile TOML.
- Use GitHub App device flow and store refresh tokens in the OS keyring.
- Keep access tokens in memory and redact token/profile bytes from diagnostics.
- Preserve GitHub Contents API SHA conflict behavior.
- Write non-secret `deleted/<profile-id>.json` tombstones for explicit synced
  profile deletion, and clear matching tombstones when a profile is uploaded
  again.
- Restore same-name remote profiles as local copies instead of overwriting
  existing local TOML files.
- Keep local sync history as non-secret operation summaries under the user
  config directory; do not store tokens or profile blob bytes in history.

### `oc-oxide-ipc`

IPC protocol between Tauri/client and the privileged daemon.

Responsibilities:

- Unix socket protocol on Linux.
- JSON-line request/response and event stream.
- Commands: connect, submit auth form, disconnect, status, logs, diagnostics.
- State snapshots suitable for Tauri.

OpenProtect's `gp-ipc` is a good reference for socket naming and simple JSON-line framing.

### `oc-oxide-daemon`

Privileged backend process.

Responsibilities:

- Own the active tunnel session.
- Run `libopenconnect` on a dedicated thread.
- Serve IPC.
- Coordinate auth prompt round-trips.
- Copy OpenConnect IP metadata into policy-planning input.
- Apply/revert route and DNS state.
- Handle shutdown and cancellation.

The current daemon implementation separates a pure state core from a worker
controller. The controller owns one active tunnel worker, forwards auth and
cancel commands, and receives typed lifecycle events from the tunnel thread.

This process needs enough privilege for TUN, route, and DNS operations. The desktop app should not run fully privileged.

Daemon runtime model:

- The packaged service runs `oc-oxide-daemon serve` and starts idle. Starting
  or restarting the service must not connect a VPN profile by itself.
- The packaged service sets `OC_OXIDE_PROFILE_DIR=/etc/oc-oxide/profiles` so
  CLI/system-profile workflows do not depend on a login user's `HOME`.
- The desktop app sends the selected user's non-secret profile TOML over IPC
  when connecting. It does not need to copy desktop-managed profiles into
  `/etc`.
- The daemon authorizes IPC clients with polkit before accepting commands. See
  [SECURITY_MODEL.md](SECURITY_MODEL.md) for policy and secret-handling
  details.
- The service uses crash-only restart semantics. A restart should recover
  stale network state and return to the idle IPC-serving state, not reconnect
  automatically.
- The runtime journal at `/run/oc-oxide/session.json` stores only non-secret
  reversible network state. On startup, recovery runs before accepting IPC
  clients. Successful recovery deletes the journal; incomplete recovery leaves
  it for the next service start.

### `ocx`

Developer CLI and IPC client.

Responsibilities:

- Exercise daemon behavior without Tauri.
- Print status and diagnostics.
- Submit auth answers in terminal mode.

This is not an `openconnect` executable wrapper. It should talk to `oc-oxide-daemon`.

### Tauri Desktop App

Responsibilities:

- Ordinary user-facing UI.
- Connect to the privileged daemon over IPC.
- Render auth forms and OTP prompts.
- Manage local non-secret profiles and optional keyring-backed VPN passwords.
- Show session status, DNS/route diagnostics, logs, and connect/disconnect
  controls.
- Run GitHub Cloud Sync sign-in, upload, and restore flows.

Desktop daemon handoff:

- When the daemon socket is unavailable, the desktop app can request
  `systemctl start oc-oxide-daemon.service`. On Linux desktops with a polkit
  agent, this gives the user the normal privilege prompt for starting the
  packaged system service.
- If the packaged service is not installed or cannot be started, the desktop
  app reports the service name, socket path, and tarball/Debian installation
  hint instead of trying to run the full desktop app as root.

## Threading Model

`libopenconnect` session state is not assumed to be thread-safe. Keep all direct calls to one tunnel thread.

Cross-thread communication should use channels:

- daemon/control thread sends commands to tunnel thread.
- tunnel thread sends events back: progress, auth prompt, connected, stats, disconnected, error.
- cancellation uses `openconnect_setup_cmd_pipe` where available.

## State Model

Suggested top-level states:

```text
Idle
ResolvingGateway
Authenticating
ConnectingCstp
ConfiguringTun
ConfiguringNetwork
Connected
Reconnecting
Disconnecting
Failed
```

Each transition should produce an event that can be shown in CLI/Tauri logs.
