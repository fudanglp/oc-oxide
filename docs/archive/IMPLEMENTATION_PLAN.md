# Implementation Plan

The implementation should go directly to `libopenconnect` FFI. A developer CLI is fine, but the CLI should control oc-oxide's daemon/FFI backend, not shell out to the `openconnect` executable.

## Milestone 0: Workspace Skeleton

Create a Cargo workspace with:

```text
crates/oc-oxide-openconnect-sys
crates/oc-oxide-tunnel
crates/oc-oxide-auth
crates/oc-oxide-net
crates/oc-oxide-dns
crates/oc-oxide-policy
crates/oc-oxide-config
crates/oc-oxide-ipc
bins/oc-oxide-daemon
bins/ocx
```

Keep `apps/desktop` for Tauri once the backend proves it can connect.

## Milestone 1: Raw FFI

Build `oc-oxide-openconnect-sys`.

Tasks:

- Use `vendor/openconnect/openconnect.h` as the primary header reference.
- Keep upstream OpenConnect source vendored under `vendor/openconnect` for
  reproducible builds and future distribution.
- Treat external OpenConnect source trees as optional comparison references
  only; the vendored header is the project reference.
- Use `bindgen` to generate bindings.
- Build/link the vendored `libopenconnect` by default once the build pipeline is
  added.
- Keep a `pkg-config` or environment override path available for development
  and diagnostics against a system or separately built OpenConnect.
- Add a C shim for the progress callback if needed, following OpenProtect's `gp-openconnect-sys/csrc/progress_shim.c`.

Useful symbols to bind first:

```text
openconnect_init_ssl
openconnect_vpninfo_new
openconnect_vpninfo_free
openconnect_set_protocol
openconnect_parse_url
openconnect_set_reported_os
openconnect_obtain_cookie
openconnect_make_cstp_connection
openconnect_setup_tun_device
openconnect_setup_dtls
openconnect_disable_dtls
openconnect_mainloop
openconnect_get_ip_info
openconnect_get_ifname
openconnect_setup_cmd_pipe
```

Also bind auth/progress/cert/stats callback types.

## Milestone 2: Tunnel Wrapper

Build `oc-oxide-tunnel`.

Tasks:

- Wrap `openconnect_info` in an owned Rust type.
- Make the wrapper explicitly not `Send`/`Sync`.
- Add `CancelHandle` based on `openconnect_setup_cmd_pipe`.
- Add protocol selection for AnyConnect.
- Add URL parsing and server setup.
- Add callback registration points.
- Add safe snapshot type for server-pushed IP info.
- Classify mainloop return codes.

Initial connect flow:

```text
openconnect_init_ssl
openconnect_vpninfo_new
openconnect_set_protocol("anyconnect")
openconnect_parse_url("https://vpn.example.test:555/")
openconnect_obtain_cookie
openconnect_make_cstp_connection
openconnect_setup_tun_device(NULL script)
openconnect_get_ifname
openconnect_get_ip_info
openconnect_setup_dtls
openconnect_mainloop
```

The exact order should be checked against `vendor/openconnect/main.c` and
`vendor/openconnect/openconnect.h`.

## Milestone 3: Auth Event Bridge

Build `oc-oxide-auth`.

Status: complete for the no-network bridge. `oc-oxide-auth` now copies
OpenConnect forms into typed requests, carries transient submitted responses
back to the tunnel thread, redacts secret answer debug output, maps public
`OC_FORM_RESULT_*` values, and supports authgroup refresh via
`OC_FORM_RESULT_NEWGROUP`. `oc-oxide-tunnel` can create a session with combined
progress/auth callbacks using a shared OpenConnect `privdata` context. Real VPN
cookie acquisition remains outside this milestone's automated tests and must
not use committed credentials or real VPN URLs.

Tasks:

- Convert OpenConnect auth forms into typed Rust structs.
- Support username/password/authgroup/OTP fields.
- Let daemon/UI submit filled forms back to the tunnel thread.
- Redact secrets in logs.

Current company auth flow:

- Server asks username/password.
- Server then sends an OTP through SMS or another out-of-band provider.
- User manually enters OTP.

Do not automate OTP reading in the first version.

## Milestone 4: Network Policy

Build `oc-oxide-net`.

Status: complete for no-side-effect planning, injected command execution, and
Linux netlink-backed apply/revert. The net crate now parses pre-VPN Linux
default route output, discovers the current default route through netlink,
parses copied OpenConnect route parts, plans VPN gateway pins, supports
split/full/off route modes, preserves configured local bypass CIDRs, routes VPN
internal/include networks to the tunnel, sends excludes back to the local
gateway, renders Linux `ip route` argv for previews, and applies or reverts TUN
config plus planned routes through an injected Linux backend. Automated tests do
not modify host routes. The daemon's target connected policy should use full
route coverage while preserving gateway pins, explicit local bypasses, and
automatically detected local LAN routes.

Tasks:

- Capture pre-VPN default route before the tunnel changes routes.
- Resolve and pin VPN gateway outside the tunnel.
- Apply configured local bypass routes. For an OpenClash fake-ip profile this
  can include:

```text
198.18.0.0/15 via local gateway dev local interface
```

- Apply VPN routes based on server-pushed config and local policy.
- Revert state on disconnect.

For the observed VPN, the server sends:

```text
INTERNAL_IP4_NETADDR=198.51.100.0
INTERNAL_IP4_NETMASKLEN=24
CISCO_SPLIT_EXC_0_ADDR=203.0.113.10/32
CISCO_SPLIT_EXC_1_ADDR=0.0.0.0/32
```

It does not send a useful `CISCO_SPLIT_INC`, so connected sessions should plan a
VPN default route explicitly.

## Milestone 5: DNS Policy

Build `oc-oxide-dns`.

Status: complete for no-side-effect planning and injected execution on the
systemd-resolved path. The DNS crate now parses copied OpenConnect DNS parts,
models DNS modes for internal tests, renders `resolvectl` argv for DNS servers,
search/routing domains, `~.` full-DNS routing, and interface revert, then
applies or reverts rendered commands through an injected runner. Automated tests
do not modify host DNS state. The daemon's target connected policy should always
use full DNS routing through VPN-provided DNS servers.

Tasks:

- Read DNS servers from `openconnect_get_ip_info`.
- Apply VPN-provided DNS servers, such as `192.0.2.53` and `198.51.100.53`
  in documentation examples.
- Apply `corp.example.test` as the search/routing domain.
- On Linux with `systemd-resolved`, use `resolvectl`.
- Render full DNS routing:

```text
all DNS -> VPN DNS via `~.`
```

## Milestone 6: Daemon And IPC

Build `oc-oxide-ipc` and `oc-oxide-daemon`.

IPC commands:

```text
connect(profile)
submit_auth(form_id, fields)
disconnect
status
diagnostics
tail_logs
```

Events:

```text
progress
auth_prompt
auth_rejected
connected
network_applied
stats
disconnecting
disconnected
error
```

The daemon owns privileged operations. Tauri should be an unprivileged client.
`oc-oxide-policy` centralizes ordered TUN, route, and DNS apply/revert, including
route and DNS failure rollback, so the daemon should call that crate rather than
duplicating policy ordering.

Status:

- Complete: pure daemon state core.
- Complete: worker controller owning one active tunnel worker.
- Complete: worker command/event channel.
- Complete: auth submission forwarding to the tunnel thread.
- Complete: cancellation and network-reverted lifecycle events.
- Complete: tunnel-event bridge from `oc-oxide-tunnel` events to daemon events.
- Complete: injectable `OpenConnectTunnelWorker` boundary.
- Complete: system workflow wiring `libopenconnect` callbacks, TUN creation,
  policy apply/revert, mainloop, and command-pipe cancellation.
- Complete: no-network `daemon-smoke` through the worker controller path.
- Complete: daemon JSON-line IPC server on a Unix socket.
- Complete: profile resolver backed by non-secret local config files.
- Complete: daemon binary `serve` mode wired to the system OpenConnect worker
  factory.
- Complete: daemon-managed TUN uses a stable `ocx0` interface name, removes
  stale `ocx0` before setup, and deletes the managed link after policy revert.
- Complete: real daemon smoke with a privileged daemon, local profile, and
  `ocx connect/status/diagnostics/disconnect`.

Current daemon profile files are intentionally non-secret TOML files. The
resolver reads `OC_OXIDE_PROFILE_DIR` or defaults to
`~/.config/oc-oxide/profiles/<name>.toml`. The legacy `key=value` `.conf`
format is not supported. Target connected-profile shape:

```toml
[connection]
server = "https://vpn.example.test:555/"
reported_os = "linux"
authgroup = "engineering"
username = "alice"

[company]
domains = ["example.test", "object-storage.example.test"]

[local]
bypass = ["198.18.0.0/15"]
```

Local user profile files may contain a username. Do not put passwords, OTP
values, cookies, private keys, or real VPN endpoints in repository files.

The implemented profile policy is summarized here and explained in the archived
[policy design record](archive/POLICY_MODE_DESIGN.md). The short version is
that the initial product has one connected policy:

```text
default route uses ocx0
all DNS uses VPN-provided DNS
VPN gateway stays pinned to the pre-VPN gateway
current directly connected LAN is detected and kept local
profile local.bypass CIDRs are kept local
```

Profiles should keep explicit non-secret company DNS domains and explicit local
bypass CIDRs. Do not put current-LAN CIDRs in TOML; detect them at connection
time.

### Milestone 6A: Recovery Hardening

Status: complete. Route/DNS/TUN recovery is hardened so daily use should not
leave the host in a broken local-network state.

Goals:

- Treat route and DNS restore as first-class behavior, not best-effort cleanup.
- Snapshot pre-VPN state before applying policy.
- Revert only state that oc-oxide created or replaced.
- Roll back partial apply failures in reverse dependency order.
- Attempt stale `ocx0` DNS/route cleanup at daemon startup before deleting the
  stale managed interface.
- Preserve local router, local LAN, and fake-ip DNS paths while connected.

Required state to capture:

- Pre-VPN default route, including gateway, interface, source, and metric when
  available.
- VPN gateway route decision before the default route changes.
- Current directly connected LAN route associated with the pre-VPN default
  interface.
- Existing route state for each explicit local bypass CIDR before replacement,
  such as a fake-ip range.
- DNS apply state for the managed VPN link, with enough information to call
  per-link revert before deleting `ocx0`.

Apply ordering:

```text
1. create/configure ocx0
2. pin VPN gateway to pre-VPN gateway
3. install automatic local LAN bypass
4. install explicit local.bypass routes
5. install VPN default route
6. apply VPN DNS with `~.`
```

Normal disconnect ordering:

```text
1. stop/cancel tunnel traffic
2. revert VPN DNS on ocx0
3. restore/delete routes created or replaced by oc-oxide
4. remove managed ocx0
```

Failure rollback ordering:

```text
DNS failure -> revert DNS partials, routes, then TUN
route failure -> restore applied routes, then TUN
TUN failure -> no route/DNS changes should remain
```

Tests:

- Full connected policy plans VPN default route, gateway pin, detected LAN
  bypass, explicit local bypass, and full DNS `~.`.
- Existing local bypass route is restored exactly when oc-oxide replaced it.
- Missing local bypass route is deleted on revert when oc-oxide created it.
- DNS revert is attempted before managed TUN deletion on normal disconnect.
- DNS apply failure rolls back DNS partials, routes, and TUN state.
- Route apply failure rolls back previously applied routes and TUN state.
- Stale startup cleanup attempts DNS revert for stale `ocx0`, removes stale
  managed TUN, and leaves unrelated interfaces/routes untouched.
- Diagnostics report `dns_errors`, `route_errors`, and `tun_errors` without
  leaking secrets.

### Milestone 6B: Daemon Crash Recovery Journal

The daemon is expected to run as a boot-started privileged system service, but
VPN sessions remain user-initiated unless a future profile explicitly opts into
auto-connect. Because the daemon owns TUN, route, DNS, and IPv6 block state, a
daemon crash must not leave the host permanently routed or resolved through a
dead VPN interface.

The recovery design uses a small runtime journal under `/run/oc-oxide`. The
journal is non-secret and records only reversible network state. It must never
store passwords, OTP values, cookies, private keys, or auth tokens.

#### 6B.1 Runtime Journal Model And Store

Status: complete. The daemon now has a versioned non-secret recovery journal
model plus an injectable file-backed store rooted at a caller-provided runtime
directory.

Tasks:

- Add a versioned recovery journal data model in the daemon layer.
- Represent only non-secret applied policy state: managed interface name,
  applied DNS link, applied IPv4 route revert actions, IPv6 default block
  ownership, and TUN address state.
- Add an injectable file store rooted at a caller-provided runtime directory.
- Persist via write-then-rename so partial writes do not replace a good journal.
- Reject or ignore unsupported journal versions.

Tests:

- Journal round-trips without secret/auth fields.
- File store writes through a temporary path and loads the final journal.
- Missing journal is a no-op.
- Unsupported versions are rejected without applying recovery.

#### 6B.2 Journaled Policy Apply And Normal Disconnect

Status: complete. The daemon workflow writes staged recovery journals during
TUN, route, DNS, and connected apply, marks the journal as reverting on normal
disconnect, and deletes it only after all cleanup succeeds.

Tasks:

- Write a journal as soon as each subsystem is successfully applied.
- Record stage/progress so crashes after TUN, routes, or DNS can be cleaned up
  according to what actually changed.
- On normal disconnect, mark the journal as reverting before cleanup starts.
- Delete the journal only after DNS, route, IPv6 block, TUN, and managed-link
  cleanup all succeed.
- Keep the journal if cleanup is partial so the next daemon start can retry.

Tests:

- Crash-after-TUN journal contains only TUN revert state.
- Crash-after-routes journal contains routes plus TUN state and no DNS state.
- Crash-after-DNS journal contains full DNS/routes/TUN state.
- Normal disconnect success removes the journal.
- Normal disconnect partial failure preserves the journal and reports counts.

#### 6B.3 Startup Recovery From Journal

Status: complete. `oc-oxide-daemon serve` runs startup recovery before opening
the IPC socket, using `/run/oc-oxide/session.json` and preserving stale-link
cleanup when no journal exists.

Tasks:

- At daemon startup, before accepting IPC, load the runtime journal if present.
- Revert in dependency order: DNS, IPv6 default block, IPv4 routes, TUN, then
  managed link deletion.
- Continue best-effort cleanup after individual failures.
- Remove the journal only after full recovery succeeds.
- Preserve the existing stale `ocx0` cleanup path for cases where no journal is
  present.

Tests:

- Startup with no journal performs only stale managed-link inspection.
- Startup with full journal reverts DNS, IPv6 block, routes, TUN, and removes
  the journal.
- Startup with partial journal reverts only recorded subsystems.
- Startup recovery failure keeps the journal for retry.
- Recovery logs and diagnostics do not contain secrets.

#### 6B.4 systemd Service Semantics

Status: complete in current
[../ARCHITECTURE.md](../ARCHITECTURE.md),
[../SECURITY_MODEL.md](../SECURITY_MODEL.md), and
`packaging/systemd/oc-oxide-daemon.service`.

Tasks:

- Add documented systemd unit behavior for a boot-started idle daemon.
- Use `Restart=on-failure` and short restart delay.
- Keep VPN auto-connect out of the default service behavior.
- Document startup recovery expectations and operator diagnostics.

Tests:

- Unit/template text does not auto-connect a profile.
- Docs and smoke checks describe daemon idle-at-boot behavior.

## Milestone 7: Developer CLI

Build `ocx`.

Status:

- Complete: `ocx smoke-cookie` uses the Rust `libopenconnect` tunnel wrapper
  directly, reads a local-only profile from `~/oc-oxide-smoke.env`, and has
  passed a real VPN smoke test through cookie acquisition and CSTP setup.
- Complete: `ocx smoke-mainloop` can authenticate, connect CSTP, create TUN,
  render route/DNS plans, optionally apply/revert policy, enter
  `openconnect_mainloop`, and cancel after a bounded duration.
- Complete: `ocx daemon-smoke --profile <name>` exercises the daemon worker
  controller through an injected no-network `OpenConnectTunnelWorker` workflow.
- Complete: `ocx connect/status/disconnect/diagnostics` over daemon IPC.
- Complete: terminal auth prompt loop over daemon IPC.
- Complete: real privileged daemon e2e smoke before Tauri work.
- Complete: manual privileged e2e checklist in
  [../DEVELOPMENT.md](../DEVELOPMENT.md).
- Observed: real `ocx connect office` can use the user keyring for the VPN
  account password, prompt only for second-factor verification, apply route/DNS
  policy, and report `connected interface=ocx0`.
- Observed: real `ocx disconnect` reverts DNS, routes, IPv6 block state, TUN
  state, the managed `ocx0` link, and the runtime journal with zero reported
  DNS, route, and TUN errors.
- Observed: real daemon-crash e2e found and fixed an idempotency gap where the
  journal remained but the managed TUN link had already disappeared. Startup
  recovery now treats missing-link DNS/TUN cleanup and already-gone route/IPv6
  cleanup as idempotent, deletes the journal, and starts serving IPC in `Idle`.
- Observed: the crash recovery path was rerun from a clean idle daemon with no
  existing journal; reconnect, `SIGKILL`, restart, and recovery passed with the
  daemon serving IPC in `Idle` and no journal or `ocx0` state remaining.
- Complete: OpenConnect level-3 packet progress is filtered out of the default
  daemon IPC event stream so `status`, `diagnostics`, `disconnect`, and the
  future GUI event stream are not flooded by packet trace logs.

`smoke-cookie` intentionally does not create a TUN device, enter
`openconnect_mainloop`, or apply route/DNS changes.

Observed safe smoke behavior:

- First auth form: authgroup, username, and VPN password.
- Second auth form: second-factor verification code presented as an `answer`
  password field.
- The command obtains an auth cookie, connects CSTP, and reads server-pushed
  IP/DNS/split-exclude/gateway data through `openconnect_get_ip_info`.
- Auth submission is bounded to two forms; any third auth form is cancelled.
- Diagnostics are redacted and must not print secrets, cookies, real VPN
  hostnames, real usernames, or sensitive public IPs.

Commands:

```text
oc-oxide-daemon serve
ocx connect office
ocx status
ocx disconnect
ocx diagnostics
```

This CLI talks to the daemon over IPC. It must not shell out to `openconnect`.
`ocx connect` prints daemon events, handles terminal auth prompts, submits
transient answers over IPC, and exits after the daemon reports `connected`; the
tunnel remains owned by the daemon until `ocx disconnect`.

Current `ocx smoke-mainloop` can authenticate, connect CSTP, create TUN, render
route/DNS plans without applying them, enter `openconnect_mainloop`, and cancel
after a bounded duration. It accepts route and DNS policy modes plus local
bypass CIDRs for environment-specific behavior. Passing `--apply-policy`
explicitly configures TUN and route policy through Linux netlink, applies DNS
through `resolvectl`, and then reverts DNS before routes and TUN config after
the timed mainloop exits.

`ocx daemon-smoke --profile <name>` exercises the daemon worker controller
through an injected no-network `OpenConnectTunnelWorker` workflow. It is a
pre-GUI smoke for connect, policy-planned `network_applied`, connected, status,
cancel-driven disconnect, policy-reverted, and disconnected event mapping. The
smoke workflow plans the network event through the daemon policy planner using
non-secret sample profile and tunnel metadata; real VPN e2e remains a separate
privileged smoke.

## Milestone 8: Tauri 2 App

Build the desktop app after daemon and CLI can connect.

Status: in progress for product polish, complete for the main daemon-backed
desktop workflow and Linux systemd daemon handoff. The app can manage profiles,
connect and disconnect through daemon IPC, render auth/OTP prompts, use the OS
keyring for saved VPN passwords, show diagnostics/log views, request startup of
the packaged `oc-oxide-daemon.service` when the daemon socket is unavailable,
and run GitHub Cloud Sync sign-in, upload, and restore flows.

Connected policy simplification is complete for the daemon path:

- Profile-selected route/DNS modes are no longer exposed in the daemon path.
- Connected daemon sessions force full route and full DNS policy.
- Automatic local LAN detection is included in local bypass planning.
- Profile-declared company DNS domains and explicit local bypasses are kept.

Views:

- Complete: profile selector and profile management.
- Complete: login/auth form and OTP prompt dialog.
- Complete: session status.
- Complete: route/DNS diagnostics.
- Complete: logs view for retained desktop/daemon lifecycle events.
- Complete: connect and disconnect controls.
- Complete: Cloud Sync settings, sign-in, upload, and restore dialogs.
- Complete: Linux daemon start/privilege handoff through `systemctl start
  oc-oxide-daemon.service`, with user-facing install guidance when the packaged
  service is absent or cannot be started.

## Verification Targets

Real VPN verification targets for manual e2e:

- VPN gateway resolves to real public IP, not `198.18.0.0/15`.
- TUN interface is created.
- Server-pushed DNS is captured.
- `corp.example.test` resolves through VPN DNS.
- Public websites still work on profiles that use local fake-ip DNS.
- Profile-selected local bypass ranges such as `198.18.0.0/15` point to the
  local gateway, not `tun0`.
- Disconnect reverts route/DNS changes.
