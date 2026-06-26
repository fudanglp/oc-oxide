# Development

This document covers local development, verification, and real-VPN manual E2E
checks. It intentionally uses placeholder names and local profile names only.
Do not paste passwords, OTP values, cookies, private keys, real VPN endpoints,
real DNS servers, or real internal domains into this file.

## Prerequisites

- Rust toolchain for the workspace `rust-version`.
- Node.js/npm for the Tauri desktop frontend.
- Linux with systemd for packaged daemon validation.
- `systemd-resolved` for the current DNS backend.

## Local Development Loop

For normal desktop development, start the privileged development daemon first:

```sh
make daemon
```

This builds the Rust workspace, then runs `oc-oxide-daemon serve` with the
local development socket and profile directory from the `Makefile`.

In a second terminal, start the Tauri desktop app:

```sh
make app
```

`make app` uses the same daemon socket as `make daemon`. Browser-only Vite mode
can render the frontend, but Tauri commands are unavailable there. Use it only
for layout checks:

```sh
make app-web
```

## Profile Setup

For first-time desktop development, start the app with `make app` and add a
profile from the UI. Desktop-managed profiles are non-secret TOML files under
the user config directory and are sent to the daemon over IPC when connecting.

For CLI-first testing or manual setup, create a profile file outside the
repository:

```sh
mkdir -p "$HOME/.config/oc-oxide/profiles"
$EDITOR "$HOME/.config/oc-oxide/profiles/office.toml"
```

Use this shape:

```toml
[connection]
server = "https://vpn.example.test:555/"
reported_os = "linux"
authgroup = "engineering"
username = "alice"

[company]
domains = ["corp.example.test"]

[local]
bypass = ["198.18.0.0/15"]
```

Only `connection.server` is required. Keep passwords, OTP values, cookies,
private keys, and real VPN endpoints out of the repository and shared logs.

## Developer CLI

Use `ocx` when you want to exercise the daemon without the desktop app:

```sh
make status
make diagnostics
make connect PROFILE=office
make disconnect
```

The raw commands use `/tmp/oc-oxide-daemon.sock` by default:

```sh
target/debug/ocx status
target/debug/ocx diagnostics
target/debug/ocx connect office
target/debug/ocx disconnect
```

Set `OC_OXIDE_DAEMON_SOCKET` only when testing a non-default socket.

## Verification Commands

Run the broad local checks before committing behavior changes:

```sh
make test
make check
```

Targeted commands used frequently during development:

```sh
cargo test -p oc-oxide-daemon
cargo test -p oc-oxide-ipc
cargo check -p oc-oxide-desktop
cd apps/desktop && npm run build
```

## Version Sync

`version.yml` is the human-edited release version source. Do not hand-edit the
version fields in `Cargo.lock` or `apps/desktop/package-lock.json`.

To bump the project version:

```sh
$EDITOR version.yml
make sync-version
```

`make sync-version` updates `Cargo.toml` and the Tauri config directly, then
delegates generated metadata to the native tools:

- `cargo update --workspace` refreshes oc-oxide workspace package versions in
  `Cargo.lock` without upgrading third-party dependencies.
- `npm version --no-git-tag-version --allow-same-version` updates
  `apps/desktop/package.json` and `apps/desktop/package-lock.json`.

## Tunnel Work References

Most frontend, packaging, profile, and UI work does not require reading the
vendored OpenConnect source. Use these references when changing the
`libopenconnect` FFI boundary, auth-form mapping, tunnel lifecycle, or
server-pushed network metadata handling:

- `vendor/openconnect/openconnect.h`
- `vendor/openconnect/main.c`
- `vendor/openconnect/auth.c`
- `vendor/openconnect/script.c`

## Packaging Checks

Packaging is not part of the normal edit-run loop. Use these commands when
changing installers, release scripts, service files, desktop metadata, or
bundled library layout:

```sh
make dist-local
make dist-tarball
make package-deb
```

The packaged daemon is an idle system service. Installing, starting, or
restarting it must not connect a VPN profile.

```sh
sudo apt install ./dist/oc-oxide_0.1.1_amd64.deb
systemctl status oc-oxide-daemon.service --no-pager
```

See [DISTRIBUTION.md](DISTRIBUTION.md) for package verification, signing, apt
repository, and updater metadata checks.

## Profiles And Secrets

Profiles contain non-secret connection settings and local routing hints. The
desktop stores user profiles under the user config directory. CLI/system
workflows can also use system profiles under `/etc/oc-oxide/profiles`.

VPN passwords can be stored in the OS keyring when the user opts in. OTP values
and second-factor answers are always transient and must not be stored.

See [SECURITY_MODEL.md](SECURITY_MODEL.md) for the full secret handling model.

## Manual Real-VPN E2E

Automated tests cover parsing, planning, IPC, and recovery ordering without
touching host networking. Real VPN coverage remains manual because it requires
privileged networking and a user-approved second-factor code.

Validate this daemon-owned runtime path:

```text
ocx connect -> libopenconnect auth -> CSTP -> ocx0 -> route/DNS apply
ocx status/diagnostics -> connected snapshots
ocx disconnect -> DNS/route/TUN restore
daemon restart after crash -> startup recovery
```

The CLI must talk to `oc-oxide-daemon` over IPC. It must not shell out to the
external `openconnect` executable.

### Preflight

1. Build the workspace.

   ```sh
   cargo build --workspace
   ```

2. Ensure the local TOML profile exists outside the repo.

   ```sh
   test -r "$HOME/.config/oc-oxide/profiles/office.toml"
   ```

3. Optionally store the VPN account password in the user keyring.

   ```sh
   target/debug/ocx vault-store office
   ```

   Expected behavior: this stores only the VPN account password. OTP values are
   never stored.

4. Start or confirm the privileged daemon is serving IPC.

   ```sh
   sudo target/debug/oc-oxide-daemon serve
   ```

   With the packaged build, confirm the system service is active instead.

### Connect

Run:

```sh
target/debug/ocx connect office
```

Expected behavior:

- The daemon accepts the request and resolves/imports the selected non-secret
  profile.
- The first auth form asks for the VPN account password unless it is available
  from keyring.
- The second auth form asks for the current OTP/second-factor answer.
- The tunnel reaches CSTP connected.
- The daemon applies route and DNS policy.
- The command exits after reporting a connected `ocx0` interface.

Sanitized success shape:

```text
ocx: accepted
ocx: progress level=0 connect requested
ocx: progress level=0 profile resolved
ocx: auth prompt: Please enter your username and password.
ocx: using stored VPN password from keyring
ocx: auth prompt: second-factor verification
ocx: network applied routes=<n> dns=<n>
ocx: connected interface=ocx0
```

### Connected Checks

Run while connected:

```sh
target/debug/ocx status
target/debug/ocx diagnostics
ls -l /run/oc-oxide /run/oc-oxide/session.json
ip -4 route show dev ocx0
resolvectl status ocx0
```

Expected:

- `ocx status` reports `Connected`, the active profile, and `ocx0`.
- Diagnostics report managed route and DNS policy on `ocx0`.
- `/run/oc-oxide/session.json` exists, is non-secret, and is mode `0600`.
- A default route through `ocx0` exists.
- The VPN gateway remains pinned through the pre-VPN local gateway/interface.
- Explicit local bypasses, such as fake-ip ranges, remain on the local
  gateway/interface.
- VPN DNS is attached to `ocx0` with full routing domain `~.`.

Check public and company resolution with locally appropriate names. Redact
real names before sharing output:

```sh
resolvectl query public.example.test
resolvectl query service.corp.example.test
```

### Disconnect

Run only when it is acceptable to tear down the real VPN session:

```sh
target/debug/ocx disconnect
```

Post-disconnect checks:

```sh
target/debug/ocx status
test ! -e /run/oc-oxide/session.json
ip link show ocx0
ip -4 route show dev ocx0
resolvectl status ocx0
```

Expected:

- `ocx status` reports no active profile and no interface.
- The runtime journal is gone.
- `ocx0` no longer exists.
- No IPv4 routes remain attached to `ocx0`.
- `systemd-resolved` has no remaining `ocx0` link state.
- Pre-existing local route and DNS behavior are restored.

### Crash Recovery

Run only when losing the live VPN session is acceptable:

1. Connect successfully and confirm `/run/oc-oxide/session.json` exists.
2. Kill only the daemon process, leaving host network state as-is.
3. Restart `oc-oxide-daemon serve` or the packaged service.
4. Confirm startup recovery runs before accepting new IPC requests.
5. Confirm DNS, routes, IPv6 block state, TUN address state, and managed link
   are reverted.
6. Confirm the journal is deleted only after recovery succeeds.

Expected recovery result:

```text
state is idle after restart
no ocx0 link remains
no ocx0 DNS state remains
no ocx0 routes remain
/run/oc-oxide/session.json is removed after successful recovery
```

If recovery is partial, the journal should remain for the next daemon start and
diagnostics should report non-secret route/DNS/TUN error counts.

## Troubleshooting

### Tauri runtime is unavailable

The browser-only Vite server cannot execute Tauri commands. Start the desktop
through Tauri when testing real app behavior:

```sh
make app
```

### Daemon reports an unknown IPC variant

The desktop and daemon binaries are from different builds. Reinstall or restart
the packaged daemon:

```sh
sudo apt install --reinstall ./dist/oc-oxide_0.1.1_amd64.deb
sudo systemctl restart oc-oxide-daemon.service
```

### Daemon socket is missing

Check the packaged service:

```sh
systemctl status oc-oxide-daemon.service --no-pager
ls -l /tmp/oc-oxide-daemon.sock
```

### Polkit authorization does not appear

The default policy allows the active local desktop session. If authorization
still fails, confirm a polkit agent is running in the desktop session and that
the policy file is installed:

```sh
test -f /usr/share/polkit-1/actions/com.github.fudanglp.oc-oxide.policy
```

### Keyring is unavailable

Connect can still proceed by prompting for the VPN password. Saved-password
flows require the user's desktop keyring service to be available.
