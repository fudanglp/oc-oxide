# Security Model

oc-oxide separates unprivileged user interaction from privileged VPN and
network state changes. The project is not a password manager and must not store
VPN auth material in repository files, profile files, logs, diagnostics, sync
objects, or recovery journals.

## Trust Boundaries

### Desktop App

The Tauri desktop app runs as the user. It is responsible for:

- profile management for non-secret TOML files
- rendering auth prompts and OTP prompts
- optional keyring-backed VPN password storage
- GitHub Cloud Sync UI
- status, diagnostics, and logs

The desktop process must not create TUN devices, modify routes, modify DNS, or
call `libopenconnect` directly.

### Privileged Daemon

`oc-oxide-daemon` is the privileged boundary. It owns:

- the active `libopenconnect` session
- TUN setup and teardown
- route and DNS policy
- runtime recovery from `/run/oc-oxide/session.json`
- daemon IPC state

The daemon starts idle. Starting or restarting the service must not connect a
VPN profile.

### CLI

`ocx` is a developer client for the daemon IPC protocol. It is not a wrapper
around the external `openconnect` executable.

## Polkit And IPC

Linux clients connect to the daemon over a Unix socket. The socket is only the
transport. Before accepting IPC commands, the daemon checks the connecting
process credentials with `SO_PEERCRED` and authorizes the client through polkit
action:

```text
com.github.fudanglp.oc-oxide.control
```

The default policy allows the active local desktop session without an extra
password prompt. Inactive or non-local sessions still require admin
authorization.

All current IPC commands share this connection-level authorization gate. A
future method-level policy can split read-only status from control operations
if the product needs that granularity.

## Profile Data

Profile TOML files are non-secret configuration. They may include:

- server URL
- reported OS
- authgroup
- username
- company domains
- explicit local bypass CIDRs

Profile files must not include:

- VPN passwords
- OTP values
- session cookies
- private keys
- client certificate passphrases
- router credentials
- temporary OpenConnect auth-form answers

Desktop-managed profiles live under the user's config directory. The desktop
sends the selected user's non-secret profile TOML over IPC at connect time.
CLI/system workflows can also use system profiles under
`/etc/oc-oxide/profiles`.

## Auth And Keyring

OpenConnect auth forms are converted into typed prompts and returned to the
desktop or CLI over IPC. Submitted answers are transient.

VPN account passwords can be stored in the OS keyring only when the user opts
in. OTP values and second-factor answers are never stored. Secret answer debug
output must be redacted.

## GitHub Sync Boundary

GitHub Cloud Sync stores only non-secret profile snapshots in a selected
private repository. It is not a password manager.

Allowed in GitHub Sync:

- non-secret profile configuration
- manifest data
- tombstones for explicitly deleted synced profiles
- normal GitHub metadata such as commits, timestamps, and file names

Not allowed in GitHub Sync:

- VPN passwords
- OTP values
- cookies
- private keys
- client certificate passphrases
- router credentials
- GitHub access or refresh tokens
- daemon tokens
- temporary auth answers

GitHub refresh tokens are stored in the OS keyring. Access tokens stay in
memory and should be refreshed as needed.

## Runtime Recovery Journal

The daemon stores a small runtime recovery journal under `/run/oc-oxide` while
network policy is active. The journal is non-secret and records only reversible
network state:

- managed interface name
- DNS link state needed for revert
- IPv4 route revert actions
- IPv6 default-route block ownership
- TUN address state

The journal must never contain passwords, OTP values, cookies, private keys,
auth tokens, GitHub tokens, or profile secret material.

## Logging And Diagnostics

Logs, diagnostics, tests, screenshots, and docs must avoid secret material.
When sharing real E2E output, redact:

- real VPN endpoints
- real usernames when sensitive
- real internal domains
- real public IPs when sensitive
- DNS server addresses if they identify private infrastructure
- all auth material
