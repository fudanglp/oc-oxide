# TOML Profile And Vault Plan

Status: archived design record. TOML profile parsing, the single connected
daemon policy, and OS keyring-backed VPN password storage are implemented. Keep
this file as background for the non-secret profile and vault boundaries.

This file originally covered two implementation slices before Tauri work:

1. TOML profile files for non-secret company and local policy.
2. OS vault/keyring integration for optional VPN password storage.

The security boundary stays unchanged: repository files, profile files, logs,
IPC events, and daemon diagnostics must not contain VPN passwords, OTP values,
cookies, private keys, router credentials, or other secret auth material.

## Profile Model

Profiles describe non-secret connection settings, company DNS knowledge, and
explicit local bypasses. The initial product supports one connected policy only:
while connected, default route and DNS use the VPN, except for the VPN gateway,
automatically detected local networks, and explicit local bypass CIDRs.

Only TOML profile files are supported:

```toml
[connection]
server = "https://vpn.example.test:555/"
reported_os = "linux"
authgroup = "engineering"
username = "alice"

[company]
domains = [
  "example.test",
  "object-storage.example.test",
]

[local]
bypass = [
  "198.18.0.0/15",
]
```

### Company Policy

`company.routes` is intentionally not part of the initial connected profile
contract. The current policy routes public and company traffic through the VPN
default route while connected. Company route discovery remains research material
until the company network boundary is known well enough to support split
routing.

`company.domains` is the profile-declared set of company DNS domains that must
resolve through company DNS. Full DNS mode already routes all DNS through the
VPN-provided resolvers, but keeping these non-secret suffixes in the profile
documents company DNS requirements and preserves a path for future split-DNS
research.

Profile-declared company domains are routing domains only. They should not be
treated as search domains unless a later profile field explicitly asks for that.
This avoids polluting short-name resolution when a profile declares multiple
company domains.

### Local Policy

`local.bypass` is the profile-declared set of local or environment-specific CIDRs
that must stay on the pre-VPN local gateway/interface. Examples include
environment-specific fake-ip ranges such as `198.18.0.0/15`.

Profiles should not store `local_gateway`, `local_interface`, or the current LAN
prefix. The daemon must discover the pre-VPN default route and directly
connected local network at connection time, then use that snapshot for the VPN
gateway pin, automatic local LAN bypass, and explicit local bypass routes.

### Connected Policy

The daemon should not expose user-facing split/full/off profile modes in the
initial product. Once connected:

```text
default route -> ocx0
all DNS -> VPN-provided DNS, rendered as `~.` on systemd-resolved
VPN gateway -> pre-VPN local gateway
auto-detected current LAN -> pre-VPN local interface
local.bypass -> pre-VPN local gateway/interface
```

## Vault Model

The vault stores optional user secrets in the OS credential store, not in profile
files. The intended backend is the platform-native credential store:

```text
Linux   -> Secret Service, such as GNOME Keyring, KWallet, or KeePassXC
macOS   -> Keychain Services
Windows -> Credential Manager / DPAPI-backed credential storage
```

Rust code should expose a small oc-oxide vault abstraction and keep the backend
injectable for tests. A keyring-backed implementation can live in
`oc-oxide-config`; callers should not depend on keyring details.

### Secret Ownership

The unprivileged client owns vault access:

```text
apps/desktop / ocx:
  read, write, and delete remembered VPN passwords from the current user's vault
  submit transient auth answers to the daemon over IPC

oc-oxide-daemon:
  does not read or write the vault
  does not persist passwords, OTP values, or cookies
  only forwards transient auth answers to libopenconnect
```

This keeps user credentials in the user's session and avoids root-daemon access
to desktop keyrings.

### Stored Secrets

First vault slice:

```text
store: optional VPN account password when the user opts in
do not store: OTP/second-factor code
do not store: OpenConnect cookie
do not store: private key material
```

The default behavior remains prompt-only. Remembered passwords are opt-in.

### Vault Keys

Use a deterministic non-secret key derived from profile identity:

```text
service = "oc-oxide.vpn"
account = "<profile>:<authgroup>:<username>"
```

Empty optional parts are omitted from the joined account key. The key contains
identity and routing context only, not the secret itself.

## Implementation Slices

### Slice 1: TOML Profiles

Status: complete.

Tasks:

- Add TOML profile structs to `oc-oxide-config`.
- Parse and validate `[connection]`, `[company]`, and `[local]`.
- Extend `VpnProfile` with profile-declared company domains and local bypasses.
- Compose company domains into DNS planning as routing domains.
- Update the daemon profile resolver to load TOML profiles.
- Do not support the legacy `key=value` `.conf` format.

Tests:

- TOML profile parsing rejects secrets and unknown fields.
- Company domains become DNS routing domains, not search domains.
- Local bypass still routes to the pre-VPN local gateway.
- Legacy `key=value` profile files are rejected by omission because the resolver
  only reads `<profile>.toml`.

### Slice 1 Follow-Up: Single Connected Policy

Status: complete.

Tasks:

- Stop relying on profile-selected route/DNS modes in the daemon.
- Apply full route policy and full DNS policy for every connected profile.
- Add automatic current-LAN detection as daemon behavior, not as a profile
  option.
- Keep explicit `local.bypass` for environment-specific ranges.
- Preserve route/DNS apply/revert ordering and diagnostics.
- Restore pre-existing route state for any route oc-oxide replaces.
- Attempt DNS revert before managed TUN deletion during normal disconnect and
  stale startup cleanup.

Tests:

- Connected policy installs a VPN default route after the gateway pin and local
  bypass routes are planned.
- Full DNS renders `~.` with VPN-provided DNS servers.
- The detected current LAN remains local without being written in TOML.
- Explicit fake-ip/local bypass CIDRs remain local.
- Existing fake-ip/local bypass routes are restored exactly on disconnect.
- Missing fake-ip/local bypass routes are deleted on disconnect if oc-oxide
  created them.
- DNS apply failures roll back DNS partials, routes, and TUN state.
- Route apply failures roll back previously applied routes and TUN state.
- Stale startup cleanup attempts DNS revert before deleting stale `ocx0`.
- Disconnect reverts DNS, routes, and TUN state without residual local routes.

### Slice 2: Vault

Status: complete.

Tasks:

- Add a small vault trait and password reference type in `oc-oxide-config`.
- Add an in-memory test backend.
- Add a keyring-backed implementation behind the public abstraction.
- Add helpers to build the VPN password account key from profile name,
  authgroup, and username.
- Keep OTP and cookies out of the vault API.

Tests:

- Password keys are deterministic and contain no password value.
- In-memory vault can store, read, overwrite, and delete a VPN password.
- Empty profile/account inputs are rejected.
- Debug output redacts secret values.
- Vault errors are non-secret.
- Daemon tests continue to prove secrets are submitted transiently over IPC only.
