# Connected Policy Design

Status: archived design record. The implemented daemon behavior is summarized
in [../ARCHITECTURE.md](../ARCHITECTURE.md) and
[../SECURITY_MODEL.md](../SECURITY_MODEL.md). Keep this file as
background for why oc-oxide uses one connected policy before revisiting split
routing.

This note records the design discussion for profile policy. The implemented
product direction is intentionally single-mode:

```text
connected means full VPN coverage
profile declares company DNS knowledge and explicit local exceptions
```

This reflects the observed AnyConnect deployment: the server does not push a
split include route list, the legacy vpnc-script installs a VPN default route,
and DNS should route through the VPN-provided resolvers while connected.

## Traffic Classes

oc-oxide should classify traffic into three policy classes even though there is
only one connected policy.

### Company Resources

Company resources use `ocx0` when the VPN is connected.

Inputs:

- Server-pushed internal network.
- Server-pushed split include routes.
- Profile-declared company routes.
- Server-pushed default/search domain.
- Server-pushed split DNS domains.
- Profile-declared company domains that must resolve through company DNS.

The server-pushed configuration is input, not the whole policy. Profiles may keep
non-secret domain knowledge for company domains that are not pushed by the VPN
server. Profile-declared company domains are DNS routing domains, not search
domains.

### Local Network

Local network traffic should remain on the pre-VPN local gateway/interface.

Inputs:

- VPN gateway pin.
- Current directly connected LAN, discovered automatically before policy apply.
- Profile-declared local bypass CIDRs for special local ranges.
- Local network quirks such as fake-ip DNS ranges.

The local network model must be conservative. Auto-discovery should prefer the
current directly connected LAN, for example one local `/24` network, not
all RFC1918 space. Company networks often use private ranges too, so broad
automatic bypasses such as `10.0.0.0/8` would be unsafe.

### Public Internet

Public internet traffic uses `ocx0` while connected. Disconnected state has no
route or DNS policy.

## Connected Semantics

```text
company resources -> ocx0
local network -> local gateway/interface
public internet -> ocx0
all DNS -> VPN DNS
```

The policy must still preserve local bypasses. It should not mean "send every
packet into the tunnel no matter what", because local router access, local LAN
services, and fake-ip DNS paths can break.

Do not expose split/full/off profile modes in the initial product. Split routing
can remain a future research area once company route boundaries are known.

## Profile Shape

Current daemon profiles are non-secret TOML files:

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

Passwords, OTP values, cookies, private keys, and real VPN endpoints must not be
stored in repository files.

## Policy Composition

Route composition:

```text
tunnel_routes =
  default_route_via_ocx0
  + server_pushed_internal_network
  + server_pushed_split_includes

local_bypass =
  vpn_gateway_pin
  + automatically discovered directly connected LAN
  + profile.local.bypass
```

DNS composition:

```text
servers = VPN-pushed DNS servers
search_domains = VPN-pushed default/search domain
routing_domains = ["~."] + profile.company.domains
```

## Implemented Daemon Direction

The daemon path has been simplified around this single connected policy:

- Stop relying on profile-selected route/DNS modes in the daemon path.
- Apply full route and full DNS policy whenever a profile is connected.
- Add automatic current-LAN detection before route planning.
- Keep explicit `local.bypass` for special local ranges such as fake-ip DNS.
- Keep profile-declared company DNS domains as routing-domain knowledge.

Recovery requirements:

- Capture pre-VPN route state before applying any connected policy changes.
- Restore or delete only routes that oc-oxide created or replaced.
- Revert DNS on the managed VPN link before removing `ocx0`.
- Roll back partial apply failures in reverse order: DNS, routes, then TUN.
- During daemon startup stale cleanup, attempt per-link DNS revert for stale
  `ocx0` before deleting the stale managed interface.
- Test normal disconnect, route failure rollback, DNS failure rollback, and
  stale startup cleanup with no real system route/DNS changes.

## Remaining Research

Split routing remains intentionally out of the first product path. Revisit it
only after company route boundaries are known well enough to avoid routing
private-but-company networks back to the local LAN by mistake.
