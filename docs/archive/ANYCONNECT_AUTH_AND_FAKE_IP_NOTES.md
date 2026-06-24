# AnyConnect Auth And Fake-IP Notes

Status: archived local diagnostics record. This file captures sanitized
observations from the original AnyConnect VPN investigation. Current profile
shape and product behavior are documented in
[../ONBOARDING.md](../ONBOARDING.md), [../ARCHITECTURE.md](../ARCHITECTURE.md), and
[../SECURITY_MODEL.md](../SECURITY_MODEL.md).

This file records the implementation lessons from the local company VPN
profile. It is documentation for implementation and diagnostics, not a secret
store. Concrete endpoint names, auth-group labels, local IPs, DNS servers, and
interface names are intentionally replaced with documentation examples.

Do not commit passwords, OTP values, session cookies, or private keys.

## Historical Profile Shape

Early suggested config before the current TOML schema was finalized:

```toml
[profile.office]
server = "https://vpn.example.test:555/"
protocol = "anyconnect"
authgroup = "engineering"
default_domain = "corp.example.test"
route_mode = "split"
dns_mode = "split"
local_bypass_cidrs = ["198.18.0.0/15"]
```

The current profile model is documented in [../ONBOARDING.md](../ONBOARDING.md),
[../ARCHITECTURE.md](../ARCHITECTURE.md), and
[../SECURITY_MODEL.md](../SECURITY_MODEL.md). The username may be stored in
local user config if desired. Passwords should not be stored in TOML.

## Authentication Flow

Observed flow:

1. Connect to the configured VPN endpoint, using `https://vpn.example.test:555/` in examples and tests.
2. Submit authgroup, username, and VPN account password.
3. Server sends a second-factor verification code through the configured
   out-of-band provider.
4. User manually enters the second-factor code into the second auth form.
5. CSTP connects.
6. DTLS may fail and fall back to SSL/CSTP. This is acceptable for first version.

Do not automate OTP reading in the first version.

Real `ocx smoke-cookie` verification on 2026-06-18 confirmed this exact
two-stage flow through `libopenconnect`:

```text
first form:  group_list:select, username:text, password:password
second form: answer:password
```

The second form is not exposed as an OpenConnect token field for this VPN. Treat
the first form's `password` field as the VPN account password, and treat later
password fields such as `answer` as second-factor verification-code fields. The
developer smoke command must keep auth submissions bounded and cancel if the
server asks for another form after the verification code.

The verified smoke command reached:

```text
cookie obtained: true
CSTP connected
VPN address present: true
DNS server count: 2
split exclude count: 2
gateway address present: true
auth prompts handled: 2
```

This smoke did not create a TUN device, enter the tunnel mainloop, or apply
route/DNS changes.

## Server-Pushed Configuration

Observed OpenConnect environment after successful connection:

```text
CISCO_CSTP_OPTIONS=X-CSTP-Version=1
CISCO_DEF_DOMAIN=corp.example.test
CISCO_SPLIT_EXC_0_ADDR=203.0.113.10
CISCO_SPLIT_EXC_0_MASK=255.255.255.255
CISCO_SPLIT_EXC_0_MASKLEN=32
CISCO_SPLIT_EXC_1_ADDR=0.0.0.0
CISCO_SPLIT_EXC_1_MASK=255.255.255.255
CISCO_SPLIT_EXC_1_MASKLEN=32
CISCO_SPLIT_EXC=2
INTERNAL_IP4_ADDRESS=198.51.100.42
INTERNAL_IP4_DNS=192.0.2.53 198.51.100.53
INTERNAL_IP4_MTU=1200
INTERNAL_IP4_NETADDR=198.51.100.0
INTERNAL_IP4_NETMASK=255.255.255.0
INTERNAL_IP4_NETMASKLEN=24
TUNDEV=tun0
VPNGATEWAY=203.0.113.10
```

Important points:

- DNS servers are provided by the VPN server.
- Search/default domain is `corp.example.test`.
- VPN address is assigned as a `/32` on `tun0`.
- VPN network is derived from `INTERNAL_IP4_NETADDR` and
  `INTERNAL_IP4_NETMASKLEN`.
- MTU is `1200`.
- No useful `CISCO_SPLIT_INC` was observed.

## OpenClash Fake-IP Interaction

The local network uses OpenClash fake-ip DNS. Fake-ip addresses are in:

```text
198.18.0.0/15
```

Failure mode:

- Public domains such as `public-web.example.test` can resolve to a fake IP like `198.18.0.40`.
- If VPN installs `default dev tun0`, traffic to fake IPs follows the VPN instead of the local router/OpenClash path.
- Public web access then fails.

Required policy:

```text
198.18.0.0/15 -> pre-VPN local gateway/interface
```

Observed local values during debugging:

```text
local_ip = 192.0.2.10
local_gateway = 192.0.2.1
local_interface = eth0
```

These must be discovered at runtime, not hardcoded.

## Gateway Resolution

The configured VPN endpoint must resolve to the real gateway IP, not a fake-ip address.

Good observed value:

```text
203.0.113.10
```

Bad observed values:

```text
198.18.163.46
198.18.0.8
```

If the gateway resolves to `198.18.0.0/15`, OpenClash fake-ip filtering is wrong or not yet applied.

## Historical DNS Policy Notes

Early notes considered split DNS:

```text
corp.example.test -> VPN DNS servers
everything else -> existing local DNS/OpenClash path
```

Keep a full-DNS mode available:

```text
. -> VPN DNS servers
```

Full-DNS mode may be useful when local DNS routing is broken, but it can also break public fake-ip behavior if route policy is wrong. Route `198.18.0.0/15` locally before relying on full DNS.

## Diagnostics To Expose

The app should show:

- resolved VPN gateway IP.
- whether gateway IP is inside `198.18.0.0/15`.
- pre-VPN default route.
- current default route.
- route for `198.18.0.0/15`.
- route for VPN gateway.
- DNS backend and applied DNS mode.
- server-pushed DNS servers and domain.
- TUN interface, VPN IP, MTU.
