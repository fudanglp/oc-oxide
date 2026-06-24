//! Route and network policy engine.
//!
//! This crate will discover pre-VPN routing state, pin the VPN gateway outside
//! the tunnel, apply explicit VPN route policy, preserve profile-selected local
//! bypass routes, and revert applied state on disconnect.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

mod linux;

pub use linux::{
    apply_network_route_plan_with, apply_tun_config_with, revert_network_route_plan_with,
    revert_tun_config_with, AppliedIpv6DefaultRouteBlock, AppliedNetworkRouteState,
    AppliedRouteChange, AppliedTunConfig, LinuxNetlinkRunner, LinuxNetworkBackend,
    RouteRevertAction, TunConfig,
};

/// Human-readable crate role used by workspace smoke tests.
pub const CRATE_ROLE: &str = "route and network policy";

/// IPv4 CIDR used by route planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Cidr {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
}

impl Ipv4Cidr {
    /// Create a CIDR after validating the prefix length.
    pub fn new(address: Ipv4Addr, prefix_len: u8) -> Result<Self, NetworkPolicyError> {
        if prefix_len > 32 {
            return Err(NetworkPolicyError::InvalidPrefixLength { prefix_len });
        }

        Ok(Self {
            address,
            prefix_len,
        })
    }

    /// Create a host route for one IPv4 address.
    pub fn host(address: Ipv4Addr) -> Self {
        Self {
            address,
            prefix_len: 32,
        }
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

impl FromStr for Ipv4Cidr {
    type Err = NetworkPolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, suffix) =
            value
                .split_once('/')
                .ok_or_else(|| NetworkPolicyError::InvalidCidr {
                    value: value.to_owned(),
                })?;
        let mut address = address
            .parse()
            .map_err(|_| NetworkPolicyError::InvalidCidr {
                value: value.to_owned(),
            })?;
        let prefix_len = match suffix.parse::<u8>() {
            Ok(prefix_len) => prefix_len,
            Err(_) => {
                let netmask = suffix
                    .parse()
                    .map_err(|_| NetworkPolicyError::InvalidCidr {
                        value: value.to_owned(),
                    })?;
                let prefix_len = ipv4_netmask_prefix_len(netmask).ok_or_else(|| {
                    NetworkPolicyError::InvalidCidr {
                        value: value.to_owned(),
                    }
                })?;
                address = apply_ipv4_netmask(address, netmask);
                prefix_len
            }
        };

        Self::new(address, prefix_len)
    }
}

/// Pre-VPN default route snapshot needed for reversible local routing policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRouteSnapshot {
    pub gateway: Ipv4Addr,
    pub interface: String,
}

impl DefaultRouteSnapshot {
    /// Create a default route snapshot from discovered local state.
    pub fn new(
        gateway: Ipv4Addr,
        interface: impl Into<String>,
    ) -> Result<Self, NetworkPolicyError> {
        let interface = clean_interface(interface.into())?;
        Ok(Self { gateway, interface })
    }
}

/// Server-pushed route material copied from OpenConnect state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerPushedRoutes {
    pub internal_network: Option<Ipv4Cidr>,
    pub split_includes: Vec<Ipv4Cidr>,
    pub split_excludes: Vec<Ipv4Cidr>,
}

impl ServerPushedRoutes {
    /// Create an empty server-pushed route set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach the observed internal IPv4 network.
    pub fn with_internal_network(mut self, network: Ipv4Cidr) -> Self {
        self.internal_network = Some(network);
        self
    }

    /// Attach pushed split include routes.
    pub fn with_split_includes(mut self, routes: Vec<Ipv4Cidr>) -> Self {
        self.split_includes = routes;
        self
    }

    /// Attach pushed split exclude routes.
    pub fn with_split_excludes(mut self, routes: Vec<Ipv4Cidr>) -> Self {
        self.split_excludes = routes;
        self
    }

    /// Build server-pushed route material from copied OpenConnect IP info parts.
    ///
    /// This consumes Rust-owned primitive values only. It intentionally does
    /// not depend on the tunnel crate or borrow libopenconnect-owned memory.
    pub fn from_openconnect_parts<I, E, IS, ES>(
        internal_netaddr: Option<Ipv4Addr>,
        internal_netmask_len: Option<u8>,
        split_includes: I,
        split_excludes: E,
    ) -> Result<Self, NetworkPolicyError>
    where
        I: IntoIterator<Item = IS>,
        E: IntoIterator<Item = ES>,
        IS: AsRef<str>,
        ES: AsRef<str>,
    {
        let internal_network = match (internal_netaddr, internal_netmask_len) {
            (Some(address), Some(prefix_len)) => Some(Ipv4Cidr::new(address, prefix_len)?),
            _ => None,
        };

        Ok(Self {
            internal_network,
            split_includes: parse_cidr_list("split include", split_includes)?,
            split_excludes: parse_cidr_list("split exclude", split_excludes)?,
        })
    }
}

/// Route application mode for a VPN session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RouteMode {
    /// Apply server/company routes to the VPN while preserving local default route.
    #[default]
    Split,
    /// Route default traffic through the VPN while preserving local bypasses.
    Full,
    /// Do not apply VPN routes.
    Off,
}

impl fmt::Display for RouteMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Split => f.write_str("split"),
            Self::Full => f.write_str("full"),
            Self::Off => f.write_str("off"),
        }
    }
}

impl FromStr for RouteMode {
    type Err = NetworkPolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "split" => Ok(Self::Split),
            "full" => Ok(Self::Full),
            "off" => Ok(Self::Off),
            _ => Err(NetworkPolicyError::InvalidRouteMode {
                value: value.to_owned(),
            }),
        }
    }
}

/// Route policy selected by profile, environment, CLI, or future GUI state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub route_mode: RouteMode,
    pub company_routes: Vec<Ipv4Cidr>,
    pub detected_local_cidrs: Vec<Ipv4Cidr>,
    pub local_bypass_cidrs: Vec<Ipv4Cidr>,
    pub block_ipv6_default_route: bool,
}

impl NetworkPolicy {
    /// Build a policy with the given route mode and no local bypasses.
    pub fn new(route_mode: RouteMode) -> Self {
        Self {
            route_mode,
            company_routes: Vec::new(),
            detected_local_cidrs: Vec::new(),
            local_bypass_cidrs: Vec::new(),
            block_ipv6_default_route: route_mode == RouteMode::Full,
        }
    }

    /// Add profile-declared company routes that must use the tunnel.
    pub fn with_company_routes(mut self, routes: Vec<Ipv4Cidr>) -> Self {
        self.company_routes = routes;
        self
    }

    /// Add local CIDRs discovered from the pre-VPN local routing state.
    pub fn with_detected_local_cidrs(mut self, cidrs: Vec<Ipv4Cidr>) -> Self {
        self.detected_local_cidrs = cidrs;
        self
    }

    /// Add CIDRs that must stay on the pre-VPN local route.
    pub fn with_local_bypass_cidrs(mut self, cidrs: Vec<Ipv4Cidr>) -> Self {
        self.local_bypass_cidrs = cidrs;
        self
    }

    /// Control whether full IPv4 VPN mode should also block unmanaged IPv6 default routing.
    pub fn with_ipv6_default_route_block(mut self, block: bool) -> Self {
        self.block_ipv6_default_route = block;
        self
    }
}

/// One route operation planned for later application by a privileged backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedRoute {
    pub destination: Ipv4Cidr,
    pub via: Option<Ipv4Addr>,
    pub dev: String,
    pub reason: RouteReason,
}

/// Existing host route state captured before oc-oxide replaces a route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSnapshot {
    pub destination: Ipv4Cidr,
    pub via: Option<Ipv4Addr>,
    pub dev: String,
    pub metric: Option<u32>,
}

impl RouteSnapshot {
    /// Create a restorable route snapshot after validating interface text.
    pub fn new(
        destination: Ipv4Cidr,
        via: Option<Ipv4Addr>,
        dev: impl Into<String>,
    ) -> Result<Self, NetworkPolicyError> {
        Ok(Self {
            destination,
            via,
            dev: clean_interface(dev.into())?,
            metric: None,
        })
    }

    /// Attach the route priority/metric when the backend provides it.
    pub fn with_metric(mut self, metric: u32) -> Self {
        self.metric = Some(metric);
        self
    }
}

/// Why a planned route exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteReason {
    VpnGatewayPin,
    DetectedLocalNetwork,
    LocalBypassCidr,
    VpnInternalNetwork,
    VpnSplitInclude,
    ProfileCompanyRoute,
    VpnSplitExclude,
    VpnDefaultRoute,
}

/// Complete no-side-effect route plan for one VPN session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRoutePlan {
    pub routes: Vec<PlannedRoute>,
    pub block_ipv6_default_route: bool,
}

impl NetworkRoutePlan {
    /// Return planned routes for a given reason.
    pub fn routes_for(&self, reason: RouteReason) -> Vec<&PlannedRoute> {
        self.routes
            .iter()
            .filter(|route| route.reason == reason)
            .collect()
    }
}

/// A rendered route command for a platform backend to execute later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCommand {
    pub program: &'static str,
    pub args: Vec<String>,
    pub reason: RouteReason,
}

/// Rendered apply/revert route commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCommandPlan {
    pub apply: Vec<RouteCommand>,
    pub revert: Vec<RouteCommand>,
}

/// State returned after route commands have been applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedRouteState {
    pub revert: Vec<RouteCommand>,
}

/// Injectable route command runner for privileged backends and tests.
pub trait RouteCommandRunner {
    fn run(&mut self, command: &RouteCommand) -> Result<(), NetworkPolicyError>;
}

/// Errors returned while building network policy plans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkPolicyError {
    BackendFailed {
        operation: &'static str,
        detail: String,
    },
    CommandFailed {
        operation: String,
        detail: String,
    },
    EmptyInterface {
        field: &'static str,
    },
    DefaultRouteNotFound,
    InteriorNul {
        field: &'static str,
    },
    InvalidCidr {
        value: String,
    },
    InvalidDefaultGateway {
        value: String,
    },
    InvalidPushedRoute {
        field: &'static str,
        value: String,
    },
    InvalidPrefixLength {
        prefix_len: u8,
    },
    InvalidRouteMode {
        value: String,
    },
}

impl fmt::Display for NetworkPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendFailed { operation, detail } => {
                write!(f, "network backend failed during {operation}: {detail}")
            }
            Self::CommandFailed { operation, detail } => {
                write!(f, "route command failed during {operation}: {detail}")
            }
            Self::EmptyInterface { field } => write!(f, "{field} must not be empty"),
            Self::DefaultRouteNotFound => write!(f, "default route was not found"),
            Self::InteriorNul { field } => write!(f, "{field} must not contain a NUL byte"),
            Self::InvalidCidr { value } => write!(f, "invalid IPv4 CIDR {value:?}"),
            Self::InvalidDefaultGateway { value } => {
                write!(f, "invalid default route gateway {value:?}")
            }
            Self::InvalidPushedRoute { field, value } => {
                write!(f, "invalid {field} IPv4 CIDR {value:?}")
            }
            Self::InvalidPrefixLength { prefix_len } => {
                write!(f, "invalid IPv4 CIDR prefix length {prefix_len}")
            }
            Self::InvalidRouteMode { value } => write!(f, "invalid route mode {value:?}"),
        }
    }
}

impl std::error::Error for NetworkPolicyError {}

/// Build a no-side-effect route plan for one VPN session.
pub fn build_network_route_plan(
    default_route: &DefaultRouteSnapshot,
    tunnel_interface: impl Into<String>,
    vpn_gateway: Ipv4Addr,
    pushed: &ServerPushedRoutes,
    policy: &NetworkPolicy,
) -> Result<NetworkRoutePlan, NetworkPolicyError> {
    let tunnel_interface = clean_interface(tunnel_interface.into())?;
    let mut routes = Vec::new();

    if policy.route_mode == RouteMode::Off {
        return Ok(NetworkRoutePlan {
            routes,
            block_ipv6_default_route: false,
        });
    }

    push_route_once(
        &mut routes,
        PlannedRoute {
            destination: Ipv4Cidr::host(vpn_gateway),
            via: Some(default_route.gateway),
            dev: default_route.interface.clone(),
            reason: RouteReason::VpnGatewayPin,
        },
    );

    for destination in &policy.detected_local_cidrs {
        push_route_once(
            &mut routes,
            PlannedRoute {
                destination: *destination,
                via: Some(default_route.gateway),
                dev: default_route.interface.clone(),
                reason: RouteReason::DetectedLocalNetwork,
            },
        );
    }

    for destination in &policy.local_bypass_cidrs {
        push_route_once(
            &mut routes,
            PlannedRoute {
                destination: *destination,
                via: Some(default_route.gateway),
                dev: default_route.interface.clone(),
                reason: RouteReason::LocalBypassCidr,
            },
        );
    }

    if let Some(internal_network) = pushed.internal_network {
        push_route_once(
            &mut routes,
            PlannedRoute {
                destination: internal_network,
                via: None,
                dev: tunnel_interface.clone(),
                reason: RouteReason::VpnInternalNetwork,
            },
        );
    }

    for destination in &pushed.split_includes {
        push_route_once(
            &mut routes,
            PlannedRoute {
                destination: *destination,
                via: None,
                dev: tunnel_interface.clone(),
                reason: RouteReason::VpnSplitInclude,
            },
        );
    }

    for destination in &policy.company_routes {
        push_route_once(
            &mut routes,
            PlannedRoute {
                destination: *destination,
                via: None,
                dev: tunnel_interface.clone(),
                reason: RouteReason::ProfileCompanyRoute,
            },
        );
    }

    for destination in &pushed.split_excludes {
        if is_ignored_split_exclude(*destination) {
            continue;
        }

        push_route_once(
            &mut routes,
            PlannedRoute {
                destination: *destination,
                via: Some(default_route.gateway),
                dev: default_route.interface.clone(),
                reason: RouteReason::VpnSplitExclude,
            },
        );
    }

    if policy.route_mode == RouteMode::Full {
        push_route_once(
            &mut routes,
            PlannedRoute {
                destination: Ipv4Cidr::new(Ipv4Addr::new(0, 0, 0, 0), 0)?,
                via: None,
                dev: tunnel_interface,
                reason: RouteReason::VpnDefaultRoute,
            },
        );
    }

    Ok(NetworkRoutePlan {
        routes,
        block_ipv6_default_route: policy.block_ipv6_default_route,
    })
}

fn push_route_once(routes: &mut Vec<PlannedRoute>, route: PlannedRoute) {
    if routes.iter().any(|existing| {
        existing.destination == route.destination
            && existing.via == route.via
            && existing.dev == route.dev
    }) {
        return;
    }

    routes.push(route);
}

fn is_ignored_split_exclude(destination: Ipv4Cidr) -> bool {
    destination.address == Ipv4Addr::new(0, 0, 0, 0) && destination.prefix_len == 32
}

/// Render route plans as Linux `ip route` commands without executing them.
pub fn render_linux_ip_route_commands(plan: &NetworkRoutePlan) -> RouteCommandPlan {
    let apply = plan
        .routes
        .iter()
        .map(|route| render_linux_route_replace(route))
        .collect();
    let revert = plan
        .routes
        .iter()
        .rev()
        .map(|route| render_linux_route_delete(route))
        .collect();

    RouteCommandPlan { apply, revert }
}

/// Apply a rendered route command plan with an injected runner.
///
/// If an apply command fails, commands that already succeeded are reverted in
/// reverse order before the original error is returned.
pub fn apply_route_command_plan_with<R: RouteCommandRunner>(
    runner: &mut R,
    plan: &RouteCommandPlan,
) -> Result<AppliedRouteState, NetworkPolicyError> {
    for (index, command) in plan.apply.iter().enumerate() {
        if let Err(err) = runner.run(command) {
            rollback_applied_prefix(runner, plan, index);
            return Err(err);
        }
    }

    Ok(AppliedRouteState {
        revert: plan.revert.clone(),
    })
}

/// Revert previously applied route commands with an injected runner.
///
/// Revert is best-effort and returns every command error to the caller.
pub fn revert_route_command_plan_with<R: RouteCommandRunner>(
    runner: &mut R,
    state: &AppliedRouteState,
) -> Vec<NetworkPolicyError> {
    state
        .revert
        .iter()
        .filter_map(|command| runner.run(command).err())
        .collect()
}

/// Parse `ip route show default` output into a pre-VPN default route snapshot.
pub fn parse_linux_default_route(output: &str) -> Result<DefaultRouteSnapshot, NetworkPolicyError> {
    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.first().copied() != Some("default") {
            continue;
        }

        let gateway =
            token_after(&fields, "via").ok_or(NetworkPolicyError::DefaultRouteNotFound)?;
        let interface =
            token_after(&fields, "dev").ok_or(NetworkPolicyError::DefaultRouteNotFound)?;
        let gateway = gateway
            .parse()
            .map_err(|_| NetworkPolicyError::InvalidDefaultGateway {
                value: gateway.to_owned(),
            })?;

        return DefaultRouteSnapshot::new(gateway, interface);
    }

    Err(NetworkPolicyError::DefaultRouteNotFound)
}

fn clean_interface(value: String) -> Result<String, NetworkPolicyError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(NetworkPolicyError::EmptyInterface { field: "interface" });
    }

    if value.contains('\0') {
        return Err(NetworkPolicyError::InteriorNul { field: "interface" });
    }

    Ok(value.to_owned())
}

fn ipv4_netmask_prefix_len(netmask: Ipv4Addr) -> Option<u8> {
    let raw = u32::from(netmask);
    let prefix_len = raw.count_ones() as u8;
    let expected = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };

    (raw == expected).then_some(prefix_len)
}

fn apply_ipv4_netmask(address: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(address) & u32::from(netmask))
}

fn token_after<'a>(fields: &'a [&str], token: &str) -> Option<&'a str> {
    fields
        .windows(2)
        .find_map(|window| (window[0] == token).then_some(window[1]))
}

fn rollback_applied_prefix<R: RouteCommandRunner>(
    runner: &mut R,
    plan: &RouteCommandPlan,
    applied_count: usize,
) {
    if applied_count == 0 {
        return;
    }

    let rollback_start = plan.revert.len().saturating_sub(applied_count);
    for command in &plan.revert[rollback_start..] {
        let _ = runner.run(command);
    }
}

fn render_linux_route_replace(route: &PlannedRoute) -> RouteCommand {
    let mut args = vec![
        "route".to_owned(),
        "replace".to_owned(),
        route.destination.to_string(),
    ];
    push_route_nexthop(&mut args, route);

    RouteCommand {
        program: "ip",
        args,
        reason: route.reason,
    }
}

fn render_linux_route_delete(route: &PlannedRoute) -> RouteCommand {
    let mut args = vec![
        "route".to_owned(),
        "del".to_owned(),
        route.destination.to_string(),
    ];
    args.push("dev".to_owned());
    args.push(route.dev.clone());

    RouteCommand {
        program: "ip",
        args,
        reason: route.reason,
    }
}

fn push_route_nexthop(args: &mut Vec<String>, route: &PlannedRoute) {
    if let Some(gateway) = route.via {
        args.push("via".to_owned());
        args.push(gateway.to_string());
    }
    args.push("dev".to_owned());
    args.push(route.dev.clone());
}

fn parse_cidr_list<I, S>(
    field: &'static str,
    routes: I,
) -> Result<Vec<Ipv4Cidr>, NetworkPolicyError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    routes
        .into_iter()
        .map(|route| {
            route
                .as_ref()
                .parse()
                .map_err(|_| NetworkPolicyError::InvalidPushedRoute {
                    field,
                    value: route.as_ref().to_owned(),
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use super::{
        apply_network_route_plan_with, apply_route_command_plan_with, apply_tun_config_with,
        build_network_route_plan, render_linux_ip_route_commands, revert_network_route_plan_with,
        revert_route_command_plan_with, revert_tun_config_with, DefaultRouteSnapshot, Ipv4Cidr,
        LinuxNetworkBackend, NetworkPolicy, NetworkPolicyError, NetworkRoutePlan, PlannedRoute,
        RouteCommand, RouteCommandRunner, RouteMode, RouteReason, RouteSnapshot,
        ServerPushedRoutes, TunConfig, CRATE_ROLE,
    };

    #[test]
    fn documents_network_role() {
        assert!(CRATE_ROLE.contains("route"));
    }

    #[test]
    fn parses_ipv4_cidr_values() {
        let cidr: Ipv4Cidr = "198.51.100.0/24".parse().unwrap();

        assert_eq!(cidr.address, Ipv4Addr::new(198, 51, 100, 0));
        assert_eq!(cidr.prefix_len, 24);
        assert_eq!(cidr.to_string(), "198.51.100.0/24");
        let host_route: Ipv4Cidr = "203.0.113.10/255.255.255.255".parse().unwrap();
        assert_eq!(host_route.address, Ipv4Addr::new(203, 0, 113, 10));
        assert_eq!(host_route.prefix_len, 32);
        assert_eq!(host_route.to_string(), "203.0.113.10/32");
        let masked_route: Ipv4Cidr = "198.51.100.7/255.255.255.0".parse().unwrap();
        assert_eq!(masked_route.address, Ipv4Addr::new(198, 51, 100, 0));
        assert_eq!(masked_route.prefix_len, 24);
        assert_eq!(
            "198.51.100.0/33".parse::<Ipv4Cidr>().unwrap_err(),
            NetworkPolicyError::InvalidPrefixLength { prefix_len: 33 }
        );
        assert!("198.51.100.0/255.0.255.0".parse::<Ipv4Cidr>().is_err());
        assert!("not-a-cidr".parse::<Ipv4Cidr>().is_err());
    }

    #[test]
    fn parses_linux_default_route_output() {
        let output = "\
default via 192.0.2.1 dev eno1 proto dhcp src 192.0.2.107 metric 100
198.51.100.0/24 dev tun0 scope link
";

        let route = super::parse_linux_default_route(output).unwrap();

        assert_eq!(route.gateway, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(route.interface, "eno1");
    }

    #[test]
    fn parses_first_linux_default_route_when_multiple_exist() {
        let output = "\
default via 192.0.2.1 dev eno1 metric 100
default via 198.51.100.1 dev tun0 metric 200
";

        let route = super::parse_linux_default_route(output).unwrap();

        assert_eq!(route.gateway, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(route.interface, "eno1");
    }

    #[test]
    fn rejects_missing_or_invalid_linux_default_route_output() {
        assert_eq!(
            super::parse_linux_default_route("198.51.100.0/24 dev tun0").unwrap_err(),
            NetworkPolicyError::DefaultRouteNotFound
        );
        assert_eq!(
            super::parse_linux_default_route("default via not-an-ip dev eno1").unwrap_err(),
            NetworkPolicyError::InvalidDefaultGateway {
                value: "not-an-ip".to_owned()
            }
        );
        assert_eq!(
            super::parse_linux_default_route("default via 192.0.2.1").unwrap_err(),
            NetworkPolicyError::DefaultRouteNotFound
        );
    }

    #[test]
    fn builds_gateway_pin_and_local_bypass_routes_without_side_effects() {
        let default_route = DefaultRouteSnapshot::new(Ipv4Addr::new(192, 0, 2, 1), "eno1").unwrap();
        let pushed = ServerPushedRoutes::new();
        let policy =
            NetworkPolicy::new(RouteMode::Split).with_local_bypass_cidrs(vec![local_bypass_cidr()]);

        let plan = build_network_route_plan(
            &default_route,
            "tun0",
            Ipv4Addr::new(203, 0, 113, 10),
            &pushed,
            &policy,
        )
        .unwrap();

        assert_eq!(plan.routes.len(), 2);
        let gateway_pin = plan.routes_for(RouteReason::VpnGatewayPin);
        assert_eq!(gateway_pin.len(), 1);
        assert_eq!(
            gateway_pin[0].destination,
            Ipv4Cidr::host(Ipv4Addr::new(203, 0, 113, 10))
        );
        assert_eq!(gateway_pin[0].via, Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(gateway_pin[0].dev, "eno1");

        let bypass = plan.routes_for(RouteReason::LocalBypassCidr);
        assert_eq!(bypass.len(), 1);
        assert_eq!(bypass[0].destination, local_bypass_cidr());
        assert_eq!(bypass[0].via, Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(bypass[0].dev, "eno1");
    }

    #[test]
    fn plans_detected_local_network_before_explicit_local_bypass() {
        let default_route =
            DefaultRouteSnapshot::new(Ipv4Addr::new(192, 0, 2, 1), "eth-test").unwrap();
        let policy = NetworkPolicy::new(RouteMode::Full)
            .with_detected_local_cidrs(vec!["192.0.2.0/24".parse().unwrap()])
            .with_local_bypass_cidrs(vec!["198.18.0.0/15".parse().unwrap()]);

        let plan = build_network_route_plan(
            &default_route,
            "tun-test",
            Ipv4Addr::new(198, 51, 100, 10),
            &ServerPushedRoutes::new(),
            &policy,
        )
        .unwrap();

        let local = plan.routes_for(RouteReason::DetectedLocalNetwork);
        assert_eq!(local.len(), 1);
        assert_eq!(local[0].destination.to_string(), "192.0.2.0/24");
        assert_eq!(local[0].via, Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(local[0].dev, "eth-test");

        let explicit = plan.routes_for(RouteReason::LocalBypassCidr);
        assert_eq!(explicit.len(), 1);
        assert_eq!(explicit[0].destination.to_string(), "198.18.0.0/15");
        assert_eq!(explicit[0].via, Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(explicit[0].dev, "eth-test");

        assert_eq!(plan.routes[1].reason, RouteReason::DetectedLocalNetwork);
        assert_eq!(plan.routes[2].reason, RouteReason::LocalBypassCidr);
    }

    #[test]
    fn parses_route_modes_from_profile_text() {
        assert_eq!("split".parse::<RouteMode>().unwrap(), RouteMode::Split);
        assert_eq!("full".parse::<RouteMode>().unwrap(), RouteMode::Full);
        assert_eq!("off".parse::<RouteMode>().unwrap(), RouteMode::Off);
        assert_eq!(RouteMode::Split.to_string(), "split");
        assert_eq!(
            "invalid".parse::<RouteMode>().unwrap_err(),
            NetworkPolicyError::InvalidRouteMode {
                value: "invalid".to_owned()
            }
        );
    }

    #[test]
    fn routes_vpn_networks_to_tunnel_and_excludes_to_local_gateway() {
        let default_route = DefaultRouteSnapshot::new(Ipv4Addr::new(192, 0, 2, 1), "eno1").unwrap();
        let pushed = ServerPushedRoutes::new()
            .with_internal_network("198.51.100.0/24".parse().unwrap())
            .with_split_includes(vec!["203.0.113.128/25".parse().unwrap()])
            .with_split_excludes(vec![
                "203.0.113.10/32".parse().unwrap(),
                "0.0.0.0/32".parse().unwrap(),
            ]);

        let plan = build_network_route_plan(
            &default_route,
            "tun0",
            Ipv4Addr::new(203, 0, 113, 10),
            &pushed,
            &NetworkPolicy::new(RouteMode::Split),
        )
        .unwrap();

        let internal = plan.routes_for(RouteReason::VpnInternalNetwork);
        assert_eq!(internal.len(), 1);
        assert_eq!(internal[0].destination.to_string(), "198.51.100.0/24");
        assert_eq!(internal[0].via, None);
        assert_eq!(internal[0].dev, "tun0");

        let includes = plan.routes_for(RouteReason::VpnSplitInclude);
        assert_eq!(includes.len(), 1);
        assert_eq!(includes[0].destination.to_string(), "203.0.113.128/25");
        assert_eq!(includes[0].via, None);
        assert_eq!(includes[0].dev, "tun0");

        let excludes = plan.routes_for(RouteReason::VpnSplitExclude);
        assert!(excludes.is_empty());
        assert_eq!(plan.routes_for(RouteReason::VpnGatewayPin).len(), 1);
    }

    #[test]
    fn routes_profile_company_routes_to_tunnel_without_system_changes() {
        let default_route = DefaultRouteSnapshot::new(Ipv4Addr::new(192, 0, 2, 1), "eno1").unwrap();
        let policy = NetworkPolicy::new(RouteMode::Split).with_company_routes(vec![
            "203.0.113.0/25".parse().unwrap(),
            "203.0.113.128/25".parse().unwrap(),
        ]);

        let plan = build_network_route_plan(
            &default_route,
            "tun0",
            Ipv4Addr::new(203, 0, 113, 10),
            &ServerPushedRoutes::new(),
            &policy,
        )
        .unwrap();

        let company = plan.routes_for(RouteReason::ProfileCompanyRoute);
        assert_eq!(company.len(), 2);
        assert_eq!(company[0].destination.to_string(), "203.0.113.0/25");
        assert_eq!(company[0].via, None);
        assert_eq!(company[0].dev, "tun0");
        assert_eq!(company[1].destination.to_string(), "203.0.113.128/25");
    }

    #[test]
    fn deduplicates_gateway_split_exclude_and_ignores_zero_host_exclude() {
        let default_route = DefaultRouteSnapshot::new(Ipv4Addr::new(192, 0, 2, 1), "eno1").unwrap();
        let pushed = ServerPushedRoutes::new()
            .with_internal_network("198.51.100.0/24".parse().unwrap())
            .with_split_excludes(vec![
                "203.0.113.10/255.255.255.255".parse().unwrap(),
                "0.0.0.0/32".parse().unwrap(),
            ]);

        let plan = build_network_route_plan(
            &default_route,
            "tun0",
            Ipv4Addr::new(203, 0, 113, 10),
            &pushed,
            &NetworkPolicy::new(RouteMode::Split),
        )
        .unwrap();

        assert_eq!(plan.routes_for(RouteReason::VpnGatewayPin).len(), 1);
        assert!(plan.routes_for(RouteReason::VpnSplitExclude).is_empty());

        let commands = render_linux_ip_route_commands(&plan);
        assert_eq!(commands.apply.len(), 2);
        assert_eq!(
            commands
                .apply
                .iter()
                .filter(|command| command.args.contains(&"203.0.113.10/32".to_owned()))
                .count(),
            1
        );
        assert!(!commands
            .apply
            .iter()
            .any(|command| command.args.contains(&"0.0.0.0/32".to_owned())));
    }

    #[test]
    fn builds_server_pushed_routes_from_openconnect_parts() {
        let pushed = ServerPushedRoutes::from_openconnect_parts(
            Some(Ipv4Addr::new(198, 51, 100, 0)),
            Some(24),
            ["203.0.113.128/25"],
            ["203.0.113.10/255.255.255.255", "0.0.0.0/32"],
        )
        .unwrap();

        assert_eq!(
            pushed.internal_network,
            Some("198.51.100.0/24".parse().unwrap())
        );
        assert_eq!(
            pushed.split_includes,
            vec!["203.0.113.128/25".parse().unwrap()]
        );
        assert_eq!(
            pushed.split_excludes,
            vec![
                "203.0.113.10/32".parse().unwrap(),
                "0.0.0.0/32".parse().unwrap()
            ]
        );
    }

    #[test]
    fn route_modes_control_default_and_noop_routes() {
        let default_route = DefaultRouteSnapshot::new(Ipv4Addr::new(192, 0, 2, 1), "eno1").unwrap();
        let pushed =
            ServerPushedRoutes::new().with_internal_network("198.51.100.0/24".parse().unwrap());

        let full = build_network_route_plan(
            &default_route,
            "tun0",
            Ipv4Addr::new(203, 0, 113, 10),
            &pushed,
            &NetworkPolicy::new(RouteMode::Full),
        )
        .unwrap();
        let default_routes = full.routes_for(RouteReason::VpnDefaultRoute);
        assert_eq!(default_routes.len(), 1);
        assert_eq!(default_routes[0].destination.to_string(), "0.0.0.0/0");
        assert_eq!(default_routes[0].dev, "tun0");
        assert!(full.block_ipv6_default_route);

        let off = build_network_route_plan(
            &default_route,
            "tun0",
            Ipv4Addr::new(203, 0, 113, 10),
            &pushed,
            &NetworkPolicy::new(RouteMode::Off),
        )
        .unwrap();
        assert!(off.routes.is_empty());
        assert!(!off.block_ipv6_default_route);
    }

    #[test]
    fn ignores_incomplete_internal_network_parts() {
        let without_prefix = ServerPushedRoutes::from_openconnect_parts(
            Some(Ipv4Addr::new(198, 51, 100, 0)),
            None,
            std::iter::empty::<&str>(),
            std::iter::empty::<&str>(),
        )
        .unwrap();
        let without_address = ServerPushedRoutes::from_openconnect_parts(
            None,
            Some(24),
            std::iter::empty::<&str>(),
            std::iter::empty::<&str>(),
        )
        .unwrap();

        assert_eq!(without_prefix.internal_network, None);
        assert_eq!(without_address.internal_network, None);
    }

    #[test]
    fn rejects_invalid_server_pushed_route_parts() {
        let err = ServerPushedRoutes::from_openconnect_parts(
            Some(Ipv4Addr::new(198, 51, 100, 0)),
            Some(33),
            std::iter::empty::<&str>(),
            std::iter::empty::<&str>(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            NetworkPolicyError::InvalidPrefixLength { prefix_len: 33 }
        );

        let err = ServerPushedRoutes::from_openconnect_parts(
            None,
            None,
            ["not-a-cidr"],
            std::iter::empty::<&str>(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            NetworkPolicyError::InvalidPushedRoute {
                field: "split include",
                value: "not-a-cidr".to_owned()
            }
        );
    }

    #[test]
    fn renders_linux_route_commands_without_executing_them() {
        let default_route = DefaultRouteSnapshot::new(Ipv4Addr::new(192, 0, 2, 1), "eno1").unwrap();
        let pushed = ServerPushedRoutes::new()
            .with_internal_network("198.51.100.0/24".parse().unwrap())
            .with_split_excludes(vec!["203.0.113.10/32".parse().unwrap()]);
        let plan = build_network_route_plan(
            &default_route,
            "tun0",
            Ipv4Addr::new(203, 0, 113, 10),
            &pushed,
            &NetworkPolicy::new(RouteMode::Split)
                .with_local_bypass_cidrs(vec![local_bypass_cidr()]),
        )
        .unwrap();

        let commands = render_linux_ip_route_commands(&plan);

        assert_eq!(commands.apply.len(), 3);
        assert_eq!(commands.revert.len(), 3);
        assert_eq!(commands.apply[0].program, "ip");
        assert_eq!(
            commands.apply[0].args,
            vec![
                "route",
                "replace",
                "203.0.113.10/32",
                "via",
                "192.0.2.1",
                "dev",
                "eno1"
            ]
        );
        assert_eq!(
            commands.apply[1].args,
            vec![
                "route",
                "replace",
                "198.18.0.0/15",
                "via",
                "192.0.2.1",
                "dev",
                "eno1"
            ]
        );
        assert_eq!(
            commands.apply[2].args,
            vec!["route", "replace", "198.51.100.0/24", "dev", "tun0"]
        );
        assert_eq!(
            commands.revert[0].args,
            vec!["route", "del", "198.51.100.0/24", "dev", "tun0"]
        );
        assert_eq!(
            commands.revert[2].args,
            vec!["route", "del", "203.0.113.10/32", "dev", "eno1"]
        );
    }

    #[test]
    fn applies_and_reverts_route_commands_with_injected_runner() {
        let commands = sample_route_commands();
        let mut runner = RecordingRouteRunner::default();

        let applied = apply_route_command_plan_with(&mut runner, &commands).unwrap();
        let revert_errors = revert_route_command_plan_with(&mut runner, &applied);

        assert!(revert_errors.is_empty());
        assert_eq!(
            runner.operations,
            vec![
                "apply:VpnGatewayPin",
                "apply:LocalBypassCidr",
                "apply:VpnInternalNetwork",
                "revert:VpnInternalNetwork",
                "revert:LocalBypassCidr",
                "revert:VpnGatewayPin",
            ]
        );
    }

    #[test]
    fn applies_and_reverts_network_routes_with_backend_trait() {
        let plan = sample_network_route_plan();
        let backend = RecordingLinuxBackend::default();

        let applied = apply_network_route_plan_with(&backend, &plan).unwrap();
        let revert_errors = revert_network_route_plan_with(&backend, &applied);

        assert!(revert_errors.is_empty());
        assert_eq!(
            backend.operations.borrow().as_slice(),
            [
                "route:replace:VpnGatewayPin",
                "route:replace:LocalBypassCidr",
                "route:replace:VpnInternalNetwork",
                "route:del:VpnInternalNetwork",
                "route:del:LocalBypassCidr",
                "route:del:VpnGatewayPin",
            ]
        );
    }

    #[test]
    fn applies_and_reverts_ipv6_default_block_for_full_policy() {
        let default_route =
            DefaultRouteSnapshot::new(Ipv4Addr::new(192, 0, 2, 1), "eth-test").unwrap();
        let plan = build_network_route_plan(
            &default_route,
            "tun-test",
            Ipv4Addr::new(203, 0, 113, 10),
            &ServerPushedRoutes::new(),
            &NetworkPolicy::new(RouteMode::Full),
        )
        .unwrap();
        let backend = RecordingLinuxBackend::default();

        let applied = apply_network_route_plan_with(&backend, &plan).unwrap();
        let revert_errors = revert_network_route_plan_with(&backend, &applied);

        assert!(revert_errors.is_empty());
        assert_eq!(
            backend.operations.borrow().as_slice(),
            [
                "route:replace:VpnGatewayPin",
                "route:replace:VpnDefaultRoute",
                "route6:block:exists",
                "route6:block:add",
                "route6:block:del",
                "route:del:VpnDefaultRoute",
                "route:del:VpnGatewayPin",
            ]
        );
    }

    #[test]
    fn keeps_pre_existing_ipv6_default_block_on_revert() {
        let default_route =
            DefaultRouteSnapshot::new(Ipv4Addr::new(192, 0, 2, 1), "eth-test").unwrap();
        let plan = build_network_route_plan(
            &default_route,
            "tun-test",
            Ipv4Addr::new(203, 0, 113, 10),
            &ServerPushedRoutes::new(),
            &NetworkPolicy::new(RouteMode::Full),
        )
        .unwrap();
        let backend = RecordingLinuxBackend {
            ipv6_default_route_block_exists: true,
            ..RecordingLinuxBackend::default()
        };

        let applied = apply_network_route_plan_with(&backend, &plan).unwrap();
        let revert_errors = revert_network_route_plan_with(&backend, &applied);

        assert!(revert_errors.is_empty());
        assert_eq!(
            backend.operations.borrow().as_slice(),
            [
                "route:replace:VpnGatewayPin",
                "route:replace:VpnDefaultRoute",
                "route6:block:exists",
                "route:del:VpnDefaultRoute",
                "route:del:VpnGatewayPin",
            ]
        );
    }

    #[test]
    fn rolls_back_backend_routes_after_apply_failure() {
        let plan = sample_network_route_plan();
        let backend = RecordingLinuxBackend {
            fail_on_operation: Some("route:replace:LocalBypassCidr".to_owned()),
            ..RecordingLinuxBackend::default()
        };

        let err = apply_network_route_plan_with(&backend, &plan).unwrap_err();

        assert_eq!(
            err,
            NetworkPolicyError::BackendFailed {
                operation: "test backend",
                detail: "route:replace:LocalBypassCidr".to_owned(),
            }
        );
        assert_eq!(
            backend.operations.borrow().as_slice(),
            [
                "route:replace:VpnGatewayPin",
                "route:replace:LocalBypassCidr",
                "route:del:VpnGatewayPin",
            ]
        );
    }

    #[test]
    fn restores_existing_backend_route_on_revert() {
        let destination = local_bypass_cidr();
        let previous = RouteSnapshot::new(
            destination,
            Some(Ipv4Addr::new(192, 0, 2, 254)),
            "eth-original",
        )
        .unwrap()
        .with_metric(50);
        let backend = RecordingLinuxBackend::with_existing_routes(vec![previous]);
        let plan = NetworkRoutePlan {
            routes: vec![PlannedRoute {
                destination,
                via: Some(Ipv4Addr::new(192, 0, 2, 1)),
                dev: "eth-test".to_owned(),
                reason: RouteReason::LocalBypassCidr,
            }],
            block_ipv6_default_route: false,
        };

        let applied = apply_network_route_plan_with(&backend, &plan).unwrap();
        let errors = revert_network_route_plan_with(&backend, &applied);

        assert!(errors.is_empty());
        assert_eq!(
            backend.operations.borrow().as_slice(),
            [
                "route:replace:LocalBypassCidr",
                "route:restore:198.18.0.0/15:via=192.0.2.254:dev=eth-original:metric=50",
            ]
        );
    }

    #[test]
    fn deletes_created_backend_route_on_revert_when_no_previous_route_exists() {
        let backend = RecordingLinuxBackend::default();
        let plan = NetworkRoutePlan {
            routes: vec![PlannedRoute {
                destination: local_bypass_cidr(),
                via: Some(Ipv4Addr::new(192, 0, 2, 1)),
                dev: "eth-test".to_owned(),
                reason: RouteReason::LocalBypassCidr,
            }],
            block_ipv6_default_route: false,
        };

        let applied = apply_network_route_plan_with(&backend, &plan).unwrap();
        let errors = revert_network_route_plan_with(&backend, &applied);

        assert!(errors.is_empty());
        assert_eq!(
            backend.operations.borrow().as_slice(),
            ["route:replace:LocalBypassCidr", "route:del:LocalBypassCidr"]
        );
    }

    #[test]
    fn route_apply_failure_restores_previously_replaced_route() {
        let local_destination = local_bypass_cidr();
        let previous = RouteSnapshot::new(
            local_destination,
            Some(Ipv4Addr::new(192, 0, 2, 254)),
            "eth-original",
        )
        .unwrap();
        let backend = RecordingLinuxBackend {
            existing_routes: RefCell::new(HashMap::from([(local_destination, previous)])),
            fail_on_operation: Some("route:replace:VpnInternalNetwork".to_owned()),
            ..RecordingLinuxBackend::default()
        };
        let plan = NetworkRoutePlan {
            routes: vec![
                PlannedRoute {
                    destination: local_destination,
                    via: Some(Ipv4Addr::new(192, 0, 2, 1)),
                    dev: "eth-test".to_owned(),
                    reason: RouteReason::LocalBypassCidr,
                },
                PlannedRoute {
                    destination: "198.51.100.0/24".parse().unwrap(),
                    via: None,
                    dev: "tun-test".to_owned(),
                    reason: RouteReason::VpnInternalNetwork,
                },
            ],
            block_ipv6_default_route: false,
        };

        let err = apply_network_route_plan_with(&backend, &plan).unwrap_err();

        assert_eq!(
            err,
            NetworkPolicyError::BackendFailed {
                operation: "test backend",
                detail: "route:replace:VpnInternalNetwork".to_owned(),
            }
        );
        assert_eq!(
            backend.operations.borrow().as_slice(),
            [
                "route:replace:LocalBypassCidr",
                "route:replace:VpnInternalNetwork",
                "route:restore:198.18.0.0/15:via=192.0.2.254:dev=eth-original:metric=none",
            ]
        );
    }

    #[test]
    fn applies_and_reverts_tun_config_with_backend_trait() {
        let backend = RecordingLinuxBackend::default();
        let config = TunConfig::new("tun0")
            .unwrap()
            .with_ipv4_address(Ipv4Addr::new(198, 51, 100, 24), 24)
            .unwrap()
            .with_mtu(1200);

        let applied = apply_tun_config_with(&backend, &config).unwrap();
        let revert_errors = revert_tun_config_with(&backend, &applied);

        assert!(revert_errors.is_empty());
        assert_eq!(
            backend.operations.borrow().as_slice(),
            [
                "addr:replace:tun0:198.51.100.24/24",
                "link:mtu:tun0:1200",
                "link:up:tun0",
                "addr:del:tun0:198.51.100.24/24",
                "link:down:tun0",
            ]
        );
    }

    #[test]
    fn deletes_link_with_backend_trait_without_system_changes() {
        let backend = RecordingLinuxBackend::default();

        let deleted = backend.delete_link_if_exists("ocx0").unwrap();

        assert!(deleted);
        assert_eq!(backend.operations.borrow().as_slice(), ["link:del:ocx0"]);
    }

    #[test]
    fn rolls_back_successful_route_commands_after_apply_failure() {
        let commands = sample_route_commands();
        let mut runner = RecordingRouteRunner {
            fail_on_operation: Some("apply:LocalBypassCidr".to_owned()),
            ..RecordingRouteRunner::default()
        };

        let err = apply_route_command_plan_with(&mut runner, &commands).unwrap_err();

        assert_eq!(
            err,
            NetworkPolicyError::CommandFailed {
                operation: "apply:LocalBypassCidr".to_owned(),
                detail: "injected failure".to_owned(),
            }
        );
        assert_eq!(
            runner.operations,
            vec![
                "apply:VpnGatewayPin",
                "apply:LocalBypassCidr",
                "revert:VpnGatewayPin",
            ]
        );
    }

    #[test]
    fn rejects_invalid_interface_names() {
        assert!(DefaultRouteSnapshot::new(Ipv4Addr::new(192, 0, 2, 1), " ").is_err());
        assert!(DefaultRouteSnapshot::new(Ipv4Addr::new(192, 0, 2, 1), "en\0o1").is_err());

        let default_route = DefaultRouteSnapshot::new(Ipv4Addr::new(192, 0, 2, 1), "eno1").unwrap();
        let err = build_network_route_plan(
            &default_route,
            " ",
            Ipv4Addr::new(203, 0, 113, 10),
            &ServerPushedRoutes::new(),
            &NetworkPolicy::new(RouteMode::Split),
        )
        .unwrap_err();

        assert_eq!(
            err,
            NetworkPolicyError::EmptyInterface { field: "interface" }
        );
    }

    fn sample_route_commands() -> super::RouteCommandPlan {
        render_linux_ip_route_commands(&sample_network_route_plan())
    }

    fn sample_network_route_plan() -> NetworkRoutePlan {
        let default_route = DefaultRouteSnapshot::new(Ipv4Addr::new(192, 0, 2, 1), "eno1").unwrap();
        let pushed =
            ServerPushedRoutes::new().with_internal_network("198.51.100.0/24".parse().unwrap());
        let plan = build_network_route_plan(
            &default_route,
            "tun0",
            Ipv4Addr::new(203, 0, 113, 10),
            &pushed,
            &NetworkPolicy::new(RouteMode::Split)
                .with_local_bypass_cidrs(vec![local_bypass_cidr()]),
        )
        .unwrap();

        plan
    }

    #[derive(Default)]
    struct RecordingRouteRunner {
        operations: Vec<String>,
        fail_on_operation: Option<String>,
    }

    impl RouteCommandRunner for RecordingRouteRunner {
        fn run(&mut self, command: &RouteCommand) -> Result<(), NetworkPolicyError> {
            let operation = command_operation(command);
            self.operations.push(operation.clone());

            if self.fail_on_operation.as_deref() == Some(operation.as_str()) {
                return Err(NetworkPolicyError::CommandFailed {
                    operation,
                    detail: "injected failure".to_owned(),
                });
            }

            Ok(())
        }
    }

    fn command_operation(command: &RouteCommand) -> String {
        let phase = match command.args.get(1).map(String::as_str) {
            Some("replace") => "apply",
            Some("del") => "revert",
            _ => "unknown",
        };
        format!("{phase}:{:?}", command.reason)
    }

    fn local_bypass_cidr() -> Ipv4Cidr {
        "198.18.0.0/15".parse().unwrap()
    }

    #[derive(Default)]
    struct RecordingLinuxBackend {
        operations: RefCell<Vec<String>>,
        existing_routes: RefCell<HashMap<Ipv4Cidr, RouteSnapshot>>,
        ipv6_default_route_block_exists: bool,
        fail_on_operation: Option<String>,
    }

    impl RecordingLinuxBackend {
        fn with_existing_routes(routes: Vec<RouteSnapshot>) -> Self {
            Self {
                existing_routes: RefCell::new(
                    routes
                        .into_iter()
                        .map(|route| (route.destination, route))
                        .collect(),
                ),
                ..Self::default()
            }
        }

        fn record(&self, operation: String) -> Result<(), NetworkPolicyError> {
            self.operations.borrow_mut().push(operation.clone());

            if self.fail_on_operation.as_deref() == Some(operation.as_str()) {
                return Err(NetworkPolicyError::BackendFailed {
                    operation: "test backend",
                    detail: operation,
                });
            }

            Ok(())
        }
    }

    impl LinuxNetworkBackend for RecordingLinuxBackend {
        fn default_route(&self) -> Result<DefaultRouteSnapshot, NetworkPolicyError> {
            DefaultRouteSnapshot::new(Ipv4Addr::new(192, 0, 2, 1), "eno1")
        }

        fn link_exists(&self, _ifname: &str) -> Result<bool, NetworkPolicyError> {
            Ok(true)
        }

        fn interface_ipv4_cidrs(&self, _ifname: &str) -> Result<Vec<Ipv4Cidr>, NetworkPolicyError> {
            Ok(Vec::new())
        }

        fn route_snapshot(
            &self,
            destination: Ipv4Cidr,
        ) -> Result<Option<RouteSnapshot>, NetworkPolicyError> {
            Ok(self.existing_routes.borrow().get(&destination).cloned())
        }

        fn replace_ipv4_address(
            &self,
            ifname: &str,
            address: Ipv4Addr,
            prefix_len: u8,
        ) -> Result<(), NetworkPolicyError> {
            self.record(format!("addr:replace:{ifname}:{address}/{prefix_len}"))
        }

        fn delete_ipv4_address(
            &self,
            ifname: &str,
            address: Ipv4Addr,
            prefix_len: u8,
        ) -> Result<(), NetworkPolicyError> {
            self.record(format!("addr:del:{ifname}:{address}/{prefix_len}"))
        }

        fn set_link_mtu(&self, ifname: &str, mtu: u32) -> Result<(), NetworkPolicyError> {
            self.record(format!("link:mtu:{ifname}:{mtu}"))
        }

        fn set_link_up(&self, ifname: &str) -> Result<(), NetworkPolicyError> {
            self.record(format!("link:up:{ifname}"))
        }

        fn set_link_down(&self, ifname: &str) -> Result<(), NetworkPolicyError> {
            self.record(format!("link:down:{ifname}"))
        }

        fn delete_link_if_exists(&self, ifname: &str) -> Result<bool, NetworkPolicyError> {
            self.record(format!("link:del:{ifname}"))?;
            Ok(true)
        }

        fn replace_route(&self, route: &PlannedRoute) -> Result<(), NetworkPolicyError> {
            self.record(format!("route:replace:{:?}", route.reason))
        }

        fn restore_route(&self, route: &RouteSnapshot) -> Result<(), NetworkPolicyError> {
            self.record(format!(
                "route:restore:{}:via={}:dev={}:metric={}",
                route.destination,
                route
                    .via
                    .map(|gateway| gateway.to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                route.dev,
                route
                    .metric
                    .map(|metric| metric.to_string())
                    .unwrap_or_else(|| "none".to_owned())
            ))
        }

        fn delete_route(&self, route: &PlannedRoute) -> Result<(), NetworkPolicyError> {
            self.record(format!("route:del:{:?}", route.reason))
        }

        fn ipv6_default_route_block_exists(&self) -> Result<bool, NetworkPolicyError> {
            self.record("route6:block:exists".to_owned())?;
            Ok(self.ipv6_default_route_block_exists)
        }

        fn block_ipv6_default_route(&self) -> Result<(), NetworkPolicyError> {
            self.record("route6:block:add".to_owned())
        }

        fn unblock_ipv6_default_route(&self) -> Result<(), NetworkPolicyError> {
            self.record("route6:block:del".to_owned())
        }
    }
}
