//! Unified VPN network policy apply and revert orchestration.
//!
//! This crate owns the ordering between TUN configuration, route policy, and
//! DNS policy while the platform-specific backends remain injectable.

use std::fmt;
use std::net::Ipv4Addr;

use oc_oxide_dns::{
    apply_dns_command_plan_with, render_systemd_resolved_commands, revert_dns_command_plan_with,
    AppliedDnsState, DnsCommandPlan, DnsCommandRunner, DnsMode, DnsPolicyError, DnsSettings,
};
use oc_oxide_net::{
    apply_network_route_plan_with, apply_tun_config_with, build_network_route_plan,
    revert_network_route_plan_with, revert_tun_config_with, AppliedNetworkRouteState,
    AppliedTunConfig, DefaultRouteSnapshot, LinuxNetworkBackend, NetworkPolicy, NetworkPolicyError,
    NetworkRoutePlan, RouteMode, ServerPushedRoutes, TunConfig,
};

/// Human-readable crate role used by workspace smoke tests.
pub const CRATE_ROLE: &str = "unified policy apply and revert";

/// Complete policy plan for one connected tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPlan {
    pub tun: TunConfig,
    pub routes: NetworkRoutePlan,
    pub dns: DnsCommandPlan,
}

impl PolicyPlan {
    pub fn new(tun: TunConfig, routes: NetworkRoutePlan, dns: DnsCommandPlan) -> Self {
        Self { tun, routes, dns }
    }
}

/// Rust-owned tunnel configuration copied from libopenconnect state.
///
/// This intentionally contains primitive strings and values only, so policy
/// planning can be shared without depending on libopenconnect or the tunnel
/// crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelPolicyInput {
    pub ifname: String,
    pub address: Option<String>,
    pub netmask: Option<String>,
    pub mtu: i32,
    pub dns_servers: Vec<String>,
    pub default_domain: Option<String>,
    pub split_dns: Vec<String>,
    pub split_includes: Vec<String>,
    pub split_excludes: Vec<String>,
    pub gateway_addr: Option<String>,
}

impl TunnelPolicyInput {
    pub fn new(ifname: impl Into<String>) -> Self {
        Self {
            ifname: ifname.into(),
            address: None,
            netmask: None,
            mtu: 0,
            dns_servers: Vec::new(),
            default_domain: None,
            split_dns: Vec::new(),
            split_includes: Vec::new(),
            split_excludes: Vec::new(),
            gateway_addr: None,
        }
    }
}

/// Errors returned while building a reusable policy plan from tunnel state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyPlanBuildError {
    Dns(DnsPolicyError),
    Network(NetworkPolicyError),
    InvalidIpv4 { field: &'static str, value: String },
    InvalidMtu { value: i32 },
    MissingVpnGateway,
    NonContiguousNetmask { value: String },
}

impl fmt::Display for PolicyPlanBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(source) => write!(f, "failed to build DNS policy: {source}"),
            Self::Network(source) => write!(f, "failed to build route policy: {source}"),
            Self::InvalidIpv4 { field, value } => {
                write!(f, "invalid IPv4 {field} value {value:?}")
            }
            Self::InvalidMtu { value } => write!(f, "invalid pushed MTU {value}"),
            Self::MissingVpnGateway => write!(f, "server-pushed VPN gateway is missing"),
            Self::NonContiguousNetmask { value } => {
                write!(f, "non-contiguous IPv4 netmask {value}")
            }
        }
    }
}

impl std::error::Error for PolicyPlanBuildError {}

impl From<DnsPolicyError> for PolicyPlanBuildError {
    fn from(source: DnsPolicyError) -> Self {
        Self::Dns(source)
    }
}

impl From<NetworkPolicyError> for PolicyPlanBuildError {
    fn from(source: NetworkPolicyError) -> Self {
        Self::Network(source)
    }
}

/// Build a complete policy plan from copied tunnel state and local policy.
pub fn build_policy_plan_from_tunnel_input(
    input: &TunnelPolicyInput,
    default_route: &DefaultRouteSnapshot,
    route_policy: &NetworkPolicy,
    dns_mode: DnsMode,
) -> Result<PolicyPlan, PolicyPlanBuildError> {
    build_policy_plan_from_tunnel_input_with_company_domains(
        input,
        default_route,
        route_policy,
        dns_mode,
        std::iter::empty::<String>(),
    )
}

/// Build a complete policy plan with profile-declared company DNS domains.
pub fn build_policy_plan_from_tunnel_input_with_company_domains<I, S>(
    input: &TunnelPolicyInput,
    default_route: &DefaultRouteSnapshot,
    route_policy: &NetworkPolicy,
    dns_mode: DnsMode,
    company_domains: I,
) -> Result<PolicyPlan, PolicyPlanBuildError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let tun = build_tun_config_from_tunnel_input(input)?;
    let pushed = server_pushed_routes_from_tunnel_input(input)?;
    let gateway = if route_policy.route_mode == RouteMode::Off {
        Ipv4Addr::UNSPECIFIED
    } else {
        parse_optional_ipv4("gateway", input.gateway_addr.as_deref())?
            .ok_or(PolicyPlanBuildError::MissingVpnGateway)?
    };
    let routes = build_network_route_plan(
        default_route,
        input.ifname.clone(),
        gateway,
        &pushed,
        route_policy,
    )?;
    let dns =
        build_dns_plan_from_tunnel_input_with_company_domains(input, dns_mode, company_domains)?;

    Ok(PolicyPlan::new(tun, routes, dns))
}

pub fn build_tun_config_from_tunnel_input(
    input: &TunnelPolicyInput,
) -> Result<TunConfig, PolicyPlanBuildError> {
    let mut config = TunConfig::new(input.ifname.clone())?;

    if let (Some(address), Some(netmask)) = (&input.address, &input.netmask) {
        let address = parse_ipv4("address", address)?;
        let prefix_len = ipv4_netmask_prefix_len(netmask)?;
        config = config.with_ipv4_address(address, prefix_len)?;
    }

    if input.mtu > 0 {
        let mtu = u32::try_from(input.mtu)
            .map_err(|_| PolicyPlanBuildError::InvalidMtu { value: input.mtu })?;
        config = config.with_mtu(mtu);
    }

    Ok(config)
}

pub fn server_pushed_routes_from_tunnel_input(
    input: &TunnelPolicyInput,
) -> Result<ServerPushedRoutes, PolicyPlanBuildError> {
    let (internal_netaddr, internal_prefix_len) = match (&input.address, &input.netmask) {
        (Some(address), Some(netmask)) => {
            let address = parse_ipv4("address", address)?;
            let netmask_addr = parse_ipv4("netmask", netmask)?;
            let prefix_len = ipv4_netmask_prefix_len(netmask)?;
            (
                Some(apply_ipv4_netmask(address, netmask_addr)),
                Some(prefix_len),
            )
        }
        _ => (None, None),
    };

    Ok(ServerPushedRoutes::from_openconnect_parts(
        internal_netaddr,
        internal_prefix_len,
        input.split_includes.iter().map(String::as_str),
        input.split_excludes.iter().map(String::as_str),
    )?)
}

pub fn build_dns_plan_from_tunnel_input(
    input: &TunnelPolicyInput,
    mode: DnsMode,
) -> Result<DnsCommandPlan, PolicyPlanBuildError> {
    build_dns_plan_from_tunnel_input_with_company_domains(input, mode, std::iter::empty::<String>())
}

pub fn build_dns_plan_from_tunnel_input_with_company_domains<I, S>(
    input: &TunnelPolicyInput,
    mode: DnsMode,
    company_domains: I,
) -> Result<DnsCommandPlan, PolicyPlanBuildError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let settings = DnsSettings::from_openconnect_parts_with_company_domains(
        input.ifname.clone(),
        input.dns_servers.iter().map(String::as_str),
        input.default_domain.as_deref(),
        input.split_dns.iter().map(String::as_str),
        company_domains,
        mode,
    )?;

    Ok(render_systemd_resolved_commands(&settings)?)
}

/// Applied policy state needed to revert in reverse dependency order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedPolicyState {
    pub tun: AppliedTunConfig,
    pub routes: AppliedNetworkRouteState,
    pub dns: AppliedDnsState,
}

fn parse_optional_ipv4(
    field: &'static str,
    value: Option<&str>,
) -> Result<Option<Ipv4Addr>, PolicyPlanBuildError> {
    value.map(|value| parse_ipv4(field, value)).transpose()
}

fn parse_ipv4(field: &'static str, value: &str) -> Result<Ipv4Addr, PolicyPlanBuildError> {
    value
        .parse()
        .map_err(|_| PolicyPlanBuildError::InvalidIpv4 {
            field,
            value: value.to_owned(),
        })
}

fn ipv4_netmask_prefix_len(netmask: &str) -> Result<u8, PolicyPlanBuildError> {
    let netmask_addr = parse_ipv4("netmask", netmask)?;
    let raw = u32::from(netmask_addr);
    let prefix_len = raw.count_ones() as u8;
    let expected = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };

    if raw != expected {
        return Err(PolicyPlanBuildError::NonContiguousNetmask {
            value: netmask.to_owned(),
        });
    }

    Ok(prefix_len)
}

fn apply_ipv4_netmask(address: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(address) & u32::from(netmask))
}

/// Errors returned while applying policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyApplyError {
    Tun(NetworkPolicyError),
    Route {
        source: NetworkPolicyError,
        tun_revert_errors: Vec<NetworkPolicyError>,
    },
    Dns {
        source: DnsPolicyError,
        route_revert_errors: Vec<NetworkPolicyError>,
        tun_revert_errors: Vec<NetworkPolicyError>,
    },
}

impl fmt::Display for PolicyApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tun(source) => write!(f, "failed to apply TUN policy: {source}"),
            Self::Route {
                source,
                tun_revert_errors,
            } => write!(
                f,
                "failed to apply route policy: {source}; TUN rollback errors: {}",
                tun_revert_errors.len()
            ),
            Self::Dns {
                source,
                route_revert_errors,
                tun_revert_errors,
            } => write!(
                f,
                "failed to apply DNS policy: {source}; route rollback errors: {}; TUN rollback errors: {}",
                route_revert_errors.len(),
                tun_revert_errors.len()
            ),
        }
    }
}

impl std::error::Error for PolicyApplyError {}

/// Best-effort revert errors grouped by subsystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRevertErrors {
    pub dns: Vec<DnsPolicyError>,
    pub routes: Vec<NetworkPolicyError>,
    pub tun: Vec<NetworkPolicyError>,
}

impl PolicyRevertErrors {
    pub fn is_empty(&self) -> bool {
        self.dns.is_empty() && self.routes.is_empty() && self.tun.is_empty()
    }
}

impl fmt::Display for PolicyRevertErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "policy revert had {} DNS errors, {} route errors, and {} TUN errors",
            self.dns.len(),
            self.routes.len(),
            self.tun.len()
        )
    }
}

impl std::error::Error for PolicyRevertErrors {}

/// Apply TUN, route, then DNS policy.
///
/// Route failure rolls back TUN. DNS failure rolls back routes and then TUN.
pub fn apply_policy_with<N, D>(
    net_backend: &N,
    dns_runner: &mut D,
    plan: &PolicyPlan,
) -> Result<AppliedPolicyState, PolicyApplyError>
where
    N: LinuxNetworkBackend,
    D: DnsCommandRunner,
{
    let tun = apply_tun_config_with(net_backend, &plan.tun).map_err(PolicyApplyError::Tun)?;

    let routes = match apply_network_route_plan_with(net_backend, &plan.routes) {
        Ok(routes) => routes,
        Err(source) => {
            let tun_revert_errors = revert_tun_config_with(net_backend, &tun);
            return Err(PolicyApplyError::Route {
                source,
                tun_revert_errors,
            });
        }
    };

    let dns = match apply_dns_command_plan_with(dns_runner, &plan.dns) {
        Ok(dns) => dns,
        Err(source) => {
            let route_revert_errors = revert_network_route_plan_with(net_backend, &routes);
            let tun_revert_errors = revert_tun_config_with(net_backend, &tun);
            return Err(PolicyApplyError::Dns {
                source,
                route_revert_errors,
                tun_revert_errors,
            });
        }
    };

    Ok(AppliedPolicyState { tun, routes, dns })
}

/// Revert DNS, routes, then TUN policy. Best effort.
pub fn revert_policy_with<N, D>(
    net_backend: &N,
    dns_runner: &mut D,
    state: &AppliedPolicyState,
) -> Result<(), PolicyRevertErrors>
where
    N: LinuxNetworkBackend,
    D: DnsCommandRunner,
{
    let errors = PolicyRevertErrors {
        dns: revert_dns_command_plan_with(dns_runner, &state.dns),
        routes: revert_network_route_plan_with(net_backend, &state.routes),
        tun: revert_tun_config_with(net_backend, &state.tun),
    };

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::net::Ipv4Addr;
    use std::rc::Rc;

    use oc_oxide_dns::{DnsCommand, DnsCommandRunner, DnsMode, DnsPolicyError};
    use oc_oxide_net::{
        DefaultRouteSnapshot, LinuxNetworkBackend, NetworkPolicy, NetworkPolicyError, PlannedRoute,
        RouteMode, RouteReason, RouteSnapshot,
    };

    use super::{apply_policy_with, revert_policy_with, PolicyApplyError, PolicyPlan, CRATE_ROLE};

    #[test]
    fn documents_policy_role() {
        assert!(CRATE_ROLE.contains("policy"));
    }

    #[test]
    fn builds_policy_plan_from_copied_tunnel_input() {
        let default_route = sample_default_route();
        let route_policy =
            NetworkPolicy::new(RouteMode::Split).with_local_bypass_cidrs(vec![local_bypass()]);

        let plan = super::build_policy_plan_from_tunnel_input(
            &sample_tunnel_input(),
            &default_route,
            &route_policy,
            DnsMode::Split,
        )
        .unwrap();

        assert_eq!(plan.tun.ifname, "tun0");
        assert_eq!(plan.tun.address, Some(Ipv4Addr::new(198, 51, 100, 24)));
        assert_eq!(plan.tun.prefix_len, Some(24));
        assert_eq!(plan.tun.mtu, Some(1200));
        assert_eq!(plan.routes.routes.len(), 3);
        assert_eq!(plan.dns.apply.len(), 2);
    }

    #[test]
    fn builds_policy_plan_with_profile_company_resources() {
        let default_route = sample_default_route();
        let route_policy = NetworkPolicy::new(RouteMode::Split)
            .with_company_routes(vec!["203.0.113.0/25".parse().unwrap()])
            .with_local_bypass_cidrs(vec![local_bypass()]);

        let plan = super::build_policy_plan_from_tunnel_input_with_company_domains(
            &sample_tunnel_input(),
            &default_route,
            &route_policy,
            DnsMode::Split,
            ["github.example.test"],
        )
        .unwrap();

        let company_routes = plan.routes.routes_for(RouteReason::ProfileCompanyRoute);
        assert_eq!(company_routes.len(), 1);
        assert_eq!(company_routes[0].destination.to_string(), "203.0.113.0/25");
        assert_eq!(company_routes[0].dev, "tun0");
        assert_eq!(
            plan.dns.apply[1].args,
            vec![
                "domain",
                "tun0",
                "corp.example.test",
                "~corp.example.test",
                "~github.example.test",
            ]
        );
    }

    #[test]
    fn rejects_missing_gateway_when_routes_are_enabled() {
        let mut input = sample_tunnel_input();
        input.gateway_addr = None;

        let err = super::build_policy_plan_from_tunnel_input(
            &input,
            &sample_default_route(),
            &NetworkPolicy::new(RouteMode::Split),
            DnsMode::Split,
        )
        .unwrap_err();

        assert_eq!(err, super::PolicyPlanBuildError::MissingVpnGateway);
    }

    #[test]
    fn rejects_non_contiguous_tunnel_netmask() {
        let mut input = sample_tunnel_input();
        input.netmask = Some("255.0.255.0".to_owned());

        let err = super::build_tun_config_from_tunnel_input(&input).unwrap_err();

        assert_eq!(
            err,
            super::PolicyPlanBuildError::NonContiguousNetmask {
                value: "255.0.255.0".to_owned()
            }
        );
    }

    #[test]
    fn applies_and_reverts_policy_in_dependency_order() {
        let net = RecordingNetBackend::default();
        let mut dns = RecordingDnsRunner::default();
        let plan = sample_policy_plan();

        let applied = apply_policy_with(&net, &mut dns, &plan).unwrap();
        revert_policy_with(&net, &mut dns, &applied).unwrap();

        assert_eq!(
            net.operations.borrow().as_slice(),
            [
                "addr:replace:tun0:198.51.100.24/24",
                "link:mtu:tun0:1200",
                "link:up:tun0",
                "route:replace:VpnGatewayPin",
                "route:replace:VpnInternalNetwork",
                "route:del:VpnInternalNetwork",
                "route:del:VpnGatewayPin",
                "addr:del:tun0:198.51.100.24/24",
                "link:down:tun0",
            ]
        );
        assert_eq!(
            dns.operations,
            [
                "dns:apply:SetServers",
                "dns:apply:SetDomains",
                "dns:revert:RevertInterface",
            ]
        );
    }

    #[test]
    fn rolls_back_tun_after_route_apply_failure() {
        let net = RecordingNetBackend {
            fail_on_operation: Some("route:replace:VpnInternalNetwork".to_owned()),
            ..RecordingNetBackend::default()
        };
        let mut dns = RecordingDnsRunner::default();

        let err = apply_policy_with(&net, &mut dns, &sample_policy_plan()).unwrap_err();

        assert!(matches!(err, PolicyApplyError::Route { .. }));
        assert_eq!(
            net.operations.borrow().as_slice(),
            [
                "addr:replace:tun0:198.51.100.24/24",
                "link:mtu:tun0:1200",
                "link:up:tun0",
                "route:replace:VpnGatewayPin",
                "route:replace:VpnInternalNetwork",
                "route:del:VpnGatewayPin",
                "addr:del:tun0:198.51.100.24/24",
                "link:down:tun0",
            ]
        );
        assert!(dns.operations.is_empty());
    }

    #[test]
    fn rolls_back_routes_and_tun_after_dns_apply_failure() {
        let net = RecordingNetBackend::default();
        let mut dns = RecordingDnsRunner {
            fail_on_operation: Some("dns:apply:SetDomains".to_owned()),
            ..RecordingDnsRunner::default()
        };

        let err = apply_policy_with(&net, &mut dns, &sample_policy_plan()).unwrap_err();

        assert!(matches!(err, PolicyApplyError::Dns { .. }));
        assert_eq!(
            net.operations.borrow().as_slice(),
            [
                "addr:replace:tun0:198.51.100.24/24",
                "link:mtu:tun0:1200",
                "link:up:tun0",
                "route:replace:VpnGatewayPin",
                "route:replace:VpnInternalNetwork",
                "route:del:VpnInternalNetwork",
                "route:del:VpnGatewayPin",
                "addr:del:tun0:198.51.100.24/24",
                "link:down:tun0",
            ]
        );
        assert_eq!(
            dns.operations,
            [
                "dns:apply:SetServers",
                "dns:apply:SetDomains",
                "dns:revert:RevertInterface",
            ]
        );
    }

    #[test]
    fn reverts_dns_before_routes_and_tun_in_global_order() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let net = OrderedNetBackend::new(Rc::clone(&log));
        let mut dns = OrderedDnsRunner::new(Rc::clone(&log));

        let applied = apply_policy_with(&net, &mut dns, &sample_policy_plan()).unwrap();
        revert_policy_with(&net, &mut dns, &applied).unwrap();

        assert_eq!(
            log.borrow().as_slice(),
            [
                "net:addr:replace:tun0:198.51.100.24/24",
                "net:link:mtu:tun0:1200",
                "net:link:up:tun0",
                "net:route:replace:VpnGatewayPin",
                "net:route:replace:VpnInternalNetwork",
                "dns:apply:SetServers",
                "dns:apply:SetDomains",
                "dns:revert:RevertInterface",
                "net:route:del:VpnInternalNetwork",
                "net:route:del:VpnGatewayPin",
                "net:addr:del:tun0:198.51.100.24/24",
                "net:link:down:tun0",
            ]
        );
    }

    #[test]
    fn dns_apply_failure_reverts_dns_partials_then_routes_then_tun() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let net = OrderedNetBackend::new(Rc::clone(&log));
        let mut dns = OrderedDnsRunner {
            log: Rc::clone(&log),
            fail_on_operation: Some("dns:apply:SetDomains".to_owned()),
        };

        let err = apply_policy_with(&net, &mut dns, &sample_policy_plan()).unwrap_err();

        assert!(matches!(err, PolicyApplyError::Dns { .. }));
        assert_eq!(
            log.borrow().as_slice(),
            [
                "net:addr:replace:tun0:198.51.100.24/24",
                "net:link:mtu:tun0:1200",
                "net:link:up:tun0",
                "net:route:replace:VpnGatewayPin",
                "net:route:replace:VpnInternalNetwork",
                "dns:apply:SetServers",
                "dns:apply:SetDomains",
                "dns:revert:RevertInterface",
                "net:route:del:VpnInternalNetwork",
                "net:route:del:VpnGatewayPin",
                "net:addr:del:tun0:198.51.100.24/24",
                "net:link:down:tun0",
            ]
        );
    }

    #[test]
    fn full_policy_blocks_ipv6_default_before_dns_apply() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let net = OrderedNetBackend::new(Rc::clone(&log));
        let mut dns = OrderedDnsRunner::new(Rc::clone(&log));
        let plan = super::build_policy_plan_from_tunnel_input(
            &sample_tunnel_input(),
            &sample_default_route(),
            &NetworkPolicy::new(RouteMode::Full),
            DnsMode::Full,
        )
        .unwrap();

        let applied = apply_policy_with(&net, &mut dns, &plan).unwrap();
        revert_policy_with(&net, &mut dns, &applied).unwrap();

        assert_eq!(
            log.borrow().as_slice(),
            [
                "net:addr:replace:tun0:198.51.100.24/24",
                "net:link:mtu:tun0:1200",
                "net:link:up:tun0",
                "net:route:replace:VpnGatewayPin",
                "net:route:replace:VpnInternalNetwork",
                "net:route:replace:VpnDefaultRoute",
                "net:route6:block:exists",
                "net:route6:block:add",
                "dns:apply:SetServers",
                "dns:apply:SetDomains",
                "dns:revert:RevertInterface",
                "net:route6:block:del",
                "net:route:del:VpnDefaultRoute",
                "net:route:del:VpnInternalNetwork",
                "net:route:del:VpnGatewayPin",
                "net:addr:del:tun0:198.51.100.24/24",
                "net:link:down:tun0",
            ]
        );
    }

    fn sample_policy_plan() -> PolicyPlan {
        super::build_policy_plan_from_tunnel_input(
            &sample_tunnel_input(),
            &sample_default_route(),
            &NetworkPolicy::new(RouteMode::Split),
            DnsMode::Split,
        )
        .unwrap()
    }

    fn sample_tunnel_input() -> super::TunnelPolicyInput {
        super::TunnelPolicyInput {
            ifname: "tun0".to_owned(),
            address: Some("198.51.100.24".to_owned()),
            netmask: Some("255.255.255.0".to_owned()),
            mtu: 1200,
            dns_servers: vec!["192.0.2.53".to_owned(), "198.51.100.53".to_owned()],
            default_domain: Some("corp.example.test".to_owned()),
            split_dns: Vec::new(),
            split_includes: Vec::new(),
            split_excludes: Vec::new(),
            gateway_addr: Some("203.0.113.10".to_owned()),
        }
    }

    fn sample_default_route() -> DefaultRouteSnapshot {
        DefaultRouteSnapshot::new(Ipv4Addr::new(192, 0, 2, 1), "eno1").unwrap()
    }

    fn local_bypass() -> oc_oxide_net::Ipv4Cidr {
        "198.18.0.0/15".parse().unwrap()
    }

    #[derive(Default)]
    struct RecordingNetBackend {
        operations: RefCell<Vec<String>>,
        fail_on_operation: Option<String>,
    }

    impl RecordingNetBackend {
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

    impl LinuxNetworkBackend for RecordingNetBackend {
        fn default_route(&self) -> Result<DefaultRouteSnapshot, NetworkPolicyError> {
            DefaultRouteSnapshot::new(Ipv4Addr::new(192, 0, 2, 1), "eno1")
        }

        fn link_exists(&self, _ifname: &str) -> Result<bool, NetworkPolicyError> {
            Ok(true)
        }

        fn interface_ipv4_cidrs(
            &self,
            _ifname: &str,
        ) -> Result<Vec<oc_oxide_net::Ipv4Cidr>, NetworkPolicyError> {
            Ok(Vec::new())
        }

        fn route_snapshot(
            &self,
            _destination: oc_oxide_net::Ipv4Cidr,
        ) -> Result<Option<RouteSnapshot>, NetworkPolicyError> {
            Ok(None)
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
            self.record(format!("route:restore:{}", route.destination))
        }

        fn delete_route(&self, route: &PlannedRoute) -> Result<(), NetworkPolicyError> {
            self.record(format!("route:del:{:?}", route.reason))
        }

        fn ipv6_default_route_block_exists(&self) -> Result<bool, NetworkPolicyError> {
            self.record("route6:block:exists".to_owned())?;
            Ok(false)
        }

        fn block_ipv6_default_route(&self) -> Result<(), NetworkPolicyError> {
            self.record("route6:block:add".to_owned())
        }

        fn unblock_ipv6_default_route(&self) -> Result<(), NetworkPolicyError> {
            self.record("route6:block:del".to_owned())
        }
    }

    struct OrderedNetBackend {
        log: Rc<RefCell<Vec<String>>>,
    }

    impl OrderedNetBackend {
        fn new(log: Rc<RefCell<Vec<String>>>) -> Self {
            Self { log }
        }

        fn record(&self, operation: String) {
            self.log.borrow_mut().push(operation);
        }
    }

    impl LinuxNetworkBackend for OrderedNetBackend {
        fn default_route(&self) -> Result<DefaultRouteSnapshot, NetworkPolicyError> {
            DefaultRouteSnapshot::new(Ipv4Addr::new(192, 0, 2, 1), "eno1")
        }

        fn link_exists(&self, _ifname: &str) -> Result<bool, NetworkPolicyError> {
            Ok(true)
        }

        fn interface_ipv4_cidrs(
            &self,
            _ifname: &str,
        ) -> Result<Vec<oc_oxide_net::Ipv4Cidr>, NetworkPolicyError> {
            Ok(Vec::new())
        }

        fn route_snapshot(
            &self,
            _destination: oc_oxide_net::Ipv4Cidr,
        ) -> Result<Option<RouteSnapshot>, NetworkPolicyError> {
            Ok(None)
        }

        fn replace_ipv4_address(
            &self,
            ifname: &str,
            address: Ipv4Addr,
            prefix_len: u8,
        ) -> Result<(), NetworkPolicyError> {
            self.record(format!("net:addr:replace:{ifname}:{address}/{prefix_len}"));
            Ok(())
        }

        fn delete_ipv4_address(
            &self,
            ifname: &str,
            address: Ipv4Addr,
            prefix_len: u8,
        ) -> Result<(), NetworkPolicyError> {
            self.record(format!("net:addr:del:{ifname}:{address}/{prefix_len}"));
            Ok(())
        }

        fn set_link_mtu(&self, ifname: &str, mtu: u32) -> Result<(), NetworkPolicyError> {
            self.record(format!("net:link:mtu:{ifname}:{mtu}"));
            Ok(())
        }

        fn set_link_up(&self, ifname: &str) -> Result<(), NetworkPolicyError> {
            self.record(format!("net:link:up:{ifname}"));
            Ok(())
        }

        fn set_link_down(&self, ifname: &str) -> Result<(), NetworkPolicyError> {
            self.record(format!("net:link:down:{ifname}"));
            Ok(())
        }

        fn delete_link_if_exists(&self, ifname: &str) -> Result<bool, NetworkPolicyError> {
            self.record(format!("net:link:del:{ifname}"));
            Ok(true)
        }

        fn replace_route(&self, route: &PlannedRoute) -> Result<(), NetworkPolicyError> {
            self.record(format!("net:route:replace:{:?}", route.reason));
            Ok(())
        }

        fn restore_route(&self, route: &RouteSnapshot) -> Result<(), NetworkPolicyError> {
            self.record(format!("net:route:restore:{}", route.destination));
            Ok(())
        }

        fn delete_route(&self, route: &PlannedRoute) -> Result<(), NetworkPolicyError> {
            self.record(format!("net:route:del:{:?}", route.reason));
            Ok(())
        }

        fn ipv6_default_route_block_exists(&self) -> Result<bool, NetworkPolicyError> {
            self.record("net:route6:block:exists".to_owned());
            Ok(false)
        }

        fn block_ipv6_default_route(&self) -> Result<(), NetworkPolicyError> {
            self.record("net:route6:block:add".to_owned());
            Ok(())
        }

        fn unblock_ipv6_default_route(&self) -> Result<(), NetworkPolicyError> {
            self.record("net:route6:block:del".to_owned());
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingDnsRunner {
        operations: Vec<&'static str>,
        fail_on_operation: Option<String>,
    }

    impl DnsCommandRunner for RecordingDnsRunner {
        fn run(&mut self, command: &DnsCommand) -> Result<(), DnsPolicyError> {
            let phase = match command.reason {
                oc_oxide_dns::DnsCommandReason::RevertInterface => "revert",
                _ => "apply",
            };
            let operation = match command.reason {
                oc_oxide_dns::DnsCommandReason::SetServers => "dns:apply:SetServers",
                oc_oxide_dns::DnsCommandReason::SetDomains => "dns:apply:SetDomains",
                oc_oxide_dns::DnsCommandReason::RevertInterface => "dns:revert:RevertInterface",
            };
            self.operations.push(operation);

            if self.fail_on_operation.as_deref() == Some(operation) {
                return Err(DnsPolicyError::CommandFailed {
                    operation: format!("{phase}:{:?}", command.reason),
                    detail: "injected failure".to_owned(),
                });
            }

            Ok(())
        }
    }

    struct OrderedDnsRunner {
        log: Rc<RefCell<Vec<String>>>,
        fail_on_operation: Option<String>,
    }

    impl OrderedDnsRunner {
        fn new(log: Rc<RefCell<Vec<String>>>) -> Self {
            Self {
                log,
                fail_on_operation: None,
            }
        }
    }

    impl DnsCommandRunner for OrderedDnsRunner {
        fn run(&mut self, command: &DnsCommand) -> Result<(), DnsPolicyError> {
            let phase = match command.reason {
                oc_oxide_dns::DnsCommandReason::SetServers
                | oc_oxide_dns::DnsCommandReason::SetDomains => "apply",
                oc_oxide_dns::DnsCommandReason::RevertInterface => "revert",
            };
            let operation = format!("dns:{phase}:{:?}", command.reason);
            self.log.borrow_mut().push(operation.clone());

            if self.fail_on_operation.as_deref() == Some(operation.as_str()) {
                return Err(DnsPolicyError::CommandFailed {
                    operation,
                    detail: "injected failure".to_owned(),
                });
            }

            Ok(())
        }
    }
}
