use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures::TryStreamExt;
use rtnetlink::{
    new_connection,
    packet_route::{
        address::AddressAttribute,
        link::LinkAttribute,
        route::{RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteScope, RouteType},
    },
    AddressMessageBuilder, Error as NetlinkError, Handle, LinkUnspec, RouteMessageBuilder,
};

use crate::{
    clean_interface, DefaultRouteSnapshot, Ipv4Cidr, NetworkPolicyError, NetworkRoutePlan,
    PlannedRoute, RouteSnapshot,
};

/// Linux network backend used by the privileged policy apply layer.
pub trait LinuxNetworkBackend {
    fn default_route(&self) -> Result<DefaultRouteSnapshot, NetworkPolicyError>;
    fn link_exists(&self, ifname: &str) -> Result<bool, NetworkPolicyError>;
    fn interface_ipv4_cidrs(&self, ifname: &str) -> Result<Vec<Ipv4Cidr>, NetworkPolicyError>;
    fn route_snapshot(
        &self,
        destination: Ipv4Cidr,
    ) -> Result<Option<RouteSnapshot>, NetworkPolicyError>;
    fn replace_ipv4_address(
        &self,
        ifname: &str,
        address: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<(), NetworkPolicyError>;
    fn delete_ipv4_address(
        &self,
        ifname: &str,
        address: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<(), NetworkPolicyError>;
    fn set_link_mtu(&self, ifname: &str, mtu: u32) -> Result<(), NetworkPolicyError>;
    fn set_link_up(&self, ifname: &str) -> Result<(), NetworkPolicyError>;
    fn set_link_down(&self, ifname: &str) -> Result<(), NetworkPolicyError>;
    fn delete_link_if_exists(&self, ifname: &str) -> Result<bool, NetworkPolicyError>;
    fn replace_route(&self, route: &PlannedRoute) -> Result<(), NetworkPolicyError>;
    fn restore_route(&self, route: &RouteSnapshot) -> Result<(), NetworkPolicyError>;
    fn delete_route(&self, route: &PlannedRoute) -> Result<(), NetworkPolicyError>;
    fn ipv6_default_route_block_exists(&self) -> Result<bool, NetworkPolicyError>;
    fn block_ipv6_default_route(&self) -> Result<(), NetworkPolicyError>;
    fn unblock_ipv6_default_route(&self) -> Result<(), NetworkPolicyError>;
}

/// TUN interface configuration to apply after libopenconnect creates the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
    pub ifname: String,
    pub address: Option<Ipv4Addr>,
    pub prefix_len: Option<u8>,
    pub mtu: Option<u32>,
}

impl TunConfig {
    pub fn new(ifname: impl Into<String>) -> Result<Self, NetworkPolicyError> {
        Ok(Self {
            ifname: clean_interface(ifname.into())?,
            address: None,
            prefix_len: None,
            mtu: None,
        })
    }

    pub fn with_ipv4_address(
        mut self,
        address: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<Self, NetworkPolicyError> {
        if prefix_len > 32 {
            return Err(NetworkPolicyError::InvalidPrefixLength { prefix_len });
        }
        self.address = Some(address);
        self.prefix_len = Some(prefix_len);
        Ok(self)
    }

    pub fn with_mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    pub fn step_count(&self) -> usize {
        1 + usize::from(self.address.is_some()) + usize::from(self.mtu.is_some())
    }
}

/// State needed to undo an applied TUN interface configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedTunConfig {
    pub ifname: String,
    pub address: Option<Ipv4Addr>,
    pub prefix_len: Option<u8>,
}

/// State needed to undo an applied route plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedNetworkRouteState {
    pub routes: Vec<AppliedRouteChange>,
    pub ipv6_default_route_block: Option<AppliedIpv6DefaultRouteBlock>,
}

/// One applied route and the exact revert action to perform later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedRouteChange {
    pub applied: PlannedRoute,
    pub revert: RouteRevertAction,
}

/// State needed to undo an IPv6 default-route block installed by oc-oxide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedIpv6DefaultRouteBlock {
    pub created: bool,
}

/// How to undo a route that oc-oxide replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteRevertAction {
    Restore(RouteSnapshot),
    Delete(PlannedRoute),
}

/// Synchronous rtnetlink-backed Linux backend.
pub struct LinuxNetlinkRunner {
    runtime: tokio::runtime::Runtime,
}

impl LinuxNetlinkRunner {
    pub fn new() -> Result<Self, NetworkPolicyError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .map_err(|err| backend_error("netlink runtime init", err))?;
        Ok(Self { runtime })
    }
}

impl LinuxNetworkBackend for LinuxNetlinkRunner {
    fn default_route(&self) -> Result<DefaultRouteSnapshot, NetworkPolicyError> {
        self.runtime.block_on(async move {
            let handle = netlink_handle()?;
            let route = RouteMessageBuilder::<Ipv4Addr>::new().build();
            let mut routes = handle.route().get(route).execute();
            let mut best: Option<(Ipv4Addr, u32, Option<u32>)> = None;

            while let Some(route) = routes
                .try_next()
                .await
                .map_err(|err| backend_error("netlink route get default", err))?
            {
                let Some((gateway, ifindex, priority)) = default_route_parts(&route) else {
                    continue;
                };

                if best
                    .as_ref()
                    .map(|(_, _, best_priority)| route_priority_less(priority, *best_priority))
                    .unwrap_or(true)
                {
                    best = Some((gateway, ifindex, priority));
                }
            }

            let (gateway, ifindex, _) = best.ok_or(NetworkPolicyError::DefaultRouteNotFound)?;
            let interface = link_name_by_index(&handle, ifindex).await?;
            DefaultRouteSnapshot::new(gateway, interface)
        })
    }

    fn link_exists(&self, ifname: &str) -> Result<bool, NetworkPolicyError> {
        self.runtime.block_on(async move {
            let ifname = clean_interface(ifname.to_owned())?;
            let handle = netlink_handle()?;
            maybe_link_index(&handle, &ifname)
                .await
                .map(|ifindex| ifindex.is_some())
        })
    }

    fn interface_ipv4_cidrs(&self, ifname: &str) -> Result<Vec<Ipv4Cidr>, NetworkPolicyError> {
        self.runtime.block_on(async move {
            let ifname = clean_interface(ifname.to_owned())?;
            let handle = netlink_handle()?;
            let ifindex = link_index(&handle, &ifname).await?;
            let mut addresses = handle
                .address()
                .get()
                .set_link_index_filter(ifindex)
                .execute();
            let mut cidrs = Vec::new();

            while let Some(address) = addresses
                .try_next()
                .await
                .map_err(|err| backend_error("netlink address get", err))?
            {
                let Some(cidr) = ipv4_cidr_from_address_message(&address)? else {
                    continue;
                };
                if !cidrs.contains(&cidr) {
                    cidrs.push(cidr);
                }
            }

            Ok(cidrs)
        })
    }

    fn route_snapshot(
        &self,
        destination: Ipv4Cidr,
    ) -> Result<Option<RouteSnapshot>, NetworkPolicyError> {
        self.runtime.block_on(async move {
            let handle = netlink_handle()?;
            let route = RouteMessageBuilder::<Ipv4Addr>::new().build();
            let mut routes = handle.route().get(route).execute();
            let mut best: Option<RouteSnapshot> = None;

            while let Some(route) = routes
                .try_next()
                .await
                .map_err(|err| backend_error("netlink route snapshot", err))?
            {
                let Some(snapshot) =
                    route_snapshot_from_message(&handle, &route, destination).await?
                else {
                    continue;
                };

                if best
                    .as_ref()
                    .map(|best| route_priority_less(snapshot.metric, best.metric))
                    .unwrap_or(true)
                {
                    best = Some(snapshot);
                }
            }

            Ok(best)
        })
    }

    fn replace_ipv4_address(
        &self,
        ifname: &str,
        address: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<(), NetworkPolicyError> {
        self.runtime.block_on(async move {
            let handle = netlink_handle()?;
            let ifindex = link_index(&handle, ifname).await?;
            handle
                .address()
                .add(ifindex, IpAddr::V4(address), prefix_len)
                .replace()
                .execute()
                .await
                .map_err(|err| backend_error("netlink addr replace", err))
        })
    }

    fn delete_ipv4_address(
        &self,
        ifname: &str,
        address: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<(), NetworkPolicyError> {
        self.runtime.block_on(async move {
            let handle = netlink_handle()?;
            let ifindex = link_index(&handle, ifname).await?;
            let message = AddressMessageBuilder::<Ipv4Addr>::new()
                .index(ifindex)
                .address(address, prefix_len)
                .build();
            handle
                .address()
                .del(message)
                .execute()
                .await
                .map_err(|err| backend_error("netlink addr del", err))
        })
    }

    fn set_link_mtu(&self, ifname: &str, mtu: u32) -> Result<(), NetworkPolicyError> {
        self.runtime.block_on(async move {
            let handle = netlink_handle()?;
            let ifindex = link_index(&handle, ifname).await?;
            handle
                .link()
                .set(LinkUnspec::new_with_index(ifindex).mtu(mtu).build())
                .execute()
                .await
                .map_err(|err| backend_error("netlink link set mtu", err))
        })
    }

    fn set_link_up(&self, ifname: &str) -> Result<(), NetworkPolicyError> {
        self.runtime.block_on(async move {
            let handle = netlink_handle()?;
            let ifindex = link_index(&handle, ifname).await?;
            handle
                .link()
                .set(LinkUnspec::new_with_index(ifindex).up().build())
                .execute()
                .await
                .map_err(|err| backend_error("netlink link set up", err))
        })
    }

    fn set_link_down(&self, ifname: &str) -> Result<(), NetworkPolicyError> {
        self.runtime.block_on(async move {
            let handle = netlink_handle()?;
            let ifindex = link_index(&handle, ifname).await?;
            handle
                .link()
                .set(LinkUnspec::new_with_index(ifindex).down().build())
                .execute()
                .await
                .map_err(|err| backend_error("netlink link set down", err))
        })
    }

    fn delete_link_if_exists(&self, ifname: &str) -> Result<bool, NetworkPolicyError> {
        self.runtime.block_on(async move {
            let handle = netlink_handle()?;
            let Some(ifindex) = maybe_link_index(&handle, ifname).await? else {
                return Ok(false);
            };
            handle
                .link()
                .del(ifindex)
                .execute()
                .await
                .map_err(|err| backend_error("netlink link del", err))?;
            Ok(true)
        })
    }

    fn replace_route(&self, route: &PlannedRoute) -> Result<(), NetworkPolicyError> {
        self.runtime.block_on(async move {
            let handle = netlink_handle()?;
            let message = planned_route_message(&handle, route).await?;
            handle
                .route()
                .add(message)
                .replace()
                .execute()
                .await
                .map_err(|err| backend_error("netlink route replace", err))
        })
    }

    fn restore_route(&self, route: &RouteSnapshot) -> Result<(), NetworkPolicyError> {
        self.runtime.block_on(async move {
            let handle = netlink_handle()?;
            let message = route_snapshot_message(&handle, route).await?;
            handle
                .route()
                .add(message)
                .replace()
                .execute()
                .await
                .map_err(|err| backend_error("netlink route restore", err))
        })
    }

    fn delete_route(&self, route: &PlannedRoute) -> Result<(), NetworkPolicyError> {
        self.runtime.block_on(async move {
            let handle = netlink_handle()?;
            let message = planned_route_message(&handle, route).await?;
            handle
                .route()
                .del(message)
                .execute()
                .await
                .map_err(|err| backend_error("netlink route del", err))
        })
    }

    fn ipv6_default_route_block_exists(&self) -> Result<bool, NetworkPolicyError> {
        self.runtime.block_on(async move {
            let handle = netlink_handle()?;
            let route = RouteMessageBuilder::<Ipv6Addr>::new().build();
            let mut routes = handle.route().get(route).execute();

            while let Some(route) = routes
                .try_next()
                .await
                .map_err(|err| backend_error("netlink ipv6 route snapshot", err))?
            {
                if is_oc_oxide_ipv6_default_route_block(&route) {
                    return Ok(true);
                }
            }

            Ok(false)
        })
    }

    fn block_ipv6_default_route(&self) -> Result<(), NetworkPolicyError> {
        self.runtime.block_on(async move {
            let handle = netlink_handle()?;
            handle
                .route()
                .add(ipv6_default_route_block_message())
                .replace()
                .execute()
                .await
                .map_err(|err| backend_error("netlink ipv6 default block", err))
        })
    }

    fn unblock_ipv6_default_route(&self) -> Result<(), NetworkPolicyError> {
        self.runtime.block_on(async move {
            let handle = netlink_handle()?;
            handle
                .route()
                .del(ipv6_default_route_block_message())
                .execute()
                .await
                .map_err(|err| backend_error("netlink ipv6 default unblock", err))
        })
    }
}

/// Apply TUN address, MTU, and link state through a Linux backend.
pub fn apply_tun_config_with<B: LinuxNetworkBackend>(
    backend: &B,
    config: &TunConfig,
) -> Result<AppliedTunConfig, NetworkPolicyError> {
    if let (Some(address), Some(prefix_len)) = (config.address, config.prefix_len) {
        backend.replace_ipv4_address(&config.ifname, address, prefix_len)?;
    }
    if let Some(mtu) = config.mtu {
        backend.set_link_mtu(&config.ifname, mtu)?;
    }
    backend.set_link_up(&config.ifname)?;

    Ok(AppliedTunConfig {
        ifname: config.ifname.clone(),
        address: config.address,
        prefix_len: config.prefix_len,
    })
}

/// Revert a previously applied TUN configuration. Best effort.
pub fn revert_tun_config_with<B: LinuxNetworkBackend>(
    backend: &B,
    state: &AppliedTunConfig,
) -> Vec<NetworkPolicyError> {
    let mut errors = Vec::new();

    if let (Some(address), Some(prefix_len)) = (state.address, state.prefix_len) {
        if let Err(err) = backend.delete_ipv4_address(&state.ifname, address, prefix_len) {
            errors.push(err);
        }
    }

    if let Err(err) = backend.set_link_down(&state.ifname) {
        errors.push(err);
    }

    errors
}

/// Apply planned routes through a Linux backend.
///
/// If one route fails, previously applied routes are removed in reverse order
/// before the original error is returned.
pub fn apply_network_route_plan_with<B: LinuxNetworkBackend>(
    backend: &B,
    plan: &NetworkRoutePlan,
) -> Result<AppliedNetworkRouteState, NetworkPolicyError> {
    let mut applied = Vec::new();

    for route in &plan.routes {
        let previous = match backend.route_snapshot(route.destination) {
            Ok(previous) => previous,
            Err(err) => {
                let state = AppliedNetworkRouteState {
                    routes: applied,
                    ipv6_default_route_block: None,
                };
                let _ = revert_network_route_plan_with(backend, &state);
                return Err(err);
            }
        };

        if let Err(err) = backend.replace_route(route) {
            let state = AppliedNetworkRouteState {
                routes: applied,
                ipv6_default_route_block: None,
            };
            let _ = revert_network_route_plan_with(backend, &state);
            return Err(err);
        }

        let revert = match previous {
            Some(previous) => RouteRevertAction::Restore(previous),
            None => RouteRevertAction::Delete(route.clone()),
        };
        applied.push(AppliedRouteChange {
            applied: route.clone(),
            revert,
        });
    }

    let ipv6_default_route_block = if plan.block_ipv6_default_route {
        let existed = match backend.ipv6_default_route_block_exists() {
            Ok(existed) => existed,
            Err(err) => {
                let state = AppliedNetworkRouteState {
                    routes: applied,
                    ipv6_default_route_block: None,
                };
                let _ = revert_network_route_plan_with(backend, &state);
                return Err(err);
            }
        };

        if !existed {
            if let Err(err) = backend.block_ipv6_default_route() {
                let state = AppliedNetworkRouteState {
                    routes: applied,
                    ipv6_default_route_block: None,
                };
                let _ = revert_network_route_plan_with(backend, &state);
                return Err(err);
            }
        }

        Some(AppliedIpv6DefaultRouteBlock { created: !existed })
    } else {
        None
    };

    Ok(AppliedNetworkRouteState {
        routes: applied,
        ipv6_default_route_block,
    })
}

/// Revert previously applied network routes. Best effort.
pub fn revert_network_route_plan_with<B: LinuxNetworkBackend>(
    backend: &B,
    state: &AppliedNetworkRouteState,
) -> Vec<NetworkPolicyError> {
    let mut errors = Vec::new();

    if state
        .ipv6_default_route_block
        .as_ref()
        .map(|block| block.created)
        .unwrap_or(false)
    {
        if let Err(err) = backend.unblock_ipv6_default_route() {
            errors.push(err);
        }
    }

    errors.extend(
        state
            .routes
            .iter()
            .rev()
            .filter_map(|route| match &route.revert {
                RouteRevertAction::Restore(previous) => backend.restore_route(previous).err(),
                RouteRevertAction::Delete(created) => backend.delete_route(created).err(),
            }),
    );

    errors
}

fn netlink_handle() -> Result<Handle, NetworkPolicyError> {
    let (connection, handle, _) =
        new_connection().map_err(|err| backend_error("netlink connect", err))?;
    tokio::spawn(connection);
    Ok(handle)
}

async fn link_index(handle: &Handle, ifname: &str) -> Result<u32, NetworkPolicyError> {
    maybe_link_index(handle, ifname)
        .await?
        .ok_or_else(|| backend_detail("netlink link get", format!("link {ifname:?} was not found")))
}

async fn maybe_link_index(
    handle: &Handle,
    ifname: &str,
) -> Result<Option<u32>, NetworkPolicyError> {
    let mut links = handle.link().get().match_name(ifname.to_owned()).execute();
    let link = match links.try_next().await {
        Ok(link) => link,
        Err(err) if is_netlink_no_such_device(&err) => None,
        Err(err) => return Err(backend_error("netlink link get", err)),
    };
    Ok(link.map(|link| link.header.index))
}

async fn link_name_by_index(handle: &Handle, ifindex: u32) -> Result<String, NetworkPolicyError> {
    let mut links = handle.link().get().match_index(ifindex).execute();
    let link = links
        .try_next()
        .await
        .map_err(|err| backend_error("netlink link get", err))?
        .ok_or_else(|| {
            backend_detail(
                "netlink link get",
                format!("link index {ifindex} was not found"),
            )
        })?;

    link.attributes
        .iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::IfName(name) => Some(name.clone()),
            _ => None,
        })
        .ok_or_else(|| {
            backend_detail(
                "netlink link get",
                format!("link index {ifindex} did not include an interface name"),
            )
        })
}

fn default_route_parts(route: &RouteMessage) -> Option<(Ipv4Addr, u32, Option<u32>)> {
    if route.header.destination_prefix_length != 0 || !is_main_route_table(route) {
        return None;
    }

    let mut gateway = None;
    let mut ifindex = None;
    let mut priority = None;

    for attribute in &route.attributes {
        match attribute {
            RouteAttribute::Gateway(RouteAddress::Inet(address)) => gateway = Some(*address),
            RouteAttribute::Oif(index) => ifindex = Some(*index),
            RouteAttribute::Priority(value) => priority = Some(*value),
            _ => {}
        }
    }

    Some((gateway?, ifindex?, priority))
}

fn ipv4_cidr_from_address_message(
    message: &rtnetlink::packet_route::address::AddressMessage,
) -> Result<Option<Ipv4Cidr>, NetworkPolicyError> {
    let local = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            AddressAttribute::Local(IpAddr::V4(address)) => Some(*address),
            _ => None,
        });
    let address_attr = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            AddressAttribute::Address(IpAddr::V4(address)) => Some(*address),
            _ => None,
        });
    let Some(address) = local.or(address_attr) else {
        return Ok(None);
    };

    ipv4_cidr_from_address_parts(address, message.header.prefix_len).map(Some)
}

fn ipv4_cidr_from_address_parts(
    address: Ipv4Addr,
    prefix_len: u8,
) -> Result<Ipv4Cidr, NetworkPolicyError> {
    if prefix_len > 32 {
        return Err(NetworkPolicyError::InvalidPrefixLength { prefix_len });
    }
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    Ipv4Cidr::new(Ipv4Addr::from(u32::from(address) & mask), prefix_len)
}

async fn route_snapshot_from_message(
    handle: &Handle,
    route: &RouteMessage,
    destination: Ipv4Cidr,
) -> Result<Option<RouteSnapshot>, NetworkPolicyError> {
    if route.header.destination_prefix_length != destination.prefix_len
        || !is_main_route_table(route)
    {
        return Ok(None);
    }

    let mut route_destination = None;
    let mut gateway = None;
    let mut ifindex = None;
    let mut priority = None;

    for attribute in &route.attributes {
        match attribute {
            RouteAttribute::Destination(RouteAddress::Inet(address)) => {
                route_destination = Some(*address)
            }
            RouteAttribute::Gateway(RouteAddress::Inet(address)) => gateway = Some(*address),
            RouteAttribute::Oif(index) => ifindex = Some(*index),
            RouteAttribute::Priority(value) => priority = Some(*value),
            _ => {}
        }
    }

    let route_destination = match route_destination {
        Some(route_destination) => route_destination,
        None if destination.prefix_len == 0 => Ipv4Addr::UNSPECIFIED,
        None => return Ok(None),
    };

    if route_destination != destination.address {
        return Ok(None);
    }

    let Some(ifindex) = ifindex else {
        return Ok(None);
    };
    let interface = link_name_by_index(handle, ifindex).await?;
    let mut snapshot = RouteSnapshot::new(destination, gateway, interface)?;
    if let Some(priority) = priority {
        snapshot = snapshot.with_metric(priority);
    }

    Ok(Some(snapshot))
}

fn is_main_route_table(route: &RouteMessage) -> bool {
    route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(table) => Some(*table),
            _ => None,
        })
        .unwrap_or(u32::from(route.header.table))
        == u32::from(RouteHeader::RT_TABLE_MAIN)
}

fn route_priority_less(candidate: Option<u32>, current: Option<u32>) -> bool {
    candidate.unwrap_or(u32::MAX) < current.unwrap_or(u32::MAX)
}

async fn planned_route_message(
    handle: &Handle,
    route: &PlannedRoute,
) -> Result<rtnetlink::packet_route::route::RouteMessage, NetworkPolicyError> {
    let ifindex = link_index(handle, &route.dev).await?;
    let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(route.destination.address, route.destination.prefix_len)
        .output_interface(ifindex);

    if let Some(gateway) = route.via {
        builder = builder.gateway(gateway);
    } else {
        builder = builder.scope(RouteScope::Link);
    }

    Ok(builder.build())
}

async fn route_snapshot_message(
    handle: &Handle,
    route: &RouteSnapshot,
) -> Result<rtnetlink::packet_route::route::RouteMessage, NetworkPolicyError> {
    let ifindex = link_index(handle, &route.dev).await?;
    let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(route.destination.address, route.destination.prefix_len)
        .output_interface(ifindex);

    if let Some(gateway) = route.via {
        builder = builder.gateway(gateway);
    } else {
        builder = builder.scope(RouteScope::Link);
    }

    if let Some(metric) = route.metric {
        builder = builder.priority(metric);
    }

    Ok(builder.build())
}

fn ipv6_default_route_block_message() -> rtnetlink::packet_route::route::RouteMessage {
    RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
        .kind(RouteType::Unreachable)
        .priority(1)
        .build()
}

fn is_oc_oxide_ipv6_default_route_block(route: &RouteMessage) -> bool {
    route.header.destination_prefix_length == 0
        && route.header.kind == RouteType::Unreachable
        && is_main_route_table(route)
        && route_metric(route) == Some(1)
}

fn route_metric(route: &RouteMessage) -> Option<u32> {
    route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Priority(value) => Some(*value),
            _ => None,
        })
}

fn backend_error(operation: &'static str, err: impl std::fmt::Display) -> NetworkPolicyError {
    backend_detail(operation, err.to_string())
}

fn backend_detail(operation: &'static str, detail: String) -> NetworkPolicyError {
    NetworkPolicyError::BackendFailed { operation, detail }
}

fn is_netlink_no_such_device(err: &NetlinkError) -> bool {
    match err {
        NetlinkError::NetlinkError(message) => {
            is_no_such_device_os_error(message.to_io().raw_os_error())
        }
        _ => false,
    }
}

fn is_no_such_device_os_error(raw_os_error: Option<i32>) -> bool {
    const ENODEV: i32 = 19;

    raw_os_error == Some(ENODEV)
}

#[cfg(test)]
mod tests {
    #[test]
    fn classifies_enodev_as_missing_link() {
        assert!(super::is_no_such_device_os_error(Some(19)));
    }

    #[test]
    fn keeps_other_os_errors_fatal() {
        assert!(!super::is_no_such_device_os_error(Some(1)));
        assert!(!super::is_no_such_device_os_error(None));
    }

    #[test]
    fn computes_connected_ipv4_cidr_from_interface_address() {
        assert_eq!(
            super::ipv4_cidr_from_address_parts("192.0.2.44".parse().unwrap(), 24)
                .unwrap()
                .to_string(),
            "192.0.2.0/24"
        );
        assert_eq!(
            super::ipv4_cidr_from_address_parts("198.51.100.8".parse().unwrap(), 32)
                .unwrap()
                .to_string(),
            "198.51.100.8/32"
        );
        assert_eq!(
            super::ipv4_cidr_from_address_parts("203.0.113.99".parse().unwrap(), 0)
                .unwrap()
                .to_string(),
            "0.0.0.0/0"
        );
        assert!(super::ipv4_cidr_from_address_parts("192.0.2.44".parse().unwrap(), 33).is_err());
    }
}
