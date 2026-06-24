use std::net::Ipv4Addr;

use oc_oxide_net::{
    apply_route_command_plan_with, build_network_route_plan, parse_linux_default_route,
    render_linux_ip_route_commands, revert_route_command_plan_with, DefaultRouteSnapshot, Ipv4Cidr,
    NetworkPolicy, NetworkPolicyError, RouteCommand, RouteCommandRunner, RouteMode, RouteReason,
    ServerPushedRoutes,
};

#[test]
fn plans_applies_and_reverts_m4_routes_without_network_or_system_changes() {
    let default_route = parse_linux_default_route(
        "default via 192.0.2.1 dev eno1 proto dhcp src 192.0.2.107 metric 100",
    )
    .unwrap();
    let pushed = ServerPushedRoutes::from_openconnect_parts(
        Some(Ipv4Addr::new(198, 51, 100, 0)),
        Some(24),
        std::iter::empty::<&str>(),
        ["203.0.113.10/32", "0.0.0.0/32"],
    )
    .unwrap();

    let plan = build_network_route_plan(
        &default_route,
        "tun0",
        Ipv4Addr::new(203, 0, 113, 10),
        &pushed,
        &NetworkPolicy::new(RouteMode::Split).with_local_bypass_cidrs(vec![local_bypass_cidr()]),
    )
    .unwrap();

    assert_eq!(plan.routes_for(RouteReason::VpnGatewayPin).len(), 1);
    assert_eq!(plan.routes_for(RouteReason::LocalBypassCidr).len(), 1);
    assert_eq!(
        plan.routes_for(RouteReason::LocalBypassCidr)[0].destination,
        local_bypass_cidr()
    );
    assert_eq!(plan.routes_for(RouteReason::VpnInternalNetwork).len(), 1);
    assert!(plan.routes_for(RouteReason::VpnSplitExclude).is_empty());

    let commands = render_linux_ip_route_commands(&plan);
    assert_eq!(commands.apply.len(), 3);
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
    assert!(!commands
        .apply
        .iter()
        .any(|command| command.args.contains(&"0.0.0.0/32".to_owned())));

    let mut runner = RecordingRouteRunner::default();
    let applied = apply_route_command_plan_with(&mut runner, &commands).unwrap();
    let revert_errors = revert_route_command_plan_with(&mut runner, &applied);

    assert!(revert_errors.is_empty());
    assert_eq!(runner.applied, commands.apply);
    assert_eq!(runner.reverted, commands.revert);
}

#[test]
fn rolls_back_m4_routes_after_injected_apply_failure() {
    let default_route = DefaultRouteSnapshot::new(Ipv4Addr::new(192, 0, 2, 1), "eno1").unwrap();
    let pushed =
        ServerPushedRoutes::new().with_internal_network("198.51.100.0/24".parse().unwrap());
    let plan = build_network_route_plan(
        &default_route,
        "tun0",
        Ipv4Addr::new(203, 0, 113, 10),
        &pushed,
        &NetworkPolicy::new(RouteMode::Split).with_local_bypass_cidrs(vec![local_bypass_cidr()]),
    )
    .unwrap();
    let commands = render_linux_ip_route_commands(&plan);
    let mut runner = RecordingRouteRunner {
        fail_on_reason: Some(RouteReason::VpnInternalNetwork),
        ..RecordingRouteRunner::default()
    };

    let err = apply_route_command_plan_with(&mut runner, &commands).unwrap_err();

    assert_eq!(
        err,
        NetworkPolicyError::CommandFailed {
            operation: "apply:VpnInternalNetwork".to_owned(),
            detail: "injected failure".to_owned(),
        }
    );
    assert_eq!(runner.applied.len(), 3);
    assert_eq!(runner.reverted.len(), 2);
    assert_eq!(runner.reverted[0].reason, RouteReason::LocalBypassCidr);
    assert_eq!(runner.reverted[1].reason, RouteReason::VpnGatewayPin);
}

#[derive(Default)]
struct RecordingRouteRunner {
    applied: Vec<RouteCommand>,
    reverted: Vec<RouteCommand>,
    fail_on_reason: Option<RouteReason>,
}

impl RouteCommandRunner for RecordingRouteRunner {
    fn run(&mut self, command: &RouteCommand) -> Result<(), NetworkPolicyError> {
        match command.args.get(1).map(String::as_str) {
            Some("replace") => {
                self.applied.push(command.clone());
                if self.fail_on_reason == Some(command.reason) {
                    return Err(NetworkPolicyError::CommandFailed {
                        operation: format!("apply:{:?}", command.reason),
                        detail: "injected failure".to_owned(),
                    });
                }
            }
            Some("del") => self.reverted.push(command.clone()),
            _ => {}
        }

        Ok(())
    }
}

fn local_bypass_cidr() -> Ipv4Cidr {
    "198.18.0.0/15".parse().unwrap()
}
