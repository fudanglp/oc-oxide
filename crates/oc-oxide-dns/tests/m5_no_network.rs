use oc_oxide_dns::{
    apply_dns_command_plan_with, render_systemd_resolved_commands, revert_dns_command_plan_with,
    DnsCommand, DnsCommandReason, DnsCommandRunner, DnsMode, DnsPolicyError, DnsSettings,
};

#[test]
fn plans_applies_and_reverts_split_dns_without_system_changes() {
    let settings = DnsSettings::from_openconnect_parts(
        "tun0",
        ["192.0.2.53", "198.51.100.53"],
        Some("corp.example.test"),
        std::iter::empty::<&str>(),
        DnsMode::Split,
    )
    .unwrap();

    let commands = render_systemd_resolved_commands(&settings).unwrap();

    assert_eq!(commands.apply.len(), 2);
    assert_eq!(
        commands.apply[0].args,
        vec!["dns", "tun0", "192.0.2.53", "198.51.100.53"]
    );
    assert_eq!(
        commands.apply[1].args,
        vec!["domain", "tun0", "corp.example.test", "~corp.example.test"]
    );
    assert_eq!(commands.revert[0].args, vec!["revert", "tun0"]);

    let mut runner = RecordingDnsRunner::default();
    let applied = apply_dns_command_plan_with(&mut runner, &commands).unwrap();
    let revert_errors = revert_dns_command_plan_with(&mut runner, &applied);

    assert!(revert_errors.is_empty());
    assert_eq!(runner.applied, commands.apply);
    assert_eq!(runner.reverted, commands.revert);
}

#[test]
fn supports_full_and_off_dns_modes_without_system_changes() {
    let full = DnsSettings::from_openconnect_parts(
        "tun0",
        ["192.0.2.53"],
        Some("corp.example.test"),
        std::iter::empty::<&str>(),
        DnsMode::Full,
    )
    .unwrap();
    let full_commands = render_systemd_resolved_commands(&full).unwrap();
    assert_eq!(
        full_commands.apply[1].args,
        vec!["domain", "tun0", "corp.example.test", "~."]
    );

    let off = DnsSettings::from_openconnect_parts(
        "tun0",
        std::iter::empty::<&str>(),
        Some("corp.example.test"),
        std::iter::empty::<&str>(),
        DnsMode::Off,
    )
    .unwrap();
    let off_commands = render_systemd_resolved_commands(&off).unwrap();
    assert!(off_commands.apply.is_empty());
    assert!(off_commands.revert.is_empty());
}

#[test]
fn rolls_back_dns_after_injected_apply_failure() {
    let settings = DnsSettings::from_openconnect_parts(
        "tun0",
        ["192.0.2.53", "198.51.100.53"],
        Some("corp.example.test"),
        std::iter::empty::<&str>(),
        DnsMode::Split,
    )
    .unwrap();
    let commands = render_systemd_resolved_commands(&settings).unwrap();
    let mut runner = RecordingDnsRunner {
        fail_on_reason: Some(DnsCommandReason::SetDomains),
        ..RecordingDnsRunner::default()
    };

    let err = apply_dns_command_plan_with(&mut runner, &commands).unwrap_err();

    assert_eq!(
        err,
        DnsPolicyError::CommandFailed {
            operation: "apply:SetDomains".to_owned(),
            detail: "injected failure".to_owned(),
        }
    );
    assert_eq!(runner.applied.len(), 2);
    assert_eq!(runner.reverted.len(), 1);
    assert_eq!(runner.reverted[0].reason, DnsCommandReason::RevertInterface);
}

#[derive(Default)]
struct RecordingDnsRunner {
    applied: Vec<DnsCommand>,
    reverted: Vec<DnsCommand>,
    fail_on_reason: Option<DnsCommandReason>,
}

impl DnsCommandRunner for RecordingDnsRunner {
    fn run(&mut self, command: &DnsCommand) -> Result<(), DnsPolicyError> {
        match command.reason {
            DnsCommandReason::SetServers | DnsCommandReason::SetDomains => {
                self.applied.push(command.clone());
                if self.fail_on_reason == Some(command.reason) {
                    return Err(DnsPolicyError::CommandFailed {
                        operation: format!("apply:{:?}", command.reason),
                        detail: "injected failure".to_owned(),
                    });
                }
            }
            DnsCommandReason::RevertInterface => self.reverted.push(command.clone()),
        }

        Ok(())
    }
}
