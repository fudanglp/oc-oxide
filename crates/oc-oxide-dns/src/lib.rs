//! DNS apply and revert policy.
//!
//! This crate will apply server-pushed DNS using system-native backends where
//! practical, starting with systemd-resolved on Linux.

use std::fmt;
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;

/// Human-readable crate role used by workspace smoke tests.
pub const CRATE_ROLE: &str = "DNS apply and revert policy";

/// DNS routing mode for a VPN session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsMode {
    Split,
    Full,
    Off,
}

impl Default for DnsMode {
    fn default() -> Self {
        Self::Split
    }
}

impl fmt::Display for DnsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Split => f.write_str("split"),
            Self::Full => f.write_str("full"),
            Self::Off => f.write_str("off"),
        }
    }
}

impl FromStr for DnsMode {
    type Err = DnsPolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "split" => Ok(Self::Split),
            "full" => Ok(Self::Full),
            "off" => Ok(Self::Off),
            _ => Err(DnsPolicyError::InvalidDnsMode {
                value: value.to_owned(),
            }),
        }
    }
}

/// DNS settings copied from VPN state and local policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSettings {
    pub ifname: String,
    pub servers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
    pub routing_domains: Vec<String>,
    pub mode: DnsMode,
}

impl DnsSettings {
    /// Create DNS settings for a tunnel interface.
    pub fn new(
        ifname: impl Into<String>,
        servers: Vec<IpAddr>,
        mode: DnsMode,
    ) -> Result<Self, DnsPolicyError> {
        Ok(Self {
            ifname: clean_dns_text("interface", ifname.into())?,
            servers,
            search_domains: Vec::new(),
            routing_domains: Vec::new(),
            mode,
        })
    }

    /// Add a non-secret search domain.
    pub fn with_search_domains<I, S>(mut self, domains: I) -> Result<Self, DnsPolicyError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.search_domains = clean_domains("search domain", domains)?;
        Ok(self)
    }

    /// Add split routing domains. These become `~domain` entries on Linux.
    pub fn with_routing_domains<I, S>(mut self, domains: I) -> Result<Self, DnsPolicyError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.routing_domains = clean_domains("routing domain", domains)?;
        Ok(self)
    }

    /// Build DNS settings from copied OpenConnect IP info parts.
    pub fn from_openconnect_parts<I, S, R, D>(
        ifname: impl Into<String>,
        servers: I,
        default_domain: Option<D>,
        split_domains: R,
        mode: DnsMode,
    ) -> Result<Self, DnsPolicyError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        R: IntoIterator<Item = D>,
        D: Into<String>,
    {
        Self::from_openconnect_parts_with_company_domains(
            ifname,
            servers,
            default_domain,
            split_domains,
            std::iter::empty::<String>(),
            mode,
        )
    }

    /// Build DNS settings from OpenConnect parts plus profile-declared company
    /// routing domains. Profile domains are not search domains.
    pub fn from_openconnect_parts_with_company_domains<I, S, R, D, C, CD>(
        ifname: impl Into<String>,
        servers: I,
        default_domain: Option<D>,
        split_domains: R,
        company_domains: C,
        mode: DnsMode,
    ) -> Result<Self, DnsPolicyError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        R: IntoIterator<Item = D>,
        D: Into<String>,
        C: IntoIterator<Item = CD>,
        CD: Into<String>,
    {
        if mode == DnsMode::Off {
            return Self::new(ifname, Vec::new(), mode);
        }

        let servers = parse_dns_servers(servers)?;
        let mut settings = Self::new(ifname, servers, mode)?;

        if let Some(default_domain) = default_domain {
            let default_domain = clean_dns_text("default domain", default_domain.into())?;
            push_domain_once(&mut settings.search_domains, default_domain.clone());
            if mode == DnsMode::Split {
                push_domain_once(&mut settings.routing_domains, default_domain);
            }
        }

        let split_domains = clean_domains("split DNS domain", split_domains)?;
        if mode == DnsMode::Split {
            for domain in split_domains {
                push_domain_once(&mut settings.routing_domains, domain);
            }
        }

        let company_domains = clean_domains("company DNS domain", company_domains)?;
        if mode == DnsMode::Split {
            for domain in company_domains {
                push_domain_once(&mut settings.routing_domains, domain);
            }
        }

        Ok(settings)
    }
}

/// Rendered DNS command for a platform backend to execute later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsCommand {
    pub program: &'static str,
    pub args: Vec<String>,
    pub reason: DnsCommandReason,
}

/// Why a DNS command exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsCommandReason {
    SetServers,
    SetDomains,
    RevertInterface,
}

/// Rendered DNS apply/revert commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsCommandPlan {
    pub apply: Vec<DnsCommand>,
    pub revert: Vec<DnsCommand>,
}

/// State returned after DNS commands have been applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedDnsState {
    pub revert: Vec<DnsCommand>,
}

/// Injectable DNS command runner for privileged backends and tests.
pub trait DnsCommandRunner {
    fn run(&mut self, command: &DnsCommand) -> Result<(), DnsPolicyError>;
}

/// systemd-resolved backend that executes rendered `resolvectl` commands.
#[derive(Debug, Default)]
pub struct SystemdResolvedCommandRunner;

impl SystemdResolvedCommandRunner {
    pub fn new() -> Self {
        Self
    }

    fn run_program(&mut self, program: &str, args: &[String]) -> Result<(), String> {
        let output = Command::new(program)
            .args(args)
            .output()
            .map_err(|err| err.to_string())?;

        if !output.status.success() {
            return Err(command_failure_detail(&output));
        }

        Ok(())
    }
}

impl DnsCommandRunner for SystemdResolvedCommandRunner {
    fn run(&mut self, command: &DnsCommand) -> Result<(), DnsPolicyError> {
        self.run_program(command.program, &command.args)
            .map_err(|detail| DnsPolicyError::CommandFailed {
                operation: format_dns_command(command.program, &command.args),
                detail,
            })
    }
}

/// Errors returned while building DNS policy plans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsPolicyError {
    CommandFailed { operation: String, detail: String },
    EmptyField { field: &'static str },
    InteriorNul { field: &'static str },
    InvalidDnsMode { value: String },
    InvalidServer { value: String },
    MissingServers,
}

impl fmt::Display for DnsPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandFailed { operation, detail } => {
                write!(f, "DNS command failed during {operation}: {detail}")
            }
            Self::EmptyField { field } => write!(f, "{field} must not be empty"),
            Self::InteriorNul { field } => write!(f, "{field} must not contain a NUL byte"),
            Self::InvalidDnsMode { value } => write!(f, "invalid DNS mode {value:?}"),
            Self::InvalidServer { value } => write!(f, "invalid DNS server {value:?}"),
            Self::MissingServers => write!(f, "DNS servers are required unless DNS mode is off"),
        }
    }
}

impl std::error::Error for DnsPolicyError {}

/// Render systemd-resolved `resolvectl` commands without executing them.
pub fn render_systemd_resolved_commands(
    settings: &DnsSettings,
) -> Result<DnsCommandPlan, DnsPolicyError> {
    if settings.mode == DnsMode::Off {
        return Ok(DnsCommandPlan {
            apply: Vec::new(),
            revert: Vec::new(),
        });
    }

    if settings.servers.is_empty() {
        return Err(DnsPolicyError::MissingServers);
    }

    let mut apply = Vec::new();
    let mut dns_args = vec!["dns".to_owned(), settings.ifname.clone()];
    dns_args.extend(settings.servers.iter().map(ToString::to_string));
    apply.push(DnsCommand {
        program: "resolvectl",
        args: dns_args,
        reason: DnsCommandReason::SetServers,
    });

    let mut domains = settings.search_domains.clone();
    match settings.mode {
        DnsMode::Split => {
            domains.extend(
                settings
                    .routing_domains
                    .iter()
                    .map(|domain| format!("~{domain}")),
            );
        }
        DnsMode::Full => domains.push("~.".to_owned()),
        DnsMode::Off => {}
    }

    if !domains.is_empty() {
        let mut domain_args = vec!["domain".to_owned(), settings.ifname.clone()];
        domain_args.extend(domains);
        apply.push(DnsCommand {
            program: "resolvectl",
            args: domain_args,
            reason: DnsCommandReason::SetDomains,
        });
    }

    Ok(DnsCommandPlan {
        apply,
        revert: vec![DnsCommand {
            program: "resolvectl",
            args: vec!["revert".to_owned(), settings.ifname.clone()],
            reason: DnsCommandReason::RevertInterface,
        }],
    })
}

/// Apply a rendered DNS command plan with an injected runner.
///
/// If an apply command fails, commands that already succeeded are reverted
/// before the original error is returned.
pub fn apply_dns_command_plan_with<R: DnsCommandRunner>(
    runner: &mut R,
    plan: &DnsCommandPlan,
) -> Result<AppliedDnsState, DnsPolicyError> {
    for (index, command) in plan.apply.iter().enumerate() {
        if let Err(err) = runner.run(command) {
            rollback_dns_if_needed(runner, plan, index);
            return Err(err);
        }
    }

    Ok(AppliedDnsState {
        revert: plan.revert.clone(),
    })
}

/// Revert previously applied DNS commands with an injected runner.
pub fn revert_dns_command_plan_with<R: DnsCommandRunner>(
    runner: &mut R,
    state: &AppliedDnsState,
) -> Vec<DnsPolicyError> {
    state
        .revert
        .iter()
        .filter_map(|command| runner.run(command).err())
        .collect()
}

/// Render a DNS backend command for diagnostics.
pub fn format_dns_command(program: &str, args: &[String]) -> String {
    std::iter::once(program.to_owned())
        .chain(args.iter().map(|arg| shell_word(arg)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn command_failure_detail(output: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    format!(
        "status={} stdout={} stderr={}",
        output.status,
        stdout.trim(),
        stderr.trim()
    )
}

fn shell_word(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "-_./:~".contains(ch))
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn clean_domains<I, S>(field: &'static str, domains: I) -> Result<Vec<String>, DnsPolicyError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    domains
        .into_iter()
        .map(|domain| clean_dns_text(field, domain.into()))
        .collect()
}

fn push_domain_once(domains: &mut Vec<String>, domain: String) {
    if !domains.iter().any(|existing| existing == &domain) {
        domains.push(domain);
    }
}

fn parse_dns_servers<I, S>(servers: I) -> Result<Vec<IpAddr>, DnsPolicyError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    servers
        .into_iter()
        .map(|server| {
            let value = server.as_ref().trim();
            if value.is_empty() {
                return Err(DnsPolicyError::EmptyField {
                    field: "DNS server",
                });
            }
            if value.contains('\0') {
                return Err(DnsPolicyError::InteriorNul {
                    field: "DNS server",
                });
            }
            value.parse().map_err(|_| DnsPolicyError::InvalidServer {
                value: value.to_owned(),
            })
        })
        .collect()
}

fn clean_dns_text(field: &'static str, value: String) -> Result<String, DnsPolicyError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(DnsPolicyError::EmptyField { field });
    }

    if value.contains('\0') {
        return Err(DnsPolicyError::InteriorNul { field });
    }

    Ok(value.to_owned())
}

fn rollback_dns_if_needed<R: DnsCommandRunner>(
    runner: &mut R,
    plan: &DnsCommandPlan,
    applied_count: usize,
) {
    if applied_count == 0 {
        return;
    }

    for command in &plan.revert {
        let _ = runner.run(command);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{
        apply_dns_command_plan_with, format_dns_command, render_systemd_resolved_commands,
        revert_dns_command_plan_with, DnsCommand, DnsCommandReason, DnsCommandRunner, DnsMode,
        DnsPolicyError, DnsSettings, CRATE_ROLE,
    };

    #[test]
    fn documents_dns_role() {
        assert!(CRATE_ROLE.contains("DNS"));
    }

    #[test]
    fn renders_split_dns_resolvectl_commands_without_executing_them() {
        let settings = DnsSettings::new(
            "tun0",
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53)),
            ],
            DnsMode::Split,
        )
        .unwrap()
        .with_search_domains(["corp.example.test"])
        .unwrap()
        .with_routing_domains(["corp.example.test"])
        .unwrap();

        let commands = render_systemd_resolved_commands(&settings).unwrap();

        assert_eq!(commands.apply.len(), 2);
        assert_eq!(commands.revert.len(), 1);
        assert_eq!(commands.apply[0].program, "resolvectl");
        assert_eq!(commands.apply[0].reason, DnsCommandReason::SetServers);
        assert_eq!(
            commands.apply[0].args,
            vec!["dns", "tun0", "192.0.2.53", "198.51.100.53"]
        );
        assert_eq!(commands.apply[1].reason, DnsCommandReason::SetDomains);
        assert_eq!(
            commands.apply[1].args,
            vec!["domain", "tun0", "corp.example.test", "~corp.example.test"]
        );
        assert_eq!(commands.revert[0].reason, DnsCommandReason::RevertInterface);
        assert_eq!(commands.revert[0].args, vec!["revert", "tun0"]);
    }

    #[test]
    fn parses_dns_modes_from_profile_text() {
        assert_eq!("split".parse::<DnsMode>().unwrap(), DnsMode::Split);
        assert_eq!("full".parse::<DnsMode>().unwrap(), DnsMode::Full);
        assert_eq!("off".parse::<DnsMode>().unwrap(), DnsMode::Off);
        assert_eq!(DnsMode::Split.to_string(), "split");
        assert_eq!(
            "invalid".parse::<DnsMode>().unwrap_err(),
            DnsPolicyError::InvalidDnsMode {
                value: "invalid".to_owned()
            }
        );
    }

    #[test]
    fn renders_full_dns_as_default_routing_domain() {
        let settings = DnsSettings::new(
            "tun0",
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))],
            DnsMode::Full,
        )
        .unwrap();

        let commands = render_systemd_resolved_commands(&settings).unwrap();

        assert_eq!(commands.apply.len(), 2);
        assert_eq!(commands.apply[1].args, vec!["domain", "tun0", "~."]);
    }

    #[test]
    fn renders_off_mode_as_noop_without_servers() {
        let settings = DnsSettings::new("tun0", Vec::new(), DnsMode::Off).unwrap();

        let commands = render_systemd_resolved_commands(&settings).unwrap();

        assert!(commands.apply.is_empty());
        assert!(commands.revert.is_empty());
    }

    #[test]
    fn builds_off_dns_settings_without_requiring_valid_openconnect_dns_parts() {
        let settings = DnsSettings::from_openconnect_parts(
            "tun0",
            ["not-a-server"],
            Some("corp\0.example.test"),
            ["bad\0split.example.test"],
            DnsMode::Off,
        )
        .unwrap();

        assert_eq!(settings.mode, DnsMode::Off);
        assert!(settings.servers.is_empty());
        assert!(settings.search_domains.is_empty());
        assert!(settings.routing_domains.is_empty());
    }

    #[test]
    fn builds_split_dns_settings_from_openconnect_parts() {
        let settings = DnsSettings::from_openconnect_parts(
            "tun0",
            ["192.0.2.53", "198.51.100.53"],
            Some("corp.example.test"),
            std::iter::empty::<&str>(),
            DnsMode::Split,
        )
        .unwrap();

        assert_eq!(
            settings.servers,
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53)),
            ]
        );
        assert_eq!(settings.search_domains, vec!["corp.example.test"]);
        assert_eq!(settings.routing_domains, vec!["corp.example.test"]);

        let commands = render_systemd_resolved_commands(&settings).unwrap();
        assert_eq!(
            commands.apply[1].args,
            vec!["domain", "tun0", "corp.example.test", "~corp.example.test"]
        );
    }

    #[test]
    fn builds_split_dns_settings_with_extra_split_domains() {
        let settings = DnsSettings::from_openconnect_parts(
            "tun0",
            ["192.0.2.53"],
            Some("corp.example.test"),
            ["eng.corp.example.test"],
            DnsMode::Split,
        )
        .unwrap();

        assert_eq!(
            settings.routing_domains,
            vec!["corp.example.test", "eng.corp.example.test"]
        );
    }

    #[test]
    fn builds_split_dns_settings_with_profile_company_domains_as_routing_only() {
        let settings = DnsSettings::from_openconnect_parts_with_company_domains(
            "tun0",
            ["192.0.2.53"],
            Some("corp.example.test"),
            ["eng.corp.example.test"],
            ["github.example.test"],
            DnsMode::Split,
        )
        .unwrap();

        assert_eq!(settings.search_domains, vec!["corp.example.test"]);
        assert_eq!(
            settings.routing_domains,
            vec![
                "corp.example.test",
                "eng.corp.example.test",
                "github.example.test"
            ]
        );

        let commands = render_systemd_resolved_commands(&settings).unwrap();
        assert_eq!(
            commands.apply[1].args,
            vec![
                "domain",
                "tun0",
                "corp.example.test",
                "~corp.example.test",
                "~eng.corp.example.test",
                "~github.example.test",
            ]
        );
    }

    #[test]
    fn full_dns_settings_keep_search_domain_without_split_routing_domains() {
        let settings = DnsSettings::from_openconnect_parts(
            "tun0",
            ["192.0.2.53"],
            Some("corp.example.test"),
            ["eng.corp.example.test"],
            DnsMode::Full,
        )
        .unwrap();

        assert_eq!(settings.search_domains, vec!["corp.example.test"]);
        assert!(settings.routing_domains.is_empty());
        let commands = render_systemd_resolved_commands(&settings).unwrap();
        assert_eq!(
            commands.apply[1].args,
            vec!["domain", "tun0", "corp.example.test", "~."]
        );
    }

    #[test]
    fn rejects_invalid_openconnect_dns_parts() {
        assert_eq!(
            DnsSettings::from_openconnect_parts(
                "tun0",
                ["not-an-ip"],
                Some("corp.example.test"),
                std::iter::empty::<&str>(),
                DnsMode::Split,
            )
            .unwrap_err(),
            DnsPolicyError::InvalidServer {
                value: "not-an-ip".to_owned()
            }
        );
        assert!(DnsSettings::from_openconnect_parts(
            "tun0",
            ["192.0.2.53"],
            Some("corp\0.example.test"),
            std::iter::empty::<&str>(),
            DnsMode::Split,
        )
        .is_err());
    }

    #[test]
    fn applies_and_reverts_dns_commands_with_injected_runner() {
        let commands = sample_dns_commands();
        let mut runner = RecordingDnsRunner::default();

        let applied = apply_dns_command_plan_with(&mut runner, &commands).unwrap();
        let revert_errors = revert_dns_command_plan_with(&mut runner, &applied);

        assert!(revert_errors.is_empty());
        assert_eq!(
            runner.operations,
            vec![
                "apply:SetServers",
                "apply:SetDomains",
                "revert:RevertInterface"
            ]
        );
    }

    #[test]
    fn formats_dns_backend_commands_for_diagnostics() {
        assert_eq!(
            format_dns_command(
                "resolvectl",
                &[
                    "domain".to_owned(),
                    "tun0".to_owned(),
                    "corp.example.test".to_owned(),
                    "~corp.example.test".to_owned(),
                ],
            ),
            "resolvectl domain tun0 corp.example.test ~corp.example.test"
        );
        assert_eq!(
            format_dns_command("resolvectl", &["domain with space".to_owned()]),
            "resolvectl 'domain with space'"
        );
    }

    #[test]
    fn rolls_back_dns_commands_after_apply_failure() {
        let commands = sample_dns_commands();
        let mut runner = RecordingDnsRunner {
            fail_on_operation: Some("apply:SetDomains".to_owned()),
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
        assert_eq!(
            runner.operations,
            vec![
                "apply:SetServers",
                "apply:SetDomains",
                "revert:RevertInterface"
            ]
        );
    }

    #[test]
    fn rejects_invalid_dns_settings() {
        assert!(DnsSettings::new(" ", Vec::new(), DnsMode::Split).is_err());
        assert!(DnsSettings::new("tu\0n0", Vec::new(), DnsMode::Split).is_err());
        assert!(DnsSettings::new("tun0", Vec::new(), DnsMode::Split)
            .and_then(|settings| settings.with_search_domains([" "]))
            .is_err());

        let settings = DnsSettings::new("tun0", Vec::new(), DnsMode::Split).unwrap();
        assert_eq!(
            render_systemd_resolved_commands(&settings).unwrap_err(),
            DnsPolicyError::MissingServers
        );
    }

    fn sample_dns_commands() -> super::DnsCommandPlan {
        let settings = DnsSettings::from_openconnect_parts(
            "tun0",
            ["192.0.2.53", "198.51.100.53"],
            Some("corp.example.test"),
            std::iter::empty::<&str>(),
            DnsMode::Split,
        )
        .unwrap();

        render_systemd_resolved_commands(&settings).unwrap()
    }

    #[derive(Default)]
    struct RecordingDnsRunner {
        operations: Vec<String>,
        fail_on_operation: Option<String>,
    }

    impl DnsCommandRunner for RecordingDnsRunner {
        fn run(&mut self, command: &DnsCommand) -> Result<(), DnsPolicyError> {
            let operation = command_operation(command);
            self.operations.push(operation.clone());

            if self.fail_on_operation.as_deref() == Some(operation.as_str()) {
                return Err(DnsPolicyError::CommandFailed {
                    operation,
                    detail: "injected failure".to_owned(),
                });
            }

            Ok(())
        }
    }

    fn command_operation(command: &DnsCommand) -> String {
        let phase = match command.reason {
            DnsCommandReason::RevertInterface => "revert",
            DnsCommandReason::SetServers | DnsCommandReason::SetDomains => "apply",
        };
        format!("{phase}:{:?}", command.reason)
    }
}
