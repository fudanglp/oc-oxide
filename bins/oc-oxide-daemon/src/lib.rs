//! Privileged daemon state machine.
//!
//! This library keeps the command/state/event logic testable without starting
//! a socket listener, touching `libopenconnect`, or changing host networking.

use std::collections::BTreeMap;
use std::env;
#[cfg(unix)]
use std::ffi::CString;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::net::Ipv4Addr;
#[cfg(unix)]
use std::os::raw::c_char;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use oc_oxide_auth::{
    AuthAnswer, AuthChoice as TunnelAuthChoice, AuthError, AuthField, AuthFieldKind,
    AuthFormDecision, AuthFormHandler, AuthRequest, AuthResponse,
};
use oc_oxide_config::{parse_toml_vpn_profile, VpnProfile};
use oc_oxide_dns::{
    apply_dns_command_plan_with, revert_dns_command_plan_with, AppliedDnsState, DnsCommand,
    DnsCommandReason, DnsCommandRunner, DnsMode, SystemdResolvedCommandRunner,
};
use oc_oxide_ipc::{
    decode_command_line, decode_response_line, encode_event_line, encode_response_line,
    AuthChoice as IpcAuthChoice, AuthPrompt, AuthSubmission, DaemonState, DaemonStatus,
    DiagnosticsSnapshot, DisconnectReason, IpcCommand, IpcErrorResponse, IpcEvent,
    IpcProtocolError, IpcResponse, LogEntry, LogLevel, NetworkApplied, ProgressUpdate,
};
use oc_oxide_net::{
    apply_network_route_plan_with, apply_tun_config_with, revert_network_route_plan_with,
    revert_tun_config_with, AppliedNetworkRouteState, AppliedRouteChange, AppliedTunConfig,
    DefaultRouteSnapshot, Ipv4Cidr, LinuxNetlinkRunner, LinuxNetworkBackend, NetworkPolicy,
    PlannedRoute, RouteMode, RouteReason, RouteRevertAction, RouteSnapshot,
};
use oc_oxide_policy::{
    build_policy_plan_from_tunnel_input_with_company_domains, AppliedPolicyState, PolicyPlan,
    PolicyPlanBuildError, TunnelPolicyInput,
};
use oc_oxide_tunnel::{
    CancelHandle, IpInfoSnapshot, MainloopOutcome, OpenConnectSession, TunnelError, TunnelEvent,
    TunnelEventSink, TunnelState,
};

#[cfg(unix)]
unsafe extern "C" {
    fn chown(path: *const c_char, owner: u32, group: u32) -> i32;
    fn geteuid() -> u32;
}

/// Human-readable daemon role used by the binary and smoke tests.
pub const DAEMON_ROLE: &str = "oc-oxide-daemon: IPC state machine ready";
pub const DAEMON_MANAGED_TUN_IFNAME: &str = "ocx0";

/// Pure in-memory daemon core.
#[derive(Debug)]
pub struct DaemonCore {
    status: DaemonStatus,
    pending_auth_form: Option<String>,
    last_error: Option<IpcErrorResponse>,
    events: Vec<IpcEvent>,
    logs: Vec<LogEntry>,
}

/// Non-secret request passed from daemon state handling to a tunnel runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelConnectRequest {
    pub profile: String,
}

/// One lifecycle step emitted by a tunnel runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelLifecycleStep {
    Progress(ProgressUpdate),
    AuthPrompt(AuthPrompt),
    NetworkApplied(NetworkApplied),
    Connected {
        interface: String,
    },
    Disconnecting,
    NetworkReverted {
        dns_errors: usize,
        route_errors: usize,
        tun_errors: usize,
    },
    Disconnected {
        reason: DisconnectReason,
    },
}

/// Commands sent from the daemon/control side to a tunnel worker thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelWorkerCommand {
    Connect(TunnelConnectRequest),
    SubmitAuth(AuthResponse),
    Cancel,
    Disconnect,
}

/// Events sent from a tunnel worker thread back to the daemon/control side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelWorkerEvent {
    Lifecycle(TunnelLifecycleStep),
    Error(TunnelLifecycleError),
}

/// Injectable tunnel runner used by the daemon core.
pub trait TunnelLifecycleRunner {
    fn run(
        &mut self,
        request: TunnelConnectRequest,
    ) -> Result<Vec<TunnelLifecycleStep>, TunnelLifecycleError>;
}

/// Runnable tunnel worker body owned by a dedicated thread.
pub trait TunnelWorker: Send + 'static {
    fn run(
        self,
        commands: mpsc::Receiver<TunnelWorkerCommand>,
        events: mpsc::Sender<TunnelWorkerEvent>,
    );
}

/// Control handle for a dedicated tunnel worker thread.
pub struct TunnelWorkerHandle {
    commands: mpsc::Sender<TunnelWorkerCommand>,
    events: mpsc::Receiver<TunnelWorkerEvent>,
    join: Option<thread::JoinHandle<()>>,
}

/// Factory for daemon-owned tunnel worker threads.
pub trait TunnelWorkerFactory {
    fn spawn_worker(&mut self) -> TunnelWorkerHandle;

    fn import_profile(
        &mut self,
        _name: String,
        _profile: VpnProfile,
    ) -> Result<(), TunnelLifecycleError> {
        Err(TunnelLifecycleError::new(
            "profile_import_unsupported",
            "this daemon worker factory does not support imported profiles",
        ))
    }
}

/// Daemon control surface that owns one active tunnel worker.
///
/// `DaemonCore` remains a pure state/event mapper. This controller is the next
/// layer up: it accepts IPC commands, creates the tunnel worker on connect, and
/// forwards auth/cancel commands to the active worker.
pub struct DaemonWorkerController<F> {
    core: DaemonCore,
    worker_factory: F,
    active_worker: Option<TunnelWorkerHandle>,
}

/// Tunnel callback sink that forwards typed tunnel events to daemon worker events.
pub struct DaemonTunnelEventSink {
    events: mpsc::Sender<TunnelWorkerEvent>,
    next_auth_form: usize,
}

/// Resolves a non-secret profile name into the settings used by a tunnel worker.
pub trait VpnProfileResolver: Send + 'static {
    fn resolve_profile(&mut self, name: &str) -> Result<VpnProfile, TunnelLifecycleError>;
}

/// OpenConnect workflow body run on the dedicated tunnel worker thread.
pub trait OpenConnectWorkflow: Send + 'static {
    fn run(
        &mut self,
        profile: VpnProfile,
        commands: mpsc::Receiver<TunnelWorkerCommand>,
        events: mpsc::Sender<TunnelWorkerEvent>,
    ) -> Result<(), TunnelLifecycleError>;
}

/// Tunnel worker that resolves a profile and delegates to an OpenConnect workflow.
pub struct OpenConnectTunnelWorker<R, W> {
    profile_resolver: R,
    workflow: W,
}

/// Worker factory used by the privileged daemon binary.
#[derive(Debug, Clone)]
pub struct SystemOpenConnectWorkerFactory {
    profile_resolver: LocalProfileResolver,
    imported_profiles: BTreeMap<String, VpnProfile>,
}

/// Resolves daemon profiles imported over IPC before falling back to disk.
#[derive(Debug, Clone)]
pub struct ImportedProfileResolver {
    local: LocalProfileResolver,
    imported: BTreeMap<String, VpnProfile>,
}

/// Auth handler used on the tunnel thread to wait for daemon-submitted answers.
pub struct WorkerAuthHandler<'a> {
    commands: &'a mpsc::Receiver<TunnelWorkerCommand>,
}

struct ImmediateErrorWorker {
    error: TunnelLifecycleError,
}

/// Production OpenConnect workflow using libopenconnect plus injected policy backends.
pub struct SystemOpenConnectWorkflow<N, D, J = RecoveryJournalStore> {
    net_backend: N,
    dns_runner: D,
    recovery_journal_store: J,
    useragent: String,
    dtls_attempt_period_seconds: i32,
    reconnect_timeout_seconds: i32,
    reconnect_interval_seconds: i32,
}

struct WorkflowAuthHandler<'a> {
    responses: &'a mpsc::Receiver<AuthResponse>,
    cancel_requested: Arc<AtomicBool>,
    auth_cancelled: Arc<AtomicBool>,
    preferred_username: Option<String>,
    preferred_authgroup: Option<String>,
    authgroup_submitted: bool,
    pending_prefilled_answers: Vec<AuthAnswer>,
}

/// File-backed non-secret profile resolver for the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalProfileResolver {
    profile_dir: PathBuf,
}

/// Errors returned while loading local non-secret daemon profiles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalProfileError {
    MissingHome,
    InvalidName { name: String },
    Io { path: PathBuf, message: String },
    Profile { message: String },
}

/// Errors returned by the daemon JSON-line IPC server.
#[derive(Debug)]
pub enum DaemonIpcError {
    Io(io::Error),
    Protocol(IpcProtocolError),
    LockPoisoned,
    ExistingSocketPath { path: PathBuf },
    Unauthorized { message: String },
}

/// Non-secret tunnel lifecycle error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelLifecycleError {
    pub code: String,
    pub message: String,
}

/// Network policy planned for a daemon-managed tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonNetworkPlan {
    pub policy: PolicyPlan,
    pub applied: NetworkApplied,
}

pub const RECOVERY_JOURNAL_VERSION: u32 = 1;
pub const RECOVERY_JOURNAL_DEFAULT_ROOT: &str = "/run/oc-oxide";
pub const RECOVERY_JOURNAL_FILE_NAME: &str = "session.json";
const RECOVERY_JOURNAL_TMP_FILE_NAME: &str = "session.json.tmp";

/// Non-secret runtime journal used to recover network state after daemon crash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryJournal {
    pub version: u32,
    pub stage: RecoveryJournalStage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub ifname: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<RecoveryDnsJournal>,
    #[serde(default)]
    pub routes: Vec<RecoveryRouteChangeJournal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_default_route_block: Option<RecoveryIpv6DefaultRouteBlockJournal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tun: Option<RecoveryTunJournal>,
}

/// Last successfully journaled recovery stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryJournalStage {
    ApplyingTun,
    ApplyingRoutes,
    ApplyingDns,
    Connected,
    Reverting,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDnsJournal {
    pub revert: Vec<RecoveryDnsCommandJournal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDnsCommandJournal {
    pub program: String,
    pub args: Vec<String>,
    pub reason: RecoveryDnsCommandReasonJournal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryDnsCommandReasonJournal {
    SetServers,
    SetDomains,
    RevertInterface,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRouteChangeJournal {
    pub applied: RecoveryPlannedRouteJournal,
    pub revert: RecoveryRouteRevertJournal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPlannedRouteJournal {
    pub destination: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    pub dev: String,
    pub reason: RecoveryRouteReasonJournal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum RecoveryRouteRevertJournal {
    Restore {
        previous: RecoveryRouteSnapshotJournal,
    },
    Delete {
        created: RecoveryPlannedRouteJournal,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRouteSnapshotJournal {
    pub destination: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    pub dev: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRouteReasonJournal {
    VpnGatewayPin,
    DetectedLocalNetwork,
    LocalBypassCidr,
    VpnInternalNetwork,
    VpnSplitInclude,
    ProfileCompanyRoute,
    VpnSplitExclude,
    VpnDefaultRoute,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryIpv6DefaultRouteBlockJournal {
    pub created: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTunJournal {
    pub ifname: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_len: Option<u8>,
}

/// File-backed non-secret runtime journal store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryJournalStore {
    root: PathBuf,
}

/// Journal writer used by policy apply/revert code.
pub trait RecoveryJournalSink {
    fn load(&self) -> Result<Option<RecoveryJournal>, RecoveryJournalError> {
        Ok(None)
    }

    fn save(&self, journal: &RecoveryJournal) -> Result<(), RecoveryJournalError>;
    fn delete(&self) -> Result<(), RecoveryJournalError>;
}

/// Errors returned while reading or writing the crash recovery journal.
#[derive(Debug)]
pub enum RecoveryJournalError {
    Io { path: PathBuf, message: String },
    Json { path: PathBuf, message: String },
    UnsupportedVersion { version: u32 },
}

/// Summary of startup recovery work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartupRecoveryReport {
    pub journal_recovered: bool,
    pub stale_link_removed: bool,
}

/// Errors returned by daemon startup recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupRecoveryError {
    Journal {
        message: String,
    },
    InvalidJournal {
        message: String,
    },
    CleanupIncomplete {
        dns_errors: usize,
        route_errors: usize,
        tun_errors: usize,
        link_errors: usize,
    },
    StaleCleanup {
        message: String,
    },
}

/// Errors returned while bridging tunnel auth events to IPC.
#[derive(Debug)]
pub enum DaemonAuthBridgeError {
    Auth(AuthError),
}

/// Errors returned while planning daemon-owned route/DNS policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonNetworkPlanError {
    Policy(PolicyPlanBuildError),
}

impl fmt::Display for DaemonAuthBridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth(source) => write!(f, "auth bridge failed: {source}"),
        }
    }
}

impl std::error::Error for DaemonAuthBridgeError {}

impl From<AuthError> for DaemonAuthBridgeError {
    fn from(source: AuthError) -> Self {
        Self::Auth(source)
    }
}

impl fmt::Display for DaemonNetworkPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(source) => write!(f, "network policy planning failed: {source}"),
        }
    }
}

impl std::error::Error for DaemonNetworkPlanError {}

impl From<PolicyPlanBuildError> for DaemonNetworkPlanError {
    fn from(source: PolicyPlanBuildError) -> Self {
        Self::Policy(source)
    }
}

impl RecoveryJournal {
    pub fn from_applied_policy(
        stage: RecoveryJournalStage,
        profile: Option<String>,
        applied: &AppliedPolicyState,
    ) -> Self {
        Self::from_applied_parts(
            stage,
            profile,
            &applied.tun.ifname,
            Some(&applied.tun),
            Some(&applied.routes),
            Some(&applied.dns),
        )
    }

    pub fn from_applied_parts(
        stage: RecoveryJournalStage,
        profile: Option<String>,
        ifname: impl Into<String>,
        tun: Option<&AppliedTunConfig>,
        routes: Option<&AppliedNetworkRouteState>,
        dns: Option<&AppliedDnsState>,
    ) -> Self {
        Self {
            version: RECOVERY_JOURNAL_VERSION,
            stage,
            profile,
            ifname: ifname.into(),
            dns: dns.map(RecoveryDnsJournal::from_applied),
            routes: routes
                .map(|routes| {
                    routes
                        .routes
                        .iter()
                        .map(RecoveryRouteChangeJournal::from_applied)
                        .collect()
                })
                .unwrap_or_default(),
            ipv6_default_route_block: routes.and_then(|routes| {
                routes.ipv6_default_route_block.as_ref().map(|block| {
                    RecoveryIpv6DefaultRouteBlockJournal {
                        created: block.created,
                    }
                })
            }),
            tun: tun.map(RecoveryTunJournal::from_applied),
        }
    }

    fn validate_version(&self) -> Result<(), RecoveryJournalError> {
        if self.version == RECOVERY_JOURNAL_VERSION {
            Ok(())
        } else {
            Err(RecoveryJournalError::UnsupportedVersion {
                version: self.version,
            })
        }
    }
}

impl RecoveryDnsJournal {
    fn from_applied(applied: &AppliedDnsState) -> Self {
        Self {
            revert: applied
                .revert
                .iter()
                .map(RecoveryDnsCommandJournal::from_command)
                .collect(),
        }
    }
}

impl RecoveryDnsCommandJournal {
    fn from_command(command: &DnsCommand) -> Self {
        Self {
            program: command.program.to_owned(),
            args: command.args.clone(),
            reason: RecoveryDnsCommandReasonJournal::from(command.reason),
        }
    }
}

impl From<DnsCommandReason> for RecoveryDnsCommandReasonJournal {
    fn from(reason: DnsCommandReason) -> Self {
        match reason {
            DnsCommandReason::SetServers => Self::SetServers,
            DnsCommandReason::SetDomains => Self::SetDomains,
            DnsCommandReason::RevertInterface => Self::RevertInterface,
        }
    }
}

impl RecoveryRouteChangeJournal {
    fn from_applied(applied: &AppliedRouteChange) -> Self {
        Self {
            applied: RecoveryPlannedRouteJournal::from_route(&applied.applied),
            revert: RecoveryRouteRevertJournal::from_revert_action(&applied.revert),
        }
    }
}

impl RecoveryPlannedRouteJournal {
    fn from_route(route: &PlannedRoute) -> Self {
        Self {
            destination: route.destination.to_string(),
            via: route.via.map(|gateway| gateway.to_string()),
            dev: route.dev.clone(),
            reason: RecoveryRouteReasonJournal::from(route.reason),
        }
    }
}

impl RecoveryRouteRevertJournal {
    fn from_revert_action(action: &RouteRevertAction) -> Self {
        match action {
            RouteRevertAction::Restore(previous) => Self::Restore {
                previous: RecoveryRouteSnapshotJournal::from_snapshot(previous),
            },
            RouteRevertAction::Delete(created) => Self::Delete {
                created: RecoveryPlannedRouteJournal::from_route(created),
            },
        }
    }
}

impl RecoveryRouteSnapshotJournal {
    fn from_snapshot(route: &RouteSnapshot) -> Self {
        Self {
            destination: route.destination.to_string(),
            via: route.via.map(|gateway| gateway.to_string()),
            dev: route.dev.clone(),
            metric: route.metric,
        }
    }
}

impl From<RouteReason> for RecoveryRouteReasonJournal {
    fn from(reason: RouteReason) -> Self {
        match reason {
            RouteReason::VpnGatewayPin => Self::VpnGatewayPin,
            RouteReason::DetectedLocalNetwork => Self::DetectedLocalNetwork,
            RouteReason::LocalBypassCidr => Self::LocalBypassCidr,
            RouteReason::VpnInternalNetwork => Self::VpnInternalNetwork,
            RouteReason::VpnSplitInclude => Self::VpnSplitInclude,
            RouteReason::ProfileCompanyRoute => Self::ProfileCompanyRoute,
            RouteReason::VpnSplitExclude => Self::VpnSplitExclude,
            RouteReason::VpnDefaultRoute => Self::VpnDefaultRoute,
        }
    }
}

impl RecoveryTunJournal {
    fn from_applied(applied: &AppliedTunConfig) -> Self {
        Self {
            ifname: applied.ifname.clone(),
            address: applied.address.map(|address| address.to_string()),
            prefix_len: applied.prefix_len,
        }
    }
}

impl RecoveryJournalStore {
    pub fn system() -> Self {
        Self::new(RECOVERY_JOURNAL_DEFAULT_ROOT)
    }

    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn journal_path(&self) -> PathBuf {
        self.root.join(RECOVERY_JOURNAL_FILE_NAME)
    }

    fn tmp_path(&self) -> PathBuf {
        self.root.join(RECOVERY_JOURNAL_TMP_FILE_NAME)
    }

    pub fn save(&self, journal: &RecoveryJournal) -> Result<(), RecoveryJournalError> {
        journal.validate_version()?;
        fs::create_dir_all(&self.root).map_err(|err| RecoveryJournalError::io(&self.root, err))?;

        let path = self.journal_path();
        let tmp_path = self.tmp_path();
        let bytes = serde_json::to_vec_pretty(journal)
            .map_err(|err| RecoveryJournalError::json(&path, err))?;
        fs::write(&tmp_path, bytes).map_err(|err| RecoveryJournalError::io(&tmp_path, err))?;
        set_private_file_permissions(&tmp_path)?;
        fs::rename(&tmp_path, &path).map_err(|err| RecoveryJournalError::io(&path, err))?;
        Ok(())
    }

    pub fn load(&self) -> Result<Option<RecoveryJournal>, RecoveryJournalError> {
        let path = self.journal_path();
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(RecoveryJournalError::io(&path, err)),
        };
        let journal: RecoveryJournal =
            serde_json::from_str(&text).map_err(|err| RecoveryJournalError::json(&path, err))?;
        journal.validate_version()?;
        Ok(Some(journal))
    }

    pub fn delete(&self) -> Result<(), RecoveryJournalError> {
        let path = self.journal_path();
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(RecoveryJournalError::io(&path, err)),
        }
    }
}

impl RecoveryJournalSink for RecoveryJournalStore {
    fn load(&self) -> Result<Option<RecoveryJournal>, RecoveryJournalError> {
        RecoveryJournalStore::load(self)
    }

    fn save(&self, journal: &RecoveryJournal) -> Result<(), RecoveryJournalError> {
        RecoveryJournalStore::save(self, journal)
    }

    fn delete(&self) -> Result<(), RecoveryJournalError> {
        RecoveryJournalStore::delete(self)
    }
}

impl RecoveryJournalError {
    fn io(path: &Path, err: io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            message: err.to_string(),
        }
    }

    fn json(path: &Path, err: serde_json::Error) -> Self {
        Self::Json {
            path: path.to_path_buf(),
            message: err.to_string(),
        }
    }
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<(), RecoveryJournalError> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|err| RecoveryJournalError::io(path, err))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<(), RecoveryJournalError> {
    Ok(())
}

impl fmt::Display for RecoveryJournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, message } => {
                write!(
                    f,
                    "recovery journal I/O failed for {}: {message}",
                    path.display()
                )
            }
            Self::Json { path, message } => {
                write!(f, "invalid recovery journal {}: {message}", path.display())
            }
            Self::UnsupportedVersion { version } => {
                write!(f, "unsupported recovery journal version {version}")
            }
        }
    }
}

impl std::error::Error for RecoveryJournalError {}

impl fmt::Display for StartupRecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal { message } => write!(f, "startup recovery journal failed: {message}"),
            Self::InvalidJournal { message } => {
                write!(f, "startup recovery journal is invalid: {message}")
            }
            Self::CleanupIncomplete {
                dns_errors,
                route_errors,
                tun_errors,
                link_errors,
            } => write!(
                f,
                "startup recovery incomplete: dns_errors={dns_errors} route_errors={route_errors} tun_errors={tun_errors} link_errors={link_errors}"
            ),
            Self::StaleCleanup { message } => {
                write!(f, "startup stale managed-link cleanup failed: {message}")
            }
        }
    }
}

impl std::error::Error for StartupRecoveryError {}

impl fmt::Display for LocalProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHome => write!(
                f,
                "HOME is not set and OC_OXIDE_PROFILE_DIR was not provided"
            ),
            Self::InvalidName { name } => write!(f, "invalid profile name {name:?}"),
            Self::Io { path, message } => {
                write!(f, "failed to read profile {}: {message}", path.display())
            }
            Self::Profile { message } => write!(f, "invalid profile: {message}"),
        }
    }
}

impl std::error::Error for LocalProfileError {}

impl fmt::Display for DaemonIpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(source) => write!(f, "daemon IPC I/O failed: {source}"),
            Self::Protocol(source) => write!(f, "daemon IPC protocol failed: {source}"),
            Self::LockPoisoned => write!(f, "daemon controller lock was poisoned"),
            Self::ExistingSocketPath { path } => {
                write!(
                    f,
                    "socket path already exists and is not a socket: {}",
                    path.display()
                )
            }
            Self::Unauthorized { message } => {
                write!(f, "daemon IPC authorization failed: {message}")
            }
        }
    }
}

impl std::error::Error for DaemonIpcError {}

impl From<io::Error> for DaemonIpcError {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

impl From<IpcProtocolError> for DaemonIpcError {
    fn from(source: IpcProtocolError) -> Self {
        Self::Protocol(source)
    }
}

impl TunnelLifecycleError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl LocalProfileResolver {
    pub const PROFILE_DIR_ENV: &'static str = "OC_OXIDE_PROFILE_DIR";

    pub fn from_env() -> Result<Self, LocalProfileError> {
        match env::var_os(Self::PROFILE_DIR_ENV) {
            Some(path) => Ok(Self::new(path)),
            None => {
                let home = env::var_os("HOME").ok_or(LocalProfileError::MissingHome)?;
                Ok(Self::new(
                    PathBuf::from(home)
                        .join(".config")
                        .join("oc-oxide")
                        .join("profiles"),
                ))
            }
        }
    }

    pub fn new(profile_dir: impl Into<PathBuf>) -> Self {
        Self {
            profile_dir: profile_dir.into(),
        }
    }

    pub fn profile_dir(&self) -> &Path {
        &self.profile_dir
    }

    pub fn load(&self, name: &str) -> Result<VpnProfile, LocalProfileError> {
        validate_profile_name(name)?;
        let toml_path = self.profile_dir.join(format!("{name}.toml"));
        let content = fs::read_to_string(&toml_path).map_err(|err| LocalProfileError::Io {
            path: toml_path,
            message: err.to_string(),
        })?;
        parse_toml_vpn_profile(name, &content).map_err(|err| LocalProfileError::Profile {
            message: err.to_string(),
        })
    }
}

impl VpnProfileResolver for LocalProfileResolver {
    fn resolve_profile(&mut self, name: &str) -> Result<VpnProfile, TunnelLifecycleError> {
        self.load(name).map_err(|err| {
            TunnelLifecycleError::new("profile_load_failed", format!("profile {name}: {err}"))
        })
    }
}

impl ImportedProfileResolver {
    pub fn new(local: LocalProfileResolver, imported: BTreeMap<String, VpnProfile>) -> Self {
        Self { local, imported }
    }
}

impl VpnProfileResolver for ImportedProfileResolver {
    fn resolve_profile(&mut self, name: &str) -> Result<VpnProfile, TunnelLifecycleError> {
        if let Some(profile) = self.imported.get(name) {
            return Ok(profile.clone());
        }

        self.local.resolve_profile(name)
    }
}

fn validate_profile_name(name: &str) -> Result<(), LocalProfileError> {
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err(LocalProfileError::InvalidName {
            name: name.to_owned(),
        })
    }
}

pub const DAEMON_SOCKET_ENV: &str = "OC_OXIDE_DAEMON_SOCKET";
#[cfg(unix)]
const POLKIT_ACTION_CONTROL: &str = "com.github.fudanglp.oc-oxide.control";
const DEFAULT_DAEMON_SOCKET_PATH: &str = "/tmp/oc-oxide-daemon.sock";
#[cfg(unix)]
static NEVER_SHUTDOWN: AtomicBool = AtomicBool::new(false);

pub fn default_daemon_socket_path() -> PathBuf {
    default_daemon_socket_path_from_env(env::var_os(DAEMON_SOCKET_ENV))
}

fn default_daemon_socket_path_from_env(value: Option<OsString>) -> PathBuf {
    value
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DAEMON_SOCKET_PATH))
}

pub fn handle_ipc_command_line<F>(
    controller: &mut DaemonWorkerController<F>,
    line: &str,
) -> Result<Vec<String>, DaemonIpcError>
where
    F: TunnelWorkerFactory,
{
    controller.drain_worker_events();
    let command = decode_command_line(line)?;
    let response = controller.handle_command(command);
    let mut lines = vec![encode_response_line(&response)?];
    controller.drain_worker_events();
    lines.extend(encode_drained_events(controller)?);
    Ok(lines)
}

fn encode_drained_events<F>(
    controller: &mut DaemonWorkerController<F>,
) -> Result<Vec<String>, DaemonIpcError>
where
    F: TunnelWorkerFactory,
{
    controller
        .drain_events()
        .iter()
        .map(encode_event_line)
        .collect::<Result<Vec<_>, _>>()
        .map_err(DaemonIpcError::Protocol)
}

#[cfg(unix)]
pub fn serve_unix_socket<F>(
    path: impl AsRef<Path>,
    controller: DaemonWorkerController<F>,
) -> Result<(), DaemonIpcError>
where
    F: TunnelWorkerFactory + Send + 'static,
{
    serve_unix_socket_until_shutdown(path, controller, &NEVER_SHUTDOWN)
}

#[cfg(unix)]
pub fn serve_unix_socket_until_shutdown<F>(
    path: impl AsRef<Path>,
    controller: DaemonWorkerController<F>,
    shutdown_requested: &AtomicBool,
) -> Result<(), DaemonIpcError>
where
    F: TunnelWorkerFactory + Send + 'static,
{
    let path = path.as_ref();
    prepare_socket_path(path)?;
    let listener = UnixListener::bind(path)?;
    listener.set_nonblocking(true)?;
    configure_socket_permissions(path)?;
    let controller = Arc::new(Mutex::new(controller));

    while !shutdown_requested.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let controller = Arc::clone(&controller);
                thread::spawn(move || {
                    let _ = handle_unix_ipc_connection(stream, controller);
                });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(DaemonIpcError::Io(err)),
        }
    }

    shutdown_controller(&controller)?;
    remove_socket_path(path)?;
    Ok(())
}

#[cfg(unix)]
fn shutdown_controller<F>(
    controller: &Arc<Mutex<DaemonWorkerController<F>>>,
) -> Result<(), DaemonIpcError>
where
    F: TunnelWorkerFactory,
{
    {
        let mut guard = controller
            .lock()
            .map_err(|_| DaemonIpcError::LockPoisoned)?;
        let _ = guard.handle_command(IpcCommand::Disconnect);
        guard.drain_worker_events();
    }

    loop {
        let mut guard = controller
            .lock()
            .map_err(|_| DaemonIpcError::LockPoisoned)?;
        if !guard.active_worker_present() {
            return Ok(());
        }
        match guard.recv_worker_event_timeout(Duration::from_millis(100)) {
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        }
    }
}

#[cfg(unix)]
fn remove_socket_path(path: &Path) -> Result<(), DaemonIpcError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(path)?;
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(DaemonIpcError::Io(err)),
    }
}

#[cfg(unix)]
fn prepare_socket_path(path: &Path) -> Result<(), DaemonIpcError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(path)?;
            Ok(())
        }
        Ok(_) => Err(DaemonIpcError::ExistingSocketPath {
            path: path.to_path_buf(),
        }),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(DaemonIpcError::Io(err)),
    }
}

#[cfg(unix)]
fn configure_socket_permissions(path: &Path) -> Result<(), DaemonIpcError> {
    let sudo_owner = sudo_socket_owner_from_env();
    if let Some((uid, gid)) = sudo_owner {
        if effective_uid() == 0 {
            chown_path(path, uid, gid)?;
        }
    }

    fs::set_permissions(
        path,
        fs::Permissions::from_mode(socket_mode_for_owner(sudo_owner)),
    )?;
    Ok(())
}

#[cfg(unix)]
fn sudo_socket_owner_from_env() -> Option<(u32, u32)> {
    parse_socket_owner(
        env::var("SUDO_UID").ok().as_deref(),
        env::var("SUDO_GID").ok().as_deref(),
    )
}

#[cfg(unix)]
fn parse_socket_owner(uid: Option<&str>, gid: Option<&str>) -> Option<(u32, u32)> {
    Some((uid?.parse().ok()?, gid?.parse().ok()?))
}

#[cfg(unix)]
fn socket_mode_for_owner(_owner: Option<(u32, u32)>) -> u32 {
    0o666
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    unsafe { geteuid() }
}

#[cfg(unix)]
fn chown_path(path: &Path, uid: u32, gid: u32) -> Result<(), DaemonIpcError> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket path contains NUL"))?;
    let rc = unsafe { chown(c_path.as_ptr(), uid, gid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(DaemonIpcError::Io(io::Error::last_os_error()))
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnixPeerCredentials {
    pid: u32,
    uid: u32,
}

#[cfg(unix)]
fn authorize_unix_ipc_stream(stream: &UnixStream) -> Result<(), DaemonIpcError> {
    let peer = unix_peer_credentials(stream)?;
    if peer.uid == 0 {
        return Ok(());
    }

    let subject = polkit_process_subject(peer);
    let output = Command::new("pkcheck")
        .arg("--allow-user-interaction")
        .arg("--action-id")
        .arg(POLKIT_ACTION_CONTROL)
        .arg("--process")
        .arg(&subject)
        .output()
        .map_err(|err| DaemonIpcError::Unauthorized {
            message: format!("failed to run pkcheck for pid {}: {err}", peer.pid),
        })?;

    if output.status.success() {
        return Ok(());
    }

    Err(DaemonIpcError::Unauthorized {
        message: authorization_failure_message(peer, &output.stderr, &output.stdout),
    })
}

#[cfg(unix)]
fn unix_peer_credentials(stream: &UnixStream) -> Result<UnixPeerCredentials, DaemonIpcError> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(DaemonIpcError::Io(io::Error::last_os_error()));
    }

    Ok(UnixPeerCredentials {
        pid: credentials.pid as u32,
        uid: credentials.uid,
    })
}

#[cfg(unix)]
fn polkit_process_subject(peer: UnixPeerCredentials) -> String {
    match proc_start_time(peer.pid) {
        Some(start_time) => format!("{},{},{}", peer.pid, start_time, peer.uid),
        None => format!("{},,{}", peer.pid, peer.uid),
    }
}

#[cfg(unix)]
fn proc_start_time(pid: u32) -> Option<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields = stat.rsplit_once(") ")?.1;
    fields.split_whitespace().nth(19).map(str::to_owned)
}

#[cfg(unix)]
fn authorization_failure_message(
    peer: UnixPeerCredentials,
    stderr: &[u8],
    stdout: &[u8],
) -> String {
    let detail = String::from_utf8_lossy(stderr).trim().to_owned();
    if !detail.is_empty() {
        return format!(
            "polkit denied {} for uid {} pid {}: {detail}",
            POLKIT_ACTION_CONTROL, peer.uid, peer.pid
        );
    }

    let detail = String::from_utf8_lossy(stdout).trim().to_owned();
    if !detail.is_empty() {
        return format!(
            "polkit denied {} for uid {} pid {}: {detail}",
            POLKIT_ACTION_CONTROL, peer.uid, peer.pid
        );
    }

    format!(
        "polkit denied {} for uid {} pid {}",
        POLKIT_ACTION_CONTROL, peer.uid, peer.pid
    )
}

#[cfg(unix)]
fn write_authorization_error(
    stream: &UnixStream,
    err: &DaemonIpcError,
) -> Result<(), DaemonIpcError> {
    let response = IpcResponse::Error(IpcErrorResponse {
        code: "authorization_failed".to_owned(),
        message: err.to_string(),
    });
    let mut writer = BufWriter::new(stream.try_clone()?);
    writer.write_all(encode_response_line(&response)?.as_bytes())?;
    writer.flush()?;
    Ok(())
}

#[cfg(unix)]
fn handle_unix_ipc_connection<F>(
    stream: UnixStream,
    controller: Arc<Mutex<DaemonWorkerController<F>>>,
) -> Result<(), DaemonIpcError>
where
    F: TunnelWorkerFactory,
{
    if let Err(err) = authorize_unix_ipc_stream(&stream) {
        let _ = write_authorization_error(&stream, &err);
        return Err(err);
    }

    stream.set_read_timeout(Some(Duration::from_millis(100)))?;
    let read_stream = stream.try_clone()?;
    let mut reader = BufReader::new(read_stream);
    let mut writer = BufWriter::new(stream);
    let mut owns_pending_connect = false;

    loop {
        write_pending_events(&controller, &mut writer)?;
        if owns_pending_connect && connection_connect_completed(&controller)? {
            owns_pending_connect = false;
        }

        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                if owns_pending_connect {
                    cancel_owned_pending_connect(&controller)?;
                }
                return Ok(());
            }
            Ok(_) => {
                if line.trim().is_empty() {
                    continue;
                }
                let command_is_connect = matches!(
                    decode_command_line(&line),
                    Ok(IpcCommand::Connect { .. } | IpcCommand::ConnectWithProfile { .. })
                );
                let output = {
                    let mut guard = controller
                        .lock()
                        .map_err(|_| DaemonIpcError::LockPoisoned)?;
                    match handle_ipc_command_line(&mut guard, &line) {
                        Ok(lines) => lines,
                        Err(err) => vec![encode_response_line(&IpcResponse::Error(
                            IpcErrorResponse {
                                code: "invalid_ipc".to_owned(),
                                message: err.to_string(),
                            },
                        ))?],
                    }
                };
                if command_is_connect && first_ipc_response_was_accepted(&output) {
                    owns_pending_connect = true;
                }
                write_json_lines(&mut writer, &output)?;
            }
            Err(err)
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::TimedOut => {}
            Err(err) => return Err(DaemonIpcError::Io(err)),
        }
    }
}

#[cfg(unix)]
fn connection_connect_completed<F>(
    controller: &Arc<Mutex<DaemonWorkerController<F>>>,
) -> Result<bool, DaemonIpcError>
where
    F: TunnelWorkerFactory,
{
    let guard = controller
        .lock()
        .map_err(|_| DaemonIpcError::LockPoisoned)?;
    Ok(matches!(
        guard.core().status().state,
        DaemonState::Connected | DaemonState::Disconnected | DaemonState::Error
    ))
}

#[cfg(unix)]
fn cancel_owned_pending_connect<F>(
    controller: &Arc<Mutex<DaemonWorkerController<F>>>,
) -> Result<(), DaemonIpcError>
where
    F: TunnelWorkerFactory,
{
    let mut guard = controller
        .lock()
        .map_err(|_| DaemonIpcError::LockPoisoned)?;
    if should_cancel_owned_connect(true, guard.core().status().state) {
        let _ = guard.handle_command(IpcCommand::Disconnect);
    }
    Ok(())
}

#[cfg(unix)]
fn first_ipc_response_was_accepted(lines: &[String]) -> bool {
    lines
        .first()
        .and_then(|line| decode_response_line(line).ok())
        .is_some_and(|response| matches!(response, IpcResponse::Accepted))
}

#[cfg(unix)]
fn should_cancel_owned_connect(owns_pending_connect: bool, state: DaemonState) -> bool {
    owns_pending_connect
        && matches!(
            state,
            DaemonState::Configuring
                | DaemonState::AwaitingAuth
                | DaemonState::Connecting
                | DaemonState::Disconnecting
        )
}

#[cfg(unix)]
fn write_pending_events<F, W>(
    controller: &Arc<Mutex<DaemonWorkerController<F>>>,
    writer: &mut W,
) -> Result<(), DaemonIpcError>
where
    F: TunnelWorkerFactory,
    W: Write,
{
    let output = {
        let mut guard = controller
            .lock()
            .map_err(|_| DaemonIpcError::LockPoisoned)?;
        guard.drain_worker_events();
        encode_drained_events(&mut guard)?
    };
    write_json_lines(writer, &output)
}

fn write_json_lines<W: Write>(writer: &mut W, lines: &[String]) -> Result<(), DaemonIpcError> {
    for line in lines {
        writer.write_all(line.as_bytes())?;
    }
    writer.flush()?;
    Ok(())
}

impl TunnelWorkerHandle {
    pub fn spawn<W: TunnelWorker>(worker: W) -> Self {
        let (command_tx, command_rx) = mpsc::channel();
        let (event_tx, event_rx) = mpsc::channel();
        let join = thread::spawn(move || worker.run(command_rx, event_tx));

        Self {
            commands: command_tx,
            events: event_rx,
            join: Some(join),
        }
    }

    pub fn send(&self, command: TunnelWorkerCommand) -> Result<(), TunnelWorkerChannelError> {
        self.commands
            .send(command)
            .map_err(|_| TunnelWorkerChannelError::CommandChannelClosed)
    }

    pub fn drain_events(&self) -> Vec<TunnelWorkerEvent> {
        let mut events = Vec::new();
        while let Ok(event) = self.events.try_recv() {
            events.push(event);
        }
        events
    }

    pub fn recv_event_timeout(
        &self,
        timeout: Duration,
    ) -> Result<TunnelWorkerEvent, mpsc::RecvTimeoutError> {
        self.events.recv_timeout(timeout)
    }

    pub fn join(mut self) -> thread::Result<()> {
        drop(self.commands);
        match self.join.take() {
            Some(join) => join.join(),
            None => Ok(()),
        }
    }
}

impl<F: TunnelWorkerFactory> DaemonWorkerController<F> {
    pub fn new(worker_factory: F) -> Self {
        Self {
            core: DaemonCore::new(),
            worker_factory,
            active_worker: None,
        }
    }

    pub fn core(&self) -> &DaemonCore {
        &self.core
    }

    pub fn core_mut(&mut self) -> &mut DaemonCore {
        &mut self.core
    }

    pub fn handle_command(&mut self, command: IpcCommand) -> IpcResponse {
        match command {
            IpcCommand::Connect { profile } => self.connect(profile),
            IpcCommand::ConnectWithProfile {
                profile,
                profile_toml,
            } => self.connect_with_profile(profile, profile_toml),
            IpcCommand::SubmitAuth(submission) => self.submit_auth(submission),
            IpcCommand::Disconnect => self.disconnect(),
            other => self.core.handle_command(other),
        }
    }

    pub fn drain_worker_events(&mut self) {
        let events = match self.active_worker.as_ref() {
            Some(worker) => worker.drain_events(),
            None => return,
        };
        for event in events {
            if self.apply_worker_event_and_check_terminal(event) {
                self.clear_active_worker();
                break;
            }
        }
    }

    pub fn recv_worker_event_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<bool, mpsc::RecvTimeoutError> {
        let event = match self.active_worker.as_ref() {
            Some(worker) => worker.recv_event_timeout(timeout)?,
            None => return Ok(false),
        };
        if self.apply_worker_event_and_check_terminal(event) {
            self.clear_active_worker();
        }
        Ok(true)
    }

    pub fn drain_events(&mut self) -> Vec<IpcEvent> {
        self.core.drain_events()
    }

    pub fn active_worker_present(&self) -> bool {
        self.active_worker.is_some()
    }

    fn connect(&mut self, profile: String) -> IpcResponse {
        let response = self.core.handle_command(IpcCommand::Connect {
            profile: profile.clone(),
        });
        if !matches!(response, IpcResponse::Accepted) {
            return response;
        }

        let worker = self.worker_factory.spawn_worker();
        match worker.send(TunnelWorkerCommand::Connect(TunnelConnectRequest {
            profile,
        })) {
            Ok(()) => {
                self.active_worker = Some(worker);
                IpcResponse::Accepted
            }
            Err(err) => {
                self.core.record_lifecycle_error(TunnelLifecycleError::new(
                    "tunnel_worker_unavailable",
                    err.to_string(),
                ));
                IpcResponse::Error(self.core.last_error.clone().expect("last error set"))
            }
        }
    }

    fn connect_with_profile(&mut self, profile: String, profile_toml: String) -> IpcResponse {
        match parse_toml_vpn_profile(&profile, &profile_toml) {
            Ok(imported_profile) => {
                if let Err(err) = self
                    .worker_factory
                    .import_profile(profile.clone(), imported_profile)
                {
                    self.core.record_lifecycle_error(err);
                    return IpcResponse::Error(
                        self.core.last_error.clone().expect("last error set"),
                    );
                }
            }
            Err(err) => {
                self.core.record_lifecycle_error(TunnelLifecycleError::new(
                    "profile_import_failed",
                    format!("profile {profile}: {err}"),
                ));
                return IpcResponse::Error(self.core.last_error.clone().expect("last error set"));
            }
        }

        self.connect(profile)
    }

    fn submit_auth(&mut self, submission: AuthSubmission) -> IpcResponse {
        match self.active_worker.as_ref() {
            Some(worker) => self.core.submit_auth_to_worker(submission, worker),
            None => self.core.error(
                "tunnel_worker_unavailable",
                "no active tunnel worker is available for auth submission",
            ),
        }
    }

    fn disconnect(&mut self) -> IpcResponse {
        match self.active_worker.as_ref() {
            Some(worker) => match worker.send(TunnelWorkerCommand::Cancel) {
                Ok(()) => IpcResponse::Accepted,
                Err(err) => {
                    self.clear_active_worker();
                    self.core
                        .error("tunnel_worker_unavailable", err.to_string())
                }
            },
            None => self.core.handle_command(IpcCommand::Disconnect),
        }
    }

    fn clear_active_worker(&mut self) {
        if let Some(worker) = self.active_worker.take() {
            let _ = worker.join();
        }
    }

    fn apply_worker_event_and_check_terminal(&mut self, event: TunnelWorkerEvent) -> bool {
        let terminal = matches!(
            event,
            TunnelWorkerEvent::Lifecycle(TunnelLifecycleStep::Disconnected { .. })
                | TunnelWorkerEvent::Error(_)
        );
        self.core.apply_worker_event(event);
        terminal
    }
}

impl<F> Drop for DaemonWorkerController<F> {
    fn drop(&mut self) {
        if let Some(worker) = self.active_worker.take() {
            let _ = worker.join();
        }
    }
}

impl DaemonTunnelEventSink {
    pub fn new(events: mpsc::Sender<TunnelWorkerEvent>) -> Self {
        Self {
            events,
            next_auth_form: 1,
        }
    }

    fn send_lifecycle(&mut self, step: TunnelLifecycleStep) {
        if let TunnelLifecycleStep::Progress(progress) = &step {
            if !should_emit_progress_to_ipc(progress) {
                return;
            }
        }
        let _ = self.events.send(TunnelWorkerEvent::Lifecycle(step));
    }

    fn send_error(&mut self, error: TunnelLifecycleError) {
        let _ = self.events.send(TunnelWorkerEvent::Error(error));
    }

    fn next_auth_form_id(&mut self) -> String {
        let form_id = format!("openconnect-auth-{}", self.next_auth_form);
        self.next_auth_form += 1;
        form_id
    }
}

impl<R, W> OpenConnectTunnelWorker<R, W> {
    pub fn new(profile_resolver: R, workflow: W) -> Self {
        Self {
            profile_resolver,
            workflow,
        }
    }
}

impl SystemOpenConnectWorkerFactory {
    pub fn new(profile_resolver: LocalProfileResolver) -> Self {
        Self {
            profile_resolver,
            imported_profiles: BTreeMap::new(),
        }
    }

    pub fn from_env() -> Result<Self, LocalProfileError> {
        Ok(Self::new(LocalProfileResolver::from_env()?))
    }
}

impl TunnelWorkerFactory for SystemOpenConnectWorkerFactory {
    fn spawn_worker(&mut self) -> TunnelWorkerHandle {
        match SystemOpenConnectWorkflow::system() {
            Ok(workflow) => TunnelWorkerHandle::spawn(OpenConnectTunnelWorker::new(
                ImportedProfileResolver::new(
                    self.profile_resolver.clone(),
                    self.imported_profiles.clone(),
                ),
                workflow,
            )),
            Err(error) => TunnelWorkerHandle::spawn(ImmediateErrorWorker { error }),
        }
    }

    fn import_profile(
        &mut self,
        name: String,
        profile: VpnProfile,
    ) -> Result<(), TunnelLifecycleError> {
        validate_profile_name(&name).map_err(|err| {
            TunnelLifecycleError::new("profile_import_failed", format!("profile {name}: {err}"))
        })?;
        self.imported_profiles.insert(name, profile);
        Ok(())
    }
}

impl<R, W> TunnelWorker for OpenConnectTunnelWorker<R, W>
where
    R: VpnProfileResolver,
    W: OpenConnectWorkflow,
{
    fn run(
        mut self,
        commands: mpsc::Receiver<TunnelWorkerCommand>,
        events: mpsc::Sender<TunnelWorkerEvent>,
    ) {
        while let Ok(command) = commands.recv() {
            match command {
                TunnelWorkerCommand::Connect(request) => {
                    let profile = match self.profile_resolver.resolve_profile(&request.profile) {
                        Ok(profile) => profile,
                        Err(error) => {
                            let _ = events.send(TunnelWorkerEvent::Error(error));
                            break;
                        }
                    };
                    let _ = events.send(TunnelWorkerEvent::Lifecycle(
                        TunnelLifecycleStep::Progress(ProgressUpdate {
                            level: 0,
                            message: "profile resolved".to_owned(),
                        }),
                    ));
                    if let Err(error) = self.workflow.run(profile, commands, events.clone()) {
                        let _ = events.send(TunnelWorkerEvent::Error(error));
                    }
                    break;
                }
                TunnelWorkerCommand::Cancel | TunnelWorkerCommand::Disconnect => {
                    let _ = events.send(TunnelWorkerEvent::Lifecycle(
                        TunnelLifecycleStep::Disconnected {
                            reason: DisconnectReason::UserRequested,
                        },
                    ));
                    break;
                }
                TunnelWorkerCommand::SubmitAuth(_) => {
                    let _ = events.send(TunnelWorkerEvent::Error(TunnelLifecycleError::new(
                        "unexpected_auth_submission",
                        "auth submission arrived before a tunnel connection was active",
                    )));
                    break;
                }
            }
        }
    }
}

impl TunnelWorker for ImmediateErrorWorker {
    fn run(
        self,
        commands: mpsc::Receiver<TunnelWorkerCommand>,
        events: mpsc::Sender<TunnelWorkerEvent>,
    ) {
        if matches!(commands.recv(), Ok(TunnelWorkerCommand::Connect(_))) {
            let _ = events.send(TunnelWorkerEvent::Error(self.error));
        }
    }
}

impl<'a> WorkerAuthHandler<'a> {
    pub fn new(commands: &'a mpsc::Receiver<TunnelWorkerCommand>) -> Self {
        Self { commands }
    }
}

impl AuthFormHandler for WorkerAuthHandler<'_> {
    fn handle_auth_request(&mut self, _request: AuthRequest) -> AuthFormDecision {
        while let Ok(command) = self.commands.recv() {
            match command {
                TunnelWorkerCommand::SubmitAuth(response) => {
                    return AuthFormDecision::Submit(response);
                }
                TunnelWorkerCommand::Cancel | TunnelWorkerCommand::Disconnect => {
                    return AuthFormDecision::Cancel;
                }
                TunnelWorkerCommand::Connect(_) => {}
            }
        }

        AuthFormDecision::Cancel
    }
}

impl<N, D> SystemOpenConnectWorkflow<N, D, RecoveryJournalStore> {
    pub fn new(net_backend: N, dns_runner: D) -> Self {
        Self::new_with_recovery_journal(net_backend, dns_runner, RecoveryJournalStore::system())
    }
}

impl<N, D, J> SystemOpenConnectWorkflow<N, D, J> {
    pub fn new_with_recovery_journal(
        net_backend: N,
        dns_runner: D,
        recovery_journal_store: J,
    ) -> Self {
        Self {
            net_backend,
            dns_runner,
            recovery_journal_store,
            useragent: "oc-oxide-daemon".to_owned(),
            dtls_attempt_period_seconds: 60,
            reconnect_timeout_seconds: 300,
            reconnect_interval_seconds: 10,
        }
    }

    pub fn with_useragent(mut self, useragent: impl Into<String>) -> Self {
        self.useragent = useragent.into();
        self
    }
}

impl
    SystemOpenConnectWorkflow<
        LinuxNetlinkRunner,
        SystemdResolvedCommandRunner,
        RecoveryJournalStore,
    >
{
    pub fn system() -> Result<Self, TunnelLifecycleError> {
        Ok(Self::new(
            LinuxNetlinkRunner::new()
                .map_err(|err| TunnelLifecycleError::new("netlink_init", err.to_string()))?,
            SystemdResolvedCommandRunner::new(),
        ))
    }
}

impl<N, D, J> OpenConnectWorkflow for SystemOpenConnectWorkflow<N, D, J>
where
    N: LinuxNetworkBackend + Send + 'static,
    D: DnsCommandRunner + Send + 'static,
    J: RecoveryJournalSink + Send + 'static,
{
    fn run(
        &mut self,
        profile: VpnProfile,
        commands: mpsc::Receiver<TunnelWorkerCommand>,
        events: mpsc::Sender<TunnelWorkerEvent>,
    ) -> Result<(), TunnelLifecycleError> {
        let (auth_tx, auth_rx) = mpsc::channel();
        let cancel_requested = Arc::new(AtomicBool::new(false));
        let cancel_handle = Arc::new(Mutex::new(None));
        spawn_workflow_command_pump(
            commands,
            auth_tx,
            Arc::clone(&cancel_requested),
            Arc::clone(&cancel_handle),
            events.clone(),
        );

        let mut sink = DaemonTunnelEventSink::new(events.clone());
        let mut auth_handler = WorkflowAuthHandler::new(
            &auth_rx,
            Arc::clone(&cancel_requested),
            profile.tunnel().username().map(str::to_owned),
            profile.tunnel().authgroup().map(str::to_owned),
        );
        let auth_cancelled = Arc::clone(&auth_handler.auth_cancelled);
        let mut session =
            OpenConnectSession::new_with_callbacks(&self.useragent, &mut sink, &mut auth_handler)
                .map_err(tunnel_lifecycle_error("openconnect_session"))?;

        session
            .session_mut()
            .configure_for_anyconnect(profile.tunnel())
            .map_err(tunnel_lifecycle_error("openconnect_configure"))?;
        if let Err(err) = session.session_mut().obtain_cookie() {
            if cancel_requested.load(Ordering::SeqCst) || auth_cancelled.load(Ordering::SeqCst) {
                let _ = events.send(TunnelWorkerEvent::Lifecycle(
                    TunnelLifecycleStep::Disconnected {
                        reason: DisconnectReason::UserRequested,
                    },
                ));
                return Ok(());
            }

            return Err(tunnel_lifecycle_error("openconnect_obtain_cookie")(err));
        }
        session
            .session_mut()
            .make_cstp_connection()
            .map_err(tunnel_lifecycle_error("openconnect_make_cstp_connection"))?;

        let ip_info = session
            .session()
            .ip_info_snapshot()
            .map_err(tunnel_lifecycle_error("openconnect_ip_info"))?;
        cleanup_managed_tun_before_setup(&self.net_backend, &mut self.dns_runner, &events)?;
        let tun = session
            .session_mut()
            .setup_tun_device_without_script(Some(DAEMON_MANAGED_TUN_IFNAME))
            .map_err(tunnel_lifecycle_error("openconnect_setup_tun"))?;
        let ifname = tun
            .ifname
            .or_else(|| session.session().ifname())
            .ok_or_else(|| {
                TunnelLifecycleError::new("missing_tun_ifname", "TUN interface name is missing")
            })?;
        if ifname != DAEMON_MANAGED_TUN_IFNAME {
            return Err(TunnelLifecycleError::new(
                "unexpected_tun_ifname",
                format!("expected managed TUN interface {DAEMON_MANAGED_TUN_IFNAME}, got {ifname}"),
            ));
        }

        let default_route = self
            .net_backend
            .default_route()
            .map_err(|err| TunnelLifecycleError::new("default_route", err.to_string()))?;
        let detected_local_cidrs = self
            .net_backend
            .interface_ipv4_cidrs(&default_route.interface)
            .map_err(|err| TunnelLifecycleError::new("local_lan_detect", err.to_string()))?;
        let policy_input = tunnel_policy_input_from_ip_info(&ip_info, &ifname);
        let daemon_plan = plan_daemon_network_policy_with_detected_local_cidrs(
            &profile,
            &default_route,
            detected_local_cidrs,
            &policy_input,
        )
        .map_err(|err| TunnelLifecycleError::new("policy_plan", err.to_string()))?;
        let profile_name = profile.tunnel().name().to_owned();
        let policy_plan = daemon_plan.policy;
        let applied_policy = apply_policy_with_recovery_journal(
            &self.net_backend,
            &mut self.dns_runner,
            &self.recovery_journal_store,
            Some(profile_name.clone()),
            &policy_plan,
        )?;

        let _ = events.send(TunnelWorkerEvent::Lifecycle(
            TunnelLifecycleStep::NetworkApplied(daemon_plan.applied),
        ));
        let _ = events.send(TunnelWorkerEvent::Lifecycle(
            TunnelLifecycleStep::Connected { interface: ifname },
        ));

        if let Err(err) = session
            .session_mut()
            .setup_dtls(self.dtls_attempt_period_seconds)
        {
            let _ = events.send(TunnelWorkerEvent::Lifecycle(TunnelLifecycleStep::Progress(
                ProgressUpdate {
                    level: 0,
                    message: format!("DTLS setup failed; using CSTP only: {err}"),
                },
            )));
        }

        let cancel = session.session_mut().take_cancel_handle().ok_or_else(|| {
            TunnelLifecycleError::new(
                "openconnect_cancel_handle",
                "OpenConnect command pipe handle was already taken",
            )
        })?;
        install_cancel_handle(
            cancel,
            &cancel_handle,
            cancel_requested.load(Ordering::SeqCst),
        )?;

        let outcome = session.session_mut().run_mainloop(
            self.reconnect_timeout_seconds,
            self.reconnect_interval_seconds,
        );
        let (dns_errors, route_errors, mut tun_errors) = revert_policy_error_counts_with_journal(
            &self.net_backend,
            &mut self.dns_runner,
            &self.recovery_journal_store,
            Some(profile_name),
            &applied_policy,
            &events,
        );
        tun_errors += cleanup_managed_tun_after_disconnect(&self.net_backend, &events);
        delete_recovery_journal_after_successful_disconnect(
            &self.recovery_journal_store,
            dns_errors,
            route_errors,
            tun_errors,
            &events,
        );
        let _ = events.send(TunnelWorkerEvent::Lifecycle(
            TunnelLifecycleStep::NetworkReverted {
                dns_errors,
                route_errors,
                tun_errors,
            },
        ));
        let _ = events.send(TunnelWorkerEvent::Lifecycle(
            TunnelLifecycleStep::Disconnected {
                reason: disconnect_reason_from_mainloop_outcome(outcome),
            },
        ));

        if outcome.is_error() {
            return Err(TunnelLifecycleError::new(
                "openconnect_mainloop",
                format!("OpenConnect mainloop ended with {outcome:?}"),
            ));
        }

        Ok(())
    }
}

impl<'a> WorkflowAuthHandler<'a> {
    fn new(
        responses: &'a mpsc::Receiver<AuthResponse>,
        cancel_requested: Arc<AtomicBool>,
        preferred_username: Option<String>,
        preferred_authgroup: Option<String>,
    ) -> Self {
        Self {
            responses,
            cancel_requested,
            auth_cancelled: Arc::new(AtomicBool::new(false)),
            preferred_username,
            preferred_authgroup,
            authgroup_submitted: false,
            pending_prefilled_answers: Vec::new(),
        }
    }

    fn cancel_auth(&self) -> AuthFormDecision {
        self.auth_cancelled.store(true, Ordering::SeqCst);
        AuthFormDecision::Cancel
    }
}

impl AuthFormHandler for WorkflowAuthHandler<'_> {
    fn maybe_handle_auth_request(&mut self, request: &AuthRequest) -> Option<AuthFormDecision> {
        if self.authgroup_submitted {
            return None;
        }

        let preferred_authgroup = self.preferred_authgroup.as_deref()?;
        let response = authgroup_response_from_request(request, preferred_authgroup)?;
        self.authgroup_submitted = true;
        Some(match response {
            Ok(response) => AuthFormDecision::NewAuthGroup(response),
            Err(_) => AuthFormDecision::Error,
        })
    }

    fn prepare_auth_request(&mut self, request: AuthRequest) -> AuthRequest {
        let mut prefilled = Vec::new();

        if let Some(preferred_username) = self.preferred_username.as_deref() {
            if let Some(field_id) = matching_username_field(&request) {
                if let Ok(answer) = AuthAnswer::text(&field_id, preferred_username) {
                    prefilled.push(answer);
                }
            }
        }

        if self.authgroup_submitted {
            if let Some(preferred_authgroup) = self.preferred_authgroup.as_deref() {
                if let Some((field_id, choice_value)) =
                    matching_authgroup_choice(&request, preferred_authgroup)
                {
                    if let Ok(answer) = AuthAnswer::text(&field_id, &choice_value) {
                        prefilled.push(answer);
                    }
                }
            }
        }

        if prefilled.is_empty() {
            return request;
        }

        let mut prepared = request;
        let remaining_field_count = prepared
            .fields
            .iter()
            .filter(|field| !prefilled.iter().any(|answer| answer.field_id == field.id))
            .count();
        if remaining_field_count == 0 {
            return prepared;
        }

        prepared
            .fields
            .retain(|field| !prefilled.iter().any(|answer| answer.field_id == field.id));
        self.pending_prefilled_answers = prefilled;
        prepared
    }

    fn handle_auth_request(&mut self, _request: AuthRequest) -> AuthFormDecision {
        loop {
            if self.cancel_requested.load(Ordering::SeqCst) {
                return self.cancel_auth();
            }

            match self.responses.recv_timeout(Duration::from_millis(100)) {
                Ok(mut response) => {
                    for answer in self.pending_prefilled_answers.drain(..) {
                        if !response
                            .answers
                            .iter()
                            .any(|existing| existing.field_id == answer.field_id)
                        {
                            response.answers.push(answer);
                        }
                    }
                    return AuthFormDecision::Submit(response);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return self.cancel_auth(),
            }
        }
    }
}

fn authgroup_response_from_request(
    request: &AuthRequest,
    preferred_authgroup: &str,
) -> Option<Result<AuthResponse, AuthError>> {
    let (field_id, choice_value) = matching_authgroup_choice(request, preferred_authgroup)?;
    let mut response = AuthResponse::new(vec![AuthAnswer::text(&field_id, &choice_value).ok()?]);
    if let Some(form_id) = &request.form_id {
        response = response.and_then(|response| response.with_form_id(form_id));
    }
    Some(response)
}

fn matching_authgroup_choice(
    request: &AuthRequest,
    preferred_authgroup: &str,
) -> Option<(String, String)> {
    for field in &request.fields {
        if !is_authgroup_field(field) {
            continue;
        }
        let AuthFieldKind::Select { choices } = &field.kind else {
            continue;
        };
        let choice = match_authgroup_choice(choices, preferred_authgroup)?;
        return Some((field.id.clone(), choice.value.clone()));
    }

    None
}

fn match_authgroup_choice<'a>(
    choices: &'a [TunnelAuthChoice],
    preferred_authgroup: &str,
) -> Option<&'a TunnelAuthChoice> {
    let preferred = preferred_authgroup.trim();
    if preferred.is_empty() {
        return None;
    }

    if let Some(choice) = choices
        .iter()
        .find(|choice| choice.value.eq_ignore_ascii_case(preferred))
    {
        return Some(choice);
    }

    if let Some(choice) = choices
        .iter()
        .find(|choice| choice.label.eq_ignore_ascii_case(preferred))
    {
        return Some(choice);
    }

    let mut prefix_matches = choices
        .iter()
        .filter(|choice| starts_with_ignore_ascii_case(&choice.label, preferred));
    let choice = prefix_matches.next()?;
    if prefix_matches.next().is_some() {
        None
    } else {
        Some(choice)
    }
}

fn starts_with_ignore_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

fn matching_username_field(request: &AuthRequest) -> Option<String> {
    request
        .fields
        .iter()
        .find(|field| matches!(field.kind, AuthFieldKind::Text { .. }) && is_username_field(field))
        .map(|field| field.id.clone())
}

fn is_username_field(field: &AuthField) -> bool {
    let id = field.id.to_ascii_lowercase();
    let label = field.label.to_ascii_lowercase();
    id.contains("user") || id.starts_with("uname") || label.contains("user")
}

fn is_authgroup_field(field: &AuthField) -> bool {
    let id = field.id.to_ascii_lowercase();
    let label = field.label.to_ascii_lowercase();
    id.contains("group") || label.contains("group")
}

fn spawn_workflow_command_pump(
    commands: mpsc::Receiver<TunnelWorkerCommand>,
    auth_tx: mpsc::Sender<AuthResponse>,
    cancel_requested: Arc<AtomicBool>,
    cancel_handle: Arc<Mutex<Option<CancelHandle>>>,
    events: mpsc::Sender<TunnelWorkerEvent>,
) {
    thread::spawn(move || {
        while let Ok(command) = commands.recv() {
            match command {
                TunnelWorkerCommand::SubmitAuth(response) => {
                    if auth_tx.send(response).is_err() {
                        break;
                    }
                }
                TunnelWorkerCommand::Cancel | TunnelWorkerCommand::Disconnect => {
                    cancel_requested.store(true, Ordering::SeqCst);
                    let _ = events.send(TunnelWorkerEvent::Lifecycle(
                        TunnelLifecycleStep::Disconnecting,
                    ));
                    if let Ok(guard) = cancel_handle.lock() {
                        if let Some(handle) = guard.as_ref() {
                            if let Err(err) = handle.cancel() {
                                let _ = events.send(TunnelWorkerEvent::Error(
                                    TunnelLifecycleError::new(
                                        "openconnect_cancel",
                                        err.to_string(),
                                    ),
                                ));
                            }
                        }
                    }
                    break;
                }
                TunnelWorkerCommand::Connect(_) => {
                    let _ = events.send(TunnelWorkerEvent::Error(TunnelLifecycleError::new(
                        "unexpected_connect",
                        "connect command arrived while workflow was active",
                    )));
                }
            }
        }
    });
}

fn install_cancel_handle(
    cancel: CancelHandle,
    slot: &Arc<Mutex<Option<CancelHandle>>>,
    cancel_immediately: bool,
) -> Result<(), TunnelLifecycleError> {
    let mut guard = slot.lock().map_err(|_| {
        TunnelLifecycleError::new(
            "openconnect_cancel_handle",
            "cancel handle lock was poisoned",
        )
    })?;
    *guard = Some(cancel);
    if cancel_immediately {
        if let Some(handle) = guard.as_ref() {
            handle
                .cancel()
                .map_err(tunnel_lifecycle_error("openconnect_cancel"))?;
        }
    }
    Ok(())
}

fn apply_policy_with_recovery_journal<N, D, J>(
    net_backend: &N,
    dns_runner: &mut D,
    journal_store: &J,
    profile: Option<String>,
    plan: &PolicyPlan,
) -> Result<AppliedPolicyState, TunnelLifecycleError>
where
    N: LinuxNetworkBackend,
    D: DnsCommandRunner,
    J: RecoveryJournalSink,
{
    let tun = apply_tun_config_with(net_backend, &plan.tun)
        .map_err(|err| TunnelLifecycleError::new("policy_apply", err.to_string()))?;
    let tun_journal = RecoveryJournal::from_applied_parts(
        RecoveryJournalStage::ApplyingTun,
        profile.clone(),
        &plan.tun.ifname,
        Some(&tun),
        None,
        None,
    );
    if let Err(err) = journal_store.save(&tun_journal) {
        let tun_errors = revert_tun_config_with(net_backend, &tun);
        cleanup_journal_if_rollback_succeeded(journal_store, tun_errors.is_empty());
        return Err(recovery_journal_lifecycle_error(err));
    }

    let routes = match apply_network_route_plan_with(net_backend, &plan.routes) {
        Ok(routes) => routes,
        Err(err) => {
            let tun_errors = revert_tun_config_with(net_backend, &tun);
            cleanup_journal_if_rollback_succeeded(journal_store, tun_errors.is_empty());
            return Err(TunnelLifecycleError::new("policy_apply", err.to_string()));
        }
    };
    let route_journal = RecoveryJournal::from_applied_parts(
        RecoveryJournalStage::ApplyingRoutes,
        profile.clone(),
        &plan.tun.ifname,
        Some(&tun),
        Some(&routes),
        None,
    );
    if let Err(err) = journal_store.save(&route_journal) {
        let route_errors = revert_network_route_plan_with(net_backend, &routes);
        let tun_errors = revert_tun_config_with(net_backend, &tun);
        cleanup_journal_if_rollback_succeeded(
            journal_store,
            route_errors.is_empty() && tun_errors.is_empty(),
        );
        return Err(recovery_journal_lifecycle_error(err));
    }

    let dns = match apply_dns_command_plan_with(dns_runner, &plan.dns) {
        Ok(dns) => dns,
        Err(err) => {
            let route_errors = revert_network_route_plan_with(net_backend, &routes);
            let tun_errors = revert_tun_config_with(net_backend, &tun);
            cleanup_journal_if_rollback_succeeded(
                journal_store,
                route_errors.is_empty() && tun_errors.is_empty(),
            );
            return Err(TunnelLifecycleError::new("policy_apply", err.to_string()));
        }
    };
    let applied = AppliedPolicyState { tun, routes, dns };
    let dns_journal = RecoveryJournal::from_applied_policy(
        RecoveryJournalStage::ApplyingDns,
        profile.clone(),
        &applied,
    );
    if let Err(err) = journal_store.save(&dns_journal) {
        rollback_full_policy_after_journal_failure(
            net_backend,
            dns_runner,
            journal_store,
            &applied,
        );
        return Err(recovery_journal_lifecycle_error(err));
    }
    let connected_journal =
        RecoveryJournal::from_applied_policy(RecoveryJournalStage::Connected, profile, &applied);
    if let Err(err) = journal_store.save(&connected_journal) {
        rollback_full_policy_after_journal_failure(
            net_backend,
            dns_runner,
            journal_store,
            &applied,
        );
        return Err(recovery_journal_lifecycle_error(err));
    }

    Ok(applied)
}

fn rollback_full_policy_after_journal_failure<N, D, J>(
    net_backend: &N,
    dns_runner: &mut D,
    journal_store: &J,
    applied: &AppliedPolicyState,
) where
    N: LinuxNetworkBackend,
    D: DnsCommandRunner,
    J: RecoveryJournalSink,
{
    let dns_errors = revert_dns_command_plan_with(dns_runner, &applied.dns);
    let route_errors = revert_network_route_plan_with(net_backend, &applied.routes);
    let tun_errors = revert_tun_config_with(net_backend, &applied.tun);
    cleanup_journal_if_rollback_succeeded(
        journal_store,
        dns_errors.is_empty() && route_errors.is_empty() && tun_errors.is_empty(),
    );
}

fn cleanup_journal_if_rollback_succeeded<J>(journal_store: &J, rollback_succeeded: bool)
where
    J: RecoveryJournalSink,
{
    if rollback_succeeded {
        let _ = journal_store.delete();
    }
}

fn revert_policy_error_counts_with_journal<N, D, J>(
    net_backend: &N,
    dns_runner: &mut D,
    journal_store: &J,
    profile: Option<String>,
    applied: &AppliedPolicyState,
    events: &mpsc::Sender<TunnelWorkerEvent>,
) -> (usize, usize, usize)
where
    N: LinuxNetworkBackend,
    D: DnsCommandRunner,
    J: RecoveryJournalSink,
{
    let reverting_journal =
        RecoveryJournal::from_applied_policy(RecoveryJournalStage::Reverting, profile, applied);
    if let Err(err) = journal_store.save(&reverting_journal) {
        send_workflow_progress(
            events,
            0,
            format!("recovery journal reverting mark failed: {err}"),
        );
    }

    let dns_errors = revert_dns_command_plan_with(dns_runner, &applied.dns);
    let route_errors = revert_network_route_plan_with(net_backend, &applied.routes);
    let tun_errors = revert_tun_config_with(net_backend, &applied.tun);

    (dns_errors.len(), route_errors.len(), tun_errors.len())
}

fn delete_recovery_journal_after_successful_disconnect<J>(
    journal_store: &J,
    dns_errors: usize,
    route_errors: usize,
    tun_errors: usize,
    events: &mpsc::Sender<TunnelWorkerEvent>,
) where
    J: RecoveryJournalSink,
{
    if dns_errors != 0 || route_errors != 0 || tun_errors != 0 {
        return;
    }

    if let Err(err) = journal_store.delete() {
        send_workflow_progress(events, 0, format!("recovery journal cleanup failed: {err}"));
    }
}

fn recovery_journal_lifecycle_error(err: RecoveryJournalError) -> TunnelLifecycleError {
    TunnelLifecycleError::new("recovery_journal", err.to_string())
}

pub fn recover_system_runtime_journal_at_startup(
) -> Result<StartupRecoveryReport, StartupRecoveryError> {
    let net_backend =
        LinuxNetlinkRunner::new().map_err(|err| StartupRecoveryError::StaleCleanup {
            message: err.to_string(),
        })?;
    let mut dns_runner = SystemdResolvedCommandRunner::new();
    let journal_store = RecoveryJournalStore::system();

    recover_runtime_journal_at_startup(&net_backend, &mut dns_runner, &journal_store)
}

pub fn recover_runtime_journal_at_startup<N, D, J>(
    net_backend: &N,
    dns_runner: &mut D,
    journal_store: &J,
) -> Result<StartupRecoveryReport, StartupRecoveryError>
where
    N: LinuxNetworkBackend,
    D: DnsCommandRunner,
    J: RecoveryJournalSink,
{
    let Some(journal) = journal_store
        .load()
        .map_err(|err| StartupRecoveryError::Journal {
            message: err.to_string(),
        })?
    else {
        let stale_link_removed = cleanup_stale_managed_link_at_startup(net_backend, dns_runner)?;
        return Ok(StartupRecoveryReport {
            journal_recovered: false,
            stale_link_removed,
        });
    };

    let managed_link_exists = net_backend.link_exists(&journal.ifname).map_err(|err| {
        StartupRecoveryError::StaleCleanup {
            message: err.to_string(),
        }
    })?;

    let dns_errors = match (managed_link_exists, journal.dns.as_ref()) {
        (true, Some(dns)) => {
            revert_dns_command_plan_with(dns_runner, &applied_dns_from_journal(dns)?).len()
        }
        _ => 0,
    };
    let route_state = applied_routes_from_journal(&journal, managed_link_exists)?;
    let route_errors = match route_state.as_ref() {
        Some(routes) => {
            startup_revert_network_routes_with(net_backend, routes, managed_link_exists)
        }
        None => 0,
    };
    let tun_errors = match (managed_link_exists, journal.tun.as_ref()) {
        (true, Some(tun)) => {
            revert_tun_config_with(net_backend, &applied_tun_from_journal(tun)?).len()
        }
        _ => 0,
    };
    let link_errors = if managed_link_exists {
        match net_backend.delete_link_if_exists(&journal.ifname) {
            Ok(_) => 0,
            Err(_) => 1,
        }
    } else {
        0
    };

    if dns_errors == 0 && route_errors == 0 && tun_errors == 0 && link_errors == 0 {
        journal_store
            .delete()
            .map_err(|err| StartupRecoveryError::Journal {
                message: err.to_string(),
            })?;
        Ok(StartupRecoveryReport {
            journal_recovered: true,
            stale_link_removed: true,
        })
    } else {
        Err(StartupRecoveryError::CleanupIncomplete {
            dns_errors,
            route_errors,
            tun_errors,
            link_errors,
        })
    }
}

fn cleanup_stale_managed_link_at_startup<N, D>(
    net_backend: &N,
    dns_runner: &mut D,
) -> Result<bool, StartupRecoveryError>
where
    N: LinuxNetworkBackend,
    D: DnsCommandRunner,
{
    let exists = net_backend
        .link_exists(DAEMON_MANAGED_TUN_IFNAME)
        .map_err(|err| StartupRecoveryError::StaleCleanup {
            message: err.to_string(),
        })?;
    if !exists {
        return Ok(false);
    }

    let command = DnsCommand {
        program: "resolvectl",
        args: vec!["revert".to_owned(), DAEMON_MANAGED_TUN_IFNAME.to_owned()],
        reason: DnsCommandReason::RevertInterface,
    };
    let _ = dns_runner.run(&command);

    net_backend
        .delete_link_if_exists(DAEMON_MANAGED_TUN_IFNAME)
        .map_err(|err| StartupRecoveryError::StaleCleanup {
            message: err.to_string(),
        })
}

fn applied_dns_from_journal(
    journal: &RecoveryDnsJournal,
) -> Result<AppliedDnsState, StartupRecoveryError> {
    Ok(AppliedDnsState {
        revert: journal
            .revert
            .iter()
            .map(dns_command_from_journal)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn dns_command_from_journal(
    journal: &RecoveryDnsCommandJournal,
) -> Result<DnsCommand, StartupRecoveryError> {
    let program = match journal.program.as_str() {
        "resolvectl" => "resolvectl",
        other => {
            return Err(StartupRecoveryError::InvalidJournal {
                message: format!("unsupported DNS program {other:?}"),
            });
        }
    };

    Ok(DnsCommand {
        program,
        args: journal.args.clone(),
        reason: match journal.reason {
            RecoveryDnsCommandReasonJournal::SetServers => DnsCommandReason::SetServers,
            RecoveryDnsCommandReasonJournal::SetDomains => DnsCommandReason::SetDomains,
            RecoveryDnsCommandReasonJournal::RevertInterface => DnsCommandReason::RevertInterface,
        },
    })
}

fn applied_routes_from_journal(
    journal: &RecoveryJournal,
    managed_link_exists: bool,
) -> Result<Option<AppliedNetworkRouteState>, StartupRecoveryError> {
    if journal.routes.is_empty() && journal.ipv6_default_route_block.is_none() {
        return Ok(None);
    }

    let routes = journal
        .routes
        .iter()
        .map(applied_route_from_journal)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|route| {
            managed_link_exists || !route_revert_targets_missing_link(route, &journal.ifname)
        })
        .collect();

    Ok(Some(AppliedNetworkRouteState {
        routes,
        ipv6_default_route_block: journal.ipv6_default_route_block.as_ref().map(|block| {
            oc_oxide_net::AppliedIpv6DefaultRouteBlock {
                created: block.created,
            }
        }),
    }))
}

fn route_revert_targets_missing_link(route: &AppliedRouteChange, missing_ifname: &str) -> bool {
    match &route.revert {
        RouteRevertAction::Delete(created) => created.dev == missing_ifname,
        RouteRevertAction::Restore(previous) => previous.dev == missing_ifname,
    }
}

fn startup_revert_network_routes_with<N>(
    net_backend: &N,
    routes: &AppliedNetworkRouteState,
    managed_link_exists: bool,
) -> usize
where
    N: LinuxNetworkBackend,
{
    let mut errors = 0;

    if routes
        .ipv6_default_route_block
        .as_ref()
        .map(|block| block.created)
        .unwrap_or(false)
        && net_backend.unblock_ipv6_default_route().is_err()
        && managed_link_exists
    {
        errors += 1;
    }

    for route in routes.routes.iter().rev() {
        match &route.revert {
            RouteRevertAction::Restore(previous) => {
                if net_backend.restore_route(previous).is_err() {
                    errors += 1;
                }
            }
            RouteRevertAction::Delete(created) => {
                if net_backend.delete_route(created).is_err() && managed_link_exists {
                    errors += 1;
                }
            }
        }
    }

    errors
}

fn applied_route_from_journal(
    journal: &RecoveryRouteChangeJournal,
) -> Result<AppliedRouteChange, StartupRecoveryError> {
    Ok(AppliedRouteChange {
        applied: planned_route_from_journal(&journal.applied)?,
        revert: match &journal.revert {
            RecoveryRouteRevertJournal::Restore { previous } => {
                RouteRevertAction::Restore(route_snapshot_from_journal(previous)?)
            }
            RecoveryRouteRevertJournal::Delete { created } => {
                RouteRevertAction::Delete(planned_route_from_journal(created)?)
            }
        },
    })
}

fn planned_route_from_journal(
    journal: &RecoveryPlannedRouteJournal,
) -> Result<PlannedRoute, StartupRecoveryError> {
    Ok(PlannedRoute {
        destination: parse_recovery_cidr(&journal.destination)?,
        via: parse_recovery_ipv4_option(journal.via.as_deref())?,
        dev: journal.dev.clone(),
        reason: match journal.reason {
            RecoveryRouteReasonJournal::VpnGatewayPin => RouteReason::VpnGatewayPin,
            RecoveryRouteReasonJournal::DetectedLocalNetwork => RouteReason::DetectedLocalNetwork,
            RecoveryRouteReasonJournal::LocalBypassCidr => RouteReason::LocalBypassCidr,
            RecoveryRouteReasonJournal::VpnInternalNetwork => RouteReason::VpnInternalNetwork,
            RecoveryRouteReasonJournal::VpnSplitInclude => RouteReason::VpnSplitInclude,
            RecoveryRouteReasonJournal::ProfileCompanyRoute => RouteReason::ProfileCompanyRoute,
            RecoveryRouteReasonJournal::VpnSplitExclude => RouteReason::VpnSplitExclude,
            RecoveryRouteReasonJournal::VpnDefaultRoute => RouteReason::VpnDefaultRoute,
        },
    })
}

fn route_snapshot_from_journal(
    journal: &RecoveryRouteSnapshotJournal,
) -> Result<RouteSnapshot, StartupRecoveryError> {
    let mut route = RouteSnapshot::new(
        parse_recovery_cidr(&journal.destination)?,
        parse_recovery_ipv4_option(journal.via.as_deref())?,
        journal.dev.clone(),
    )
    .map_err(|err| StartupRecoveryError::InvalidJournal {
        message: err.to_string(),
    })?;
    if let Some(metric) = journal.metric {
        route = route.with_metric(metric);
    }
    Ok(route)
}

fn applied_tun_from_journal(
    journal: &RecoveryTunJournal,
) -> Result<AppliedTunConfig, StartupRecoveryError> {
    Ok(AppliedTunConfig {
        ifname: journal.ifname.clone(),
        address: parse_recovery_ipv4_option(journal.address.as_deref())?,
        prefix_len: journal.prefix_len,
    })
}

fn parse_recovery_cidr(value: &str) -> Result<Ipv4Cidr, StartupRecoveryError> {
    value
        .parse()
        .map_err(
            |err: oc_oxide_net::NetworkPolicyError| StartupRecoveryError::InvalidJournal {
                message: err.to_string(),
            },
        )
}

fn parse_recovery_ipv4_option(
    value: Option<&str>,
) -> Result<Option<Ipv4Addr>, StartupRecoveryError> {
    value
        .map(|value| {
            value
                .parse()
                .map_err(|_| StartupRecoveryError::InvalidJournal {
                    message: format!("invalid IPv4 address {value:?}"),
                })
        })
        .transpose()
}

fn cleanup_managed_tun_before_setup<N, D>(
    net_backend: &N,
    dns_runner: &mut D,
    events: &mpsc::Sender<TunnelWorkerEvent>,
) -> Result<(), TunnelLifecycleError>
where
    N: LinuxNetworkBackend,
    D: DnsCommandRunner,
{
    let exists = net_backend
        .link_exists(DAEMON_MANAGED_TUN_IFNAME)
        .map_err(|err| TunnelLifecycleError::new("managed_tun_cleanup", err.to_string()))?;
    if !exists {
        return Ok(());
    }

    revert_managed_tun_dns_before_delete(dns_runner, events);

    match net_backend.delete_link_if_exists(DAEMON_MANAGED_TUN_IFNAME) {
        Ok(true) => {
            send_workflow_progress(
                events,
                1,
                format!("removed stale managed TUN interface {DAEMON_MANAGED_TUN_IFNAME}"),
            );
            Ok(())
        }
        Ok(false) => Ok(()),
        Err(err) => Err(TunnelLifecycleError::new(
            "managed_tun_cleanup",
            err.to_string(),
        )),
    }
}

fn revert_managed_tun_dns_before_delete<D>(
    dns_runner: &mut D,
    events: &mpsc::Sender<TunnelWorkerEvent>,
) where
    D: DnsCommandRunner,
{
    let command = DnsCommand {
        program: "resolvectl",
        args: vec!["revert".to_owned(), DAEMON_MANAGED_TUN_IFNAME.to_owned()],
        reason: DnsCommandReason::RevertInterface,
    };

    match dns_runner.run(&command) {
        Ok(()) => send_workflow_progress(
            events,
            2,
            format!("reverted stale managed TUN DNS for {DAEMON_MANAGED_TUN_IFNAME}"),
        ),
        Err(err) => send_workflow_progress(
            events,
            0,
            format!("stale managed TUN DNS cleanup failed: {err}"),
        ),
    }
}

fn cleanup_managed_tun_after_disconnect<N>(
    net_backend: &N,
    events: &mpsc::Sender<TunnelWorkerEvent>,
) -> usize
where
    N: LinuxNetworkBackend,
{
    match net_backend.delete_link_if_exists(DAEMON_MANAGED_TUN_IFNAME) {
        Ok(true) => {
            send_workflow_progress(
                events,
                1,
                format!("removed managed TUN interface {DAEMON_MANAGED_TUN_IFNAME}"),
            );
            0
        }
        Ok(false) => 0,
        Err(err) => {
            send_workflow_progress(events, 0, format!("managed TUN cleanup failed: {err}"));
            1
        }
    }
}

fn send_workflow_progress(
    events: &mpsc::Sender<TunnelWorkerEvent>,
    level: i32,
    message: impl Into<String>,
) {
    let _ = events.send(TunnelWorkerEvent::Lifecycle(TunnelLifecycleStep::Progress(
        ProgressUpdate {
            level,
            message: message.into(),
        },
    )));
}

fn disconnect_reason_from_mainloop_outcome(outcome: MainloopOutcome) -> DisconnectReason {
    match outcome {
        MainloopOutcome::UserCancelled | MainloopOutcome::Detached => {
            DisconnectReason::UserRequested
        }
        MainloopOutcome::CookieRejected => DisconnectReason::AuthFailed,
        MainloopOutcome::ServerTerminated => DisconnectReason::ServerRequested,
        MainloopOutcome::UnrecoverableIo | MainloopOutcome::UnknownError { .. } => {
            DisconnectReason::NetworkError
        }
        MainloopOutcome::ReconnectRequested => DisconnectReason::Unknown,
    }
}

fn tunnel_lifecycle_error(
    operation: &'static str,
) -> impl FnOnce(TunnelError) -> TunnelLifecycleError {
    move |err| TunnelLifecycleError::new(operation, err.to_string())
}

impl TunnelEventSink for DaemonTunnelEventSink {
    fn emit(&mut self, event: TunnelEvent) {
        match event {
            TunnelEvent::Progress(progress) => {
                self.send_lifecycle(TunnelLifecycleStep::Progress(ProgressUpdate {
                    level: progress.level.raw(),
                    message: progress.message,
                }));
            }
            TunnelEvent::AuthRequired(request) => {
                let fallback_form_id = self.next_auth_form_id();
                match auth_prompt_from_request(request, fallback_form_id) {
                    Ok(prompt) => self.send_lifecycle(TunnelLifecycleStep::AuthPrompt(prompt)),
                    Err(err) => self.send_error(TunnelLifecycleError::new(
                        "auth_prompt_bridge_failed",
                        err.to_string(),
                    )),
                }
            }
            TunnelEvent::StateChanged(TunnelState::Disconnecting) => {
                self.send_lifecycle(TunnelLifecycleStep::Disconnecting);
            }
            TunnelEvent::StateChanged(TunnelState::Disconnected | TunnelState::Cancelled) => {
                self.send_lifecycle(TunnelLifecycleStep::Disconnected {
                    reason: DisconnectReason::UserRequested,
                });
            }
            TunnelEvent::StateChanged(state) => {
                self.send_lifecycle(TunnelLifecycleStep::Progress(ProgressUpdate {
                    level: 0,
                    message: format!("tunnel state changed: {state:?}"),
                }));
            }
            TunnelEvent::Error(error) => {
                self.send_error(TunnelLifecycleError::new(
                    error
                        .operation
                        .unwrap_or_else(|| "tunnel_event_error".to_owned()),
                    error.message,
                ));
            }
        }
    }
}

/// Errors returned while controlling a tunnel worker thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelWorkerChannelError {
    CommandChannelClosed,
}

impl fmt::Display for TunnelWorkerChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandChannelClosed => write!(f, "tunnel worker command channel is closed"),
        }
    }
}

impl std::error::Error for TunnelWorkerChannelError {}

impl DaemonCore {
    /// Create an idle daemon state machine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow the current status snapshot.
    pub fn status(&self) -> &DaemonStatus {
        &self.status
    }

    /// Borrow the pending auth form id, if OpenConnect is waiting for input.
    pub fn pending_auth_form_id(&self) -> Option<&str> {
        self.pending_auth_form.as_deref()
    }

    /// Handle one client command and return its immediate response.
    pub fn handle_command(&mut self, command: IpcCommand) -> IpcResponse {
        match command {
            IpcCommand::Connect { profile } => self.connect(profile),
            IpcCommand::ConnectWithProfile { profile, .. } => self.connect(profile),
            IpcCommand::SubmitAuth(submission) => self.submit_auth(submission),
            IpcCommand::Disconnect => self.disconnect(),
            IpcCommand::Status => IpcResponse::Status(self.status.clone()),
            IpcCommand::Diagnostics => IpcResponse::Diagnostics(self.diagnostics()),
            IpcCommand::TailLogs { cursor: _ } => IpcResponse::LogBatch {
                entries: self.logs.clone(),
                next_cursor: None,
            },
        }
    }

    /// Start a tunnel using an injected lifecycle runner.
    ///
    /// This keeps the daemon state/event mapping testable without performing
    /// network I/O. A production runner can own the real libopenconnect tunnel
    /// thread behind this boundary.
    pub fn connect_with_runner<R: TunnelLifecycleRunner>(
        &mut self,
        profile: String,
        runner: &mut R,
    ) -> IpcResponse {
        let response = self.connect(profile.clone());
        if !matches!(response, IpcResponse::Accepted) {
            return response;
        }

        match runner.run(TunnelConnectRequest { profile }) {
            Ok(steps) => {
                for step in steps {
                    self.apply_lifecycle_step(step);
                }
                IpcResponse::Accepted
            }
            Err(err) => {
                self.record_lifecycle_error(err);
                IpcResponse::Error(self.last_error.clone().expect("last error set"))
            }
        }
    }

    /// Apply events received from a tunnel worker thread.
    pub fn apply_worker_event(&mut self, event: TunnelWorkerEvent) {
        match event {
            TunnelWorkerEvent::Lifecycle(step) => self.apply_lifecycle_step(step),
            TunnelWorkerEvent::Error(error) => self.record_lifecycle_error(error),
        }
    }

    /// Apply all currently available events from a tunnel worker thread.
    pub fn drain_worker_events(&mut self, worker: &TunnelWorkerHandle) {
        for event in worker.drain_events() {
            self.apply_worker_event(event);
        }
    }

    /// Validate an auth submission and forward it to the tunnel worker thread.
    pub fn submit_auth_to_worker(
        &mut self,
        submission: AuthSubmission,
        worker: &TunnelWorkerHandle,
    ) -> IpcResponse {
        match self.pending_auth_form.as_deref() {
            Some(form_id) if form_id == submission.form_id => {
                let response = match auth_response_from_submission(submission) {
                    Ok(response) => response,
                    Err(err) => return self.error("invalid_auth_response", err.to_string()),
                };
                if let Err(err) = worker.send(TunnelWorkerCommand::SubmitAuth(response)) {
                    return self.error("tunnel_worker_unavailable", err.to_string());
                }
                self.mark_auth_submitted()
            }
            Some(_) => self.error(
                "auth_form_mismatch",
                "auth response did not match pending form",
            ),
            None => self.error(
                "no_pending_auth",
                "no auth prompt is waiting for a response",
            ),
        }
    }

    /// Record an auth prompt produced by the tunnel thread.
    pub fn emit_auth_prompt(&mut self, prompt: AuthPrompt) {
        self.pending_auth_form = Some(prompt.form_id.clone());
        self.status.state = DaemonState::AwaitingAuth;
        self.push_log(LogLevel::Info, "auth prompt received");
        self.events.push(IpcEvent::AuthPrompt(prompt));
    }

    /// Convert and record an auth request produced by the tunnel thread.
    pub fn emit_auth_request(
        &mut self,
        request: AuthRequest,
        fallback_form_id: impl Into<String>,
    ) -> Result<(), DaemonAuthBridgeError> {
        let prompt = auth_prompt_from_request(request, fallback_form_id)?;
        self.emit_auth_prompt(prompt);
        Ok(())
    }

    /// Record that route/DNS policy has been applied.
    pub fn mark_network_applied(&mut self, applied: NetworkApplied) {
        self.push_log(LogLevel::Info, "network policy applied");
        self.events.push(IpcEvent::NetworkApplied(applied));
    }

    /// Record that the tunnel is connected on an interface.
    pub fn mark_connected(&mut self, interface: impl Into<String>) {
        let interface = interface.into();
        self.status.state = DaemonState::Connected;
        self.status.interface = Some(interface.clone());
        self.push_log(LogLevel::Info, "tunnel connected");
        self.events.push(IpcEvent::Connected { interface });
    }

    /// Consume all queued events.
    pub fn drain_events(&mut self) -> Vec<IpcEvent> {
        std::mem::take(&mut self.events)
    }

    fn connect(&mut self, profile: String) -> IpcResponse {
        if !matches!(
            self.status.state,
            DaemonState::Idle | DaemonState::Disconnected | DaemonState::Error
        ) {
            return self.error("already_active", "a tunnel session is already active");
        }

        self.status = DaemonStatus {
            state: DaemonState::Connecting,
            active_profile: Some(profile),
            interface: None,
        };
        self.pending_auth_form = None;
        self.last_error = None;
        self.push_log(LogLevel::Info, "connect requested");
        self.events.push(IpcEvent::Progress(ProgressUpdate {
            level: 0,
            message: "connect requested".to_owned(),
        }));
        IpcResponse::Accepted
    }

    fn apply_lifecycle_step(&mut self, step: TunnelLifecycleStep) {
        match step {
            TunnelLifecycleStep::Progress(progress) => {
                if !should_emit_progress_to_ipc(&progress) {
                    return;
                }
                self.push_log(LogLevel::Info, "tunnel progress");
                self.events.push(IpcEvent::Progress(progress));
            }
            TunnelLifecycleStep::AuthPrompt(prompt) => self.emit_auth_prompt(prompt),
            TunnelLifecycleStep::NetworkApplied(applied) => self.mark_network_applied(applied),
            TunnelLifecycleStep::Connected { interface } => self.mark_connected(interface),
            TunnelLifecycleStep::Disconnecting => {
                self.status.state = DaemonState::Disconnecting;
                self.push_log(LogLevel::Info, "tunnel disconnecting");
                self.events.push(IpcEvent::Disconnecting);
            }
            TunnelLifecycleStep::NetworkReverted {
                dns_errors,
                route_errors,
                tun_errors,
            } => {
                self.push_log(LogLevel::Info, "network policy reverted");
                self.events.push(IpcEvent::Progress(ProgressUpdate {
                    level: 0,
                    message: format!(
                        "network policy reverted: dns_errors={dns_errors} route_errors={route_errors} tun_errors={tun_errors}"
                    ),
                }));
            }
            TunnelLifecycleStep::Disconnected { reason } => {
                self.status = DaemonStatus {
                    state: DaemonState::Disconnected,
                    active_profile: None,
                    interface: None,
                };
                self.pending_auth_form = None;
                self.push_log(LogLevel::Info, "tunnel disconnected");
                self.events.push(IpcEvent::Disconnected { reason });
            }
        }
    }

    fn record_lifecycle_error(&mut self, err: TunnelLifecycleError) {
        self.status = DaemonStatus {
            state: DaemonState::Error,
            active_profile: None,
            interface: None,
        };
        self.pending_auth_form = None;
        self.last_error = Some(IpcErrorResponse {
            code: err.code.clone(),
            message: err.message.clone(),
        });
        self.push_log(LogLevel::Error, err.message.clone());
        self.events.push(IpcEvent::Error(IpcErrorResponse {
            code: err.code,
            message: err.message,
        }));
    }

    fn submit_auth(&mut self, submission: AuthSubmission) -> IpcResponse {
        match self.pending_auth_form.as_deref() {
            Some(form_id) if form_id == submission.form_id => self.mark_auth_submitted(),
            Some(_) => self.error(
                "auth_form_mismatch",
                "auth response did not match pending form",
            ),
            None => self.error(
                "no_pending_auth",
                "no auth prompt is waiting for a response",
            ),
        }
    }

    fn mark_auth_submitted(&mut self) -> IpcResponse {
        self.pending_auth_form = None;
        self.status.state = DaemonState::Connecting;
        self.push_log(LogLevel::Info, "auth response submitted");
        self.events.push(IpcEvent::Progress(ProgressUpdate {
            level: 0,
            message: "auth response submitted".to_owned(),
        }));
        IpcResponse::Accepted
    }

    fn disconnect(&mut self) -> IpcResponse {
        if matches!(
            self.status.state,
            DaemonState::Idle | DaemonState::Disconnected
        ) {
            self.status.state = DaemonState::Disconnected;
            return IpcResponse::Accepted;
        }

        self.status = DaemonStatus {
            state: DaemonState::Disconnected,
            active_profile: None,
            interface: None,
        };
        self.pending_auth_form = None;
        self.push_log(LogLevel::Info, "disconnect requested");
        self.events.push(IpcEvent::Disconnecting);
        self.events.push(IpcEvent::Disconnected {
            reason: DisconnectReason::UserRequested,
        });
        IpcResponse::Accepted
    }

    fn diagnostics(&self) -> DiagnosticsSnapshot {
        DiagnosticsSnapshot {
            state: self.status.state,
            route_policy: self
                .status
                .interface
                .as_ref()
                .map(|ifname| format!("managed on {ifname}")),
            dns_policy: self
                .status
                .interface
                .as_ref()
                .map(|ifname| format!("managed on {ifname}")),
            last_error: self.last_error.clone(),
        }
    }

    fn error(&mut self, code: impl Into<String>, message: impl Into<String>) -> IpcResponse {
        let error = IpcErrorResponse {
            code: code.into(),
            message: message.into(),
        };
        self.last_error = Some(error.clone());
        self.push_log(LogLevel::Warn, error.message.clone());
        IpcResponse::Error(error)
    }

    fn push_log(&mut self, level: LogLevel, message: impl Into<String>) {
        self.logs.push(LogEntry {
            level,
            message: message.into(),
        });
    }
}

fn should_emit_progress_to_ipc(progress: &ProgressUpdate) -> bool {
    progress.level < 3
}

/// Convert a tunnel auth request into an IPC prompt without submitted answers.
pub fn auth_prompt_from_request(
    request: AuthRequest,
    fallback_form_id: impl Into<String>,
) -> Result<AuthPrompt, DaemonAuthBridgeError> {
    let form_id = request.form_id.unwrap_or_else(|| fallback_form_id.into());
    Ok(AuthPrompt {
        form_id,
        title: request.title,
        message: request.message,
        error: request.error,
        fields: request
            .fields
            .into_iter()
            .map(|field| {
                Ok(oc_oxide_ipc::AuthPromptField {
                    id: field.id,
                    label: field.label,
                    kind: match field.kind {
                        AuthFieldKind::Text { secret } => {
                            oc_oxide_ipc::AuthPromptFieldKind::Text { secret }
                        }
                        AuthFieldKind::Password => oc_oxide_ipc::AuthPromptFieldKind::Password,
                        AuthFieldKind::Otp => oc_oxide_ipc::AuthPromptFieldKind::Otp,
                        AuthFieldKind::Select { choices } => {
                            oc_oxide_ipc::AuthPromptFieldKind::Select {
                                choices: choices
                                    .into_iter()
                                    .map(ipc_choice_from_tunnel_choice)
                                    .collect::<Result<Vec<_>, _>>()?,
                            }
                        }
                    },
                    required: field.required,
                })
            })
            .collect::<Result<Vec<_>, DaemonAuthBridgeError>>()?,
    })
}

/// Convert transient IPC auth answers back into tunnel auth answers.
pub fn auth_response_from_submission(
    submission: AuthSubmission,
) -> Result<AuthResponse, DaemonAuthBridgeError> {
    let form_id = submission.form_id.clone();
    let answers = submission
        .fields
        .into_iter()
        .map(|field| {
            if field.secret {
                AuthAnswer::secret(field.id, field.value)
            } else {
                AuthAnswer::text(field.id, field.value)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(AuthResponse::new(answers)?.with_form_id(form_id)?)
}

/// Copy OpenConnect IP configuration into policy-planning input.
///
/// This bridge intentionally copies Rust-owned snapshot fields only. It does
/// not borrow libopenconnect memory and does not apply any host networking.
pub fn tunnel_policy_input_from_ip_info(
    ip_info: &IpInfoSnapshot,
    ifname: impl Into<String>,
) -> TunnelPolicyInput {
    TunnelPolicyInput {
        ifname: ifname.into(),
        address: ip_info.address.clone(),
        netmask: ip_info.netmask.clone(),
        mtu: ip_info.mtu,
        dns_servers: ip_info.dns.clone(),
        default_domain: ip_info.domain.clone(),
        split_dns: ip_info
            .split_dns
            .iter()
            .map(|route| route.route.clone())
            .collect(),
        split_includes: ip_info
            .split_includes
            .iter()
            .map(|route| route.route.clone())
            .collect(),
        split_excludes: ip_info
            .split_excludes
            .iter()
            .map(|route| route.route.clone())
            .collect(),
        gateway_addr: ip_info.gateway_addr.clone(),
    }
}

/// Plan route/DNS/TUN policy for a daemon-managed tunnel without applying it.
///
/// A real tunnel runner should call this after CSTP setup has produced copied
/// tunnel metadata and before applying the plan through the policy backend.
pub fn plan_daemon_network_policy(
    profile: &VpnProfile,
    default_route: &DefaultRouteSnapshot,
    tunnel_input: &TunnelPolicyInput,
) -> Result<DaemonNetworkPlan, DaemonNetworkPlanError> {
    plan_daemon_network_policy_with_detected_local_cidrs(
        profile,
        default_route,
        std::iter::empty::<Ipv4Cidr>(),
        tunnel_input,
    )
}

/// Plan daemon connected policy with local CIDRs discovered before VPN apply.
///
/// This is the single connected policy path: daemon-managed profiles always
/// use VPN default route and full DNS, while preserving the VPN gateway,
/// detected local LANs, and profile-declared local bypass CIDRs.
pub fn plan_daemon_network_policy_with_detected_local_cidrs<I>(
    profile: &VpnProfile,
    default_route: &DefaultRouteSnapshot,
    detected_local_cidrs: I,
    tunnel_input: &TunnelPolicyInput,
) -> Result<DaemonNetworkPlan, DaemonNetworkPlanError>
where
    I: IntoIterator<Item = Ipv4Cidr>,
{
    let route_policy = NetworkPolicy::new(RouteMode::Full)
        .with_detected_local_cidrs(detected_local_cidrs.into_iter().collect())
        .with_local_bypass_cidrs(profile.local_bypass_cidrs().to_vec());
    let policy = build_policy_plan_from_tunnel_input_with_company_domains(
        tunnel_input,
        default_route,
        &route_policy,
        DnsMode::Full,
        profile.company_domains().iter().cloned(),
    )?;
    let applied = network_applied_from_policy_plan(&policy);

    Ok(DaemonNetworkPlan { policy, applied })
}

/// Summarize a policy plan into the non-secret IPC event payload.
pub fn network_applied_from_policy_plan(policy: &PolicyPlan) -> NetworkApplied {
    NetworkApplied {
        route_commands: policy.routes.routes.len()
            + usize::from(policy.routes.block_ipv6_default_route),
        dns_commands: policy.dns.apply.len(),
    }
}

fn ipc_choice_from_tunnel_choice(
    choice: TunnelAuthChoice,
) -> Result<IpcAuthChoice, DaemonAuthBridgeError> {
    Ok(IpcAuthChoice {
        value: choice.value,
        label: choice.label,
    })
}

impl Default for DaemonCore {
    fn default() -> Self {
        Self {
            status: default_status(),
            pending_auth_form: None,
            last_error: None,
            events: Vec::new(),
            logs: Vec::new(),
        }
    }
}

fn default_status() -> DaemonStatus {
    DaemonStatus {
        state: DaemonState::Idle,
        active_profile: None,
        interface: None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_policy_with_recovery_journal, auth_response_from_submission,
        cleanup_managed_tun_after_disconnect, cleanup_managed_tun_before_setup,
        default_daemon_socket_path_from_env, delete_recovery_journal_after_successful_disconnect,
        disconnect_reason_from_mainloop_outcome, handle_ipc_command_line, match_authgroup_choice,
        plan_daemon_network_policy, plan_daemon_network_policy_with_detected_local_cidrs,
        polkit_process_subject, recover_runtime_journal_at_startup,
        revert_policy_error_counts_with_journal, shutdown_controller, socket_mode_for_owner,
        spawn_workflow_command_pump, tunnel_policy_input_from_ip_info, DaemonCore,
        DaemonTunnelEventSink, DaemonWorkerController, ImportedProfileResolver, LocalProfileError,
        LocalProfileResolver, OpenConnectTunnelWorker, OpenConnectWorkflow, RecoveryJournal,
        RecoveryJournalError, RecoveryJournalSink, RecoveryJournalStage, RecoveryJournalStore,
        StartupRecoveryError, SystemOpenConnectWorkerFactory, TunnelConnectRequest,
        TunnelLifecycleError, TunnelLifecycleRunner, TunnelLifecycleStep, TunnelWorker,
        TunnelWorkerCommand, TunnelWorkerEvent, TunnelWorkerFactory, TunnelWorkerHandle,
        UnixPeerCredentials, VpnProfileResolver, WorkerAuthHandler, WorkflowAuthHandler,
        DAEMON_MANAGED_TUN_IFNAME,
    };
    use oc_oxide_auth::{
        AuthAnswer, AuthChoice as TunnelAuthChoice, AuthField, AuthFormDecision, AuthFormHandler,
        AuthRequest, AuthResponse,
    };
    use oc_oxide_config::{ServerUrl, VpnProfile};
    use oc_oxide_dns::{
        AppliedDnsState, DnsCommand, DnsCommandPlan, DnsCommandReason, DnsCommandRunner, DnsMode,
        DnsPolicyError,
    };
    use oc_oxide_ipc::{
        decode_command_line, decode_event_line, decode_response_line, AuthPrompt, AuthPromptField,
        AuthPromptFieldKind, AuthSubmission, AuthSubmittedField, DaemonState, DisconnectReason,
        IpcCommand, IpcEvent, IpcResponse, NetworkApplied,
    };
    use oc_oxide_net::{
        AppliedIpv6DefaultRouteBlock, AppliedNetworkRouteState, AppliedRouteChange,
        AppliedTunConfig, DefaultRouteSnapshot, Ipv4Cidr, LinuxNetworkBackend, NetworkPolicyError,
        NetworkRoutePlan, PlannedRoute, RouteMode, RouteReason, RouteRevertAction, RouteSnapshot,
        TunConfig,
    };
    use oc_oxide_policy::{AppliedPolicyState, PolicyPlan, TunnelPolicyInput};
    use oc_oxide_tunnel::{
        IpInfoSnapshot, MainloopOutcome, ProgressEvent, SplitRoute, TunnelEvent, TunnelEventError,
        TunnelEventSink, TunnelState,
    };
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    use super::{parse_socket_owner, should_cancel_owned_connect};

    #[test]
    fn empty_daemon_socket_env_falls_back_to_default_path() {
        assert_eq!(
            default_daemon_socket_path_from_env(None),
            PathBuf::from("/tmp/oc-oxide-daemon.sock")
        );
        assert_eq!(
            default_daemon_socket_path_from_env(Some(OsString::from(""))),
            PathBuf::from("/tmp/oc-oxide-daemon.sock")
        );
        assert_eq!(
            default_daemon_socket_path_from_env(Some(OsString::from("/tmp/custom.sock"))),
            PathBuf::from("/tmp/custom.sock")
        );
    }

    #[cfg(unix)]
    #[test]
    fn socket_permissions_allow_clients_to_reach_polkit_gate() {
        assert_eq!(
            parse_socket_owner(Some("1000"), Some("1000")),
            Some((1000, 1000))
        );
        assert_eq!(parse_socket_owner(Some("1000"), None), None);
        assert_eq!(parse_socket_owner(Some("bad"), Some("1000")), None);

        assert_eq!(socket_mode_for_owner(Some((1000, 1000))), 0o666);
        assert_eq!(socket_mode_for_owner(None), 0o666);
    }

    #[cfg(unix)]
    #[test]
    fn polkit_subject_falls_back_to_pid_and_uid_without_start_time() {
        assert_eq!(
            polkit_process_subject(UnixPeerCredentials {
                pid: u32::MAX,
                uid: 1000
            }),
            format!("{},,1000", u32::MAX)
        );
    }

    #[cfg(unix)]
    #[test]
    fn ipc_connect_owner_disconnect_cancels_only_before_connected() {
        assert!(should_cancel_owned_connect(true, DaemonState::Configuring));
        assert!(should_cancel_owned_connect(true, DaemonState::AwaitingAuth));
        assert!(should_cancel_owned_connect(true, DaemonState::Connecting));
        assert!(!should_cancel_owned_connect(true, DaemonState::Connected));
        assert!(!should_cancel_owned_connect(
            true,
            DaemonState::Disconnected
        ));
        assert!(!should_cancel_owned_connect(
            false,
            DaemonState::AwaitingAuth
        ));
    }

    #[test]
    fn reports_idle_status_before_connect() {
        let mut core = DaemonCore::new();

        let response = core.handle_command(IpcCommand::Status);

        assert_eq!(
            response,
            IpcResponse::Status(oc_oxide_ipc::DaemonStatus {
                state: DaemonState::Idle,
                active_profile: None,
                interface: None,
            })
        );
        assert!(core.drain_events().is_empty());
    }

    #[test]
    fn connect_records_profile_and_emits_progress_without_network() {
        let mut core = DaemonCore::new();

        let response = core.handle_command(IpcCommand::Connect {
            profile: "office".to_owned(),
        });

        assert_eq!(response, IpcResponse::Accepted);
        assert_eq!(core.status().state, DaemonState::Connecting);
        assert_eq!(core.status().active_profile.as_deref(), Some("office"));
        assert_eq!(
            core.drain_events(),
            vec![IpcEvent::Progress(oc_oxide_ipc::ProgressUpdate {
                level: 0,
                message: "connect requested".to_owned(),
            })]
        );
    }

    #[test]
    fn rejects_second_connect_while_active() {
        let mut core = DaemonCore::new();
        assert_eq!(
            core.handle_command(IpcCommand::Connect {
                profile: "office".to_owned(),
            }),
            IpcResponse::Accepted
        );

        let response = core.handle_command(IpcCommand::Connect {
            profile: "other".to_owned(),
        });

        assert!(matches!(
            response,
            IpcResponse::Error(error) if error.code == "already_active"
        ));
        assert_eq!(core.status().active_profile.as_deref(), Some("office"));
    }

    #[test]
    fn auth_prompt_then_matching_submit_returns_to_connecting() {
        let mut core = DaemonCore::new();
        core.handle_command(IpcCommand::Connect {
            profile: "office".to_owned(),
        });
        core.emit_auth_prompt(sample_prompt());

        let response = core.handle_command(IpcCommand::SubmitAuth(
            AuthSubmission::new(
                "form-1",
                vec![
                    AuthSubmittedField::new("username", "alice", false).unwrap(),
                    AuthSubmittedField::new("password", "secret", true).unwrap(),
                ],
            )
            .unwrap(),
        ));

        assert_eq!(response, IpcResponse::Accepted);
        assert_eq!(core.status().state, DaemonState::Connecting);
        assert!(core.pending_auth_form_id().is_none());

        let debug = format!("{core:?}");
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn emits_ipc_auth_prompt_from_tunnel_auth_request() {
        let mut core = DaemonCore::new();
        let request = sample_auth_request();

        core.emit_auth_request(request, "fallback-form").unwrap();

        assert_eq!(core.status().state, DaemonState::AwaitingAuth);
        assert_eq!(core.pending_auth_form_id(), Some("form-1"));
        let events = core.drain_events();
        let prompt = match events.as_slice() {
            [IpcEvent::AuthPrompt(prompt)] => prompt,
            other => panic!("unexpected events: {other:?}"),
        };
        assert_eq!(prompt.title, "Login");
        assert_eq!(prompt.fields.len(), 3);
        assert!(matches!(
            prompt.fields[1].kind,
            AuthPromptFieldKind::Password
        ));
        assert!(matches!(
            prompt.fields[2].kind,
            AuthPromptFieldKind::Select { ref choices } if choices[0].value == "GroupA"
        ));
    }

    #[test]
    fn converts_ipc_auth_submission_back_to_redacted_tunnel_response() {
        let submission = AuthSubmission::new(
            "form-1",
            vec![
                AuthSubmittedField::new("username", "alice", false).unwrap(),
                AuthSubmittedField::new("password", "do-not-log", true).unwrap(),
            ],
        )
        .unwrap();

        let response = auth_response_from_submission(submission).unwrap();
        let debug = format!("{response:?}");

        assert_eq!(response.form_id.as_deref(), Some("form-1"));
        assert!(debug.contains("alice"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("do-not-log"));
    }

    #[test]
    fn submit_auth_to_worker_forwards_response_without_network() {
        let mut core = DaemonCore::new();
        core.handle_command(IpcCommand::Connect {
            profile: "office".to_owned(),
        });
        core.emit_auth_prompt(sample_prompt());
        let worker = TunnelWorkerHandle::spawn(AuthForwardingWorker);

        let response = core.submit_auth_to_worker(
            AuthSubmission::new(
                "form-1",
                vec![AuthSubmittedField::new("password", "do-not-log", true).unwrap()],
            )
            .unwrap(),
            &worker,
        );

        assert_eq!(response, IpcResponse::Accepted);
        assert_eq!(core.status().state, DaemonState::Connecting);
        assert!(core.pending_auth_form_id().is_none());
        let event = recv_worker_event(&worker);
        assert!(matches!(
            event,
            TunnelWorkerEvent::Lifecycle(TunnelLifecycleStep::Progress(progress))
                if progress.message == "worker received auth response"
        ));
        assert!(!format!("{core:?}").contains("do-not-log"));
        worker.join().unwrap();
    }

    #[test]
    fn rejects_auth_submit_without_matching_prompt() {
        let mut core = DaemonCore::new();

        let response = core.handle_command(IpcCommand::SubmitAuth(
            AuthSubmission::new(
                "form-1",
                vec![AuthSubmittedField::new("password", "secret", true).unwrap()],
            )
            .unwrap(),
        ));

        assert!(matches!(
            response,
            IpcResponse::Error(error) if error.code == "no_pending_auth"
        ));
        assert_eq!(core.status().state, DaemonState::Idle);
    }

    #[test]
    fn network_and_connected_events_update_diagnostics() {
        let mut core = DaemonCore::new();
        core.handle_command(IpcCommand::Connect {
            profile: "office".to_owned(),
        });

        core.mark_network_applied(NetworkApplied {
            route_commands: 4,
            dns_commands: 2,
        });
        core.mark_connected("tun0");

        let diagnostics = match core.handle_command(IpcCommand::Diagnostics) {
            IpcResponse::Diagnostics(diagnostics) => diagnostics,
            other => panic!("unexpected response: {other:?}"),
        };

        assert_eq!(diagnostics.state, DaemonState::Connected);
        assert_eq!(diagnostics.route_policy.as_deref(), Some("managed on tun0"));
        assert_eq!(diagnostics.dns_policy.as_deref(), Some("managed on tun0"));
        assert!(core.drain_events().contains(&IpcEvent::Connected {
            interface: "tun0".to_owned()
        }));
    }

    #[test]
    fn connect_with_runner_maps_tunnel_lifecycle_steps() {
        let mut core = DaemonCore::new();
        let mut runner = ScriptedTunnelRunner {
            steps: vec![
                TunnelLifecycleStep::Progress(oc_oxide_ipc::ProgressUpdate {
                    level: 1,
                    message: "cstp connected".to_owned(),
                }),
                TunnelLifecycleStep::NetworkApplied(NetworkApplied {
                    route_commands: 3,
                    dns_commands: 2,
                }),
                TunnelLifecycleStep::Connected {
                    interface: "tun0".to_owned(),
                },
            ],
            error: None,
            seen_profile: None,
        };

        let response = core.connect_with_runner("office".to_owned(), &mut runner);

        assert_eq!(response, IpcResponse::Accepted);
        assert_eq!(runner.seen_profile.as_deref(), Some("office"));
        assert_eq!(core.status().state, DaemonState::Connected);
        assert_eq!(core.status().interface.as_deref(), Some("tun0"));
        assert!(core
            .drain_events()
            .contains(&IpcEvent::NetworkApplied(NetworkApplied {
                route_commands: 3,
                dns_commands: 2,
            })));
    }

    #[test]
    fn daemon_core_suppresses_trace_progress_from_ipc_events_without_network() {
        let mut core = DaemonCore::new();

        core.apply_lifecycle_step(TunnelLifecycleStep::Progress(
            oc_oxide_ipc::ProgressUpdate {
                level: 3,
                message: "RX packet trace".to_owned(),
            },
        ));
        core.apply_lifecycle_step(TunnelLifecycleStep::Progress(
            oc_oxide_ipc::ProgressUpdate {
                level: 2,
                message: "CSTP connected".to_owned(),
            },
        ));

        assert_eq!(
            core.drain_events(),
            vec![IpcEvent::Progress(oc_oxide_ipc::ProgressUpdate {
                level: 2,
                message: "CSTP connected".to_owned(),
            })]
        );
    }

    #[test]
    fn connect_with_runner_maps_tunnel_error_without_secret_material() {
        let mut core = DaemonCore::new();
        let mut runner = ScriptedTunnelRunner {
            steps: Vec::new(),
            error: Some(TunnelLifecycleError::new(
                "tunnel_failed",
                "openconnect_obtain_cookie failed",
            )),
            seen_profile: None,
        };

        let response = core.connect_with_runner("office".to_owned(), &mut runner);

        assert!(matches!(
            response,
            IpcResponse::Error(error) if error.code == "tunnel_failed"
        ));
        assert_eq!(core.status().state, DaemonState::Error);
        assert_eq!(core.status().active_profile, None);
        assert_eq!(core.pending_auth_form_id(), None);
        assert!(matches!(
            core.handle_command(IpcCommand::Connect {
                profile: "office".to_owned(),
            }),
            IpcResponse::Accepted
        ));
        assert!(!format!("{core:?}").contains("password"));
        assert!(core
            .drain_events()
            .iter()
            .any(|event| matches!(event, IpcEvent::Error(error) if error.code == "tunnel_failed")));
    }

    #[test]
    fn tunnel_worker_channel_drives_daemon_lifecycle_without_network() {
        let mut core = DaemonCore::new();
        let worker = TunnelWorkerHandle::spawn(ScriptedChannelWorker);

        assert_eq!(
            core.handle_command(IpcCommand::Connect {
                profile: "office".to_owned(),
            }),
            IpcResponse::Accepted
        );
        worker
            .send(TunnelWorkerCommand::Connect(TunnelConnectRequest {
                profile: "office".to_owned(),
            }))
            .unwrap();

        core.apply_worker_event(recv_worker_event(&worker));
        core.apply_worker_event(recv_worker_event(&worker));

        assert_eq!(core.status().state, DaemonState::Connected);
        assert_eq!(core.status().interface.as_deref(), Some("tun-worker0"));
        assert!(core.drain_events().contains(&IpcEvent::Connected {
            interface: "tun-worker0".to_owned()
        }));

        worker.send(TunnelWorkerCommand::Disconnect).unwrap();
        core.apply_worker_event(recv_worker_event(&worker));

        assert_eq!(core.status().state, DaemonState::Disconnected);
        assert!(core
            .drain_events()
            .iter()
            .any(|event| matches!(event, IpcEvent::Disconnected { .. })));
        worker.join().unwrap();
    }

    #[test]
    fn tunnel_worker_cancel_reports_revert_lifecycle_without_network() {
        let mut core = DaemonCore::new();
        let worker = TunnelWorkerHandle::spawn(ScriptedChannelWorker);

        assert_eq!(
            core.handle_command(IpcCommand::Connect {
                profile: "office".to_owned(),
            }),
            IpcResponse::Accepted
        );
        worker
            .send(TunnelWorkerCommand::Connect(TunnelConnectRequest {
                profile: "office".to_owned(),
            }))
            .unwrap();
        core.apply_worker_event(recv_worker_event(&worker));
        core.apply_worker_event(recv_worker_event(&worker));
        core.drain_events();

        worker.send(TunnelWorkerCommand::Cancel).unwrap();
        core.apply_worker_event(recv_worker_event(&worker));
        core.apply_worker_event(recv_worker_event(&worker));
        core.apply_worker_event(recv_worker_event(&worker));

        assert_eq!(core.status().state, DaemonState::Disconnected);
        let events = core.drain_events();
        assert!(events.contains(&IpcEvent::Disconnecting));
        assert!(events.iter().any(|event| {
            matches!(
                event,
                IpcEvent::Progress(progress)
                    if progress.message == "network policy reverted: dns_errors=0 route_errors=0 tun_errors=0"
            )
        }));
        assert!(events
            .iter()
            .any(|event| matches!(event, IpcEvent::Disconnected { .. })));
        worker.join().unwrap();
    }

    #[test]
    fn tunnel_worker_error_event_maps_to_daemon_error_without_network() {
        let mut core = DaemonCore::new();
        let worker = TunnelWorkerHandle::spawn(ErrorChannelWorker);

        assert_eq!(
            core.handle_command(IpcCommand::Connect {
                profile: "office".to_owned(),
            }),
            IpcResponse::Accepted
        );
        worker
            .send(TunnelWorkerCommand::Connect(TunnelConnectRequest {
                profile: "office".to_owned(),
            }))
            .unwrap();

        core.apply_worker_event(recv_worker_event(&worker));

        assert_eq!(core.status().state, DaemonState::Error);
        assert_eq!(core.status().active_profile, None);
        assert!(matches!(
            core.handle_command(IpcCommand::Connect {
                profile: "office".to_owned(),
            }),
            IpcResponse::Accepted
        ));
        assert!(core.drain_events().iter().any(
            |event| matches!(event, IpcEvent::Error(error) if error.code == "scripted_failure")
        ));
        worker.join().unwrap();
    }

    #[test]
    fn worker_controller_owns_command_lifecycle_without_network() {
        let mut controller = DaemonWorkerController::new(ControllerScriptedWorkerFactory);

        assert_eq!(
            controller.handle_command(IpcCommand::Connect {
                profile: "office".to_owned(),
            }),
            IpcResponse::Accepted
        );
        assert!(controller.active_worker_present());
        controller
            .recv_worker_event_timeout(Duration::from_secs(1))
            .unwrap();
        controller
            .recv_worker_event_timeout(Duration::from_secs(1))
            .unwrap();
        assert_eq!(controller.core().status().state, DaemonState::AwaitingAuth);
        assert_eq!(controller.core().pending_auth_form_id(), Some("form-1"));

        let response = controller.handle_command(IpcCommand::SubmitAuth(
            AuthSubmission::new(
                "form-1",
                vec![AuthSubmittedField::new("password", "do-not-log", true).unwrap()],
            )
            .unwrap(),
        ));

        assert_eq!(response, IpcResponse::Accepted);
        controller
            .recv_worker_event_timeout(Duration::from_secs(1))
            .unwrap();
        controller
            .recv_worker_event_timeout(Duration::from_secs(1))
            .unwrap();
        assert_eq!(controller.core().status().state, DaemonState::Connected);
        assert_eq!(
            controller.core().status().interface.as_deref(),
            Some("tun-controller0")
        );
        assert!(!format!("{:?}", controller.core()).contains("do-not-log"));

        assert_eq!(
            controller.handle_command(IpcCommand::Disconnect),
            IpcResponse::Accepted
        );
        controller
            .recv_worker_event_timeout(Duration::from_secs(1))
            .unwrap();
        controller
            .recv_worker_event_timeout(Duration::from_secs(1))
            .unwrap();
        controller
            .recv_worker_event_timeout(Duration::from_secs(1))
            .unwrap();

        assert!(!controller.active_worker_present());
        assert_eq!(controller.core().status().state, DaemonState::Disconnected);
        let events = controller.drain_events();
        assert!(events.contains(&IpcEvent::Disconnecting));
        assert!(events
            .iter()
            .any(|event| matches!(event, IpcEvent::Disconnected { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn daemon_shutdown_cancels_active_worker_without_network() {
        let controller = Arc::new(Mutex::new(DaemonWorkerController::new(
            ControllerScriptedWorkerFactory,
        )));

        {
            let mut guard = controller.lock().unwrap();
            assert_eq!(
                guard.handle_command(IpcCommand::Connect {
                    profile: "office".to_owned(),
                }),
                IpcResponse::Accepted
            );
            guard
                .recv_worker_event_timeout(Duration::from_secs(1))
                .unwrap();
            guard
                .recv_worker_event_timeout(Duration::from_secs(1))
                .unwrap();
            assert!(guard.active_worker_present());
            assert_eq!(guard.core().status().state, DaemonState::AwaitingAuth);
        }

        shutdown_controller(&controller).unwrap();

        let mut guard = controller.lock().unwrap();
        assert!(!guard.active_worker_present());
        assert_eq!(guard.core().status().state, DaemonState::Disconnected);
        let events = guard.drain_events();
        assert!(events.contains(&IpcEvent::Disconnecting));
        assert!(events
            .iter()
            .any(|event| matches!(event, IpcEvent::Disconnected { .. })));
    }

    #[test]
    fn ipc_command_line_handles_response_and_events_without_network() {
        let mut controller = DaemonWorkerController::new(ControllerScriptedWorkerFactory);

        let mut lines = handle_ipc_command_line(
            &mut controller,
            "{\"type\":\"connect\",\"profile\":\"office\"}\n",
        )
        .unwrap();
        assert_eq!(
            decode_response_line(&lines[0]).unwrap(),
            IpcResponse::Accepted
        );

        wait_for_controller_state(&mut controller, DaemonState::AwaitingAuth);
        let status_lines =
            handle_ipc_command_line(&mut controller, "{\"type\":\"status\"}\n").unwrap();

        assert!(matches!(
            decode_response_line(&status_lines[0]).unwrap(),
            IpcResponse::Status(status) if status.state == DaemonState::AwaitingAuth
        ));
        lines.extend(status_lines);
        assert!(lines.iter().any(|line| match decode_event_line(line) {
            Ok(IpcEvent::AuthPrompt(AuthPrompt { form_id, .. })) => form_id == "form-1",
            _ => false,
        }));
    }

    fn wait_for_controller_state<F>(
        controller: &mut DaemonWorkerController<F>,
        expected: DaemonState,
    ) where
        F: TunnelWorkerFactory,
    {
        for _ in 0..4 {
            if controller.core().status().state == expected {
                return;
            }
            controller
                .recv_worker_event_timeout(Duration::from_secs(1))
                .unwrap();
        }

        assert_eq!(controller.core().status().state, expected);
    }

    #[test]
    fn daemon_tunnel_event_sink_maps_tunnel_events_without_network() {
        let (tx, rx) = mpsc::channel();
        let mut sink = DaemonTunnelEventSink::new(tx);

        sink.emit(TunnelEvent::Progress(ProgressEvent::new(
            2,
            "CSTP connected",
        )));
        sink.emit(TunnelEvent::AuthRequired(
            AuthRequest::new(
                "Second factor",
                vec![AuthField::password("otp", "OTP").unwrap()],
            )
            .unwrap(),
        ));
        sink.emit(TunnelEvent::StateChanged(TunnelState::Disconnecting));
        sink.emit(TunnelEvent::StateChanged(TunnelState::Disconnected));
        sink.emit(TunnelEvent::Error(
            TunnelEventError::new("OpenConnect setup failed").with_operation("openconnect_setup"),
        ));

        let events = rx.try_iter().collect::<Vec<_>>();
        assert!(matches!(
            &events[0],
            TunnelWorkerEvent::Lifecycle(TunnelLifecycleStep::Progress(progress))
                if progress.level == 2 && progress.message == "CSTP connected"
        ));
        assert!(matches!(
            &events[1],
            TunnelWorkerEvent::Lifecycle(TunnelLifecycleStep::AuthPrompt(prompt))
                if prompt.form_id == "openconnect-auth-1"
                    && prompt.title == "Second factor"
                    && matches!(prompt.fields[0].kind, AuthPromptFieldKind::Password)
        ));
        assert!(matches!(
            events[2],
            TunnelWorkerEvent::Lifecycle(TunnelLifecycleStep::Disconnecting)
        ));
        assert!(matches!(
            events[3],
            TunnelWorkerEvent::Lifecycle(TunnelLifecycleStep::Disconnected {
                reason: DisconnectReason::UserRequested
            })
        ));
        assert!(matches!(
            &events[4],
            TunnelWorkerEvent::Error(error)
                if error.code == "openconnect_setup"
                    && error.message == "OpenConnect setup failed"
        ));
        assert!(!format!("{events:?}").contains("do-not-log"));
    }

    #[test]
    fn daemon_tunnel_event_sink_suppresses_trace_progress_without_network() {
        let (tx, rx) = mpsc::channel();
        let mut sink = DaemonTunnelEventSink::new(tx);

        sink.emit(TunnelEvent::Progress(ProgressEvent::new(
            3,
            "RX packet trace",
        )));
        sink.emit(TunnelEvent::Progress(ProgressEvent::new(
            2,
            "CSTP connected",
        )));

        let events = rx.try_iter().collect::<Vec<_>>();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0],
            TunnelWorkerEvent::Lifecycle(TunnelLifecycleStep::Progress(progress))
                if progress.level == 2 && progress.message == "CSTP connected"
        ));
    }

    #[test]
    fn openconnect_worker_resolves_profile_and_runs_workflow_without_network() {
        let worker = TunnelWorkerHandle::spawn(OpenConnectTunnelWorker::new(
            StaticProfileResolver::new(sample_vpn_profile()),
            RecordingOpenConnectWorkflow,
        ));

        worker
            .send(TunnelWorkerCommand::Connect(TunnelConnectRequest {
                profile: "office".to_owned(),
            }))
            .unwrap();

        assert!(matches!(
            recv_worker_event(&worker),
            TunnelWorkerEvent::Lifecycle(TunnelLifecycleStep::Progress(progress))
                if progress.message == "profile resolved"
        ));
        assert!(matches!(
            recv_worker_event(&worker),
            TunnelWorkerEvent::Lifecycle(TunnelLifecycleStep::Progress(progress))
                if progress.message == "workflow running office"
        ));

        worker.send(TunnelWorkerCommand::Cancel).unwrap();
        assert!(matches!(
            recv_worker_event(&worker),
            TunnelWorkerEvent::Lifecycle(TunnelLifecycleStep::Disconnecting)
        ));
        assert!(matches!(
            recv_worker_event(&worker),
            TunnelWorkerEvent::Lifecycle(TunnelLifecycleStep::Disconnected {
                reason: DisconnectReason::UserRequested
            })
        ));
        worker.join().unwrap();
    }

    #[test]
    fn openconnect_worker_reports_profile_resolution_errors_without_network() {
        let worker = TunnelWorkerHandle::spawn(OpenConnectTunnelWorker::new(
            StaticProfileResolver::new(sample_vpn_profile()),
            RecordingOpenConnectWorkflow,
        ));

        worker
            .send(TunnelWorkerCommand::Connect(TunnelConnectRequest {
                profile: "missing".to_owned(),
            }))
            .unwrap();

        assert!(matches!(
            recv_worker_event(&worker),
            TunnelWorkerEvent::Error(error)
                if error.code == "profile_not_found"
                    && error.message == "profile missing was not found"
        ));
        worker.join().unwrap();
    }

    #[test]
    fn system_worker_factory_reports_startup_or_profile_error_without_vpn_network() {
        let mut factory =
            SystemOpenConnectWorkerFactory::new(LocalProfileResolver::new("/tmp/oc-oxide-missing"));
        let worker = factory.spawn_worker();

        worker
            .send(TunnelWorkerCommand::Connect(TunnelConnectRequest {
                profile: "missing".to_owned(),
            }))
            .unwrap();

        let event = recv_worker_event(&worker);
        assert!(matches!(
            event,
            TunnelWorkerEvent::Error(error)
                if error.code == "profile_load_failed" || error.code == "netlink_init"
        ));
        worker.join().unwrap();
    }

    #[test]
    fn systemd_unit_starts_idle_daemon_without_profile_auto_connect() {
        let unit = include_str!("../../../packaging/systemd/oc-oxide-daemon.service");

        assert!(unit.contains("Environment=OC_OXIDE_PROFILE_DIR=/etc/oc-oxide/profiles"));
        assert!(!unit.contains("Group=oc-oxide"));
        assert!(unit.contains("ExecStart=/usr/local/bin/oc-oxide-daemon serve"));
        assert!(!unit.contains("ocx connect"));
        assert!(!unit.contains("--profile"));
        assert!(!unit.contains("OC_OXIDE_PROFILE="));
    }

    #[test]
    fn systemd_unit_documents_restart_and_startup_recovery() {
        let unit = include_str!("../../../packaging/systemd/oc-oxide-daemon.service");
        let architecture = include_str!("../../../docs/ARCHITECTURE.md");
        let security = include_str!("../../../docs/SECURITY_MODEL.md");

        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("RestartSec=2s"));
        assert!(unit.contains("RuntimeDirectory=oc-oxide"));
        assert!(architecture.contains("starts idle"));
        assert!(architecture.contains("On startup, recovery runs before accepting IPC"));
        assert!(architecture.contains("return to the idle IPC-serving state"));
        assert!(security.contains("/run/oc-oxide/session.json"));
        assert!(security.contains("must never contain passwords"));
    }

    #[test]
    fn worker_auth_handler_returns_submitted_auth_response_without_network() {
        let (tx, rx) = mpsc::channel();
        let response =
            oc_oxide_auth::AuthResponse::new(vec![
                AuthAnswer::secret("password", "do-not-log").unwrap()
            ])
            .unwrap()
            .with_form_id("form-1")
            .unwrap();
        tx.send(TunnelWorkerCommand::SubmitAuth(response)).unwrap();
        let mut handler = WorkerAuthHandler::new(&rx);

        let decision = handler.handle_auth_request(sample_auth_request());

        assert!(matches!(
            decision,
            AuthFormDecision::Submit(response)
                if response.form_id.as_deref() == Some("form-1")
                    && response.answers[0].is_secret()
                    && !format!("{response:?}").contains("do-not-log")
        ));
    }

    #[test]
    fn worker_auth_handler_maps_cancel_to_auth_cancel_without_network() {
        let (tx, rx) = mpsc::channel();
        tx.send(TunnelWorkerCommand::Cancel).unwrap();
        let mut handler = WorkerAuthHandler::new(&rx);

        let decision = handler.handle_auth_request(sample_auth_request());

        assert_eq!(decision, AuthFormDecision::Cancel);
    }

    #[test]
    fn worker_auth_handler_cancels_when_command_channel_closes() {
        let (tx, rx) = mpsc::channel();
        drop(tx);
        let mut handler = WorkerAuthHandler::new(&rx);

        let decision = handler.handle_auth_request(sample_auth_request());

        assert_eq!(decision, AuthFormDecision::Cancel);
    }

    #[test]
    fn workflow_auth_handler_cancels_when_cancel_flag_is_set_without_network() {
        let (_tx, rx) = mpsc::channel();
        let cancel_requested = Arc::new(AtomicBool::new(true));
        let mut handler = WorkflowAuthHandler::new(&rx, cancel_requested, None, None);

        let decision = handler.handle_auth_request(sample_auth_request());

        assert_eq!(decision, AuthFormDecision::Cancel);
        assert!(handler.auth_cancelled.load(Ordering::SeqCst));
    }

    #[test]
    fn workflow_auth_handler_marks_cancelled_when_auth_channel_closes() {
        let (tx, rx) = mpsc::channel();
        drop(tx);
        let cancel_requested = Arc::new(AtomicBool::new(false));
        let mut handler = WorkflowAuthHandler::new(&rx, cancel_requested, None, None);

        let decision = handler.handle_auth_request(sample_auth_request());

        assert_eq!(decision, AuthFormDecision::Cancel);
        assert!(handler.auth_cancelled.load(Ordering::SeqCst));
    }

    #[test]
    fn workflow_auth_handler_submits_preferred_authgroup_before_ipc_prompt() {
        let (_tx, rx) = mpsc::channel();
        let cancel_requested = Arc::new(AtomicBool::new(false));
        let mut handler =
            WorkflowAuthHandler::new(&rx, cancel_requested, None, Some("Group A".to_owned()));
        let request = sample_auth_request();

        let decision = handler
            .maybe_handle_auth_request(&request)
            .expect("preferred authgroup should match");

        let AuthFormDecision::NewAuthGroup(response) = decision else {
            panic!("expected authgroup refresh decision");
        };
        assert_eq!(response.form_id.as_deref(), Some("form-1"));
        assert_eq!(response.answers[0].field_id, "authgroup");
        assert!(format!("{response:?}").contains("GroupA"));
        assert!(handler.maybe_handle_auth_request(&request).is_none());
    }

    #[test]
    fn authgroup_choice_matching_follows_openconnect_cli_style() {
        let choices = vec![
            TunnelAuthChoice::new("gIGA", "Giga").unwrap(),
            TunnelAuthChoice::new("engineering", "Engineering").unwrap(),
        ];

        assert_eq!(
            match_authgroup_choice(&choices, "Giga").map(|choice| choice.value.as_str()),
            Some("gIGA")
        );
        assert_eq!(
            match_authgroup_choice(&choices, "gig").map(|choice| choice.value.as_str()),
            Some("gIGA")
        );
        assert_eq!(
            match_authgroup_choice(&choices, "ENGINEERING").map(|choice| choice.value.as_str()),
            Some("engineering")
        );
    }

    #[test]
    fn authgroup_choice_matching_rejects_ambiguous_prefixes() {
        let choices = vec![
            TunnelAuthChoice::new("giga-a", "Giga Alpha").unwrap(),
            TunnelAuthChoice::new("giga-b", "Giga Beta").unwrap(),
        ];

        assert!(match_authgroup_choice(&choices, "Giga").is_none());
    }

    #[test]
    fn workflow_auth_handler_hides_repeated_authgroup_and_submits_it() {
        let (tx, rx) = mpsc::channel();
        let cancel_requested = Arc::new(AtomicBool::new(false));
        let mut handler =
            WorkflowAuthHandler::new(&rx, cancel_requested, None, Some("Group A".to_owned()));
        handler.authgroup_submitted = true;

        let prepared = handler.prepare_auth_request(sample_auth_request());

        assert!(!prepared.fields.iter().any(|field| field.id == "authgroup"));
        tx.send(
            AuthResponse::new(vec![
                AuthAnswer::text("username", "alice").unwrap(),
                AuthAnswer::secret("password", "do-not-log").unwrap(),
            ])
            .unwrap()
            .with_form_id("form-1")
            .unwrap(),
        )
        .unwrap();

        let AuthFormDecision::Submit(response) = handler.handle_auth_request(prepared) else {
            panic!("expected auth response to be submitted");
        };

        assert!(response.answers.iter().any(
            |answer| answer.field_id == "authgroup" && format!("{answer:?}").contains("GroupA")
        ));
        assert!(!format!("{response:?}").contains("do-not-log"));
    }

    #[test]
    fn workflow_auth_handler_hides_profile_username_and_submits_it() {
        let (tx, rx) = mpsc::channel();
        let cancel_requested = Arc::new(AtomicBool::new(false));
        let mut handler =
            WorkflowAuthHandler::new(&rx, cancel_requested, Some("alice".to_owned()), None);

        let prepared = handler.prepare_auth_request(sample_auth_request());

        assert!(!prepared.fields.iter().any(|field| field.id == "username"));
        assert!(prepared.fields.iter().any(|field| field.id == "password"));
        tx.send(
            AuthResponse::new(vec![AuthAnswer::secret("password", "do-not-log").unwrap()])
                .unwrap()
                .with_form_id("form-1")
                .unwrap(),
        )
        .unwrap();

        let AuthFormDecision::Submit(response) = handler.handle_auth_request(prepared) else {
            panic!("expected auth response to be submitted");
        };

        assert!(
            response
                .answers
                .iter()
                .any(|answer| answer.field_id == "username"
                    && format!("{answer:?}").contains("alice"))
        );
        assert!(!format!("{response:?}").contains("do-not-log"));
    }

    #[test]
    fn workflow_auth_handler_does_not_hide_authgroup_before_newgroup_submission() {
        let (_tx, rx) = mpsc::channel();
        let cancel_requested = Arc::new(AtomicBool::new(false));
        let mut handler =
            WorkflowAuthHandler::new(&rx, cancel_requested, None, Some("Group A".to_owned()));

        let prepared = handler.prepare_auth_request(sample_auth_request());

        assert!(prepared.fields.iter().any(|field| field.id == "authgroup"));
    }

    #[test]
    fn workflow_auth_handler_keeps_group_only_prompt_non_empty() {
        let (_tx, rx) = mpsc::channel();
        let cancel_requested = Arc::new(AtomicBool::new(false));
        let mut handler =
            WorkflowAuthHandler::new(&rx, cancel_requested, None, Some("Group A".to_owned()));
        handler.authgroup_submitted = true;
        let request = AuthRequest::new(
            "Login",
            vec![AuthField::select(
                "authgroup",
                "Group",
                vec![TunnelAuthChoice::new("GroupA", "Group A").unwrap()],
            )
            .unwrap()],
        )
        .unwrap();

        let prepared = handler.prepare_auth_request(request);

        assert_eq!(prepared.fields.len(), 1);
        assert_eq!(prepared.fields[0].id, "authgroup");
    }

    #[test]
    fn workflow_command_pump_forwards_auth_response_without_network() {
        let (command_tx, command_rx) = mpsc::channel();
        let (auth_tx, auth_rx) = mpsc::channel();
        let (event_tx, _event_rx) = mpsc::channel();
        let response =
            oc_oxide_auth::AuthResponse::new(vec![
                AuthAnswer::secret("password", "do-not-log").unwrap()
            ])
            .unwrap()
            .with_form_id("form-1")
            .unwrap();

        spawn_workflow_command_pump(
            command_rx,
            auth_tx,
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(None)),
            event_tx,
        );
        command_tx
            .send(TunnelWorkerCommand::SubmitAuth(response))
            .unwrap();

        let forwarded = auth_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(forwarded.form_id.as_deref(), Some("form-1"));
        assert!(!format!("{forwarded:?}").contains("do-not-log"));
    }

    #[test]
    fn mainloop_outcomes_map_to_disconnect_reasons() {
        assert_eq!(
            disconnect_reason_from_mainloop_outcome(MainloopOutcome::UserCancelled),
            DisconnectReason::UserRequested
        );
        assert_eq!(
            disconnect_reason_from_mainloop_outcome(MainloopOutcome::CookieRejected),
            DisconnectReason::AuthFailed
        );
        assert_eq!(
            disconnect_reason_from_mainloop_outcome(MainloopOutcome::ServerTerminated),
            DisconnectReason::ServerRequested
        );
        assert_eq!(
            disconnect_reason_from_mainloop_outcome(MainloopOutcome::UnrecoverableIo),
            DisconnectReason::NetworkError
        );
    }

    #[test]
    fn managed_tun_cleanup_removes_stale_interface_before_setup_without_network() {
        let backend = TunCleanupBackend::new(Ok(true));
        let mut dns = TunCleanupDnsRunner::new(Rc::clone(&backend.operations), Ok(()));
        let (tx, rx) = mpsc::channel();

        cleanup_managed_tun_before_setup(&backend, &mut dns, &tx).unwrap();

        assert_eq!(
            backend.operations.borrow().as_slice(),
            [
                format!("link:exists:{DAEMON_MANAGED_TUN_IFNAME}"),
                format!("dns:revert:{DAEMON_MANAGED_TUN_IFNAME}"),
                format!("link:del:{DAEMON_MANAGED_TUN_IFNAME}"),
            ]
        );
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            TunnelWorkerEvent::Lifecycle(TunnelLifecycleStep::Progress(progress))
                if progress.message == format!(
                    "reverted stale managed TUN DNS for {DAEMON_MANAGED_TUN_IFNAME}"
                )
        ));
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            TunnelWorkerEvent::Lifecycle(TunnelLifecycleStep::Progress(progress))
                if progress.message == format!(
                    "removed stale managed TUN interface {DAEMON_MANAGED_TUN_IFNAME}"
                )
        ));
    }

    #[test]
    fn managed_tun_cleanup_continues_after_stale_dns_revert_failure_without_network() {
        let backend = TunCleanupBackend::new(Ok(true));
        let mut dns = TunCleanupDnsRunner::new(
            Rc::clone(&backend.operations),
            Err(DnsPolicyError::CommandFailed {
                operation: "revert".to_owned(),
                detail: "injected failure".to_owned(),
            }),
        );
        let (tx, rx) = mpsc::channel();

        cleanup_managed_tun_before_setup(&backend, &mut dns, &tx).unwrap();

        assert_eq!(
            backend.operations.borrow().as_slice(),
            [
                format!("link:exists:{DAEMON_MANAGED_TUN_IFNAME}"),
                format!("dns:revert:{DAEMON_MANAGED_TUN_IFNAME}"),
                format!("link:del:{DAEMON_MANAGED_TUN_IFNAME}"),
            ]
        );
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            TunnelWorkerEvent::Lifecycle(TunnelLifecycleStep::Progress(progress))
                if progress.message.contains("stale managed TUN DNS cleanup failed")
        ));
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            TunnelWorkerEvent::Lifecycle(TunnelLifecycleStep::Progress(progress))
                if progress.message == format!(
                    "removed stale managed TUN interface {DAEMON_MANAGED_TUN_IFNAME}"
                )
        ));
    }

    #[test]
    fn managed_tun_cleanup_skips_dns_when_stale_interface_is_absent_without_network() {
        let backend = TunCleanupBackend::new(Ok(false));
        let mut dns = TunCleanupDnsRunner::new(Rc::clone(&backend.operations), Ok(()));
        let (tx, _rx) = mpsc::channel();

        cleanup_managed_tun_before_setup(&backend, &mut dns, &tx).unwrap();

        assert_eq!(
            backend.operations.borrow().as_slice(),
            [format!("link:exists:{DAEMON_MANAGED_TUN_IFNAME}")]
        );
    }

    #[test]
    fn managed_tun_cleanup_counts_delete_failure_after_disconnect_without_network() {
        let backend = TunCleanupBackend::new(Err(NetworkPolicyError::BackendFailed {
            operation: "test backend",
            detail: "delete failed".to_owned(),
        }));
        let (tx, rx) = mpsc::channel();

        let errors = cleanup_managed_tun_after_disconnect(&backend, &tx);

        assert_eq!(errors, 1);
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            TunnelWorkerEvent::Lifecycle(TunnelLifecycleStep::Progress(progress))
                if progress.message.contains("managed TUN cleanup failed")
        ));
    }

    #[test]
    fn local_profile_resolver_loads_toml_profiles_without_network() {
        let dir = unique_test_profile_dir("toml-only");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("office.toml"),
            r#"
[connection]
server = "https://vpn.example.test/"
reported_os = "linux-64"
authgroup = "engineering"
username = "alice"

[company]
domains = ["github.example.test"]

[local]
bypass = ["198.18.0.0/15"]
"#,
        )
        .unwrap();

        let profile = LocalProfileResolver::new(&dir).load("office").unwrap();

        assert_eq!(
            profile.tunnel().server_url().as_openconnect_url(),
            "https://vpn.example.test/"
        );
        assert_eq!(profile.tunnel().reported_os(), "linux-64");
        assert_eq!(profile.tunnel().authgroup(), Some("engineering"));
        assert_eq!(profile.tunnel().username(), Some("alice"));
        assert_eq!(profile.route_mode(), RouteMode::Split);
        assert_eq!(profile.dns_mode(), DnsMode::Split);
        assert!(profile.company_routes().is_empty());
        assert_eq!(
            profile.company_domains(),
            &["github.example.test".to_owned()]
        );
        assert_eq!(profile.local_bypass_cidrs()[0].to_string(), "198.18.0.0/15");
    }

    #[test]
    fn imported_profile_resolver_prefers_ipc_profile() {
        let local_dir = unique_test_profile_dir("imported-resolver");
        let imported_profile = sample_vpn_profile();
        let mut imported = BTreeMap::new();
        imported.insert("office".to_owned(), imported_profile.clone());
        let mut resolver =
            ImportedProfileResolver::new(LocalProfileResolver::new(local_dir), imported);

        assert_eq!(
            resolver.resolve_profile("office").unwrap(),
            imported_profile
        );
    }

    #[test]
    fn local_profile_resolver_rejects_unknown_toml_fields_without_secret_leak() {
        let dir = unique_test_profile_dir("toml-secret-field");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("office.toml"),
            r#"
[connection]
server = "https://vpn.example.test/"
password = "do-not-store"
"#,
        )
        .unwrap();

        let err = LocalProfileResolver::new(&dir).load("office").unwrap_err();

        assert!(err.to_string().contains("unknown field"));
        assert!(err.to_string().contains("password"));
        assert!(!format!("{err:?}").contains("do-not-store"));
        assert!(!err.to_string().contains("do-not-store"));
    }

    #[test]
    fn local_profile_resolver_rejects_unsafe_profile_names() {
        let resolver = LocalProfileResolver::new("/tmp/oc-oxide-test-profiles");

        let err = resolver.load("../office").unwrap_err();

        assert_eq!(
            err,
            LocalProfileError::InvalidName {
                name: "../office".to_owned()
            }
        );
    }

    #[test]
    fn recovery_journal_round_trips_without_secret_fields() {
        let applied = sample_applied_policy_state();

        let journal = RecoveryJournal::from_applied_policy(
            RecoveryJournalStage::Connected,
            Some("office".to_owned()),
            &applied,
        );
        let encoded = serde_json::to_string_pretty(&journal).unwrap();
        let decoded: RecoveryJournal = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded, journal);
        assert_eq!(decoded.version, super::RECOVERY_JOURNAL_VERSION);
        assert_eq!(decoded.ifname, "tun-test");
        assert!(encoded.contains("tun-test"));
        assert!(encoded.contains("198.18.0.0/15"));
        assert!(encoded.contains("203.0.113.10/32"));
        for forbidden in [
            "password",
            "otp",
            "cookie",
            "token",
            "private_key",
            "secret",
        ] {
            assert!(
                !encoded.to_ascii_lowercase().contains(forbidden),
                "journal unexpectedly contained {forbidden}"
            );
        }
    }

    #[test]
    fn recovery_journal_store_writes_loads_and_deletes_without_network() {
        let dir = unique_test_profile_dir("recovery-journal-store");
        let store = RecoveryJournalStore::new(&dir);
        let journal = RecoveryJournal::from_applied_policy(
            RecoveryJournalStage::Connected,
            Some("office".to_owned()),
            &sample_applied_policy_state(),
        );

        store.save(&journal).unwrap();

        assert_eq!(store.load().unwrap(), Some(journal));
        assert!(store.journal_path().exists());
        assert!(!dir.join("session.json.tmp").exists());
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(store.journal_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        store.delete().unwrap();

        assert_eq!(store.load().unwrap(), None);
    }

    #[test]
    fn recovery_journal_store_missing_file_is_noop() {
        let store = RecoveryJournalStore::new(unique_test_profile_dir("recovery-journal-missing"));

        assert_eq!(store.load().unwrap(), None);
        store.delete().unwrap();
    }

    #[test]
    fn recovery_journal_store_rejects_unsupported_version() {
        let dir = unique_test_profile_dir("recovery-journal-version");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("session.json"),
            r#"{"version":999,"stage":"connected","ifname":"tun-test"}"#,
        )
        .unwrap();
        let store = RecoveryJournalStore::new(&dir);

        let err = store.load().unwrap_err();

        assert!(matches!(
            err,
            RecoveryJournalError::UnsupportedVersion { version: 999 }
        ));
    }

    #[test]
    fn copies_tunnel_ip_snapshot_into_policy_input() {
        let input = tunnel_policy_input_from_ip_info(&sample_ip_info(), "tun0");

        assert_eq!(input.ifname, "tun0");
        assert_eq!(input.address.as_deref(), Some("198.51.100.24"));
        assert_eq!(input.netmask.as_deref(), Some("255.255.255.0"));
        assert_eq!(input.dns_servers, vec!["192.0.2.53", "198.51.100.53"]);
        assert_eq!(input.default_domain.as_deref(), Some("corp.example.test"));
        assert_eq!(input.split_dns, vec!["corp.example.test"]);
        assert_eq!(input.split_includes, vec!["203.0.113.0/24"]);
        assert_eq!(input.split_excludes, vec!["203.0.113.10/32"]);
        assert_eq!(input.gateway_addr.as_deref(), Some("203.0.113.10"));
    }

    #[test]
    fn plans_single_connected_policy_without_applying_system_changes() {
        let profile = sample_vpn_profile()
            .with_route_mode(RouteMode::Split)
            .with_dns_mode(DnsMode::Split)
            .with_local_bypass_cidrs(vec!["198.18.0.0/15".parse().unwrap()]);

        let planned = plan_daemon_network_policy(
            &profile,
            &sample_default_route(),
            &sample_tunnel_policy_input(),
        )
        .unwrap();

        assert_eq!(planned.policy.tun.ifname, "tun0");
        assert_eq!(
            planned.policy.tun.address,
            Some(Ipv4Addr::new(198, 51, 100, 24))
        );
        assert_eq!(
            planned.applied,
            NetworkApplied {
                route_commands: 6,
                dns_commands: 2,
            }
        );
        assert!(planned.policy.routes.block_ipv6_default_route);
        assert_eq!(
            planned
                .policy
                .routes
                .routes_for(RouteReason::VpnDefaultRoute)[0]
                .destination
                .to_string(),
            "0.0.0.0/0"
        );
        assert_eq!(
            planned.policy.dns.apply[1].args,
            vec!["domain", "tun0", "corp.example.test", "~."]
        );
    }

    #[test]
    fn plans_detected_local_lan_in_single_connected_policy() {
        let profile = sample_vpn_profile()
            .with_route_mode(RouteMode::Off)
            .with_dns_mode(DnsMode::Off)
            .with_local_bypass_cidrs(vec!["198.18.0.0/15".parse().unwrap()]);

        let planned = plan_daemon_network_policy_with_detected_local_cidrs(
            &profile,
            &sample_default_route(),
            vec!["192.0.2.0/24".parse::<Ipv4Cidr>().unwrap()],
            &sample_tunnel_policy_input(),
        )
        .unwrap();

        let detected = planned
            .policy
            .routes
            .routes_for(RouteReason::DetectedLocalNetwork);
        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0].destination.to_string(), "192.0.2.0/24");
        assert_eq!(detected[0].via, Some(sample_default_route().gateway));
        assert_eq!(detected[0].dev, sample_default_route().interface);
        assert_eq!(
            planned
                .policy
                .routes
                .routes_for(RouteReason::VpnDefaultRoute)
                .len(),
            1
        );
        assert_eq!(
            planned.policy.dns.apply[1].args,
            vec!["domain", "tun0", "corp.example.test", "~."]
        );
    }

    #[test]
    fn profile_company_domains_are_covered_by_full_dns_without_extra_routes() {
        let profile = sample_vpn_profile()
            .with_route_mode(RouteMode::Split)
            .with_dns_mode(DnsMode::Split)
            .with_company_routes(vec!["192.0.2.128/25".parse().unwrap()])
            .with_company_domains(["github.example.test"])
            .unwrap()
            .with_local_bypass_cidrs(vec!["198.18.0.0/15".parse().unwrap()]);

        let planned = plan_daemon_network_policy(
            &profile,
            &sample_default_route(),
            &sample_tunnel_policy_input(),
        )
        .unwrap();

        assert!(planned
            .policy
            .routes
            .routes_for(RouteReason::ProfileCompanyRoute)
            .is_empty());
        assert_eq!(
            planned.policy.dns.apply[1].args,
            vec!["domain", "tun0", "corp.example.test", "~."]
        );
    }

    #[test]
    fn profile_off_modes_do_not_disable_daemon_connected_policy() {
        let profile = sample_vpn_profile()
            .with_route_mode(RouteMode::Off)
            .with_dns_mode(DnsMode::Off);

        let planned = plan_daemon_network_policy(
            &profile,
            &sample_default_route(),
            &sample_tunnel_policy_input(),
        )
        .unwrap();

        assert_eq!(
            planned.applied,
            NetworkApplied {
                route_commands: 5,
                dns_commands: 2,
            }
        );
        assert!(planned.policy.routes.block_ipv6_default_route);
        assert_eq!(
            planned
                .policy
                .routes
                .routes_for(RouteReason::VpnDefaultRoute)
                .len(),
            1
        );
        assert_eq!(
            planned.policy.dns.apply[1].args,
            vec!["domain", "tun0", "corp.example.test", "~."]
        );
    }

    #[test]
    fn journaled_policy_apply_records_tun_routes_dns_and_connected_stages_without_network() {
        let backend = JournalPolicyBackend::new();
        let mut dns = JournalDnsRunner::new();
        let journal = RecordingRecoveryJournalSink::new();

        let applied = apply_policy_with_recovery_journal(
            &backend,
            &mut dns,
            &journal,
            Some("office".to_owned()),
            &sample_journal_policy_plan(),
        )
        .unwrap();

        let saves = journal.saved();
        assert_eq!(
            saves.iter().map(|save| save.stage).collect::<Vec<_>>(),
            vec![
                RecoveryJournalStage::ApplyingTun,
                RecoveryJournalStage::ApplyingRoutes,
                RecoveryJournalStage::ApplyingDns,
                RecoveryJournalStage::Connected,
            ]
        );
        assert!(saves[0].tun.is_some());
        assert!(saves[0].routes.is_empty());
        assert!(saves[0].dns.is_none());
        assert_eq!(saves[1].routes.len(), 2);
        assert!(saves[1].dns.is_none());
        assert_eq!(saves[2].routes.len(), 2);
        assert!(saves[2].dns.is_some());
        assert_eq!(saves[3].ifname, "tun-test");
        assert_eq!(saves[3].profile.as_deref(), Some("office"));
        assert_eq!(applied.tun.ifname, "tun-test");
        assert_eq!(journal.delete_count(), 0);
        assert!(!format!("{saves:?}").contains("do-not-log"));
    }

    #[test]
    fn journaled_policy_apply_rolls_back_and_deletes_journal_after_dns_failure_without_network() {
        let backend = JournalPolicyBackend::new();
        let mut dns = JournalDnsRunner::new().with_failure_on(DnsCommandReason::SetDomains);
        let journal = RecordingRecoveryJournalSink::new();

        let err = apply_policy_with_recovery_journal(
            &backend,
            &mut dns,
            &journal,
            Some("office".to_owned()),
            &sample_journal_policy_plan(),
        )
        .unwrap_err();

        assert_eq!(err.code, "policy_apply");
        assert_eq!(
            journal
                .saved()
                .iter()
                .map(|save| save.stage)
                .collect::<Vec<_>>(),
            vec![
                RecoveryJournalStage::ApplyingTun,
                RecoveryJournalStage::ApplyingRoutes,
            ]
        );
        assert_eq!(journal.delete_count(), 1);
        assert!(dns.operations().iter().any(|op| op == "dns:revert"));
        assert!(backend
            .operations()
            .iter()
            .any(|op| op.starts_with("route:delete:")));
        assert!(backend
            .operations()
            .iter()
            .any(|op| op.starts_with("link:down:")));
    }

    #[test]
    fn journaled_policy_revert_marks_reverting_and_deletes_after_success_without_network() {
        let backend = JournalPolicyBackend::new();
        let mut dns = JournalDnsRunner::new();
        let journal = RecordingRecoveryJournalSink::new();
        let (tx, _rx) = mpsc::channel();

        let counts = revert_policy_error_counts_with_journal(
            &backend,
            &mut dns,
            &journal,
            Some("office".to_owned()),
            &sample_applied_policy_state(),
            &tx,
        );
        delete_recovery_journal_after_successful_disconnect(
            &journal, counts.0, counts.1, counts.2, &tx,
        );

        assert_eq!(counts, (0, 0, 0));
        assert_eq!(journal.saved()[0].stage, RecoveryJournalStage::Reverting);
        assert_eq!(journal.delete_count(), 1);
    }

    #[test]
    fn journaled_policy_revert_keeps_journal_after_partial_failure_without_network() {
        let backend = JournalPolicyBackend::new().with_restore_route_failure();
        let mut dns = JournalDnsRunner::new();
        let journal = RecordingRecoveryJournalSink::new();
        let (tx, _rx) = mpsc::channel();

        let counts = revert_policy_error_counts_with_journal(
            &backend,
            &mut dns,
            &journal,
            Some("office".to_owned()),
            &sample_applied_policy_state(),
            &tx,
        );
        delete_recovery_journal_after_successful_disconnect(
            &journal, counts.0, counts.1, counts.2, &tx,
        );

        assert_eq!(counts, (0, 1, 0));
        assert_eq!(journal.saved()[0].stage, RecoveryJournalStage::Reverting);
        assert_eq!(journal.delete_count(), 0);
    }

    #[test]
    fn startup_recovery_without_journal_only_cleans_stale_managed_link_without_network() {
        let backend = JournalPolicyBackend::new().with_stale_link();
        let mut dns = JournalDnsRunner::new();
        let journal = RecordingRecoveryJournalSink::new();

        let report = recover_runtime_journal_at_startup(&backend, &mut dns, &journal).unwrap();

        assert_eq!(report.journal_recovered, false);
        assert_eq!(report.stale_link_removed, true);
        assert_eq!(journal.delete_count(), 0);
        assert_eq!(dns.operations(), vec!["dns:revert"]);
        assert!(backend
            .operations()
            .iter()
            .any(|op| op == "link:delete:ocx0"));
    }

    #[test]
    fn startup_recovery_reverts_full_journal_and_deletes_it_without_network() {
        let backend = JournalPolicyBackend::new().with_stale_link();
        let mut dns = JournalDnsRunner::new();
        let journal =
            RecordingRecoveryJournalSink::new().with_loaded(RecoveryJournal::from_applied_policy(
                RecoveryJournalStage::Connected,
                Some("office".to_owned()),
                &sample_applied_policy_state(),
            ));

        let report = recover_runtime_journal_at_startup(&backend, &mut dns, &journal).unwrap();

        assert_eq!(report.journal_recovered, true);
        assert_eq!(journal.delete_count(), 1);
        assert_eq!(dns.operations(), vec!["dns:revert"]);
        let operations = backend.operations();
        assert!(operations.iter().any(|op| op == "ipv6:unblock-default"));
        assert!(operations.iter().any(|op| op.starts_with("route:restore:")));
        assert!(operations.iter().any(|op| op.starts_with("route:delete:")));
        assert!(operations.iter().any(|op| op == "addr:delete:tun-test"));
        assert!(operations.iter().any(|op| op == "link:down:tun-test"));
        assert!(operations.iter().any(|op| op == "link:delete:tun-test"));
    }

    #[test]
    fn startup_recovery_reverts_only_recorded_partial_journal_without_network() {
        let backend = JournalPolicyBackend::new().with_stale_link();
        let mut dns = JournalDnsRunner::new();
        let applied = sample_applied_policy_state();
        let journal =
            RecordingRecoveryJournalSink::new().with_loaded(RecoveryJournal::from_applied_parts(
                RecoveryJournalStage::ApplyingTun,
                Some("office".to_owned()),
                "tun-test",
                Some(&applied.tun),
                None,
                None,
            ));

        let report = recover_runtime_journal_at_startup(&backend, &mut dns, &journal).unwrap();

        assert_eq!(report.journal_recovered, true);
        assert_eq!(journal.delete_count(), 1);
        assert!(dns.operations().is_empty());
        let operations = backend.operations();
        assert!(!operations.iter().any(|op| op.starts_with("route:")));
        assert!(operations.iter().any(|op| op == "addr:delete:tun-test"));
        assert!(operations.iter().any(|op| op == "link:down:tun-test"));
        assert!(operations.iter().any(|op| op == "link:delete:tun-test"));
    }

    #[test]
    fn startup_recovery_with_missing_journaled_link_is_idempotent_without_network() {
        let backend = JournalPolicyBackend::new()
            .with_delete_route_failure()
            .with_unblock_ipv6_failure();
        let mut dns = JournalDnsRunner::new();
        let mut applied = sample_applied_policy_state();
        let internal_route = PlannedRoute {
            destination: "198.51.100.0/24".parse().unwrap(),
            via: None,
            dev: "tun-test".to_owned(),
            reason: RouteReason::VpnInternalNetwork,
        };
        applied.routes.routes.push(AppliedRouteChange {
            applied: internal_route.clone(),
            revert: RouteRevertAction::Delete(internal_route),
        });
        let stale_previous_route =
            RouteSnapshot::new("198.51.101.0/24".parse().unwrap(), None, "tun-test").unwrap();
        let stale_applied_route = PlannedRoute {
            destination: "198.51.101.0/24".parse().unwrap(),
            via: None,
            dev: "tun-test".to_owned(),
            reason: RouteReason::VpnInternalNetwork,
        };
        applied.routes.routes.push(AppliedRouteChange {
            applied: stale_applied_route,
            revert: RouteRevertAction::Restore(stale_previous_route),
        });
        let journal =
            RecordingRecoveryJournalSink::new().with_loaded(RecoveryJournal::from_applied_policy(
                RecoveryJournalStage::Connected,
                Some("office".to_owned()),
                &applied,
            ));

        let report = recover_runtime_journal_at_startup(&backend, &mut dns, &journal).unwrap();

        assert_eq!(report.journal_recovered, true);
        assert_eq!(report.stale_link_removed, true);
        assert_eq!(journal.delete_count(), 1);
        assert!(dns.operations().is_empty());

        let operations = backend.operations();
        assert!(operations.iter().any(|op| op == "ipv6:unblock-default"));
        assert!(operations
            .iter()
            .any(|op| op == "route:delete:203.0.113.10/32"));
        assert!(operations
            .iter()
            .any(|op| op == "route:restore:198.18.0.0/15"));
        assert!(!operations
            .iter()
            .any(|op| op == "route:delete:198.51.100.0/24"));
        assert!(!operations
            .iter()
            .any(|op| op == "route:restore:198.51.101.0/24"));
        assert!(!operations.iter().any(|op| op == "addr:delete:tun-test"));
        assert!(!operations.iter().any(|op| op == "link:down:tun-test"));
        assert!(!operations.iter().any(|op| op == "link:delete:tun-test"));
    }

    #[test]
    fn startup_recovery_failure_keeps_journal_for_retry_without_network() {
        let backend = JournalPolicyBackend::new()
            .with_stale_link()
            .with_restore_route_failure();
        let mut dns = JournalDnsRunner::new();
        let journal =
            RecordingRecoveryJournalSink::new().with_loaded(RecoveryJournal::from_applied_policy(
                RecoveryJournalStage::Connected,
                Some("office".to_owned()),
                &sample_applied_policy_state(),
            ));

        let err = recover_runtime_journal_at_startup(&backend, &mut dns, &journal).unwrap_err();

        assert!(matches!(
            err,
            StartupRecoveryError::CleanupIncomplete {
                dns_errors: 0,
                route_errors: 1,
                tun_errors: 0,
                link_errors: 0,
            }
        ));
        assert_eq!(journal.delete_count(), 0);
    }

    #[test]
    fn disconnect_clears_profile_and_emits_lifecycle_events() {
        let mut core = DaemonCore::new();
        core.handle_command(IpcCommand::Connect {
            profile: "office".to_owned(),
        });

        let response = core.handle_command(IpcCommand::Disconnect);

        assert_eq!(response, IpcResponse::Accepted);
        assert_eq!(core.status().state, DaemonState::Disconnected);
        assert_eq!(core.status().active_profile, None);
        assert_eq!(
            core.drain_events(),
            vec![
                IpcEvent::Progress(oc_oxide_ipc::ProgressUpdate {
                    level: 0,
                    message: "connect requested".to_owned(),
                }),
                IpcEvent::Disconnecting,
                IpcEvent::Disconnected {
                    reason: DisconnectReason::UserRequested
                },
            ]
        );
    }

    #[test]
    fn command_can_arrive_from_json_line() {
        let mut core = DaemonCore::new();
        let command = decode_command_line("{\"type\":\"connect\",\"profile\":\"office\"}\n")
            .expect("valid command");

        assert_eq!(core.handle_command(command), IpcResponse::Accepted);
        assert_eq!(core.status().active_profile.as_deref(), Some("office"));
    }

    #[test]
    fn tail_logs_returns_non_secret_lifecycle_messages() {
        let mut core = DaemonCore::new();
        core.handle_command(IpcCommand::Connect {
            profile: "office".to_owned(),
        });
        core.emit_auth_prompt(sample_prompt());

        let response = core.handle_command(IpcCommand::TailLogs { cursor: None });

        let entries = match response {
            IpcResponse::LogBatch { entries, .. } => entries,
            other => panic!("unexpected response: {other:?}"),
        };
        let joined = entries
            .iter()
            .map(|entry| entry.message.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(joined.contains("connect requested"));
        assert!(joined.contains("auth prompt received"));
        assert!(!joined.contains("password"));
    }

    fn sample_prompt() -> AuthPrompt {
        AuthPrompt {
            form_id: "form-1".to_owned(),
            title: "Login".to_owned(),
            message: None,
            error: None,
            fields: vec![AuthPromptField {
                id: "password".to_owned(),
                label: "Password".to_owned(),
                kind: AuthPromptFieldKind::Password,
                required: true,
            }],
        }
    }

    fn sample_auth_request() -> AuthRequest {
        AuthRequest::new(
            "Login",
            vec![
                AuthField::text("username", "Username").unwrap(),
                AuthField::password("password", "Password").unwrap(),
                AuthField::select(
                    "authgroup",
                    "Group",
                    vec![TunnelAuthChoice::new("GroupA", "Group A").unwrap()],
                )
                .unwrap(),
            ],
        )
        .unwrap()
        .with_form_id("form-1")
        .unwrap()
    }

    fn sample_vpn_profile() -> VpnProfile {
        VpnProfile::new(
            "office",
            ServerUrl::parse("https://vpn.example.test/+CSCOE+/logon.html").unwrap(),
        )
        .unwrap()
    }

    fn unique_test_profile_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("oc-oxide-daemon-{label}-{}", std::process::id()))
    }

    fn sample_default_route() -> DefaultRouteSnapshot {
        DefaultRouteSnapshot::new(Ipv4Addr::new(192, 0, 2, 1), "eth-test").unwrap()
    }

    fn sample_tunnel_policy_input() -> TunnelPolicyInput {
        tunnel_policy_input_from_ip_info(&sample_ip_info(), "tun0")
    }

    fn sample_journal_policy_plan() -> PolicyPlan {
        let tun = TunConfig::new("tun-test")
            .unwrap()
            .with_ipv4_address(Ipv4Addr::new(198, 51, 100, 24), 24)
            .unwrap()
            .with_mtu(1200);
        let routes = NetworkRoutePlan {
            routes: vec![
                PlannedRoute {
                    destination: "203.0.113.10/32".parse().unwrap(),
                    via: Some(Ipv4Addr::new(192, 0, 2, 1)),
                    dev: "eth-test".to_owned(),
                    reason: RouteReason::VpnGatewayPin,
                },
                PlannedRoute {
                    destination: "198.18.0.0/15".parse().unwrap(),
                    via: Some(Ipv4Addr::new(192, 0, 2, 1)),
                    dev: "eth-test".to_owned(),
                    reason: RouteReason::LocalBypassCidr,
                },
            ],
            block_ipv6_default_route: true,
        };
        let dns = DnsCommandPlan {
            apply: vec![
                DnsCommand {
                    program: "resolvectl",
                    args: vec![
                        "dns".to_owned(),
                        "tun-test".to_owned(),
                        "192.0.2.53".to_owned(),
                    ],
                    reason: DnsCommandReason::SetServers,
                },
                DnsCommand {
                    program: "resolvectl",
                    args: vec![
                        "domain".to_owned(),
                        "tun-test".to_owned(),
                        "corp.example.test".to_owned(),
                        "~.".to_owned(),
                    ],
                    reason: DnsCommandReason::SetDomains,
                },
            ],
            revert: vec![DnsCommand {
                program: "resolvectl",
                args: vec!["revert".to_owned(), "tun-test".to_owned()],
                reason: DnsCommandReason::RevertInterface,
            }],
        };

        PolicyPlan::new(tun, routes, dns)
    }

    fn sample_applied_policy_state() -> AppliedPolicyState {
        let gateway_pin = PlannedRoute {
            destination: "203.0.113.10/32".parse().unwrap(),
            via: Some(Ipv4Addr::new(192, 0, 2, 1)),
            dev: "eth-test".to_owned(),
            reason: RouteReason::VpnGatewayPin,
        };
        let local_bypass = PlannedRoute {
            destination: "198.18.0.0/15".parse().unwrap(),
            via: Some(Ipv4Addr::new(192, 0, 2, 1)),
            dev: "eth-test".to_owned(),
            reason: RouteReason::LocalBypassCidr,
        };
        let previous_local_bypass = RouteSnapshot::new(
            "198.18.0.0/15".parse().unwrap(),
            Some(Ipv4Addr::new(192, 0, 2, 254)),
            "eth-original",
        )
        .unwrap()
        .with_metric(50);

        AppliedPolicyState {
            tun: AppliedTunConfig {
                ifname: "tun-test".to_owned(),
                address: Some(Ipv4Addr::new(198, 51, 100, 24)),
                prefix_len: Some(24),
            },
            routes: AppliedNetworkRouteState {
                routes: vec![
                    AppliedRouteChange {
                        applied: gateway_pin.clone(),
                        revert: RouteRevertAction::Delete(gateway_pin),
                    },
                    AppliedRouteChange {
                        applied: local_bypass,
                        revert: RouteRevertAction::Restore(previous_local_bypass),
                    },
                ],
                ipv6_default_route_block: Some(AppliedIpv6DefaultRouteBlock { created: true }),
            },
            dns: AppliedDnsState {
                revert: vec![DnsCommand {
                    program: "resolvectl",
                    args: vec!["revert".to_owned(), "tun-test".to_owned()],
                    reason: DnsCommandReason::RevertInterface,
                }],
            },
        }
    }

    fn sample_ip_info() -> IpInfoSnapshot {
        IpInfoSnapshot {
            address: Some("198.51.100.24".to_owned()),
            netmask: Some("255.255.255.0".to_owned()),
            address6: None,
            netmask6: None,
            dns: vec!["192.0.2.53".to_owned(), "198.51.100.53".to_owned()],
            nbns: Vec::new(),
            domain: Some("corp.example.test".to_owned()),
            proxy_pac: None,
            mtu: 1200,
            split_dns: vec![SplitRoute {
                route: "corp.example.test".to_owned(),
            }],
            split_includes: vec![SplitRoute {
                route: "203.0.113.0/24".to_owned(),
            }],
            split_excludes: vec![SplitRoute {
                route: "203.0.113.10/32".to_owned(),
            }],
            gateway_addr: Some("203.0.113.10".to_owned()),
        }
    }

    struct ScriptedTunnelRunner {
        steps: Vec<TunnelLifecycleStep>,
        error: Option<TunnelLifecycleError>,
        seen_profile: Option<String>,
    }

    impl TunnelLifecycleRunner for ScriptedTunnelRunner {
        fn run(
            &mut self,
            request: TunnelConnectRequest,
        ) -> Result<Vec<TunnelLifecycleStep>, TunnelLifecycleError> {
            self.seen_profile = Some(request.profile);
            match self.error.take() {
                Some(error) => Err(error),
                None => Ok(std::mem::take(&mut self.steps)),
            }
        }
    }

    struct ScriptedChannelWorker;

    impl TunnelWorker for ScriptedChannelWorker {
        fn run(
            self,
            commands: mpsc::Receiver<TunnelWorkerCommand>,
            events: mpsc::Sender<TunnelWorkerEvent>,
        ) {
            while let Ok(command) = commands.recv() {
                match command {
                    TunnelWorkerCommand::Connect(request) => {
                        let _ = events.send(TunnelWorkerEvent::Lifecycle(
                            TunnelLifecycleStep::Progress(oc_oxide_ipc::ProgressUpdate {
                                level: 1,
                                message: format!("worker connecting {}", request.profile),
                            }),
                        ));
                        let _ = events.send(TunnelWorkerEvent::Lifecycle(
                            TunnelLifecycleStep::Connected {
                                interface: "tun-worker0".to_owned(),
                            },
                        ));
                    }
                    TunnelWorkerCommand::SubmitAuth(_) => {
                        let _ = events.send(TunnelWorkerEvent::Lifecycle(
                            TunnelLifecycleStep::Progress(oc_oxide_ipc::ProgressUpdate {
                                level: 1,
                                message: "worker received auth response".to_owned(),
                            }),
                        ));
                    }
                    TunnelWorkerCommand::Cancel => {
                        let _ = events.send(TunnelWorkerEvent::Lifecycle(
                            TunnelLifecycleStep::Disconnecting,
                        ));
                        let _ = events.send(TunnelWorkerEvent::Lifecycle(
                            TunnelLifecycleStep::NetworkReverted {
                                dns_errors: 0,
                                route_errors: 0,
                                tun_errors: 0,
                            },
                        ));
                        let _ = events.send(TunnelWorkerEvent::Lifecycle(
                            TunnelLifecycleStep::Disconnected {
                                reason: DisconnectReason::UserRequested,
                            },
                        ));
                        break;
                    }
                    TunnelWorkerCommand::Disconnect => {
                        let _ = events.send(TunnelWorkerEvent::Lifecycle(
                            TunnelLifecycleStep::Disconnected {
                                reason: DisconnectReason::UserRequested,
                            },
                        ));
                        break;
                    }
                }
            }
        }
    }

    struct AuthForwardingWorker;

    impl TunnelWorker for AuthForwardingWorker {
        fn run(
            self,
            commands: mpsc::Receiver<TunnelWorkerCommand>,
            events: mpsc::Sender<TunnelWorkerEvent>,
        ) {
            if let Ok(TunnelWorkerCommand::SubmitAuth(response)) = commands.recv() {
                assert_eq!(response.form_id.as_deref(), Some("form-1"));
                assert_eq!(response.answers.len(), 1);
                assert_eq!(response.answers[0].field_id, "password");
                assert!(response.answers[0].is_secret());
                assert!(!format!("{response:?}").contains("do-not-log"));
                let _ = events.send(TunnelWorkerEvent::Lifecycle(TunnelLifecycleStep::Progress(
                    oc_oxide_ipc::ProgressUpdate {
                        level: 1,
                        message: "worker received auth response".to_owned(),
                    },
                )));
            }
        }
    }

    struct ControllerScriptedWorkerFactory;

    impl TunnelWorkerFactory for ControllerScriptedWorkerFactory {
        fn spawn_worker(&mut self) -> TunnelWorkerHandle {
            TunnelWorkerHandle::spawn(ControllerScriptedWorker)
        }
    }

    struct ControllerScriptedWorker;

    impl TunnelWorker for ControllerScriptedWorker {
        fn run(
            self,
            commands: mpsc::Receiver<TunnelWorkerCommand>,
            events: mpsc::Sender<TunnelWorkerEvent>,
        ) {
            while let Ok(command) = commands.recv() {
                match command {
                    TunnelWorkerCommand::Connect(request) => {
                        assert_eq!(request.profile, "office");
                        let _ = events.send(TunnelWorkerEvent::Lifecycle(
                            TunnelLifecycleStep::Progress(oc_oxide_ipc::ProgressUpdate {
                                level: 1,
                                message: "controller worker connecting".to_owned(),
                            }),
                        ));
                        let _ = events.send(TunnelWorkerEvent::Lifecycle(
                            TunnelLifecycleStep::AuthPrompt(sample_prompt()),
                        ));
                    }
                    TunnelWorkerCommand::SubmitAuth(response) => {
                        assert_eq!(response.form_id.as_deref(), Some("form-1"));
                        let _ = events.send(TunnelWorkerEvent::Lifecycle(
                            TunnelLifecycleStep::NetworkApplied(NetworkApplied {
                                route_commands: 3,
                                dns_commands: 2,
                            }),
                        ));
                        let _ = events.send(TunnelWorkerEvent::Lifecycle(
                            TunnelLifecycleStep::Connected {
                                interface: "tun-controller0".to_owned(),
                            },
                        ));
                    }
                    TunnelWorkerCommand::Cancel => {
                        let _ = events.send(TunnelWorkerEvent::Lifecycle(
                            TunnelLifecycleStep::Disconnecting,
                        ));
                        let _ = events.send(TunnelWorkerEvent::Lifecycle(
                            TunnelLifecycleStep::NetworkReverted {
                                dns_errors: 0,
                                route_errors: 0,
                                tun_errors: 0,
                            },
                        ));
                        let _ = events.send(TunnelWorkerEvent::Lifecycle(
                            TunnelLifecycleStep::Disconnected {
                                reason: DisconnectReason::UserRequested,
                            },
                        ));
                        break;
                    }
                    TunnelWorkerCommand::Disconnect => {
                        let _ = events.send(TunnelWorkerEvent::Lifecycle(
                            TunnelLifecycleStep::Disconnected {
                                reason: DisconnectReason::UserRequested,
                            },
                        ));
                        break;
                    }
                }
            }
        }
    }

    struct StaticProfileResolver {
        profile: VpnProfile,
    }

    impl StaticProfileResolver {
        fn new(profile: VpnProfile) -> Self {
            Self { profile }
        }
    }

    impl VpnProfileResolver for StaticProfileResolver {
        fn resolve_profile(&mut self, name: &str) -> Result<VpnProfile, TunnelLifecycleError> {
            if self.profile.tunnel().name() == name {
                Ok(self.profile.clone())
            } else {
                Err(TunnelLifecycleError::new(
                    "profile_not_found",
                    format!("profile {name} was not found"),
                ))
            }
        }
    }

    struct RecordingOpenConnectWorkflow;

    impl OpenConnectWorkflow for RecordingOpenConnectWorkflow {
        fn run(
            &mut self,
            profile: VpnProfile,
            commands: mpsc::Receiver<TunnelWorkerCommand>,
            events: mpsc::Sender<TunnelWorkerEvent>,
        ) -> Result<(), TunnelLifecycleError> {
            let _ = events.send(TunnelWorkerEvent::Lifecycle(TunnelLifecycleStep::Progress(
                oc_oxide_ipc::ProgressUpdate {
                    level: 0,
                    message: format!("workflow running {}", profile.tunnel().name()),
                },
            )));

            while let Ok(command) = commands.recv() {
                match command {
                    TunnelWorkerCommand::SubmitAuth(response) => {
                        let _ = events.send(TunnelWorkerEvent::Lifecycle(
                            TunnelLifecycleStep::Progress(oc_oxide_ipc::ProgressUpdate {
                                level: 0,
                                message: format!(
                                    "workflow received auth {}",
                                    response.form_id.as_deref().unwrap_or("<none>")
                                ),
                            }),
                        ));
                    }
                    TunnelWorkerCommand::Cancel | TunnelWorkerCommand::Disconnect => {
                        let _ = events.send(TunnelWorkerEvent::Lifecycle(
                            TunnelLifecycleStep::Disconnecting,
                        ));
                        let _ = events.send(TunnelWorkerEvent::Lifecycle(
                            TunnelLifecycleStep::Disconnected {
                                reason: DisconnectReason::UserRequested,
                            },
                        ));
                        return Ok(());
                    }
                    TunnelWorkerCommand::Connect(_) => {
                        return Err(TunnelLifecycleError::new(
                            "unexpected_connect",
                            "connect command arrived while workflow was active",
                        ));
                    }
                }
            }

            Ok(())
        }
    }

    struct RecordingRecoveryJournalSink {
        loaded: Rc<RefCell<Option<RecoveryJournal>>>,
        saves: Rc<RefCell<Vec<RecoveryJournal>>>,
        deletes: Rc<RefCell<usize>>,
    }

    impl RecordingRecoveryJournalSink {
        fn new() -> Self {
            Self {
                loaded: Rc::new(RefCell::new(None)),
                saves: Rc::new(RefCell::new(Vec::new())),
                deletes: Rc::new(RefCell::new(0)),
            }
        }

        fn with_loaded(self, journal: RecoveryJournal) -> Self {
            *self.loaded.borrow_mut() = Some(journal);
            self
        }

        fn saved(&self) -> Vec<RecoveryJournal> {
            self.saves.borrow().clone()
        }

        fn delete_count(&self) -> usize {
            *self.deletes.borrow()
        }
    }

    impl RecoveryJournalSink for RecordingRecoveryJournalSink {
        fn load(&self) -> Result<Option<RecoveryJournal>, RecoveryJournalError> {
            Ok(self.loaded.borrow().clone())
        }

        fn save(&self, journal: &RecoveryJournal) -> Result<(), RecoveryJournalError> {
            self.saves.borrow_mut().push(journal.clone());
            Ok(())
        }

        fn delete(&self) -> Result<(), RecoveryJournalError> {
            *self.deletes.borrow_mut() += 1;
            Ok(())
        }
    }

    struct JournalPolicyBackend {
        operations: Rc<RefCell<Vec<String>>>,
        fail_restore_route: bool,
        fail_delete_route: bool,
        fail_unblock_ipv6: bool,
        stale_link_exists: bool,
    }

    impl JournalPolicyBackend {
        fn new() -> Self {
            Self {
                operations: Rc::new(RefCell::new(Vec::new())),
                fail_restore_route: false,
                fail_delete_route: false,
                fail_unblock_ipv6: false,
                stale_link_exists: false,
            }
        }

        fn with_restore_route_failure(mut self) -> Self {
            self.fail_restore_route = true;
            self
        }

        fn with_delete_route_failure(mut self) -> Self {
            self.fail_delete_route = true;
            self
        }

        fn with_unblock_ipv6_failure(mut self) -> Self {
            self.fail_unblock_ipv6 = true;
            self
        }

        fn with_stale_link(mut self) -> Self {
            self.stale_link_exists = true;
            self
        }

        fn operations(&self) -> Vec<String> {
            self.operations.borrow().clone()
        }
    }

    impl LinuxNetworkBackend for JournalPolicyBackend {
        fn default_route(&self) -> Result<DefaultRouteSnapshot, NetworkPolicyError> {
            Ok(sample_default_route())
        }

        fn link_exists(&self, _ifname: &str) -> Result<bool, NetworkPolicyError> {
            Ok(self.stale_link_exists)
        }

        fn interface_ipv4_cidrs(&self, _ifname: &str) -> Result<Vec<Ipv4Cidr>, NetworkPolicyError> {
            Ok(Vec::new())
        }

        fn route_snapshot(
            &self,
            _destination: Ipv4Cidr,
        ) -> Result<Option<RouteSnapshot>, NetworkPolicyError> {
            Ok(None)
        }

        fn replace_ipv4_address(
            &self,
            ifname: &str,
            _address: Ipv4Addr,
            _prefix_len: u8,
        ) -> Result<(), NetworkPolicyError> {
            self.operations
                .borrow_mut()
                .push(format!("addr:replace:{ifname}"));
            Ok(())
        }

        fn delete_ipv4_address(
            &self,
            ifname: &str,
            _address: Ipv4Addr,
            _prefix_len: u8,
        ) -> Result<(), NetworkPolicyError> {
            self.operations
                .borrow_mut()
                .push(format!("addr:delete:{ifname}"));
            Ok(())
        }

        fn set_link_mtu(&self, ifname: &str, _mtu: u32) -> Result<(), NetworkPolicyError> {
            self.operations
                .borrow_mut()
                .push(format!("mtu:set:{ifname}"));
            Ok(())
        }

        fn set_link_up(&self, ifname: &str) -> Result<(), NetworkPolicyError> {
            self.operations
                .borrow_mut()
                .push(format!("link:up:{ifname}"));
            Ok(())
        }

        fn set_link_down(&self, ifname: &str) -> Result<(), NetworkPolicyError> {
            self.operations
                .borrow_mut()
                .push(format!("link:down:{ifname}"));
            Ok(())
        }

        fn delete_link_if_exists(&self, ifname: &str) -> Result<bool, NetworkPolicyError> {
            self.operations
                .borrow_mut()
                .push(format!("link:delete:{ifname}"));
            Ok(true)
        }

        fn replace_route(&self, route: &PlannedRoute) -> Result<(), NetworkPolicyError> {
            self.operations
                .borrow_mut()
                .push(format!("route:replace:{}", route.destination));
            Ok(())
        }

        fn restore_route(&self, route: &RouteSnapshot) -> Result<(), NetworkPolicyError> {
            self.operations
                .borrow_mut()
                .push(format!("route:restore:{}", route.destination));
            if self.fail_restore_route {
                Err(NetworkPolicyError::BackendFailed {
                    operation: "restore route",
                    detail: "injected failure".to_owned(),
                })
            } else {
                Ok(())
            }
        }

        fn delete_route(&self, route: &PlannedRoute) -> Result<(), NetworkPolicyError> {
            self.operations
                .borrow_mut()
                .push(format!("route:delete:{}", route.destination));
            if self.fail_delete_route {
                Err(NetworkPolicyError::BackendFailed {
                    operation: "delete route",
                    detail: "injected failure".to_owned(),
                })
            } else {
                Ok(())
            }
        }

        fn ipv6_default_route_block_exists(&self) -> Result<bool, NetworkPolicyError> {
            Ok(false)
        }

        fn block_ipv6_default_route(&self) -> Result<(), NetworkPolicyError> {
            self.operations
                .borrow_mut()
                .push("ipv6:block-default".to_owned());
            Ok(())
        }

        fn unblock_ipv6_default_route(&self) -> Result<(), NetworkPolicyError> {
            self.operations
                .borrow_mut()
                .push("ipv6:unblock-default".to_owned());
            if self.fail_unblock_ipv6 {
                Err(NetworkPolicyError::BackendFailed {
                    operation: "unblock IPv6 default route",
                    detail: "injected failure".to_owned(),
                })
            } else {
                Ok(())
            }
        }
    }

    struct JournalDnsRunner {
        operations: Rc<RefCell<Vec<String>>>,
        fail_on: Option<DnsCommandReason>,
    }

    impl JournalDnsRunner {
        fn new() -> Self {
            Self {
                operations: Rc::new(RefCell::new(Vec::new())),
                fail_on: None,
            }
        }

        fn with_failure_on(mut self, reason: DnsCommandReason) -> Self {
            self.fail_on = Some(reason);
            self
        }

        fn operations(&self) -> Vec<String> {
            self.operations.borrow().clone()
        }
    }

    impl DnsCommandRunner for JournalDnsRunner {
        fn run(&mut self, command: &DnsCommand) -> Result<(), DnsPolicyError> {
            self.operations.borrow_mut().push(match command.reason {
                DnsCommandReason::SetServers => "dns:set-servers".to_owned(),
                DnsCommandReason::SetDomains => "dns:set-domains".to_owned(),
                DnsCommandReason::RevertInterface => "dns:revert".to_owned(),
            });

            if self.fail_on == Some(command.reason) {
                Err(DnsPolicyError::CommandFailed {
                    operation: "injected dns".to_owned(),
                    detail: "injected failure".to_owned(),
                })
            } else {
                Ok(())
            }
        }
    }

    struct ErrorChannelWorker;

    impl TunnelWorker for ErrorChannelWorker {
        fn run(
            self,
            commands: mpsc::Receiver<TunnelWorkerCommand>,
            events: mpsc::Sender<TunnelWorkerEvent>,
        ) {
            if let Ok(TunnelWorkerCommand::Connect(_)) = commands.recv() {
                let _ = events.send(TunnelWorkerEvent::Error(TunnelLifecycleError::new(
                    "scripted_failure",
                    "scripted tunnel worker failed",
                )));
            }
        }
    }

    fn recv_worker_event(worker: &TunnelWorkerHandle) -> TunnelWorkerEvent {
        worker
            .recv_event_timeout(Duration::from_secs(1))
            .expect("worker event")
    }

    struct TunCleanupBackend {
        operations: Rc<RefCell<Vec<String>>>,
        delete_result: Result<bool, NetworkPolicyError>,
    }

    impl TunCleanupBackend {
        fn new(delete_result: Result<bool, NetworkPolicyError>) -> Self {
            Self {
                operations: Rc::new(RefCell::new(Vec::new())),
                delete_result,
            }
        }
    }

    impl LinuxNetworkBackend for TunCleanupBackend {
        fn default_route(&self) -> Result<DefaultRouteSnapshot, NetworkPolicyError> {
            Ok(sample_default_route())
        }

        fn link_exists(&self, ifname: &str) -> Result<bool, NetworkPolicyError> {
            self.operations
                .borrow_mut()
                .push(format!("link:exists:{ifname}"));
            self.delete_result
                .as_ref()
                .map(|deleted| *deleted)
                .map_err(Clone::clone)
        }

        fn interface_ipv4_cidrs(&self, _ifname: &str) -> Result<Vec<Ipv4Cidr>, NetworkPolicyError> {
            Ok(Vec::new())
        }

        fn route_snapshot(
            &self,
            _destination: Ipv4Cidr,
        ) -> Result<Option<RouteSnapshot>, NetworkPolicyError> {
            Ok(None)
        }

        fn replace_ipv4_address(
            &self,
            _ifname: &str,
            _address: Ipv4Addr,
            _prefix_len: u8,
        ) -> Result<(), NetworkPolicyError> {
            Ok(())
        }

        fn delete_ipv4_address(
            &self,
            _ifname: &str,
            _address: Ipv4Addr,
            _prefix_len: u8,
        ) -> Result<(), NetworkPolicyError> {
            Ok(())
        }

        fn set_link_mtu(&self, _ifname: &str, _mtu: u32) -> Result<(), NetworkPolicyError> {
            Ok(())
        }

        fn set_link_up(&self, _ifname: &str) -> Result<(), NetworkPolicyError> {
            Ok(())
        }

        fn set_link_down(&self, _ifname: &str) -> Result<(), NetworkPolicyError> {
            Ok(())
        }

        fn delete_link_if_exists(&self, ifname: &str) -> Result<bool, NetworkPolicyError> {
            self.operations
                .borrow_mut()
                .push(format!("link:del:{ifname}"));
            self.delete_result.clone()
        }

        fn replace_route(&self, _route: &PlannedRoute) -> Result<(), NetworkPolicyError> {
            Ok(())
        }

        fn restore_route(&self, _route: &RouteSnapshot) -> Result<(), NetworkPolicyError> {
            Ok(())
        }

        fn delete_route(&self, _route: &PlannedRoute) -> Result<(), NetworkPolicyError> {
            Ok(())
        }

        fn ipv6_default_route_block_exists(&self) -> Result<bool, NetworkPolicyError> {
            Ok(false)
        }

        fn block_ipv6_default_route(&self) -> Result<(), NetworkPolicyError> {
            Ok(())
        }

        fn unblock_ipv6_default_route(&self) -> Result<(), NetworkPolicyError> {
            Ok(())
        }
    }

    struct TunCleanupDnsRunner {
        operations: Rc<RefCell<Vec<String>>>,
        result: Result<(), DnsPolicyError>,
    }

    impl TunCleanupDnsRunner {
        fn new(operations: Rc<RefCell<Vec<String>>>, result: Result<(), DnsPolicyError>) -> Self {
            Self { operations, result }
        }
    }

    impl DnsCommandRunner for TunCleanupDnsRunner {
        fn run(&mut self, command: &DnsCommand) -> Result<(), DnsPolicyError> {
            self.operations
                .borrow_mut()
                .push(format!("dns:revert:{}", command.args[1]));
            self.result.clone()
        }
    }
}
