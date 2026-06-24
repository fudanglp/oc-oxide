use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use oc_oxide_auth::{
    AuthAnswer, AuthFieldKind, AuthFormDecision, AuthFormHandler, AuthRequest, AuthResponse,
};
use oc_oxide_config::{
    parse_toml_vpn_profile, KeyringVpnPasswordVault, ServerUrl, TunnelProfile, VpnPassword,
    VpnPasswordKey, VpnPasswordVault, VpnProfile,
};
use oc_oxide_daemon::{
    default_daemon_socket_path, plan_daemon_network_policy, tunnel_policy_input_from_ip_info,
    DaemonWorkerController, OpenConnectTunnelWorker, OpenConnectWorkflow, TunnelLifecycleError,
    TunnelLifecycleStep, TunnelWorkerCommand, TunnelWorkerEvent, TunnelWorkerFactory,
    TunnelWorkerHandle, VpnProfileResolver,
};
use oc_oxide_dns::{format_dns_command, DnsCommandPlan, DnsMode, SystemdResolvedCommandRunner};
use oc_oxide_ipc::{
    decode_event_line, decode_response_line, encode_command_line, AuthPrompt, AuthPromptFieldKind,
    AuthSubmission, AuthSubmittedField, DaemonState, DisconnectReason, IpcCommand, IpcEvent,
    IpcResponse, ProgressUpdate,
};
use oc_oxide_net::{
    render_linux_ip_route_commands, AppliedNetworkRouteState, DefaultRouteSnapshot, Ipv4Cidr,
    LinuxNetlinkRunner, LinuxNetworkBackend, NetworkPolicy, NetworkRoutePlan, RouteCommandPlan,
    RouteMode, RouteRevertAction,
};
use oc_oxide_policy::{
    apply_policy_with, build_policy_plan_from_tunnel_input, revert_policy_with, AppliedPolicyState,
    PolicyPlan, PolicyRevertErrors,
};
use oc_oxide_sync::{
    decode_device_flow_poll_response, decode_device_flow_start_response,
    decode_github_token_refresh_response, poll_device_flow_once, refresh_github_user_access_token,
    DeviceFlowPoll, DeviceFlowStart, DeviceFlowTokenSet, GithubAppConfig, GithubContentsClient,
    GithubContentsHttp, GithubContentsMethod, GithubContentsRequest, GithubContentsResponse,
    GithubDeviceFlowHttp, GithubRefreshToken, GithubTokenRefreshHttp, GithubTokenVault,
    KeyringGithubTokenVault, ManifestSyncCodec, PrivateRepoSyncCodec, SyncClient, SyncError,
    SyncManifest, SyncObjectPath, SyncProfileConnection, SyncProfileDocument, SyncWrite,
    DEFAULT_GITHUB_TOKEN_ACCOUNT,
};
use oc_oxide_tunnel::{
    CancelHandle, IpInfoSnapshot, MainloopOutcome, OpenConnectSession, SplitRoute, TunnelEvent,
    TunnelEventSink,
};

const SMOKE_MAINLOOP_USAGE: &str = "usage: ocx smoke-mainloop --profile <path> [--seconds <n>] [--route-mode split|full|off] [--dns-mode split|full|off] [--local-bypass <cidr>]... [--apply-policy]";
const GITHUB_DEVICE_LOGIN_USAGE: &str = "usage: ocx github-device-login [--no-store]";
const GITHUB_SYNC_SMOKE_USAGE: &str = "usage: ocx github-sync-smoke [--no-store]";
const GITHUB_SYNC_INIT_USAGE: &str = "usage: ocx github-sync-init [--no-store]";
const GITHUB_SYNC_RESET_USAGE: &str = "usage: ocx github-sync-reset [--no-store]";
const GITHUB_SYNC_UPLOAD_USAGE: &str = "usage: ocx github-sync-upload [--no-store]";
const GITHUB_DEVICE_CODE_URL: &str = "https://github.com/login/device/code";
const GITHUB_ACCESS_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const GITHUB_API_URL: &str = "https://api.github.com";
const GITHUB_DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
const GITHUB_REFRESH_TOKEN_GRANT_TYPE: &str = "refresh_token";
const GITHUB_API_VERSION: &str = "2022-11-28";
const USER_AGENT: &str = "oc-oxide/0.1";

fn main() {
    if let Err(err) = run() {
        eprintln!("ocx error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("smoke-cookie") => {
            let profile_path = parse_profile_arg("smoke-cookie", args.collect())?;
            run_smoke(&profile_path, SmokeMode::Cookie)?;
        }
        Some("smoke-tun") => {
            let profile_path = parse_profile_arg("smoke-tun", args.collect())?;
            run_smoke(&profile_path, SmokeMode::Tun)?;
        }
        Some("smoke-mainloop") => {
            let smoke_args = parse_smoke_mainloop_args(args.collect())?;
            let profile_path = smoke_args.profile_path.clone();
            run_smoke(&profile_path, SmokeMode::Mainloop(smoke_args))?;
        }
        Some("daemon-smoke") => {
            let profile = parse_named_profile_arg("daemon-smoke", args.collect())?;
            run_daemon_smoke(&profile)?;
        }
        Some("connect") => {
            let profile = parse_positional_profile_arg("connect", args.collect())?;
            run_ipc_connect(&profile)?;
        }
        Some("status") => {
            run_ipc_one_shot(IpcCommand::Status)?;
        }
        Some("disconnect") => {
            run_ipc_one_shot(IpcCommand::Disconnect)?;
        }
        Some("diagnostics") => {
            run_ipc_one_shot(IpcCommand::Diagnostics)?;
        }
        Some("vault-store") => {
            let profile = parse_positional_profile_arg("vault-store", args.collect())?;
            run_vault_store(&profile)?;
        }
        Some("github-device-login") => {
            let login_args = parse_github_device_login_args(args.collect())?;
            run_github_device_login(login_args)?;
        }
        Some("github-sync-smoke") => {
            let smoke_args = parse_github_sync_smoke_args(args.collect())?;
            run_github_sync_smoke(smoke_args)?;
        }
        Some("github-sync-init") => {
            let init_args = parse_github_sync_init_args(args.collect())?;
            run_github_sync_init(init_args)?;
        }
        Some("github-sync-reset") => {
            let reset_args = parse_github_sync_reset_args(args.collect())?;
            run_github_sync_reset(reset_args)?;
        }
        Some("github-sync-upload") => {
            let upload_args = parse_github_sync_upload_args(args.collect())?;
            run_github_sync_upload(upload_args)?;
        }
        Some("help") | Some("--help") | Some("-h") | None => print_help(),
        Some(command) => return Err(format!("unknown ocx command {command:?}").into()),
    }

    Ok(())
}

fn print_help() {
    println!("ocx smoke-cookie --profile <path>");
    println!("ocx smoke-tun --profile <path>");
    println!(
        "ocx smoke-mainloop --profile <path> [--seconds <n>] [--route-mode split|full|off] [--dns-mode split|full|off] [--local-bypass <cidr>]... [--apply-policy]"
    );
    println!("ocx daemon-smoke --profile <name>");
    println!("ocx connect <profile>");
    println!("ocx status");
    println!("ocx disconnect");
    println!("ocx diagnostics");
    println!("ocx vault-store <profile>");
    println!("ocx github-device-login [--no-store]");
    println!("ocx github-sync-smoke [--no-store]");
    println!("ocx github-sync-init [--no-store]");
    println!("ocx github-sync-reset [--no-store]");
    println!("ocx github-sync-upload [--no-store]");
}

fn parse_profile_arg(command: &str, args: Vec<String>) -> Result<PathBuf, Box<dyn Error>> {
    let mut iter = args.into_iter();
    match (iter.next().as_deref(), iter.next(), iter.next()) {
        (Some("--profile"), Some(path), None) => Ok(PathBuf::from(path)),
        _ => Err(format!("usage: ocx {command} --profile <path>").into()),
    }
}

fn parse_named_profile_arg(command: &str, args: Vec<String>) -> Result<String, Box<dyn Error>> {
    let mut iter = args.into_iter();
    match (iter.next().as_deref(), iter.next(), iter.next()) {
        (Some("--profile"), Some(profile), None) if !profile.trim().is_empty() => Ok(profile),
        _ => Err(format!("usage: ocx {command} --profile <name>").into()),
    }
}

fn parse_positional_profile_arg(
    command: &str,
    args: Vec<String>,
) -> Result<String, Box<dyn Error>> {
    let mut iter = args.into_iter();
    match (iter.next(), iter.next()) {
        (Some(profile), None) if !profile.trim().is_empty() => Ok(profile),
        _ => Err(format!("usage: ocx {command} <profile>").into()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GithubDeviceLoginArgs {
    no_store: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GithubSyncInitArgs {
    no_store: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GithubSyncUploadArgs {
    no_store: bool,
}

fn parse_github_device_login_args(
    args: Vec<String>,
) -> Result<GithubDeviceLoginArgs, Box<dyn Error>> {
    parse_github_no_store_args(args, GITHUB_DEVICE_LOGIN_USAGE)
}

fn parse_github_sync_smoke_args(
    args: Vec<String>,
) -> Result<GithubDeviceLoginArgs, Box<dyn Error>> {
    parse_github_no_store_args(args, GITHUB_SYNC_SMOKE_USAGE)
}

fn parse_github_sync_init_args(args: Vec<String>) -> Result<GithubSyncInitArgs, Box<dyn Error>> {
    Ok(GithubSyncInitArgs {
        no_store: parse_github_no_store_args(args, GITHUB_SYNC_INIT_USAGE)?.no_store,
    })
}

fn parse_github_sync_upload_args(
    args: Vec<String>,
) -> Result<GithubSyncUploadArgs, Box<dyn Error>> {
    parse_github_write_args(args, GITHUB_SYNC_UPLOAD_USAGE)
}

fn parse_github_sync_reset_args(args: Vec<String>) -> Result<GithubSyncUploadArgs, Box<dyn Error>> {
    parse_github_write_args(args, GITHUB_SYNC_RESET_USAGE)
}

fn parse_github_write_args(
    args: Vec<String>,
    usage: &'static str,
) -> Result<GithubSyncUploadArgs, Box<dyn Error>> {
    Ok(GithubSyncUploadArgs {
        no_store: parse_github_no_store_args(args, usage)?.no_store,
    })
}

fn parse_github_no_store_args(
    args: Vec<String>,
    usage: &'static str,
) -> Result<GithubDeviceLoginArgs, Box<dyn Error>> {
    let mut no_store = false;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--no-store" => no_store = true,
            _ => return Err(usage.into()),
        }
    }

    Ok(GithubDeviceLoginArgs { no_store })
}

fn parse_smoke_mainloop_args(args: Vec<String>) -> Result<SmokeMainloopArgs, Box<dyn Error>> {
    let mut profile_path = None;
    let mut seconds = 5;
    let mut route_mode = RouteMode::Split;
    let mut dns_mode = DnsMode::Split;
    let mut local_bypass_cidrs = Vec::new();
    let mut apply_policy = false;
    let mut iter = args.into_iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--profile" => {
                let Some(path) = iter.next() else {
                    return Err(SMOKE_MAINLOOP_USAGE.into());
                };
                profile_path = Some(PathBuf::from(path));
            }
            "--seconds" => {
                let Some(value) = iter.next() else {
                    return Err(SMOKE_MAINLOOP_USAGE.into());
                };
                seconds = value.parse()?;
                if seconds == 0 {
                    return Err("smoke-mainloop --seconds must be greater than zero".into());
                }
            }
            "--route-mode" => {
                let Some(value) = iter.next() else {
                    return Err(SMOKE_MAINLOOP_USAGE.into());
                };
                route_mode = value.parse()?;
            }
            "--dns-mode" => {
                let Some(value) = iter.next() else {
                    return Err(SMOKE_MAINLOOP_USAGE.into());
                };
                dns_mode = value.parse()?;
            }
            "--local-bypass" => {
                let Some(value) = iter.next() else {
                    return Err(SMOKE_MAINLOOP_USAGE.into());
                };
                local_bypass_cidrs.push(value.parse()?);
            }
            "--apply-policy" => {
                apply_policy = true;
            }
            _ => {
                return Err(SMOKE_MAINLOOP_USAGE.into());
            }
        }
    }

    let Some(profile_path) = profile_path else {
        return Err(SMOKE_MAINLOOP_USAGE.into());
    };

    Ok(SmokeMainloopArgs {
        profile_path,
        seconds,
        route_mode,
        dns_mode,
        local_bypass_cidrs,
        apply_policy,
    })
}

fn run_github_device_login(args: GithubDeviceLoginArgs) -> Result<(), Box<dyn Error>> {
    let tokens = authorize_github_device_flow()?;
    print_github_token_metadata(&tokens);
    store_github_tokens(&tokens, args.no_store)?;
    Ok(())
}

fn run_github_sync_smoke(args: GithubDeviceLoginArgs) -> Result<(), Box<dyn Error>> {
    let tokens = authorize_or_refresh_github_for_sync(args.no_store)?;

    let http = ReqwestGithubContentsHttp::new()?;
    let client = GithubContentsClient::oc_oxide_sync(tokens.access_token.clone(), http)?;
    match client.read_object(&SyncObjectPath::manifest())? {
        Some(object) => {
            println!("manifest: present");
            println!("manifest_sha: {}", object.sha);
            println!("manifest_bytes: {}", object.bytes().len());
        }
        None => {
            println!("manifest: missing");
        }
    }

    Ok(())
}

fn run_github_sync_init(args: GithubSyncInitArgs) -> Result<(), Box<dyn Error>> {
    let tokens = authorize_or_refresh_github_for_sync(args.no_store)?;

    let http = ReqwestGithubContentsHttp::new()?;
    let mut client = GithubContentsClient::oc_oxide_sync(tokens.access_token.clone(), http)?;
    let path = SyncObjectPath::manifest();
    if let Some(existing) = client.read_object(&path)? {
        println!("manifest: present");
        println!("manifest_sha: {}", existing.sha);
        println!("manifest_bytes: {}", existing.bytes().len());
        println!("init: skipped");
        return Ok(());
    }

    let codec = PrivateRepoSyncCodec::new();
    let blob = codec.encode_manifest(&SyncManifest::new())?;
    let written = client.write_object(SyncWrite::create(
        blob,
        "Initialize oc-oxide sync manifest",
    )?)?;
    println!("manifest: created");
    println!("manifest_sha: {}", written.sha);
    println!("manifest_bytes: {}", written.bytes().len());

    Ok(())
}

fn run_github_sync_upload(args: GithubSyncUploadArgs) -> Result<(), Box<dyn Error>> {
    let documents = local_sync_profile_documents()?;
    if documents.is_empty() {
        return Err("no local profiles to upload".into());
    }

    let tokens = authorize_or_refresh_github_for_sync(args.no_store)?;
    let http = ReqwestGithubContentsHttp::new()?;
    let mut client = GithubContentsClient::oc_oxide_sync(tokens.access_token.clone(), http)?;
    let codec = PrivateRepoSyncCodec::new();
    let report = oc_oxide_sync::upload_profile_documents(
        &mut client,
        &codec,
        &documents,
        &sync_updated_at(),
        &sync_device_id(),
    )
    .map_err(github_sync_upload_error)?;

    println!("upload: complete");
    println!("uploaded_profiles: {}", report.uploaded_profiles);
    println!("manifest_profile_count: {}", report.manifest_profile_count);
    println!("manifest_sha: {}", report.manifest_sha);
    println!("manifest_bytes: {}", report.manifest_bytes);

    Ok(())
}

fn run_github_sync_reset(args: GithubSyncUploadArgs) -> Result<(), Box<dyn Error>> {
    let tokens = authorize_or_refresh_github_for_sync(args.no_store)?;
    let http = ReqwestGithubContentsHttp::new()?;
    let mut client = GithubContentsClient::oc_oxide_sync(tokens.access_token.clone(), http)?;
    let codec = PrivateRepoSyncCodec::new();
    let blob = codec.encode_manifest(&SyncManifest::new())?;
    let path = SyncObjectPath::manifest();

    let written = match client.read_object(&path)? {
        Some(existing) => client.write_object(SyncWrite::update(
            blob,
            existing.sha,
            "Reset oc-oxide sync manifest",
        )?)?,
        None => client.write_object(SyncWrite::create(
            blob,
            "Initialize oc-oxide sync manifest",
        )?)?,
    };

    println!("manifest: reset");
    println!("manifest_sha: {}", written.sha);
    println!("manifest_bytes: {}", written.bytes().len());

    Ok(())
}

fn github_sync_upload_error(err: SyncError) -> Box<dyn Error> {
    err.into()
}

fn authorize_or_refresh_github_for_sync(
    no_store: bool,
) -> Result<DeviceFlowTokenSet, Box<dyn Error>> {
    if no_store {
        println!("auth: device_flow");
        let tokens = authorize_github_device_flow()?;
        print_github_token_metadata(&tokens);
        store_github_tokens(&tokens, true)?;
        return Ok(tokens);
    }

    let mut vault = KeyringGithubTokenVault::new();
    if let Some(refresh_token) = vault.get_refresh_token(DEFAULT_GITHUB_TOKEN_ACCOUNT)? {
        match refresh_github_tokens(&refresh_token) {
            Ok(tokens) => {
                println!("auth: refresh_token");
                print_github_token_metadata(&tokens);
                store_github_tokens_in_vault(&mut vault, &tokens)?;
                return Ok(tokens);
            }
            Err(err) => {
                println!("refresh: failed ({err})");
            }
        }
    } else {
        println!("refresh: missing");
    }

    println!("auth: device_flow");
    let tokens = authorize_github_device_flow()?;
    print_github_token_metadata(&tokens);
    store_github_tokens_in_vault(&mut vault, &tokens)?;
    Ok(tokens)
}

fn refresh_github_tokens(
    refresh_token: &GithubRefreshToken,
) -> Result<DeviceFlowTokenSet, Box<dyn Error>> {
    let app = GithubAppConfig::oc_oxide_sync();
    app.validate()?;
    let mut http = ReqwestGithubTokenRefreshHttp::new()?;
    Ok(refresh_github_user_access_token(
        &mut http,
        &app.client_id,
        refresh_token,
    )?)
}

fn authorize_github_device_flow() -> Result<DeviceFlowTokenSet, Box<dyn Error>> {
    let app = GithubAppConfig::oc_oxide_sync();
    app.validate()?;

    let mut http = ReqwestGithubDeviceFlowHttp::new()?;
    let start = http.start_device_flow(&app.client_id)?;
    print_device_flow_start(&start);

    let expires_at = Instant::now() + Duration::from_secs(start.expires_in_secs);
    let mut interval_secs = start.interval_secs;
    loop {
        wait_for_device_flow_poll(expires_at, interval_secs)?;
        let step =
            poll_device_flow_once(&mut http, &app.client_id, &start.device_code, interval_secs)?;
        interval_secs = step.next_interval_secs;

        match step.poll {
            DeviceFlowPoll::Pending { .. } => {
                println!("authorization_pending: retrying in {interval_secs}s");
            }
            DeviceFlowPoll::SlowDown { .. } => {
                println!("slow_down: retrying in {interval_secs}s");
            }
            DeviceFlowPoll::Authorized(tokens) => {
                return Ok(tokens);
            }
            DeviceFlowPoll::AccessDenied => {
                return Err("GitHub device authorization was denied".into());
            }
            DeviceFlowPoll::Expired => {
                return Err("GitHub device authorization expired".into());
            }
        }
    }
}

fn print_github_token_metadata(tokens: &DeviceFlowTokenSet) {
    println!("authorized: true");
    println!("token_type: {}", tokens.token_type);
    println!("scope: {}", tokens.scope);
    println!("expires_in_secs: {}", tokens.expires_in_secs);
    println!(
        "refresh_token_expires_in_secs: {}",
        tokens.refresh_token_expires_in_secs
    );
}

fn store_github_tokens(tokens: &DeviceFlowTokenSet, no_store: bool) -> Result<(), Box<dyn Error>> {
    if no_store {
        println!("storage: skipped (--no-store)");
    } else {
        let mut vault = KeyringGithubTokenVault::new();
        store_github_tokens_in_vault(&mut vault, tokens)?;
    }

    Ok(())
}

fn store_github_tokens_in_vault(
    vault: &mut impl GithubTokenVault,
    tokens: &DeviceFlowTokenSet,
) -> Result<(), Box<dyn Error>> {
    vault.set_refresh_token(DEFAULT_GITHUB_TOKEN_ACCOUNT, &tokens.refresh_token)?;
    println!("storage: keyring");
    println!("keyring_account: {DEFAULT_GITHUB_TOKEN_ACCOUNT}");
    Ok(())
}

fn print_device_flow_start(start: &DeviceFlowStart) {
    println!("verification_uri: {}", start.verification_uri);
    println!("user_code: {}", start.user_code);
    println!("expires_in_secs: {}", start.expires_in_secs);
    println!("poll_interval_secs: {}", start.interval_secs);
}

fn wait_for_device_flow_poll(
    expires_at: Instant,
    interval_secs: u64,
) -> Result<(), Box<dyn Error>> {
    let now = Instant::now();
    if now >= expires_at {
        return Err("GitHub device code expired before authorization completed".into());
    }

    let interval = Duration::from_secs(interval_secs);
    let remaining = expires_at.saturating_duration_since(now);
    if remaining <= interval {
        thread::sleep(remaining);
        return Err("GitHub device code expired before authorization completed".into());
    }

    thread::sleep(interval);
    Ok(())
}

#[derive(Debug)]
struct ReqwestGithubDeviceFlowHttp {
    client: reqwest::blocking::Client,
}

impl ReqwestGithubDeviceFlowHttp {
    fn new() -> Result<Self, SyncError> {
        let client = reqwest::blocking::Client::builder()
            .user_agent(USER_AGENT)
            .build()
            .map_err(github_request_error("create device flow HTTP client"))?;
        Ok(Self { client })
    }
}

impl GithubDeviceFlowHttp for ReqwestGithubDeviceFlowHttp {
    fn start_device_flow(&mut self, client_id: &str) -> Result<DeviceFlowStart, SyncError> {
        if client_id.trim().is_empty() {
            return Err(SyncError::EmptyField { field: "client ID" });
        }

        let response = self
            .client
            .post(GITHUB_DEVICE_CODE_URL)
            .header("Accept", "application/json")
            .form(&[("client_id", client_id)])
            .send()
            .map_err(github_request_error("start GitHub device flow"))?;
        let status = response.status();
        let body = response.text().map_err(github_request_error(
            "read GitHub device flow start response",
        ))?;
        let parsed = decode_device_flow_start_response(&body);
        if status.is_success() {
            return parsed;
        }

        match parsed {
            Ok(_) => Err(github_status_error(
                "start GitHub device flow",
                status.as_u16(),
            )),
            Err(err) => Err(err),
        }
    }

    fn poll_device_flow(
        &mut self,
        client_id: &str,
        device_code: &str,
        current_interval_secs: u64,
    ) -> Result<DeviceFlowPoll, SyncError> {
        if client_id.trim().is_empty() {
            return Err(SyncError::EmptyField { field: "client ID" });
        }
        if device_code.trim().is_empty() {
            return Err(SyncError::EmptyField {
                field: "device code",
            });
        }

        let response = self
            .client
            .post(GITHUB_ACCESS_TOKEN_URL)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", client_id),
                ("device_code", device_code),
                ("grant_type", GITHUB_DEVICE_GRANT_TYPE),
            ])
            .send()
            .map_err(github_request_error("poll GitHub device flow"))?;
        let status = response.status();
        let body = response.text().map_err(github_request_error(
            "read GitHub device flow poll response",
        ))?;
        let parsed = decode_device_flow_poll_response(&body, current_interval_secs);
        if status.is_success() {
            return parsed;
        }

        match parsed {
            Ok(poll) => Ok(poll),
            Err(err) => Err(err),
        }
    }
}

#[derive(Debug)]
struct ReqwestGithubTokenRefreshHttp {
    client: reqwest::blocking::Client,
}

impl ReqwestGithubTokenRefreshHttp {
    fn new() -> Result<Self, SyncError> {
        let client = reqwest::blocking::Client::builder()
            .user_agent(USER_AGENT)
            .build()
            .map_err(github_request_error("create token refresh HTTP client"))?;
        Ok(Self { client })
    }
}

impl GithubTokenRefreshHttp for ReqwestGithubTokenRefreshHttp {
    fn refresh_user_access_token(
        &mut self,
        client_id: &str,
        refresh_token: &GithubRefreshToken,
    ) -> Result<DeviceFlowTokenSet, SyncError> {
        if client_id.trim().is_empty() {
            return Err(SyncError::EmptyField { field: "client ID" });
        }

        let response = self
            .client
            .post(GITHUB_ACCESS_TOKEN_URL)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", client_id),
                ("grant_type", GITHUB_REFRESH_TOKEN_GRANT_TYPE),
                ("refresh_token", refresh_token.expose_secret()),
            ])
            .send()
            .map_err(github_request_error("refresh GitHub user access token"))?;
        let status = response.status();
        let body = response
            .text()
            .map_err(github_request_error("read GitHub token refresh response"))?;
        let parsed = decode_github_token_refresh_response(&body);
        if status.is_success() {
            return parsed;
        }

        match parsed {
            Ok(_) => Err(github_status_error(
                "refresh GitHub user access token",
                status.as_u16(),
            )),
            Err(err) => Err(err),
        }
    }
}

#[derive(Debug)]
struct ReqwestGithubContentsHttp {
    client: reqwest::blocking::Client,
}

impl ReqwestGithubContentsHttp {
    fn new() -> Result<Self, SyncError> {
        let client = reqwest::blocking::Client::builder()
            .user_agent(USER_AGENT)
            .build()
            .map_err(github_request_error("create GitHub contents HTTP client"))?;
        Ok(Self { client })
    }
}

impl GithubContentsHttp for ReqwestGithubContentsHttp {
    fn send_contents_request(
        &self,
        token: &oc_oxide_sync::GithubAccessToken,
        request: &GithubContentsRequest,
    ) -> Result<GithubContentsResponse, SyncError> {
        let method = match request.method {
            GithubContentsMethod::Get => reqwest::Method::GET,
            GithubContentsMethod::Put => reqwest::Method::PUT,
            GithubContentsMethod::Delete => reqwest::Method::DELETE,
        };
        let url = format!("{GITHUB_API_URL}{}", request.api_path);
        let mut builder = self
            .client
            .request(method, url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
            .bearer_auth(token.expose_secret());

        if let Some(body) = request.body() {
            builder = builder
                .header("Content-Type", "application/json")
                .body(body.to_owned());
        }

        let response = builder
            .send()
            .map_err(github_request_error("send GitHub contents request"))?;
        let status = response.status().as_u16();
        let body = response
            .text()
            .map_err(github_request_error("read GitHub contents response"))?;

        Ok(GithubContentsResponse::new(status, body))
    }
}

fn github_request_error(
    operation: &'static str,
) -> impl FnOnce(reqwest::Error) -> SyncError + 'static {
    move |err| SyncError::Backend {
        operation,
        detail: err.without_url().to_string(),
    }
}

fn github_status_error(operation: &'static str, status: u16) -> SyncError {
    SyncError::Backend {
        operation,
        detail: format!("GitHub returned HTTP {status}"),
    }
}

fn run_ipc_one_shot(command: IpcCommand) -> Result<(), Box<dyn Error>> {
    let mut stream = connect_daemon_socket()?;
    stream.write_all(encode_command_line(&command)?.as_bytes())?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err("daemon closed IPC connection without a response".into());
        }

        match decode_ipc_line(&line)? {
            IpcLine::Response(response) => {
                print_ipc_response(&response);
                if let IpcResponse::Error(error) = response {
                    return Err(format!("{}: {}", error.code, error.message).into());
                }
                return Ok(());
            }
            IpcLine::Event(event) => print_ipc_event(&event),
        }
    }
}

fn run_ipc_connect(profile: &str) -> Result<(), Box<dyn Error>> {
    let vpn_password = load_vpn_password_from_keyring(profile)?;
    let stream = connect_daemon_socket()?;
    stream.set_read_timeout(None)?;
    let read_stream = stream.try_clone()?;
    let mut reader = BufReader::new(read_stream);
    let mut writer = BufWriter::new(stream);
    let command = IpcCommand::Connect {
        profile: profile.to_owned(),
    };
    writer.write_all(encode_command_line(&command)?.as_bytes())?;
    writer.flush()?;

    let mut auth_prompt_count = 0;
    let mut auth_state = IpcAuthSessionState::new(vpn_password);
    let mut connect_accepted = false;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err("daemon closed IPC connection before connect completed".into());
        }

        match decode_ipc_line(&line)? {
            IpcLine::Response(response) => {
                if matches!(response, IpcResponse::Accepted) {
                    connect_accepted = true;
                }
                print_ipc_response(&response);
                if let IpcResponse::Error(error) = response {
                    return Err(format!("{}: {}", error.code, error.message).into());
                }
            }
            IpcLine::Event(event) => match event {
                IpcEvent::AuthPrompt(prompt) => {
                    let submission =
                        read_ipc_auth_submission(&prompt, auth_prompt_count, &mut auth_state)?;
                    auth_prompt_count += 1;
                    writer.write_all(
                        encode_command_line(&IpcCommand::SubmitAuth(submission))?.as_bytes(),
                    )?;
                    writer.flush()?;
                }
                IpcEvent::Connected { interface } => {
                    println!("ocx: connected interface={interface}");
                    return Ok(());
                }
                IpcEvent::Error(error) => {
                    print_ipc_event(&IpcEvent::Error(error.clone()));
                    if connect_event_error_is_fatal(connect_accepted) {
                        return Err(format!("{}: {}", error.code, error.message).into());
                    }
                }
                event => print_ipc_event(&event),
            },
        }
    }
}

fn load_vpn_password_from_keyring(
    profile_name: &str,
) -> Result<Option<VpnPassword>, Box<dyn Error>> {
    let profile = load_toml_profile(profile_name)?;
    let key = VpnPasswordKey::for_vpn_profile(&profile)?;
    KeyringVpnPasswordVault::new()
        .get_vpn_password(&key)
        .map_err(|err| err.into())
}

fn connect_event_error_is_fatal(connect_accepted: bool) -> bool {
    connect_accepted
}

enum IpcLine {
    Response(IpcResponse),
    Event(IpcEvent),
}

fn decode_ipc_line(line: &str) -> Result<IpcLine, Box<dyn Error>> {
    if let Ok(response) = decode_response_line(line) {
        return Ok(IpcLine::Response(response));
    }

    Ok(IpcLine::Event(decode_event_line(line)?))
}

fn connect_daemon_socket() -> Result<UnixStream, Box<dyn Error>> {
    let path = default_daemon_socket_path();
    UnixStream::connect(&path)
        .map_err(|err| format!("failed to connect daemon socket {}: {err}", path.display()).into())
}

fn run_vault_store(profile_name: &str) -> Result<(), Box<dyn Error>> {
    let profile = load_toml_profile(profile_name)?;
    let key = VpnPasswordKey::for_vpn_profile(&profile)?;
    let password = VpnPassword::new(read_secret_from_stdin(SecretPrompt {
        kind: SecretPromptKind::VpnPassword,
        field_id: profile_name.to_owned(),
        context: SecretPromptContext::Vault,
    })?)?;

    KeyringVpnPasswordVault::new().set_vpn_password(&key, &password)?;
    println!("ocx: stored VPN password in user keyring for profile {profile_name}");
    Ok(())
}

fn load_toml_profile(profile_name: &str) -> Result<VpnProfile, Box<dyn Error>> {
    let path = local_profile_path(profile_name)?;
    let content = fs::read_to_string(&path)
        .map_err(|err| format!("failed to read profile {}: {err}", path.display()))?;
    parse_toml_vpn_profile(profile_name, &content)
        .map_err(|err| format!("failed to parse profile {}: {err}", path.display()).into())
}

fn local_sync_profile_documents() -> Result<Vec<SyncProfileDocument>, Box<dyn Error>> {
    let mut documents = Vec::new();
    match fs::read_dir(local_profile_dir()?) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|extension| extension.to_str()) != Some("toml") {
                    continue;
                }
                let Some(name) = path.file_stem().and_then(|stem| stem.to_str()) else {
                    continue;
                };
                if validate_local_profile_name(name).is_err() {
                    continue;
                }
                documents.push(sync_profile_document(&load_toml_profile(name)?)?);
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    Ok(documents)
}

fn sync_profile_document(profile: &VpnProfile) -> Result<SyncProfileDocument, Box<dyn Error>> {
    let tunnel = profile.tunnel();
    let mut connection = SyncProfileConnection::anyconnect(
        tunnel.server_url().as_openconnect_url(),
        tunnel.reported_os(),
    )?;

    if let Some(authgroup) = tunnel.authgroup() {
        connection = connection.with_authgroup(authgroup)?;
    }

    if let Some(username) = tunnel.username() {
        connection = connection.with_username(username)?;
    }

    Ok(
        SyncProfileDocument::new(tunnel.name(), tunnel.name(), connection)?
            .with_company_domains(profile.company_domains().to_vec())?
            .with_local_bypass(
                profile
                    .local_bypass_cidrs()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            )?,
    )
}

fn local_profile_path(profile_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    validate_local_profile_name(profile_name)?;
    let profile_dir = local_profile_dir()?;
    local_profile_path_in_dir(profile_name, profile_dir)
}

fn local_profile_dir() -> Result<PathBuf, Box<dyn Error>> {
    Ok(match env::var_os("OC_OXIDE_PROFILE_DIR") {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => {
            let home = env::var_os("HOME").ok_or("HOME is not set")?;
            PathBuf::from(home)
                .join(".config")
                .join("oc-oxide")
                .join("profiles")
        }
    })
}

fn local_profile_path_in_dir(
    profile_name: &str,
    profile_dir: impl Into<PathBuf>,
) -> Result<PathBuf, Box<dyn Error>> {
    validate_local_profile_name(profile_name)?;
    let profile_dir = profile_dir.into();
    Ok(profile_dir.join(format!("{profile_name}.toml")))
}

fn validate_local_profile_name(profile_name: &str) -> Result<(), Box<dyn Error>> {
    let valid = !profile_name.is_empty()
        && profile_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err(format!("invalid profile name {profile_name:?}").into())
    }
}

fn sync_updated_at() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    format!("unix:{seconds}")
}

fn sync_device_id() -> String {
    env::var("HOSTNAME")
        .ok()
        .or_else(|| env::var("COMPUTERNAME").ok())
        .and_then(|value| {
            let value = value.trim();
            (!value.is_empty() && !value.contains('\0')).then(|| value.to_owned())
        })
        .unwrap_or_else(|| "ocx".to_owned())
}

fn print_ipc_response(response: &IpcResponse) {
    match response {
        IpcResponse::Accepted => println!("ocx: accepted"),
        IpcResponse::Status(status) => {
            println!("ocx: state: {:?}", status.state);
            println!(
                "ocx: active profile: {}",
                status.active_profile.as_deref().unwrap_or("<none>")
            );
            println!(
                "ocx: interface: {}",
                status.interface.as_deref().unwrap_or("<none>")
            );
        }
        IpcResponse::Diagnostics(diagnostics) => {
            println!("ocx: state: {:?}", diagnostics.state);
            println!(
                "ocx: route policy: {}",
                diagnostics.route_policy.as_deref().unwrap_or("<none>")
            );
            println!(
                "ocx: dns policy: {}",
                diagnostics.dns_policy.as_deref().unwrap_or("<none>")
            );
            if let Some(error) = &diagnostics.last_error {
                println!("ocx: last error: {}: {}", error.code, error.message);
            }
        }
        IpcResponse::LogBatch { entries, .. } => {
            for entry in entries {
                println!("ocx: log {:?}: {}", entry.level, entry.message);
            }
        }
        IpcResponse::Error(error) => {
            println!("ocx: error: {}: {}", error.code, error.message);
        }
    }
}

fn print_ipc_event(event: &IpcEvent) {
    match event {
        IpcEvent::Progress(progress) => {
            println!(
                "ocx: progress level={} {}",
                progress.level, progress.message
            );
        }
        IpcEvent::NetworkApplied(applied) => {
            println!(
                "ocx: network applied routes={} dns={}",
                applied.route_commands, applied.dns_commands
            );
        }
        IpcEvent::Disconnecting => println!("ocx: disconnecting"),
        IpcEvent::Disconnected { reason } => println!("ocx: disconnected reason={reason:?}"),
        IpcEvent::Stats(stats) => {
            println!("ocx: stats rx={} tx={}", stats.rx_bytes, stats.tx_bytes);
        }
        IpcEvent::AuthRejected { message, .. } => println!("ocx: auth rejected: {message}"),
        IpcEvent::Connected { interface } => println!("ocx: connected interface={interface}"),
        IpcEvent::Error(error) => println!("ocx: event error: {}: {}", error.code, error.message),
        IpcEvent::AuthPrompt(_) => {}
    }
}

fn read_ipc_auth_submission(
    prompt: &AuthPrompt,
    prompt_index: usize,
    auth_state: &mut IpcAuthSessionState,
) -> Result<AuthSubmission, Box<dyn Error>> {
    println!(
        "ocx: auth prompt: {}",
        auth_prompt_title(prompt, prompt_index)
    );
    if let Some(message) = &prompt.message {
        println!("ocx: auth message: {message}");
    }
    if let Some(error) = &prompt.error {
        println!("ocx: auth error: {error}");
    }
    print_auth_prompt_diagnostics(prompt);

    let mut fields = Vec::new();
    for field in &prompt.fields {
        match &field.kind {
            AuthPromptFieldKind::Text { secret: false } => {
                let value = if let Some(value) = auth_state.saved_text_answer(&field.id) {
                    value
                } else {
                    let value = read_text_from_stdin(&text_prompt(&field.label))?;
                    auth_state.record_text_answer(&field.id, &value);
                    value
                };
                fields.push(AuthSubmittedField::new(&field.id, value, false)?);
            }
            AuthPromptFieldKind::Text { secret: true } | AuthPromptFieldKind::Password => {
                let kind = ipc_password_prompt_kind(prompt, prompt_index, &field.id);
                let value = match kind {
                    SecretPromptKind::VpnPassword => {
                        if let Some(value) =
                            auth_state.stored_vpn_password_for_prompt(prompt.error.is_some())
                        {
                            println!("{}", stored_vpn_password_message(prompt.error.is_some()));
                            value
                        } else {
                            read_secret_from_stdin(SecretPrompt {
                                kind,
                                field_id: field.id.clone(),
                                context: SecretPromptContext::Ipc,
                            })?
                        }
                    }
                    SecretPromptKind::SecondFactorCode => read_secret_from_stdin(SecretPrompt {
                        kind,
                        field_id: field.id.clone(),
                        context: SecretPromptContext::Ipc,
                    })?,
                };
                let submitted = AuthSubmittedField::new(&field.id, value, true)?;
                auth_state.record_secret_submission(kind);
                fields.push(submitted);
            }
            AuthPromptFieldKind::Otp => {
                let kind = SecretPromptKind::SecondFactorCode;
                let value = read_secret_from_stdin(SecretPrompt {
                    kind,
                    field_id: field.id.clone(),
                    context: SecretPromptContext::Ipc,
                })?;
                let submitted = AuthSubmittedField::new(&field.id, value, true)?;
                auth_state.record_secret_submission(kind);
                fields.push(submitted);
            }
            AuthPromptFieldKind::Select { choices } => {
                for (index, choice) in choices.iter().enumerate() {
                    println!("ocx:   [{}] {} ({})", index + 1, choice.label, choice.value);
                }
                let value = read_select_choice_from_stdin(&field.label, choices)?;
                fields.push(AuthSubmittedField::new(&field.id, value, false)?);
            }
        }
    }

    Ok(AuthSubmission::new(&prompt.form_id, fields)?)
}

#[derive(Default)]
struct IpcAuthSessionState {
    username: Option<String>,
    vpn_password: Option<VpnPassword>,
    last_secret_submission: Option<SecretPromptKind>,
}

impl IpcAuthSessionState {
    fn new(vpn_password: Option<VpnPassword>) -> Self {
        Self {
            username: None,
            vpn_password,
            last_secret_submission: None,
        }
    }

    fn saved_text_answer(&self, field_id: &str) -> Option<String> {
        if is_username_field(field_id, "") {
            self.username.clone()
        } else {
            None
        }
    }

    fn record_text_answer(&mut self, field_id: &str, value: &str) {
        if is_username_field(field_id, "") && !value.is_empty() {
            self.username = Some(value.to_owned());
        }
    }

    fn stored_vpn_password_for_prompt(&self, prompt_has_error: bool) -> Option<String> {
        if prompt_has_error && self.last_secret_submission == Some(SecretPromptKind::VpnPassword) {
            return None;
        }

        self.vpn_password
            .as_ref()
            .map(|password| password.expose_secret().to_owned())
    }

    fn record_secret_submission(&mut self, kind: SecretPromptKind) {
        self.last_secret_submission = Some(kind);
    }
}

fn stored_vpn_password_message(prompt_has_error: bool) -> &'static str {
    if prompt_has_error {
        "ocx: reusing stored VPN password from keyring to request a new second-factor code"
    } else {
        "ocx: using stored VPN password from keyring"
    }
}

fn text_prompt(label: &str) -> String {
    if label.trim_end().ends_with(':') {
        format!("{label} ")
    } else {
        format!("{label}: ")
    }
}

fn auth_prompt_title(prompt: &AuthPrompt, prompt_index: usize) -> &str {
    if prompt_index > 0
        && prompt.error.is_none()
        && prompt.fields.iter().any(|field| {
            matches!(
                field.kind,
                AuthPromptFieldKind::Password | AuthPromptFieldKind::Otp
            )
        })
    {
        "Second-factor verification"
    } else {
        &prompt.title
    }
}

fn ipc_password_prompt_kind(
    prompt: &AuthPrompt,
    prompt_index: usize,
    field_id: &str,
) -> SecretPromptKind {
    if prompt.error.is_some() {
        SecretPromptKind::VpnPassword
    } else {
        password_field_prompt_kind(prompt_index, field_id)
    }
}

fn print_auth_prompt_diagnostics(prompt: &AuthPrompt) {
    println!(
        "ocx: auth form: id={} field_count={}",
        prompt.form_id,
        prompt.fields.len()
    );
    for field in &prompt.fields {
        println!(
            "ocx: auth field: id={} kind={} label={} required={}",
            field.id,
            auth_prompt_field_kind_name(&field.kind),
            field.label,
            field.required
        );
    }
}

fn auth_prompt_field_kind_name(kind: &AuthPromptFieldKind) -> &'static str {
    match kind {
        AuthPromptFieldKind::Text { secret: false } => "text",
        AuthPromptFieldKind::Text { secret: true } => "secret_text",
        AuthPromptFieldKind::Password => "password",
        AuthPromptFieldKind::Otp => "otp",
        AuthPromptFieldKind::Select { .. } => "select",
    }
}

fn read_text_from_stdin(prompt: &str) -> Result<String, Box<dyn Error>> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim().to_owned())
}

fn read_select_choice_from_stdin(
    label: &str,
    choices: &[oc_oxide_ipc::AuthChoice],
) -> Result<String, Box<dyn Error>> {
    let value = read_text_from_stdin(&format!("{label} [1]: "))?;
    if value.trim().is_empty() {
        return choices
            .first()
            .map(|choice| choice.value.clone())
            .ok_or_else(|| "select auth prompt had no choices".into());
    }

    if let Ok(index) = value.parse::<usize>() {
        if let Some(choice) = choices.get(index.saturating_sub(1)) {
            return Ok(choice.value.clone());
        }
    }

    Ok(value)
}

fn run_daemon_smoke(profile: &str) -> Result<(), Box<dyn Error>> {
    let mut daemon = DaemonWorkerController::new(ScriptedDaemonSmokeWorkerFactory::new()?);

    println!("daemon-smoke: starting profile {profile}");
    let response = daemon.handle_command(IpcCommand::Connect {
        profile: profile.to_owned(),
    });
    println!(
        "daemon-smoke: connect response: {}",
        response_name(&response)
    );
    if let IpcResponse::Error(error) = response {
        return Err(format!(
            "daemon smoke connect failed: {}: {}",
            error.code, error.message
        )
        .into());
    }

    wait_for_daemon_smoke_state(&mut daemon, DaemonState::Connected)?;
    let status = daemon.handle_command(IpcCommand::Status);
    let IpcResponse::Status(status) = status else {
        return Err("daemon smoke status did not return status".into());
    };
    println!("daemon-smoke: state after connect: {:?}", status.state);
    println!(
        "daemon-smoke: interface after connect: {}",
        status.interface.as_deref().unwrap_or("<none>")
    );
    if status.state != DaemonState::Connected {
        return Err(format!("daemon smoke expected Connected, got {:?}", status.state).into());
    }

    let events = daemon.drain_events();
    println!("daemon-smoke: event count after connect: {}", events.len());
    println!(
        "daemon-smoke: network applied present: {}",
        events
            .iter()
            .any(|event| matches!(event, IpcEvent::NetworkApplied(_)))
    );

    let response = daemon.handle_command(IpcCommand::Disconnect);
    println!(
        "daemon-smoke: disconnect response: {}",
        response_name(&response)
    );
    if !matches!(response, IpcResponse::Accepted) {
        return Err("daemon smoke disconnect was not accepted".into());
    }
    wait_for_daemon_smoke_state(&mut daemon, DaemonState::Disconnected)?;
    let disconnect_events = daemon.drain_events();
    println!(
        "daemon-smoke: disconnected event present: {}",
        disconnect_events
            .iter()
            .any(|event| matches!(event, IpcEvent::Disconnected { .. }))
    );

    Ok(())
}

#[derive(Debug)]
struct ScriptedDaemonSmokeWorkerFactory {
    profile: VpnProfile,
    steps: Vec<TunnelLifecycleStep>,
}

impl ScriptedDaemonSmokeWorkerFactory {
    fn new() -> Result<Self, Box<dyn Error>> {
        let profile = VpnProfile::new(
            "office",
            ServerUrl::parse("https://vpn.example.test/+CSCOE+/logon.html")?,
        )?
        .with_route_mode(RouteMode::Split)
        .with_dns_mode(DnsMode::Split)
        .with_local_bypass_cidrs(vec![local_fake_ip_bypass()?]);
        let default_route = DefaultRouteSnapshot::new(Ipv4Addr::new(192, 0, 2, 1), "eth-test")?;
        let policy_input =
            tunnel_policy_input_from_ip_info(&scripted_daemon_smoke_ip_info(), "tun-smoke0");
        let planned = plan_daemon_network_policy(&profile, &default_route, &policy_input)?;

        Ok(Self {
            profile,
            steps: vec![
                TunnelLifecycleStep::Progress(ProgressUpdate {
                    level: 0,
                    message: "scripted daemon smoke connect".to_owned(),
                }),
                TunnelLifecycleStep::NetworkApplied(planned.applied),
                TunnelLifecycleStep::Connected {
                    interface: "tun-smoke0".to_owned(),
                },
            ],
        })
    }
}

impl TunnelWorkerFactory for ScriptedDaemonSmokeWorkerFactory {
    fn spawn_worker(&mut self) -> TunnelWorkerHandle {
        TunnelWorkerHandle::spawn(OpenConnectTunnelWorker::new(
            ScriptedDaemonSmokeProfileResolver {
                profile: self.profile.clone(),
            },
            ScriptedDaemonSmokeWorkflow {
                steps: self.steps.clone(),
            },
        ))
    }
}

struct ScriptedDaemonSmokeProfileResolver {
    profile: VpnProfile,
}

impl VpnProfileResolver for ScriptedDaemonSmokeProfileResolver {
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

struct ScriptedDaemonSmokeWorkflow {
    steps: Vec<TunnelLifecycleStep>,
}

impl OpenConnectWorkflow for ScriptedDaemonSmokeWorkflow {
    fn run(
        &mut self,
        _profile: VpnProfile,
        commands: mpsc::Receiver<TunnelWorkerCommand>,
        events: mpsc::Sender<TunnelWorkerEvent>,
    ) -> Result<(), TunnelLifecycleError> {
        for step in std::mem::take(&mut self.steps) {
            let _ = events.send(TunnelWorkerEvent::Lifecycle(step));
        }

        while let Ok(command) = commands.recv() {
            match command {
                TunnelWorkerCommand::Cancel | TunnelWorkerCommand::Disconnect => {
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
                    return Ok(());
                }
                TunnelWorkerCommand::SubmitAuth(_) => {
                    let _ = events.send(TunnelWorkerEvent::Error(TunnelLifecycleError::new(
                        "unexpected_auth_submission",
                        "daemon smoke does not expect auth submissions",
                    )));
                }
                TunnelWorkerCommand::Connect(_) => {
                    return Err(TunnelLifecycleError::new(
                        "unexpected_connect",
                        "connect command arrived while daemon smoke workflow was active",
                    ));
                }
            }
        }

        Ok(())
    }
}

fn wait_for_daemon_smoke_state<F>(
    daemon: &mut DaemonWorkerController<F>,
    expected: DaemonState,
) -> Result<(), Box<dyn Error>>
where
    F: TunnelWorkerFactory,
{
    for _ in 0..16 {
        if daemon.core().status().state == expected {
            return Ok(());
        }
        daemon.recv_worker_event_timeout(Duration::from_secs(1))?;
    }

    Err(format!(
        "daemon smoke timed out waiting for {expected:?}, current state {:?}",
        daemon.core().status().state
    )
    .into())
}

fn local_fake_ip_bypass() -> Result<Ipv4Cidr, Box<dyn Error>> {
    Ok("198.18.0.0/15".parse()?)
}

fn scripted_daemon_smoke_ip_info() -> IpInfoSnapshot {
    IpInfoSnapshot {
        address: Some("198.51.100.20".to_owned()),
        netmask: Some("255.255.255.0".to_owned()),
        address6: None,
        netmask6: None,
        dns: vec!["192.0.2.53".to_owned(), "198.51.100.53".to_owned()],
        nbns: Vec::new(),
        domain: Some("corp.example.test".to_owned()),
        proxy_pac: None,
        mtu: 1200,
        split_dns: Vec::new(),
        split_includes: Vec::new(),
        split_excludes: vec![
            SplitRoute {
                route: "203.0.113.10/255.255.255.255".to_owned(),
            },
            SplitRoute {
                route: "0.0.0.0/32".to_owned(),
            },
        ],
        gateway_addr: Some("203.0.113.10".to_owned()),
    }
}

fn response_name(response: &IpcResponse) -> &'static str {
    match response {
        IpcResponse::Accepted => "accepted",
        IpcResponse::Status(_) => "status",
        IpcResponse::Diagnostics(_) => "diagnostics",
        IpcResponse::LogBatch { .. } => "log_batch",
        IpcResponse::Error(_) => "error",
    }
}

#[derive(Debug)]
enum SmokeMode {
    Cookie,
    Tun,
    Mainloop(SmokeMainloopArgs),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SmokeMainloopArgs {
    profile_path: PathBuf,
    seconds: u64,
    route_mode: RouteMode,
    dns_mode: DnsMode,
    local_bypass_cidrs: Vec<Ipv4Cidr>,
    apply_policy: bool,
}

fn run_smoke(path: &Path, mode: SmokeMode) -> Result<(), Box<dyn Error>> {
    let profile = SmokeProfile::load(path)?;
    let server = ServerUrl::parse(&profile.server)?;
    let tunnel_profile = TunnelProfile::new("smoke", server)?;
    let vpn_password_source = profile.vpn_password_source();
    let otp_source = SecretSource::Prompt;
    let mainloop_args = match &mode {
        SmokeMode::Mainloop(args) => Some(args.clone()),
        _ => None,
    };
    let default_route = if mainloop_args.is_some() {
        let route = read_default_route()?;
        println!(
            "smoke: pre-vpn default route gateway={} interface={}",
            route.gateway, route.interface
        );
        Some(route)
    } else {
        None
    };

    let mut sink = SmokeEventSink::new();
    let mut handler = SmokeAuthHandler {
        username: profile.username,
        vpn_password_source,
        otp_source,
        authgroup: profile.authgroup,
        max_auth_prompts: profile.max_auth_prompts,
        prompts: Vec::new(),
    };

    let mut session =
        OpenConnectSession::new_with_callbacks("oc-oxide-smoke", &mut sink, &mut handler)?;
    session
        .session_mut()
        .configure_for_anyconnect(&tunnel_profile)?;

    println!("smoke: configured AnyConnect profile");
    session.session_mut().obtain_cookie()?;
    println!("smoke: cookie obtained: {}", session.session().has_cookie());
    session.session_mut().make_cstp_connection()?;
    println!("smoke: CSTP connected");

    let ip_info = session.session().ip_info_snapshot()?;
    println!("smoke: ip address present: {}", ip_info.address.is_some());
    println!("smoke: dns server count: {}", ip_info.dns.len());
    println!(
        "smoke: split include count: {}",
        ip_info.split_includes.len()
    );
    println!(
        "smoke: split exclude count: {}",
        ip_info.split_excludes.len()
    );
    println!(
        "smoke: gateway address present: {}",
        ip_info.gateway_addr.is_some()
    );

    if matches!(mode, SmokeMode::Tun) {
        let tun = session
            .session_mut()
            .setup_tun_device_without_script(None)?;
        println!("smoke: tun created: {}", tun.ifname.is_some());
        println!(
            "smoke: tun ifname: {}",
            tun.ifname.as_deref().unwrap_or("<unknown>")
        );
        println!("smoke: route/dns policy not applied");
        println!("smoke: mainloop not entered");
    }

    if let (Some(args), Some(default_route)) = (mainloop_args, default_route) {
        let tun = session
            .session_mut()
            .setup_tun_device_without_script(None)?;
        let ifname = tun
            .ifname
            .clone()
            .or_else(|| session.session().ifname())
            .ok_or("OpenConnect did not report a TUN interface name")?;
        println!("smoke: tun created: true");
        println!("smoke: tun ifname: {ifname}");
        println!("smoke: route mode: {}", args.route_mode);
        println!("smoke: dns mode: {}", args.dns_mode);
        println!("smoke: apply policy: {}", args.apply_policy);
        println!(
            "smoke: local bypass count: {}",
            args.local_bypass_cidrs.len()
        );
        for cidr in &args.local_bypass_cidrs {
            println!("smoke: local bypass: {cidr}");
        }

        let route_policy = NetworkPolicy::new(args.route_mode)
            .with_local_bypass_cidrs(args.local_bypass_cidrs.clone());
        let policy_input = tunnel_policy_input_from_ip_info(&ip_info, &ifname);
        let policy_plan = build_policy_plan_from_tunnel_input(
            &policy_input,
            &default_route,
            &route_policy,
            args.dns_mode,
        )?;
        let route_commands = render_linux_ip_route_commands(&policy_plan.routes);
        print_route_plan(&route_commands);

        print_dns_plan(&policy_plan.dns);

        let mut dns_runner = SystemdResolvedCommandRunner::new();
        let netlink_runner = LinuxNetlinkRunner::new()?;
        let mut applied_policy = None;
        if args.apply_policy {
            applied_policy = Some(apply_smoke_policy(
                &netlink_runner,
                &mut dns_runner,
                &ifname,
                &policy_plan,
            )?);
        } else {
            println!("smoke: route/dns policy not applied");
        }

        match session.session_mut().setup_dtls(60) {
            Ok(()) => println!("smoke: DTLS setup attempted: ok"),
            Err(err) => println!("smoke: DTLS setup failed; using CSTP only: {err}"),
        }

        let mainloop_result = (|| {
            let cancel = session
                .session_mut()
                .take_cancel_handle()
                .ok_or("OpenConnect command pipe handle was already taken")?;
            println!("smoke: entering mainloop for {} seconds", args.seconds);
            run_mainloop_with_timed_cancel(
                session.session_mut(),
                cancel,
                Duration::from_secs(args.seconds),
            )
        })();

        let revert_result = if let Some(applied_policy) = applied_policy.as_ref() {
            revert_smoke_policy(&netlink_runner, &mut dns_runner, applied_policy)
        } else {
            Ok(())
        };

        let outcome = mainloop_result?;
        revert_result?;
        println!("smoke: mainloop outcome: {outcome:?}");
        println!(
            "smoke: mainloop graceful stop: {}",
            outcome.is_graceful_stop()
        );
    }

    let events = sink.into_events();
    println!("smoke: auth prompts handled: {}", handler.prompts.len());
    println!("smoke: tunnel events captured: {}", events.len());

    Ok(())
}

fn read_default_route() -> Result<DefaultRouteSnapshot, Box<dyn Error>> {
    Ok(LinuxNetlinkRunner::new()?.default_route()?)
}

#[derive(Debug)]
struct AppliedSmokePolicy {
    state: AppliedPolicyState,
}

fn apply_smoke_policy(
    netlink: &LinuxNetlinkRunner,
    dns_runner: &mut SystemdResolvedCommandRunner,
    ifname: &str,
    policy_plan: &PolicyPlan,
) -> Result<AppliedSmokePolicy, Box<dyn Error>> {
    println!(
        "smoke: configuring tun netlink step count: {}",
        policy_plan.tun.step_count()
    );
    if let (Some(address), Some(prefix_len)) = (policy_plan.tun.address, policy_plan.tun.prefix_len)
    {
        println!("smoke:   netlink addr replace {address}/{prefix_len} dev {ifname}");
    }
    if let Some(mtu) = policy_plan.tun.mtu {
        println!("smoke:   netlink link set dev {ifname} mtu {mtu}");
    }
    println!("smoke:   netlink link set dev {ifname} up");
    println!(
        "smoke: applying route policy route count: {}",
        policy_plan.routes.routes.len()
    );
    print_netlink_route_replace_plan(&policy_plan.routes);
    println!(
        "smoke: applying dns policy command count: {}",
        policy_plan.dns.apply.len()
    );

    let state = apply_policy_with(netlink, dns_runner, policy_plan)?;
    println!("smoke: tun configured");
    println!(
        "smoke: route policy applied route count: {}",
        policy_plan.routes.routes.len()
    );
    println!(
        "smoke: dns policy applied command count: {}",
        policy_plan.dns.apply.len()
    );

    Ok(AppliedSmokePolicy { state })
}

fn revert_smoke_policy(
    netlink: &LinuxNetlinkRunner,
    dns_runner: &mut SystemdResolvedCommandRunner,
    policy: &AppliedSmokePolicy,
) -> Result<(), Box<dyn Error>> {
    println!(
        "smoke: reverting dns policy command count: {}",
        policy.state.dns.revert.len()
    );

    println!(
        "smoke: reverting route policy route count: {}",
        policy.state.routes.routes.len()
    );
    print_netlink_route_delete_plan(&policy.state.routes);

    println!("smoke: reverting tun config");
    print_tun_revert_plan(&policy.state);

    match revert_policy_with(netlink, dns_runner, &policy.state) {
        Ok(()) => {
            println!("smoke: dns policy revert error count: 0");
            println!("smoke: route policy revert error count: 0");
            println!("smoke: tun config revert error count: 0");
        }
        Err(errors) => {
            print_policy_revert_errors(&errors);
            return Err(Box::new(errors));
        }
    }

    println!("smoke: route/dns policy reverted");
    Ok(())
}

fn print_tun_revert_plan(policy: &AppliedPolicyState) {
    if let (Some(address), Some(prefix_len)) = (policy.tun.address, policy.tun.prefix_len) {
        println!(
            "smoke:   netlink addr del {address}/{prefix_len} dev {}",
            policy.tun.ifname
        );
    }
    println!("smoke:   netlink link set dev {} down", policy.tun.ifname);
}

fn print_netlink_route_replace_plan(plan: &NetworkRoutePlan) {
    for route in &plan.routes {
        println!(
            "smoke:   netlink route replace {} dev {} [{:?}]",
            route.destination, route.dev, route.reason
        );
    }
}

fn print_netlink_route_delete_plan(state: &AppliedNetworkRouteState) {
    for route in state.routes.iter().rev() {
        match &route.revert {
            RouteRevertAction::Restore(previous) => println!(
                "smoke:   netlink route restore {} dev {} [{:?}]",
                previous.destination, previous.dev, route.applied.reason
            ),
            RouteRevertAction::Delete(created) => println!(
                "smoke:   netlink route del {} dev {} [{:?}]",
                created.destination, created.dev, created.reason
            ),
        }
    }
}

fn print_policy_revert_errors(errors: &PolicyRevertErrors) {
    println!("smoke: dns policy revert error count: {}", errors.dns.len());
    println!(
        "smoke: route policy revert error count: {}",
        errors.routes.len()
    );
    println!("smoke: tun config revert error count: {}", errors.tun.len());
}

fn print_route_plan(plan: &RouteCommandPlan) {
    println!("smoke: route plan apply commands:");
    if plan.apply.is_empty() {
        println!("smoke:   <none>");
    }
    for command in &plan.apply {
        println!(
            "smoke:   {} [{:?}]",
            format_command(command.program, &command.args),
            command.reason
        );
    }

    println!("smoke: route plan revert commands:");
    if plan.revert.is_empty() {
        println!("smoke:   <none>");
    }
    for command in &plan.revert {
        println!(
            "smoke:   {} [{:?}]",
            format_command(command.program, &command.args),
            command.reason
        );
    }
}

fn print_dns_plan(plan: &DnsCommandPlan) {
    println!("smoke: dns plan apply commands:");
    if plan.apply.is_empty() {
        println!("smoke:   <none>");
    }
    for command in &plan.apply {
        println!(
            "smoke:   {} [{:?}]",
            format_dns_command(command.program, &command.args),
            command.reason
        );
    }

    println!("smoke: dns plan revert commands:");
    if plan.revert.is_empty() {
        println!("smoke:   <none>");
    }
    for command in &plan.revert {
        println!(
            "smoke:   {} [{:?}]",
            format_dns_command(command.program, &command.args),
            command.reason
        );
    }
}

fn format_command(program: &str, args: &[String]) -> String {
    std::iter::once(program.to_owned())
        .chain(args.iter().map(|arg| shell_word(arg)))
        .collect::<Vec<_>>()
        .join(" ")
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

fn run_mainloop_with_timed_cancel(
    session: &mut OpenConnectSession,
    cancel: CancelHandle,
    duration: Duration,
) -> Result<MainloopOutcome, Box<dyn Error>> {
    let (done_tx, done_rx) = mpsc::channel();
    let timer = thread::spawn(move || {
        if done_rx.recv_timeout(duration).is_err() {
            println!("smoke: cancelling mainloop");
            if let Err(err) = cancel.cancel() {
                eprintln!("smoke: failed to cancel mainloop: {err}");
            }
        }
    });

    let outcome = session.run_mainloop(300, 10);
    let _ = done_tx.send(());
    timer
        .join()
        .map_err(|_| "mainloop cancel timer thread panicked")?;

    Ok(outcome)
}

#[derive(Debug, Default)]
struct SmokeEventSink {
    events: Vec<TunnelEvent>,
}

impl SmokeEventSink {
    fn new() -> Self {
        Self::default()
    }

    fn into_events(self) -> Vec<TunnelEvent> {
        self.events
    }
}

impl TunnelEventSink for SmokeEventSink {
    fn emit(&mut self, event: TunnelEvent) {
        match &event {
            TunnelEvent::Progress(progress) => {
                println!(
                    "smoke: progress level={} message_bytes={}",
                    progress.level.raw(),
                    progress.message.len()
                );
            }
            TunnelEvent::AuthRequired(request) => {
                let fields = request
                    .fields
                    .iter()
                    .map(|field| format!("{}:{}", field.id, auth_kind_name(&field.kind)))
                    .collect::<Vec<_>>()
                    .join(",");
                println!(
                    "smoke: auth prompt fields={} form_id_present={}",
                    fields,
                    request.form_id.is_some()
                );
            }
            TunnelEvent::StateChanged(state) => {
                println!("smoke: state changed: {state:?}");
            }
            TunnelEvent::Error(error) => {
                println!(
                    "smoke: tunnel error operation_present={} message_bytes={}",
                    error.operation.is_some(),
                    error.message.len()
                );
            }
        }

        self.events.push(event);
    }
}

fn auth_kind_name(kind: &AuthFieldKind) -> &'static str {
    match kind {
        AuthFieldKind::Text { secret: false } => "text",
        AuthFieldKind::Text { secret: true } => "secret_text",
        AuthFieldKind::Password => "password",
        AuthFieldKind::Otp => "otp",
        AuthFieldKind::Select { .. } => "select",
    }
}

#[derive(Debug)]
struct SmokeProfile {
    server: String,
    username: String,
    authgroup: Option<String>,
    vpn_password: Option<String>,
    max_auth_prompts: usize,
}

impl SmokeProfile {
    fn load(path: &Path) -> Result<Self, Box<dyn Error>> {
        let values = parse_key_value_file(path)?;
        let server = required_value(&values, "server")?;
        let username = required_value(&values, "username")?;
        let authgroup = values.get("authgroup").cloned();
        if values.contains_key("password_command") {
            return Err("password_command is intentionally unsupported".into());
        }
        if values.contains_key("password") {
            return Err("use vpn_password for the local VPN account password".into());
        }
        let vpn_password = values.get("vpn_password").cloned();
        let password_prompt = values
            .get("password_prompt")
            .map(|value| parse_bool(value))
            .transpose()?
            .unwrap_or(false);
        let max_auth_prompts = values
            .get("max_auth_prompts")
            .map(|value| value.parse())
            .transpose()?
            .unwrap_or(if vpn_password.is_some() { 2 } else { 1 });

        if vpn_password.is_none() && !password_prompt {
            return Err(
                "profile must include vpn_password or password_prompt=true; password_command is intentionally unsupported".into(),
            );
        }
        if max_auth_prompts == 0 {
            return Err("max_auth_prompts must be greater than zero".into());
        }
        if max_auth_prompts > 2 {
            return Err("smoke-cookie refuses to submit more than two auth prompts".into());
        }

        Ok(Self {
            server,
            username,
            authgroup,
            vpn_password,
            max_auth_prompts,
        })
    }

    fn vpn_password_source(&self) -> SecretSource {
        match &self.vpn_password {
            Some(value) => SecretSource::Fixed(value.clone()),
            None => SecretSource::Prompt,
        }
    }
}

enum SecretSource {
    Fixed(String),
    Prompt,
}

impl SecretSource {
    fn resolve(&self, prompt: SecretPrompt) -> Result<String, String> {
        match self {
            Self::Fixed(value) => Ok(value.clone()),
            Self::Prompt => read_secret_from_stdin(prompt),
        }
    }
}

impl fmt::Debug for SecretSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fixed(_) => f.write_str("Fixed(<redacted>)"),
            Self::Prompt => f.write_str("Prompt"),
        }
    }
}

struct SmokeAuthHandler {
    username: String,
    vpn_password_source: SecretSource,
    otp_source: SecretSource,
    authgroup: Option<String>,
    max_auth_prompts: usize,
    prompts: Vec<String>,
}

impl fmt::Debug for SmokeAuthHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmokeAuthHandler")
            .field("username", &self.username)
            .field("vpn_password_source", &self.vpn_password_source)
            .field("otp_source", &self.otp_source)
            .field("authgroup", &self.authgroup)
            .field("max_auth_prompts", &self.max_auth_prompts)
            .field("prompts", &self.prompts)
            .finish()
    }
}

impl AuthFormHandler for SmokeAuthHandler {
    fn handle_auth_request(&mut self, request: AuthRequest) -> AuthFormDecision {
        let prompt_index = self.prompts.len();
        if prompt_index >= self.max_auth_prompts {
            println!("smoke: auth prompt limit reached; cancelling");
            return AuthFormDecision::Cancel;
        }

        self.prompts.push(request.title.clone());

        let mut answers = Vec::new();
        for field in &request.fields {
            match &field.kind {
                AuthFieldKind::Text { secret } if is_username_field(&field.id, &field.label) => {
                    let answer = if *secret {
                        AuthAnswer::secret(&field.id, self.username.clone())
                    } else {
                        AuthAnswer::text(&field.id, self.username.clone())
                    };
                    answers.push(match answer {
                        Ok(answer) => answer,
                        Err(_) => return AuthFormDecision::Error,
                    });
                }
                AuthFieldKind::Password => {
                    let prompt = SecretPrompt {
                        kind: password_field_prompt_kind(prompt_index, &field.id),
                        field_id: field.id.clone(),
                        context: SecretPromptContext::Smoke,
                    };
                    let source = match prompt.kind {
                        SecretPromptKind::VpnPassword => &self.vpn_password_source,
                        SecretPromptKind::SecondFactorCode => &self.otp_source,
                    };
                    let secret = match source.resolve(prompt) {
                        Ok(secret) => secret,
                        Err(err) => {
                            println!("smoke: failed to read auth secret: {err}");
                            return AuthFormDecision::Error;
                        }
                    };
                    answers.push(match AuthAnswer::secret(&field.id, secret) {
                        Ok(answer) => answer,
                        Err(_) => return AuthFormDecision::Error,
                    });
                }
                AuthFieldKind::Otp => {
                    let secret = match self.otp_source.resolve(SecretPrompt {
                        kind: SecretPromptKind::SecondFactorCode,
                        field_id: field.id.clone(),
                        context: SecretPromptContext::Smoke,
                    }) {
                        Ok(secret) => secret,
                        Err(err) => {
                            println!("smoke: failed to read auth secret: {err}");
                            return AuthFormDecision::Error;
                        }
                    };
                    answers.push(match AuthAnswer::secret(&field.id, secret) {
                        Ok(answer) => answer,
                        Err(_) => return AuthFormDecision::Error,
                    });
                }
                AuthFieldKind::Select { choices } => {
                    let Some(choice) = select_choice(choices, self.authgroup.as_deref()) else {
                        println!("smoke: configured authgroup did not match offered choices");
                        return AuthFormDecision::Error;
                    };
                    answers.push(match AuthAnswer::text(&field.id, choice) {
                        Ok(answer) => answer,
                        Err(_) => return AuthFormDecision::Error,
                    });
                }
                AuthFieldKind::Text { .. } if !field.required => {}
                AuthFieldKind::Text { .. } => return AuthFormDecision::Error,
            }
        }

        let response = match AuthResponse::new(answers) {
            Ok(response) => response,
            Err(_) => return AuthFormDecision::Error,
        };
        let response = match request.form_id {
            Some(form_id) => match response.with_form_id(form_id) {
                Ok(response) => response,
                Err(_) => return AuthFormDecision::Error,
            },
            None => response,
        };

        AuthFormDecision::Submit(response)
    }
}

fn is_username_field(id: &str, label: &str) -> bool {
    let id = id.to_ascii_lowercase();
    let label = label.to_ascii_lowercase();
    id.contains("user") || id.starts_with("uname") || label.contains("user")
}

fn select_choice(choices: &[oc_oxide_auth::AuthChoice], desired: Option<&str>) -> Option<String> {
    if let Some(desired) = desired {
        for choice in choices {
            if choice.value == desired || choice.label == desired {
                return Some(choice.value.clone());
            }
        }
        return None;
    }

    choices.first().map(|choice| choice.value.clone())
}

fn password_field_prompt_kind(prompt_index: usize, field_id: &str) -> SecretPromptKind {
    if prompt_index == 0 && field_id.eq_ignore_ascii_case("password") {
        SecretPromptKind::VpnPassword
    } else {
        SecretPromptKind::SecondFactorCode
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SecretPrompt {
    kind: SecretPromptKind,
    field_id: String,
    context: SecretPromptContext,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecretPromptKind {
    VpnPassword,
    SecondFactorCode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SecretPromptContext {
    Smoke,
    Ipc,
    Vault,
}

fn read_secret_from_stdin(prompt: SecretPrompt) -> Result<String, String> {
    eprint!("{}", secret_prompt_text(&prompt));
    io::stderr()
        .flush()
        .map_err(|err| format!("failed to flush prompt: {err}"))?;

    let _ = Command::new("stty").arg("-echo").status();
    let mut value = String::new();
    let read_result = io::stdin().read_line(&mut value);
    let _ = Command::new("stty").arg("echo").status();
    eprintln!();

    read_result.map_err(|err| format!("failed to read auth secret: {err}"))?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err("auth secret must not be empty".to_owned());
    }

    Ok(value)
}

fn secret_prompt_text(prompt: &SecretPrompt) -> String {
    let prefix = match prompt.context {
        SecretPromptContext::Smoke => "smoke",
        SecretPromptContext::Ipc => "ocx",
        SecretPromptContext::Vault => "ocx vault",
    };
    match prompt.kind {
        SecretPromptKind::VpnPassword => format!(
            "{prefix}: enter VPN password for {}; second-factor challenge should arrive after submit: ",
            prompt.field_id,
        ),
        SecretPromptKind::SecondFactorCode => {
            format!("{prefix}: enter second-factor verification code: ")
        }
    }
}

fn parse_bool(value: &str) -> Result<bool, CliError> {
    match value {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(CliError::InvalidBool {
            value: value.to_owned(),
        }),
    }
}

fn parse_key_value_file(path: &Path) -> Result<BTreeMap<String, String>, Box<dyn Error>> {
    let text = fs::read_to_string(path)?;
    let mut values = BTreeMap::new();

    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("invalid profile line {}", index + 1).into());
        };
        let key = key.trim();
        let value = unquote(value.trim());
        if key.is_empty() || value.is_empty() {
            return Err(format!("invalid empty profile entry on line {}", index + 1).into());
        }

        values.insert(key.to_owned(), value);
    }

    Ok(values)
}

fn required_value(
    values: &BTreeMap<String, String>,
    key: &'static str,
) -> Result<String, CliError> {
    values
        .get(key)
        .cloned()
        .ok_or(CliError::MissingProfileKey { key })
}

fn unquote(value: &str) -> String {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
        .unwrap_or(value)
        .to_owned()
}

#[derive(Debug)]
enum CliError {
    MissingProfileKey { key: &'static str },
    InvalidBool { value: String },
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProfileKey { key } => write!(f, "profile is missing {key}"),
            Self::InvalidBool { value } => write!(f, "invalid boolean value {value:?}"),
        }
    }
}

impl Error for CliError {}

#[cfg(test)]
mod tests {
    use super::{
        auth_prompt_title, connect_event_error_is_fatal, ipc_password_prompt_kind,
        is_username_field, local_profile_path_in_dir, parse_github_device_login_args,
        parse_github_sync_init_args, parse_github_sync_reset_args, parse_github_sync_smoke_args,
        parse_github_sync_upload_args, parse_key_value_file, parse_named_profile_arg,
        parse_positional_profile_arg, parse_smoke_mainloop_args, password_field_prompt_kind,
        read_ipc_auth_submission, run_daemon_smoke, secret_prompt_text, select_choice,
        stored_vpn_password_message, text_prompt, IpcAuthSessionState,
        ScriptedDaemonSmokeWorkerFactory, SecretPrompt, SecretPromptContext, SecretPromptKind,
        SecretSource, SmokeAuthHandler, SmokeProfile,
    };
    use oc_oxide_auth::{
        AuthAnswerValue, AuthChoice, AuthField, AuthFormDecision, AuthFormHandler, AuthRequest,
    };
    use oc_oxide_config::VpnPassword;
    use oc_oxide_daemon::{tunnel_policy_input_from_ip_info, TunnelLifecycleStep};
    use oc_oxide_dns::DnsMode;
    use oc_oxide_ipc::{AuthPrompt, AuthPromptField, AuthPromptFieldKind, NetworkApplied};
    use oc_oxide_net::{
        render_linux_ip_route_commands, DefaultRouteSnapshot, Ipv4Cidr, NetworkPolicy, RouteMode,
    };
    use oc_oxide_policy::{
        build_policy_plan_from_tunnel_input, build_tun_config_from_tunnel_input,
    };
    use oc_oxide_tunnel::{IpInfoSnapshot, SplitRoute};
    use std::fs;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_local_profile_without_shell_sourcing_it() {
        let path =
            std::env::temp_dir().join(format!("oc-oxide-profile-{}.env", std::process::id()));
        fs::write(
            &path,
            "server=https://vpn.example.test:555/\nusername=alice\nauthgroup=Giga\npassword_prompt=true\n",
        )
        .unwrap();

        let values = parse_key_value_file(&path).unwrap();

        assert_eq!(
            values.get("server").unwrap(),
            "https://vpn.example.test:555/"
        );
        assert_eq!(values.get("username").unwrap(), "alice");
        assert_eq!(values.get("authgroup").unwrap(), "Giga");
        assert_eq!(values.get("password_prompt").unwrap(), "true");

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn loads_prompt_based_profile_without_secret_material() {
        let path = std::env::temp_dir().join(format!(
            "oc-oxide-profile-prompt-{}.env",
            std::process::id()
        ));
        fs::write(
            &path,
            "server=https://vpn.example.test:555/\nusername=alice\nauthgroup=Giga\npassword_prompt=true\n",
        )
        .unwrap();

        let profile = SmokeProfile::load(&path).unwrap();

        assert_eq!(profile.server, "https://vpn.example.test:555/");
        assert_eq!(profile.username, "alice");
        assert!(profile.vpn_password.is_none());
        assert_eq!(profile.max_auth_prompts, 1);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn loads_local_vpn_password_without_requiring_prompt() {
        let path = std::env::temp_dir().join(format!(
            "oc-oxide-profile-password-{}.env",
            std::process::id()
        ));
        fs::write(
            &path,
            "server=https://vpn.example.test:555/\nusername=alice\nvpn_password=do-not-log\n",
        )
        .unwrap();

        let profile = SmokeProfile::load(&path).unwrap();
        let source = profile.vpn_password_source();

        assert_eq!(profile.max_auth_prompts, 2);
        assert!(matches!(source, SecretSource::Fixed(_)));
        assert!(!format!("{source:?}").contains("do-not-log"));

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_command_based_auth_secret_sources_even_with_prompt_enabled() {
        let path = std::env::temp_dir().join(format!(
            "oc-oxide-profile-command-{}.env",
            std::process::id()
        ));
        fs::write(
            &path,
            "server=https://vpn.example.test:555/\nusername=alice\npassword_prompt=true\npassword_command=printf old-code\n",
        )
        .unwrap();

        let err = SmokeProfile::load(&path).unwrap_err().to_string();

        assert!(err.contains("password_command"));

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_ambiguous_password_profile_key() {
        let path = std::env::temp_dir().join(format!(
            "oc-oxide-profile-ambiguous-password-{}.env",
            std::process::id()
        ));
        fs::write(
            &path,
            "server=https://vpn.example.test:555/\nusername=alice\npassword=do-not-log\n",
        )
        .unwrap();

        let err = SmokeProfile::load(&path).unwrap_err().to_string();

        assert!(err.contains("vpn_password"));

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_more_than_two_auth_prompt_submissions_for_smoke() {
        let path =
            std::env::temp_dir().join(format!("oc-oxide-profile-retry-{}.env", std::process::id()));
        fs::write(
            &path,
            "server=https://vpn.example.test:555/\nusername=alice\nvpn_password=do-not-log\nmax_auth_prompts=3\n",
        )
        .unwrap();

        let err = SmokeProfile::load(&path).unwrap_err().to_string();

        assert!(err.contains("more than two auth prompts"));

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn parses_smoke_mainloop_args_with_default_and_custom_duration() {
        let args =
            parse_smoke_mainloop_args(vec!["--profile".to_owned(), "/tmp/profile.env".to_owned()])
                .unwrap();

        assert_eq!(
            args.profile_path,
            std::path::PathBuf::from("/tmp/profile.env")
        );
        assert_eq!(args.seconds, 5);
        assert_eq!(args.route_mode, RouteMode::Split);
        assert_eq!(args.dns_mode, DnsMode::Split);
        assert!(args.local_bypass_cidrs.is_empty());
        assert!(!args.apply_policy);

        let args = parse_smoke_mainloop_args(vec![
            "--seconds".to_owned(),
            "7".to_owned(),
            "--route-mode".to_owned(),
            "full".to_owned(),
            "--dns-mode".to_owned(),
            "off".to_owned(),
            "--local-bypass".to_owned(),
            "198.18.0.0/15".to_owned(),
            "--apply-policy".to_owned(),
            "--profile".to_owned(),
            "/tmp/profile.env".to_owned(),
        ])
        .unwrap();

        assert_eq!(args.seconds, 7);
        assert_eq!(args.route_mode, RouteMode::Full);
        assert_eq!(args.dns_mode, DnsMode::Off);
        assert_eq!(args.local_bypass_cidrs, vec![local_bypass_cidr()]);
        assert!(args.apply_policy);
        assert!(parse_smoke_mainloop_args(vec![
            "--profile".to_owned(),
            "/tmp/profile.env".to_owned(),
            "--seconds".to_owned(),
            "0".to_owned(),
        ])
        .is_err());
        assert!(parse_smoke_mainloop_args(vec![
            "--profile".to_owned(),
            "/tmp/profile.env".to_owned(),
            "--route-mode".to_owned(),
            "invalid".to_owned(),
        ])
        .is_err());
    }

    #[test]
    fn parses_github_device_login_storage_mode() {
        let args = parse_github_device_login_args(Vec::new()).unwrap();
        assert!(!args.no_store);

        let args = parse_github_device_login_args(vec!["--no-store".to_owned()]).unwrap();
        assert!(args.no_store);
        assert!(parse_github_device_login_args(vec!["--store".to_owned()]).is_err());
    }

    #[test]
    fn parses_github_sync_smoke_storage_mode() {
        let args = parse_github_sync_smoke_args(Vec::new()).unwrap();
        assert!(!args.no_store);

        let args = parse_github_sync_smoke_args(vec!["--no-store".to_owned()]).unwrap();
        assert!(args.no_store);
        assert!(parse_github_sync_smoke_args(vec!["--write".to_owned()]).is_err());
    }

    #[test]
    fn parses_github_sync_init_storage_mode() {
        let args = parse_github_sync_init_args(Vec::new()).unwrap();
        assert!(!args.no_store);

        let args = parse_github_sync_init_args(vec!["--no-store".to_owned()]).unwrap();
        assert!(args.no_store);
        assert!(parse_github_sync_init_args(vec!["--passphrase-stdin".to_owned()]).is_err());
        assert!(parse_github_sync_init_args(vec!["--passphrase".to_owned()]).is_err());
    }

    #[test]
    fn parses_github_sync_reset_storage_mode() {
        let args = parse_github_sync_reset_args(Vec::new()).unwrap();
        assert!(!args.no_store);

        let args = parse_github_sync_reset_args(vec!["--no-store".to_owned()]).unwrap();
        assert!(args.no_store);
        assert!(parse_github_sync_reset_args(vec!["--passphrase-stdin".to_owned()]).is_err());
        assert!(parse_github_sync_reset_args(vec!["--passphrase".to_owned()]).is_err());
    }

    #[test]
    fn parses_github_sync_upload_storage_mode() {
        let args = parse_github_sync_upload_args(Vec::new()).unwrap();
        assert!(!args.no_store);

        let args = parse_github_sync_upload_args(vec!["--no-store".to_owned()]).unwrap();
        assert!(args.no_store);
        assert!(parse_github_sync_upload_args(vec!["--passphrase-stdin".to_owned()]).is_err());
        assert!(parse_github_sync_upload_args(vec!["--passphrase".to_owned()]).is_err());
    }

    #[test]
    fn daemon_smoke_uses_named_profile_without_network() {
        assert_eq!(
            parse_named_profile_arg(
                "daemon-smoke",
                vec!["--profile".to_owned(), "office".to_owned()],
            )
            .unwrap(),
            "office"
        );
        assert!(parse_named_profile_arg("daemon-smoke", vec!["--profile".to_owned()]).is_err());

        run_daemon_smoke("office").unwrap();
    }

    #[test]
    fn connect_uses_single_positional_profile_name() {
        assert_eq!(
            parse_positional_profile_arg("connect", vec!["office".to_owned()]).unwrap(),
            "office"
        );
        assert!(parse_positional_profile_arg("connect", Vec::new()).is_err());
        assert!(parse_positional_profile_arg(
            "connect",
            vec!["office".to_owned(), "extra".to_owned()],
        )
        .is_err());
    }

    #[test]
    fn vault_store_uses_toml_profile_path_without_keyring_side_effects() {
        let base = std::path::PathBuf::from("/tmp/oc-oxide-example-profiles");

        assert_eq!(
            local_profile_path_in_dir("office_dev", &base).unwrap(),
            base.join("office_dev.toml")
        );
        assert_eq!(
            parse_positional_profile_arg("vault-store", vec!["office-dev".to_owned()]).unwrap(),
            "office-dev"
        );

        assert!(local_profile_path_in_dir("../office", &base).is_err());
        assert!(local_profile_path_in_dir("office.toml", &base).is_err());
        assert!(local_profile_path_in_dir("", &base).is_err());
    }

    #[test]
    fn connect_ignores_stale_error_events_before_acceptance() {
        assert!(!connect_event_error_is_fatal(false));
        assert!(connect_event_error_is_fatal(true));
    }

    #[test]
    fn daemon_smoke_runner_plans_network_event_without_network() {
        let factory = ScriptedDaemonSmokeWorkerFactory::new().unwrap();

        let applied = factory
            .steps
            .iter()
            .find_map(|step| match step {
                TunnelLifecycleStep::NetworkApplied(applied) => Some(applied),
                _ => None,
            })
            .expect("network applied event");

        assert_eq!(
            *applied,
            NetworkApplied {
                route_commands: 5,
                dns_commands: 2,
            }
        );
    }

    #[test]
    fn builds_route_and_dns_plans_from_smoke_ip_info_without_applying_them() {
        let ip_info = sample_ip_info();
        let default_route =
            DefaultRouteSnapshot::new(Ipv4Addr::new(192, 0, 2, 1), "eth-test").unwrap();

        let route_policy =
            NetworkPolicy::new(RouteMode::Split).with_local_bypass_cidrs(vec![local_bypass_cidr()]);
        let input = tunnel_policy_input_from_ip_info(&ip_info, "tun0");
        let plan = build_policy_plan_from_tunnel_input(
            &input,
            &default_route,
            &route_policy,
            DnsMode::Split,
        )
        .unwrap();
        assert_eq!(plan.routes.routes.len(), 3);
        let route_commands = render_linux_ip_route_commands(&plan.routes);
        assert_eq!(route_commands.apply.len(), 3);
        assert_eq!(route_commands.apply[0].program, "ip");
        assert_eq!(
            route_commands.apply[1].args,
            vec![
                "route",
                "replace",
                "198.18.0.0/15",
                "via",
                "192.0.2.1",
                "dev",
                "eth-test"
            ]
        );
        assert!(!route_commands
            .apply
            .iter()
            .any(|command| command.args.contains(&"0.0.0.0/32".to_owned())));

        let dns_plan = &plan.dns;
        assert_eq!(dns_plan.apply.len(), 2);
        assert_eq!(
            dns_plan.apply[0].args,
            vec!["dns", "tun0", "192.0.2.53", "198.51.100.53"]
        );
        assert_eq!(
            dns_plan.apply[1].args,
            vec!["domain", "tun0", "corp.example.test", "~corp.example.test"]
        );

        let route_off = NetworkPolicy::new(RouteMode::Off);
        let route_off_plan =
            build_policy_plan_from_tunnel_input(&input, &default_route, &route_off, DnsMode::Off)
                .unwrap();
        let route_off_commands = render_linux_ip_route_commands(&route_off_plan.routes);
        assert!(route_off_plan.routes.routes.is_empty());
        assert!(route_off_commands.apply.is_empty());
        assert!(route_off_commands.revert.is_empty());

        let full_dns = build_policy_plan_from_tunnel_input(
            &input,
            &default_route,
            &route_policy,
            DnsMode::Full,
        )
        .unwrap()
        .dns;
        assert_eq!(
            full_dns.apply[1].args,
            vec!["domain", "tun0", "corp.example.test", "~."]
        );

        let off_dns = build_policy_plan_from_tunnel_input(
            &input,
            &default_route,
            &route_policy,
            DnsMode::Off,
        )
        .unwrap()
        .dns;
        assert!(off_dns.apply.is_empty());
        assert!(off_dns.revert.is_empty());
    }

    #[test]
    fn rejects_non_contiguous_smoke_netmask() {
        let mut input = tunnel_policy_input_from_ip_info(&sample_ip_info(), "tun0");
        input.netmask = Some("255.0.255.0".to_owned());

        assert!(build_tun_config_from_tunnel_input(&input).is_err());
    }

    #[test]
    fn strict_authgroup_selection_does_not_fall_back_when_configured() {
        let choices = vec![AuthChoice::new("Other", "Other").unwrap()];

        assert_eq!(select_choice(&choices, Some("Giga")), None);
        assert_eq!(select_choice(&choices, None), Some("Other".to_owned()));
    }

    #[test]
    fn labels_first_password_prompt_as_vpn_password_not_second_factor_code() {
        let password_prompt = secret_prompt_text(&SecretPrompt {
            kind: SecretPromptKind::VpnPassword,
            field_id: "password".to_owned(),
            context: SecretPromptContext::Smoke,
        });
        let otp_prompt = secret_prompt_text(&SecretPrompt {
            kind: SecretPromptKind::SecondFactorCode,
            field_id: "otp".to_owned(),
            context: SecretPromptContext::Smoke,
        });
        let ipc_prompt = secret_prompt_text(&SecretPrompt {
            kind: SecretPromptKind::VpnPassword,
            field_id: "password".to_owned(),
            context: SecretPromptContext::Ipc,
        });

        assert!(password_prompt.contains("VPN password"));
        assert!(!password_prompt.contains("verification code"));
        assert!(password_prompt.starts_with("smoke:"));
        assert!(otp_prompt.contains("second-factor verification code"));
        assert!(!otp_prompt.contains("otp"));
        assert!(ipc_prompt.starts_with("ocx:"));
    }

    #[test]
    fn classifies_second_answer_password_field_as_second_factor_code() {
        assert_eq!(
            password_field_prompt_kind(0, "password"),
            SecretPromptKind::VpnPassword
        );
        assert_eq!(
            password_field_prompt_kind(1, "answer"),
            SecretPromptKind::SecondFactorCode
        );
        assert_eq!(
            password_field_prompt_kind(1, "password"),
            SecretPromptKind::SecondFactorCode
        );
    }

    #[test]
    fn ipc_auth_state_reuses_username_fields_without_persisting_secrets() {
        let mut state = IpcAuthSessionState::default();

        assert!(is_username_field("username", ""));
        assert!(is_username_field("uname", ""));
        assert!(!is_username_field("email", ""));
        assert_eq!(state.saved_text_answer("username"), None);

        state.record_text_answer("username", "alice");

        assert_eq!(
            state.saved_text_answer("username").as_deref(),
            Some("alice")
        );
        assert_eq!(state.saved_text_answer("uname").as_deref(), Some("alice"));
        assert_eq!(state.saved_text_answer("email"), None);
    }

    #[test]
    fn ipc_auth_submission_uses_stored_vpn_password_without_leaking_it() {
        let mut state = IpcAuthSessionState::new(Some(VpnPassword::new("stored-secret").unwrap()));
        let prompt = AuthPrompt {
            form_id: "form-password".to_owned(),
            title: "Login".to_owned(),
            message: None,
            error: None,
            fields: vec![AuthPromptField {
                id: "password".to_owned(),
                label: "Password:".to_owned(),
                kind: AuthPromptFieldKind::Password,
                required: true,
            }],
        };

        let submission = read_ipc_auth_submission(&prompt, 0, &mut state).unwrap();

        assert_eq!(submission.form_id, "form-password");
        assert_eq!(submission.fields[0].id, "password");
        assert_eq!(submission.fields[0].value, "stored-secret");
        assert!(submission.fields[0].secret);
        assert_eq!(
            state.stored_vpn_password_for_prompt(false).as_deref(),
            Some("stored-secret")
        );
        assert!(!format!("{submission:?}").contains("stored-secret"));
    }

    #[test]
    fn ipc_auth_submission_reuses_stored_vpn_password_after_otp_failure() {
        let mut state = IpcAuthSessionState::new(Some(VpnPassword::new("stored-secret").unwrap()));
        state.record_secret_submission(SecretPromptKind::SecondFactorCode);
        let prompt = AuthPrompt {
            form_id: "main".to_owned(),
            title: "Please enter your username and password.".to_owned(),
            message: None,
            error: Some("Login failed.".to_owned()),
            fields: vec![AuthPromptField {
                id: "password".to_owned(),
                label: "Password:".to_owned(),
                kind: AuthPromptFieldKind::Password,
                required: true,
            }],
        };

        let submission = read_ipc_auth_submission(&prompt, 2, &mut state).unwrap();

        assert_eq!(submission.form_id, "main");
        assert_eq!(submission.fields[0].id, "password");
        assert_eq!(submission.fields[0].value, "stored-secret");
        assert!(submission.fields[0].secret);
        assert_eq!(
            stored_vpn_password_message(true),
            "ocx: reusing stored VPN password from keyring to request a new second-factor code"
        );
    }

    #[test]
    fn ipc_auth_state_does_not_auto_retry_stored_vpn_password_after_password_failure() {
        let mut state = IpcAuthSessionState::new(Some(VpnPassword::new("stored-secret").unwrap()));

        assert_eq!(
            state.stored_vpn_password_for_prompt(false).as_deref(),
            Some("stored-secret")
        );

        state.record_secret_submission(SecretPromptKind::VpnPassword);

        assert_eq!(state.stored_vpn_password_for_prompt(true), None);
    }

    #[test]
    fn text_prompt_does_not_duplicate_trailing_colon() {
        assert_eq!(text_prompt("Username"), "Username: ");
        assert_eq!(text_prompt("Username:"), "Username: ");
    }

    #[test]
    fn ipc_auth_prompt_title_labels_second_password_form_as_second_factor() {
        let mut prompt = oc_oxide_ipc::AuthPrompt {
            form_id: "form-otp".to_owned(),
            title: "Please enter your username and password.".to_owned(),
            message: None,
            error: None,
            fields: vec![oc_oxide_ipc::AuthPromptField {
                id: "password".to_owned(),
                label: "Password:".to_owned(),
                kind: oc_oxide_ipc::AuthPromptFieldKind::Password,
                required: true,
            }],
        };

        assert_eq!(
            auth_prompt_title(&prompt, 0),
            "Please enter your username and password."
        );
        assert_eq!(auth_prompt_title(&prompt, 1), "Second-factor verification");
        assert_eq!(
            ipc_password_prompt_kind(&prompt, 1, "password"),
            SecretPromptKind::SecondFactorCode
        );

        prompt.error = Some("Login failed.".to_owned());
        assert_eq!(
            auth_prompt_title(&prompt, 1),
            "Please enter your username and password."
        );
        assert_eq!(
            ipc_password_prompt_kind(&prompt, 1, "password"),
            SecretPromptKind::VpnPassword
        );
    }

    #[test]
    fn smoke_auth_handler_cancels_after_prompt_limit() {
        let mut handler = SmokeAuthHandler {
            username: "alice".to_owned(),
            vpn_password_source: SecretSource::Fixed("do-not-log".to_owned()),
            otp_source: SecretSource::Prompt,
            authgroup: Some("Giga".to_owned()),
            max_auth_prompts: 1,
            prompts: Vec::new(),
        };
        let request = AuthRequest::new(
            "Login",
            vec![
                AuthField::select(
                    "group_list",
                    "Group",
                    vec![AuthChoice::new("Giga", "Giga").unwrap()],
                )
                .unwrap(),
                AuthField::text("username", "Username").unwrap(),
                AuthField::password("password", "Password").unwrap(),
            ],
        )
        .unwrap()
        .with_form_id("form-1")
        .unwrap();

        assert!(matches!(
            handler.handle_auth_request(request.clone()),
            AuthFormDecision::Submit(_)
        ));
        assert!(matches!(
            handler.handle_auth_request(request),
            AuthFormDecision::Cancel
        ));

        let debug = format!("{handler:?}");
        assert!(!debug.contains("do-not-log"));
    }

    #[test]
    fn smoke_auth_handler_submits_two_stage_password_then_second_factor_code() {
        let mut handler = SmokeAuthHandler {
            username: "alice".to_owned(),
            vpn_password_source: SecretSource::Fixed("do-not-log".to_owned()),
            otp_source: SecretSource::Fixed("123456".to_owned()),
            authgroup: None,
            max_auth_prompts: 2,
            prompts: Vec::new(),
        };
        let password_request = AuthRequest::new(
            "Login",
            vec![
                AuthField::text("username", "Username").unwrap(),
                AuthField::password("password", "Password").unwrap(),
            ],
        )
        .unwrap()
        .with_form_id("form-password")
        .unwrap();
        let otp_request = AuthRequest::new(
            "OTP",
            vec![AuthField::password("answer", "One-time password").unwrap()],
        )
        .unwrap()
        .with_form_id("form-otp")
        .unwrap();
        let unexpected_request = AuthRequest::new(
            "Retry",
            vec![AuthField::password("password", "Password").unwrap()],
        )
        .unwrap()
        .with_form_id("form-retry")
        .unwrap();

        assert!(matches!(
            handler.handle_auth_request(password_request),
            AuthFormDecision::Submit(_)
        ));
        let AuthFormDecision::Submit(otp_response) = handler.handle_auth_request(otp_request)
        else {
            panic!("expected OTP response to be submitted");
        };
        assert!(matches!(
            handler.handle_auth_request(unexpected_request),
            AuthFormDecision::Cancel
        ));

        let answer = otp_response
            .answers
            .iter()
            .find(|answer| answer.field_id == "answer")
            .expect("answer field should be present");
        let AuthAnswerValue::Secret(secret) = &answer.value else {
            panic!("answer field should be secret");
        };
        assert_eq!(secret.expose_secret(), "123456");

        let debug = format!("{handler:?}");
        assert!(!debug.contains("do-not-log"));
        assert!(!debug.contains("123456"));
    }

    fn local_bypass_cidr() -> Ipv4Cidr {
        "198.18.0.0/15".parse().unwrap()
    }

    fn sample_ip_info() -> IpInfoSnapshot {
        IpInfoSnapshot {
            address: Some("198.51.100.7".to_owned()),
            netmask: Some("255.255.255.0".to_owned()),
            address6: None,
            netmask6: None,
            dns: vec!["192.0.2.53".to_owned(), "198.51.100.53".to_owned()],
            nbns: Vec::new(),
            domain: Some("corp.example.test".to_owned()),
            proxy_pac: None,
            mtu: 1200,
            split_dns: Vec::new(),
            split_includes: Vec::new(),
            split_excludes: vec![
                SplitRoute {
                    route: "203.0.113.10/255.255.255.255".to_owned(),
                },
                SplitRoute {
                    route: "0.0.0.0/32".to_owned(),
                },
            ],
            gateway_addr: Some("203.0.113.10".to_owned()),
        }
    }
}
