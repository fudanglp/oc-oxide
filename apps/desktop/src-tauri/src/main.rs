use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, fs};

use oc_oxide_config::{
    parse_toml_vpn_profile, KeyringVpnPasswordVault, VpnPassword, VpnPasswordKey, VpnPasswordVault,
};
use oc_oxide_ipc::{
    decode_event_line, decode_response_line, encode_command_line, AuthPrompt, AuthPromptFieldKind,
    AuthSubmission, AuthSubmittedField, DaemonState, DaemonStatus, IpcCommand, IpcErrorResponse,
    IpcEvent, IpcResponse, ProgressUpdate,
};
use oc_oxide_sync::{
    decode_device_flow_poll_response, decode_device_flow_start_response,
    decode_github_token_refresh_response, delete_profile_document, download_profile_documents,
    refresh_github_user_access_token, DeviceFlowPoll, DeviceFlowStart, DeviceFlowTokenSet,
    GithubAppConfig, GithubContentsClient, GithubContentsHttp, GithubContentsMethod,
    GithubContentsRequest, GithubContentsResponse, GithubDeviceFlowHttp, GithubRefreshToken,
    GithubTokenRefreshHttp, GithubTokenVault, KeyringGithubTokenVault, ManifestSyncCodec,
    PrivateRepoSyncCodec, RemoteSyncObject, SyncClient, SyncError, SyncManifest, SyncObjectPath,
    SyncProfileConnection, SyncProfileDocument, SyncWrite, DEFAULT_GITHUB_TOKEN_ACCOUNT,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{
    image::Image,
    menu::{Menu, MenuItem, MenuItemBuilder, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, State, WindowEvent, Wry,
};

const DAEMON_SOCKET_ENV: &str = "OC_OXIDE_DAEMON_SOCKET";
const PROFILE_DIR_ENV: &str = "OC_OXIDE_PROFILE_DIR";
const CONFIG_DIR_ENV: &str = "OC_OXIDE_CONFIG_DIR";
const DEFAULT_DAEMON_SOCKET_PATH: &str = "/tmp/oc-oxide-daemon.sock";
const DAEMON_SERVICE_NAME: &str = "oc-oxide-daemon.service";
const DAEMON_INSTALL_HINT: &str =
    "Install oc-oxide first, then enable the daemon with systemctl. Tarball installs can run sudo ./install.sh && sudo systemctl enable --now oc-oxide-daemon.service; Debian installs can run sudo apt install ./oc-oxide_<version>_<arch>.deb.";
const MAIN_WINDOW_LABEL: &str = "main";
const TRAY_STATUS_ITEM_ID: &str = "tray-status";
const TRAY_SHOW_ITEM_ID: &str = "tray-show";
const TRAY_QUIT_ITEM_ID: &str = "tray-quit";
const GITHUB_DEVICE_CODE_URL: &str = "https://github.com/login/device/code";
const GITHUB_ACCESS_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const GITHUB_API_URL: &str = "https://api.github.com";
const GITHUB_DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
const GITHUB_REFRESH_TOKEN_GRANT_TYPE: &str = "refresh_token";
const GITHUB_API_VERSION: &str = "2022-11-28";
const USER_AGENT: &str = "oc-oxide-desktop/0.1";
const UPDATE_REPO_ENV: &str = "OC_OXIDE_UPDATE_REPO";
const UPDATE_WRAPPER_ENV: &str = "OC_OXIDE_UPDATE_WRAPPER";
const DEFAULT_UPDATE_REPO: &str = "fudanglp/oc-oxide";
const LOCAL_UPDATE_WRAPPER: &str = "/usr/local/libexec/oc-oxide/oc-oxide-update";
const SYSTEM_UPDATE_WRAPPER: &str = "/usr/libexec/oc-oxide/oc-oxide-update";

#[derive(Default)]
struct DesktopState {
    connection: Mutex<Option<DaemonConnection>>,
    tray: Mutex<Option<TrayState>>,
}

struct DaemonConnection {
    writer: Arc<Mutex<UnixStream>>,
}

struct TrayState {
    icon: TrayIcon<Wry>,
    status_item: MenuItem<Wry>,
    connected_icon: Image<'static>,
    disconnected_icon: Image<'static>,
    active_profile: Option<String>,
    interface: Option<String>,
}

#[derive(Debug, Default)]
struct KeyringAuthState {
    vpn_password: Option<String>,
    last_secret_submission: Option<SecretSubmissionKind>,
}

impl KeyringAuthState {
    fn new(vpn_password: Option<String>) -> Self {
        Self {
            vpn_password,
            last_secret_submission: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretSubmissionKind {
    VpnPassword,
}

#[derive(Debug, Deserialize)]
struct SubmittedField {
    id: String,
    value: String,
    secret: bool,
}

#[derive(Debug, Serialize)]
struct IpcExchange {
    response: IpcResponse,
    events: Vec<IpcEvent>,
}

#[derive(Debug, Serialize)]
struct ProfileList {
    profile_dir: String,
    profiles: Vec<ProfileItem>,
}

#[derive(Debug, Serialize)]
struct ProfileItem {
    name: String,
}

#[derive(Debug, Serialize)]
struct ProfileDetail {
    name: String,
    server: String,
    username: Option<String>,
    authgroup: Option<String>,
    reported_os: String,
    company_domains_count: usize,
    local_bypass_count: usize,
}

#[derive(Debug, Serialize)]
struct VpnPasswordStatus {
    saved: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DaemonHandoffStatus {
    socket_path: String,
    service_name: String,
    socket_reachable: bool,
    service_installed: Option<bool>,
    service_active: Option<bool>,
    message: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GithubSyncStatus {
    auth: GithubSyncAuthState,
    repository: String,
    keyring_account: String,
    manifest: GithubSyncManifestState,
    manifest_sha: Option<String>,
    manifest_bytes: Option<usize>,
    message: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GithubSyncHistory {
    entries: Vec<GithubSyncHistoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GithubSyncHistoryEntry {
    recorded_at: String,
    operation: String,
    outcome: String,
    repository: String,
    manifest_sha: Option<String>,
    manifest_bytes: Option<usize>,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum GithubSyncAuthState {
    NotAuthorized,
    Authorized,
    RefreshFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum GithubSyncManifestState {
    Unknown,
    Missing,
    Present,
    Created,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GithubDeviceFlowStartResult {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in_secs: u64,
    interval_secs: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GithubDeviceFlowPollResult {
    status: GithubDeviceFlowPollStatus,
    next_interval_secs: u64,
    expires_in_secs: Option<u64>,
    refresh_token_expires_in_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateStatus {
    current_version: String,
    latest_version: Option<String>,
    update_available: bool,
    release_url: Option<String>,
    asset_name: Option<String>,
    asset_url: Option<String>,
    sha256_url: Option<String>,
    artifact_path: Option<String>,
    sha256_path: Option<String>,
    manifest_path: Option<String>,
    checked_at: String,
    message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateInstallManifest {
    version: String,
    method: UpdateInstallMethod,
    artifact: String,
    sha256: String,
    expected_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum UpdateInstallMethod {
    Deb,
    Tarball,
}

#[derive(Debug, Clone)]
struct GithubRelease {
    repo: String,
    tag_name: String,
    html_url: String,
}

#[derive(Debug, Clone)]
struct UpdateCandidate {
    status: UpdateStatus,
    version: String,
    method: UpdateInstallMethod,
    asset_url: String,
    sha256_url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum GithubDeviceFlowPollStatus {
    Pending,
    SlowDown,
    Authorized,
    AccessDenied,
    Expired,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateProfileInput {
    name: String,
    server: String,
    reported_os: Option<String>,
    username: Option<String>,
    authgroup: Option<String>,
    company_domains: Vec<String>,
    local_bypass: Vec<String>,
}

#[tauri::command]
fn daemon_status(app: AppHandle) -> Result<IpcExchange, String> {
    let exchange = send_one_shot(IpcCommand::Status)?;
    if let IpcResponse::Status(status) = &exchange.response {
        update_tray_status_from_status(&app, status);
    }
    Ok(exchange)
}

#[tauri::command]
fn daemon_diagnostics() -> Result<IpcExchange, String> {
    send_one_shot(IpcCommand::Diagnostics)
}

#[tauri::command]
fn profiles_list() -> Result<ProfileList, String> {
    let profile_dir = local_profile_dir()?;
    let profiles = profiles_from_dir(&profile_dir)?;

    Ok(ProfileList {
        profile_dir: profile_dir.display().to_string(),
        profiles,
    })
}

fn profiles_from_dir(profile_dir: &Path) -> Result<Vec<ProfileItem>, String> {
    let mut profiles = Vec::new();

    match fs::read_dir(profile_dir) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|err| {
                    format!(
                        "failed to read profile directory {}: {err}",
                        profile_dir.display()
                    )
                })?;
                let path = entry.path();
                if path.extension().and_then(|extension| extension.to_str()) != Some("toml") {
                    continue;
                }

                let Some(name) = path.file_stem().and_then(|stem| stem.to_str()) else {
                    continue;
                };
                if clean_profile(name.to_owned()).is_ok() {
                    profiles.push(ProfileItem {
                        name: name.to_owned(),
                    });
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!(
                "failed to read profile directory {}: {err}",
                profile_dir.display()
            ));
        }
    }

    profiles.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(profiles)
}

#[tauri::command]
fn profile_create(input: CreateProfileInput) -> Result<ProfileItem, String> {
    let name = clean_profile(input.name.clone())?;
    let profile_dir = local_profile_dir()?;
    fs::create_dir_all(&profile_dir).map_err(|err| {
        format!(
            "failed to create profile directory {}: {err}",
            profile_dir.display()
        )
    })?;

    let content = render_profile_toml(&input)?;
    parse_toml_vpn_profile(&name, &content)
        .map_err(|err| format!("invalid profile configuration: {err}"))?;

    let path = profile_dir.join(format!("{name}.toml"));
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .and_then(|mut file| file.write_all(content.as_bytes()))
        .map_err(|err| format!("failed to write profile {}: {err}", path.display()))?;

    Ok(ProfileItem { name })
}

#[tauri::command]
fn profile_detail(profile: String) -> Result<ProfileDetail, String> {
    let profile = clean_profile(profile)?;
    let parsed = load_vpn_profile(&profile)?;
    let tunnel = parsed.tunnel();

    Ok(ProfileDetail {
        name: tunnel.name().to_owned(),
        server: tunnel.server_url().as_openconnect_url().to_owned(),
        username: tunnel.username().map(str::to_owned),
        authgroup: tunnel.authgroup().map(str::to_owned),
        reported_os: tunnel.reported_os().to_owned(),
        company_domains_count: parsed.company_domains().len(),
        local_bypass_count: parsed.local_bypass_cidrs().len(),
    })
}

#[tauri::command]
fn profile_duplicate(profile: String) -> Result<ProfileItem, String> {
    let profile = clean_profile(profile)?;
    let profile_dir = local_profile_dir()?;
    let source_path = local_profile_path(&profile)?;
    let content = fs::read_to_string(&source_path)
        .map_err(|err| format!("failed to read profile {}: {err}", source_path.display()))?;
    let name = duplicate_profile_name(&profile_dir, &profile);
    parse_toml_vpn_profile(&name, &content)
        .map_err(|err| format!("invalid duplicated profile configuration: {err}"))?;

    let path = profile_dir.join(format!("{name}.toml"));
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .and_then(|mut file| file.write_all(content.as_bytes()))
        .map_err(|err| format!("failed to write profile {}: {err}", path.display()))?;

    Ok(ProfileItem { name })
}

#[tauri::command]
fn profile_rename(profile: String, new_name: String) -> Result<ProfileItem, String> {
    let profile = clean_profile(profile)?;
    let new_name = clean_profile(new_name)?;
    if profile == new_name {
        return Ok(ProfileItem { name: profile });
    }

    let profile_dir = local_profile_dir()?;
    let source_path = profile_dir.join(format!("{profile}.toml"));
    let target_path = profile_dir.join(format!("{new_name}.toml"));
    if target_path.exists() {
        return Err(format!("profile {new_name:?} already exists"));
    }

    let content = fs::read_to_string(&source_path)
        .map_err(|err| format!("failed to read profile {}: {err}", source_path.display()))?;
    let old_profile = parse_toml_vpn_profile(&profile, &content)
        .map_err(|err| format!("failed to parse profile {}: {err}", source_path.display()))?;
    let new_profile = parse_toml_vpn_profile(&new_name, &content)
        .map_err(|err| format!("invalid renamed profile configuration: {err}"))?;

    fs::rename(&source_path, &target_path).map_err(|err| {
        format!(
            "failed to rename profile {} to {}: {err}",
            source_path.display(),
            target_path.display()
        )
    })?;

    migrate_vpn_password_key(&old_profile, &new_profile)?;

    Ok(ProfileItem { name: new_name })
}

#[tauri::command]
fn profile_delete(profile: String) -> Result<(), String> {
    let profile = clean_profile(profile)?;
    let key = vpn_password_key_for_profile(&profile)?;
    KeyringVpnPasswordVault::new()
        .delete_vpn_password(&key)
        .map_err(|err| err.to_string())?;

    let path = local_profile_path(&profile)?;
    fs::remove_file(&path)
        .map_err(|err| format!("failed to delete profile {}: {err}", path.display()))
}

#[tauri::command]
fn profile_save_vpn_password(profile: String, password: String) -> Result<(), String> {
    let profile = clean_profile(profile)?;
    store_vpn_password_for_profile(&profile, &password)
}

#[tauri::command]
fn profile_vpn_password_status(profile: String) -> Result<VpnPasswordStatus, String> {
    let profile = clean_profile(profile)?;
    let key = vpn_password_key_for_profile(&profile)?;
    let saved = KeyringVpnPasswordVault::new()
        .get_vpn_password(&key)
        .map_err(|err| err.to_string())?
        .is_some();
    Ok(VpnPasswordStatus { saved })
}

#[tauri::command]
fn profile_forget_vpn_password(profile: String) -> Result<VpnPasswordStatus, String> {
    let profile = clean_profile(profile)?;
    let key = vpn_password_key_for_profile(&profile)?;
    KeyringVpnPasswordVault::new()
        .delete_vpn_password(&key)
        .map_err(|err| err.to_string())?;
    Ok(VpnPasswordStatus { saved: false })
}

#[tauri::command]
fn github_sync_history() -> Result<GithubSyncHistory, String> {
    load_github_sync_history()
}

#[tauri::command]
fn daemon_handoff_status() -> DaemonHandoffStatus {
    daemon_handoff_status_with_message(None)
}

#[tauri::command]
async fn daemon_handoff_start() -> Result<DaemonHandoffStatus, String> {
    tauri::async_runtime::spawn_blocking(daemon_handoff_start_blocking)
        .await
        .map_err(|err| format!("daemon handoff task failed: {err}"))?
}

#[tauri::command]
async fn update_check() -> Result<UpdateStatus, String> {
    tauri::async_runtime::spawn_blocking(update_check_blocking)
        .await
        .map_err(|err| format!("update check task failed: {err}"))?
}

#[tauri::command]
async fn update_prepare() -> Result<UpdateStatus, String> {
    tauri::async_runtime::spawn_blocking(update_prepare_blocking)
        .await
        .map_err(|err| format!("update download task failed: {err}"))?
}

#[tauri::command]
async fn update_install(manifest_path: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || update_install_blocking(manifest_path))
        .await
        .map_err(|err| format!("update install task failed: {err}"))?
}

#[tauri::command]
fn update_relaunch(app: AppHandle) -> Result<(), String> {
    app.request_restart();
    Ok(())
}

#[tauri::command]
fn open_external_url(url: String) -> Result<(), String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("only http and https URLs can be opened externally".to_owned());
    }

    let output = Command::new("xdg-open")
        .arg(&url)
        .output()
        .map_err(|err| format!("failed to start xdg-open: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "xdg-open failed: {}",
            command_output_detail(&output.stderr, &output.stdout)
        ));
    }
    Ok(())
}

fn update_check_blocking() -> Result<UpdateStatus, String> {
    Ok(resolve_update_candidate()?.status)
}

fn update_prepare_blocking() -> Result<UpdateStatus, String> {
    let candidate = resolve_update_candidate()?;
    if !candidate.status.update_available {
        return Ok(candidate.status);
    }

    let asset_name = candidate
        .status
        .asset_name
        .clone()
        .ok_or_else(|| "update candidate has no release asset".to_owned())?;
    let version_dir = update_cache_dir()?.join(&candidate.version);
    fs::create_dir_all(&version_dir).map_err(|err| {
        format!(
            "failed to create update cache {}: {err}",
            version_dir.display()
        )
    })?;

    let artifact_path = version_dir.join(&asset_name);
    let sha256_name = format!("{asset_name}.sha256");
    let sha256_path = version_dir.join(&sha256_name);

    download_update_file(&candidate.asset_url, &artifact_path)?;
    download_update_file(&candidate.sha256_url, &sha256_path)?;

    let expected_sha256 = read_expected_sha256(&sha256_path, &asset_name)?;
    let actual_sha256 = sha256_file_hex(&artifact_path)?;
    if !expected_sha256.eq_ignore_ascii_case(&actual_sha256) {
        return Err(format!(
            "downloaded update checksum mismatch for {asset_name}: expected {expected_sha256}, got {actual_sha256}"
        ));
    }

    let manifest = UpdateInstallManifest {
        version: candidate.version.clone(),
        method: candidate.method,
        artifact: artifact_path.display().to_string(),
        sha256: sha256_path.display().to_string(),
        expected_sha256,
    };
    let manifest_path = version_dir.join("install-manifest.json");
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|err| format!("failed to serialize update manifest: {err}"))?;
    fs::write(&manifest_path, manifest_json).map_err(|err| {
        format!(
            "failed to write update manifest {}: {err}",
            manifest_path.display()
        )
    })?;

    let mut status = candidate.status;
    status.artifact_path = Some(artifact_path.display().to_string());
    status.sha256_path = Some(sha256_path.display().to_string());
    status.manifest_path = Some(manifest_path.display().to_string());
    status.message = Some(format!("Downloaded and verified {asset_name}"));
    Ok(status)
}

fn update_install_blocking(manifest_path: String) -> Result<String, String> {
    let manifest_path = PathBuf::from(manifest_path);
    if !manifest_path.is_file() {
        return Err(format!(
            "update manifest is missing: {}",
            manifest_path.display()
        ));
    }

    let wrapper = update_wrapper_path()?;
    let mut command = if current_user_is_root() {
        let mut command = Command::new(&wrapper);
        command.arg("install");
        command
    } else {
        if !command_exists("pkexec") {
            return Err("pkexec is required to install updates from the desktop app".to_owned());
        }
        let mut command = Command::new("pkexec");
        command.arg(&wrapper).arg("install");
        command
    };
    let output = command
        .arg("--manifest")
        .arg(&manifest_path)
        .output()
        .map_err(|err| {
            format!(
                "failed to start update installer {}: {err}",
                wrapper.display()
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "update installer failed: {}",
            command_output_detail(&output.stderr, &output.stdout)
        ));
    }

    Ok(command_output_detail(&output.stderr, &output.stdout))
}

fn resolve_update_candidate() -> Result<UpdateCandidate, String> {
    let release = fetch_latest_release()?;
    let current_version = env!("CARGO_PKG_VERSION").to_owned();
    let latest_version = release.tag_name.trim_start_matches('v').to_owned();
    let update_available = version_is_newer(&latest_version, &current_version);
    let checked_at = sync_updated_at();
    let method = preferred_update_method();
    let (asset_name, asset_url, sha256_url) = if update_available {
        let asset_name = update_asset_name(&latest_version, method)?;
        let sha256_name = format!("{asset_name}.sha256");
        (
            Some(asset_name.clone()),
            Some(github_release_asset_url(
                &release.repo,
                &release.tag_name,
                &asset_name,
            )),
            Some(github_release_asset_url(
                &release.repo,
                &release.tag_name,
                &sha256_name,
            )),
        )
    } else {
        (None, None, None)
    };

    let status = UpdateStatus {
        current_version,
        latest_version: Some(latest_version.clone()),
        update_available,
        release_url: Some(release.html_url),
        asset_name,
        asset_url: asset_url.clone(),
        sha256_url: sha256_url.clone(),
        artifact_path: None,
        sha256_path: None,
        manifest_path: None,
        checked_at,
        message: Some(if update_available {
            format!("oc-oxide {} is available", release.tag_name)
        } else {
            "oc-oxide is up to date".to_owned()
        }),
    };

    Ok(UpdateCandidate {
        status,
        version: release.tag_name,
        method,
        asset_url: asset_url.unwrap_or_default(),
        sha256_url: sha256_url.unwrap_or_default(),
    })
}

fn fetch_latest_release() -> Result<GithubRelease, String> {
    let repo = env::var(UPDATE_REPO_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_UPDATE_REPO.to_owned());
    let url = format!("https://github.com/{repo}/releases/latest");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent(USER_AGENT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| format!("failed to build update HTTP client: {err}"))?;
    let response = client
        .get(&url)
        .send()
        .map_err(|err| format!("failed to fetch latest release metadata: {err}"))?
        .error_for_status()
        .map_err(|err| format!("latest release request failed: {err}"))?;
    if !response.status().is_redirection() {
        return Err(format!(
            "latest release endpoint did not redirect: HTTP {}",
            response.status()
        ));
    }
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| "latest release redirect did not include a Location header".to_owned())?;
    let tag_name = parse_release_tag(location).ok_or_else(|| {
        format!("latest release redirect did not include a release tag: {location}")
    })?;
    let html_url = if location.starts_with("http://") || location.starts_with("https://") {
        location.to_owned()
    } else {
        format!("https://github.com{location}")
    };

    Ok(GithubRelease {
        repo,
        tag_name,
        html_url,
    })
}

fn parse_release_tag(location: &str) -> Option<String> {
    let marker = "/releases/tag/";
    let (_, tag) = location.split_once(marker)?;
    let tag = tag
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .trim_matches('/');
    (!tag.is_empty()).then(|| tag.to_owned())
}

fn github_release_asset_url(repo: &str, tag: &str, asset_name: &str) -> String {
    format!("https://github.com/{repo}/releases/download/{tag}/{asset_name}")
}

fn preferred_update_method() -> UpdateInstallMethod {
    if command_exists("apt") && command_exists("dpkg") {
        UpdateInstallMethod::Deb
    } else {
        UpdateInstallMethod::Tarball
    }
}

fn update_asset_name(version: &str, method: UpdateInstallMethod) -> Result<String, String> {
    let version = version.trim_start_matches('v');
    match method {
        UpdateInstallMethod::Deb => Ok(format!("oc-oxide_{version}_{}.deb", deb_arch()?)),
        UpdateInstallMethod::Tarball => {
            Ok(format!("oc-oxide-{version}-linux-{}.tar.gz", linux_arch()?))
        }
    }
}

fn download_update_file(url: &str, path: &Path) -> Result<(), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent(USER_AGENT)
        .build()
        .map_err(|err| format!("failed to build update download client: {err}"))?;
    let mut response = client
        .get(url)
        .send()
        .map_err(|err| format!("failed to download {url}: {err}"))?
        .error_for_status()
        .map_err(|err| format!("download failed for {url}: {err}"))?;
    let part_path = path.with_extension(format!(
        "{}part",
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| format!("{extension}."))
            .unwrap_or_default()
    ));
    let mut file = fs::File::create(&part_path)
        .map_err(|err| format!("failed to create {}: {err}", part_path.display()))?;
    response
        .copy_to(&mut file)
        .map_err(|err| format!("failed to write {}: {err}", part_path.display()))?;
    file.flush()
        .map_err(|err| format!("failed to flush {}: {err}", part_path.display()))?;
    fs::rename(&part_path, path).map_err(|err| {
        format!(
            "failed to move downloaded update {} to {}: {err}",
            part_path.display(),
            path.display()
        )
    })
}

fn read_expected_sha256(path: &Path, asset_name: &str) -> Result<String, String> {
    let content = fs::read_to_string(path)
        .map_err(|err| format!("failed to read checksum file {}: {err}", path.display()))?;
    let mut fields = content.split_whitespace();
    let checksum = fields
        .next()
        .ok_or_else(|| format!("checksum file {} is empty", path.display()))?;
    if checksum.len() != 64
        || !checksum
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(format!(
            "checksum file {} does not contain a sha256 digest",
            path.display()
        ));
    }
    if let Some(name) = fields.next() {
        let clean_name = name.trim_start_matches('*');
        if clean_name != asset_name {
            return Err(format!(
                "checksum file {} describes {clean_name}, expected {asset_name}",
                path.display()
            ));
        }
    }
    Ok(checksum.to_ascii_lowercase())
}

fn sha256_file_hex(path: &Path) -> Result<String, String> {
    let mut file =
        fs::File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex_lower(&hasher.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn update_cache_dir() -> Result<PathBuf, String> {
    let base = env::var_os("XDG_CACHE_HOME")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .ok_or_else(|| "HOME or XDG_CACHE_HOME is required to store update downloads".to_owned())?;
    Ok(base.join("oc-oxide").join("updates"))
}

fn update_wrapper_path() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os(UPDATE_WRAPPER_ENV)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
    {
        if path.is_file() {
            return Ok(path);
        }
        return Err(format!(
            "configured update wrapper is missing: {}",
            path.display()
        ));
    }

    [SYSTEM_UPDATE_WRAPPER, LOCAL_UPDATE_WRAPPER]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .ok_or_else(|| {
            format!(
                "update wrapper is not installed; expected {SYSTEM_UPDATE_WRAPPER} or {LOCAL_UPDATE_WRAPPER}"
            )
        })
}

fn current_user_is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim() == "0")
        .unwrap_or(false)
}

fn command_exists(name: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {name} >/dev/null 2>&1"))
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn linux_arch() -> Result<&'static str, String> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("x86_64"),
        "aarch64" => Ok("aarch64"),
        other => Err(format!("unsupported update architecture: {other}")),
    }
}

fn deb_arch() -> Result<&'static str, String> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("amd64"),
        "aarch64" => Ok("arm64"),
        other => Err(format!("unsupported update architecture: {other}")),
    }
}

fn version_is_newer(candidate: &str, current: &str) -> bool {
    let Some(candidate) = parse_semver_triplet(candidate) else {
        return candidate > current;
    };
    let Some(current) = parse_semver_triplet(current) else {
        return true;
    };
    candidate > current
}

fn parse_semver_triplet(value: &str) -> Option<(u64, u64, u64)> {
    let value = value.trim_start_matches('v');
    let core = value.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

fn daemon_handoff_start_blocking() -> Result<DaemonHandoffStatus, String> {
    if daemon_socket_available() {
        return Ok(daemon_handoff_status_with_message(Some(
            "daemon is already running".to_owned(),
        )));
    }

    let service = systemd_service_state();
    if matches!(service.installed, Some(false)) {
        return Err(format!(
            "{} is not installed. {DAEMON_INSTALL_HINT}",
            DAEMON_SERVICE_NAME
        ));
    }

    let output = Command::new("systemctl")
        .arg("start")
        .arg(DAEMON_SERVICE_NAME)
        .output()
        .map_err(|err| format!("failed to start {DAEMON_SERVICE_NAME} with systemctl: {err}"))?;
    if !output.status.success() {
        let detail = command_output_detail(&output.stderr, &output.stdout);
        return Err(format!(
            "systemctl could not start {DAEMON_SERVICE_NAME}: {detail}. {DAEMON_INSTALL_HINT}"
        ));
    }

    for _ in 0..20 {
        if daemon_socket_available() {
            return Ok(daemon_handoff_status_with_message(Some(
                "daemon service started".to_owned(),
            )));
        }
        thread::sleep(Duration::from_millis(150));
    }

    Ok(daemon_handoff_status_with_message(Some(
        "systemd accepted the start request, but the daemon socket is not present yet".to_owned(),
    )))
}

#[tauri::command]
async fn github_sync_status() -> Result<GithubSyncStatus, String> {
    spawn_github_sync_task(github_sync_status_blocking).await
}

fn github_sync_status_blocking() -> Result<GithubSyncStatus, String> {
    let mut vault = KeyringGithubTokenVault::new();
    let Some(refresh_token) = vault
        .get_refresh_token(DEFAULT_GITHUB_TOKEN_ACCOUNT)
        .map_err(|err| err.to_string())?
    else {
        return Ok(github_sync_status_response(
            GithubSyncAuthState::NotAuthorized,
            GithubSyncManifestState::Unknown,
            None,
            None,
            None,
        ));
    };

    let tokens = match refresh_github_tokens(&refresh_token) {
        Ok(tokens) => tokens,
        Err(err) => {
            return Ok(github_sync_status_response(
                GithubSyncAuthState::RefreshFailed,
                GithubSyncManifestState::Unknown,
                None,
                None,
                Some(err),
            ));
        }
    };
    store_github_tokens_in_vault(&mut vault, &tokens)?;

    let http = ReqwestGithubContentsHttp::new().map_err(|err| err.to_string())?;
    let client = GithubContentsClient::oc_oxide_sync(tokens.access_token.clone(), http)
        .map_err(|err| err.to_string())?;
    let manifest = client
        .read_object(&SyncObjectPath::manifest())
        .map_err(|err| err.to_string())?;

    let status = match manifest {
        Some(object) => github_sync_status_for_manifest(
            GithubSyncAuthState::Authorized,
            GithubSyncManifestState::Present,
            Some(&object),
            None,
        ),
        None => github_sync_status_response(
            GithubSyncAuthState::Authorized,
            GithubSyncManifestState::Missing,
            None,
            None,
            None,
        ),
    };
    let _ = record_github_sync_history("status", "success", &status);
    Ok(status)
}

#[tauri::command]
async fn github_sync_device_flow_start() -> Result<GithubDeviceFlowStartResult, String> {
    spawn_github_sync_task(github_sync_device_flow_start_blocking).await
}

fn github_sync_device_flow_start_blocking() -> Result<GithubDeviceFlowStartResult, String> {
    let app = GithubAppConfig::oc_oxide_sync();
    app.validate().map_err(|err| err.to_string())?;
    let mut http = ReqwestGithubDeviceFlowHttp::new().map_err(|err| err.to_string())?;
    let start = http
        .start_device_flow(&app.client_id)
        .map_err(|err| err.to_string())?;
    Ok(github_device_flow_start_result(start))
}

#[tauri::command]
async fn github_sync_device_flow_poll(
    device_code: String,
    interval_secs: u64,
) -> Result<GithubDeviceFlowPollResult, String> {
    spawn_github_sync_task(move || {
        github_sync_device_flow_poll_blocking(device_code, interval_secs)
    })
    .await
}

fn github_sync_device_flow_poll_blocking(
    device_code: String,
    interval_secs: u64,
) -> Result<GithubDeviceFlowPollResult, String> {
    let app = GithubAppConfig::oc_oxide_sync();
    app.validate().map_err(|err| err.to_string())?;
    let mut http = ReqwestGithubDeviceFlowHttp::new().map_err(|err| err.to_string())?;
    let step = oc_oxide_sync::poll_device_flow_once(
        &mut http,
        &app.client_id,
        &device_code,
        interval_secs,
    )
    .map_err(|err| err.to_string())?;

    let mut result = match step.poll {
        DeviceFlowPoll::Pending { .. } => GithubDeviceFlowPollResult {
            status: GithubDeviceFlowPollStatus::Pending,
            next_interval_secs: step.next_interval_secs,
            expires_in_secs: None,
            refresh_token_expires_in_secs: None,
        },
        DeviceFlowPoll::SlowDown { .. } => GithubDeviceFlowPollResult {
            status: GithubDeviceFlowPollStatus::SlowDown,
            next_interval_secs: step.next_interval_secs,
            expires_in_secs: None,
            refresh_token_expires_in_secs: None,
        },
        DeviceFlowPoll::Authorized(tokens) => {
            let expires_in_secs = tokens.expires_in_secs;
            let refresh_token_expires_in_secs = tokens.refresh_token_expires_in_secs;
            let mut vault = KeyringGithubTokenVault::new();
            store_github_tokens_in_vault(&mut vault, &tokens)?;
            GithubDeviceFlowPollResult {
                status: GithubDeviceFlowPollStatus::Authorized,
                next_interval_secs: step.next_interval_secs,
                expires_in_secs: Some(expires_in_secs),
                refresh_token_expires_in_secs: Some(refresh_token_expires_in_secs),
            }
        }
        DeviceFlowPoll::AccessDenied => GithubDeviceFlowPollResult {
            status: GithubDeviceFlowPollStatus::AccessDenied,
            next_interval_secs: step.next_interval_secs,
            expires_in_secs: None,
            refresh_token_expires_in_secs: None,
        },
        DeviceFlowPoll::Expired => GithubDeviceFlowPollResult {
            status: GithubDeviceFlowPollStatus::Expired,
            next_interval_secs: step.next_interval_secs,
            expires_in_secs: None,
            refresh_token_expires_in_secs: None,
        },
    };

    if result.next_interval_secs == 0 {
        result.next_interval_secs = interval_secs.max(1);
    }
    Ok(result)
}

#[tauri::command]
async fn github_sync_init_manifest() -> Result<GithubSyncStatus, String> {
    spawn_github_sync_task(github_sync_init_manifest_blocking).await
}

fn github_sync_init_manifest_blocking() -> Result<GithubSyncStatus, String> {
    let codec = PrivateRepoSyncCodec::new();
    let mut vault = KeyringGithubTokenVault::new();
    let stored_refresh = vault
        .get_refresh_token(DEFAULT_GITHUB_TOKEN_ACCOUNT)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| "GitHub sync is not authorized".to_owned())?;
    let tokens = refresh_github_tokens(&stored_refresh)?;
    store_github_tokens_in_vault(&mut vault, &tokens)?;

    let http = ReqwestGithubContentsHttp::new().map_err(|err| err.to_string())?;
    let mut client = GithubContentsClient::oc_oxide_sync(tokens.access_token.clone(), http)
        .map_err(|err| err.to_string())?;
    let path = SyncObjectPath::manifest();
    if let Some(existing) = client.read_object(&path).map_err(|err| err.to_string())? {
        let status = github_sync_status_for_manifest(
            GithubSyncAuthState::Authorized,
            GithubSyncManifestState::Present,
            Some(&existing),
            Some("manifest already exists".to_owned()),
        );
        let _ = record_github_sync_history("init", "success", &status);
        return Ok(status);
    }

    let blob = codec
        .encode_manifest(&SyncManifest::new())
        .map_err(|err| err.to_string())?;
    let written = client
        .write_object(
            SyncWrite::create(blob, "Initialize oc-oxide sync manifest")
                .map_err(|err| err.to_string())?,
        )
        .map_err(|err| err.to_string())?;
    let status = github_sync_status_for_manifest(
        GithubSyncAuthState::Authorized,
        GithubSyncManifestState::Created,
        Some(&written),
        None,
    );
    let _ = record_github_sync_history("init", "success", &status);
    Ok(status)
}

#[tauri::command]
async fn github_sync_upload_profiles() -> Result<GithubSyncStatus, String> {
    spawn_github_sync_task(github_sync_upload_profiles_blocking).await
}

fn github_sync_upload_profiles_blocking() -> Result<GithubSyncStatus, String> {
    let documents = local_sync_profile_documents()?;
    if documents.is_empty() {
        return Err("no local profiles to upload".to_owned());
    }

    let codec = PrivateRepoSyncCodec::new();
    let mut vault = KeyringGithubTokenVault::new();
    let stored_refresh = vault
        .get_refresh_token(DEFAULT_GITHUB_TOKEN_ACCOUNT)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| "GitHub sync is not authorized".to_owned())?;
    let tokens = refresh_github_tokens(&stored_refresh)?;
    store_github_tokens_in_vault(&mut vault, &tokens)?;

    let http = ReqwestGithubContentsHttp::new().map_err(|err| err.to_string())?;
    let mut client = GithubContentsClient::oc_oxide_sync(tokens.access_token.clone(), http)
        .map_err(|err| err.to_string())?;
    let report = oc_oxide_sync::upload_profile_documents(
        &mut client,
        &codec,
        &documents,
        &sync_updated_at(),
        &sync_device_id(),
    )
    .map_err(github_sync_upload_error)?;

    let status = github_sync_status_response(
        GithubSyncAuthState::Authorized,
        GithubSyncManifestState::Present,
        Some(report.manifest_sha),
        Some(report.manifest_bytes),
        Some(format!(
            "uploaded {} profile(s); remote manifest tracks {} profile(s)",
            report.uploaded_profiles, report.manifest_profile_count
        )),
    );
    let _ = record_github_sync_history("upload", "success", &status);
    Ok(status)
}

#[tauri::command]
async fn github_sync_download_profiles() -> Result<GithubSyncStatus, String> {
    spawn_github_sync_task(github_sync_download_profiles_blocking).await
}

#[tauri::command]
async fn github_sync_delete_profile(profile: String) -> Result<GithubSyncStatus, String> {
    let profile = clean_profile(profile)?;
    spawn_github_sync_task(move || github_sync_delete_profile_blocking(profile)).await
}

fn github_sync_download_profiles_blocking() -> Result<GithubSyncStatus, String> {
    let codec = PrivateRepoSyncCodec::new();
    let mut vault = KeyringGithubTokenVault::new();
    let stored_refresh = vault
        .get_refresh_token(DEFAULT_GITHUB_TOKEN_ACCOUNT)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| "GitHub sync is not authorized".to_owned())?;
    let tokens = refresh_github_tokens(&stored_refresh)?;
    store_github_tokens_in_vault(&mut vault, &tokens)?;

    let http = ReqwestGithubContentsHttp::new().map_err(|err| err.to_string())?;
    let client = GithubContentsClient::oc_oxide_sync(tokens.access_token.clone(), http)
        .map_err(|err| err.to_string())?;
    let report = download_profile_documents(&client, &codec).map_err(|err| err.to_string())?;
    let profile_dir = local_profile_dir()?;
    fs::create_dir_all(&profile_dir).map_err(|err| {
        format!(
            "failed to create profile directory {}: {err}",
            profile_dir.display()
        )
    })?;

    let mut existing = profiles_from_dir(&profile_dir)?
        .into_iter()
        .map(|item| item.name)
        .collect::<BTreeSet<_>>();
    let mut imported = 0usize;
    let mut copied_conflicts = 0usize;

    for document in &report.profiles {
        let name = clean_profile(document.profile_id.clone())?;
        let import_name = if existing.contains(&name) {
            copied_conflicts += 1;
            restored_conflict_profile_name(&existing, &name)
        } else {
            name
        };

        let content = render_sync_profile_toml(document)?;
        parse_toml_vpn_profile(&import_name, &content)
            .map_err(|err| format!("invalid downloaded profile configuration: {err}"))?;

        let path = profile_dir.join(format!("{import_name}.toml"));
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .and_then(|mut file| file.write_all(content.as_bytes()))
            .map_err(|err| format!("failed to write profile {}: {err}", path.display()))?;

        existing.insert(import_name);
        imported += 1;
    }

    let status = github_sync_status_response(
        GithubSyncAuthState::Authorized,
        GithubSyncManifestState::Present,
        Some(report.manifest_sha),
        Some(report.manifest_bytes),
        Some(format!(
            "downloaded {} profile(s); imported {} same-name conflict(s) as local copies; remote manifest tracks {} profile(s)",
            imported, copied_conflicts, report.manifest_profile_count
        )),
    );
    let _ = record_github_sync_history("restore", "success", &status);
    Ok(status)
}

fn github_sync_delete_profile_blocking(profile: String) -> Result<GithubSyncStatus, String> {
    let codec = PrivateRepoSyncCodec::new();
    let mut vault = KeyringGithubTokenVault::new();
    let stored_refresh = vault
        .get_refresh_token(DEFAULT_GITHUB_TOKEN_ACCOUNT)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| "GitHub sync is not authorized".to_owned())?;
    let tokens = refresh_github_tokens(&stored_refresh)?;
    store_github_tokens_in_vault(&mut vault, &tokens)?;

    let http = ReqwestGithubContentsHttp::new().map_err(|err| err.to_string())?;
    let mut client = GithubContentsClient::oc_oxide_sync(tokens.access_token.clone(), http)
        .map_err(|err| err.to_string())?;
    let report = delete_profile_document(
        &mut client,
        &codec,
        &profile,
        &sync_updated_at(),
        &sync_device_id(),
    )
    .map_err(|err| err.to_string())?;

    let status = github_sync_status_response(
        GithubSyncAuthState::Authorized,
        GithubSyncManifestState::Present,
        Some(report.manifest_sha),
        Some(report.manifest_bytes),
        Some(format!(
            "deleted remote profile {}; tombstone {}; manifest tracks {} profile(s)",
            report.profile_id, report.tombstone_sha, report.manifest_profile_count
        )),
    );
    let _ = record_github_sync_history("delete", "success", &status);
    Ok(status)
}

fn github_sync_upload_error(err: SyncError) -> String {
    match err {
        SyncError::Conflict { path, .. } => format!(
            "remote sync object changed while uploading {path}; refresh Cloud Sync status, restore remote profiles if needed, then retry upload"
        ),
        other => other.to_string(),
    }
}

#[tauri::command]
fn daemon_connect(
    app: AppHandle,
    state: State<'_, DesktopState>,
    profile: String,
) -> Result<(), String> {
    let profile = clean_profile(profile)?;
    update_tray_status(&app, DaemonState::Configuring, Some(profile.as_str()), None);
    let stored_vpn_password = load_vpn_password_from_keyring(&profile).unwrap_or(None);
    let profile_toml = local_profile_toml(&profile)?;
    let mut stream = connect_daemon_socket()?;
    let writer =
        Arc::new(Mutex::new(stream.try_clone().map_err(|err| {
            format!("failed to clone daemon socket: {err}")
        })?));
    let auth_state = Arc::new(Mutex::new(KeyringAuthState::new(stored_vpn_password)));

    write_command(
        &mut stream,
        &IpcCommand::ConnectWithProfile {
            profile,
            profile_toml,
        },
    )?;
    {
        let mut guard = state
            .connection
            .lock()
            .map_err(|_| "desktop connection lock was poisoned".to_owned())?;
        *guard = Some(DaemonConnection {
            writer: Arc::clone(&writer),
        });
    }

    thread::spawn(move || read_daemon_stream(app, stream, writer, auth_state));
    Ok(())
}

#[tauri::command]
fn daemon_submit_auth(
    state: State<'_, DesktopState>,
    form_id: String,
    fields: Vec<SubmittedField>,
) -> Result<(), String> {
    let fields = fields
        .into_iter()
        .map(|field| AuthSubmittedField::new(field.id, field.value, field.secret))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())?;
    let command = IpcCommand::SubmitAuth(
        AuthSubmission::new(form_id, fields).map_err(|err| err.to_string())?,
    );
    write_active_command(&state, &command)
}

#[tauri::command]
fn daemon_disconnect(app: AppHandle, state: State<'_, DesktopState>) -> Result<(), String> {
    update_tray_status(&app, DaemonState::Disconnecting, None, None);
    if write_active_command(&state, &IpcCommand::Disconnect).is_ok() {
        return Ok(());
    }

    send_one_shot(IpcCommand::Disconnect).map(|_| ())
}

fn read_daemon_stream(
    app: AppHandle,
    stream: UnixStream,
    writer: Arc<Mutex<UnixStream>>,
    auth_state: Arc<Mutex<KeyringAuthState>>,
) {
    let mut reader = BufReader::new(stream);

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                let event = IpcEvent::Disconnected {
                    reason: oc_oxide_ipc::DisconnectReason::Unknown,
                };
                update_tray_status_from_event(&app, &event);
                let _ = app.emit("daemon-event", event);
                break;
            }
            Ok(_) => emit_ipc_line(&app, &line, &writer, &auth_state),
            Err(err) => {
                let event = IpcEvent::Error(oc_oxide_ipc::IpcErrorResponse {
                    code: "daemon_read_failed".to_owned(),
                    message: err.to_string(),
                });
                update_tray_status_from_event(&app, &event);
                let _ = app.emit("daemon-event", event);
                break;
            }
        }
    }
}

fn emit_ipc_line(
    app: &AppHandle,
    line: &str,
    writer: &Arc<Mutex<UnixStream>>,
    auth_state: &Arc<Mutex<KeyringAuthState>>,
) {
    if let Ok(response) = decode_response_line(line) {
        if let IpcResponse::Status(status) = &response {
            update_tray_status_from_status(app, status);
        }
        let _ = app.emit("daemon-response", response);
        return;
    }

    match decode_event_line(line) {
        Ok(event) => {
            update_tray_status_from_event(app, &event);
            if let IpcEvent::AuthPrompt(prompt) = &event {
                if try_submit_stored_vpn_password(app, writer, auth_state, prompt) {
                    return;
                }
            }
            let _ = app.emit("daemon-event", event);
        }
        Err(err) => {
            let event = IpcEvent::Error(oc_oxide_ipc::IpcErrorResponse {
                code: "daemon_decode_failed".to_owned(),
                message: err.to_string(),
            });
            update_tray_status_from_event(app, &event);
            let _ = app.emit("daemon-event", event);
        }
    }
}

fn try_submit_stored_vpn_password(
    app: &AppHandle,
    writer: &Arc<Mutex<UnixStream>>,
    auth_state: &Arc<Mutex<KeyringAuthState>>,
    prompt: &AuthPrompt,
) -> bool {
    let Some(field) = stored_vpn_password_field(prompt) else {
        return false;
    };

    let password = {
        let guard = match auth_state.lock() {
            Ok(guard) => guard,
            Err(_) => return false,
        };
        if prompt.error.is_some()
            && guard.last_secret_submission == Some(SecretSubmissionKind::VpnPassword)
        {
            return false;
        }
        let Some(password) = &guard.vpn_password else {
            return false;
        };
        password.clone()
    };

    let submitted = match AuthSubmittedField::new(field.id.clone(), password, true)
        .and_then(|field| AuthSubmission::new(prompt.form_id.clone(), vec![field]))
    {
        Ok(submission) => submission,
        Err(err) => {
            let _ = app.emit(
                "daemon-event",
                IpcEvent::Error(IpcErrorResponse {
                    code: "keyring_auth_submit_failed".to_owned(),
                    message: err.to_string(),
                }),
            );
            return false;
        }
    };
    let command = IpcCommand::SubmitAuth(submitted);

    let result = writer
        .lock()
        .map_err(|_| "daemon writer lock was poisoned".to_owned())
        .and_then(|mut writer| write_command(&mut writer, &command));
    if let Err(err) = result {
        let _ = app.emit(
            "daemon-event",
            IpcEvent::Error(IpcErrorResponse {
                code: "keyring_auth_submit_failed".to_owned(),
                message: err,
            }),
        );
        return false;
    }

    if let Ok(mut guard) = auth_state.lock() {
        guard.last_secret_submission = Some(SecretSubmissionKind::VpnPassword);
    }
    let _ = app.emit(
        "daemon-event",
        IpcEvent::Progress(ProgressUpdate {
            level: 0,
            message: "using stored VPN password from keyring".to_owned(),
        }),
    );
    update_tray_status(app, DaemonState::Connecting, None, None);
    true
}

fn stored_vpn_password_field(prompt: &AuthPrompt) -> Option<&oc_oxide_ipc::AuthPromptField> {
    if prompt.fields.len() != 1 {
        return None;
    }

    let field = &prompt.fields[0];
    let is_password_id = field.id.eq_ignore_ascii_case("password");
    let is_secret_field = matches!(
        field.kind,
        AuthPromptFieldKind::Password | AuthPromptFieldKind::Text { secret: true }
    );
    if is_password_id && is_secret_field {
        Some(field)
    } else {
        None
    }
}

fn write_active_command(
    state: &State<'_, DesktopState>,
    command: &IpcCommand,
) -> Result<(), String> {
    let guard = state
        .connection
        .lock()
        .map_err(|_| "desktop connection lock was poisoned".to_owned())?;
    let connection = guard
        .as_ref()
        .ok_or_else(|| "no active daemon connection".to_owned())?;
    let mut writer = connection
        .writer
        .lock()
        .map_err(|_| "daemon writer lock was poisoned".to_owned())?;
    write_command(&mut writer, command)
}

fn send_one_shot(command: IpcCommand) -> Result<IpcExchange, String> {
    let mut stream = connect_daemon_socket()?;
    write_command(&mut stream, &command)?;

    let mut reader = BufReader::new(stream);
    let mut events = Vec::new();
    loop {
        let mut line = String::new();
        if reader
            .read_line(&mut line)
            .map_err(|err| format!("daemon read failed: {err}"))?
            == 0
        {
            return Err("daemon closed IPC connection without a response".to_owned());
        }

        if let Ok(response) = decode_response_line(&line) {
            return Ok(IpcExchange { response, events });
        }

        events.push(decode_event_line(&line).map_err(|err| err.to_string())?);
    }
}

fn write_command(stream: &mut UnixStream, command: &IpcCommand) -> Result<(), String> {
    let line = encode_command_line(command).map_err(|err| err.to_string())?;
    stream
        .write_all(line.as_bytes())
        .map_err(|err| format!("daemon write failed: {err}"))?;
    stream
        .flush()
        .map_err(|err| format!("daemon flush failed: {err}"))
}

async fn spawn_github_sync_task<T, F>(task: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(task)
        .await
        .map_err(|err| format!("GitHub sync task failed: {err}"))?
}

fn github_sync_status_response(
    auth: GithubSyncAuthState,
    manifest: GithubSyncManifestState,
    manifest_sha: Option<String>,
    manifest_bytes: Option<usize>,
    message: Option<String>,
) -> GithubSyncStatus {
    GithubSyncStatus {
        auth,
        repository: oc_oxide_sync::SyncRepository::oc_oxide_sync().full_name(),
        keyring_account: DEFAULT_GITHUB_TOKEN_ACCOUNT.to_owned(),
        manifest,
        manifest_sha,
        manifest_bytes,
        message,
    }
}

fn github_sync_status_for_manifest(
    auth: GithubSyncAuthState,
    manifest: GithubSyncManifestState,
    object: Option<&RemoteSyncObject>,
    message: Option<String>,
) -> GithubSyncStatus {
    github_sync_status_response(
        auth,
        manifest,
        object.map(|object| object.sha.clone()),
        object.map(|object| object.bytes().len()),
        message,
    )
}

fn github_device_flow_start_result(start: DeviceFlowStart) -> GithubDeviceFlowStartResult {
    GithubDeviceFlowStartResult {
        device_code: start.device_code,
        user_code: start.user_code,
        verification_uri: start.verification_uri,
        expires_in_secs: start.expires_in_secs,
        interval_secs: start.interval_secs,
    }
}

fn refresh_github_tokens(refresh_token: &GithubRefreshToken) -> Result<DeviceFlowTokenSet, String> {
    let app = GithubAppConfig::oc_oxide_sync();
    app.validate().map_err(|err| err.to_string())?;
    let mut http = ReqwestGithubTokenRefreshHttp::new().map_err(|err| err.to_string())?;
    refresh_github_user_access_token(&mut http, &app.client_id, refresh_token)
        .map_err(|err| err.to_string())
}

fn store_github_tokens_in_vault(
    vault: &mut impl GithubTokenVault,
    tokens: &DeviceFlowTokenSet,
) -> Result<(), String> {
    vault
        .set_refresh_token(DEFAULT_GITHUB_TOKEN_ACCOUNT, &tokens.refresh_token)
        .map_err(|err| err.to_string())
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

fn connect_daemon_socket() -> Result<UnixStream, String> {
    let path = daemon_socket_path();
    UnixStream::connect(&path)
        .map_err(|err| format!("failed to connect daemon socket {}: {err}", path.display()))
}

fn daemon_socket_available() -> bool {
    daemon_socket_probe_message().is_none()
}

fn daemon_socket_path() -> PathBuf {
    env::var_os(DAEMON_SOCKET_ENV)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DAEMON_SOCKET_PATH))
}

#[derive(Debug, Default)]
struct SystemdServiceState {
    installed: Option<bool>,
    active: Option<bool>,
}

fn daemon_handoff_status_with_message(message: Option<String>) -> DaemonHandoffStatus {
    let service = systemd_service_state();
    let socket_message = daemon_socket_probe_message();
    let socket_reachable = socket_message.is_none();
    DaemonHandoffStatus {
        socket_path: daemon_socket_path().display().to_string(),
        service_name: DAEMON_SERVICE_NAME.to_owned(),
        socket_reachable,
        service_installed: service.installed,
        service_active: service.active,
        message: message.or_else(|| daemon_handoff_default_message(&service, socket_message)),
    }
}

fn daemon_handoff_default_message(
    service: &SystemdServiceState,
    socket_message: Option<String>,
) -> Option<String> {
    if socket_message.is_none() {
        return None;
    }

    if matches!(service.installed, Some(false)) {
        return Some(format!(
            "{} is not installed. {DAEMON_INSTALL_HINT}",
            DAEMON_SERVICE_NAME
        ));
    }

    if matches!(service.active, Some(true)) {
        return Some(format!(
            "The daemon service is active, but {}",
            socket_message.unwrap_or_else(|| "the daemon socket is not present yet".to_owned())
        ));
    }

    Some(
        "The privileged daemon is not running. Start the packaged systemd service before connecting."
            .to_owned(),
    )
}

fn daemon_socket_probe_message() -> Option<String> {
    let path = daemon_socket_path();
    match fs::symlink_metadata(&path) {
        Ok(metadata) if is_unix_socket(&metadata) => None,
        Ok(_) => Some(format!(
            "{} exists but is not a Unix socket",
            path.display()
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Some(format!("{} is not present yet", path.display()))
        }
        Err(err) => Some(format!("{} cannot be inspected: {err}", path.display())),
    }
}

#[cfg(unix)]
fn is_unix_socket(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_socket()
}

#[cfg(not(unix))]
fn is_unix_socket(_metadata: &fs::Metadata) -> bool {
    false
}

fn systemd_service_state() -> SystemdServiceState {
    SystemdServiceState {
        installed: systemctl_show_value("LoadState").map(|value| value == "loaded"),
        active: systemctl_show_value("ActiveState").map(|value| value == "active"),
    }
}

fn systemctl_show_value(property: &str) -> Option<String> {
    let output = Command::new("systemctl")
        .arg("show")
        .arg(DAEMON_SERVICE_NAME)
        .arg(format!("--property={property}"))
        .arg("--value")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!value.is_empty()).then_some(value)
}

fn command_output_detail(stderr: &[u8], stdout: &[u8]) -> String {
    let stderr = String::from_utf8_lossy(stderr).trim().to_owned();
    if !stderr.is_empty() {
        return stderr;
    }

    let stdout = String::from_utf8_lossy(stdout).trim().to_owned();
    if !stdout.is_empty() {
        return stdout;
    }

    "no systemctl output".to_owned()
}

fn load_vpn_password_from_keyring(profile_name: &str) -> Result<Option<String>, String> {
    let key = vpn_password_key_for_profile(profile_name)?;
    Ok(KeyringVpnPasswordVault::new()
        .get_vpn_password(&key)
        .map_err(|err| err.to_string())?
        .map(|password| password.expose_secret().to_owned()))
}

fn store_vpn_password_for_profile(profile_name: &str, password: &str) -> Result<(), String> {
    let key = vpn_password_key_for_profile(profile_name)?;
    let password = VpnPassword::new(password.to_owned()).map_err(|err| err.to_string())?;
    KeyringVpnPasswordVault::new()
        .set_vpn_password(&key, &password)
        .map_err(|err| err.to_string())
}

fn vpn_password_key_for_profile(profile_name: &str) -> Result<VpnPasswordKey, String> {
    let profile = load_vpn_profile(profile_name)?;
    VpnPasswordKey::for_vpn_profile(&profile).map_err(|err| err.to_string())
}

fn load_vpn_profile(profile_name: &str) -> Result<oc_oxide_config::VpnProfile, String> {
    let profile_path = local_profile_path(profile_name)?;
    let content = fs::read_to_string(&profile_path)
        .map_err(|err| format!("failed to read profile {}: {err}", profile_path.display()))?;
    parse_toml_vpn_profile(profile_name, &content)
        .map_err(|err| format!("failed to parse profile {}: {err}", profile_path.display()))
}

fn local_sync_profile_documents() -> Result<Vec<SyncProfileDocument>, String> {
    profiles_from_dir(&local_profile_dir()?)?
        .into_iter()
        .map(|item| sync_profile_document(&load_vpn_profile(&item.name)?))
        .collect()
}

fn sync_profile_document(
    profile: &oc_oxide_config::VpnProfile,
) -> Result<SyncProfileDocument, String> {
    let tunnel = profile.tunnel();
    let mut connection = SyncProfileConnection::anyconnect(
        tunnel.server_url().as_openconnect_url(),
        tunnel.reported_os(),
    )
    .map_err(|err| err.to_string())?;

    if let Some(authgroup) = tunnel.authgroup() {
        connection = connection
            .with_authgroup(authgroup)
            .map_err(|err| err.to_string())?;
    }

    if let Some(username) = tunnel.username() {
        connection = connection
            .with_username(username)
            .map_err(|err| err.to_string())?;
    }

    SyncProfileDocument::new(tunnel.name(), tunnel.name(), connection)
        .and_then(|document| document.with_company_domains(profile.company_domains().to_vec()))
        .and_then(|document| {
            document.with_local_bypass(
                profile
                    .local_bypass_cidrs()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            )
        })
        .map_err(|err| err.to_string())
}

fn render_sync_profile_toml(document: &SyncProfileDocument) -> Result<String, String> {
    document.validate().map_err(|err| err.to_string())?;
    let input = CreateProfileInput {
        name: document.profile_id.clone(),
        server: document.connection.server.clone(),
        reported_os: Some(document.connection.reported_os.clone()),
        username: document.connection.username.clone(),
        authgroup: document.connection.authgroup.clone(),
        company_domains: document.company.domains.clone(),
        local_bypass: document.local.bypass.clone(),
    };
    clean_profile(input.name.clone())?;
    render_profile_toml(&input)
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
        .unwrap_or_else(|| "desktop".to_owned())
}

fn load_github_sync_history() -> Result<GithubSyncHistory, String> {
    let path = github_sync_history_path()?;
    load_github_sync_history_from_path(&path)
}

fn load_github_sync_history_from_path(path: &Path) -> Result<GithubSyncHistory, String> {
    match fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content)
            .map_err(|err| format!("failed to parse sync history {}: {err}", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(GithubSyncHistory::default()),
        Err(err) => Err(format!(
            "failed to read sync history {}: {err}",
            path.display()
        )),
    }
}

fn record_github_sync_history(
    operation: &str,
    outcome: &str,
    status: &GithubSyncStatus,
) -> Result<(), String> {
    let path = github_sync_history_path()?;
    record_github_sync_history_at(&path, operation, outcome, status)
}

fn record_github_sync_history_at(
    path: &Path,
    operation: &str,
    outcome: &str,
    status: &GithubSyncStatus,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create sync history directory {}: {err}",
                parent.display()
            )
        })?;
    }

    let mut history = load_github_sync_history_from_path(path).unwrap_or_default();
    history.entries.insert(
        0,
        GithubSyncHistoryEntry {
            recorded_at: sync_updated_at(),
            operation: clean_history_text(operation),
            outcome: clean_history_text(outcome),
            repository: status.repository.clone(),
            manifest_sha: status.manifest_sha.clone(),
            manifest_bytes: status.manifest_bytes,
            message: clean_history_text(status.message.as_deref().unwrap_or("ok")),
        },
    );
    history.entries.truncate(20);

    let content = serde_json::to_string_pretty(&history)
        .map_err(|err| format!("failed to serialize sync history: {err}"))?;
    fs::write(&path, content)
        .map_err(|err| format!("failed to write sync history {}: {err}", path.display()))
}

fn github_sync_history_path() -> Result<PathBuf, String> {
    Ok(local_config_dir()?.join("sync-history.json"))
}

fn local_config_dir() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os(CONFIG_DIR_ENV).filter(|path| !path.is_empty()) {
        return Ok(PathBuf::from(path));
    }

    env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".config").join("oc-oxide"))
        .ok_or_else(|| "HOME is not set and OC_OXIDE_CONFIG_DIR was not provided".to_owned())
}

fn clean_history_text(value: &str) -> String {
    value
        .chars()
        .filter(|ch| *ch != '\0')
        .take(240)
        .collect::<String>()
}

fn local_profile_path(profile_name: &str) -> Result<PathBuf, String> {
    Ok(local_profile_dir()?.join(format!("{profile_name}.toml")))
}

fn local_profile_toml(profile_name: &str) -> Result<String, String> {
    let path = local_profile_path(profile_name)?;
    fs::read_to_string(&path)
        .map_err(|err| format!("failed to read profile {}: {err}", path.display()))
}

fn duplicate_profile_name(profile_dir: &Path, profile_name: &str) -> String {
    let first = format!("{profile_name}-copy");
    if !profile_dir.join(format!("{first}.toml")).exists() {
        return first;
    }

    for index in 2.. {
        let candidate = format!("{profile_name}-copy-{index}");
        if !profile_dir.join(format!("{candidate}.toml")).exists() {
            return candidate;
        }
    }

    unreachable!("unbounded duplicate profile name search should always return")
}

fn restored_conflict_profile_name(existing: &BTreeSet<String>, profile_name: &str) -> String {
    let first = format!("{profile_name}-remote");
    if !existing.contains(&first) {
        return first;
    }

    for index in 2.. {
        let candidate = format!("{profile_name}-remote-{index}");
        if !existing.contains(&candidate) {
            return candidate;
        }
    }

    unreachable!("unbounded restored profile name search should always return")
}

fn migrate_vpn_password_key(
    old_profile: &oc_oxide_config::VpnProfile,
    new_profile: &oc_oxide_config::VpnProfile,
) -> Result<(), String> {
    let old_key = VpnPasswordKey::for_vpn_profile(old_profile).map_err(|err| err.to_string())?;
    let new_key = VpnPasswordKey::for_vpn_profile(new_profile).map_err(|err| err.to_string())?;
    let vault = KeyringVpnPasswordVault::new();

    if let Some(password) = vault
        .get_vpn_password(&old_key)
        .map_err(|err| err.to_string())?
    {
        vault
            .set_vpn_password(&new_key, &password)
            .map_err(|err| err.to_string())?;
        vault
            .delete_vpn_password(&old_key)
            .map_err(|err| err.to_string())?;
    }

    Ok(())
}

fn local_profile_dir() -> Result<PathBuf, String> {
    env::var_os(PROFILE_DIR_ENV)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("HOME").map(|home| {
                PathBuf::from(home)
                    .join(".config")
                    .join("oc-oxide")
                    .join("profiles")
            })
        })
        .ok_or_else(|| "HOME is not set and OC_OXIDE_PROFILE_DIR was not provided".to_owned())
}

fn clean_profile(profile: String) -> Result<String, String> {
    let profile = profile.trim();
    let valid = !profile.is_empty()
        && profile
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        Ok(profile.to_owned())
    } else {
        Err(format!("invalid profile name {profile:?}"))
    }
}

fn render_profile_toml(input: &CreateProfileInput) -> Result<String, String> {
    let server = clean_required_text("server", &input.server)?;
    let mut output = String::new();

    output.push_str("[connection]\n");
    output.push_str(&format!("server = \"{}\"\n", toml_escape(&server)));
    if let Some(value) = clean_optional_text(input.reported_os.as_deref()) {
        output.push_str(&format!("reported_os = \"{}\"\n", toml_escape(&value)));
    }
    if let Some(value) = clean_optional_text(input.authgroup.as_deref()) {
        output.push_str(&format!("authgroup = \"{}\"\n", toml_escape(&value)));
    }
    if let Some(value) = clean_optional_text(input.username.as_deref()) {
        output.push_str(&format!("username = \"{}\"\n", toml_escape(&value)));
    }

    let company_domains = clean_text_list(&input.company_domains)?;
    if !company_domains.is_empty() {
        output.push_str("\n[company]\n");
        output.push_str(&format!("domains = {}\n", toml_array(&company_domains)));
    }

    let local_bypass = clean_text_list(&input.local_bypass)?;
    if !local_bypass.is_empty() {
        output.push_str("\n[local]\n");
        output.push_str(&format!("bypass = {}\n", toml_array(&local_bypass)));
    }

    Ok(output)
}

fn clean_required_text(field: &'static str, value: &str) -> Result<String, String> {
    clean_optional_text(Some(value)).ok_or_else(|| format!("{field} is required"))
}

fn clean_optional_text(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

fn clean_text_list(values: &[String]) -> Result<Vec<String>, String> {
    values
        .iter()
        .filter_map(|value| clean_optional_text(Some(value)))
        .map(|value| {
            if value.contains('\0') {
                Err("profile values cannot contain NUL bytes".to_owned())
            } else {
                Ok(value)
            }
        })
        .collect()
}

fn toml_array(values: &[String]) -> String {
    let values = values
        .iter()
        .map(|value| format!("\"{}\"", toml_escape(value)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{values}]")
}

fn toml_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect(),
            '\n' => "\\n".chars().collect(),
            '\r' => "\\r".chars().collect(),
            '\t' => "\\t".chars().collect(),
            _ => vec![ch],
        })
        .collect()
}

fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    let status_text = tray_status_text(DaemonState::Idle, None, None);
    let status_item = MenuItemBuilder::with_id(TRAY_STATUS_ITEM_ID, &status_text)
        .enabled(false)
        .build(app)?;
    let show_item = MenuItemBuilder::with_id(TRAY_SHOW_ITEM_ID, "Show oc-oxide").build(app)?;
    let quit_item = MenuItemBuilder::with_id(TRAY_QUIT_ITEM_ID, "Quit oc-oxide").build(app)?;
    let top_separator = PredefinedMenuItem::separator(app)?;
    let bottom_separator = PredefinedMenuItem::separator(app)?;
    let connected_icon = Image::from_bytes(include_bytes!("../icons/32x32.png"))?.to_owned();
    let disconnected_icon =
        Image::from_bytes(include_bytes!("../icons/inactive-32x32.png"))?.to_owned();
    let menu = Menu::with_items(
        app,
        &[
            &status_item,
            &top_separator,
            &show_item,
            &bottom_separator,
            &quit_item,
        ],
    )?;

    let builder = TrayIconBuilder::with_id("main")
        .menu(&menu)
        .icon(disconnected_icon.clone())
        .show_menu_on_left_click(false)
        .tooltip(format!("oc-oxide: {status_text}"))
        .on_menu_event(|app, event| {
            if event.id() == TRAY_SHOW_ITEM_ID {
                show_main_window(app);
            } else if event.id() == TRAY_QUIT_ITEM_ID {
                app.exit(0);
            }
        })
        .on_tray_icon_event(|tray, event| {
            let should_show = match event {
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                }
                | TrayIconEvent::DoubleClick {
                    button: MouseButton::Left,
                    ..
                } => true,
                _ => false,
            };
            if should_show {
                show_main_window(tray.app_handle());
            }
        });

    let icon = builder.build(app)?;
    let state = app.state::<DesktopState>();
    if let Ok(mut guard) = state.tray.lock() {
        *guard = Some(TrayState {
            icon,
            status_item,
            connected_icon,
            disconnected_icon,
            active_profile: None,
            interface: None,
        });
    }

    Ok(())
}

fn show_main_window(app: &AppHandle) {
    let app = app.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        let Some(window) = app
            .get_webview_window(MAIN_WINDOW_LABEL)
            .or_else(|| app.webview_windows().into_values().next())
        else {
            eprintln!("failed to show main window: no webview window is registered");
            return;
        };

        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    });
}

fn update_tray_status_from_status(app: &AppHandle, status: &DaemonStatus) {
    update_tray_status_context(
        app,
        status.state,
        status.active_profile.as_deref(),
        status.interface.as_deref(),
        true,
    );
}

fn update_tray_status_from_event(app: &AppHandle, event: &IpcEvent) {
    match event {
        IpcEvent::AuthPrompt(_) | IpcEvent::AuthRejected { .. } => {
            update_tray_status(app, DaemonState::AwaitingAuth, None, None);
        }
        IpcEvent::Connected { interface } => {
            update_tray_status(app, DaemonState::Connected, None, Some(interface));
        }
        IpcEvent::Disconnecting => {
            update_tray_status(app, DaemonState::Disconnecting, None, None);
        }
        IpcEvent::Disconnected { .. } => {
            update_tray_status(app, DaemonState::Disconnected, None, None);
        }
        IpcEvent::Error(_) => {
            update_tray_status(app, DaemonState::Error, None, None);
        }
        IpcEvent::Progress(_) | IpcEvent::NetworkApplied(_) | IpcEvent::Stats(_) => {}
    }
}

fn update_tray_status(
    app: &AppHandle,
    state: DaemonState,
    profile: Option<&str>,
    interface: Option<&str>,
) {
    update_tray_status_context(app, state, profile, interface, false);
}

fn update_tray_status_context(
    app: &AppHandle,
    state: DaemonState,
    profile: Option<&str>,
    interface: Option<&str>,
    exact_snapshot: bool,
) {
    let desktop_state = app.state::<DesktopState>();
    let Ok(mut guard) = desktop_state.tray.lock() else {
        return;
    };
    let Some(tray) = guard.as_mut() else {
        return;
    };

    if exact_snapshot {
        tray.active_profile = profile.map(str::to_owned);
        tray.interface = interface.map(str::to_owned);
    } else {
        if let Some(profile) = profile {
            tray.active_profile = Some(profile.to_owned());
        }
        if let Some(interface) = interface {
            tray.interface = Some(interface.to_owned());
        }
        if matches!(state, DaemonState::Configuring) {
            tray.interface = None;
        }
        if matches!(state, DaemonState::Idle | DaemonState::Disconnected) {
            tray.active_profile = None;
            tray.interface = None;
        }
    }

    let status_text = tray_status_text(
        state,
        tray.active_profile.as_deref(),
        tray.interface.as_deref(),
    );
    let _ = tray.status_item.set_text(&status_text);
    let _ = tray
        .icon
        .set_tooltip(Some(format!("oc-oxide: {status_text}")));
    let icon = if matches!(state, DaemonState::Connected) {
        tray.connected_icon.clone()
    } else {
        tray.disconnected_icon.clone()
    };
    let _ = tray.icon.set_icon(Some(icon));
}

fn tray_status_text(state: DaemonState, profile: Option<&str>, interface: Option<&str>) -> String {
    let label = match state {
        DaemonState::Idle => "idle",
        DaemonState::Configuring => "configuring",
        DaemonState::AwaitingAuth => "waiting for auth",
        DaemonState::Connecting => "connecting",
        DaemonState::Connected => "connected",
        DaemonState::Disconnecting => "disconnecting",
        DaemonState::Disconnected => "disconnected",
        DaemonState::Error => "error",
    };

    match (profile, interface) {
        (Some(profile), Some(interface)) => format!("Status: {label} ({profile}, {interface})"),
        (Some(profile), None) => format!("Status: {label} ({profile})"),
        (None, Some(interface)) => format!("Status: {label} ({interface})"),
        (None, None) => format!("Status: {label}"),
    }
}

fn main() {
    tauri::Builder::default()
        .manage(DesktopState::default())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_main_window(app);
        }))
        .on_window_event(|window, event| {
            if window.label() == MAIN_WINDOW_LABEL {
                if let WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .setup(|app| {
            if let Err(err) = setup_tray(app.handle()) {
                eprintln!("failed to initialize tray: {err}");
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            daemon_status,
            daemon_diagnostics,
            profiles_list,
            profile_create,
            profile_detail,
            profile_duplicate,
            profile_rename,
            profile_delete,
            profile_save_vpn_password,
            profile_vpn_password_status,
            profile_forget_vpn_password,
            github_sync_history,
            update_check,
            update_prepare,
            update_install,
            update_relaunch,
            open_external_url,
            daemon_handoff_status,
            daemon_handoff_start,
            github_sync_status,
            github_sync_device_flow_start,
            github_sync_device_flow_poll,
            github_sync_init_manifest,
            github_sync_upload_profiles,
            github_sync_download_profiles,
            github_sync_delete_profile,
            daemon_connect,
            daemon_submit_auth,
            daemon_disconnect,
        ])
        .run(tauri::generate_context!())
        .expect("error while running oc-oxide desktop");
}

#[cfg(test)]
mod tests {
    use super::{
        command_output_detail, duplicate_profile_name, github_device_flow_start_result,
        github_release_asset_url, github_sync_status_response, github_sync_upload_error,
        load_github_sync_history_from_path, parse_release_tag, profiles_from_dir,
        record_github_sync_history_at, render_profile_toml, render_sync_profile_toml,
        restored_conflict_profile_name, stored_vpn_password_field, sync_profile_document,
        tray_status_text, update_asset_name, version_is_newer, CreateProfileInput,
        GithubSyncAuthState, GithubSyncManifestState, UpdateInstallMethod,
    };
    use oc_oxide_config::parse_toml_vpn_profile;
    use oc_oxide_ipc::{AuthPrompt, AuthPromptField, AuthPromptFieldKind, DaemonState};
    use oc_oxide_sync::{
        DeviceFlowStart, SyncError, SyncProfileConnection, SyncProfileDocument,
        DEFAULT_GITHUB_TOKEN_ACCOUNT,
    };
    use std::collections::BTreeSet;
    use std::fs;

    #[test]
    fn stored_vpn_password_field_matches_single_password_prompt() {
        let prompt = AuthPrompt {
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
        };

        assert_eq!(
            stored_vpn_password_field(&prompt).map(|field| field.id.as_str()),
            Some("password")
        );
    }

    #[test]
    fn stored_vpn_password_field_rejects_otp_and_mixed_prompts() {
        let otp_prompt = AuthPrompt {
            form_id: "form-2".to_owned(),
            title: "Verification".to_owned(),
            message: None,
            error: None,
            fields: vec![AuthPromptField {
                id: "answer".to_owned(),
                label: "Code".to_owned(),
                kind: AuthPromptFieldKind::Password,
                required: true,
            }],
        };
        assert!(stored_vpn_password_field(&otp_prompt).is_none());

        let mixed_prompt = AuthPrompt {
            form_id: "form-3".to_owned(),
            title: "Login".to_owned(),
            message: None,
            error: None,
            fields: vec![
                AuthPromptField {
                    id: "username".to_owned(),
                    label: "Username".to_owned(),
                    kind: AuthPromptFieldKind::Text { secret: false },
                    required: true,
                },
                AuthPromptField {
                    id: "password".to_owned(),
                    label: "Password".to_owned(),
                    kind: AuthPromptFieldKind::Password,
                    required: true,
                },
            ],
        };
        assert!(stored_vpn_password_field(&mixed_prompt).is_none());
    }

    #[test]
    fn profiles_from_dir_lists_valid_toml_profile_names() {
        let dir =
            std::env::temp_dir().join(format!("oc-oxide-desktop-profiles-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("office.toml"), "").unwrap();
        fs::write(dir.join("lab_1.toml"), "").unwrap();
        fs::write(dir.join("bad.name.toml"), "").unwrap();
        fs::write(dir.join("notes.txt"), "").unwrap();

        let profiles = profiles_from_dir(&dir).unwrap();
        let names = profiles
            .into_iter()
            .map(|profile| profile.name)
            .collect::<Vec<_>>();

        assert_eq!(names, vec!["lab_1", "office"]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn duplicate_profile_name_skips_existing_copies() {
        let dir = std::env::temp_dir().join(format!(
            "oc-oxide-desktop-duplicate-profiles-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("office-copy.toml"), "").unwrap();
        fs::write(dir.join("office-copy-2.toml"), "").unwrap();

        assert_eq!(duplicate_profile_name(&dir, "office"), "office-copy-3");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn restored_conflict_profile_name_uses_remote_suffixes() {
        let existing = ["office", "office-remote", "office-remote-2"]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();

        assert_eq!(
            restored_conflict_profile_name(&existing, "office"),
            "office-remote-3"
        );
    }

    #[test]
    fn render_profile_toml_writes_only_non_secret_profile_config() {
        let input = CreateProfileInput {
            name: "office".to_owned(),
            server: " https://vpn.example.test:555/ ".to_owned(),
            reported_os: Some("linux-64".to_owned()),
            username: Some(" alice ".to_owned()),
            authgroup: Some(" engineering ".to_owned()),
            company_domains: vec!["corp.example.test".to_owned(), " ".to_owned()],
            local_bypass: vec!["198.18.0.0/15".to_owned()],
        };

        let toml = render_profile_toml(&input).unwrap();
        let profile = parse_toml_vpn_profile("office", &toml).unwrap();

        assert!(toml.contains("[connection]"));
        assert!(toml.contains("server = \"https://vpn.example.test:555/\""));
        assert!(toml.contains("username = \"alice\""));
        assert!(toml.contains("authgroup = \"engineering\""));
        assert!(toml.contains("domains = [\"corp.example.test\"]"));
        assert!(toml.contains("bypass = [\"198.18.0.0/15\"]"));
        assert_eq!(profile.tunnel().username(), Some("alice"));
        assert_eq!(profile.tunnel().authgroup(), Some("engineering"));
    }

    #[test]
    fn sync_profile_document_exports_only_non_secret_profile_fields() {
        let input = CreateProfileInput {
            name: "office".to_owned(),
            server: " https://vpn.example.test:555/ ".to_owned(),
            reported_os: Some("linux-64".to_owned()),
            username: Some(" alice ".to_owned()),
            authgroup: Some(" engineering ".to_owned()),
            company_domains: vec!["corp.example.test".to_owned()],
            local_bypass: vec!["198.18.0.0/15".to_owned()],
        };
        let toml = render_profile_toml(&input).unwrap();
        let profile = parse_toml_vpn_profile("office", &toml).unwrap();
        let document = sync_profile_document(&profile).unwrap();

        assert_eq!(document.profile_id, "office");
        assert_eq!(document.display_name, "office");
        assert_eq!(document.connection.server, "https://vpn.example.test:555/");
        assert_eq!(document.connection.reported_os, "linux-64");
        assert_eq!(
            document.connection.authgroup.as_deref(),
            Some("engineering")
        );
        assert_eq!(document.connection.username.as_deref(), Some("alice"));
        assert_eq!(document.company.domains, vec!["corp.example.test"]);
        assert_eq!(document.local.bypass, vec!["198.18.0.0/15"]);

        let encoded = serde_json::to_string(&document).unwrap();
        assert!(!encoded.contains("password"));
        assert!(!encoded.contains("otp"));
    }

    #[test]
    fn render_sync_profile_toml_restores_non_secret_profile_config() {
        let document = SyncProfileDocument::new(
            "office",
            "office",
            SyncProfileConnection::anyconnect("https://vpn.example.test:555/", "linux-64")
                .unwrap()
                .with_username("alice")
                .unwrap()
                .with_authgroup("engineering")
                .unwrap(),
        )
        .unwrap()
        .with_company_domains(["corp.example.test"])
        .unwrap()
        .with_local_bypass(["198.18.0.0/15"])
        .unwrap();

        let toml = render_sync_profile_toml(&document).unwrap();
        let profile = parse_toml_vpn_profile("office", &toml).unwrap();

        assert!(toml.contains("server = \"https://vpn.example.test:555/\""));
        assert!(toml.contains("username = \"alice\""));
        assert!(toml.contains("authgroup = \"engineering\""));
        assert!(toml.contains("domains = [\"corp.example.test\"]"));
        assert!(toml.contains("bypass = [\"198.18.0.0/15\"]"));
        assert!(!toml.contains("password"));
        assert_eq!(profile.tunnel().reported_os(), "linux-64");
    }

    #[test]
    fn github_sync_status_response_uses_public_repo_and_keyring_metadata() {
        let status = github_sync_status_response(
            GithubSyncAuthState::NotAuthorized,
            GithubSyncManifestState::Unknown,
            None,
            None,
            None,
        );

        assert_eq!(status.auth, GithubSyncAuthState::NotAuthorized);
        assert_eq!(status.manifest, GithubSyncManifestState::Unknown);
        assert_eq!(status.repository, "fudanglp/oc-oxide-sync");
        assert_eq!(status.keyring_account, DEFAULT_GITHUB_TOKEN_ACCOUNT);
        assert_eq!(status.manifest_sha, None);
        assert_eq!(status.manifest_bytes, None);
    }

    #[test]
    fn sync_history_records_non_secret_operation_summaries() {
        let dir = std::env::temp_dir().join(format!(
            "oc-oxide-desktop-sync-history-{}",
            std::process::id()
        ));
        let path = dir.join("sync-history.json");
        let _ = fs::remove_dir_all(&dir);

        let status = github_sync_status_response(
            GithubSyncAuthState::Authorized,
            GithubSyncManifestState::Present,
            Some("manifest-sha".to_owned()),
            Some(256),
            Some("uploaded 2 profile(s)\0".to_owned()),
        );
        record_github_sync_history_at(&path, "upload", "success", &status).unwrap();
        record_github_sync_history_at(&path, "restore", "success", &status).unwrap();

        let history = load_github_sync_history_from_path(&path).unwrap();
        assert_eq!(history.entries.len(), 2);
        assert_eq!(history.entries[0].operation, "restore");
        assert_eq!(
            history.entries[0].manifest_sha.as_deref(),
            Some("manifest-sha")
        );
        assert_eq!(history.entries[0].manifest_bytes, Some(256));
        assert!(!history.entries[0].message.contains('\0'));

        let content = fs::read_to_string(&path).unwrap();
        assert!(!content.contains("password"));
        assert!(!content.contains("token"));
        assert!(!content.contains("cookie"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn command_output_detail_prefers_stderr() {
        assert_eq!(
            command_output_detail(b"permission denied\n", b"ignored\n"),
            "permission denied"
        );
    }

    #[test]
    fn command_output_detail_falls_back_to_stdout() {
        assert_eq!(command_output_detail(b"", b"started\n"), "started");
    }

    #[test]
    fn version_compare_handles_tag_prefix_and_patch_versions() {
        assert!(version_is_newer("v0.1.2", "0.1.1"));
        assert!(version_is_newer("0.2.0", "0.1.9"));
        assert!(!version_is_newer("v0.1.1", "0.1.1"));
        assert!(!version_is_newer("0.1.0", "0.1.1"));
    }

    #[test]
    fn update_asset_name_matches_release_packaging_names() {
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(
                update_asset_name("v0.1.2", UpdateInstallMethod::Deb).unwrap(),
                "oc-oxide_0.1.2_amd64.deb"
            );
            assert_eq!(
                update_asset_name("0.1.2", UpdateInstallMethod::Tarball).unwrap(),
                "oc-oxide-0.1.2-linux-x86_64.tar.gz"
            );
        }

        #[cfg(target_arch = "aarch64")]
        {
            assert_eq!(
                update_asset_name("v0.1.2", UpdateInstallMethod::Deb).unwrap(),
                "oc-oxide_0.1.2_arm64.deb"
            );
            assert_eq!(
                update_asset_name("0.1.2", UpdateInstallMethod::Tarball).unwrap(),
                "oc-oxide-0.1.2-linux-aarch64.tar.gz"
            );
        }
    }

    #[test]
    fn update_release_redirect_helpers_avoid_github_api() {
        assert_eq!(
            parse_release_tag("https://github.com/fudanglp/oc-oxide/releases/tag/v0.1.2"),
            Some("v0.1.2".to_owned())
        );
        assert_eq!(
            parse_release_tag("/fudanglp/oc-oxide/releases/tag/v0.1.2?expanded=true"),
            Some("v0.1.2".to_owned())
        );
        assert_eq!(
            github_release_asset_url("fudanglp/oc-oxide", "v0.1.2", "oc-oxide_0.1.2_amd64.deb"),
            "https://github.com/fudanglp/oc-oxide/releases/download/v0.1.2/oc-oxide_0.1.2_amd64.deb"
        );
    }

    #[test]
    fn github_device_flow_start_result_maps_user_visible_fields() {
        let start = DeviceFlowStart::new(
            "device-code",
            "ABCD-1234",
            "https://github.com/login/device",
            900,
            5,
        )
        .unwrap();

        let result = github_device_flow_start_result(start);
        assert_eq!(result.device_code, "device-code");
        assert_eq!(result.user_code, "ABCD-1234");
        assert_eq!(result.verification_uri, "https://github.com/login/device");
        assert_eq!(result.expires_in_secs, 900);
        assert_eq!(result.interval_secs, 5);
    }

    #[test]
    fn github_sync_upload_error_keeps_codec_context() {
        let message = github_sync_upload_error(SyncError::Codec {
            operation: "deserialize manifest",
            detail: "expected value".to_owned(),
        });

        assert!(message.contains("deserialize manifest"));
        assert!(message.contains("expected value"));
    }

    #[test]
    fn github_sync_upload_error_explains_conflict_recovery() {
        let message = github_sync_upload_error(SyncError::Conflict {
            path: oc_oxide_sync::SyncObjectPath::manifest(),
            expected: Some("old".to_owned()),
            actual: Some("new".to_owned()),
        });

        assert!(message.contains("remote sync object changed"));
        assert!(message.contains("restore remote profiles"));
        assert!(message.contains("retry upload"));
    }

    #[test]
    fn tray_status_text_includes_non_secret_context() {
        assert_eq!(
            tray_status_text(DaemonState::Connected, Some("office"), Some("tun0")),
            "Status: connected (office, tun0)"
        );
        assert_eq!(
            tray_status_text(DaemonState::AwaitingAuth, Some("office"), None),
            "Status: waiting for auth (office)"
        );
        assert_eq!(
            tray_status_text(DaemonState::Disconnected, None, None),
            "Status: disconnected"
        );
    }
}
