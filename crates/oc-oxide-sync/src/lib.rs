//! GitHub-backed profile synchronization model.
//!
//! This crate defines the no-network core used by future GitHub profile sync:
//! public GitHub App configuration, application object paths, manifest metadata,
//! conflict semantics, and an injectable backend boundary.

use std::collections::BTreeMap;
use std::fmt;

use base64::Engine;
use serde::{Deserialize, Serialize};

/// Human-readable crate role used by workspace smoke tests.
pub const CRATE_ROLE: &str = "GitHub private repo profile synchronization";

pub const DEFAULT_GITHUB_APP_OWNER: &str = "fudanglp";
pub const DEFAULT_GITHUB_APP_ID: u64 = 4_125_299;
pub const DEFAULT_GITHUB_APP_CLIENT_ID: &str = "Iv23lioGMVnzQNiz9AE5";
pub const DEFAULT_GITHUB_APP_HOMEPAGE: &str = "https://oc-oxide.glp.ai";
pub const DEFAULT_GITHUB_APP_PRIVACY: &str = "https://oc-oxide.glp.ai/privacy.html";

pub const DEFAULT_SYNC_REPO_OWNER: &str = "fudanglp";
pub const DEFAULT_SYNC_REPO_NAME: &str = "oc-oxide-sync";
pub const DEFAULT_SYNC_REPO_BRANCH: &str = "master";
pub const GITHUB_TOKEN_SERVICE: &str = "oc-oxide.github";
pub const DEFAULT_GITHUB_TOKEN_ACCOUNT: &str = "fudanglp:oc-oxide-sync";

pub const SYNC_FORMAT: &str = "oc-oxide-sync";
pub const SYNC_VERSION: u32 = 1;
pub const SYNC_PROFILE_SCHEMA_VERSION: u32 = 1;
pub const SYNC_TOMBSTONE_SCHEMA_VERSION: u32 = 1;

/// Public GitHub App identifiers needed by device flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubAppConfig {
    pub owner: String,
    pub app_id: u64,
    pub client_id: String,
    pub homepage: String,
    pub privacy: String,
}

impl GithubAppConfig {
    pub fn oc_oxide_sync() -> Self {
        Self {
            owner: DEFAULT_GITHUB_APP_OWNER.to_owned(),
            app_id: DEFAULT_GITHUB_APP_ID,
            client_id: DEFAULT_GITHUB_APP_CLIENT_ID.to_owned(),
            homepage: DEFAULT_GITHUB_APP_HOMEPAGE.to_owned(),
            privacy: DEFAULT_GITHUB_APP_PRIVACY.to_owned(),
        }
    }

    pub fn validate(&self) -> Result<(), SyncError> {
        if self.app_id == 0 {
            return Err(SyncError::InvalidAppId);
        }

        clean_text("owner", &self.owner)?;
        clean_text("client ID", &self.client_id)?;
        clean_https_url("homepage", &self.homepage)?;
        clean_https_url("privacy URL", &self.privacy)?;

        Ok(())
    }
}

/// Selected GitHub repository for sync objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncRepository {
    pub owner: String,
    pub name: String,
    pub default_branch: String,
}

impl SyncRepository {
    pub fn oc_oxide_sync() -> Self {
        Self {
            owner: DEFAULT_SYNC_REPO_OWNER.to_owned(),
            name: DEFAULT_SYNC_REPO_NAME.to_owned(),
            default_branch: DEFAULT_SYNC_REPO_BRANCH.to_owned(),
        }
    }

    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }

    pub fn html_url(&self) -> String {
        format!("https://github.com/{}", self.full_name())
    }

    pub fn validate(&self) -> Result<(), SyncError> {
        clean_repo_part("owner", &self.owner)?;
        clean_repo_part("name", &self.name)?;
        clean_repo_part("default branch", &self.default_branch)?;
        Ok(())
    }
}

/// GitHub Device Flow start response shown to the user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceFlowStart {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in_secs: u64,
    pub interval_secs: u64,
}

impl DeviceFlowStart {
    pub fn new(
        device_code: impl Into<String>,
        user_code: impl Into<String>,
        verification_uri: impl Into<String>,
        expires_in_secs: u64,
        interval_secs: u64,
    ) -> Result<Self, SyncError> {
        let start = Self {
            device_code: clean_text_owned("device code", device_code.into())?,
            user_code: clean_text_owned("user code", user_code.into())?,
            verification_uri: clean_text_owned("verification URI", verification_uri.into())?,
            expires_in_secs,
            interval_secs,
        };
        start.validate()?;
        Ok(start)
    }

    pub fn validate(&self) -> Result<(), SyncError> {
        clean_text("device code", &self.device_code)?;
        clean_text("user code", &self.user_code)?;
        if !self.verification_uri.starts_with("https://") {
            return Err(SyncError::InvalidDeviceFlow {
                detail: "verification URI must be HTTPS".to_owned(),
            });
        }

        if self.expires_in_secs == 0 {
            return Err(SyncError::InvalidDeviceFlow {
                detail: "device code expiry must be non-zero".to_owned(),
            });
        }

        if self.interval_secs == 0 {
            return Err(SyncError::InvalidDeviceFlow {
                detail: "poll interval must be non-zero".to_owned(),
            });
        }

        Ok(())
    }
}

/// Device Flow polling state derived from GitHub responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceFlowPoll {
    Pending { interval_secs: u64 },
    SlowDown { interval_secs: u64 },
    Authorized(DeviceFlowTokenSet),
    AccessDenied,
    Expired,
}

impl DeviceFlowPoll {
    pub fn from_success(
        token_type: impl Into<String>,
        scope: impl Into<String>,
        access_token: impl Into<String>,
        refresh_token: impl Into<String>,
        expires_in_secs: u64,
        refresh_token_expires_in_secs: u64,
    ) -> Result<Self, SyncError> {
        Ok(Self::Authorized(DeviceFlowTokenSet::new(
            token_type,
            scope,
            access_token,
            refresh_token,
            expires_in_secs,
            refresh_token_expires_in_secs,
        )?))
    }

    pub fn from_error(
        error: DeviceFlowErrorCode,
        current_interval_secs: u64,
    ) -> Result<Self, SyncError> {
        if current_interval_secs == 0 {
            return Err(SyncError::InvalidDeviceFlow {
                detail: "current poll interval must be non-zero".to_owned(),
            });
        }

        Ok(match error {
            DeviceFlowErrorCode::AuthorizationPending => Self::Pending {
                interval_secs: current_interval_secs,
            },
            DeviceFlowErrorCode::SlowDown => Self::SlowDown {
                interval_secs: current_interval_secs.saturating_add(5),
            },
            DeviceFlowErrorCode::AccessDenied => Self::AccessDenied,
            DeviceFlowErrorCode::ExpiredToken => Self::Expired,
        })
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Authorized(_) | Self::AccessDenied | Self::Expired
        )
    }
}

/// GitHub Device Flow polling error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceFlowErrorCode {
    AuthorizationPending,
    SlowDown,
    AccessDenied,
    ExpiredToken,
}

/// Access token kept in memory and redacted from debug output.
#[derive(Clone, PartialEq, Eq)]
pub struct GithubAccessToken(String);

impl GithubAccessToken {
    pub fn new(value: impl Into<String>) -> Result<Self, SyncError> {
        Ok(Self(clean_text_owned("GitHub access token", value.into())?))
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GithubAccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GithubAccessToken(<redacted>)")
    }
}

/// Refresh token stored in an OS keyring backend and redacted from debug output.
#[derive(Clone, PartialEq, Eq)]
pub struct GithubRefreshToken(String);

impl GithubRefreshToken {
    pub fn new(value: impl Into<String>) -> Result<Self, SyncError> {
        Ok(Self(clean_text_owned(
            "GitHub refresh token",
            value.into(),
        )?))
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GithubRefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GithubRefreshToken(<redacted>)")
    }
}

/// Successful GitHub App Device Flow token response.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceFlowTokenSet {
    pub token_type: String,
    pub scope: String,
    pub access_token: GithubAccessToken,
    pub refresh_token: GithubRefreshToken,
    pub expires_in_secs: u64,
    pub refresh_token_expires_in_secs: u64,
}

impl DeviceFlowTokenSet {
    pub fn new(
        token_type: impl Into<String>,
        scope: impl Into<String>,
        access_token: impl Into<String>,
        refresh_token: impl Into<String>,
        expires_in_secs: u64,
        refresh_token_expires_in_secs: u64,
    ) -> Result<Self, SyncError> {
        let token_type = clean_text_owned("token type", token_type.into())?;
        if !token_type.eq_ignore_ascii_case("bearer") {
            return Err(SyncError::InvalidDeviceFlow {
                detail: format!("unsupported token type {token_type}"),
            });
        }

        if expires_in_secs == 0 || refresh_token_expires_in_secs == 0 {
            return Err(SyncError::InvalidDeviceFlow {
                detail: "token expiry values must be non-zero".to_owned(),
            });
        }

        Ok(Self {
            token_type,
            scope: clean_token_scope(scope.into())?,
            access_token: GithubAccessToken::new(access_token)?,
            refresh_token: GithubRefreshToken::new(refresh_token)?,
            expires_in_secs,
            refresh_token_expires_in_secs,
        })
    }
}

impl fmt::Debug for DeviceFlowTokenSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceFlowTokenSet")
            .field("token_type", &self.token_type)
            .field("scope", &self.scope)
            .field("access_token", &self.access_token)
            .field("refresh_token", &self.refresh_token)
            .field("expires_in_secs", &self.expires_in_secs)
            .field(
                "refresh_token_expires_in_secs",
                &self.refresh_token_expires_in_secs,
            )
            .finish()
    }
}

/// HTTP boundary for GitHub App Device Flow.
pub trait GithubDeviceFlowHttp {
    fn start_device_flow(&mut self, client_id: &str) -> Result<DeviceFlowStart, SyncError>;
    fn poll_device_flow(
        &mut self,
        client_id: &str,
        device_code: &str,
        current_interval_secs: u64,
    ) -> Result<DeviceFlowPoll, SyncError>;
}

/// HTTP boundary for refreshing expiring GitHub App user access tokens.
pub trait GithubTokenRefreshHttp {
    fn refresh_user_access_token(
        &mut self,
        client_id: &str,
        refresh_token: &GithubRefreshToken,
    ) -> Result<DeviceFlowTokenSet, SyncError>;
}

/// Poll once and return the next interval plus the GitHub outcome.
pub fn poll_device_flow_once<H>(
    http: &mut H,
    client_id: &str,
    device_code: &str,
    current_interval_secs: u64,
) -> Result<DeviceFlowStep, SyncError>
where
    H: GithubDeviceFlowHttp,
{
    clean_text("client ID", client_id)?;
    clean_text("device code", device_code)?;
    if current_interval_secs == 0 {
        return Err(SyncError::InvalidDeviceFlow {
            detail: "current poll interval must be non-zero".to_owned(),
        });
    }

    let poll = http.poll_device_flow(client_id, device_code, current_interval_secs)?;
    let next_interval_secs = match &poll {
        DeviceFlowPoll::Pending { interval_secs } | DeviceFlowPoll::SlowDown { interval_secs } => {
            *interval_secs
        }
        DeviceFlowPoll::Authorized(_) | DeviceFlowPoll::AccessDenied | DeviceFlowPoll::Expired => {
            current_interval_secs
        }
    };

    Ok(DeviceFlowStep {
        poll,
        next_interval_secs,
    })
}

pub fn refresh_github_user_access_token<H>(
    http: &mut H,
    client_id: &str,
    refresh_token: &GithubRefreshToken,
) -> Result<DeviceFlowTokenSet, SyncError>
where
    H: GithubTokenRefreshHttp,
{
    clean_text("client ID", client_id)?;
    http.refresh_user_access_token(client_id, refresh_token)
}

pub fn decode_device_flow_start_response(body: &str) -> Result<DeviceFlowStart, SyncError> {
    let response: GithubDeviceFlowStartResponse =
        serde_json::from_str(body).map_err(device_flow_json_error)?;
    if let Some(error) = response.error {
        return Err(device_flow_remote_error(
            "GitHub returned device flow start error",
            &error,
        ));
    }

    DeviceFlowStart::new(
        required_device_flow_field("device_code", response.device_code)?,
        required_device_flow_field("user_code", response.user_code)?,
        required_device_flow_field("verification_uri", response.verification_uri)?,
        required_device_flow_field("expires_in", response.expires_in)?,
        required_device_flow_field("interval", response.interval)?,
    )
}

pub fn decode_device_flow_poll_response(
    body: &str,
    current_interval_secs: u64,
) -> Result<DeviceFlowPoll, SyncError> {
    if current_interval_secs == 0 {
        return Err(SyncError::InvalidDeviceFlow {
            detail: "current poll interval must be non-zero".to_owned(),
        });
    }

    let response: GithubDeviceFlowPollResponse =
        serde_json::from_str(body).map_err(device_flow_json_error)?;
    if let Some(error) = response.error {
        let error = parse_device_flow_error_code(&error)?;
        return DeviceFlowPoll::from_error(error, current_interval_secs);
    }

    Ok(DeviceFlowPoll::Authorized(token_set_from_response(
        response,
    )?))
}

pub fn decode_github_token_refresh_response(body: &str) -> Result<DeviceFlowTokenSet, SyncError> {
    let response: GithubDeviceFlowPollResponse =
        serde_json::from_str(body).map_err(device_flow_json_error)?;
    if let Some(error) = response.error {
        return Err(device_flow_remote_error(
            "GitHub returned token refresh error",
            &error,
        ));
    }

    token_set_from_response(response)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceFlowStep {
    pub poll: DeviceFlowPoll,
    pub next_interval_secs: u64,
}

/// Scripted no-network Device Flow backend for tests.
#[derive(Debug, Clone)]
pub struct ScriptedDeviceFlowHttp {
    start: DeviceFlowStart,
    polls: Vec<DeviceFlowPoll>,
    started: bool,
}

impl ScriptedDeviceFlowHttp {
    pub fn new(start: DeviceFlowStart, polls: Vec<DeviceFlowPoll>) -> Self {
        Self {
            start,
            polls,
            started: false,
        }
    }

    pub fn remaining_polls(&self) -> usize {
        self.polls.len()
    }
}

impl GithubDeviceFlowHttp for ScriptedDeviceFlowHttp {
    fn start_device_flow(&mut self, client_id: &str) -> Result<DeviceFlowStart, SyncError> {
        clean_text("client ID", client_id)?;
        self.started = true;
        Ok(self.start.clone())
    }

    fn poll_device_flow(
        &mut self,
        client_id: &str,
        device_code: &str,
        current_interval_secs: u64,
    ) -> Result<DeviceFlowPoll, SyncError> {
        clean_text("client ID", client_id)?;
        clean_text("device code", device_code)?;
        if current_interval_secs == 0 {
            return Err(SyncError::InvalidDeviceFlow {
                detail: "current poll interval must be non-zero".to_owned(),
            });
        }

        if !self.started {
            return Err(SyncError::Backend {
                operation: "scripted device flow poll",
                detail: "device flow has not been started".to_owned(),
            });
        }

        if self.start.device_code != device_code {
            return Err(SyncError::Backend {
                operation: "scripted device flow poll",
                detail: "unexpected device code".to_owned(),
            });
        }

        if self.polls.is_empty() {
            return Err(SyncError::Backend {
                operation: "scripted device flow poll",
                detail: "script exhausted".to_owned(),
            });
        }

        Ok(self.polls.remove(0))
    }
}

#[derive(Debug, Deserialize)]
struct GithubDeviceFlowStartResponse {
    device_code: Option<String>,
    user_code: Option<String>,
    verification_uri: Option<String>,
    expires_in: Option<u64>,
    interval: Option<u64>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GithubDeviceFlowPollResponse {
    access_token: Option<String>,
    token_type: Option<String>,
    scope: Option<String>,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    refresh_token_expires_in: Option<u64>,
    error: Option<String>,
}

fn token_set_from_response(
    response: GithubDeviceFlowPollResponse,
) -> Result<DeviceFlowTokenSet, SyncError> {
    DeviceFlowTokenSet::new(
        required_device_flow_field("token_type", response.token_type)?,
        response.scope.unwrap_or_default(),
        required_device_flow_field("access_token", response.access_token)?,
        required_device_flow_field("refresh_token", response.refresh_token)?,
        required_device_flow_field("expires_in", response.expires_in)?,
        required_device_flow_field(
            "refresh_token_expires_in",
            response.refresh_token_expires_in,
        )?,
    )
}

/// Application object path in the sync repository.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SyncObjectPath(String);

impl SyncObjectPath {
    pub fn manifest() -> Self {
        Self("manifest.json".to_owned())
    }

    pub fn profile(profile_id: impl Into<String>) -> Result<Self, SyncError> {
        let profile_id = clean_profile_id(profile_id.into())?;
        Ok(Self(format!("profiles/{profile_id}.json")))
    }

    pub fn deleted_profile(profile_id: impl Into<String>) -> Result<Self, SyncError> {
        let profile_id = clean_profile_id(profile_id.into())?;
        Ok(Self(format!("deleted/{profile_id}.json")))
    }

    pub fn application_path(path: impl Into<String>) -> Result<Self, SyncError> {
        let path = path.into();
        validate_application_path(&path)?;
        Ok(Self(path))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SyncObjectPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SyncObjectPath").field(&self.0).finish()
    }
}

impl fmt::Display for SyncObjectPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Local decoded manifest. Its repository representation is stored in the
/// selected private GitHub repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncManifest {
    pub format: String,
    pub version: u32,
    pub storage: SyncStorage,
    #[serde(default)]
    pub profiles: BTreeMap<String, SyncProfileEntry>,
}

impl SyncManifest {
    pub fn new() -> Self {
        Self {
            format: SYNC_FORMAT.to_owned(),
            version: SYNC_VERSION,
            storage: SyncStorage::GithubPrivateRepo,
            profiles: BTreeMap::new(),
        }
    }

    pub fn add_profile(&mut self, entry: SyncProfileEntry) -> Result<(), SyncError> {
        clean_profile_id(entry.profile_id.clone())?;
        if entry.path != SyncObjectPath::profile(&entry.profile_id)? {
            return Err(SyncError::InvalidManifest {
                detail: "profile entry path does not match profile id".to_owned(),
            });
        }

        self.profiles.insert(entry.profile_id.clone(), entry);
        Ok(())
    }

    pub fn remove_profile(
        &mut self,
        profile_id: &str,
    ) -> Result<Option<SyncProfileEntry>, SyncError> {
        let profile_id = clean_profile_id(profile_id.to_owned())?;
        Ok(self.profiles.remove(&profile_id))
    }

    pub fn validate(&self) -> Result<(), SyncError> {
        if self.format != SYNC_FORMAT {
            return Err(SyncError::InvalidManifest {
                detail: format!("unsupported format {}", self.format),
            });
        }

        if self.version != SYNC_VERSION {
            return Err(SyncError::InvalidManifest {
                detail: format!("unsupported version {}", self.version),
            });
        }

        if self.storage != SyncStorage::GithubPrivateRepo {
            return Err(SyncError::InvalidManifest {
                detail: "sync storage must be github-private-repo".to_owned(),
            });
        }

        for (key, entry) in &self.profiles {
            if key != &entry.profile_id {
                return Err(SyncError::InvalidManifest {
                    detail: "profile map key does not match profile id".to_owned(),
                });
            }

            clean_profile_id(entry.profile_id.clone())?;
            validate_application_path(entry.path.as_str())?;

            if entry.path != SyncObjectPath::profile(&entry.profile_id)? {
                return Err(SyncError::InvalidManifest {
                    detail: "profile entry path does not match profile id".to_owned(),
                });
            }
        }

        Ok(())
    }
}

impl Default for SyncManifest {
    fn default() -> Self {
        Self::new()
    }
}

/// Repository storage mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SyncStorage {
    GithubPrivateRepo,
}

/// One profile listed by the decoded manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncProfileEntry {
    pub profile_id: String,
    pub path: SyncObjectPath,
    pub revision: String,
    pub updated_at: String,
    pub updated_by_device: String,
}

impl SyncProfileEntry {
    pub fn new(
        profile_id: impl Into<String>,
        revision: impl Into<String>,
        updated_at: impl Into<String>,
        updated_by_device: impl Into<String>,
    ) -> Result<Self, SyncError> {
        let profile_id = clean_profile_id(profile_id.into())?;
        Ok(Self {
            path: SyncObjectPath::profile(&profile_id)?,
            profile_id,
            revision: clean_text_owned("revision", revision.into())?,
            updated_at: clean_text_owned("updated_at", updated_at.into())?,
            updated_by_device: clean_text_owned("updated_by_device", updated_by_device.into())?,
        })
    }
}

/// Stable non-secret profile document encoded before encryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncProfileDocument {
    pub schema_version: u32,
    pub profile_id: String,
    pub display_name: String,
    pub connection: SyncProfileConnection,
    #[serde(default)]
    pub company: SyncProfileCompany,
    #[serde(default)]
    pub local: SyncProfileLocal,
}

impl SyncProfileDocument {
    pub fn new(
        profile_id: impl Into<String>,
        display_name: impl Into<String>,
        connection: SyncProfileConnection,
    ) -> Result<Self, SyncError> {
        let document = Self {
            schema_version: SYNC_PROFILE_SCHEMA_VERSION,
            profile_id: clean_profile_id(profile_id.into())?,
            display_name: clean_text_owned("display name", display_name.into())?,
            connection,
            company: SyncProfileCompany::default(),
            local: SyncProfileLocal::default(),
        };
        document.validate()?;
        Ok(document)
    }

    pub fn with_company_domains<I, S>(mut self, domains: I) -> Result<Self, SyncError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.company.domains = domains
            .into_iter()
            .map(|domain| clean_domain(domain.into()))
            .collect::<Result<Vec<_>, _>>()?;
        self.validate()?;
        Ok(self)
    }

    pub fn with_local_bypass<I, S>(mut self, cidrs: I) -> Result<Self, SyncError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.local.bypass = cidrs
            .into_iter()
            .map(|cidr| clean_cidr_text(cidr.into()))
            .collect::<Result<Vec<_>, _>>()?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), SyncError> {
        if self.schema_version != SYNC_PROFILE_SCHEMA_VERSION {
            return Err(SyncError::InvalidProfileDocument {
                detail: format!("unsupported schema version {}", self.schema_version),
            });
        }

        clean_profile_id(self.profile_id.clone())?;
        clean_text("display name", &self.display_name)?;
        self.connection.validate()?;

        for domain in &self.company.domains {
            clean_domain(domain.clone())?;
        }

        for cidr in &self.local.bypass {
            clean_cidr_text(cidr.clone())?;
        }

        Ok(())
    }
}

/// Non-secret connection fields suitable for profile sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncProfileConnection {
    pub server: String,
    pub protocol: String,
    pub reported_os: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authgroup: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

impl SyncProfileConnection {
    pub fn anyconnect(
        server: impl Into<String>,
        reported_os: impl Into<String>,
    ) -> Result<Self, SyncError> {
        let connection = Self {
            server: server.into(),
            protocol: "anyconnect".to_owned(),
            reported_os: reported_os.into(),
            authgroup: None,
            username: None,
        };
        connection.validate()?;
        Ok(connection)
    }

    pub fn with_authgroup(mut self, authgroup: impl Into<String>) -> Result<Self, SyncError> {
        self.authgroup = Some(clean_text_owned("authgroup", authgroup.into())?);
        self.validate()?;
        Ok(self)
    }

    pub fn with_username(mut self, username: impl Into<String>) -> Result<Self, SyncError> {
        self.username = Some(clean_text_owned("username", username.into())?);
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), SyncError> {
        clean_https_url("server", &self.server)?;
        if self.protocol != "anyconnect" {
            return Err(SyncError::InvalidProfileDocument {
                detail: format!("unsupported protocol {}", self.protocol),
            });
        }

        clean_text("reported OS", &self.reported_os)?;

        if let Some(authgroup) = &self.authgroup {
            clean_text("authgroup", authgroup)?;
        }

        if let Some(username) = &self.username {
            clean_text("username", username)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncProfileCompany {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncProfileLocal {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bypass: Vec<String>,
}

/// Non-secret deletion tombstone stored under `deleted/<profile-id>.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncDeletedProfileDocument {
    pub schema_version: u32,
    pub profile_id: String,
    pub deleted_at: String,
    pub deleted_by_device: String,
}

impl SyncDeletedProfileDocument {
    pub fn new(
        profile_id: impl Into<String>,
        deleted_at: impl Into<String>,
        deleted_by_device: impl Into<String>,
    ) -> Result<Self, SyncError> {
        let document = Self {
            schema_version: SYNC_TOMBSTONE_SCHEMA_VERSION,
            profile_id: clean_profile_id(profile_id.into())?,
            deleted_at: clean_text_owned("deleted_at", deleted_at.into())?,
            deleted_by_device: clean_text_owned("deleted_by_device", deleted_by_device.into())?,
        };
        document.validate()?;
        Ok(document)
    }

    pub fn validate(&self) -> Result<(), SyncError> {
        if self.schema_version != SYNC_TOMBSTONE_SCHEMA_VERSION {
            return Err(SyncError::InvalidProfileDocument {
                detail: format!(
                    "unsupported tombstone schema version {}",
                    self.schema_version
                ),
            });
        }

        clean_profile_id(self.profile_id.clone())?;
        clean_text("deleted_at", &self.deleted_at)?;
        clean_text("deleted_by_device", &self.deleted_by_device)?;
        Ok(())
    }
}

/// Encodes and decodes profile documents as repository sync blobs.
pub trait ProfileSyncCodec {
    fn encode_profile(
        &self,
        document: &SyncProfileDocument,
    ) -> Result<EncryptedSyncBlob, SyncError>;
    fn decode_profile(&self, blob: &EncryptedSyncBlob) -> Result<SyncProfileDocument, SyncError>;
}

/// Encodes and decodes profile deletion tombstones.
pub trait DeletedProfileSyncCodec {
    fn encode_deleted_profile(
        &self,
        document: &SyncDeletedProfileDocument,
    ) -> Result<EncryptedSyncBlob, SyncError>;
    fn decode_deleted_profile(
        &self,
        blob: &EncryptedSyncBlob,
    ) -> Result<SyncDeletedProfileDocument, SyncError>;
}

/// Encodes and decodes the manifest object.
pub trait ManifestSyncCodec {
    fn encode_manifest(&self, manifest: &SyncManifest) -> Result<EncryptedSyncBlob, SyncError>;
    fn decode_manifest(&self, blob: &EncryptedSyncBlob) -> Result<SyncManifest, SyncError>;
}

/// Production codec for sync objects stored in the user's private GitHub repo.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct PrivateRepoSyncCodec;

impl PrivateRepoSyncCodec {
    pub fn new() -> Self {
        Self
    }

    fn encode_json<T>(&self, value: &T, operation: &'static str) -> Result<Vec<u8>, SyncError>
    where
        T: Serialize,
    {
        serde_json::to_vec_pretty(value).map_err(codec_error(operation))
    }

    fn decode_json<T>(
        &self,
        blob: &EncryptedSyncBlob,
        operation: &'static str,
    ) -> Result<T, SyncError>
    where
        T: for<'de> Deserialize<'de>,
    {
        validate_application_path(blob.path().as_str())?;
        serde_json::from_slice(blob.bytes()).map_err(codec_error(operation))
    }
}

impl fmt::Debug for PrivateRepoSyncCodec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateRepoSyncCodec")
    }
}

impl ManifestSyncCodec for PrivateRepoSyncCodec {
    fn encode_manifest(&self, manifest: &SyncManifest) -> Result<EncryptedSyncBlob, SyncError> {
        manifest.validate()?;
        EncryptedSyncBlob::new(
            SyncObjectPath::manifest(),
            self.encode_json(manifest, "serialize manifest")?,
        )
    }

    fn decode_manifest(&self, blob: &EncryptedSyncBlob) -> Result<SyncManifest, SyncError> {
        if blob.path() != &SyncObjectPath::manifest() {
            return Err(SyncError::InvalidManifest {
                detail: "manifest blob path must be manifest.json".to_owned(),
            });
        }

        let manifest: SyncManifest = self.decode_json(blob, "deserialize manifest")?;
        manifest.validate()?;
        Ok(manifest)
    }
}

impl ProfileSyncCodec for PrivateRepoSyncCodec {
    fn encode_profile(
        &self,
        document: &SyncProfileDocument,
    ) -> Result<EncryptedSyncBlob, SyncError> {
        document.validate()?;
        EncryptedSyncBlob::new(
            SyncObjectPath::profile(&document.profile_id)?,
            self.encode_json(document, "serialize profile")?,
        )
    }

    fn decode_profile(&self, blob: &EncryptedSyncBlob) -> Result<SyncProfileDocument, SyncError> {
        let document: SyncProfileDocument = self.decode_json(blob, "deserialize profile")?;
        document.validate()?;

        if blob.path() != &SyncObjectPath::profile(&document.profile_id)? {
            return Err(SyncError::InvalidProfileDocument {
                detail: "profile blob path does not match profile id".to_owned(),
            });
        }

        Ok(document)
    }
}

impl DeletedProfileSyncCodec for PrivateRepoSyncCodec {
    fn encode_deleted_profile(
        &self,
        document: &SyncDeletedProfileDocument,
    ) -> Result<EncryptedSyncBlob, SyncError> {
        document.validate()?;
        EncryptedSyncBlob::new(
            SyncObjectPath::deleted_profile(&document.profile_id)?,
            self.encode_json(document, "serialize deleted profile")?,
        )
    }

    fn decode_deleted_profile(
        &self,
        blob: &EncryptedSyncBlob,
    ) -> Result<SyncDeletedProfileDocument, SyncError> {
        let document: SyncDeletedProfileDocument =
            self.decode_json(blob, "deserialize deleted profile")?;
        document.validate()?;

        if blob.path() != &SyncObjectPath::deleted_profile(&document.profile_id)? {
            return Err(SyncError::InvalidProfileDocument {
                detail: "deleted profile blob path does not match profile id".to_owned(),
            });
        }

        Ok(document)
    }
}

/// Test codec that proves the sync boundary without selecting a production
/// encryption provider. Do not use this for real sync.
#[derive(Debug, Default, Clone, Copy)]
pub struct FakeEncryptedProfileCodec;

impl FakeEncryptedProfileCodec {
    const PREFIX: &'static [u8] = b"oc-oxide-test-encrypted:";

    pub fn new() -> Self {
        Self
    }
}

impl ProfileSyncCodec for FakeEncryptedProfileCodec {
    fn encode_profile(
        &self,
        document: &SyncProfileDocument,
    ) -> Result<EncryptedSyncBlob, SyncError> {
        document.validate()?;
        let mut bytes = Self::PREFIX.to_vec();
        bytes.extend(serde_json::to_vec(document).map_err(codec_error("serialize profile"))?);
        EncryptedSyncBlob::new(SyncObjectPath::profile(&document.profile_id)?, bytes)
    }

    fn decode_profile(&self, blob: &EncryptedSyncBlob) -> Result<SyncProfileDocument, SyncError> {
        validate_application_path(blob.path().as_str())?;
        let Some(payload) = blob.bytes().strip_prefix(Self::PREFIX) else {
            return Err(SyncError::Codec {
                operation: "decrypt profile",
                detail: "unsupported test ciphertext prefix".to_owned(),
            });
        };

        let document: SyncProfileDocument =
            serde_json::from_slice(payload).map_err(codec_error("deserialize profile"))?;
        document.validate()?;

        if blob.path() != &SyncObjectPath::profile(&document.profile_id)? {
            return Err(SyncError::InvalidProfileDocument {
                detail: "profile blob path does not match profile id".to_owned(),
            });
        }

        Ok(document)
    }
}

/// Encrypted bytes ready for repository storage.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedSyncBlob {
    path: SyncObjectPath,
    bytes: Vec<u8>,
}

impl EncryptedSyncBlob {
    pub fn new(path: SyncObjectPath, bytes: impl Into<Vec<u8>>) -> Result<Self, SyncError> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(SyncError::EmptyBlob { path });
        }

        Ok(Self { path, bytes })
    }

    pub fn path(&self) -> &SyncObjectPath {
        &self.path
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl fmt::Debug for EncryptedSyncBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedSyncBlob")
            .field("path", &self.path)
            .field(
                "bytes",
                &format_args!("<{} sync object bytes>", self.bytes.len()),
            )
            .finish()
    }
}

/// Object returned by a remote sync backend.
#[derive(Clone, PartialEq, Eq)]
pub struct RemoteSyncObject {
    pub path: SyncObjectPath,
    pub sha: String,
    bytes: Vec<u8>,
}

impl RemoteSyncObject {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for RemoteSyncObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteSyncObject")
            .field("path", &self.path)
            .field("sha", &self.sha)
            .field(
                "bytes",
                &format_args!("<{} sync object bytes>", self.bytes.len()),
            )
            .finish()
    }
}

/// Write request with optimistic concurrency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncWrite {
    pub blob: EncryptedSyncBlob,
    pub expected_sha: Option<String>,
    pub commit_message: String,
}

impl SyncWrite {
    pub fn create(
        blob: EncryptedSyncBlob,
        commit_message: impl Into<String>,
    ) -> Result<Self, SyncError> {
        Ok(Self {
            blob,
            expected_sha: None,
            commit_message: clean_text_owned("commit message", commit_message.into())?,
        })
    }

    pub fn update(
        blob: EncryptedSyncBlob,
        expected_sha: impl Into<String>,
        commit_message: impl Into<String>,
    ) -> Result<Self, SyncError> {
        Ok(Self {
            blob,
            expected_sha: Some(clean_text_owned("expected sha", expected_sha.into())?),
            commit_message: clean_text_owned("commit message", commit_message.into())?,
        })
    }
}

/// Backend boundary for GitHub Contents API or tests.
pub trait SyncClient {
    fn read_object(&self, path: &SyncObjectPath) -> Result<Option<RemoteSyncObject>, SyncError>;
    fn write_object(&mut self, write: SyncWrite) -> Result<RemoteSyncObject, SyncError>;
    fn delete_object(
        &mut self,
        path: &SyncObjectPath,
        expected_sha: &str,
        commit_message: &str,
    ) -> Result<(), SyncError>;
}

/// Result of uploading local profile documents into sync storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileUploadReport {
    pub uploaded_profiles: usize,
    pub manifest_profile_count: usize,
    pub manifest_sha: String,
    pub manifest_bytes: usize,
}

/// Result of downloading remote profile documents from sync storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileDownloadReport {
    pub profiles: Vec<SyncProfileDocument>,
    pub manifest_profile_count: usize,
    pub manifest_sha: String,
    pub manifest_bytes: usize,
}

/// Result of deleting a remote profile and writing a tombstone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileDeleteReport {
    pub profile_id: String,
    pub removed_from_manifest: bool,
    pub deleted_profile_object: bool,
    pub tombstone_sha: String,
    pub manifest_sha: String,
    pub manifest_bytes: usize,
    pub manifest_profile_count: usize,
}

/// Upload profile documents and update the manifest.
pub fn upload_profile_documents<C, K>(
    client: &mut C,
    codec: &K,
    documents: &[SyncProfileDocument],
    updated_at: &str,
    updated_by_device: &str,
) -> Result<ProfileUploadReport, SyncError>
where
    C: SyncClient,
    K: ManifestSyncCodec + ProfileSyncCodec,
{
    clean_text("updated_at", updated_at)?;
    clean_text("updated_by_device", updated_by_device)?;

    if documents.is_empty() {
        return Err(SyncError::InvalidProfileDocument {
            detail: "at least one profile is required for upload".to_owned(),
        });
    }

    let manifest_path = SyncObjectPath::manifest();
    let manifest_object =
        client
            .read_object(&manifest_path)?
            .ok_or_else(|| SyncError::NotFound {
                path: manifest_path.clone(),
            })?;
    let manifest_blob =
        EncryptedSyncBlob::new(manifest_path.clone(), manifest_object.bytes().to_vec())?;
    let mut manifest = codec.decode_manifest(&manifest_blob)?;

    for document in documents {
        document.validate()?;
        let profile_blob = codec.encode_profile(document)?;
        let profile_path = profile_blob.path().clone();
        let current_profile = client.read_object(&profile_path)?;
        let write = match current_profile {
            Some(object) => {
                SyncWrite::update(profile_blob, object.sha, "Update oc-oxide sync profile")?
            }
            None => SyncWrite::create(profile_blob, "Create oc-oxide sync profile")?,
        };
        let written = client.write_object(write)?;
        let tombstone_path = SyncObjectPath::deleted_profile(&document.profile_id)?;
        if let Some(tombstone) = client.read_object(&tombstone_path)? {
            client.delete_object(
                &tombstone_path,
                &tombstone.sha,
                "Delete oc-oxide sync profile tombstone",
            )?;
        }
        manifest.add_profile(SyncProfileEntry::new(
            document.profile_id.clone(),
            written.sha,
            updated_at.to_owned(),
            updated_by_device.to_owned(),
        )?)?;
    }

    let manifest_blob = codec.encode_manifest(&manifest)?;
    let manifest_bytes = manifest_blob.bytes().len();
    let written_manifest = client.write_object(SyncWrite::update(
        manifest_blob,
        manifest_object.sha,
        "Update oc-oxide sync manifest",
    )?)?;

    Ok(ProfileUploadReport {
        uploaded_profiles: documents.len(),
        manifest_profile_count: manifest.profiles.len(),
        manifest_sha: written_manifest.sha,
        manifest_bytes,
    })
}

/// Remove a profile from the remote manifest, write a deletion tombstone, and
/// best-effort delete the old profile object when present.
pub fn delete_profile_document<C, K>(
    client: &mut C,
    codec: &K,
    profile_id: &str,
    deleted_at: &str,
    deleted_by_device: &str,
) -> Result<ProfileDeleteReport, SyncError>
where
    C: SyncClient,
    K: ManifestSyncCodec + DeletedProfileSyncCodec,
{
    let profile_id = clean_profile_id(profile_id.to_owned())?;
    clean_text("deleted_at", deleted_at)?;
    clean_text("deleted_by_device", deleted_by_device)?;

    let manifest_path = SyncObjectPath::manifest();
    let manifest_object =
        client
            .read_object(&manifest_path)?
            .ok_or_else(|| SyncError::NotFound {
                path: manifest_path.clone(),
            })?;
    let manifest_blob =
        EncryptedSyncBlob::new(manifest_path.clone(), manifest_object.bytes().to_vec())?;
    let mut manifest = codec.decode_manifest(&manifest_blob)?;
    let removed_from_manifest = manifest.remove_profile(&profile_id)?.is_some();

    let manifest_blob = codec.encode_manifest(&manifest)?;
    let manifest_bytes = manifest_blob.bytes().len();
    let written_manifest = if removed_from_manifest {
        client.write_object(SyncWrite::update(
            manifest_blob,
            manifest_object.sha,
            "Remove oc-oxide sync profile from manifest",
        )?)?
    } else {
        manifest_object
    };

    let tombstone = SyncDeletedProfileDocument::new(
        profile_id.clone(),
        deleted_at.to_owned(),
        deleted_by_device.to_owned(),
    )?;
    let tombstone_blob = codec.encode_deleted_profile(&tombstone)?;
    let tombstone_path = tombstone_blob.path().clone();
    let current_tombstone = client.read_object(&tombstone_path)?;
    let tombstone_write = match current_tombstone {
        Some(object) => SyncWrite::update(
            tombstone_blob,
            object.sha,
            "Update oc-oxide sync profile tombstone",
        )?,
        None => SyncWrite::create(tombstone_blob, "Create oc-oxide sync profile tombstone")?,
    };
    let written_tombstone = client.write_object(tombstone_write)?;

    let profile_path = SyncObjectPath::profile(&profile_id)?;
    let deleted_profile_object = match client.read_object(&profile_path)? {
        Some(object) => {
            client.delete_object(
                &profile_path,
                &object.sha,
                "Delete oc-oxide sync profile object",
            )?;
            true
        }
        None => false,
    };

    Ok(ProfileDeleteReport {
        profile_id,
        removed_from_manifest,
        deleted_profile_object,
        tombstone_sha: written_tombstone.sha,
        manifest_sha: written_manifest.sha,
        manifest_bytes,
        manifest_profile_count: manifest.profiles.len(),
    })
}

/// Download profile documents listed in the remote manifest.
pub fn download_profile_documents<C, K>(
    client: &C,
    codec: &K,
) -> Result<ProfileDownloadReport, SyncError>
where
    C: SyncClient,
    K: ManifestSyncCodec + ProfileSyncCodec,
{
    let manifest_path = SyncObjectPath::manifest();
    let manifest_object =
        client
            .read_object(&manifest_path)?
            .ok_or_else(|| SyncError::NotFound {
                path: manifest_path.clone(),
            })?;
    let manifest_blob =
        EncryptedSyncBlob::new(manifest_path.clone(), manifest_object.bytes().to_vec())?;
    let manifest = codec.decode_manifest(&manifest_blob)?;
    let mut profiles = Vec::with_capacity(manifest.profiles.len());

    for entry in manifest.profiles.values() {
        let profile_object =
            client
                .read_object(&entry.path)?
                .ok_or_else(|| SyncError::NotFound {
                    path: entry.path.clone(),
                })?;
        let profile_blob =
            EncryptedSyncBlob::new(entry.path.clone(), profile_object.bytes().to_vec())?;
        profiles.push(codec.decode_profile(&profile_blob)?);
    }

    let manifest_bytes = manifest_object.bytes().len();
    Ok(ProfileDownloadReport {
        profiles,
        manifest_profile_count: manifest.profiles.len(),
        manifest_sha: manifest_object.sha,
        manifest_bytes,
    })
}

/// Minimal HTTP transport boundary for the GitHub Contents API.
pub trait GithubContentsHttp {
    fn send_contents_request(
        &self,
        token: &GithubAccessToken,
        request: &GithubContentsRequest,
    ) -> Result<GithubContentsResponse, SyncError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GithubContentsMethod {
    Get,
    Put,
    Delete,
}

#[derive(Clone, PartialEq, Eq)]
pub struct GithubContentsRequest {
    pub method: GithubContentsMethod,
    pub api_path: String,
    body: Option<String>,
}

impl GithubContentsRequest {
    pub fn new(
        method: GithubContentsMethod,
        api_path: impl Into<String>,
        body: Option<String>,
    ) -> Result<Self, SyncError> {
        Ok(Self {
            method,
            api_path: clean_text_owned("GitHub API path", api_path.into())?,
            body,
        })
    }

    pub fn body(&self) -> Option<&str> {
        self.body.as_deref()
    }
}

impl fmt::Debug for GithubContentsRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("GithubContentsRequest");
        debug
            .field("method", &self.method)
            .field("api_path", &self.api_path);
        match &self.body {
            Some(body) => debug.field("body", &format_args!("<{} request bytes>", body.len())),
            None => debug.field("body", &Option::<String>::None),
        };
        debug.finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubContentsResponse {
    pub status: u16,
    pub body: String,
}

impl GithubContentsResponse {
    pub fn new(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
        }
    }
}

/// GitHub Contents API implementation of the sync client boundary.
#[derive(Debug, Clone)]
pub struct GithubContentsClient<H> {
    repository: SyncRepository,
    branch: String,
    token: GithubAccessToken,
    http: H,
}

impl<H> GithubContentsClient<H>
where
    H: GithubContentsHttp,
{
    pub fn new(
        repository: SyncRepository,
        branch: impl Into<String>,
        token: GithubAccessToken,
        http: H,
    ) -> Result<Self, SyncError> {
        repository.validate()?;
        Ok(Self {
            repository,
            branch: clean_text_owned("GitHub branch", branch.into())?,
            token,
            http,
        })
    }

    pub fn oc_oxide_sync(token: GithubAccessToken, http: H) -> Result<Self, SyncError> {
        Self::new(
            SyncRepository::oc_oxide_sync(),
            DEFAULT_SYNC_REPO_BRANCH,
            token,
            http,
        )
    }

    pub fn http(&self) -> &H {
        &self.http
    }

    fn request(
        &self,
        method: GithubContentsMethod,
        path: &SyncObjectPath,
        body: Option<String>,
    ) -> Result<GithubContentsRequest, SyncError> {
        let mut api_path = format!(
            "/repos/{}/{}/contents/{}",
            encode_uri_path_part(&self.repository.owner),
            encode_uri_path_part(&self.repository.name),
            encode_sync_object_path(path.as_str())
        );
        if method == GithubContentsMethod::Get {
            api_path.push_str("?ref=");
            api_path.push_str(&encode_uri_query_value(&self.branch));
        }

        GithubContentsRequest::new(method, api_path, body)
    }
}

impl<H> SyncClient for GithubContentsClient<H>
where
    H: GithubContentsHttp,
{
    fn read_object(&self, path: &SyncObjectPath) -> Result<Option<RemoteSyncObject>, SyncError> {
        let request = self.request(GithubContentsMethod::Get, path, None)?;
        let response = self.http.send_contents_request(&self.token, &request)?;
        match response.status {
            200 => {
                let file = decode_contents_read_response(&response.body)?;
                if let Some(response_path) = file.path.as_deref() {
                    if response_path != path.as_str() {
                        return Err(SyncError::Backend {
                            operation: "read GitHub contents object",
                            detail: "GitHub returned a different content path".to_owned(),
                        });
                    }
                }

                let bytes = decode_github_base64_content(&file.content)?;
                if bytes.is_empty() {
                    return Err(SyncError::EmptyBlob { path: path.clone() });
                }

                Ok(Some(RemoteSyncObject {
                    path: path.clone(),
                    sha: clean_text_owned("GitHub content sha", file.sha)?,
                    bytes,
                }))
            }
            404 => Ok(None),
            401 | 403 => Err(github_http_status_error(
                "read GitHub contents object",
                response.status,
            )),
            status => Err(github_http_status_error(
                "read GitHub contents object",
                status,
            )),
        }
    }

    fn write_object(&mut self, write: SyncWrite) -> Result<RemoteSyncObject, SyncError> {
        let path = write.blob.path().clone();
        let bytes = write.blob.bytes().to_vec();
        let body = encode_contents_write_body(&write, &self.branch)?;
        let request = self.request(GithubContentsMethod::Put, &path, Some(body))?;
        let response = self.http.send_contents_request(&self.token, &request)?;
        match response.status {
            200 | 201 => {
                let file = decode_contents_write_response(&response.body)?;
                Ok(RemoteSyncObject {
                    path,
                    sha: clean_text_owned("GitHub content sha", file.content.sha)?,
                    bytes,
                })
            }
            409 | 422 => Err(SyncError::Conflict {
                path,
                expected: write.expected_sha,
                actual: None,
            }),
            401 | 403 => Err(github_http_status_error(
                "write GitHub contents object",
                response.status,
            )),
            status => Err(github_http_status_error(
                "write GitHub contents object",
                status,
            )),
        }
    }

    fn delete_object(
        &mut self,
        path: &SyncObjectPath,
        expected_sha: &str,
        commit_message: &str,
    ) -> Result<(), SyncError> {
        clean_text("expected sha", expected_sha)?;
        clean_text("commit message", commit_message)?;

        let body = encode_contents_delete_body(expected_sha, commit_message, &self.branch)?;
        let request = self.request(GithubContentsMethod::Delete, path, Some(body))?;
        let response = self.http.send_contents_request(&self.token, &request)?;
        match response.status {
            200 | 204 => Ok(()),
            404 => Err(SyncError::NotFound { path: path.clone() }),
            409 | 422 => Err(SyncError::Conflict {
                path: path.clone(),
                expected: Some(expected_sha.to_owned()),
                actual: None,
            }),
            401 | 403 => Err(github_http_status_error(
                "delete GitHub contents object",
                response.status,
            )),
            status => Err(github_http_status_error(
                "delete GitHub contents object",
                status,
            )),
        }
    }
}

#[derive(Debug, Deserialize)]
struct GithubContentsReadResponse {
    path: Option<String>,
    sha: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct GithubContentsWriteResponse {
    content: GithubContentsWriteContent,
}

#[derive(Debug, Deserialize)]
struct GithubContentsWriteContent {
    sha: String,
}

#[derive(Debug, Serialize)]
struct GithubContentsWriteBody<'a> {
    message: &'a str,
    content: String,
    branch: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct GithubContentsDeleteBody<'a> {
    message: &'a str,
    sha: &'a str,
    branch: &'a str,
}

/// Refresh-token storage boundary. Production code should use an OS keyring.
pub trait GithubTokenVault {
    fn get_refresh_token(&self, account: &str) -> Result<Option<GithubRefreshToken>, SyncError>;
    fn set_refresh_token(
        &mut self,
        account: &str,
        token: &GithubRefreshToken,
    ) -> Result<(), SyncError>;
    fn delete_refresh_token(&mut self, account: &str) -> Result<bool, SyncError>;
}

/// No-side-effect token vault for tests.
#[derive(Debug, Default)]
pub struct InMemoryGithubTokenVault {
    entries: BTreeMap<String, GithubRefreshToken>,
}

impl InMemoryGithubTokenVault {
    pub fn new() -> Self {
        Self::default()
    }
}

impl GithubTokenVault for InMemoryGithubTokenVault {
    fn get_refresh_token(&self, account: &str) -> Result<Option<GithubRefreshToken>, SyncError> {
        let account = clean_token_account(account)?;
        Ok(self.entries.get(account).cloned())
    }

    fn set_refresh_token(
        &mut self,
        account: &str,
        token: &GithubRefreshToken,
    ) -> Result<(), SyncError> {
        let account = clean_token_account(account)?.to_owned();
        self.entries.insert(account, token.clone());
        Ok(())
    }

    fn delete_refresh_token(&mut self, account: &str) -> Result<bool, SyncError> {
        let account = clean_token_account(account)?;
        Ok(self.entries.remove(account).is_some())
    }
}

/// System keyring-backed GitHub refresh-token vault.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyringGithubTokenVault;

impl KeyringGithubTokenVault {
    pub fn new() -> Self {
        Self
    }

    fn entry(account: &str) -> Result<keyring::Entry, SyncError> {
        let account = clean_token_account(account)?;
        keyring::Entry::new(GITHUB_TOKEN_SERVICE, account).map_err(keyring_error("keyring entry"))
    }
}

impl GithubTokenVault for KeyringGithubTokenVault {
    fn get_refresh_token(&self, account: &str) -> Result<Option<GithubRefreshToken>, SyncError> {
        match Self::entry(account)?.get_password() {
            Ok(token) => Ok(Some(GithubRefreshToken::new(token)?)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(keyring_error("keyring get")(err)),
        }
    }

    fn set_refresh_token(
        &mut self,
        account: &str,
        token: &GithubRefreshToken,
    ) -> Result<(), SyncError> {
        Self::entry(account)?
            .set_password(token.expose_secret())
            .map_err(keyring_error("keyring set"))
    }

    fn delete_refresh_token(&mut self, account: &str) -> Result<bool, SyncError> {
        match Self::entry(account)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(err) => Err(keyring_error("keyring delete")(err)),
        }
    }
}

/// No-network backend for tests and model smoke checks.
#[derive(Debug, Default)]
pub struct InMemorySyncClient {
    objects: BTreeMap<SyncObjectPath, RemoteSyncObject>,
    next_sha: u64,
}

impl InMemorySyncClient {
    pub fn new() -> Self {
        Self::default()
    }

    fn allocate_sha(&mut self) -> String {
        self.next_sha += 1;
        format!("mem-sha-{}", self.next_sha)
    }
}

impl SyncClient for InMemorySyncClient {
    fn read_object(&self, path: &SyncObjectPath) -> Result<Option<RemoteSyncObject>, SyncError> {
        Ok(self.objects.get(path).cloned())
    }

    fn write_object(&mut self, write: SyncWrite) -> Result<RemoteSyncObject, SyncError> {
        let path = write.blob.path().clone();
        let current_sha = self.objects.get(&path).map(|object| object.sha.clone());

        match (&write.expected_sha, current_sha.as_deref()) {
            (None, Some(actual)) => {
                return Err(SyncError::Conflict {
                    path,
                    expected: None,
                    actual: Some(actual.to_owned()),
                });
            }
            (Some(expected), Some(actual)) if expected != actual => {
                return Err(SyncError::Conflict {
                    path,
                    expected: Some(expected.clone()),
                    actual: Some(actual.to_owned()),
                });
            }
            (Some(expected), None) => {
                return Err(SyncError::Conflict {
                    path,
                    expected: Some(expected.clone()),
                    actual: None,
                });
            }
            _ => {}
        }

        let object = RemoteSyncObject {
            path: path.clone(),
            sha: self.allocate_sha(),
            bytes: write.blob.into_bytes(),
        };
        self.objects.insert(path, object.clone());
        Ok(object)
    }

    fn delete_object(
        &mut self,
        path: &SyncObjectPath,
        expected_sha: &str,
        commit_message: &str,
    ) -> Result<(), SyncError> {
        clean_text("expected sha", expected_sha)?;
        clean_text("commit message", commit_message)?;

        let Some(current) = self.objects.get(path) else {
            return Err(SyncError::NotFound { path: path.clone() });
        };

        if current.sha != expected_sha {
            return Err(SyncError::Conflict {
                path: path.clone(),
                expected: Some(expected_sha.to_owned()),
                actual: Some(current.sha.clone()),
            });
        }

        self.objects.remove(path);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncError {
    EmptyField {
        field: &'static str,
    },
    InteriorNul {
        field: &'static str,
    },
    InvalidAppId,
    InvalidHttpsUrl {
        field: &'static str,
        value: String,
    },
    InvalidPath {
        path: String,
        reason: &'static str,
    },
    InvalidManifest {
        detail: String,
    },
    InvalidProfileDocument {
        detail: String,
    },
    InvalidDeviceFlow {
        detail: String,
    },
    EmptyBlob {
        path: SyncObjectPath,
    },
    Conflict {
        path: SyncObjectPath,
        expected: Option<String>,
        actual: Option<String>,
    },
    NotFound {
        path: SyncObjectPath,
    },
    Backend {
        operation: &'static str,
        detail: String,
    },
    Codec {
        operation: &'static str,
        detail: String,
    },
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField { field } => write!(f, "{field} is empty"),
            Self::InteriorNul { field } => write!(f, "{field} contains an interior NUL"),
            Self::InvalidAppId => f.write_str("GitHub App ID must be non-zero"),
            Self::InvalidHttpsUrl { field, .. } => write!(f, "{field} must be an HTTPS URL"),
            Self::InvalidPath { path, reason } => write!(f, "invalid sync path {path}: {reason}"),
            Self::InvalidManifest { detail } => write!(f, "invalid sync manifest: {detail}"),
            Self::InvalidProfileDocument { detail } => {
                write!(f, "invalid sync profile document: {detail}")
            }
            Self::InvalidDeviceFlow { detail } => {
                write!(f, "invalid GitHub Device Flow response: {detail}")
            }
            Self::EmptyBlob { path } => write!(f, "sync object blob is empty: {path}"),
            Self::Conflict { path, .. } => write!(f, "sync conflict for {path}"),
            Self::NotFound { path } => write!(f, "sync object not found: {path}"),
            Self::Backend { operation, detail } => {
                write!(f, "sync backend failed during {operation}: {detail}")
            }
            Self::Codec { operation, detail } => {
                write!(f, "sync codec failed during {operation}: {detail}")
            }
        }
    }
}

impl std::error::Error for SyncError {}

fn required_device_flow_field<T>(field: &'static str, value: Option<T>) -> Result<T, SyncError> {
    value.ok_or_else(|| SyncError::InvalidDeviceFlow {
        detail: format!("missing {field}"),
    })
}

fn parse_device_flow_error_code(value: &str) -> Result<DeviceFlowErrorCode, SyncError> {
    match value {
        "authorization_pending" => Ok(DeviceFlowErrorCode::AuthorizationPending),
        "slow_down" => Ok(DeviceFlowErrorCode::SlowDown),
        "access_denied" => Ok(DeviceFlowErrorCode::AccessDenied),
        "expired_token" | "token_expired" => Ok(DeviceFlowErrorCode::ExpiredToken),
        _ => Err(device_flow_remote_error(
            "GitHub returned unsupported device flow error",
            value,
        )),
    }
}

fn device_flow_remote_error(prefix: &str, error: &str) -> SyncError {
    SyncError::InvalidDeviceFlow {
        detail: format!("{prefix}: {}", sanitized_device_flow_error(error)),
    }
}

fn sanitized_device_flow_error(error: &str) -> String {
    error
        .chars()
        .filter(|ch| ch.is_ascii_lowercase() || *ch == '_')
        .take(64)
        .collect::<String>()
}

fn device_flow_json_error(err: serde_json::Error) -> SyncError {
    SyncError::InvalidDeviceFlow {
        detail: format!("invalid GitHub JSON response: {err}"),
    }
}

fn keyring_error(operation: &'static str) -> impl FnOnce(keyring::Error) -> SyncError {
    move |err| SyncError::Backend {
        operation,
        detail: err.to_string(),
    }
}

fn encode_contents_write_body(write: &SyncWrite, branch: &str) -> Result<String, SyncError> {
    let body = GithubContentsWriteBody {
        message: &write.commit_message,
        content: base64::engine::general_purpose::STANDARD.encode(write.blob.bytes()),
        branch,
        sha: write.expected_sha.as_deref(),
    };
    serde_json::to_string(&body).map_err(github_contents_json_error("encode GitHub write body"))
}

fn encode_contents_delete_body(
    expected_sha: &str,
    commit_message: &str,
    branch: &str,
) -> Result<String, SyncError> {
    let body = GithubContentsDeleteBody {
        message: commit_message,
        sha: expected_sha,
        branch,
    };
    serde_json::to_string(&body).map_err(github_contents_json_error("encode GitHub delete body"))
}

fn decode_contents_read_response(body: &str) -> Result<GithubContentsReadResponse, SyncError> {
    serde_json::from_str(body).map_err(github_contents_json_error("decode GitHub read response"))
}

fn decode_contents_write_response(body: &str) -> Result<GithubContentsWriteResponse, SyncError> {
    serde_json::from_str(body).map_err(github_contents_json_error("decode GitHub write response"))
}

fn decode_github_base64_content(content: &str) -> Result<Vec<u8>, SyncError> {
    let content = content
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>();
    base64::engine::general_purpose::STANDARD
        .decode(content)
        .map_err(|err| SyncError::Backend {
            operation: "decode GitHub content",
            detail: err.to_string(),
        })
}

fn github_contents_json_error(
    operation: &'static str,
) -> impl FnOnce(serde_json::Error) -> SyncError {
    move |err| SyncError::Backend {
        operation,
        detail: err.to_string(),
    }
}

fn github_http_status_error(operation: &'static str, status: u16) -> SyncError {
    SyncError::Backend {
        operation,
        detail: format!("GitHub returned HTTP {status}"),
    }
}

fn encode_sync_object_path(path: &str) -> String {
    path.split('/')
        .map(encode_uri_path_part)
        .collect::<Vec<_>>()
        .join("/")
}

fn encode_uri_path_part(value: &str) -> String {
    encode_uri_component(value, false)
}

fn encode_uri_query_value(value: &str) -> String {
    encode_uri_component(value, true)
}

fn encode_uri_component(value: &str, space_as_plus: bool) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            b' ' if space_as_plus => encoded.push('+'),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn clean_text_owned(field: &'static str, value: String) -> Result<String, SyncError> {
    Ok(clean_text(field, &value)?.to_owned())
}

fn clean_text<'a>(field: &'static str, value: &'a str) -> Result<&'a str, SyncError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(SyncError::EmptyField { field });
    }

    if value.contains('\0') {
        return Err(SyncError::InteriorNul { field });
    }

    Ok(value)
}

fn clean_https_url(field: &'static str, value: &str) -> Result<(), SyncError> {
    let value = clean_text(field, value)?;
    if !value.starts_with("https://") {
        return Err(SyncError::InvalidHttpsUrl {
            field,
            value: value.to_owned(),
        });
    }

    Ok(())
}

fn clean_repo_part(field: &'static str, value: &str) -> Result<(), SyncError> {
    let value = clean_text(field, value)?;
    if value.contains('/') || value.contains('\\') {
        return Err(SyncError::InvalidPath {
            path: value.to_owned(),
            reason: "repository identifiers must not contain path separators",
        });
    }

    Ok(())
}

fn clean_profile_id(value: String) -> Result<String, SyncError> {
    let value = clean_text_owned("profile id", value)?;
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        Ok(value)
    } else {
        Err(SyncError::InvalidPath {
            path: value,
            reason: "profile id may only contain ASCII letters, digits, '-' and '_'",
        })
    }
}

fn validate_application_path(path: &str) -> Result<(), SyncError> {
    let path = clean_text("path", path)?;
    if path.starts_with('/') {
        return Err(SyncError::InvalidPath {
            path: path.to_owned(),
            reason: "path must be relative",
        });
    }

    if !path.ends_with(".json") {
        return Err(SyncError::InvalidPath {
            path: path.to_owned(),
            reason: "application sync objects must be JSON files",
        });
    }

    for part in path.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(SyncError::InvalidPath {
                path: path.to_owned(),
                reason: "path contains an invalid component",
            });
        }

        if part.contains('\\') || part.contains('\0') {
            return Err(SyncError::InvalidPath {
                path: path.to_owned(),
                reason: "path contains an invalid character",
            });
        }
    }

    Ok(())
}

fn clean_domain(value: String) -> Result<String, SyncError> {
    let value = clean_text_owned("company domain", value)?;
    if value.contains('/') || value.contains('\\') || value.contains(':') {
        return Err(SyncError::InvalidProfileDocument {
            detail: format!("invalid company domain {value}"),
        });
    }

    Ok(value)
}

fn clean_cidr_text(value: String) -> Result<String, SyncError> {
    let value = clean_text_owned("local bypass CIDR", value)?;
    if value.contains('\\') {
        return Err(SyncError::InvalidProfileDocument {
            detail: format!("invalid local bypass CIDR {value}"),
        });
    }

    let mut parts = value.split('/');
    let Some(addr) = parts.next() else {
        return Err(SyncError::InvalidProfileDocument {
            detail: "missing CIDR address".to_owned(),
        });
    };
    let Some(prefix) = parts.next() else {
        return Err(SyncError::InvalidProfileDocument {
            detail: "missing CIDR prefix".to_owned(),
        });
    };
    if parts.next().is_some() || addr.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(SyncError::InvalidProfileDocument {
            detail: format!("invalid local bypass CIDR {value}"),
        });
    }

    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| SyncError::InvalidProfileDocument {
            detail: format!("invalid local bypass CIDR {value}"),
        })?;
    if prefix > 32 {
        return Err(SyncError::InvalidProfileDocument {
            detail: format!("invalid local bypass CIDR {value}"),
        });
    }

    Ok(value)
}

fn clean_token_account(value: &str) -> Result<&str, SyncError> {
    let value = clean_text("GitHub token account", value)?;
    if value.contains('\0') || value.contains('/') || value.contains('\\') {
        return Err(SyncError::InvalidDeviceFlow {
            detail: "GitHub token account contains an invalid character".to_owned(),
        });
    }

    Ok(value)
}

fn clean_token_scope(value: String) -> Result<String, SyncError> {
    let value = value.trim();
    if value.contains('\0') {
        return Err(SyncError::InteriorNul { field: "scope" });
    }

    Ok(value.to_owned())
}

fn codec_error(operation: &'static str) -> impl FnOnce(serde_json::Error) -> SyncError {
    move |err| SyncError::Codec {
        operation,
        detail: err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_device_flow_poll_response, decode_device_flow_start_response,
        decode_github_token_refresh_response, refresh_github_user_access_token,
        DeletedProfileSyncCodec, DeviceFlowErrorCode, DeviceFlowPoll, DeviceFlowStart,
        DeviceFlowTokenSet, EncryptedSyncBlob, FakeEncryptedProfileCodec, GithubAccessToken,
        GithubAppConfig, GithubContentsClient, GithubContentsHttp, GithubContentsMethod,
        GithubContentsRequest, GithubContentsResponse, GithubDeviceFlowHttp, GithubRefreshToken,
        GithubTokenRefreshHttp, GithubTokenVault, InMemoryGithubTokenVault, InMemorySyncClient,
        ManifestSyncCodec, PrivateRepoSyncCodec, ProfileSyncCodec, ScriptedDeviceFlowHttp,
        SyncClient, SyncDeletedProfileDocument, SyncError, SyncManifest, SyncObjectPath,
        SyncProfileConnection, SyncProfileDocument, SyncProfileEntry, SyncRepository, SyncWrite,
        CRATE_ROLE, DEFAULT_GITHUB_APP_CLIENT_ID, DEFAULT_GITHUB_TOKEN_ACCOUNT,
        GITHUB_TOKEN_SERVICE, SYNC_FORMAT,
    };
    use base64::Engine;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Debug)]
    struct ScriptedContentsHttp {
        responses: Mutex<VecDeque<GithubContentsResponse>>,
        requests: Mutex<Vec<GithubContentsRequest>>,
    }

    impl ScriptedContentsHttp {
        fn new(responses: Vec<GithubContentsResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<GithubContentsRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl GithubContentsHttp for ScriptedContentsHttp {
        fn send_contents_request(
            &self,
            token: &GithubAccessToken,
            request: &GithubContentsRequest,
        ) -> Result<GithubContentsResponse, SyncError> {
            assert_eq!(token.expose_secret(), "alpha-redaction-marker");
            self.requests.lock().unwrap().push(request.clone());
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| SyncError::Backend {
                    operation: "scripted GitHub contents request",
                    detail: "script exhausted".to_owned(),
                })
        }
    }

    #[test]
    fn documents_sync_role_and_public_github_app_config() {
        assert!(CRATE_ROLE.contains("sync"));

        let app = GithubAppConfig::oc_oxide_sync();
        app.validate().unwrap();
        assert_eq!(app.app_id, 4_125_299);
        assert_eq!(app.client_id, DEFAULT_GITHUB_APP_CLIENT_ID);
        assert_eq!(app.homepage, "https://oc-oxide.glp.ai");

        let repo = SyncRepository::oc_oxide_sync();
        repo.validate().unwrap();
        assert_eq!(repo.full_name(), "fudanglp/oc-oxide-sync");
        assert_eq!(repo.html_url(), "https://github.com/fudanglp/oc-oxide-sync");
        assert_eq!(GITHUB_TOKEN_SERVICE, "oc-oxide.github");
        assert_eq!(DEFAULT_GITHUB_TOKEN_ACCOUNT, "fudanglp:oc-oxide-sync");
    }

    #[test]
    fn only_constructs_application_paths() {
        assert_eq!(SyncObjectPath::manifest().as_str(), "manifest.json");
        assert_eq!(
            SyncObjectPath::profile("office").unwrap().as_str(),
            "profiles/office.json"
        );
        assert_eq!(
            SyncObjectPath::deleted_profile("office").unwrap().as_str(),
            "deleted/office.json"
        );

        assert!(SyncObjectPath::application_path("profiles/office.toml").is_err());
        assert!(SyncObjectPath::application_path("../office.json").is_err());
        assert!(SyncObjectPath::profile("office/prod").is_err());
    }

    #[test]
    fn manifest_lists_profiles_in_private_repo_storage() {
        let mut manifest = SyncManifest::new();
        manifest
            .add_profile(
                SyncProfileEntry::new("office", "rev-1", "2026-06-23T15:00:00Z", "thinkpad")
                    .unwrap(),
            )
            .unwrap();

        manifest.validate().unwrap();
        assert_eq!(
            manifest.profiles["office"].path,
            SyncObjectPath::profile("office").unwrap()
        );

        let encoded = serde_json::to_string(&manifest).unwrap();
        assert!(encoded.contains("github-private-repo"));
        assert!(!encoded.contains("password"));

        let mut invalid = manifest.clone();
        invalid.profiles.insert(
            "other".to_owned(),
            invalid.profiles.get("office").unwrap().clone(),
        );
        assert!(matches!(
            invalid.validate(),
            Err(SyncError::InvalidManifest { .. })
        ));
    }

    #[test]
    fn sync_blob_debug_redacts_bytes() {
        let blob =
            EncryptedSyncBlob::new(SyncObjectPath::profile("office").unwrap(), b"ciphertext")
                .unwrap();

        let debug = format!("{blob:?}");
        assert!(debug.contains("sync object bytes"));
        assert!(!debug.contains("ciphertext"));

        assert!(EncryptedSyncBlob::new(SyncObjectPath::manifest(), Vec::<u8>::new()).is_err());
    }

    #[test]
    fn device_flow_start_validates_user_visible_login_fields() {
        let start = DeviceFlowStart::new(
            "device-code",
            "ABCD-1234",
            "https://github.com/login/device",
            900,
            5,
        )
        .unwrap();

        assert_eq!(start.user_code, "ABCD-1234");
        assert_eq!(start.interval_secs, 5);
        assert!(
            DeviceFlowStart::new("device-code", "code", "http://example.test", 900, 5).is_err()
        );
        assert!(DeviceFlowStart::new(
            "device-code",
            "code",
            "https://github.com/login/device",
            0,
            5
        )
        .is_err());
        assert!(DeviceFlowStart::new(
            "device-code",
            "code",
            "https://github.com/login/device",
            900,
            0
        )
        .is_err());
    }

    #[test]
    fn device_flow_poll_maps_pending_slowdown_and_terminal_outcomes() {
        assert_eq!(
            DeviceFlowPoll::from_error(DeviceFlowErrorCode::AuthorizationPending, 5).unwrap(),
            DeviceFlowPoll::Pending { interval_secs: 5 }
        );
        assert_eq!(
            DeviceFlowPoll::from_error(DeviceFlowErrorCode::SlowDown, 5).unwrap(),
            DeviceFlowPoll::SlowDown { interval_secs: 10 }
        );
        assert!(
            DeviceFlowPoll::from_error(DeviceFlowErrorCode::AccessDenied, 5)
                .unwrap()
                .is_terminal()
        );
        assert!(
            DeviceFlowPoll::from_error(DeviceFlowErrorCode::ExpiredToken, 5)
                .unwrap()
                .is_terminal()
        );
        assert!(DeviceFlowPoll::from_error(DeviceFlowErrorCode::SlowDown, 0).is_err());
    }

    #[test]
    fn decodes_github_device_flow_start_json_without_network() {
        let start = decode_device_flow_start_response(
            r#"{
                "device_code": "device-code",
                "user_code": "ABCD-1234",
                "verification_uri": "https://github.com/login/device",
                "expires_in": 900,
                "interval": 5
            }"#,
        )
        .unwrap();

        assert_eq!(start.device_code, "device-code");
        assert_eq!(start.user_code, "ABCD-1234");
        assert_eq!(start.verification_uri, "https://github.com/login/device");
        assert_eq!(start.expires_in_secs, 900);
        assert_eq!(start.interval_secs, 5);

        let err = decode_device_flow_start_response(r#"{"error":"device_flow_disabled"}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("device_flow_disabled"));
    }

    #[test]
    fn decodes_github_device_flow_poll_json_without_leaking_tokens() {
        assert_eq!(
            decode_device_flow_poll_response(r#"{"error":"authorization_pending"}"#, 5).unwrap(),
            DeviceFlowPoll::Pending { interval_secs: 5 }
        );
        assert_eq!(
            decode_device_flow_poll_response(r#"{"error":"slow_down"}"#, 5).unwrap(),
            DeviceFlowPoll::SlowDown { interval_secs: 10 }
        );
        assert_eq!(
            decode_device_flow_poll_response(r#"{"error":"expired_token"}"#, 5).unwrap(),
            DeviceFlowPoll::Expired
        );
        assert_eq!(
            decode_device_flow_poll_response(r#"{"error":"token_expired"}"#, 5).unwrap(),
            DeviceFlowPoll::Expired
        );

        let poll = decode_device_flow_poll_response(
            r#"{
                "access_token": "alpha-redaction-marker",
                "token_type": "bearer",
                "scope": "contents:read contents:write",
                "expires_in": 28800,
                "refresh_token": "beta-redaction-marker",
                "refresh_token_expires_in": 15811200
            }"#,
            5,
        )
        .unwrap();

        let DeviceFlowPoll::Authorized(tokens) = poll else {
            panic!("expected an authorized token response");
        };
        assert_eq!(tokens.token_type, "bearer");
        assert_eq!(tokens.scope, "contents:read contents:write");
        let debug = format!("{tokens:?}");
        assert!(!debug.contains("alpha-redaction-marker"));
        assert!(!debug.contains("beta-redaction-marker"));
    }

    #[test]
    fn rejects_device_flow_success_without_refresh_token() {
        let err = decode_device_flow_poll_response(
            r#"{
                "access_token": "alpha-redaction-marker",
                "token_type": "bearer",
                "scope": "",
                "expires_in": 28800
            }"#,
            5,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("refresh_token"));
        assert!(!err.contains("alpha-redaction-marker"));
    }

    #[test]
    fn decodes_github_token_refresh_response_without_leaking_tokens() {
        let tokens = decode_github_token_refresh_response(
            r#"{
                "access_token": "alpha-redaction-marker",
                "token_type": "bearer",
                "scope": "contents:read contents:write",
                "expires_in": 28800,
                "refresh_token": "gamma-redaction-marker",
                "refresh_token_expires_in": 15811200
            }"#,
        )
        .unwrap();

        assert_eq!(tokens.token_type, "bearer");
        assert_eq!(tokens.scope, "contents:read contents:write");
        let debug = format!("{tokens:?}");
        assert!(!debug.contains("alpha-redaction-marker"));
        assert!(!debug.contains("gamma-redaction-marker"));

        let err = decode_github_token_refresh_response(r#"{"error":"bad_refresh_token"}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("bad_refresh_token"));
        assert!(!err.contains("gamma-redaction-marker"));
    }

    struct ScriptedTokenRefreshHttp {
        response: Option<DeviceFlowTokenSet>,
        saw_expected_refresh: bool,
    }

    impl GithubTokenRefreshHttp for ScriptedTokenRefreshHttp {
        fn refresh_user_access_token(
            &mut self,
            client_id: &str,
            refresh_token: &GithubRefreshToken,
        ) -> Result<DeviceFlowTokenSet, SyncError> {
            assert_eq!(client_id, DEFAULT_GITHUB_APP_CLIENT_ID);
            self.saw_expected_refresh = refresh_token.expose_secret() == "beta-redaction-marker";
            self.response.take().ok_or_else(|| SyncError::Backend {
                operation: "scripted token refresh",
                detail: "script exhausted".to_owned(),
            })
        }
    }

    #[test]
    fn refresh_token_http_boundary_runs_without_network_or_debug_leaks() {
        let refreshed = DeviceFlowTokenSet::new(
            "bearer",
            "",
            "alpha-redaction-marker",
            "gamma-redaction-marker",
            28_800,
            15_811_200,
        )
        .unwrap();
        let mut http = ScriptedTokenRefreshHttp {
            response: Some(refreshed.clone()),
            saw_expected_refresh: false,
        };
        let refresh = GithubRefreshToken::new("beta-redaction-marker").unwrap();

        let tokens =
            refresh_github_user_access_token(&mut http, DEFAULT_GITHUB_APP_CLIENT_ID, &refresh)
                .unwrap();
        assert_eq!(tokens, refreshed);
        assert!(http.saw_expected_refresh);
        assert!(!format!("{tokens:?}").contains("alpha-redaction-marker"));
        assert!(!format!("{refresh:?}").contains("beta-redaction-marker"));
        assert!(refresh_github_user_access_token(&mut http, "", &refresh).is_err());
    }

    #[test]
    fn scripted_device_flow_backend_runs_no_network_poll_steps() {
        let start = DeviceFlowStart::new(
            "device-code",
            "ABCD-1234",
            "https://github.com/login/device",
            900,
            5,
        )
        .unwrap();
        let authorized = DeviceFlowPoll::from_success(
            "bearer",
            "",
            "alpha-redaction-marker",
            "beta-redaction-marker",
            28_800,
            15_552_000,
        )
        .unwrap();
        let mut http = ScriptedDeviceFlowHttp::new(
            start,
            vec![
                DeviceFlowPoll::from_error(DeviceFlowErrorCode::AuthorizationPending, 5).unwrap(),
                DeviceFlowPoll::from_error(DeviceFlowErrorCode::SlowDown, 5).unwrap(),
                authorized.clone(),
            ],
        );

        let start = http
            .start_device_flow(DEFAULT_GITHUB_APP_CLIENT_ID)
            .unwrap();
        assert_eq!(start.user_code, "ABCD-1234");

        let step = super::poll_device_flow_once(
            &mut http,
            DEFAULT_GITHUB_APP_CLIENT_ID,
            &start.device_code,
            start.interval_secs,
        )
        .unwrap();
        assert_eq!(step.next_interval_secs, 5);
        assert_eq!(step.poll, DeviceFlowPoll::Pending { interval_secs: 5 });

        let step = super::poll_device_flow_once(
            &mut http,
            DEFAULT_GITHUB_APP_CLIENT_ID,
            &start.device_code,
            step.next_interval_secs,
        )
        .unwrap();
        assert_eq!(step.next_interval_secs, 10);
        assert_eq!(step.poll, DeviceFlowPoll::SlowDown { interval_secs: 10 });

        let step = super::poll_device_flow_once(
            &mut http,
            DEFAULT_GITHUB_APP_CLIENT_ID,
            &start.device_code,
            step.next_interval_secs,
        )
        .unwrap();
        assert_eq!(step.next_interval_secs, 10);
        assert_eq!(step.poll, authorized);
        assert_eq!(http.remaining_polls(), 0);
    }

    #[test]
    fn scripted_device_flow_backend_rejects_invalid_poll_inputs_without_leaking_values() {
        let start = DeviceFlowStart::new(
            "device-code",
            "ABCD-1234",
            "https://github.com/login/device",
            900,
            5,
        )
        .unwrap();
        let mut http = ScriptedDeviceFlowHttp::new(start, Vec::new());

        assert!(super::poll_device_flow_once(
            &mut http,
            DEFAULT_GITHUB_APP_CLIENT_ID,
            "device-code",
            5
        )
        .is_err());

        let start = http
            .start_device_flow(DEFAULT_GITHUB_APP_CLIENT_ID)
            .unwrap();
        let err =
            super::poll_device_flow_once(&mut http, DEFAULT_GITHUB_APP_CLIENT_ID, "wrong-code", 5)
                .unwrap_err();

        let debug = format!("{err:?}");
        assert!(!debug.contains("wrong-code"));
        assert!(!debug.contains(&start.device_code));
    }

    #[test]
    fn github_tokens_and_device_flow_token_set_redact_debug_output() {
        let access = GithubAccessToken::new("alpha-redaction-marker").unwrap();
        let refresh = GithubRefreshToken::new("beta-redaction-marker").unwrap();

        assert_eq!(access.expose_secret(), "alpha-redaction-marker");
        assert_eq!(refresh.expose_secret(), "beta-redaction-marker");
        assert!(!format!("{access:?}").contains("alpha-redaction-marker"));
        assert!(!format!("{refresh:?}").contains("beta-redaction-marker"));

        let set = DeviceFlowTokenSet::new(
            "bearer",
            "",
            "alpha-redaction-marker",
            "beta-redaction-marker",
            28_800,
            15_552_000,
        )
        .unwrap();
        let debug = format!("{set:?}");
        assert!(debug.contains("DeviceFlowTokenSet"));
        assert!(!debug.contains("alpha-redaction-marker"));
        assert!(!debug.contains("beta-redaction-marker"));

        assert!(DeviceFlowTokenSet::new("mac", "contents", "a", "r", 1, 1).is_err());
        assert!(DeviceFlowTokenSet::new("bearer", "contents", "a", "r", 0, 1).is_err());
    }

    #[test]
    fn token_vault_stores_refresh_tokens_without_debug_leaks() {
        let mut vault = InMemoryGithubTokenVault::new();
        let token = GithubRefreshToken::new("beta-redaction-marker").unwrap();
        let replacement = GithubRefreshToken::new("gamma-redaction-marker").unwrap();

        assert!(vault.get_refresh_token("fudanglp").unwrap().is_none());
        vault.set_refresh_token("fudanglp", &token).unwrap();

        let stored = vault.get_refresh_token("fudanglp").unwrap().unwrap();
        assert_eq!(stored.expose_secret(), "beta-redaction-marker");
        assert!(!format!("{vault:?}").contains("beta-redaction-marker"));

        vault.set_refresh_token("fudanglp", &replacement).unwrap();
        let stored = vault.get_refresh_token("fudanglp").unwrap().unwrap();
        assert_eq!(stored.expose_secret(), "gamma-redaction-marker");
        assert!(!format!("{vault:?}").contains("gamma-redaction-marker"));

        assert!(vault.delete_refresh_token("fudanglp").unwrap());
        assert!(vault.get_refresh_token("fudanglp").unwrap().is_none());
        assert!(vault.set_refresh_token("bad/account", &token).is_err());
    }

    #[test]
    fn fake_encrypted_codec_round_trips_non_secret_profile_document() {
        let connection =
            SyncProfileConnection::anyconnect("https://vpn.example.test:555/", "linux")
                .unwrap()
                .with_authgroup("engineering")
                .unwrap()
                .with_username("alice")
                .unwrap();
        let document = SyncProfileDocument::new("office", "Office VPN", connection)
            .unwrap()
            .with_company_domains(["corp.example.test"])
            .unwrap()
            .with_local_bypass(["198.18.0.0/15"])
            .unwrap();

        let codec = FakeEncryptedProfileCodec::new();
        let blob = codec.encode_profile(&document).unwrap();

        assert_eq!(blob.path(), &SyncObjectPath::profile("office").unwrap());
        assert!(blob.bytes().starts_with(b"oc-oxide-test-encrypted:"));
        assert!(!format!("{blob:?}").contains("corp.example.test"));

        let decoded = codec.decode_profile(&blob).unwrap();
        assert_eq!(decoded, document);
    }

    #[test]
    fn profile_document_rejects_plaintext_secret_fields_during_decode() {
        let plaintext = br#"{
            "schema_version": 1,
            "profile_id": "office",
            "display_name": "Office VPN",
            "connection": {
                "server": "https://vpn.example.test:555/",
                "protocol": "anyconnect",
                "reported_os": "linux",
                "password": true
            }
        }"#;

        let mut bytes = b"oc-oxide-test-encrypted:".to_vec();
        bytes.extend(plaintext);
        let blob =
            EncryptedSyncBlob::new(SyncObjectPath::profile("office").unwrap(), bytes).unwrap();

        let err = FakeEncryptedProfileCodec::new()
            .decode_profile(&blob)
            .unwrap_err();
        assert!(matches!(err, SyncError::Codec { .. }));
    }

    #[test]
    fn profile_codec_rejects_path_mismatches_and_invalid_documents() {
        assert!(SyncProfileConnection::anyconnect("http://vpn.example.test", "linux").is_err());
        assert!(
            SyncProfileConnection::anyconnect("https://vpn.example.test", "linux")
                .unwrap()
                .with_authgroup(" ")
                .is_err()
        );

        let document = SyncProfileDocument::new(
            "office",
            "Office VPN",
            SyncProfileConnection::anyconnect("https://vpn.example.test", "linux").unwrap(),
        )
        .unwrap();
        assert!(document
            .clone()
            .with_local_bypass(["198.18.0.0/33"])
            .is_err());

        let codec = FakeEncryptedProfileCodec::new();
        let blob = codec.encode_profile(&document).unwrap();
        let wrong_path_blob = EncryptedSyncBlob::new(
            SyncObjectPath::profile("other").unwrap(),
            blob.bytes().to_vec(),
        )
        .unwrap();

        assert!(matches!(
            codec.decode_profile(&wrong_path_blob),
            Err(SyncError::InvalidProfileDocument { .. })
        ));
    }

    #[test]
    fn private_repo_codec_round_trips_manifest_and_profile_json() {
        let codec = PrivateRepoSyncCodec::new();
        let manifest = SyncManifest::new();

        let manifest_blob = codec.encode_manifest(&manifest).unwrap();
        assert_eq!(manifest_blob.path(), &SyncObjectPath::manifest());
        assert!(!manifest_blob.bytes().is_empty());
        assert!(String::from_utf8_lossy(manifest_blob.bytes()).contains(SYNC_FORMAT));
        assert!(String::from_utf8_lossy(manifest_blob.bytes()).contains("github-private-repo"));
        assert_eq!(codec.decode_manifest(&manifest_blob).unwrap(), manifest);

        let profile = SyncProfileDocument::new(
            "office",
            "Office VPN",
            SyncProfileConnection::anyconnect("https://vpn.example.test", "linux").unwrap(),
        )
        .unwrap();
        let profile_blob = codec.encode_profile(&profile).unwrap();
        assert_eq!(
            profile_blob.path(),
            &SyncObjectPath::profile("office").unwrap()
        );
        let encoded = String::from_utf8_lossy(profile_blob.bytes());
        assert!(encoded.contains("Office VPN"));
        assert!(encoded.contains("vpn.example.test"));
        assert_eq!(codec.decode_profile(&profile_blob).unwrap(), profile);
        assert_eq!(format!("{codec:?}"), "PrivateRepoSyncCodec");
    }

    #[test]
    fn github_contents_client_reads_objects_and_maps_missing_files_without_network() {
        let manifest_path = SyncObjectPath::manifest();
        let manifest_bytes = br#"{"format":"oc-oxide-sync"}"#;
        let manifest_content = base64::engine::general_purpose::STANDARD.encode(manifest_bytes);
        let http = ScriptedContentsHttp::new(vec![
            GithubContentsResponse::new(
                200,
                format!(
                    r#"{{"path":"manifest.json","sha":"sha-read","content":"{}"}}"#,
                    manifest_content
                ),
            ),
            GithubContentsResponse::new(404, r#"{"message":"Not Found"}"#),
        ]);
        let token = GithubAccessToken::new("alpha-redaction-marker").unwrap();
        let client = GithubContentsClient::oc_oxide_sync(token, http).unwrap();

        let object = client.read_object(&manifest_path).unwrap().unwrap();
        assert_eq!(object.sha, "sha-read");
        assert_eq!(object.bytes(), manifest_bytes);

        let missing = client
            .read_object(&SyncObjectPath::profile("office").unwrap())
            .unwrap();
        assert!(missing.is_none());

        let requests = client.http().requests();
        assert_eq!(requests[0].method, GithubContentsMethod::Get);
        assert_eq!(
            requests[0].api_path,
            "/repos/fudanglp/oc-oxide-sync/contents/manifest.json?ref=master"
        );
        assert_eq!(
            requests[1].api_path,
            "/repos/fudanglp/oc-oxide-sync/contents/profiles/office.json?ref=master"
        );
        assert!(!format!("{:?}", requests[0]).contains("alpha-redaction-marker"));
    }

    #[test]
    fn github_contents_client_writes_and_deletes_sync_blobs_without_network() {
        let http = ScriptedContentsHttp::new(vec![
            GithubContentsResponse::new(201, r#"{"content":{"sha":"sha-created"}}"#),
            GithubContentsResponse::new(200, r#"{"content":{"sha":"sha-updated"}}"#),
            GithubContentsResponse::new(200, r#"{"commit":{"sha":"commit-delete"}}"#),
        ]);
        let token = GithubAccessToken::new("alpha-redaction-marker").unwrap();
        let mut client = GithubContentsClient::oc_oxide_sync(token, http).unwrap();
        let path = SyncObjectPath::profile("office").unwrap();

        let created_blob = EncryptedSyncBlob::new(path.clone(), b"sync-create").unwrap();
        let created = client
            .write_object(super::SyncWrite::create(created_blob, "create office profile").unwrap())
            .unwrap();
        assert_eq!(created.sha, "sha-created");
        assert_eq!(created.bytes(), b"sync-create");

        let updated_blob = EncryptedSyncBlob::new(path.clone(), b"sync-update").unwrap();
        let updated = client
            .write_object(
                super::SyncWrite::update(
                    updated_blob,
                    created.sha.clone(),
                    "update office profile",
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(updated.sha, "sha-updated");
        assert_eq!(updated.bytes(), b"sync-update");

        client
            .delete_object(&path, &updated.sha, "delete office profile")
            .unwrap();

        let requests = client.http().requests();
        assert_eq!(requests[0].method, GithubContentsMethod::Put);
        assert_eq!(
            requests[0].api_path,
            "/repos/fudanglp/oc-oxide-sync/contents/profiles/office.json"
        );
        let create_body: serde_json::Value =
            serde_json::from_str(requests[0].body().unwrap()).unwrap();
        assert_eq!(create_body["message"], "create office profile");
        assert_eq!(create_body["branch"], "master");
        assert!(create_body.get("sha").is_none());
        assert_eq!(
            create_body["content"],
            base64::engine::general_purpose::STANDARD.encode(b"sync-create")
        );
        assert!(!requests[0].body().unwrap().contains("sync-create"));

        let update_body: serde_json::Value =
            serde_json::from_str(requests[1].body().unwrap()).unwrap();
        assert_eq!(update_body["sha"], "sha-created");
        assert_eq!(
            update_body["content"],
            base64::engine::general_purpose::STANDARD.encode(b"sync-update")
        );

        assert_eq!(requests[2].method, GithubContentsMethod::Delete);
        let delete_body: serde_json::Value =
            serde_json::from_str(requests[2].body().unwrap()).unwrap();
        assert_eq!(delete_body["message"], "delete office profile");
        assert_eq!(delete_body["sha"], "sha-updated");
        assert_eq!(delete_body["branch"], "master");
    }

    #[test]
    fn github_contents_client_maps_conflicts_and_auth_errors_without_token_leaks() {
        let http = ScriptedContentsHttp::new(vec![
            GithubContentsResponse::new(401, r#"{"message":"Bad credentials"}"#),
            GithubContentsResponse::new(409, r#"{"message":"sha does not match"}"#),
            GithubContentsResponse::new(404, r#"{"message":"Not Found"}"#),
        ]);
        let token = GithubAccessToken::new("alpha-redaction-marker").unwrap();
        let mut client = GithubContentsClient::oc_oxide_sync(token, http).unwrap();
        let path = SyncObjectPath::profile("office").unwrap();

        let auth_err = client
            .read_object(&SyncObjectPath::manifest())
            .unwrap_err()
            .to_string();
        assert!(auth_err.contains("HTTP 401"));
        assert!(!auth_err.contains("alpha-redaction-marker"));

        let blob = EncryptedSyncBlob::new(path.clone(), b"encrypted-conflict").unwrap();
        assert!(matches!(
            client.write_object(super::SyncWrite::create(blob, "create conflict").unwrap()),
            Err(SyncError::Conflict { .. })
        ));

        assert!(matches!(
            client.delete_object(&path, "sha-missing", "delete missing"),
            Err(SyncError::NotFound { .. })
        ));
    }

    #[test]
    fn in_memory_client_uses_github_style_sha_conflicts() {
        let mut client = InMemorySyncClient::new();
        let path = SyncObjectPath::profile("office").unwrap();
        let first = EncryptedSyncBlob::new(path.clone(), b"first").unwrap();

        let created = client
            .write_object(super::SyncWrite::create(first, "create office profile").unwrap())
            .unwrap();

        assert_eq!(created.sha, "mem-sha-1");
        assert_eq!(
            client.read_object(&path).unwrap().unwrap().bytes(),
            b"first"
        );

        let duplicate = EncryptedSyncBlob::new(path.clone(), b"duplicate").unwrap();
        assert!(matches!(
            client.write_object(super::SyncWrite::create(duplicate, "duplicate").unwrap()),
            Err(SyncError::Conflict { .. })
        ));

        let updated = EncryptedSyncBlob::new(path.clone(), b"second").unwrap();
        let updated = client
            .write_object(
                super::SyncWrite::update(updated, created.sha.clone(), "update office profile")
                    .unwrap(),
            )
            .unwrap();

        assert_eq!(updated.sha, "mem-sha-2");
        assert_eq!(
            client.read_object(&path).unwrap().unwrap().bytes(),
            b"second"
        );

        assert!(matches!(
            client.delete_object(&path, &created.sha, "delete stale"),
            Err(SyncError::Conflict { .. })
        ));

        client
            .delete_object(&path, &updated.sha, "delete office profile")
            .unwrap();
        assert!(client.read_object(&path).unwrap().is_none());
    }

    #[test]
    fn upload_profile_documents_writes_profiles_then_manifest() {
        let mut client = InMemorySyncClient::new();
        let codec = PrivateRepoSyncCodec::new();
        let manifest_blob = codec.encode_manifest(&SyncManifest::new()).unwrap();
        let initial_manifest_sha = client
            .write_object(SyncWrite::create(manifest_blob, "init manifest").unwrap())
            .unwrap()
            .sha;
        assert_eq!(initial_manifest_sha, "mem-sha-1");

        let office = SyncProfileDocument::new(
            "office",
            "office",
            SyncProfileConnection::anyconnect("https://vpn.example.test:555/", "linux")
                .unwrap()
                .with_authgroup("engineering")
                .unwrap()
                .with_username("alice")
                .unwrap(),
        )
        .unwrap()
        .with_company_domains(["corp.example.test"])
        .unwrap()
        .with_local_bypass(["198.18.0.0/15"])
        .unwrap();
        let lab = SyncProfileDocument::new(
            "lab",
            "lab",
            SyncProfileConnection::anyconnect("https://lab.example.test/", "linux").unwrap(),
        )
        .unwrap();

        let report = super::upload_profile_documents(
            &mut client,
            &codec,
            &[office.clone(), lab.clone()],
            "unix:1782259200",
            "thinkpad",
        )
        .unwrap();

        assert_eq!(report.uploaded_profiles, 2);
        assert_eq!(report.manifest_profile_count, 2);
        assert_eq!(report.manifest_sha, "mem-sha-4");
        assert!(report.manifest_bytes > 0);

        let office_blob = client
            .read_object(&SyncObjectPath::profile("office").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(
            codec
                .decode_profile(
                    &EncryptedSyncBlob::new(office_blob.path.clone(), office_blob.bytes().to_vec())
                        .unwrap()
                )
                .unwrap(),
            office
        );

        let manifest_object = client
            .read_object(&SyncObjectPath::manifest())
            .unwrap()
            .unwrap();
        let manifest = codec
            .decode_manifest(
                &EncryptedSyncBlob::new(
                    SyncObjectPath::manifest(),
                    manifest_object.bytes().to_vec(),
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(manifest.profiles["office"].revision, "mem-sha-2");
        assert_eq!(manifest.profiles["lab"].revision, "mem-sha-3");
        assert_eq!(manifest.profiles["office"].updated_by_device, "thinkpad");
        assert_eq!(manifest.profiles["office"].updated_at, "unix:1782259200");
    }

    #[test]
    fn upload_profile_documents_updates_existing_profile_objects() {
        let mut client = InMemorySyncClient::new();
        let codec = PrivateRepoSyncCodec::new();
        client
            .write_object(
                SyncWrite::create(
                    codec.encode_manifest(&SyncManifest::new()).unwrap(),
                    "init manifest",
                )
                .unwrap(),
            )
            .unwrap();

        let first = SyncProfileDocument::new(
            "office",
            "office",
            SyncProfileConnection::anyconnect("https://vpn.example.test/", "linux").unwrap(),
        )
        .unwrap();
        let first_report = super::upload_profile_documents(
            &mut client,
            &codec,
            &[first],
            "unix:1782259200",
            "thinkpad",
        )
        .unwrap();
        assert_eq!(first_report.manifest_sha, "mem-sha-3");

        let second = SyncProfileDocument::new(
            "office",
            "office",
            SyncProfileConnection::anyconnect("https://vpn2.example.test/", "linux").unwrap(),
        )
        .unwrap();
        let second_report = super::upload_profile_documents(
            &mut client,
            &codec,
            &[second],
            "unix:1782259300",
            "desktop",
        )
        .unwrap();
        assert_eq!(second_report.manifest_sha, "mem-sha-5");

        let manifest_object = client
            .read_object(&SyncObjectPath::manifest())
            .unwrap()
            .unwrap();
        let manifest = codec
            .decode_manifest(
                &EncryptedSyncBlob::new(
                    SyncObjectPath::manifest(),
                    manifest_object.bytes().to_vec(),
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(manifest.profiles.len(), 1);
        assert_eq!(manifest.profiles["office"].revision, "mem-sha-4");
        assert_eq!(manifest.profiles["office"].updated_by_device, "desktop");
    }

    #[test]
    fn download_profile_documents_reads_manifest_profiles() {
        let mut client = InMemorySyncClient::new();
        let codec = PrivateRepoSyncCodec::new();
        client
            .write_object(
                SyncWrite::create(
                    codec.encode_manifest(&SyncManifest::new()).unwrap(),
                    "init manifest",
                )
                .unwrap(),
            )
            .unwrap();

        let office = SyncProfileDocument::new(
            "office",
            "office",
            SyncProfileConnection::anyconnect("https://vpn.example.test/", "linux").unwrap(),
        )
        .unwrap();
        let lab = SyncProfileDocument::new(
            "lab",
            "lab",
            SyncProfileConnection::anyconnect("https://lab.example.test/", "linux").unwrap(),
        )
        .unwrap();
        let upload = super::upload_profile_documents(
            &mut client,
            &codec,
            &[office.clone(), lab.clone()],
            "unix:1782259200",
            "thinkpad",
        )
        .unwrap();

        let download = super::download_profile_documents(&client, &codec).unwrap();
        assert_eq!(download.manifest_sha, upload.manifest_sha);
        assert_eq!(download.manifest_profile_count, 2);
        assert_eq!(download.profiles, vec![lab, office]);
    }

    #[test]
    fn download_profile_documents_requires_referenced_profile_objects() {
        let mut client = InMemorySyncClient::new();
        let codec = PrivateRepoSyncCodec::new();
        let mut manifest = SyncManifest::new();
        manifest
            .add_profile(
                SyncProfileEntry::new("office", "missing-sha", "unix:1782259200", "thinkpad")
                    .unwrap(),
            )
            .unwrap();
        client
            .write_object(
                SyncWrite::create(codec.encode_manifest(&manifest).unwrap(), "init manifest")
                    .unwrap(),
            )
            .unwrap();

        assert!(matches!(
            super::download_profile_documents(&client, &codec),
            Err(SyncError::NotFound { path }) if path == SyncObjectPath::profile("office").unwrap()
        ));
    }

    #[test]
    fn deleted_profile_codec_round_trips_non_secret_tombstone() {
        let codec = PrivateRepoSyncCodec::new();
        let tombstone =
            SyncDeletedProfileDocument::new("office", "unix:1782259400", "thinkpad").unwrap();
        let blob = codec.encode_deleted_profile(&tombstone).unwrap();

        assert_eq!(
            blob.path(),
            &SyncObjectPath::deleted_profile("office").unwrap()
        );
        assert_eq!(codec.decode_deleted_profile(&blob).unwrap(), tombstone);

        let json = String::from_utf8(blob.bytes().to_vec()).unwrap();
        assert!(json.contains("\"profile_id\""));
        assert!(!json.contains("password"));
        assert!(!json.contains("token"));
        assert!(!json.contains("cookie"));
    }

    #[test]
    fn delete_profile_document_writes_tombstone_and_removes_profile() {
        let mut client = InMemorySyncClient::new();
        let codec = PrivateRepoSyncCodec::new();
        client
            .write_object(
                SyncWrite::create(
                    codec.encode_manifest(&SyncManifest::new()).unwrap(),
                    "init manifest",
                )
                .unwrap(),
            )
            .unwrap();

        let office = SyncProfileDocument::new(
            "office",
            "office",
            SyncProfileConnection::anyconnect("https://vpn.example.test/", "linux").unwrap(),
        )
        .unwrap();
        super::upload_profile_documents(
            &mut client,
            &codec,
            &[office],
            "unix:1782259200",
            "thinkpad",
        )
        .unwrap();

        let report = super::delete_profile_document(
            &mut client,
            &codec,
            "office",
            "unix:1782259400",
            "thinkpad",
        )
        .unwrap();

        assert_eq!(report.profile_id, "office");
        assert!(report.removed_from_manifest);
        assert!(report.deleted_profile_object);
        assert_eq!(report.manifest_profile_count, 0);
        assert_eq!(report.manifest_sha, "mem-sha-4");
        assert_eq!(report.tombstone_sha, "mem-sha-5");
        assert!(report.manifest_bytes > 0);
        assert!(client
            .read_object(&SyncObjectPath::profile("office").unwrap())
            .unwrap()
            .is_none());

        let tombstone_object = client
            .read_object(&SyncObjectPath::deleted_profile("office").unwrap())
            .unwrap()
            .unwrap();
        let tombstone = codec
            .decode_deleted_profile(
                &EncryptedSyncBlob::new(
                    tombstone_object.path.clone(),
                    tombstone_object.bytes().to_vec(),
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(tombstone.profile_id, "office");

        let manifest_object = client
            .read_object(&SyncObjectPath::manifest())
            .unwrap()
            .unwrap();
        let manifest = codec
            .decode_manifest(
                &EncryptedSyncBlob::new(
                    SyncObjectPath::manifest(),
                    manifest_object.bytes().to_vec(),
                )
                .unwrap(),
            )
            .unwrap();
        assert!(manifest.profiles.is_empty());
    }

    #[test]
    fn delete_profile_document_updates_existing_tombstone_without_manifest_entry() {
        let mut client = InMemorySyncClient::new();
        let codec = PrivateRepoSyncCodec::new();
        client
            .write_object(
                SyncWrite::create(
                    codec.encode_manifest(&SyncManifest::new()).unwrap(),
                    "init manifest",
                )
                .unwrap(),
            )
            .unwrap();

        let first = super::delete_profile_document(
            &mut client,
            &codec,
            "office",
            "unix:1782259400",
            "thinkpad",
        )
        .unwrap();
        assert!(!first.removed_from_manifest);
        assert!(!first.deleted_profile_object);
        assert_eq!(first.manifest_sha, "mem-sha-1");
        assert_eq!(first.tombstone_sha, "mem-sha-2");

        let second = super::delete_profile_document(
            &mut client,
            &codec,
            "office",
            "unix:1782259500",
            "desktop",
        )
        .unwrap();
        assert!(!second.removed_from_manifest);
        assert!(!second.deleted_profile_object);
        assert_eq!(second.manifest_sha, "mem-sha-1");
        assert_eq!(second.tombstone_sha, "mem-sha-3");
    }

    #[test]
    fn upload_profile_documents_clears_matching_tombstone() {
        let mut client = InMemorySyncClient::new();
        let codec = PrivateRepoSyncCodec::new();
        client
            .write_object(
                SyncWrite::create(
                    codec.encode_manifest(&SyncManifest::new()).unwrap(),
                    "init manifest",
                )
                .unwrap(),
            )
            .unwrap();
        super::delete_profile_document(
            &mut client,
            &codec,
            "office",
            "unix:1782259400",
            "thinkpad",
        )
        .unwrap();
        assert!(client
            .read_object(&SyncObjectPath::deleted_profile("office").unwrap())
            .unwrap()
            .is_some());

        let office = SyncProfileDocument::new(
            "office",
            "office",
            SyncProfileConnection::anyconnect("https://vpn.example.test/", "linux").unwrap(),
        )
        .unwrap();
        let report = super::upload_profile_documents(
            &mut client,
            &codec,
            &[office],
            "unix:1782259600",
            "desktop",
        )
        .unwrap();

        assert_eq!(report.manifest_profile_count, 1);
        assert!(client
            .read_object(&SyncObjectPath::deleted_profile("office").unwrap())
            .unwrap()
            .is_none());
        assert!(client
            .read_object(&SyncObjectPath::profile("office").unwrap())
            .unwrap()
            .is_some());
    }

    #[test]
    fn upload_profile_documents_requires_existing_manifest_and_profiles() {
        let mut client = InMemorySyncClient::new();
        let codec = PrivateRepoSyncCodec::new();
        let document = SyncProfileDocument::new(
            "office",
            "office",
            SyncProfileConnection::anyconnect("https://vpn.example.test/", "linux").unwrap(),
        )
        .unwrap();

        assert!(matches!(
            super::upload_profile_documents(
                &mut client,
                &codec,
                &[document.clone()],
                "unix:1782259200",
                "thinkpad"
            ),
            Err(SyncError::NotFound { .. })
        ));

        client
            .write_object(
                SyncWrite::create(
                    codec.encode_manifest(&SyncManifest::new()).unwrap(),
                    "init manifest",
                )
                .unwrap(),
            )
            .unwrap();

        assert!(matches!(
            super::upload_profile_documents(
                &mut client,
                &codec,
                &[],
                "unix:1782259200",
                "thinkpad"
            ),
            Err(SyncError::InvalidProfileDocument { .. })
        ));
    }
}
