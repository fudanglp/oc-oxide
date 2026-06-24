//! Profile configuration.
//!
//! This crate will persist non-secret profile settings in user config paths and
//! use OS keyring integration only when a user explicitly opts in to storing
//! secrets.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::sync::Mutex;

use oc_oxide_dns::DnsMode;
use oc_oxide_net::{Ipv4Cidr, NetworkPolicy, RouteMode};
use serde::Deserialize;
use url::Url;

/// Human-readable crate role used by workspace smoke tests.
pub const CRATE_ROLE: &str = "profile configuration";

const DEFAULT_REPORTED_OS: &str = "linux";
const VPN_PASSWORD_SERVICE: &str = "oc-oxide.vpn";

/// GUI-facing policy preset.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProfileMode {
    Off,
    #[default]
    Split,
    Full,
}

impl ProfileMode {
    pub fn route_mode(self) -> RouteMode {
        match self {
            Self::Off => RouteMode::Off,
            Self::Split => RouteMode::Split,
            Self::Full => RouteMode::Full,
        }
    }

    pub fn dns_mode(self) -> DnsMode {
        match self {
            Self::Off => DnsMode::Off,
            Self::Split => DnsMode::Split,
            Self::Full => DnsMode::Full,
        }
    }
}

impl fmt::Display for ProfileMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Off => f.write_str("off"),
            Self::Split => f.write_str("split"),
            Self::Full => f.write_str("full"),
        }
    }
}

impl FromStr for ProfileMode {
    type Err = ProfileConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "off" => Ok(Self::Off),
            "split" => Ok(Self::Split),
            "full" => Ok(Self::Full),
            _ => Err(ProfileConfigError::InvalidMode {
                value: value.to_owned(),
            }),
        }
    }
}

/// Non-secret key used to locate a remembered VPN password in a vault.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VpnPasswordKey {
    service: String,
    account: String,
}

impl VpnPasswordKey {
    pub fn for_profile(
        profile: impl Into<String>,
        authgroup: Option<&str>,
        username: Option<&str>,
    ) -> Result<Self, VaultError> {
        let mut parts = vec![clean_vault_key_part("profile", profile.into())?];

        if let Some(authgroup) = authgroup {
            parts.push(clean_vault_key_part("authgroup", authgroup.to_owned())?);
        }

        if let Some(username) = username {
            parts.push(clean_vault_key_part("username", username.to_owned())?);
        }

        Ok(Self {
            service: VPN_PASSWORD_SERVICE.to_owned(),
            account: parts.join(":"),
        })
    }

    pub fn for_vpn_profile(profile: &VpnProfile) -> Result<Self, VaultError> {
        Self::for_profile(
            profile.tunnel().name(),
            profile.tunnel().authgroup(),
            profile.tunnel().username(),
        )
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    pub fn account(&self) -> &str {
        &self.account
    }
}

impl fmt::Debug for VpnPasswordKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VpnPasswordKey")
            .field("service", &self.service)
            .field("account", &self.account)
            .finish()
    }
}

/// Secret VPN password value. Debug output is always redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct VpnPassword {
    value: String,
}

impl VpnPassword {
    pub fn new(value: impl Into<String>) -> Result<Self, VaultError> {
        let value = value.into();
        if value.is_empty() {
            return Err(VaultError::EmptyField {
                field: "VPN password",
            });
        }

        if value.contains('\0') {
            return Err(VaultError::InteriorNul {
                field: "VPN password",
            });
        }

        Ok(Self { value })
    }

    pub fn expose_secret(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for VpnPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VpnPassword(<redacted>)")
    }
}

/// Minimal vault operations needed by oc-oxide clients.
pub trait VpnPasswordVault {
    fn get_vpn_password(&self, key: &VpnPasswordKey) -> Result<Option<VpnPassword>, VaultError>;
    fn set_vpn_password(
        &self,
        key: &VpnPasswordKey,
        password: &VpnPassword,
    ) -> Result<(), VaultError>;
    fn delete_vpn_password(&self, key: &VpnPasswordKey) -> Result<bool, VaultError>;
}

/// In-memory vault backend for no-side-effect tests.
#[derive(Debug, Default)]
pub struct InMemoryVpnPasswordVault {
    entries: Mutex<BTreeMap<VpnPasswordKey, VpnPassword>>,
}

impl InMemoryVpnPasswordVault {
    pub fn new() -> Self {
        Self::default()
    }
}

impl VpnPasswordVault for InMemoryVpnPasswordVault {
    fn get_vpn_password(&self, key: &VpnPasswordKey) -> Result<Option<VpnPassword>, VaultError> {
        let entries = self.entries.lock().map_err(|_| VaultError::Backend {
            operation: "memory vault lock",
            detail: "lock poisoned".to_owned(),
        })?;
        Ok(entries.get(key).cloned())
    }

    fn set_vpn_password(
        &self,
        key: &VpnPasswordKey,
        password: &VpnPassword,
    ) -> Result<(), VaultError> {
        let mut entries = self.entries.lock().map_err(|_| VaultError::Backend {
            operation: "memory vault lock",
            detail: "lock poisoned".to_owned(),
        })?;
        entries.insert(key.clone(), password.clone());
        Ok(())
    }

    fn delete_vpn_password(&self, key: &VpnPasswordKey) -> Result<bool, VaultError> {
        let mut entries = self.entries.lock().map_err(|_| VaultError::Backend {
            operation: "memory vault lock",
            detail: "lock poisoned".to_owned(),
        })?;
        Ok(entries.remove(key).is_some())
    }
}

/// System keyring-backed vault. Tests should use `InMemoryVpnPasswordVault`.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyringVpnPasswordVault;

impl KeyringVpnPasswordVault {
    pub fn new() -> Self {
        Self
    }

    fn entry(key: &VpnPasswordKey) -> Result<keyring::Entry, VaultError> {
        keyring::Entry::new(key.service(), key.account()).map_err(keyring_error("keyring entry"))
    }
}

impl VpnPasswordVault for KeyringVpnPasswordVault {
    fn get_vpn_password(&self, key: &VpnPasswordKey) -> Result<Option<VpnPassword>, VaultError> {
        match Self::entry(key)?.get_password() {
            Ok(password) => Ok(Some(VpnPassword::new(password)?)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(keyring_error("keyring get")(err)),
        }
    }

    fn set_vpn_password(
        &self,
        key: &VpnPasswordKey,
        password: &VpnPassword,
    ) -> Result<(), VaultError> {
        Self::entry(key)?
            .set_password(password.expose_secret())
            .map_err(keyring_error("keyring set"))
    }

    fn delete_vpn_password(&self, key: &VpnPasswordKey) -> Result<bool, VaultError> {
        match Self::entry(key)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(err) => Err(keyring_error("keyring delete")(err)),
        }
    }
}

/// Errors returned by vault key construction and backends.
#[derive(Clone, PartialEq, Eq)]
pub enum VaultError {
    Backend {
        operation: &'static str,
        detail: String,
    },
    EmptyField {
        field: &'static str,
    },
    InteriorNul {
        field: &'static str,
    },
    SeparatorNotAllowed {
        field: &'static str,
    },
}

impl fmt::Debug for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend { operation, detail } => f
                .debug_struct("Backend")
                .field("operation", operation)
                .field("detail", detail)
                .finish(),
            Self::EmptyField { field } => {
                f.debug_struct("EmptyField").field("field", field).finish()
            }
            Self::InteriorNul { field } => {
                f.debug_struct("InteriorNul").field("field", field).finish()
            }
            Self::SeparatorNotAllowed { field } => f
                .debug_struct("SeparatorNotAllowed")
                .field("field", field)
                .finish(),
        }
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend { operation, detail } => {
                write!(f, "vault backend failed during {operation}: {detail}")
            }
            Self::EmptyField { field } => write!(f, "{field} must not be empty"),
            Self::InteriorNul { field } => write!(f, "{field} must not contain a NUL byte"),
            Self::SeparatorNotAllowed { field } => {
                write!(f, "{field} must not contain ':'")
            }
        }
    }
}

impl std::error::Error for VaultError {}

fn keyring_error(operation: &'static str) -> impl FnOnce(keyring::Error) -> VaultError {
    move |err| VaultError::Backend {
        operation,
        detail: err.to_string(),
    }
}

fn clean_vault_key_part(field: &'static str, value: String) -> Result<String, VaultError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(VaultError::EmptyField { field });
    }

    if value.contains('\0') {
        return Err(VaultError::InteriorNul { field });
    }

    if value.contains(':') {
        return Err(VaultError::SeparatorNotAllowed { field });
    }

    Ok(value.to_owned())
}

/// Validated, non-secret server URL for an OpenConnect profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerUrl {
    openconnect_url: String,
    dns_name: String,
    port: u16,
    path: String,
}

impl ServerUrl {
    /// Parse and validate a server URL before passing it to libopenconnect.
    pub fn parse(input: &str) -> Result<Self, ServerUrlError> {
        let url = Url::parse(input).map_err(ServerUrlError::Parse)?;

        if url.scheme() != "https" {
            return Err(ServerUrlError::UnsupportedScheme(url.scheme().to_owned()));
        }

        if !url.username().is_empty() || url.password().is_some() {
            return Err(ServerUrlError::UserInfoNotAllowed);
        }

        if url.query().is_some() {
            return Err(ServerUrlError::QueryNotAllowed);
        }

        if url.fragment().is_some() {
            return Err(ServerUrlError::FragmentNotAllowed);
        }

        let dns_name = url
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or(ServerUrlError::MissingHost)?
            .to_owned();
        let port = url
            .port_or_known_default()
            .ok_or(ServerUrlError::MissingPort)?;
        let path = url.path().to_owned();

        Ok(Self {
            openconnect_url: url.to_string(),
            dns_name,
            port,
            path,
        })
    }

    /// URL string to pass to `openconnect_parse_url`.
    pub fn as_openconnect_url(&self) -> &str {
        &self.openconnect_url
    }

    /// DNS host name parsed by Rust-side profile validation.
    pub fn dns_name(&self) -> &str {
        &self.dns_name
    }

    /// Explicit or default HTTPS port parsed by Rust-side profile validation.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// URL path with the leading slash retained, matching normal URL syntax.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Path shape returned by `openconnect_get_urlpath`.
    pub fn openconnect_url_path(&self) -> &str {
        self.path.strip_prefix('/').unwrap_or(&self.path)
    }
}

/// Server URL validation errors.
#[derive(Debug)]
pub enum ServerUrlError {
    Parse(url::ParseError),
    UnsupportedScheme(String),
    UserInfoNotAllowed,
    QueryNotAllowed,
    FragmentNotAllowed,
    MissingHost,
    MissingPort,
}

impl fmt::Display for ServerUrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(source) => write!(f, "invalid server URL: {source}"),
            Self::UnsupportedScheme(scheme) => {
                write!(
                    f,
                    "unsupported server URL scheme {scheme:?}; expected https"
                )
            }
            Self::UserInfoNotAllowed => {
                write!(f, "server URL must not include username or password")
            }
            Self::QueryNotAllowed => write!(f, "server URL must not include a query string"),
            Self::FragmentNotAllowed => write!(f, "server URL must not include a fragment"),
            Self::MissingHost => write!(f, "server URL must include a host name"),
            Self::MissingPort => write!(f, "server URL must include or imply a port"),
        }
    }
}

impl std::error::Error for ServerUrlError {}

/// Non-secret tunnel profile settings.
///
/// Secrets such as passwords, OTP values, cookies, private keys, and router
/// credentials do not belong in this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelProfile {
    name: String,
    server_url: ServerUrl,
    reported_os: String,
    username: Option<String>,
    authgroup: Option<String>,
}

impl TunnelProfile {
    /// Create a profile using the default reported OS for OpenConnect.
    pub fn new(name: impl Into<String>, server_url: ServerUrl) -> Result<Self, TunnelProfileError> {
        Self::with_reported_os(name, server_url, DEFAULT_REPORTED_OS)
    }

    /// Create a profile with an explicit reported OS string.
    pub fn with_reported_os(
        name: impl Into<String>,
        server_url: ServerUrl,
        reported_os: impl Into<String>,
    ) -> Result<Self, TunnelProfileError> {
        let name = clean_profile_text("profile name", name.into())?;
        let reported_os = clean_profile_text("reported OS", reported_os.into())?;

        Ok(Self {
            name,
            server_url,
            reported_os,
            username: None,
            authgroup: None,
        })
    }

    /// Human-readable profile name. This is not sent to libopenconnect.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Validated OpenConnect server URL.
    pub fn server_url(&self) -> &ServerUrl {
        &self.server_url
    }

    /// Client OS string passed to libopenconnect.
    pub fn reported_os(&self) -> &str {
        &self.reported_os
    }

    /// Preferred username to submit when the server asks for a user field.
    /// This is local account identity, not a password or OTP secret.
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    pub fn with_username(
        mut self,
        username: impl Into<String>,
    ) -> Result<Self, TunnelProfileError> {
        self.username = Some(clean_profile_text("username", username.into())?);
        Ok(self)
    }

    /// Preferred authentication group to submit when the server offers a group
    /// selection. This is non-secret policy/config, not a password.
    pub fn authgroup(&self) -> Option<&str> {
        self.authgroup.as_deref()
    }

    pub fn with_authgroup(
        mut self,
        authgroup: impl Into<String>,
    ) -> Result<Self, TunnelProfileError> {
        self.authgroup = Some(clean_profile_text("authgroup", authgroup.into())?);
        Ok(self)
    }
}

/// Non-secret VPN profile selected by CLI, daemon, or GUI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnProfile {
    tunnel: TunnelProfile,
    route_mode: RouteMode,
    dns_mode: DnsMode,
    company_routes: Vec<Ipv4Cidr>,
    company_domains: Vec<String>,
    local_bypass_cidrs: Vec<Ipv4Cidr>,
}

impl VpnProfile {
    /// Create a profile with conservative split route/DNS defaults.
    pub fn new(name: impl Into<String>, server_url: ServerUrl) -> Result<Self, TunnelProfileError> {
        Ok(Self {
            tunnel: TunnelProfile::new(name, server_url)?,
            route_mode: RouteMode::Split,
            dns_mode: DnsMode::Split,
            company_routes: Vec::new(),
            company_domains: Vec::new(),
            local_bypass_cidrs: Vec::new(),
        })
    }

    /// Create a profile with an explicit OpenConnect reported OS string.
    pub fn with_reported_os(
        name: impl Into<String>,
        server_url: ServerUrl,
        reported_os: impl Into<String>,
    ) -> Result<Self, TunnelProfileError> {
        Ok(Self {
            tunnel: TunnelProfile::with_reported_os(name, server_url, reported_os)?,
            route_mode: RouteMode::Split,
            dns_mode: DnsMode::Split,
            company_routes: Vec::new(),
            company_domains: Vec::new(),
            local_bypass_cidrs: Vec::new(),
        })
    }

    pub fn tunnel(&self) -> &TunnelProfile {
        &self.tunnel
    }

    pub fn route_mode(&self) -> RouteMode {
        self.route_mode
    }

    pub fn dns_mode(&self) -> DnsMode {
        self.dns_mode
    }

    pub fn company_routes(&self) -> &[Ipv4Cidr] {
        &self.company_routes
    }

    pub fn company_domains(&self) -> &[String] {
        &self.company_domains
    }

    pub fn local_bypass_cidrs(&self) -> &[Ipv4Cidr] {
        &self.local_bypass_cidrs
    }

    pub fn with_authgroup(
        mut self,
        authgroup: impl Into<String>,
    ) -> Result<Self, TunnelProfileError> {
        self.tunnel = self.tunnel.with_authgroup(authgroup)?;
        Ok(self)
    }

    pub fn with_username(
        mut self,
        username: impl Into<String>,
    ) -> Result<Self, TunnelProfileError> {
        self.tunnel = self.tunnel.with_username(username)?;
        Ok(self)
    }

    pub fn with_route_mode(mut self, mode: RouteMode) -> Self {
        self.route_mode = mode;
        self
    }

    pub fn with_dns_mode(mut self, mode: DnsMode) -> Self {
        self.dns_mode = mode;
        self
    }

    pub fn with_profile_mode(mut self, mode: ProfileMode) -> Self {
        self.route_mode = mode.route_mode();
        self.dns_mode = mode.dns_mode();
        self
    }

    pub fn with_company_routes(mut self, routes: Vec<Ipv4Cidr>) -> Self {
        self.company_routes = routes;
        self
    }

    pub fn with_company_domains<I, S>(mut self, domains: I) -> Result<Self, TunnelProfileError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.company_domains = domains
            .into_iter()
            .map(|domain| clean_profile_text("company domain", domain.into()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self)
    }

    pub fn with_local_bypass_cidrs(mut self, cidrs: Vec<Ipv4Cidr>) -> Self {
        self.local_bypass_cidrs = cidrs;
        self
    }

    pub fn network_policy(&self) -> NetworkPolicy {
        NetworkPolicy::new(self.route_mode)
            .with_company_routes(self.company_routes.clone())
            .with_local_bypass_cidrs(self.local_bypass_cidrs.clone())
    }
}

/// Tunnel profile validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelProfileError {
    EmptyField { field: &'static str },
    InteriorNul { field: &'static str },
}

impl fmt::Display for TunnelProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField { field } => write!(f, "{field} must not be empty"),
            Self::InteriorNul { field } => write!(f, "{field} must not contain a NUL byte"),
        }
    }
}

impl std::error::Error for TunnelProfileError {}

/// Errors returned while parsing non-secret profile configuration.
pub enum ProfileConfigError {
    DnsMode(oc_oxide_dns::DnsPolicyError),
    InvalidMode { value: String },
    Network(oc_oxide_net::NetworkPolicyError),
    Profile(TunnelProfileError),
    ServerUrl(ServerUrlError),
    Toml(toml::de::Error),
}

impl fmt::Debug for ProfileConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DnsMode(source) => f.debug_tuple("DnsMode").field(&source.to_string()).finish(),
            Self::InvalidMode { value } => {
                f.debug_struct("InvalidMode").field("value", value).finish()
            }
            Self::Network(source) => f.debug_tuple("Network").field(&source.to_string()).finish(),
            Self::Profile(source) => f.debug_tuple("Profile").field(source).finish(),
            Self::ServerUrl(source) => f
                .debug_tuple("ServerUrl")
                .field(&source.to_string())
                .finish(),
            Self::Toml(source) => f.debug_tuple("Toml").field(&source.message()).finish(),
        }
    }
}

impl fmt::Display for ProfileConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DnsMode(source) => write!(f, "invalid DNS mode: {source}"),
            Self::InvalidMode { value } => write!(f, "invalid profile mode {value:?}"),
            Self::Network(source) => write!(f, "invalid network policy: {source}"),
            Self::Profile(source) => write!(f, "invalid profile field: {source}"),
            Self::ServerUrl(source) => write!(f, "{source}"),
            Self::Toml(source) => write!(f, "invalid TOML profile: {}", source.message()),
        }
    }
}

impl std::error::Error for ProfileConfigError {}

impl From<oc_oxide_dns::DnsPolicyError> for ProfileConfigError {
    fn from(source: oc_oxide_dns::DnsPolicyError) -> Self {
        Self::DnsMode(source)
    }
}

impl From<oc_oxide_net::NetworkPolicyError> for ProfileConfigError {
    fn from(source: oc_oxide_net::NetworkPolicyError) -> Self {
        Self::Network(source)
    }
}

impl From<TunnelProfileError> for ProfileConfigError {
    fn from(source: TunnelProfileError) -> Self {
        Self::Profile(source)
    }
}

impl From<ServerUrlError> for ProfileConfigError {
    fn from(source: ServerUrlError) -> Self {
        Self::ServerUrl(source)
    }
}

impl From<toml::de::Error> for ProfileConfigError {
    fn from(source: toml::de::Error) -> Self {
        Self::Toml(source)
    }
}

/// Parse a non-secret TOML VPN profile.
pub fn parse_toml_vpn_profile(name: &str, content: &str) -> Result<VpnProfile, ProfileConfigError> {
    let raw: TomlVpnProfile = toml::from_str(content)?;
    raw.into_vpn_profile(name)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlVpnProfile {
    connection: TomlConnection,
    #[serde(default)]
    company: TomlCompany,
    #[serde(default)]
    local: TomlLocal,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlConnection {
    server: String,
    reported_os: Option<String>,
    authgroup: Option<String>,
    username: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlCompany {
    #[serde(default)]
    domains: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlLocal {
    #[serde(default)]
    bypass: Vec<String>,
}

impl TomlVpnProfile {
    fn into_vpn_profile(self, name: &str) -> Result<VpnProfile, ProfileConfigError> {
        let server = ServerUrl::parse(&self.connection.server)?;
        let mut profile = match self.connection.reported_os {
            Some(reported_os) => VpnProfile::with_reported_os(name, server, reported_os)?,
            None => VpnProfile::new(name, server)?,
        };

        if let Some(authgroup) = self.connection.authgroup {
            profile = profile.with_authgroup(authgroup)?;
        }

        if let Some(username) = self.connection.username {
            profile = profile.with_username(username)?;
        }

        profile = profile.with_company_domains(self.company.domains)?;

        Ok(profile.with_local_bypass_cidrs(parse_cidrs(self.local.bypass)?))
    }
}

fn parse_cidrs(values: Vec<String>) -> Result<Vec<Ipv4Cidr>, ProfileConfigError> {
    values
        .into_iter()
        .map(|value| value.parse::<Ipv4Cidr>().map_err(ProfileConfigError::from))
        .collect()
}

fn clean_profile_text(field: &'static str, value: String) -> Result<String, TunnelProfileError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(TunnelProfileError::EmptyField { field });
    }

    if value.contains('\0') {
        return Err(TunnelProfileError::InteriorNul { field });
    }

    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use oc_oxide_dns::DnsMode;
    use oc_oxide_net::{Ipv4Cidr, RouteMode};

    use super::{
        parse_toml_vpn_profile, InMemoryVpnPasswordVault, ProfileMode, ServerUrl, TunnelProfile,
        VpnPassword, VpnPasswordKey, VpnPasswordVault, VpnProfile, CRATE_ROLE,
    };

    #[test]
    fn documents_config_role() {
        assert!(CRATE_ROLE.contains("configuration"));
    }

    #[test]
    fn builds_deterministic_vpn_password_key_without_secret_material() {
        let key = VpnPasswordKey::for_profile(" office ", Some(" engineering "), Some(" alice "))
            .unwrap();

        assert_eq!(key.service(), "oc-oxide.vpn");
        assert_eq!(key.account(), "office:engineering:alice");
        assert!(!format!("{key:?}").contains("password"));

        let server = ServerUrl::parse("https://vpn.example.test/").unwrap();
        let profile = VpnProfile::new("office", server)
            .unwrap()
            .with_authgroup("engineering")
            .unwrap()
            .with_username("alice")
            .unwrap();

        assert_eq!(VpnPasswordKey::for_vpn_profile(&profile).unwrap(), key);
    }

    #[test]
    fn rejects_invalid_vpn_password_key_parts() {
        assert!(VpnPasswordKey::for_profile(" ", None, None).is_err());
        assert!(VpnPasswordKey::for_profile("office\0", None, None).is_err());
        assert!(VpnPasswordKey::for_profile("office:prod", None, None).is_err());
        assert!(VpnPasswordKey::for_profile("office", Some("eng:prod"), None).is_err());
    }

    #[test]
    fn in_memory_vault_stores_overwrites_and_deletes_vpn_passwords_without_side_effects() {
        let vault = InMemoryVpnPasswordVault::new();
        let key =
            VpnPasswordKey::for_profile("office", Some("engineering"), Some("alice")).unwrap();
        let first = VpnPassword::new("first-secret").unwrap();
        let second = VpnPassword::new("second-secret").unwrap();

        assert!(vault.get_vpn_password(&key).unwrap().is_none());

        vault.set_vpn_password(&key, &first).unwrap();
        assert_eq!(
            vault
                .get_vpn_password(&key)
                .unwrap()
                .unwrap()
                .expose_secret(),
            "first-secret"
        );

        vault.set_vpn_password(&key, &second).unwrap();
        assert_eq!(
            vault
                .get_vpn_password(&key)
                .unwrap()
                .unwrap()
                .expose_secret(),
            "second-secret"
        );

        assert!(vault.delete_vpn_password(&key).unwrap());
        assert!(!vault.delete_vpn_password(&key).unwrap());
        assert!(vault.get_vpn_password(&key).unwrap().is_none());
    }

    #[test]
    fn vpn_password_debug_and_errors_do_not_leak_secret_values() {
        let password = VpnPassword::new("do-not-log").unwrap();
        assert_eq!(password.expose_secret(), "do-not-log");
        assert!(!format!("{password:?}").contains("do-not-log"));
        assert!(format!("{password:?}").contains("<redacted>"));

        assert!(VpnPassword::new("").is_err());
        let err = VpnPassword::new("bad\0secret").unwrap_err();
        assert!(!format!("{err:?}").contains("bad"));
        assert!(!err.to_string().contains("bad"));
    }

    #[test]
    fn parses_https_server_url_without_network() {
        let server = ServerUrl::parse("https://vpn.example.test:555/+CSCOE+/logon.html").unwrap();

        assert_eq!(
            server.as_openconnect_url(),
            "https://vpn.example.test:555/+CSCOE+/logon.html"
        );
        assert_eq!(server.dns_name(), "vpn.example.test");
        assert_eq!(server.port(), 555);
        assert_eq!(server.path(), "/+CSCOE+/logon.html");
        assert_eq!(server.openconnect_url_path(), "+CSCOE+/logon.html");
    }

    #[test]
    fn fills_https_default_port_without_network() {
        let server = ServerUrl::parse("https://vpn.example.test/+CSCOE+/logon.html").unwrap();

        assert_eq!(server.dns_name(), "vpn.example.test");
        assert_eq!(server.port(), 443);
    }

    #[test]
    fn rejects_server_urls_that_could_carry_secrets() {
        assert!(ServerUrl::parse("https://user@vpn.example.test/").is_err());
        assert!(ServerUrl::parse("https://user:password@vpn.example.test/").is_err());
        assert!(ServerUrl::parse("https://vpn.example.test/?token=abc").is_err());
        assert!(ServerUrl::parse("https://vpn.example.test/#token").is_err());
    }

    #[test]
    fn rejects_non_https_server_urls() {
        let err = ServerUrl::parse("http://vpn.example.test/").unwrap_err();

        assert!(err.to_string().contains("expected https"));
    }

    #[test]
    fn builds_non_secret_tunnel_profile() {
        let server = ServerUrl::parse("https://vpn.example.test:555/+CSCOE+/logon.html").unwrap();
        let profile = TunnelProfile::new(" office vpn ", server.clone())
            .unwrap()
            .with_username(" alice ")
            .unwrap()
            .with_authgroup(" engineering ")
            .unwrap();

        assert_eq!(profile.name(), "office vpn");
        assert_eq!(profile.server_url(), &server);
        assert_eq!(profile.reported_os(), "linux");
        assert_eq!(profile.username(), Some("alice"));
        assert_eq!(profile.authgroup(), Some("engineering"));
    }

    #[test]
    fn builds_non_secret_vpn_profile_with_policy_defaults() {
        let server = ServerUrl::parse("https://vpn.example.test/").unwrap();
        let profile = VpnProfile::new("office", server).unwrap();

        assert_eq!(profile.tunnel().name(), "office");
        assert_eq!(profile.route_mode(), RouteMode::Split);
        assert_eq!(profile.dns_mode(), DnsMode::Split);
        assert!(profile.company_routes().is_empty());
        assert!(profile.company_domains().is_empty());
        assert!(profile.local_bypass_cidrs().is_empty());
        assert_eq!(profile.network_policy().route_mode, RouteMode::Split);
    }

    #[test]
    fn vpn_profile_keeps_environment_policy_explicit() {
        let server = ServerUrl::parse("https://vpn.example.test/").unwrap();
        let bypass: Ipv4Cidr = "198.18.0.0/15".parse().unwrap();
        let profile = VpnProfile::with_reported_os("office", server, "linux-64")
            .unwrap()
            .with_username("alice")
            .unwrap()
            .with_authgroup("engineering")
            .unwrap()
            .with_profile_mode(ProfileMode::Full)
            .with_route_mode(RouteMode::Full)
            .with_dns_mode(DnsMode::Off)
            .with_company_routes(vec!["203.0.113.0/25".parse().unwrap()])
            .with_company_domains(["corp.example.test"])
            .unwrap()
            .with_local_bypass_cidrs(vec![bypass]);

        assert_eq!(profile.tunnel().reported_os(), "linux-64");
        assert_eq!(profile.tunnel().username(), Some("alice"));
        assert_eq!(profile.tunnel().authgroup(), Some("engineering"));
        assert_eq!(profile.route_mode(), RouteMode::Full);
        assert_eq!(profile.dns_mode(), DnsMode::Off);
        assert_eq!(profile.company_routes()[0].to_string(), "203.0.113.0/25");
        assert_eq!(profile.company_domains(), &["corp.example.test".to_owned()]);
        assert_eq!(profile.local_bypass_cidrs(), &[bypass]);
        assert_eq!(
            profile.network_policy().company_routes,
            profile.company_routes()
        );
        assert_eq!(profile.network_policy().local_bypass_cidrs, vec![bypass]);
        assert!(!format!("{profile:?}").contains("password"));
    }

    #[test]
    fn parses_toml_profile_with_company_domains_and_local_bypass() {
        let profile = parse_toml_vpn_profile(
            "office",
            r#"
[connection]
server = "https://vpn.example.test:555/"
reported_os = "linux-64"
authgroup = "engineering"
username = "alice"

[company]
domains = ["corp.example.test", "github.example.test"]

[local]
bypass = ["198.18.0.0/15"]
"#,
        )
        .unwrap();

        assert_eq!(profile.tunnel().name(), "office");
        assert_eq!(profile.tunnel().reported_os(), "linux-64");
        assert_eq!(profile.tunnel().authgroup(), Some("engineering"));
        assert_eq!(profile.tunnel().username(), Some("alice"));
        assert_eq!(profile.route_mode(), RouteMode::Split);
        assert_eq!(profile.dns_mode(), DnsMode::Split);
        assert!(profile.company_routes().is_empty());
        assert_eq!(
            profile.company_domains(),
            &[
                "corp.example.test".to_owned(),
                "github.example.test".to_owned()
            ]
        );
        assert_eq!(
            profile
                .local_bypass_cidrs()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["198.18.0.0/15"]
        );
    }

    #[test]
    fn toml_profile_rejects_policy_modes() {
        let err = parse_toml_vpn_profile(
            "office",
            r#"
[connection]
server = "https://vpn.example.test/"

[policy]
mode = "full"
"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown field"));
        assert!(err.to_string().contains("policy"));
    }

    #[test]
    fn toml_profile_rejects_company_routes() {
        let err = parse_toml_vpn_profile(
            "office",
            r#"
[connection]
server = "https://vpn.example.test/"

[company]
routes = ["198.51.100.0/24"]
"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown field"));
        assert!(err.to_string().contains("routes"));
    }

    #[test]
    fn toml_profile_rejects_unknown_secret_fields() {
        let err = parse_toml_vpn_profile(
            "office",
            r#"
[connection]
server = "https://vpn.example.test/"
password = "do-not-store"
"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown field"));
        assert!(err.to_string().contains("password"));
        assert!(!format!("{err:?}").contains("do-not-store"));
    }

    #[test]
    fn builds_tunnel_profile_with_explicit_reported_os() {
        let server = ServerUrl::parse("https://vpn.example.test:555/").unwrap();
        let profile = TunnelProfile::with_reported_os("office", server, " android ").unwrap();

        assert_eq!(profile.reported_os(), "android");
    }

    #[test]
    fn rejects_empty_profile_fields() {
        let server = ServerUrl::parse("https://vpn.example.test:555/").unwrap();

        let err = TunnelProfile::new(" ", server.clone()).unwrap_err();
        assert!(err.to_string().contains("profile name"));

        let err = TunnelProfile::with_reported_os("office", server, " ").unwrap_err();
        assert!(err.to_string().contains("reported OS"));
    }

    #[test]
    fn rejects_nul_in_profile_fields() {
        let server = ServerUrl::parse("https://vpn.example.test:555/").unwrap();

        let err = TunnelProfile::new("bad\0name", server.clone()).unwrap_err();
        assert!(err.to_string().contains("profile name"));

        let err = TunnelProfile::with_reported_os("office", server, "bad\0os").unwrap_err();
        assert!(err.to_string().contains("reported OS"));
    }
}
