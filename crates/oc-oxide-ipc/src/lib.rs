//! IPC protocol.
//!
//! This crate will define the Unix socket JSON-line commands, responses, and
//! event stream shared by the daemon, developer CLI, and desktop UI.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Human-readable crate role used by workspace smoke tests.
pub const CRATE_ROLE: &str = "daemon IPC protocol";

/// One command sent by an unprivileged client to the privileged daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcCommand {
    Connect {
        profile: String,
    },
    ConnectWithProfile {
        profile: String,
        profile_toml: String,
    },
    SubmitAuth(AuthSubmission),
    Disconnect,
    Status,
    Diagnostics,
    TailLogs {
        cursor: Option<String>,
    },
}

/// Transient answers for one auth prompt.
///
/// Submitted values may contain passwords or OTP values. Keep this type out of
/// persistent config and logs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthSubmission {
    pub form_id: String,
    pub fields: Vec<AuthSubmittedField>,
}

impl AuthSubmission {
    pub fn new(
        form_id: impl Into<String>,
        fields: Vec<AuthSubmittedField>,
    ) -> Result<Self, IpcProtocolError> {
        let form_id = clean_ipc_text("form id", form_id.into())?;
        if fields.is_empty() {
            return Err(IpcProtocolError::EmptyFieldList { field: "fields" });
        }

        Ok(Self { form_id, fields })
    }
}

impl fmt::Debug for AuthSubmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthSubmission")
            .field("form_id", &self.form_id)
            .field("fields", &RedactedFields(&self.fields))
            .finish()
    }
}

/// One field submitted for an auth prompt.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthSubmittedField {
    pub id: String,
    pub value: String,
    pub secret: bool,
}

impl AuthSubmittedField {
    pub fn new(
        id: impl Into<String>,
        value: impl Into<String>,
        secret: bool,
    ) -> Result<Self, IpcProtocolError> {
        Ok(Self {
            id: clean_ipc_text("field id", id.into())?,
            value: clean_ipc_text("field value", value.into())?,
            secret,
        })
    }
}

impl fmt::Debug for AuthSubmittedField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value: &dyn fmt::Debug = if self.secret {
            &"<redacted>"
        } else {
            &self.value
        };

        f.debug_struct("AuthSubmittedField")
            .field("id", &self.id)
            .field("value", value)
            .field("secret", &self.secret)
            .finish()
    }
}

struct RedactedFields<'a>(&'a [AuthSubmittedField]);

impl fmt::Debug for RedactedFields<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0).finish()
    }
}

/// One response returned for a command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcResponse {
    Accepted,
    Status(DaemonStatus),
    Diagnostics(DiagnosticsSnapshot),
    LogBatch {
        entries: Vec<LogEntry>,
        next_cursor: Option<String>,
    },
    Error(IpcErrorResponse),
}

/// One event emitted by the daemon to subscribed clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcEvent {
    Progress(ProgressUpdate),
    AuthPrompt(AuthPrompt),
    AuthRejected {
        form_id: Option<String>,
        message: String,
    },
    Connected {
        interface: String,
    },
    NetworkApplied(NetworkApplied),
    Stats(TunnelStats),
    Disconnecting,
    Disconnected {
        reason: DisconnectReason,
    },
    #[serde(rename = "event_error")]
    Error(IpcErrorResponse),
}

/// Current daemon/tunnel state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonState {
    Idle,
    Configuring,
    AwaitingAuth,
    Connecting,
    Connected,
    Disconnecting,
    Disconnected,
    Error,
}

/// Status snapshot returned by `status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub state: DaemonState,
    pub active_profile: Option<String>,
    pub interface: Option<String>,
}

/// Non-secret diagnostics returned by `diagnostics`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsSnapshot {
    pub state: DaemonState,
    pub route_policy: Option<String>,
    pub dns_policy: Option<String>,
    pub last_error: Option<IpcErrorResponse>,
}

/// One non-secret log entry returned by `tail_logs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub level: LogLevel,
    pub message: String,
}

/// Log severity suitable for IPC transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// OpenConnect progress update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressUpdate {
    pub level: i32,
    pub message: String,
}

/// Auth prompt shown to the client without submitted answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthPrompt {
    pub form_id: String,
    pub title: String,
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub fields: Vec<AuthPromptField>,
}

/// One field requested by an auth prompt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthPromptField {
    pub id: String,
    pub label: String,
    pub kind: AuthPromptFieldKind,
    pub required: bool,
}

/// Client-renderable auth field shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthPromptFieldKind {
    Text { secret: bool },
    Password,
    Otp,
    Select { choices: Vec<AuthChoice> },
}

/// One non-secret select choice in an auth prompt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthChoice {
    pub value: String,
    pub label: String,
}

/// Route/DNS application summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkApplied {
    pub route_commands: usize,
    pub dns_commands: usize,
}

/// Tunnel byte/packet counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Why the tunnel reached `disconnected`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisconnectReason {
    UserRequested,
    ServerRequested,
    AuthFailed,
    NetworkError,
    Unknown,
}

/// Non-secret error payload for responses and events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcErrorResponse {
    pub code: String,
    pub message: String,
}

/// Errors returned while encoding or decoding IPC messages.
#[derive(Debug)]
pub enum IpcProtocolError {
    EmptyField { field: &'static str },
    EmptyFieldList { field: &'static str },
    InteriorNul { field: &'static str },
    Json(serde_json::Error),
    MultiLineMessage,
}

impl fmt::Display for IpcProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField { field } => write!(f, "{field} must not be empty"),
            Self::EmptyFieldList { field } => write!(f, "{field} must not be empty"),
            Self::InteriorNul { field } => write!(f, "{field} must not contain a NUL byte"),
            Self::Json(source) => write!(f, "invalid IPC JSON message: {source}"),
            Self::MultiLineMessage => write!(f, "IPC messages must be single JSON lines"),
        }
    }
}

impl std::error::Error for IpcProtocolError {}

impl From<serde_json::Error> for IpcProtocolError {
    fn from(source: serde_json::Error) -> Self {
        Self::Json(source)
    }
}

/// Serialize a command as one JSON line.
pub fn encode_command_line(command: &IpcCommand) -> Result<String, IpcProtocolError> {
    encode_json_line(command)
}

/// Deserialize one JSON-line command.
pub fn decode_command_line(line: &str) -> Result<IpcCommand, IpcProtocolError> {
    decode_json_line(line)
}

/// Serialize an event as one JSON line.
pub fn encode_event_line(event: &IpcEvent) -> Result<String, IpcProtocolError> {
    encode_json_line(event)
}

/// Deserialize one JSON-line event.
pub fn decode_event_line(line: &str) -> Result<IpcEvent, IpcProtocolError> {
    decode_json_line(line)
}

/// Serialize a response as one JSON line.
pub fn encode_response_line(response: &IpcResponse) -> Result<String, IpcProtocolError> {
    encode_json_line(response)
}

/// Deserialize one JSON-line response.
pub fn decode_response_line(line: &str) -> Result<IpcResponse, IpcProtocolError> {
    decode_json_line(line)
}

fn encode_json_line<T: Serialize>(value: &T) -> Result<String, IpcProtocolError> {
    let mut line = serde_json::to_string(value)?;
    if line.contains('\n') || line.contains('\r') {
        return Err(IpcProtocolError::MultiLineMessage);
    }
    line.push('\n');
    Ok(line)
}

fn decode_json_line<T: for<'de> Deserialize<'de>>(line: &str) -> Result<T, IpcProtocolError> {
    if line.trim_end_matches(['\r', '\n']).contains(['\r', '\n']) {
        return Err(IpcProtocolError::MultiLineMessage);
    }

    Ok(serde_json::from_str(line.trim_end_matches(['\r', '\n']))?)
}

fn clean_ipc_text(field: &'static str, value: String) -> Result<String, IpcProtocolError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(IpcProtocolError::EmptyField { field });
    }

    if value.contains('\0') {
        return Err(IpcProtocolError::InteriorNul { field });
    }

    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        decode_command_line, decode_event_line, decode_response_line, encode_command_line,
        encode_event_line, encode_response_line, AuthPrompt, AuthPromptField, AuthPromptFieldKind,
        AuthSubmission, AuthSubmittedField, DaemonState, DaemonStatus, DisconnectReason,
        IpcCommand, IpcEvent, IpcProtocolError, IpcResponse, NetworkApplied, ProgressUpdate,
        CRATE_ROLE,
    };

    #[test]
    fn documents_ipc_role() {
        assert!(CRATE_ROLE.contains("IPC"));
    }

    #[test]
    fn round_trips_connect_command_as_json_line() {
        let command = IpcCommand::Connect {
            profile: "office".to_owned(),
        };

        let line = encode_command_line(&command).unwrap();

        assert!(line.ends_with('\n'));
        assert_eq!(decode_command_line(&line).unwrap(), command);
        assert!(line.contains(r#""type":"connect""#));
    }

    #[test]
    fn round_trips_connect_with_profile_command_as_json_line() {
        let command = IpcCommand::ConnectWithProfile {
            profile: "office".to_owned(),
            profile_toml: "server_url = \"https://vpn.example.test\"\n".to_owned(),
        };

        let line = encode_command_line(&command).unwrap();

        assert!(line.ends_with('\n'));
        assert_eq!(decode_command_line(&line).unwrap(), command);
        assert!(line.contains(r#""type":"connect_with_profile""#));
        assert!(line.contains("https://vpn.example.test"));
    }

    #[test]
    fn redacts_secret_auth_submission_in_debug_output() {
        let submission = AuthSubmission::new(
            "form-1",
            vec![
                AuthSubmittedField::new("username", "alice", false).unwrap(),
                AuthSubmittedField::new("password", "do-not-log", true).unwrap(),
                AuthSubmittedField::new("otp", "123456", true).unwrap(),
            ],
        )
        .unwrap();

        let debug = format!("{submission:?}");

        assert!(debug.contains("alice"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("do-not-log"));
        assert!(!debug.contains("123456"));
    }

    #[test]
    fn round_trips_submit_auth_command_with_transient_values() {
        let command = IpcCommand::SubmitAuth(
            AuthSubmission::new(
                "form-1",
                vec![AuthSubmittedField::new("password", "secret value", true).unwrap()],
            )
            .unwrap(),
        );

        let line = encode_command_line(&command).unwrap();

        assert_eq!(decode_command_line(&line).unwrap(), command);
        assert!(line.contains("secret value"));
    }

    #[test]
    fn round_trips_auth_prompt_event_without_answers() {
        let event = IpcEvent::AuthPrompt(AuthPrompt {
            form_id: "form-1".to_owned(),
            title: "Login".to_owned(),
            message: Some("Enter credentials".to_owned()),
            error: Some("Authentication failed".to_owned()),
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
        });

        let line = encode_event_line(&event).unwrap();

        assert_eq!(decode_event_line(&line).unwrap(), event);
        assert!(line.contains(r#""type":"auth_prompt""#));
        assert!(line.contains(r#""type":"password""#));
    }

    #[test]
    fn round_trips_status_response() {
        let response = IpcResponse::Status(DaemonStatus {
            state: DaemonState::Connected,
            active_profile: Some("office".to_owned()),
            interface: Some("tun0".to_owned()),
        });

        let line = encode_response_line(&response).unwrap();

        assert_eq!(decode_response_line(&line).unwrap(), response);
        assert!(line.contains(r#""state":"connected""#));
    }

    #[test]
    fn round_trips_network_and_disconnect_events() {
        let applied = IpcEvent::NetworkApplied(NetworkApplied {
            route_commands: 4,
            dns_commands: 2,
        });
        let disconnected = IpcEvent::Disconnected {
            reason: DisconnectReason::UserRequested,
        };

        assert_eq!(
            decode_event_line(&encode_event_line(&applied).unwrap()).unwrap(),
            applied
        );
        assert_eq!(
            decode_event_line(&encode_event_line(&disconnected).unwrap()).unwrap(),
            disconnected
        );
    }

    #[test]
    fn event_errors_do_not_overlap_response_errors_on_the_wire() {
        let event = IpcEvent::Error(super::IpcErrorResponse {
            code: "old_tunnel_error".to_owned(),
            message: "previous tunnel failed".to_owned(),
        });
        let response = IpcResponse::Error(super::IpcErrorResponse {
            code: "command_failed".to_owned(),
            message: "command failed".to_owned(),
        });

        let event_line = encode_event_line(&event).unwrap();
        let response_line = encode_response_line(&response).unwrap();

        assert!(event_line.contains(r#""type":"event_error""#));
        assert!(response_line.contains(r#""type":"error""#));
        assert_eq!(decode_event_line(&event_line).unwrap(), event);
        assert!(decode_response_line(&event_line).is_err());
        assert_eq!(decode_response_line(&response_line).unwrap(), response);
    }

    #[test]
    fn rejects_multi_line_json_input() {
        let err = decode_command_line(
            "{\"type\":\"connect\",\"profile\":\"office\"}\n{\"type\":\"status\"}\n",
        )
        .unwrap_err();

        assert!(matches!(err, IpcProtocolError::MultiLineMessage));
    }

    #[test]
    fn rejects_empty_or_nul_auth_submission_parts() {
        assert!(AuthSubmission::new("form-1", Vec::new()).is_err());
        assert!(
            AuthSubmission::new(" ", vec![AuthSubmittedField::new("u", "v", false).unwrap()])
                .is_err()
        );
        assert!(AuthSubmittedField::new("password", "bad\0value", true).is_err());
    }

    #[test]
    fn progress_event_uses_raw_openconnect_level() {
        let event = IpcEvent::Progress(ProgressUpdate {
            level: 7,
            message: "connecting".to_owned(),
        });

        let line = encode_event_line(&event).unwrap();

        assert_eq!(decode_event_line(&line).unwrap(), event);
        assert!(line.contains(r#""level":7"#));
    }
}
