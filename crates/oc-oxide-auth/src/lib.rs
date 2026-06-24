//! Typed authentication event bridge.
//!
//! OpenConnect remains responsible for the AnyConnect authentication exchange.
//! This crate will translate auth forms into Rust events and carry submitted
//! answers back to the tunnel thread without persisting secrets.

use std::ffi::{CStr, CString};
use std::fmt;

use oc_oxide_openconnect_sys as sys;

/// Human-readable crate role used by workspace smoke tests.
pub const CRATE_ROLE: &str = "auth form event bridge";

/// Authentication request emitted by the tunnel thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub form_id: Option<String>,
    pub title: String,
    pub message: Option<String>,
    pub error: Option<String>,
    pub fields: Vec<AuthField>,
}

impl AuthRequest {
    /// Create an auth request without storing any submitted answers.
    pub fn new(title: impl Into<String>, fields: Vec<AuthField>) -> Result<Self, AuthError> {
        let title = clean_auth_text("auth title", title.into())?;
        if fields.is_empty() {
            return Err(AuthError::EmptyFields);
        }

        Ok(Self {
            form_id: None,
            title,
            message: None,
            error: None,
            fields,
        })
    }

    /// Attach a stable form identifier from OpenConnect.
    pub fn with_form_id(mut self, form_id: impl Into<String>) -> Result<Self, AuthError> {
        self.form_id = Some(clean_auth_text("form id", form_id.into())?);
        Ok(self)
    }

    /// Attach non-secret display text from OpenConnect.
    pub fn with_message(mut self, message: impl Into<String>) -> Result<Self, AuthError> {
        self.message = Some(clean_auth_text("auth message", message.into())?);
        Ok(self)
    }

    /// Attach non-secret server-side form error text, such as rejected auth.
    pub fn with_error(mut self, error: impl Into<String>) -> Result<Self, AuthError> {
        self.error = Some(clean_auth_text("auth error", error.into())?);
        Ok(self)
    }
}

/// A single auth input requested from the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthField {
    pub id: String,
    pub label: String,
    pub kind: AuthFieldKind,
    pub required: bool,
}

impl AuthField {
    /// Create a username or other non-secret text field.
    pub fn text(id: impl Into<String>, label: impl Into<String>) -> Result<Self, AuthError> {
        Self::new(id, label, AuthFieldKind::Text { secret: false }, true)
    }

    /// Create a secret password field.
    pub fn password(id: impl Into<String>, label: impl Into<String>) -> Result<Self, AuthError> {
        Self::new(id, label, AuthFieldKind::Password, true)
    }

    /// Create a one-time password field.
    pub fn otp(id: impl Into<String>, label: impl Into<String>) -> Result<Self, AuthError> {
        Self::new(id, label, AuthFieldKind::Otp, true)
    }

    /// Create a select field with non-secret choices.
    pub fn select(
        id: impl Into<String>,
        label: impl Into<String>,
        choices: Vec<AuthChoice>,
    ) -> Result<Self, AuthError> {
        if choices.is_empty() {
            return Err(AuthError::EmptyChoices);
        }

        Self::new(id, label, AuthFieldKind::Select { choices }, true)
    }

    /// Whether a submitted answer for this field must be treated as secret.
    pub fn is_secret(&self) -> bool {
        match self.kind {
            AuthFieldKind::Text { secret } => secret,
            AuthFieldKind::Password | AuthFieldKind::Otp => true,
            AuthFieldKind::Select { .. } => false,
        }
    }

    fn new(
        id: impl Into<String>,
        label: impl Into<String>,
        kind: AuthFieldKind,
        required: bool,
    ) -> Result<Self, AuthError> {
        Ok(Self {
            id: clean_auth_text("field id", id.into())?,
            label: clean_auth_text("field label", label.into())?,
            kind,
            required,
        })
    }
}

/// Auth input shape expected by the UI or IPC consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthFieldKind {
    Text { secret: bool },
    Password,
    Otp,
    Select { choices: Vec<AuthChoice> },
}

/// A non-secret option for a select auth field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChoice {
    pub value: String,
    pub label: String,
}

impl AuthChoice {
    /// Create a non-secret select choice.
    pub fn new(value: impl Into<String>, label: impl Into<String>) -> Result<Self, AuthError> {
        Ok(Self {
            value: clean_auth_text("choice value", value.into())?,
            label: clean_auth_text("choice label", label.into())?,
        })
    }
}

/// Decision returned by the auth UI/daemon for one OpenConnect form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthFormDecision {
    Submit(AuthResponse),
    Cancel,
    NewAuthGroup(AuthResponse),
    Error,
}

/// Result returned from an OpenConnect auth form callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFormResult {
    Submitted,
    Cancelled,
    NewAuthGroup,
    Error,
}

impl AuthFormResult {
    /// Convert a callback result to the public `OC_FORM_RESULT_*` ABI value.
    pub fn to_openconnect_code(self) -> i32 {
        match self {
            Self::Submitted => sys::OC_FORM_RESULT_OK as i32,
            Self::Cancelled => sys::OC_FORM_RESULT_CANCELLED as i32,
            Self::NewAuthGroup => sys::OC_FORM_RESULT_NEWGROUP as i32,
            Self::Error => sys::OC_FORM_RESULT_ERR,
        }
    }

    /// Convert a public `OC_FORM_RESULT_*` ABI value into a typed result.
    pub fn from_openconnect_code(code: i32) -> Result<Self, AuthError> {
        match code {
            code if code == sys::OC_FORM_RESULT_OK as i32 => Ok(Self::Submitted),
            code if code == sys::OC_FORM_RESULT_CANCELLED as i32 => Ok(Self::Cancelled),
            code if code == sys::OC_FORM_RESULT_NEWGROUP as i32 => Ok(Self::NewAuthGroup),
            code if code == sys::OC_FORM_RESULT_ERR => Ok(Self::Error),
            code => Err(AuthError::UnknownFormResult { code }),
        }
    }
}

/// Handler that receives copied auth requests and returns transient answers.
pub trait AuthFormHandler {
    fn maybe_handle_auth_request(&mut self, _request: &AuthRequest) -> Option<AuthFormDecision> {
        None
    }

    fn prepare_auth_request(&mut self, request: AuthRequest) -> AuthRequest {
        request
    }

    fn handle_auth_request(&mut self, request: AuthRequest) -> AuthFormDecision;
}

/// User-submitted answers for one auth form.
///
/// This type is intended to be transient on the tunnel thread. Do not persist
/// it in profile/config files or logs.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthResponse {
    pub form_id: Option<String>,
    pub answers: Vec<AuthAnswer>,
}

impl AuthResponse {
    /// Create a response without persisting submitted values.
    pub fn new(answers: Vec<AuthAnswer>) -> Result<Self, AuthError> {
        if answers.is_empty() {
            return Err(AuthError::EmptyAnswers);
        }

        Ok(Self {
            form_id: None,
            answers,
        })
    }

    /// Attach the OpenConnect form identifier being answered.
    pub fn with_form_id(mut self, form_id: impl Into<String>) -> Result<Self, AuthError> {
        self.form_id = Some(clean_auth_text("form id", form_id.into())?);
        Ok(self)
    }
}

impl fmt::Debug for AuthResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthResponse")
            .field("form_id", &self.form_id)
            .field("answers", &self.answers)
            .finish()
    }
}

/// One submitted auth answer.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthAnswer {
    pub field_id: String,
    pub value: AuthAnswerValue,
}

impl AuthAnswer {
    /// Create a non-secret text/select answer.
    pub fn text(field_id: impl Into<String>, value: impl Into<String>) -> Result<Self, AuthError> {
        Ok(Self {
            field_id: clean_auth_text("field id", field_id.into())?,
            value: AuthAnswerValue::Text(clean_auth_text("answer value", value.into())?),
        })
    }

    /// Create a secret password/OTP answer.
    pub fn secret(
        field_id: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, AuthError> {
        Ok(Self {
            field_id: clean_auth_text("field id", field_id.into())?,
            value: AuthAnswerValue::Secret(SecretAnswer::new(value)?),
        })
    }

    /// Whether this answer value must be redacted.
    pub fn is_secret(&self) -> bool {
        self.value.is_secret()
    }
}

impl fmt::Debug for AuthAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthAnswer")
            .field("field_id", &self.field_id)
            .field("value", &self.value)
            .finish()
    }
}

/// Submitted answer value.
#[derive(Clone, PartialEq, Eq)]
pub enum AuthAnswerValue {
    Text(String),
    Secret(SecretAnswer),
}

impl AuthAnswerValue {
    fn as_str(&self) -> &str {
        match self {
            Self::Text(value) => value,
            Self::Secret(value) => value.expose_secret(),
        }
    }

    fn is_secret(&self) -> bool {
        matches!(self, Self::Secret(_))
    }
}

impl fmt::Debug for AuthAnswerValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(value) => f.debug_tuple("Text").field(value).finish(),
            Self::Secret(value) => f.debug_tuple("Secret").field(value).finish(),
        }
    }
}

/// Secret auth answer value with redacted debug output.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretAnswer(String);

impl SecretAnswer {
    /// Create a secret answer.
    pub fn new(value: impl Into<String>) -> Result<Self, AuthError> {
        Ok(Self(clean_auth_text("secret answer", value.into())?))
    }

    /// Expose the secret only for immediate submission to libopenconnect.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Auth event validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    EmptyField { field: &'static str },
    EmptyFields,
    EmptyAnswers,
    EmptyChoices,
    InteriorNul { field: &'static str },
    NullForm,
    NullFieldName,
    UnsupportedFieldType { field_id: String, field_type: i32 },
    UnknownFormResult { code: i32 },
    FormIdMismatch { expected: String, actual: String },
    UnknownAnswerField { field_id: String },
    SetOptionValueFailed { field_id: String, code: i32 },
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField { field } => write!(f, "{field} must not be empty"),
            Self::EmptyFields => write!(f, "auth request must include at least one field"),
            Self::EmptyAnswers => write!(f, "auth response must include at least one answer"),
            Self::EmptyChoices => write!(f, "select auth field must include at least one choice"),
            Self::InteriorNul { field } => write!(f, "{field} must not contain a NUL byte"),
            Self::NullForm => write!(f, "auth form pointer must not be NULL"),
            Self::NullFieldName => write!(f, "auth form field is missing its name"),
            Self::UnsupportedFieldType {
                field_id,
                field_type,
            } => {
                write!(
                    f,
                    "auth field {field_id:?} has unsupported type {field_type}"
                )
            }
            Self::UnknownFormResult { code } => {
                write!(f, "unknown OpenConnect auth form result {code}")
            }
            Self::FormIdMismatch { expected, actual } => {
                write!(
                    f,
                    "auth response form id {actual:?} does not match request form id {expected:?}"
                )
            }
            Self::UnknownAnswerField { field_id } => {
                write!(f, "auth response references unknown field {field_id:?}")
            }
            Self::SetOptionValueFailed { field_id, code } => {
                write!(
                    f,
                    "openconnect_set_option_value failed for field {field_id:?} with {code}"
                )
            }
        }
    }
}

impl std::error::Error for AuthError {}

/// Copy an OpenConnect auth form into a Rust-owned auth request.
///
/// The raw form and linked option list are owned by libopenconnect. This
/// function copies display metadata and field descriptors only; submitted
/// answers are intentionally not stored in the returned request.
pub unsafe fn auth_request_from_openconnect_form(
    form: *const sys::oc_auth_form,
) -> Result<AuthRequest, AuthError> {
    let form = form.as_ref().ok_or(AuthError::NullForm)?;
    let title = cstr_nonempty(form.banner)
        .or_else(|| cstr_nonempty(form.message))
        .unwrap_or_else(|| "VPN authentication".to_owned());
    let mut request = AuthRequest::new(title.clone(), auth_fields_from_openconnect(form.opts)?)?;

    if let Some(form_id) = cstr_nonempty(form.auth_id) {
        request = request.with_form_id(form_id)?;
    }

    if let Some(message) = cstr_nonempty(form.message) {
        if message != title {
            request = request.with_message(message)?;
        }
    }

    if let Some(error) = cstr_nonempty(form.error) {
        request = request.with_error(error)?;
    }

    Ok(request)
}

/// Apply submitted answers to an OpenConnect auth form.
///
/// This writes values into libopenconnect's transient form structure using
/// `openconnect_set_option_value`. It does not persist answers in oc-oxide
/// config or profile files.
pub unsafe fn apply_auth_response_to_openconnect_form(
    form: *mut sys::oc_auth_form,
    response: &AuthResponse,
) -> Result<(), AuthError> {
    let form = form.as_mut().ok_or(AuthError::NullForm)?;

    for answer in &response.answers {
        let opt = find_openconnect_form_option(form.opts, &answer.field_id).ok_or_else(|| {
            AuthError::UnknownAnswerField {
                field_id: answer.field_id.clone(),
            }
        })?;
        let value = CString::new(answer.value.as_str()).map_err(|_| AuthError::InteriorNul {
            field: "answer value",
        })?;
        let rc = sys::openconnect_set_option_value(opt, value.as_ptr());
        if rc != 0 {
            return Err(AuthError::SetOptionValueFailed {
                field_id: answer.field_id.clone(),
                code: rc,
            });
        }
    }

    Ok(())
}

/// Process one raw OpenConnect auth form through a Rust auth handler.
///
/// The handler receives a Rust-owned request with no submitted answers. If it
/// returns a submit decision, the transient response is written back into the
/// raw OpenConnect form before returning `Submitted`.
pub unsafe fn process_openconnect_auth_form_with_handler(
    form: *mut sys::oc_auth_form,
    handler: &mut impl AuthFormHandler,
) -> Result<AuthFormResult, AuthError> {
    let request = auth_request_from_openconnect_form(form)?;
    let request_form_id = request.form_id.clone();

    match handler.handle_auth_request(request) {
        AuthFormDecision::Submit(response) => {
            ensure_response_matches_request(request_form_id.as_deref(), &response)?;
            apply_auth_response_to_openconnect_form(form, &response)?;
            Ok(AuthFormResult::Submitted)
        }
        AuthFormDecision::Cancel => Ok(AuthFormResult::Cancelled),
        AuthFormDecision::NewAuthGroup(response) => {
            ensure_response_matches_request(request_form_id.as_deref(), &response)?;
            apply_auth_response_to_openconnect_form(form, &response)?;
            Ok(AuthFormResult::NewAuthGroup)
        }
        AuthFormDecision::Error => Ok(AuthFormResult::Error),
    }
}

unsafe fn auth_fields_from_openconnect(
    mut opt: *mut sys::oc_form_opt,
) -> Result<Vec<AuthField>, AuthError> {
    let mut fields = Vec::new();

    while !opt.is_null() {
        let field = &*opt;
        opt = field.next;

        if field.flags & sys::OC_FORM_OPT_IGNORE != 0 {
            continue;
        }

        let Some(id) = cstr_nonempty(field.name) else {
            return Err(AuthError::NullFieldName);
        };
        let label = cstr_nonempty(field.label).unwrap_or_else(|| id.clone());

        match field.type_ {
            field_type
                if field_type == sys::OC_FORM_OPT_TEXT as i32
                    || field_type == sys::OC_FORM_OPT_SSO_USER as i32 =>
            {
                fields.push(AuthField::text(id, label)?);
            }
            field_type if field_type == sys::OC_FORM_OPT_PASSWORD as i32 => {
                fields.push(AuthField::password(id, label)?);
            }
            field_type
                if field_type == sys::OC_FORM_OPT_TOKEN as i32
                    || field_type == sys::OC_FORM_OPT_SSO_TOKEN as i32 =>
            {
                fields.push(AuthField::otp(id, label)?);
            }
            field_type if field_type == sys::OC_FORM_OPT_SELECT as i32 => {
                let select = &*(field as *const sys::oc_form_opt as *const sys::oc_form_opt_select);
                fields.push(AuthField::select(
                    id,
                    label,
                    auth_choices_from_openconnect(select)?,
                )?);
            }
            field_type if field_type == sys::OC_FORM_OPT_HIDDEN as i32 => {}
            field_type => {
                return Err(AuthError::UnsupportedFieldType {
                    field_id: id,
                    field_type,
                });
            }
        }
    }

    Ok(fields)
}

unsafe fn find_openconnect_form_option(
    mut opt: *mut sys::oc_form_opt,
    field_id: &str,
) -> Option<*mut sys::oc_form_opt> {
    while !opt.is_null() {
        let field = &*opt;
        if cstr_nonempty(field.name).as_deref() == Some(field_id) {
            return Some(opt);
        }
        opt = field.next;
    }

    None
}

fn ensure_response_matches_request(
    request_form_id: Option<&str>,
    response: &AuthResponse,
) -> Result<(), AuthError> {
    match (request_form_id, response.form_id.as_deref()) {
        (Some(expected), Some(actual)) if expected != actual => Err(AuthError::FormIdMismatch {
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        }),
        _ => Ok(()),
    }
}

unsafe fn auth_choices_from_openconnect(
    select: &sys::oc_form_opt_select,
) -> Result<Vec<AuthChoice>, AuthError> {
    if select.nr_choices <= 0 || select.choices.is_null() {
        return Err(AuthError::EmptyChoices);
    }

    let choices = std::slice::from_raw_parts(select.choices, select.nr_choices as usize);
    choices
        .iter()
        .filter_map(|choice| choice.as_ref())
        .map(|choice| {
            let value = cstr_nonempty(choice.name).ok_or(AuthError::NullFieldName)?;
            let label = cstr_nonempty(choice.label).unwrap_or_else(|| value.clone());
            AuthChoice::new(value, label)
        })
        .collect()
}

fn clean_auth_text(field: &'static str, value: String) -> Result<String, AuthError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(AuthError::EmptyField { field });
    }

    if value.contains('\0') {
        return Err(AuthError::InteriorNul { field });
    }

    Ok(value.to_owned())
}

fn cstr_nonempty(ptr: *const std::os::raw::c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }

    let value = unsafe { CStr::from_ptr(ptr) }.to_string_lossy();
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::{CStr, CString};
    use std::ptr;

    use super::{
        apply_auth_response_to_openconnect_form, auth_request_from_openconnect_form, AuthAnswer,
        AuthChoice, AuthError, AuthField, AuthFieldKind, AuthFormDecision, AuthFormHandler,
        AuthFormResult, AuthRequest, AuthResponse, CRATE_ROLE,
    };
    use oc_oxide_openconnect_sys as sys;

    #[test]
    fn documents_auth_role() {
        assert!(CRATE_ROLE.contains("auth"));
    }

    #[test]
    fn builds_auth_request_without_answers() {
        let request = AuthRequest::new(
            "VPN Login",
            vec![
                AuthField::text("username", "Username").unwrap(),
                AuthField::password("password", "Password").unwrap(),
                AuthField::otp("otp", "One-time password").unwrap(),
            ],
        )
        .unwrap()
        .with_form_id("main")
        .unwrap()
        .with_message("Enter credentials")
        .unwrap();

        assert_eq!(request.form_id.as_deref(), Some("main"));
        assert_eq!(request.title, "VPN Login");
        assert_eq!(request.message.as_deref(), Some("Enter credentials"));
        assert_eq!(request.fields.len(), 3);
        assert!(!request.fields[0].is_secret());
        assert!(request.fields[1].is_secret());
        assert!(request.fields[2].is_secret());
    }

    #[test]
    fn builds_non_secret_select_field() {
        let field = AuthField::select(
            "group",
            "Group",
            vec![
                AuthChoice::new("engineering", "Engineering").unwrap(),
                AuthChoice::new("ops", "Operations").unwrap(),
            ],
        )
        .unwrap();

        assert!(!field.is_secret());
        let AuthFieldKind::Select { choices } = field.kind else {
            panic!("expected select field");
        };
        assert_eq!(choices.len(), 2);
        assert_eq!(choices[0].value, "engineering");
    }

    #[test]
    fn maps_public_openconnect_auth_form_results() {
        let cases = [
            (AuthFormResult::Submitted, sys::OC_FORM_RESULT_OK as i32),
            (
                AuthFormResult::Cancelled,
                sys::OC_FORM_RESULT_CANCELLED as i32,
            ),
            (
                AuthFormResult::NewAuthGroup,
                sys::OC_FORM_RESULT_NEWGROUP as i32,
            ),
            (AuthFormResult::Error, sys::OC_FORM_RESULT_ERR),
        ];

        for (result, code) in cases {
            assert_eq!(result.to_openconnect_code(), code);
            assert_eq!(AuthFormResult::from_openconnect_code(code), Ok(result));
        }
    }

    #[test]
    fn rejects_unknown_openconnect_auth_form_result() {
        assert!(AuthFormResult::from_openconnect_code(12345).is_err());
    }

    #[test]
    fn rejects_empty_auth_shapes() {
        assert!(AuthRequest::new("VPN Login", Vec::new()).is_err());
        assert!(AuthResponse::new(Vec::new()).is_err());
        assert!(AuthField::select("group", "Group", Vec::new()).is_err());
        assert!(AuthField::text(" ", "Username").is_err());
        assert!(AuthField::text("username", " ").is_err());
    }

    #[test]
    fn rejects_nul_in_auth_text() {
        assert!(AuthField::text("user\0name", "Username").is_err());
        assert!(AuthChoice::new("eng\0", "Engineering").is_err());
        assert!(AuthRequest::new(
            "VPN\0Login",
            vec![AuthField::text("u", "Username").unwrap()]
        )
        .is_err());
    }

    #[test]
    fn translates_openconnect_auth_form_without_answers() {
        let banner = CString::new("VPN Login").unwrap();
        let message = CString::new("Enter credentials").unwrap();
        let auth_id = CString::new("main").unwrap();
        let user_name = CString::new("username").unwrap();
        let user_label = CString::new("Username").unwrap();
        let pass_name = CString::new("password").unwrap();
        let pass_label = CString::new("Password").unwrap();
        let otp_name = CString::new("otp").unwrap();
        let otp_label = CString::new("One-time password").unwrap();
        let error = CString::new("Authentication failed").unwrap();

        let mut user = raw_opt(sys::OC_FORM_OPT_TEXT as i32, &user_name, &user_label);
        let mut password = raw_opt(sys::OC_FORM_OPT_PASSWORD as i32, &pass_name, &pass_label);
        let mut otp = raw_opt(sys::OC_FORM_OPT_TOKEN as i32, &otp_name, &otp_label);
        user.next = &mut *password;
        password.next = &mut *otp;

        let mut form = raw_form(&banner, Some(&message), Some(&auth_id), &mut *user);
        form.error = error.as_ptr() as *mut _;

        let request = unsafe { auth_request_from_openconnect_form(&mut *form) }.unwrap();
        assert_eq!(request.form_id.as_deref(), Some("main"));
        assert_eq!(request.title, "VPN Login");
        assert_eq!(request.message.as_deref(), Some("Enter credentials"));
        assert_eq!(request.error.as_deref(), Some("Authentication failed"));
        assert_eq!(request.fields.len(), 3);
        assert_eq!(request.fields[0].id, "username");
        assert!(!request.fields[0].is_secret());
        assert!(request.fields[1].is_secret());
        assert!(request.fields[2].is_secret());
    }

    #[test]
    fn translates_openconnect_select_auth_field() {
        let banner = CString::new("VPN Login").unwrap();
        let select_name = CString::new("group").unwrap();
        let select_label = CString::new("Group").unwrap();
        let eng_value = CString::new("engineering").unwrap();
        let eng_label = CString::new("Engineering").unwrap();
        let ops_value = CString::new("ops").unwrap();
        let ops_label = CString::new("Operations").unwrap();

        let mut engineering = raw_choice(&eng_value, &eng_label);
        let mut ops = raw_choice(&ops_value, &ops_label);
        let mut choice_ptrs = vec![&mut *engineering as *mut _, &mut *ops as *mut _];
        let mut select = raw_select(&select_name, &select_label, &mut choice_ptrs);
        let mut form = raw_form(&banner, None, None, &mut select.form);

        let request = unsafe { auth_request_from_openconnect_form(&mut *form) }.unwrap();
        assert_eq!(request.fields.len(), 1);
        assert!(!request.fields[0].is_secret());
        let AuthFieldKind::Select { choices } = &request.fields[0].kind else {
            panic!("expected select field");
        };
        assert_eq!(choices.len(), 2);
        assert_eq!(choices[0].value, "engineering");
        assert_eq!(choices[1].label, "Operations");
    }

    #[test]
    fn ignores_hidden_openconnect_auth_fields() {
        let banner = CString::new("VPN Login").unwrap();
        let hidden_name = CString::new("csrf").unwrap();
        let hidden_label = CString::new("csrf").unwrap();
        let user_name = CString::new("username").unwrap();
        let user_label = CString::new("Username").unwrap();

        let mut hidden = raw_opt(sys::OC_FORM_OPT_HIDDEN as i32, &hidden_name, &hidden_label);
        let mut user = raw_opt(sys::OC_FORM_OPT_TEXT as i32, &user_name, &user_label);
        hidden.next = &mut *user;
        let mut form = raw_form(&banner, None, None, &mut *hidden);

        let request = unsafe { auth_request_from_openconnect_form(&mut *form) }.unwrap();
        assert_eq!(request.fields.len(), 1);
        assert_eq!(request.fields[0].id, "username");
    }

    #[test]
    fn rejects_null_openconnect_auth_form() {
        assert!(unsafe { auth_request_from_openconnect_form(ptr::null()) }.is_err());
    }

    #[test]
    fn redacts_secret_auth_answers_in_debug() {
        let response = AuthResponse::new(vec![
            AuthAnswer::text("username", "alice").unwrap(),
            AuthAnswer::secret("password", "not-a-real-password").unwrap(),
        ])
        .unwrap()
        .with_form_id("main")
        .unwrap();

        assert!(!response.answers[0].is_secret());
        assert!(response.answers[1].is_secret());
        let debug = format!("{response:?}");
        assert!(debug.contains("alice"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("not-a-real-password"));
    }

    #[test]
    fn applies_auth_response_to_openconnect_form() {
        let banner = CString::new("VPN Login").unwrap();
        let user_name = CString::new("username").unwrap();
        let user_label = CString::new("Username").unwrap();
        let pass_name = CString::new("password").unwrap();
        let pass_label = CString::new("Password").unwrap();
        let group_name = CString::new("group").unwrap();
        let group_label = CString::new("Group").unwrap();
        let eng_value = CString::new("engineering").unwrap();
        let eng_label = CString::new("Engineering").unwrap();

        let mut user = raw_opt(sys::OC_FORM_OPT_TEXT as i32, &user_name, &user_label);
        let mut password = raw_opt(sys::OC_FORM_OPT_PASSWORD as i32, &pass_name, &pass_label);
        let mut engineering = raw_choice(&eng_value, &eng_label);
        let mut choice_ptrs = vec![&mut *engineering as *mut _];
        let mut group = raw_select(&group_name, &group_label, &mut choice_ptrs);
        user.next = &mut *password;
        password.next = &mut group.form;
        let mut form = raw_form(&banner, None, None, &mut *user);
        let response = AuthResponse::new(vec![
            AuthAnswer::text("username", "alice").unwrap(),
            AuthAnswer::secret("password", "not-a-real-password").unwrap(),
            AuthAnswer::text("group", "engineering").unwrap(),
        ])
        .unwrap();

        unsafe {
            apply_auth_response_to_openconnect_form(&mut *form, &response).unwrap();
        }

        assert_eq!(raw_value(&user), Some("alice".to_owned()));
        assert_eq!(raw_value(&password), Some("not-a-real-password".to_owned()));
        assert_eq!(raw_value(&group.form), Some("engineering".to_owned()));
    }

    #[test]
    fn rejects_auth_response_for_unknown_field() {
        let banner = CString::new("VPN Login").unwrap();
        let user_name = CString::new("username").unwrap();
        let user_label = CString::new("Username").unwrap();
        let mut user = raw_opt(sys::OC_FORM_OPT_TEXT as i32, &user_name, &user_label);
        let mut form = raw_form(&banner, None, None, &mut *user);
        let response =
            AuthResponse::new(vec![AuthAnswer::text("missing", "alice").unwrap()]).unwrap();

        assert!(unsafe { apply_auth_response_to_openconnect_form(&mut *form, &response) }.is_err());
    }

    #[test]
    fn processes_openconnect_auth_form_submit_decision() {
        let banner = CString::new("VPN Login").unwrap();
        let auth_id = CString::new("main").unwrap();
        let user_name = CString::new("username").unwrap();
        let user_label = CString::new("Username").unwrap();
        let pass_name = CString::new("password").unwrap();
        let pass_label = CString::new("Password").unwrap();

        let mut user = raw_opt(sys::OC_FORM_OPT_TEXT as i32, &user_name, &user_label);
        let mut password = raw_opt(sys::OC_FORM_OPT_PASSWORD as i32, &pass_name, &pass_label);
        user.next = &mut *password;
        let mut form = raw_form(&banner, None, Some(&auth_id), &mut *user);
        let mut handler = StaticAuthHandler::new(AuthFormDecision::Submit(
            AuthResponse::new(vec![
                AuthAnswer::text("username", "alice").unwrap(),
                AuthAnswer::secret("password", "not-a-real-password").unwrap(),
            ])
            .unwrap()
            .with_form_id("main")
            .unwrap(),
        ));

        let result =
            unsafe { super::process_openconnect_auth_form_with_handler(&mut *form, &mut handler) }
                .unwrap();

        assert_eq!(result, AuthFormResult::Submitted);
        assert_eq!(raw_value(&user), Some("alice".to_owned()));
        assert_eq!(raw_value(&password), Some("not-a-real-password".to_owned()));
        assert_eq!(handler.requests.len(), 1);
        assert_eq!(handler.requests[0].form_id.as_deref(), Some("main"));
        assert_eq!(handler.requests[0].fields.len(), 2);
    }

    #[test]
    fn processes_openconnect_new_auth_group_decision() {
        let banner = CString::new("VPN Login").unwrap();
        let auth_id = CString::new("main").unwrap();
        let group_name = CString::new("group_list").unwrap();
        let group_label = CString::new("Group").unwrap();
        let eng_value = CString::new("engineering").unwrap();
        let eng_label = CString::new("Engineering").unwrap();
        let ops_value = CString::new("ops").unwrap();
        let ops_label = CString::new("Operations").unwrap();

        let mut engineering = raw_choice(&eng_value, &eng_label);
        let mut ops = raw_choice(&ops_value, &ops_label);
        let mut choice_ptrs = vec![&mut *engineering as *mut _, &mut *ops as *mut _];
        let mut group = raw_select(&group_name, &group_label, &mut choice_ptrs);
        let mut form = raw_form(&banner, None, Some(&auth_id), &mut group.form);
        form.authgroup_opt = &mut *group;
        let mut handler = StaticAuthHandler::new(AuthFormDecision::NewAuthGroup(
            AuthResponse::new(vec![AuthAnswer::text("group_list", "engineering").unwrap()])
                .unwrap()
                .with_form_id("main")
                .unwrap(),
        ));

        let result =
            unsafe { super::process_openconnect_auth_form_with_handler(&mut *form, &mut handler) }
                .unwrap();

        assert_eq!(result, AuthFormResult::NewAuthGroup);
        assert_eq!(raw_value(&group.form), Some("engineering".to_owned()));
        assert_eq!(handler.requests.len(), 1);
        assert_eq!(handler.requests[0].fields.len(), 1);
        let AuthFieldKind::Select { choices } = &handler.requests[0].fields[0].kind else {
            panic!("expected authgroup select field");
        };
        assert_eq!(choices.len(), 2);
    }

    #[test]
    fn returns_cancelled_auth_form_decision_without_writing_answers() {
        let banner = CString::new("VPN Login").unwrap();
        let user_name = CString::new("username").unwrap();
        let user_label = CString::new("Username").unwrap();
        let mut user = raw_opt(sys::OC_FORM_OPT_TEXT as i32, &user_name, &user_label);
        let mut form = raw_form(&banner, None, None, &mut *user);
        let mut handler = StaticAuthHandler::new(AuthFormDecision::Cancel);

        let result =
            unsafe { super::process_openconnect_auth_form_with_handler(&mut *form, &mut handler) }
                .unwrap();

        assert_eq!(result, AuthFormResult::Cancelled);
        assert_eq!(raw_value(&user), None);
        assert_eq!(handler.requests.len(), 1);
    }

    #[test]
    fn rejects_auth_response_with_mismatched_form_id_before_writing_answers() {
        let banner = CString::new("VPN Login").unwrap();
        let auth_id = CString::new("main").unwrap();
        let user_name = CString::new("username").unwrap();
        let user_label = CString::new("Username").unwrap();
        let mut user = raw_opt(sys::OC_FORM_OPT_TEXT as i32, &user_name, &user_label);
        let mut form = raw_form(&banner, None, Some(&auth_id), &mut *user);
        let mut handler = StaticAuthHandler::new(AuthFormDecision::Submit(
            AuthResponse::new(vec![AuthAnswer::text("username", "alice").unwrap()])
                .unwrap()
                .with_form_id("other")
                .unwrap(),
        ));

        let error =
            unsafe { super::process_openconnect_auth_form_with_handler(&mut *form, &mut handler) }
                .unwrap_err();

        assert!(matches!(error, AuthError::FormIdMismatch { .. }));
        assert_eq!(raw_value(&user), None);
    }

    struct StaticAuthHandler {
        decision: Option<AuthFormDecision>,
        requests: Vec<AuthRequest>,
    }

    impl StaticAuthHandler {
        fn new(decision: AuthFormDecision) -> Self {
            Self {
                decision: Some(decision),
                requests: Vec::new(),
            }
        }
    }

    impl AuthFormHandler for StaticAuthHandler {
        fn handle_auth_request(&mut self, request: AuthRequest) -> AuthFormDecision {
            self.requests.push(request);
            self.decision.take().unwrap()
        }
    }

    fn raw_opt(field_type: i32, name: &CString, label: &CString) -> Box<sys::oc_form_opt> {
        let mut opt = Box::new(unsafe { std::mem::zeroed::<sys::oc_form_opt>() });
        opt.type_ = field_type;
        opt.name = name.as_ptr() as *mut _;
        opt.label = label.as_ptr() as *mut _;
        opt
    }

    fn raw_choice(name: &CString, label: &CString) -> Box<sys::oc_choice> {
        let mut choice = Box::new(unsafe { std::mem::zeroed::<sys::oc_choice>() });
        choice.name = name.as_ptr() as *mut _;
        choice.label = label.as_ptr() as *mut _;
        choice
    }

    fn raw_select(
        name: &CString,
        label: &CString,
        choices: &mut Vec<*mut sys::oc_choice>,
    ) -> Box<sys::oc_form_opt_select> {
        let mut select = Box::new(unsafe { std::mem::zeroed::<sys::oc_form_opt_select>() });
        select.form.type_ = sys::OC_FORM_OPT_SELECT as i32;
        select.form.name = name.as_ptr() as *mut _;
        select.form.label = label.as_ptr() as *mut _;
        select.nr_choices = choices.len() as i32;
        select.choices = choices.as_mut_ptr();
        select
    }

    fn raw_form(
        banner: &CString,
        message: Option<&CString>,
        auth_id: Option<&CString>,
        opts: *mut sys::oc_form_opt,
    ) -> Box<sys::oc_auth_form> {
        let mut form = Box::new(unsafe { std::mem::zeroed::<sys::oc_auth_form>() });
        form.banner = banner.as_ptr() as *mut _;
        form.message = message.map_or(ptr::null_mut(), |value| value.as_ptr() as *mut _);
        form.auth_id = auth_id.map_or(ptr::null_mut(), |value| value.as_ptr() as *mut _);
        form.opts = opts;
        form
    }

    fn raw_value(opt: &sys::oc_form_opt) -> Option<String> {
        if opt._value.is_null() {
            return None;
        }

        Some(
            unsafe { CStr::from_ptr(opt._value) }
                .to_string_lossy()
                .into_owned(),
        )
    }
}
