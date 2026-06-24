use std::collections::VecDeque;
use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::Mutex;

use oc_oxide_auth::{
    AuthAnswer, AuthFieldKind, AuthFormDecision, AuthFormHandler, AuthRequest, AuthResponse,
};
use oc_oxide_config::{ServerUrl, TunnelProfile};
use oc_oxide_openconnect_sys as sys;
use oc_oxide_tunnel::{
    install_openconnect_callback_progress_hook, openconnect_auth_callback, AuthCallbackContext,
    OpenConnectSession, TunnelEvent, TunnelState, VecEventSink,
};

static CALLBACK_PROGRESS_HOOK_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn combined_context_routes_progress_and_auth_submit_without_network() {
    let _lock = CALLBACK_PROGRESS_HOOK_TEST_LOCK.lock().unwrap();
    let mut sink = VecEventSink::new();
    let mut handler = QueueAuthHandler::new(vec![AuthFormDecision::Submit(
        AuthResponse::new(vec![
            AuthAnswer::text("username", "alice").unwrap(),
            AuthAnswer::secret("password", "not-a-real-password").unwrap(),
        ])
        .unwrap()
        .with_form_id("main")
        .unwrap(),
    )]);
    let mut context = AuthCallbackContext::new(&mut sink, &mut handler);
    let _guard = install_openconnect_callback_progress_hook::<VecEventSink, QueueAuthHandler>();
    let progress = CString::new("configured").unwrap();

    unsafe {
        sys::oc_oxide_progress_sink(context.as_privdata(), 1, progress.as_ptr());
    }

    let banner = CString::new("VPN Login").unwrap();
    let auth_id = CString::new("main").unwrap();
    let user_name = CString::new("username").unwrap();
    let user_label = CString::new("Username").unwrap();
    let pass_name = CString::new("password").unwrap();
    let pass_label = CString::new("Password").unwrap();
    let mut user = raw_opt(sys::OC_FORM_OPT_TEXT as i32, &user_name, &user_label);
    let mut password = raw_opt(sys::OC_FORM_OPT_PASSWORD as i32, &pass_name, &pass_label);
    user.next = &mut *password;
    let mut form = raw_form(&banner, Some(&auth_id), &mut *user);

    let rc = unsafe {
        openconnect_auth_callback::<VecEventSink, QueueAuthHandler>(
            context.as_privdata(),
            &mut *form,
        )
    };

    assert_eq!(rc, sys::OC_FORM_RESULT_OK as i32);
    assert_eq!(raw_value(&user), Some("alice".to_owned()));
    assert_eq!(raw_value(&password), Some("not-a-real-password".to_owned()));
    drop(context);

    assert_eq!(handler.requests.len(), 1);
    let events = sink.into_events();
    assert_eq!(events.len(), 3);
    assert!(matches!(events[0], TunnelEvent::Progress(_)));
    assert_eq!(
        events[1],
        TunnelEvent::StateChanged(TunnelState::AwaitingAuth)
    );
    let TunnelEvent::AuthRequired(request) = &events[2] else {
        panic!("expected auth request event");
    };
    assert_eq!(request.form_id.as_deref(), Some("main"));
    assert_eq!(request.fields.len(), 2);
    assert!(request.fields[1].is_secret());
}

#[test]
fn handles_username_password_then_otp_prompts_without_network() {
    let mut sink = VecEventSink::new();
    let mut handler = QueueAuthHandler::new(vec![
        AuthFormDecision::Submit(
            AuthResponse::new(vec![
                AuthAnswer::text("username", "alice").unwrap(),
                AuthAnswer::secret("password", "not-a-real-password").unwrap(),
            ])
            .unwrap()
            .with_form_id("primary")
            .unwrap(),
        ),
        AuthFormDecision::Submit(
            AuthResponse::new(vec![AuthAnswer::secret("otp", "123456").unwrap()])
                .unwrap()
                .with_form_id("otp-step")
                .unwrap(),
        ),
    ]);
    let mut context = AuthCallbackContext::new(&mut sink, &mut handler);

    let banner = CString::new("VPN Login").unwrap();
    let primary_id = CString::new("primary").unwrap();
    let user_name = CString::new("username").unwrap();
    let user_label = CString::new("Username").unwrap();
    let pass_name = CString::new("password").unwrap();
    let pass_label = CString::new("Password").unwrap();
    let mut user = raw_opt(sys::OC_FORM_OPT_TEXT as i32, &user_name, &user_label);
    let mut password = raw_opt(sys::OC_FORM_OPT_PASSWORD as i32, &pass_name, &pass_label);
    user.next = &mut *password;
    let mut primary_form = raw_form(&banner, Some(&primary_id), &mut *user);

    let primary_rc = unsafe {
        openconnect_auth_callback::<VecEventSink, QueueAuthHandler>(
            context.as_privdata(),
            &mut *primary_form,
        )
    };

    let otp_banner = CString::new("VPN verification").unwrap();
    let otp_id = CString::new("otp-step").unwrap();
    let otp_name = CString::new("otp").unwrap();
    let otp_label = CString::new("One-time password").unwrap();
    let mut otp = raw_opt(sys::OC_FORM_OPT_TOKEN as i32, &otp_name, &otp_label);
    let mut otp_form = raw_form(&otp_banner, Some(&otp_id), &mut *otp);

    let otp_rc = unsafe {
        openconnect_auth_callback::<VecEventSink, QueueAuthHandler>(
            context.as_privdata(),
            &mut *otp_form,
        )
    };

    assert_eq!(primary_rc, sys::OC_FORM_RESULT_OK as i32);
    assert_eq!(otp_rc, sys::OC_FORM_RESULT_OK as i32);
    assert_eq!(raw_value(&user), Some("alice".to_owned()));
    assert_eq!(raw_value(&password), Some("not-a-real-password".to_owned()));
    assert_eq!(raw_value(&otp), Some("123456".to_owned()));
    drop(context);

    assert_eq!(handler.requests.len(), 2);
    assert_eq!(handler.requests[0].form_id.as_deref(), Some("primary"));
    assert_eq!(handler.requests[1].form_id.as_deref(), Some("otp-step"));
    assert!(handler.requests[1].fields[0].is_secret());
    let events = sink.into_events();
    assert_eq!(events.len(), 4);
    assert!(matches!(events[1], TunnelEvent::AuthRequired(_)));
    assert!(matches!(events[3], TunnelEvent::AuthRequired(_)));
    let debug = format!("{events:?}");
    assert!(!debug.contains("not-a-real-password"));
    assert!(!debug.contains("123456"));
}

#[test]
fn applies_authgroup_selection_before_newgroup_without_network() {
    let mut sink = VecEventSink::new();
    let mut handler = QueueAuthHandler::new(vec![AuthFormDecision::NewAuthGroup(
        AuthResponse::new(vec![AuthAnswer::text("group_list", "engineering").unwrap()])
            .unwrap()
            .with_form_id("main")
            .unwrap(),
    )]);
    let mut context = AuthCallbackContext::new(&mut sink, &mut handler);
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
    let mut form = raw_form(&banner, Some(&auth_id), &mut group.form);
    form.authgroup_opt = &mut *group;

    let rc = unsafe {
        openconnect_auth_callback::<VecEventSink, QueueAuthHandler>(
            context.as_privdata(),
            &mut *form,
        )
    };

    assert_eq!(rc, sys::OC_FORM_RESULT_NEWGROUP as i32);
    assert_eq!(raw_value(&group.form), Some("engineering".to_owned()));
    drop(context);

    assert_eq!(handler.requests.len(), 1);
    let AuthFieldKind::Select { choices } = &handler.requests[0].fields[0].kind else {
        panic!("expected authgroup select field");
    };
    assert_eq!(choices.len(), 2);
}

#[test]
fn callback_errors_do_not_leak_secret_answers() {
    let mut sink = VecEventSink::new();
    let mut handler = QueueAuthHandler::new(vec![AuthFormDecision::Submit(
        AuthResponse::new(vec![
            AuthAnswer::secret("missing", "not-a-real-password").unwrap()
        ])
        .unwrap(),
    )]);
    let mut context = AuthCallbackContext::new(&mut sink, &mut handler);
    let banner = CString::new("VPN Login").unwrap();
    let user_name = CString::new("username").unwrap();
    let user_label = CString::new("Username").unwrap();
    let mut user = raw_opt(sys::OC_FORM_OPT_TEXT as i32, &user_name, &user_label);
    let mut form = raw_form(&banner, None, &mut *user);

    let rc = unsafe {
        openconnect_auth_callback::<VecEventSink, QueueAuthHandler>(
            context.as_privdata(),
            &mut *form,
        )
    };

    assert_eq!(rc, sys::OC_FORM_RESULT_ERR);
    assert_eq!(raw_value(&user), None);
    drop(context);

    let events = sink.into_events();
    let TunnelEvent::Error(error) = events.last().unwrap() else {
        panic!("expected error event");
    };
    assert_eq!(error.operation.as_deref(), Some("openconnect_auth"));
    assert!(error.message.contains("missing"));
    assert!(!error.message.contains("not-a-real-password"));
}

#[test]
fn session_with_callbacks_configures_without_network() {
    let mut sink = VecEventSink::new();
    let mut handler = QueueAuthHandler::new(Vec::new());
    let mut session =
        OpenConnectSession::new_with_callbacks("oc-oxide-m2-m3-test", &mut sink, &mut handler)
            .unwrap();
    let server = ServerUrl::parse("https://vpn.example.test:555/+CSCOE+/logon.html").unwrap();
    let profile = TunnelProfile::new("office", server.clone()).unwrap();

    session
        .session_mut()
        .configure_for_anyconnect(&profile)
        .unwrap();

    let parsed = session.session().parsed_server();
    assert_eq!(parsed.protocol.as_deref(), Some("anyconnect"));
    assert_eq!(parsed.dns_name.as_deref(), Some(server.dns_name()));
    assert!(session.session().cmd_write_fd() >= 0);
}

struct QueueAuthHandler {
    decisions: VecDeque<AuthFormDecision>,
    requests: Vec<AuthRequest>,
}

impl QueueAuthHandler {
    fn new(decisions: impl Into<VecDeque<AuthFormDecision>>) -> Self {
        Self {
            decisions: decisions.into(),
            requests: Vec::new(),
        }
    }
}

impl AuthFormHandler for QueueAuthHandler {
    fn handle_auth_request(&mut self, request: AuthRequest) -> AuthFormDecision {
        self.requests.push(request);
        self.decisions
            .pop_front()
            .unwrap_or(AuthFormDecision::Cancel)
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
    auth_id: Option<&CString>,
    opts: *mut sys::oc_form_opt,
) -> Box<sys::oc_auth_form> {
    let mut form = Box::new(unsafe { std::mem::zeroed::<sys::oc_auth_form>() });
    form.banner = banner.as_ptr() as *mut _;
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
