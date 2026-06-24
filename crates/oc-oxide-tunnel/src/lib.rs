//! Safe tunnel lifecycle wrapper.
//!
//! Direct `libopenconnect` calls should stay on one tunnel thread. This crate
//! owns `openconnect_info` lifecycle and exposes a narrow safe API over the raw
//! FFI boundary.

use std::ffi::{CStr, CString, NulError};
use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::os::raw::{c_char, c_int, c_void};
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::ptr::NonNull;
use std::rc::Rc;
use std::sync::OnceLock;

use oc_oxide_auth::{
    process_openconnect_auth_form_with_handler, AuthFormDecision, AuthFormHandler, AuthFormResult,
    AuthRequest,
};
use oc_oxide_config::TunnelProfile;
use oc_oxide_openconnect_sys as sys;

const ANYCONNECT_PROTOCOL: &CStr = c"anyconnect";
const ERRNO_EPERM: i32 = 1;
const ERRNO_EINTR: i32 = 4;
const ERRNO_EIO: i32 = 5;
const ERRNO_EPIPE: i32 = 32;
const ERRNO_ECONNABORTED: i32 = 103;
const OC_CMD_CANCEL: u8 = b'x';

unsafe extern "C" {
    fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
}

static INIT_SSL_RC: OnceLock<i32> = OnceLock::new();

/// Human-readable crate role used by workspace smoke tests.
pub const CRATE_ROLE: &str = "safe tunnel lifecycle";

/// Errors returned by the safe tunnel lifecycle wrapper.
#[derive(Debug)]
pub enum TunnelError {
    InteriorNul {
        field: &'static str,
        source: NulError,
    },
    OpenConnect {
        operation: &'static str,
        code: i32,
    },
    NullVpnInfo,
    NullIpInfo,
    CommandPipe,
    CommandPipeWrite {
        source: io::Error,
    },
    InvalidTunFd,
}

impl fmt::Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InteriorNul { field, source } => {
                write!(f, "{field} contains an interior NUL byte: {source}")
            }
            Self::OpenConnect { operation, code } => {
                write!(f, "{operation} failed with OpenConnect status {code}")
            }
            Self::NullVpnInfo => write!(f, "openconnect_vpninfo_new returned NULL"),
            Self::NullIpInfo => write!(f, "openconnect_get_ip_info returned NULL ip info"),
            Self::CommandPipe => write!(f, "openconnect_setup_cmd_pipe failed"),
            Self::CommandPipeWrite { source } => {
                write!(f, "failed to write OpenConnect command pipe: {source}")
            }
            Self::InvalidTunFd => write!(f, "TUN file descriptor must be non-negative"),
        }
    }
}

impl std::error::Error for TunnelError {}

/// Errors returned while translating progress messages into events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgressEventError {
    EmptyMessage,
    InteriorNul,
}

impl fmt::Display for ProgressEventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyMessage => write!(f, "progress message must not be empty"),
            Self::InteriorNul => write!(f, "progress message must not contain a NUL byte"),
        }
    }
}

impl std::error::Error for ProgressEventError {}

/// Errors returned while translating OpenConnect progress callback payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgressCallbackError {
    NullMessage,
    InvalidMessage(ProgressEventError),
}

impl fmt::Display for ProgressCallbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullMessage => write!(f, "progress callback message pointer was NULL"),
            Self::InvalidMessage(source) => {
                write!(f, "invalid progress callback message: {source}")
            }
        }
    }
}

impl std::error::Error for ProgressCallbackError {}

/// Owned `libopenconnect` session.
///
/// This type is intentionally `!Send` and `!Sync`; direct calls into
/// `libopenconnect` must remain on the thread that owns the session. Cross
/// thread cancellation will be layered on top of the command pipe later.
pub struct OpenConnectSession {
    inner: NonNull<sys::openconnect_info>,
    cmd_write_fd: Option<i32>,
    _not_send_sync: PhantomData<Rc<()>>,
}

/// OpenConnect session with progress callback routing installed.
pub struct OpenConnectSessionWithProgress<'a, S: TunnelEventSink> {
    session: OpenConnectSession,
    _progress_context: Box<ProgressCallbackContext<S>>,
    _progress_hook: ProgressHookGuard,
    _sink_lifetime: PhantomData<&'a mut S>,
}

/// OpenConnect session with progress and auth callbacks routed to Rust.
pub struct OpenConnectSessionWithCallbacks<'a, S: TunnelEventSink, H: AuthFormHandler> {
    session: OpenConnectSession,
    _callback_context: Box<AuthCallbackContext<S, H>>,
    _progress_hook: ProgressHookGuard,
    _sink_lifetime: PhantomData<&'a mut S>,
    _handler_lifetime: PhantomData<&'a mut H>,
}

/// Context passed to OpenConnect auth callbacks as `privdata`.
pub struct AuthCallbackContext<S: TunnelEventSink, H: AuthFormHandler> {
    sink: NonNull<S>,
    handler: NonNull<H>,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl<S: TunnelEventSink, H: AuthFormHandler> AuthCallbackContext<S, H> {
    /// Create an auth callback context owned by the tunnel thread.
    pub fn new(sink: &mut S, handler: &mut H) -> Self {
        Self {
            sink: NonNull::from(sink),
            handler: NonNull::from(handler),
            _not_send_sync: PhantomData,
        }
    }

    /// Return the raw pointer passed to OpenConnect as callback private data.
    ///
    /// The context, sink, and handler must outlive callback invocations using
    /// this pointer.
    pub fn as_privdata(&mut self) -> *mut c_void {
        self as *mut Self as *mut c_void
    }
}

/// Write-side handle for libopenconnect's command pipe.
///
/// The underlying fd is owned by libopenconnect. It is closed by
/// `openconnect_vpninfo_free`, so this handle deliberately has no `Drop`
/// behavior that closes the fd.
#[derive(Debug)]
pub struct CancelHandle {
    write_fd: i32,
}

impl CancelHandle {
    /// Return the raw command-pipe fd for diagnostics and future integration.
    pub fn raw_fd(&self) -> i32 {
        self.write_fd
    }

    /// Request local cancellation through OpenConnect's command pipe.
    pub fn cancel(&self) -> Result<(), TunnelError> {
        write_cmd_byte(self.write_fd, OC_CMD_CANCEL)
    }
}

/// Rust-owned snapshot of OpenConnect's parsed server URL state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedServer {
    pub protocol: Option<String>,
    pub dns_name: Option<String>,
    pub url_path: Option<String>,
    pub port: i32,
}

/// Rust-owned snapshot of OpenConnect's current IP configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpInfoSnapshot {
    pub address: Option<String>,
    pub netmask: Option<String>,
    pub address6: Option<String>,
    pub netmask6: Option<String>,
    pub dns: Vec<String>,
    pub nbns: Vec<String>,
    pub domain: Option<String>,
    pub proxy_pac: Option<String>,
    pub mtu: i32,
    pub split_dns: Vec<SplitRoute>,
    pub split_includes: Vec<SplitRoute>,
    pub split_excludes: Vec<SplitRoute>,
    pub gateway_addr: Option<String>,
}

/// Rust-owned snapshot of a TUN device created by OpenConnect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunDeviceSnapshot {
    pub ifname: Option<String>,
}

/// Server-pushed split route entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitRoute {
    pub route: String,
}

/// Typed event emitted by the tunnel thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelEvent {
    Progress(ProgressEvent),
    AuthRequired(AuthRequest),
    StateChanged(TunnelState),
    Error(TunnelEventError),
}

/// Progress message from libopenconnect or the tunnel wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgressEvent {
    pub level: ProgressLevel,
    pub message: String,
}

impl ProgressEvent {
    /// Create a progress event while preserving OpenConnect's raw level.
    pub fn new(raw_level: i32, message: impl Into<String>) -> Self {
        Self {
            level: ProgressLevel::from_raw(raw_level),
            message: message.into(),
        }
    }

    /// Create a validated progress event while preserving OpenConnect's raw level.
    pub fn try_new(raw_level: i32, message: impl Into<String>) -> Result<Self, ProgressEventError> {
        Ok(Self {
            level: ProgressLevel::from_raw(raw_level),
            message: clean_progress_message(message.into())?,
        })
    }
}

/// OpenConnect progress level preserved as raw data for now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgressLevel {
    raw: i32,
}

impl ProgressLevel {
    /// Preserve a raw libopenconnect progress level.
    pub fn from_raw(raw: i32) -> Self {
        Self { raw }
    }

    /// Raw libopenconnect progress level.
    pub fn raw(self) -> i32 {
        self.raw
    }
}

/// Coarse tunnel state for UI and IPC consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    Idle,
    Configuring,
    AwaitingAuth,
    Connecting,
    Connected,
    Disconnecting,
    Disconnected,
    Cancelled,
}

/// Classified result from `openconnect_mainloop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainloopOutcome {
    /// Mainloop returned zero; OpenConnect CLI treats this as a reconnect request.
    ReconnectRequested,
    CookieRejected,
    ServerTerminated,
    UserCancelled,
    Detached,
    UnrecoverableIo,
    UnknownError {
        code: i32,
    },
}

impl MainloopOutcome {
    /// Whether this outcome is a graceful user-driven stop.
    pub fn is_graceful_stop(self) -> bool {
        matches!(self, Self::UserCancelled | Self::Detached)
    }

    /// Whether this outcome should be treated as an error by callers.
    pub fn is_error(self) -> bool {
        matches!(
            self,
            Self::CookieRejected
                | Self::ServerTerminated
                | Self::UnrecoverableIo
                | Self::UnknownError { .. }
        )
    }
}

/// Classify a raw `openconnect_mainloop` return code.
pub fn classify_mainloop_return(code: i32) -> MainloopOutcome {
    match code {
        0 => MainloopOutcome::ReconnectRequested,
        code if code == -ERRNO_EPERM => MainloopOutcome::CookieRejected,
        code if code == -ERRNO_EPIPE => MainloopOutcome::ServerTerminated,
        code if code == -ERRNO_EINTR => MainloopOutcome::UserCancelled,
        code if code == -ERRNO_ECONNABORTED => MainloopOutcome::Detached,
        code if code == -ERRNO_EIO => MainloopOutcome::UnrecoverableIo,
        code => MainloopOutcome::UnknownError { code },
    }
}

/// Non-secret tunnel error event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelEventError {
    pub operation: Option<String>,
    pub message: String,
}

impl TunnelEventError {
    /// Create an error event suitable for UI/IPC forwarding.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            operation: None,
            message: message.into(),
        }
    }

    /// Attach a non-secret operation name.
    pub fn with_operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = Some(operation.into());
        self
    }
}

/// Destination for tunnel events emitted on the tunnel thread.
pub trait TunnelEventSink {
    /// Emit one event to the sink.
    fn emit(&mut self, event: TunnelEvent);
}

/// In-memory event sink for no-network tests and callback translation tests.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VecEventSink {
    events: Vec<TunnelEvent>,
}

impl VecEventSink {
    /// Create an empty in-memory event sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow all events collected so far.
    pub fn events(&self) -> &[TunnelEvent] {
        &self.events
    }

    /// Consume the sink and return collected events.
    pub fn into_events(self) -> Vec<TunnelEvent> {
        self.events
    }
}

impl TunnelEventSink for VecEventSink {
    fn emit(&mut self, event: TunnelEvent) {
        self.events.push(event);
    }
}

/// Emit one event through the given sink.
pub fn emit_tunnel_event(sink: &mut impl TunnelEventSink, event: TunnelEvent) {
    sink.emit(event);
}

/// Translate a progress callback payload into a typed tunnel event.
pub fn emit_progress(
    sink: &mut impl TunnelEventSink,
    raw_level: i32,
    message: impl Into<String>,
) -> Result<(), ProgressEventError> {
    emit_tunnel_event(
        sink,
        TunnelEvent::Progress(ProgressEvent::try_new(raw_level, message)?),
    );
    Ok(())
}

/// Progress callback context passed to libopenconnect as `privdata`.
pub struct ProgressCallbackContext<S: TunnelEventSink> {
    sink: NonNull<S>,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl<S: TunnelEventSink> ProgressCallbackContext<S> {
    /// Create a callback context for a sink owned by the tunnel thread.
    pub fn new(sink: &mut S) -> Self {
        Self {
            sink: NonNull::from(sink),
            _not_send_sync: PhantomData,
        }
    }

    /// Return the raw pointer passed to OpenConnect as callback private data.
    ///
    /// The context and sink must outlive any callback invocation using this
    /// pointer.
    pub fn as_privdata(&mut self) -> *mut c_void {
        self as *mut Self as *mut c_void
    }

    fn sink_mut(&mut self) -> &mut S {
        unsafe { self.sink.as_mut() }
    }
}

/// RAII guard for the process-global low-level OpenConnect progress hook.
pub struct ProgressHookGuard {
    previous: Option<sys::OcOxideProgressSink>,
}

impl Drop for ProgressHookGuard {
    fn drop(&mut self) {
        sys::oc_oxide_set_progress_sink(self.previous.take());
    }
}

/// Install the tunnel progress callback in the raw FFI layer.
pub fn install_openconnect_progress_hook<S: TunnelEventSink>() -> ProgressHookGuard {
    let previous = sys::oc_oxide_set_progress_sink(Some(openconnect_progress_callback::<S>));
    ProgressHookGuard { previous }
}

/// Install the progress hook used when progress and auth share callback data.
pub fn install_openconnect_callback_progress_hook<S, H>() -> ProgressHookGuard
where
    S: TunnelEventSink,
    H: AuthFormHandler,
{
    let previous =
        sys::oc_oxide_set_progress_sink(Some(openconnect_progress_callback_with_auth::<S, H>));
    ProgressHookGuard { previous }
}

/// Translate an OpenConnect C string progress payload into a typed event.
pub unsafe fn emit_openconnect_progress(
    sink: &mut impl TunnelEventSink,
    raw_level: c_int,
    msg: *const c_char,
) -> Result<(), ProgressCallbackError> {
    if msg.is_null() {
        return Err(ProgressCallbackError::NullMessage);
    }

    let message = CStr::from_ptr(msg).to_string_lossy().into_owned();
    emit_progress(sink, raw_level, message).map_err(ProgressCallbackError::InvalidMessage)
}

/// Low-level callback registered behind the C progress trampoline.
pub unsafe extern "C" fn openconnect_progress_callback<S: TunnelEventSink>(
    privdata: *mut c_void,
    level: c_int,
    msg: *const c_char,
) {
    if privdata.is_null() {
        return;
    }

    let context = &mut *(privdata as *mut ProgressCallbackContext<S>);
    if let Err(err) = emit_openconnect_progress(context.sink_mut(), level, msg) {
        context.sink_mut().emit(TunnelEvent::Error(
            TunnelEventError::new(err.to_string()).with_operation("openconnect_progress"),
        ));
    }
}

/// Low-level progress callback for sessions whose `privdata` is AuthCallbackContext.
pub unsafe extern "C" fn openconnect_progress_callback_with_auth<S, H>(
    privdata: *mut c_void,
    level: c_int,
    msg: *const c_char,
) where
    S: TunnelEventSink,
    H: AuthFormHandler,
{
    if privdata.is_null() {
        return;
    }

    let context = &mut *(privdata as *mut AuthCallbackContext<S, H>);
    let sink = context.sink.as_mut();
    if let Err(err) = emit_openconnect_progress(sink, level, msg) {
        sink.emit(TunnelEvent::Error(
            TunnelEventError::new(err.to_string()).with_operation("openconnect_progress"),
        ));
    }
}

/// Low-level OpenConnect auth callback that emits auth events and applies answers.
pub unsafe extern "C" fn openconnect_auth_callback<S, H>(
    privdata: *mut c_void,
    form: *mut sys::oc_auth_form,
) -> c_int
where
    S: TunnelEventSink,
    H: AuthFormHandler,
{
    if privdata.is_null() {
        return AuthFormResult::Error.to_openconnect_code();
    }

    let context = &mut *(privdata as *mut AuthCallbackContext<S, H>);
    let sink = context.sink.as_mut();
    let handler = context.handler.as_mut();
    let mut emitting_handler = EmittingAuthHandler { sink, handler };

    match process_openconnect_auth_form_with_handler(form, &mut emitting_handler) {
        Ok(result) => result.to_openconnect_code(),
        Err(err) => {
            emitting_handler.sink.emit(TunnelEvent::Error(
                TunnelEventError::new(err.to_string()).with_operation("openconnect_auth"),
            ));
            AuthFormResult::Error.to_openconnect_code()
        }
    }
}

struct EmittingAuthHandler<'a, S: TunnelEventSink, H: AuthFormHandler> {
    sink: &'a mut S,
    handler: &'a mut H,
}

impl<S: TunnelEventSink, H: AuthFormHandler> AuthFormHandler for EmittingAuthHandler<'_, S, H> {
    fn maybe_handle_auth_request(&mut self, request: &AuthRequest) -> Option<AuthFormDecision> {
        self.handler.maybe_handle_auth_request(request)
    }

    fn handle_auth_request(&mut self, request: AuthRequest) -> AuthFormDecision {
        self.sink
            .emit(TunnelEvent::StateChanged(TunnelState::AwaitingAuth));
        if let Some(decision) = self.maybe_handle_auth_request(&request) {
            return decision;
        }
        let request = self.handler.prepare_auth_request(request);
        self.sink.emit(TunnelEvent::AuthRequired(request.clone()));
        self.handler.handle_auth_request(request)
    }
}

impl OpenConnectSession {
    /// Create a new OpenConnect session and command pipe.
    pub fn new(useragent: &str) -> Result<Self, TunnelError> {
        Self::new_with_callbacks_privdata(useragent, None, std::ptr::null_mut())
    }

    /// Create a new OpenConnect session with progress events routed to a sink.
    pub fn new_with_progress_sink<'a, S: TunnelEventSink>(
        useragent: &str,
        sink: &'a mut S,
    ) -> Result<OpenConnectSessionWithProgress<'a, S>, TunnelError> {
        let mut progress_context = Box::new(ProgressCallbackContext::new(sink));
        let progress_privdata = progress_context.as_privdata();
        let progress_hook = install_openconnect_progress_hook::<S>();
        let session = Self::new_with_callbacks_privdata(useragent, None, progress_privdata)?;

        Ok(OpenConnectSessionWithProgress {
            session,
            _progress_context: progress_context,
            _progress_hook: progress_hook,
            _sink_lifetime: PhantomData,
        })
    }

    /// Create a new OpenConnect session with progress and auth callbacks.
    pub fn new_with_callbacks<'a, S, H>(
        useragent: &str,
        sink: &'a mut S,
        handler: &'a mut H,
    ) -> Result<OpenConnectSessionWithCallbacks<'a, S, H>, TunnelError>
    where
        S: TunnelEventSink,
        H: AuthFormHandler,
    {
        let mut callback_context = Box::new(AuthCallbackContext::new(sink, handler));
        let callback_privdata = callback_context.as_privdata();
        let progress_hook = install_openconnect_callback_progress_hook::<S, H>();
        let session = Self::new_with_callbacks_privdata(
            useragent,
            Some(openconnect_auth_callback::<S, H>),
            callback_privdata,
        )?;

        Ok(OpenConnectSessionWithCallbacks {
            session,
            _callback_context: callback_context,
            _progress_hook: progress_hook,
            _sink_lifetime: PhantomData,
            _handler_lifetime: PhantomData,
        })
    }

    fn new_with_callbacks_privdata(
        useragent: &str,
        auth_callback: sys::openconnect_process_auth_form_vfn,
        callback_privdata: *mut c_void,
    ) -> Result<Self, TunnelError> {
        init_ssl_once()?;

        let useragent = cstring("useragent", useragent)?;
        let inner = unsafe {
            sys::openconnect_vpninfo_new(
                useragent.as_ptr(),
                None,
                None,
                auth_callback,
                Some(sys::oc_oxide_progress_trampoline),
                callback_privdata,
            )
        };
        let inner = NonNull::new(inner).ok_or(TunnelError::NullVpnInfo)?;

        let cmd_write_fd = unsafe { sys::openconnect_setup_cmd_pipe(inner.as_ptr()) };
        if cmd_write_fd < 0 {
            unsafe { sys::openconnect_vpninfo_free(inner.as_ptr()) };
            return Err(TunnelError::CommandPipe);
        }

        Ok(Self {
            inner,
            cmd_write_fd: Some(cmd_write_fd),
            _not_send_sync: PhantomData,
        })
    }

    /// Select the AnyConnect protocol.
    pub fn set_protocol_anyconnect(&mut self) -> Result<(), TunnelError> {
        let rc = unsafe {
            sys::openconnect_set_protocol(self.inner.as_ptr(), ANYCONNECT_PROTOCOL.as_ptr())
        };
        ok(rc, "openconnect_set_protocol(anyconnect)")
    }

    /// Set the reported client OS string accepted by OpenConnect.
    pub fn set_reported_os(&mut self, os: &str) -> Result<(), TunnelError> {
        let os = cstring("reported_os", os)?;
        let rc = unsafe { sys::openconnect_set_reported_os(self.inner.as_ptr(), os.as_ptr()) };
        ok(rc, "openconnect_set_reported_os")
    }

    /// Parse a server URL into the OpenConnect session.
    ///
    /// This only parses and stores URL components. It does not connect to the
    /// network.
    pub fn parse_url(&mut self, url: &str) -> Result<(), TunnelError> {
        let url = cstring("url", url)?;
        let rc = unsafe { sys::openconnect_parse_url(self.inner.as_ptr(), url.as_ptr()) };
        ok(rc, "openconnect_parse_url")
    }

    /// Configure this session for an AnyConnect profile without connecting.
    ///
    /// This sets protocol, reported OS, and the validated server URL in the
    /// order libopenconnect expects. It does not acquire cookies, authenticate,
    /// open CSTP/DTLS, create a TUN device, or run the mainloop.
    pub fn configure_for_anyconnect(&mut self, profile: &TunnelProfile) -> Result<(), TunnelError> {
        self.set_protocol_anyconnect()?;
        self.set_reported_os(profile.reported_os())?;
        self.parse_url(profile.server_url().as_openconnect_url())
    }

    /// Run the OpenConnect authentication flow and obtain a session cookie.
    ///
    /// This performs network I/O and may invoke the registered auth callback.
    /// It does not create a TUN device or enter the tunnel mainloop.
    pub fn obtain_cookie(&mut self) -> Result<(), TunnelError> {
        let rc = unsafe { sys::openconnect_obtain_cookie(self.inner.as_ptr()) };
        ok(rc, "openconnect_obtain_cookie")
    }

    /// Open the CSTP control channel.
    ///
    /// On success, server-pushed IP configuration is available through
    /// [`Self::ip_info_snapshot`]. This does not create a TUN device or apply
    /// host route/DNS changes.
    pub fn make_cstp_connection(&mut self) -> Result<(), TunnelError> {
        let rc = unsafe { sys::openconnect_make_cstp_connection(self.inner.as_ptr()) };
        ok(rc, "openconnect_make_cstp_connection")
    }

    /// Attempt to set up DTLS/UDP for the current CSTP session.
    pub fn setup_dtls(&mut self, attempt_period_seconds: i32) -> Result<(), TunnelError> {
        let rc =
            unsafe { sys::openconnect_setup_dtls(self.inner.as_ptr(), attempt_period_seconds) };
        ok(rc, "openconnect_setup_dtls")
    }

    /// Create an OS TUN device without running a vpnc-script.
    ///
    /// This performs privileged host I/O and leaves route/DNS policy untouched
    /// because the script argument is passed as NULL. The TUN fd is owned by
    /// libopenconnect; persistent connections should enter the mainloop so
    /// OpenConnect can drive the normal tunnel shutdown path.
    pub fn setup_tun_device_without_script(
        &mut self,
        requested_ifname: Option<&str>,
    ) -> Result<TunDeviceSnapshot, TunnelError> {
        let requested_ifname = requested_ifname
            .map(|ifname| cstring("ifname", ifname))
            .transpose()?;
        let ifname_ptr = requested_ifname
            .as_ref()
            .map_or(std::ptr::null(), |ifname| ifname.as_ptr());
        let rc = unsafe {
            sys::openconnect_setup_tun_device(self.inner.as_ptr(), std::ptr::null(), ifname_ptr)
        };
        ok(rc, "openconnect_setup_tun_device")?;

        Ok(TunDeviceSnapshot {
            ifname: self.ifname(),
        })
    }

    /// Install a caller-provided fd as OpenConnect's tunnel fd.
    ///
    /// This is intended for tests that back the tunnel side with a socketpair
    /// or similar mock fd instead of `/dev/net/tun`. The fd must remain valid
    /// while this session may use it. Do not use this for production tunnel
    /// setup; persistent connections should use an OS TUN device and enter the
    /// normal OpenConnect mainloop/shutdown path.
    #[cfg(unix)]
    pub unsafe fn setup_tun_fd_for_test(
        &mut self,
        raw_fd: RawFd,
    ) -> Result<TunDeviceSnapshot, TunnelError> {
        if raw_fd < 0 {
            return Err(TunnelError::InvalidTunFd);
        }

        let rc = sys::openconnect_setup_tun_fd(self.inner.as_ptr(), raw_fd);
        ok(rc, "openconnect_setup_tun_fd")?;

        Ok(TunDeviceSnapshot {
            ifname: self.ifname(),
        })
    }

    /// Run OpenConnect's packet mainloop and classify its terminal status.
    pub fn run_mainloop(
        &mut self,
        reconnect_timeout_seconds: i32,
        reconnect_interval_seconds: i32,
    ) -> MainloopOutcome {
        let rc = unsafe {
            sys::openconnect_mainloop(
                self.inner.as_ptr(),
                reconnect_timeout_seconds,
                reconnect_interval_seconds,
            )
        };
        classify_mainloop_return(rc)
    }

    /// Return whether OpenConnect currently has an auth cookie.
    ///
    /// The cookie value is intentionally not exposed by the safe wrapper.
    pub fn has_cookie(&self) -> bool {
        let ptr = unsafe { sys::openconnect_get_cookie(self.inner.as_ptr()) };
        !ptr.is_null()
    }

    /// Return the current OpenConnect TUN interface name, if one exists.
    pub fn ifname(&self) -> Option<String> {
        cstr_opt(unsafe { sys::openconnect_get_ifname(self.inner.as_ptr()) })
    }

    /// Copy parsed URL/protocol state out of OpenConnect.
    pub fn parsed_server(&self) -> ParsedServer {
        ParsedServer {
            protocol: cstr_opt(unsafe { sys::openconnect_get_protocol(self.inner.as_ptr()) }),
            dns_name: cstr_opt(unsafe { sys::openconnect_get_dnsname(self.inner.as_ptr()) }),
            url_path: cstr_opt(unsafe { sys::openconnect_get_urlpath(self.inner.as_ptr()) }),
            port: unsafe { sys::openconnect_get_port(self.inner.as_ptr()) },
        }
    }

    /// Copy current IP configuration out of OpenConnect.
    ///
    /// The source structures are owned by libopenconnect and can be replaced
    /// during reconnect/rekey. This method copies the values into Rust-owned
    /// strings and must be called on the tunnel thread.
    pub fn ip_info_snapshot(&self) -> Result<IpInfoSnapshot, TunnelError> {
        let mut info: *const sys::oc_ip_info = std::ptr::null();
        let rc = unsafe {
            sys::openconnect_get_ip_info(
                self.inner.as_ptr(),
                &mut info,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        ok(rc, "openconnect_get_ip_info")?;

        let info = unsafe { info.as_ref() }.ok_or(TunnelError::NullIpInfo)?;
        Ok(IpInfoSnapshot {
            address: cstr_opt(info.addr),
            netmask: cstr_opt(info.netmask),
            address6: cstr_opt(info.addr6),
            netmask6: cstr_opt(info.netmask6),
            dns: cstr_array(&info.dns),
            nbns: cstr_array(&info.nbns),
            domain: cstr_opt(info.domain),
            proxy_pac: cstr_opt(info.proxy_pac),
            mtu: info.mtu,
            split_dns: split_routes(info.split_dns),
            split_includes: split_routes(info.split_includes),
            split_excludes: split_routes(info.split_excludes),
            gateway_addr: cstr_opt(info.gateway_addr),
        })
    }

    /// Return the command pipe write fd created by OpenConnect.
    ///
    /// The fd remains owned by OpenConnect and is closed by
    /// `openconnect_vpninfo_free`.
    pub fn cmd_write_fd(&self) -> i32 {
        self.cmd_write_fd.unwrap_or(-1)
    }

    /// Move out the command-pipe write handle.
    ///
    /// This can only be called once. The returned handle must not outlive the
    /// session; libopenconnect still owns and closes the fd.
    pub fn take_cancel_handle(&mut self) -> Option<CancelHandle> {
        self.cmd_write_fd
            .take()
            .map(|write_fd| CancelHandle { write_fd })
    }
}

impl<S: TunnelEventSink> OpenConnectSessionWithProgress<'_, S> {
    /// Borrow the underlying OpenConnect session.
    pub fn session(&self) -> &OpenConnectSession {
        &self.session
    }

    /// Mutably borrow the underlying OpenConnect session.
    pub fn session_mut(&mut self) -> &mut OpenConnectSession {
        &mut self.session
    }

    #[cfg(test)]
    fn progress_privdata(&mut self) -> *mut c_void {
        self._progress_context.as_privdata()
    }
}

impl<S: TunnelEventSink, H: AuthFormHandler> OpenConnectSessionWithCallbacks<'_, S, H> {
    /// Borrow the underlying OpenConnect session.
    pub fn session(&self) -> &OpenConnectSession {
        &self.session
    }

    /// Mutably borrow the underlying OpenConnect session.
    pub fn session_mut(&mut self) -> &mut OpenConnectSession {
        &mut self.session
    }

    #[cfg(test)]
    fn callback_privdata(&mut self) -> *mut c_void {
        self._callback_context.as_privdata()
    }
}

impl Drop for OpenConnectSession {
    fn drop(&mut self) {
        unsafe { sys::openconnect_vpninfo_free(self.inner.as_ptr()) };
    }
}

fn init_ssl_once() -> Result<(), TunnelError> {
    let rc = *INIT_SSL_RC.get_or_init(|| unsafe { sys::openconnect_init_ssl() });
    ok(rc, "openconnect_init_ssl")
}

fn cstring(field: &'static str, value: &str) -> Result<CString, TunnelError> {
    CString::new(value).map_err(|source| TunnelError::InteriorNul { field, source })
}

fn ok(code: i32, operation: &'static str) -> Result<(), TunnelError> {
    if code == 0 {
        Ok(())
    } else {
        Err(TunnelError::OpenConnect { operation, code })
    }
}

fn write_cmd_byte(fd: i32, command: u8) -> Result<(), TunnelError> {
    let bytes = [command];
    let written = unsafe { write(fd, bytes.as_ptr().cast(), bytes.len()) };
    if written == bytes.len() as isize {
        Ok(())
    } else {
        Err(TunnelError::CommandPipeWrite {
            source: io::Error::last_os_error(),
        })
    }
}

fn cstr_opt(ptr: *const std::os::raw::c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }

    Some(
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned(),
    )
}

fn cstr_array(ptrs: &[*const c_char]) -> Vec<String> {
    ptrs.iter().filter_map(|ptr| cstr_opt(*ptr)).collect()
}

fn split_routes(mut node: *mut sys::oc_split_include) -> Vec<SplitRoute> {
    let mut routes = Vec::new();

    while !node.is_null() {
        let include = unsafe { &*node };
        if let Some(route) = cstr_opt(include.route) {
            routes.push(SplitRoute { route });
        }
        node = include.next;
    }

    routes
}

fn clean_progress_message(message: String) -> Result<String, ProgressEventError> {
    let message = message.trim();
    if message.is_empty() {
        return Err(ProgressEventError::EmptyMessage);
    }

    if message.contains('\0') {
        return Err(ProgressEventError::InteriorNul);
    }

    Ok(message.to_owned())
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    #[cfg(unix)]
    use std::os::unix::io::AsRawFd;
    #[cfg(unix)]
    use std::os::unix::net::UnixDatagram;
    use std::ptr;
    use std::sync::Mutex;

    use super::{
        classify_mainloop_return, emit_openconnect_progress, emit_progress, emit_tunnel_event,
        install_openconnect_progress_hook, openconnect_auth_callback,
        openconnect_progress_callback, AuthCallbackContext, MainloopOutcome, OpenConnectSession,
        ProgressCallbackContext, ProgressCallbackError, ProgressEvent, ProgressEventError,
        TunnelError, TunnelEvent, TunnelEventError, TunnelState, VecEventSink, CRATE_ROLE,
    };
    use crate::sys;
    use oc_oxide_auth::{
        AuthAnswer, AuthField, AuthFormDecision, AuthFormHandler, AuthRequest, AuthResponse,
    };
    use oc_oxide_config::{ServerUrl, TunnelProfile};

    static PROGRESS_HOOK_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn documents_tunnel_role() {
        assert!(CRATE_ROLE.contains("tunnel"));
    }

    #[test]
    fn creates_configures_and_drops_session_without_network() {
        let mut session = OpenConnectSession::new("oc-oxide-test").unwrap();
        assert!(session.cmd_write_fd() >= 0);

        let server = ServerUrl::parse("https://vpn.example.test:555/+CSCOE+/logon.html").unwrap();
        let profile = TunnelProfile::new("office", server.clone()).unwrap();
        session.configure_for_anyconnect(&profile).unwrap();

        let parsed = session.parsed_server();
        assert_eq!(parsed.protocol.as_deref(), Some("anyconnect"));
        assert_eq!(parsed.dns_name.as_deref(), Some(server.dns_name()));
        assert_eq!(
            parsed.url_path.as_deref(),
            Some(server.openconnect_url_path())
        );
        assert_eq!(parsed.port, i32::from(server.port()));
    }

    #[test]
    fn snapshots_empty_ip_info_without_network() {
        let session = OpenConnectSession::new("oc-oxide-test").unwrap();

        let snapshot = session.ip_info_snapshot().unwrap();
        assert_eq!(snapshot.address, None);
        assert_eq!(snapshot.netmask, None);
        assert_eq!(snapshot.address6, None);
        assert_eq!(snapshot.netmask6, None);
        assert!(snapshot.dns.is_empty());
        assert!(snapshot.nbns.is_empty());
        assert_eq!(snapshot.domain, None);
        assert_eq!(snapshot.proxy_pac, None);
        assert_eq!(snapshot.mtu, 0);
        assert!(snapshot.split_dns.is_empty());
        assert!(snapshot.split_includes.is_empty());
        assert!(snapshot.split_excludes.is_empty());
        assert_eq!(snapshot.gateway_addr, None);
    }

    #[test]
    fn new_session_starts_without_cookie() {
        let session = OpenConnectSession::new("oc-oxide-test").unwrap();

        assert!(!session.has_cookie());
    }

    #[test]
    fn new_session_starts_without_tun_interface() {
        let session = OpenConnectSession::new("oc-oxide-test").unwrap();

        assert_eq!(session.ifname(), None);
    }

    #[cfg(unix)]
    #[test]
    fn installs_mock_tun_fd_without_opening_os_tun() {
        let _lock = PROGRESS_HOOK_TEST_LOCK.lock().unwrap();
        let (mock_tun, peer) = UnixDatagram::pair().unwrap();
        let mut session = OpenConnectSession::new("oc-oxide-test").unwrap();

        peer.send(&mock_ipv4_packet()).unwrap();
        let tun = unsafe { session.setup_tun_fd_for_test(mock_tun.as_raw_fd()) }.unwrap();

        assert_eq!(tun.ifname, None);
        assert_eq!(session.ifname(), None);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_invalid_mock_tun_fd() {
        let _lock = PROGRESS_HOOK_TEST_LOCK.lock().unwrap();
        let mut session = OpenConnectSession::new("oc-oxide-test").unwrap();

        let err = unsafe { session.setup_tun_fd_for_test(-1) }.unwrap_err();

        assert!(matches!(err, TunnelError::InvalidTunFd));
    }

    #[test]
    fn cancel_handle_can_only_be_taken_once() {
        let mut session = OpenConnectSession::new("oc-oxide-test").unwrap();

        let handle = session.take_cancel_handle().unwrap();
        assert!(handle.raw_fd() >= 0);
        assert!(session.take_cancel_handle().is_none());
        assert_eq!(session.cmd_write_fd(), -1);
    }

    #[test]
    fn cancel_handle_writes_cancel_command_without_network() {
        let mut session = OpenConnectSession::new("oc-oxide-test").unwrap();
        let handle = session.take_cancel_handle().unwrap();

        handle.cancel().unwrap();
    }

    #[test]
    fn rejects_interior_nul_inputs() {
        let err = match OpenConnectSession::new("bad\0agent") {
            Ok(_) => panic!("expected interior NUL error"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("useragent"));

        let mut session = OpenConnectSession::new("oc-oxide-test").unwrap();
        let err = session
            .parse_url("https://bad\0.example.test/")
            .unwrap_err();
        assert!(err.to_string().contains("url"));
    }

    #[test]
    fn builds_progress_and_state_events_without_network() {
        let event = TunnelEvent::Progress(ProgressEvent::new(3, "Connected to server"));
        let cloned = event.clone();

        let TunnelEvent::Progress(progress) = cloned else {
            panic!("expected progress event");
        };
        assert_eq!(progress.level.raw(), 3);
        assert_eq!(progress.message, "Connected to server");

        let state = TunnelEvent::StateChanged(TunnelState::AwaitingAuth);
        assert_eq!(state, TunnelEvent::StateChanged(TunnelState::AwaitingAuth));
    }

    #[test]
    fn builds_auth_required_event_without_answers() {
        let request = AuthRequest::new(
            "VPN Login",
            vec![
                AuthField::text("username", "Username").unwrap(),
                AuthField::password("password", "Password").unwrap(),
            ],
        )
        .unwrap();
        let event = TunnelEvent::AuthRequired(request);

        let TunnelEvent::AuthRequired(request) = event else {
            panic!("expected auth event");
        };
        assert_eq!(request.fields.len(), 2);
        assert!(!request.fields[0].is_secret());
        assert!(request.fields[1].is_secret());
    }

    #[test]
    fn builds_non_secret_error_event() {
        let event = TunnelEvent::Error(
            TunnelEventError::new("OpenConnect setup failed")
                .with_operation("openconnect_parse_url"),
        );

        let TunnelEvent::Error(error) = event else {
            panic!("expected error event");
        };
        assert_eq!(error.operation.as_deref(), Some("openconnect_parse_url"));
        assert_eq!(error.message, "OpenConnect setup failed");
    }

    #[test]
    fn classifies_known_mainloop_return_codes() {
        assert_eq!(
            classify_mainloop_return(0),
            MainloopOutcome::ReconnectRequested
        );
        assert_eq!(
            classify_mainloop_return(-1),
            MainloopOutcome::CookieRejected
        );
        assert_eq!(
            classify_mainloop_return(-32),
            MainloopOutcome::ServerTerminated
        );
        assert_eq!(classify_mainloop_return(-4), MainloopOutcome::UserCancelled);
        assert_eq!(classify_mainloop_return(-103), MainloopOutcome::Detached);
        assert_eq!(
            classify_mainloop_return(-5),
            MainloopOutcome::UnrecoverableIo
        );
    }

    #[test]
    fn classifies_unknown_mainloop_return_codes() {
        assert_eq!(
            classify_mainloop_return(-22),
            MainloopOutcome::UnknownError { code: -22 }
        );
        assert_eq!(
            classify_mainloop_return(7),
            MainloopOutcome::UnknownError { code: 7 }
        );
    }

    #[test]
    fn marks_mainloop_outcome_severity() {
        assert!(MainloopOutcome::UserCancelled.is_graceful_stop());
        assert!(MainloopOutcome::Detached.is_graceful_stop());
        assert!(!MainloopOutcome::ServerTerminated.is_graceful_stop());

        assert!(MainloopOutcome::CookieRejected.is_error());
        assert!(MainloopOutcome::ServerTerminated.is_error());
        assert!(MainloopOutcome::UnrecoverableIo.is_error());
        assert!(MainloopOutcome::UnknownError { code: -22 }.is_error());
        assert!(!MainloopOutcome::ReconnectRequested.is_error());
        assert!(!MainloopOutcome::UserCancelled.is_error());
    }

    #[cfg(unix)]
    fn mock_ipv4_packet() -> [u8; 20] {
        [
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 2,
            10, 0, 0, 1,
        ]
    }

    #[test]
    fn collects_events_in_order_without_network() {
        let auth = AuthRequest::new(
            "VPN Login",
            vec![
                AuthField::text("username", "Username").unwrap(),
                AuthField::password("password", "Password").unwrap(),
                AuthField::otp("otp", "One-time password").unwrap(),
            ],
        )
        .unwrap();
        let mut sink = VecEventSink::new();

        emit_tunnel_event(
            &mut sink,
            TunnelEvent::StateChanged(TunnelState::Configuring),
        );
        emit_tunnel_event(
            &mut sink,
            TunnelEvent::Progress(ProgressEvent::new(1, "setup")),
        );
        emit_tunnel_event(&mut sink, TunnelEvent::AuthRequired(auth));
        emit_tunnel_event(
            &mut sink,
            TunnelEvent::StateChanged(TunnelState::AwaitingAuth),
        );

        let events = sink.events();
        assert_eq!(events.len(), 4);
        assert_eq!(
            events[0],
            TunnelEvent::StateChanged(TunnelState::Configuring)
        );

        let TunnelEvent::Progress(progress) = &events[1] else {
            panic!("expected progress event");
        };
        assert_eq!(progress.level.raw(), 1);
        assert_eq!(progress.message, "setup");

        let TunnelEvent::AuthRequired(request) = &events[2] else {
            panic!("expected auth event");
        };
        assert_eq!(request.fields.len(), 3);
        assert!(!request.fields[0].is_secret());
        assert!(request.fields[1].is_secret());
        assert!(request.fields[2].is_secret());

        assert_eq!(
            events[3],
            TunnelEvent::StateChanged(TunnelState::AwaitingAuth)
        );
    }

    #[test]
    fn vec_event_sink_can_be_consumed() {
        let mut sink = VecEventSink::new();
        emit_tunnel_event(&mut sink, TunnelEvent::StateChanged(TunnelState::Idle));

        assert_eq!(
            sink.into_events(),
            vec![TunnelEvent::StateChanged(TunnelState::Idle)]
        );
    }

    #[test]
    fn emits_validated_progress_events_without_network() {
        let mut sink = VecEventSink::new();

        emit_progress(&mut sink, 2, "  TLS handshake complete\n").unwrap();

        let events = sink.into_events();
        assert_eq!(events.len(), 1);
        let TunnelEvent::Progress(progress) = &events[0] else {
            panic!("expected progress event");
        };
        assert_eq!(progress.level.raw(), 2);
        assert_eq!(progress.message, "TLS handshake complete");
    }

    #[test]
    fn rejects_invalid_progress_messages() {
        let mut sink = VecEventSink::new();

        assert_eq!(
            emit_progress(&mut sink, 1, "  \n").unwrap_err(),
            ProgressEventError::EmptyMessage
        );
        assert_eq!(
            emit_progress(&mut sink, 1, "bad\0message").unwrap_err(),
            ProgressEventError::InteriorNul
        );
        assert!(sink.events().is_empty());
    }

    #[test]
    fn preserves_multiple_progress_event_order() {
        let mut sink = VecEventSink::new();

        emit_progress(&mut sink, 1, "first").unwrap();
        emit_progress(&mut sink, 3, "second").unwrap();

        let events = sink.events();
        assert_eq!(events.len(), 2);
        let TunnelEvent::Progress(first) = &events[0] else {
            panic!("expected first progress event");
        };
        let TunnelEvent::Progress(second) = &events[1] else {
            panic!("expected second progress event");
        };
        assert_eq!(first.level.raw(), 1);
        assert_eq!(first.message, "first");
        assert_eq!(second.level.raw(), 3);
        assert_eq!(second.message, "second");
    }

    #[test]
    fn translates_openconnect_progress_c_string_without_network() {
        let mut sink = VecEventSink::new();
        let message = CString::new("CSTP setup complete").unwrap();

        unsafe {
            emit_openconnect_progress(&mut sink, 1, message.as_ptr()).unwrap();
        }

        let events = sink.into_events();
        assert_eq!(events.len(), 1);
        let TunnelEvent::Progress(progress) = &events[0] else {
            panic!("expected progress event");
        };
        assert_eq!(progress.level.raw(), 1);
        assert_eq!(progress.message, "CSTP setup complete");
    }

    #[test]
    fn rejects_null_openconnect_progress_message() {
        let mut sink = VecEventSink::new();

        let err = unsafe { emit_openconnect_progress(&mut sink, 1, ptr::null()) }.unwrap_err();

        assert_eq!(err, ProgressCallbackError::NullMessage);
        assert!(sink.events().is_empty());
    }

    #[test]
    fn registered_progress_hook_emits_tunnel_event_without_network() {
        let _lock = PROGRESS_HOOK_TEST_LOCK.lock().unwrap();
        let mut sink = VecEventSink::new();
        let mut context = ProgressCallbackContext::new(&mut sink);
        let message = CString::new("ESP disabled").unwrap();
        let _guard = install_openconnect_progress_hook::<VecEventSink>();

        unsafe {
            sys::oc_oxide_progress_sink(context.as_privdata(), 2, message.as_ptr());
        }

        drop(context);
        let events = sink.into_events();
        assert_eq!(events.len(), 1);
        let TunnelEvent::Progress(progress) = &events[0] else {
            panic!("expected progress event");
        };
        assert_eq!(progress.level.raw(), 2);
        assert_eq!(progress.message, "ESP disabled");
    }

    #[test]
    fn session_with_progress_sink_routes_callback_without_network() {
        let _lock = PROGRESS_HOOK_TEST_LOCK.lock().unwrap();
        let mut sink = VecEventSink::new();
        let mut session =
            OpenConnectSession::new_with_progress_sink("oc-oxide-test", &mut sink).unwrap();
        let server = ServerUrl::parse("https://vpn.example.test:555/+CSCOE+/logon.html").unwrap();
        let profile = TunnelProfile::new("office", server).unwrap();
        session
            .session_mut()
            .configure_for_anyconnect(&profile)
            .unwrap();
        let message = CString::new("configured").unwrap();

        unsafe {
            sys::oc_oxide_progress_sink(session.progress_privdata(), 1, message.as_ptr());
        }

        assert!(session.session().cmd_write_fd() >= 0);
        drop(session);
        let events = sink.into_events();
        assert_eq!(events.len(), 1);
        let TunnelEvent::Progress(progress) = &events[0] else {
            panic!("expected progress event");
        };
        assert_eq!(progress.level.raw(), 1);
        assert_eq!(progress.message, "configured");
    }

    #[test]
    fn session_with_callbacks_routes_progress_and_auth_without_network() {
        let _lock = PROGRESS_HOOK_TEST_LOCK.lock().unwrap();
        let mut sink = VecEventSink::new();
        let mut handler = StaticAuthHandler::new(AuthFormDecision::Submit(
            AuthResponse::new(vec![
                AuthAnswer::text("username", "alice").unwrap(),
                AuthAnswer::secret("password", "not-a-real-password").unwrap(),
            ])
            .unwrap()
            .with_form_id("main")
            .unwrap(),
        ));
        let mut session =
            OpenConnectSession::new_with_callbacks("oc-oxide-test", &mut sink, &mut handler)
                .unwrap();
        let server = ServerUrl::parse("https://vpn.example.test:555/+CSCOE+/logon.html").unwrap();
        let profile = TunnelProfile::new("office", server).unwrap();
        session
            .session_mut()
            .configure_for_anyconnect(&profile)
            .unwrap();
        let progress_message = CString::new("configured").unwrap();

        unsafe {
            sys::oc_oxide_progress_sink(session.callback_privdata(), 1, progress_message.as_ptr());
        }

        let banner = CString::new("VPN Login").unwrap();
        let auth_id = CString::new("main").unwrap();
        let user_name = CString::new("username").unwrap();
        let user_label = CString::new("Username").unwrap();
        let pass_name = CString::new("password").unwrap();
        let pass_label = CString::new("Password").unwrap();
        let mut user = raw_auth_opt(sys::OC_FORM_OPT_TEXT as i32, &user_name, &user_label);
        let mut password = raw_auth_opt(sys::OC_FORM_OPT_PASSWORD as i32, &pass_name, &pass_label);
        user.next = &mut *password;
        let mut form = raw_auth_form(&banner, Some(&auth_id), &mut *user);

        let rc = unsafe {
            openconnect_auth_callback::<VecEventSink, StaticAuthHandler>(
                session.callback_privdata(),
                &mut *form,
            )
        };

        assert_eq!(rc, sys::OC_FORM_RESULT_OK as i32);
        assert_eq!(raw_auth_value(&user), Some("alice".to_owned()));
        assert_eq!(
            raw_auth_value(&password),
            Some("not-a-real-password".to_owned())
        );
        assert!(session.session().cmd_write_fd() >= 0);
        drop(session);

        assert_eq!(handler.requests.len(), 1);
        let events = sink.into_events();
        assert_eq!(events.len(), 3);
        let TunnelEvent::Progress(progress) = &events[0] else {
            panic!("expected progress event");
        };
        assert_eq!(progress.message, "configured");
        assert_eq!(
            events[1],
            TunnelEvent::StateChanged(TunnelState::AwaitingAuth)
        );
        assert!(matches!(events[2], TunnelEvent::AuthRequired(_)));
    }

    #[test]
    fn progress_callback_reports_invalid_payload_without_panic() {
        let mut sink = VecEventSink::new();
        let mut context = ProgressCallbackContext::new(&mut sink);

        unsafe {
            openconnect_progress_callback::<VecEventSink>(context.as_privdata(), 1, ptr::null());
        }

        drop(context);
        let events = sink.into_events();
        assert_eq!(events.len(), 1);
        let TunnelEvent::Error(error) = &events[0] else {
            panic!("expected error event");
        };
        assert_eq!(error.operation.as_deref(), Some("openconnect_progress"));
        assert!(error.message.contains("NULL"));
    }

    #[test]
    fn auth_callback_emits_request_and_applies_response_without_network() {
        let banner = CString::new("VPN Login").unwrap();
        let auth_id = CString::new("main").unwrap();
        let user_name = CString::new("username").unwrap();
        let user_label = CString::new("Username").unwrap();
        let pass_name = CString::new("password").unwrap();
        let pass_label = CString::new("Password").unwrap();
        let mut user = raw_auth_opt(sys::OC_FORM_OPT_TEXT as i32, &user_name, &user_label);
        let mut password = raw_auth_opt(sys::OC_FORM_OPT_PASSWORD as i32, &pass_name, &pass_label);
        user.next = &mut *password;
        let mut form = raw_auth_form(&banner, Some(&auth_id), &mut *user);
        let mut sink = VecEventSink::new();
        let mut handler = StaticAuthHandler::new(AuthFormDecision::Submit(
            AuthResponse::new(vec![
                AuthAnswer::text("username", "alice").unwrap(),
                AuthAnswer::secret("password", "not-a-real-password").unwrap(),
            ])
            .unwrap()
            .with_form_id("main")
            .unwrap(),
        ));
        let mut context = AuthCallbackContext::new(&mut sink, &mut handler);

        let rc = unsafe {
            openconnect_auth_callback::<VecEventSink, StaticAuthHandler>(
                context.as_privdata(),
                &mut *form,
            )
        };

        assert_eq!(rc, sys::OC_FORM_RESULT_OK as i32);
        assert_eq!(raw_auth_value(&user), Some("alice".to_owned()));
        assert_eq!(
            raw_auth_value(&password),
            Some("not-a-real-password".to_owned())
        );
        drop(context);

        assert_eq!(handler.requests.len(), 1);
        assert_eq!(handler.requests[0].form_id.as_deref(), Some("main"));
        let events = sink.into_events();
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0],
            TunnelEvent::StateChanged(TunnelState::AwaitingAuth)
        );
        let TunnelEvent::AuthRequired(request) = &events[1] else {
            panic!("expected auth required event");
        };
        assert_eq!(request.fields.len(), 2);
        assert!(request.fields[1].is_secret());
    }

    #[test]
    fn auth_callback_returns_cancelled_without_writing_answers() {
        let banner = CString::new("VPN Login").unwrap();
        let user_name = CString::new("username").unwrap();
        let user_label = CString::new("Username").unwrap();
        let mut user = raw_auth_opt(sys::OC_FORM_OPT_TEXT as i32, &user_name, &user_label);
        let mut form = raw_auth_form(&banner, None, &mut *user);
        let mut sink = VecEventSink::new();
        let mut handler = StaticAuthHandler::new(AuthFormDecision::Cancel);
        let mut context = AuthCallbackContext::new(&mut sink, &mut handler);

        let rc = unsafe {
            openconnect_auth_callback::<VecEventSink, StaticAuthHandler>(
                context.as_privdata(),
                &mut *form,
            )
        };

        assert_eq!(rc, sys::OC_FORM_RESULT_CANCELLED as i32);
        assert_eq!(raw_auth_value(&user), None);
        drop(context);

        assert_eq!(handler.requests.len(), 1);
        let events = sink.into_events();
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0],
            TunnelEvent::StateChanged(TunnelState::AwaitingAuth)
        );
        assert!(matches!(events[1], TunnelEvent::AuthRequired(_)));
    }

    #[test]
    fn auth_callback_reports_errors_without_leaking_secret_answers() {
        let banner = CString::new("VPN Login").unwrap();
        let user_name = CString::new("username").unwrap();
        let user_label = CString::new("Username").unwrap();
        let mut user = raw_auth_opt(sys::OC_FORM_OPT_TEXT as i32, &user_name, &user_label);
        let mut form = raw_auth_form(&banner, None, &mut *user);
        let mut sink = VecEventSink::new();
        let mut handler = StaticAuthHandler::new(AuthFormDecision::Submit(
            AuthResponse::new(vec![
                AuthAnswer::secret("missing", "not-a-real-password").unwrap()
            ])
            .unwrap(),
        ));
        let mut context = AuthCallbackContext::new(&mut sink, &mut handler);

        let rc = unsafe {
            openconnect_auth_callback::<VecEventSink, StaticAuthHandler>(
                context.as_privdata(),
                &mut *form,
            )
        };

        assert_eq!(rc, sys::OC_FORM_RESULT_ERR);
        assert_eq!(raw_auth_value(&user), None);
        drop(context);

        let events = sink.into_events();
        assert_eq!(events.len(), 3);
        let TunnelEvent::Error(error) = &events[2] else {
            panic!("expected auth error event");
        };
        assert_eq!(error.operation.as_deref(), Some("openconnect_auth"));
        assert!(error.message.contains("missing"));
        assert!(!error.message.contains("not-a-real-password"));
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

    fn raw_auth_opt(field_type: i32, name: &CString, label: &CString) -> Box<sys::oc_form_opt> {
        let mut opt = Box::new(unsafe { std::mem::zeroed::<sys::oc_form_opt>() });
        opt.type_ = field_type;
        opt.name = name.as_ptr() as *mut _;
        opt.label = label.as_ptr() as *mut _;
        opt
    }

    fn raw_auth_form(
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

    fn raw_auth_value(opt: &sys::oc_form_opt) -> Option<String> {
        if opt._value.is_null() {
            return None;
        }

        Some(
            unsafe { std::ffi::CStr::from_ptr(opt._value) }
                .to_string_lossy()
                .into_owned(),
        )
    }
}
