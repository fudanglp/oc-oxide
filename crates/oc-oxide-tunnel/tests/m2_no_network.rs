use std::ffi::CString;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(unix)]
use std::os::unix::net::UnixDatagram;
use std::ptr;
use std::sync::Mutex;

use oc_oxide_config::{ServerUrl, TunnelProfile};
use oc_oxide_openconnect_sys as sys;
use oc_oxide_tunnel::{
    classify_mainloop_return, emit_openconnect_progress, install_openconnect_progress_hook,
    MainloopOutcome, OpenConnectSession, ProgressCallbackContext, ProgressCallbackError,
    TunnelEvent, TunnelState, VecEventSink,
};

static PROGRESS_HOOK_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn configures_anyconnect_session_without_network() {
    let mut session = OpenConnectSession::new("oc-oxide-m2-test").unwrap();
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
fn exposes_cancel_handle_and_empty_ip_snapshot_without_network() {
    let mut session = OpenConnectSession::new("oc-oxide-m2-test").unwrap();

    assert_eq!(session.ifname(), None);

    let snapshot = session.ip_info_snapshot().unwrap();
    assert_eq!(snapshot.address, None);
    assert_eq!(snapshot.netmask, None);
    assert_eq!(snapshot.domain, None);
    assert!(snapshot.dns.is_empty());
    assert!(snapshot.split_includes.is_empty());
    assert!(snapshot.split_excludes.is_empty());

    let cancel = session.take_cancel_handle().unwrap();
    assert!(cancel.raw_fd() >= 0);
    assert!(session.take_cancel_handle().is_none());
    assert_eq!(session.cmd_write_fd(), -1);
}

#[cfg(unix)]
#[test]
fn injects_mock_tun_fd_without_root_or_dev_net_tun() {
    let _lock = PROGRESS_HOOK_TEST_LOCK.lock().unwrap();
    let (mock_tun, peer) = UnixDatagram::pair().unwrap();
    let mut session = OpenConnectSession::new("oc-oxide-m2-test").unwrap();

    peer.send(&mock_ipv4_packet()).unwrap();
    let tun = unsafe { session.setup_tun_fd_for_test(mock_tun.as_raw_fd()) }.unwrap();

    assert_eq!(tun.ifname, None);
    assert_eq!(session.ifname(), None);
}

#[test]
fn routes_openconnect_progress_into_tunnel_events_without_network() {
    let _lock = PROGRESS_HOOK_TEST_LOCK.lock().unwrap();
    let mut sink = VecEventSink::new();
    let mut context = ProgressCallbackContext::new(&mut sink);
    let message = CString::new("configured").unwrap();
    let _guard = install_openconnect_progress_hook::<VecEventSink>();

    unsafe {
        sys::oc_oxide_progress_sink(context.as_privdata(), 1, message.as_ptr());
    }

    drop(context);
    let events = sink.into_events();
    assert_eq!(events.len(), 1);
    let TunnelEvent::Progress(progress) = &events[0] else {
        panic!("expected progress event");
    };
    assert_eq!(progress.level.raw(), 1);
    assert_eq!(progress.message, "configured");
}

#[test]
fn rejects_null_progress_payload_without_network() {
    let mut sink = VecEventSink::new();

    let err = unsafe { emit_openconnect_progress(&mut sink, 1, ptr::null()) }.unwrap_err();

    assert_eq!(err, ProgressCallbackError::NullMessage);
    assert!(sink.events().is_empty());
}

#[test]
fn classifies_mainloop_return_codes_for_callers() {
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
    assert!(MainloopOutcome::UserCancelled.is_graceful_stop());
    assert!(MainloopOutcome::CookieRejected.is_error());
    assert_eq!(
        classify_mainloop_return(-22),
        MainloopOutcome::UnknownError { code: -22 }
    );
}

#[test]
fn event_sink_preserves_milestone_ordering() {
    let mut sink = VecEventSink::new();

    oc_oxide_tunnel::emit_tunnel_event(&mut sink, TunnelEvent::StateChanged(TunnelState::Idle));
    oc_oxide_tunnel::emit_tunnel_event(
        &mut sink,
        TunnelEvent::StateChanged(TunnelState::Configuring),
    );

    assert_eq!(
        sink.into_events(),
        vec![
            TunnelEvent::StateChanged(TunnelState::Idle),
            TunnelEvent::StateChanged(TunnelState::Configuring),
        ]
    );
}

#[cfg(unix)]
fn mock_ipv4_packet() -> [u8; 20] {
    [
        0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 2, 10, 0,
        0, 1,
    ]
}
