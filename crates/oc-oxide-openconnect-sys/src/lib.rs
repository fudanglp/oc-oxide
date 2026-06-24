//! Raw FFI boundary for libopenconnect.
//!
//! This crate intentionally owns only generated bindings and C shims. Higher
//! level VPN lifecycle, auth, route, DNS, IPC, and UI behavior belongs in other
//! crates.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::os::raw::{c_char, c_int, c_void};
use std::sync::{Mutex, OnceLock};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

extern "C" {
    /// Variadic progress callback trampoline for `openconnect_vpninfo_new`.
    pub fn oc_oxide_progress_trampoline(
        privdata: *mut ::std::os::raw::c_void,
        level: ::std::os::raw::c_int,
        fmt: *const ::std::os::raw::c_char,
        ...
    );
}

/// Plain Rust-callable progress sink used by the C trampoline.
pub type OcOxideProgressSink =
    unsafe extern "C" fn(privdata: *mut c_void, level: c_int, msg: *const c_char);

static PROGRESS_SINK: OnceLock<Mutex<Option<OcOxideProgressSink>>> = OnceLock::new();

/// Register the low-level progress sink used by `oc_oxide_progress_sink`.
///
/// This is process-global because the C symbol called by the progress shim is
/// process-global. Higher-level crates should keep direct libopenconnect calls
/// on one tunnel thread and restore the previous sink when they install one for
/// tests.
pub fn oc_oxide_set_progress_sink(
    sink: Option<OcOxideProgressSink>,
) -> Option<OcOxideProgressSink> {
    let mut guard = progress_sink_cell()
        .lock()
        .expect("progress sink mutex poisoned");
    std::mem::replace(&mut *guard, sink)
}

/// Rust sink called by the C progress trampoline after formatting.
#[no_mangle]
pub unsafe extern "C" fn oc_oxide_progress_sink(
    privdata: *mut c_void,
    level: c_int,
    msg: *const c_char,
) {
    let sink = progress_sink_cell()
        .lock()
        .expect("progress sink mutex poisoned")
        .as_ref()
        .copied();

    if let Some(sink) = sink {
        sink(privdata, level, msg);
    }
}

/// Human-readable crate role used by workspace smoke tests.
pub const CRATE_ROLE: &str = "raw libopenconnect FFI";

fn progress_sink_cell() -> &'static Mutex<Option<OcOxideProgressSink>> {
    PROGRESS_SINK.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
mod tests {
    use std::ffi::{CStr, CString};
    use std::ptr;
    use std::sync::{Mutex, OnceLock};

    use super::{
        oc_ip_info, oc_oxide_progress_sink, oc_oxide_progress_trampoline,
        oc_oxide_set_progress_sink, oc_vpn_option, oc_vpn_proto,
        openconnect_free_supported_protocols, openconnect_get_dnsname, openconnect_get_ip_info,
        openconnect_get_port, openconnect_get_protocol, openconnect_get_supported_protocols,
        openconnect_get_urlpath, openconnect_get_version, openconnect_init_ssl,
        openconnect_parse_url, openconnect_set_protocol, openconnect_set_reported_os,
        openconnect_setup_cmd_pipe, openconnect_vpninfo_free, openconnect_vpninfo_new, CRATE_ROLE,
    };

    static RECORDED_PROGRESS: OnceLock<Mutex<Vec<(usize, i32, String)>>> = OnceLock::new();
    static PROGRESS_HOOK_TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn record_progress(
        privdata: *mut std::os::raw::c_void,
        level: std::os::raw::c_int,
        msg: *const std::os::raw::c_char,
    ) {
        let message = if msg.is_null() {
            String::new()
        } else {
            CStr::from_ptr(msg).to_string_lossy().into_owned()
        };
        recorded_progress()
            .lock()
            .unwrap()
            .push((privdata as usize, level, message));
    }

    fn recorded_progress() -> &'static Mutex<Vec<(usize, i32, String)>> {
        RECORDED_PROGRESS.get_or_init(|| Mutex::new(Vec::new()))
    }

    #[test]
    fn documents_ffi_role() {
        assert!(CRATE_ROLE.contains("libopenconnect"));
    }

    #[test]
    fn links_vendored_openconnect_version_symbol() {
        let version = unsafe {
            let ptr = openconnect_get_version();
            assert!(!ptr.is_null());
            CStr::from_ptr(ptr).to_str().unwrap()
        };

        assert!(version.starts_with('v'));
    }

    #[test]
    fn forwards_progress_sink_payload_without_network() {
        let _lock = PROGRESS_HOOK_TEST_LOCK.lock().unwrap();
        recorded_progress().lock().unwrap().clear();
        let previous = oc_oxide_set_progress_sink(Some(record_progress));
        let msg = CString::new("connected").unwrap();

        unsafe {
            oc_oxide_progress_sink(0x1234usize as *mut _, 2, msg.as_ptr());
        }

        oc_oxide_set_progress_sink(previous);
        let recorded = recorded_progress().lock().unwrap().clone();
        assert_eq!(recorded, vec![(0x1234, 2, "connected".to_owned())]);
    }

    #[test]
    fn formats_progress_trampoline_payload_without_network() {
        let _lock = PROGRESS_HOOK_TEST_LOCK.lock().unwrap();
        recorded_progress().lock().unwrap().clear();
        let previous = oc_oxide_set_progress_sink(Some(record_progress));

        unsafe {
            oc_oxide_progress_trampoline(
                0x5678usize as *mut _,
                3,
                c"step %s\n".as_ptr(),
                c"ready".as_ptr(),
            );
        }

        oc_oxide_set_progress_sink(previous);
        let recorded = recorded_progress().lock().unwrap().clone();
        assert_eq!(recorded, vec![(0x5678, 3, "step ready".to_owned())]);
    }

    #[test]
    fn creates_configures_and_frees_vpninfo_without_network() {
        let rc = unsafe { openconnect_init_ssl() };
        assert_eq!(rc, 0);

        let useragent = CString::new("oc-oxide-test").unwrap();
        let vpninfo = unsafe {
            openconnect_vpninfo_new(
                useragent.as_ptr(),
                None,
                None,
                None,
                Some(oc_oxide_progress_trampoline),
                ptr::null_mut(),
            )
        };
        assert!(!vpninfo.is_null());

        let protocol = CString::new("anyconnect").unwrap();
        let rc = unsafe { openconnect_set_protocol(vpninfo, protocol.as_ptr()) };
        assert_eq!(rc, 0);
        let parsed_protocol = unsafe { CStr::from_ptr(openconnect_get_protocol(vpninfo)) };
        assert_eq!(parsed_protocol.to_bytes(), b"anyconnect");

        let os = CString::new("linux").unwrap();
        let rc = unsafe { openconnect_set_reported_os(vpninfo, os.as_ptr()) };
        assert_eq!(rc, 0);

        let url = CString::new("https://vpn.example.test:443/+CSCOE+/logon.html").unwrap();
        let rc = unsafe { openconnect_parse_url(vpninfo, url.as_ptr()) };
        assert_eq!(rc, 0);
        let dns_name_ptr = unsafe { openconnect_get_dnsname(vpninfo) };
        assert!(!dns_name_ptr.is_null());
        let dns_name = unsafe { CStr::from_ptr(dns_name_ptr) };
        assert_eq!(dns_name.to_bytes(), b"vpn.example.test");
        assert_eq!(unsafe { openconnect_get_port(vpninfo) }, 443);
        let url_path_ptr = unsafe { openconnect_get_urlpath(vpninfo) };
        assert!(!url_path_ptr.is_null());
        let url_path = unsafe { CStr::from_ptr(url_path_ptr) };
        assert_eq!(url_path.to_bytes(), b"+CSCOE+/logon.html");

        let cmd_fd = unsafe { openconnect_setup_cmd_pipe(vpninfo) };
        assert!(cmd_fd >= 0);

        unsafe { openconnect_vpninfo_free(vpninfo) };
    }

    #[test]
    fn reads_empty_ip_info_without_network() {
        let rc = unsafe { openconnect_init_ssl() };
        assert_eq!(rc, 0);

        let useragent = CString::new("oc-oxide-test").unwrap();
        let vpninfo = unsafe {
            openconnect_vpninfo_new(
                useragent.as_ptr(),
                None,
                None,
                None,
                Some(oc_oxide_progress_trampoline),
                ptr::null_mut(),
            )
        };
        assert!(!vpninfo.is_null());

        let mut info: *const oc_ip_info = ptr::null();
        let mut cstp_options: *const oc_vpn_option = ptr::null();
        let mut dtls_options: *const oc_vpn_option = ptr::null();
        let rc = unsafe {
            openconnect_get_ip_info(vpninfo, &mut info, &mut cstp_options, &mut dtls_options)
        };
        assert_eq!(rc, 0);
        assert!(!info.is_null());
        assert!(cstp_options.is_null());
        assert!(dtls_options.is_null());

        let info = unsafe { &*info };
        assert!(info.addr.is_null());
        assert!(info.netmask.is_null());
        assert!(info.addr6.is_null());
        assert!(info.netmask6.is_null());
        assert!(info.dns.iter().all(|dns| dns.is_null()));
        assert!(info.nbns.iter().all(|nbns| nbns.is_null()));
        assert!(info.domain.is_null());
        assert!(info.proxy_pac.is_null());
        assert_eq!(info.mtu, 0);
        assert!(info.split_dns.is_null());
        assert!(info.split_includes.is_null());
        assert!(info.split_excludes.is_null());
        assert!(info.gateway_addr.is_null());

        unsafe { openconnect_vpninfo_free(vpninfo) };
    }

    #[test]
    fn lists_supported_protocols_without_network() {
        let mut protos: *mut oc_vpn_proto = ptr::null_mut();
        let count = unsafe { openconnect_get_supported_protocols(&mut protos) };
        assert!(count > 0);
        assert!(!protos.is_null());

        let protocols = unsafe { std::slice::from_raw_parts(protos, count as usize) };
        let has_anyconnect = protocols.iter().any(|proto| {
            if proto.name.is_null() {
                return false;
            }
            unsafe { CStr::from_ptr(proto.name).to_bytes() == b"anyconnect" }
        });

        unsafe { openconnect_free_supported_protocols(protos) };

        assert!(has_anyconnect);
    }
}
