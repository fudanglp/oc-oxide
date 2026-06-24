use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=csrc/progress_shim.c");
    println!("cargo:rerun-if-changed=../../vendor/openconnect");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "linux" {
        panic!("vendored OpenConnect build is currently implemented for Linux only");
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let vendor_dir = manifest_dir.join("../../vendor/openconnect");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let source_dir = out_dir.join("openconnect-src");
    let build_dir = out_dir.join("openconnect-build");
    let install_dir = out_dir.join("openconnect-install");

    build_openconnect(&vendor_dir, &source_dir, &build_dir, &install_dir);
    generate_bindings(&install_dir, &out_dir);
    compile_progress_shim();
    emit_link_directives(&install_dir);
}

fn build_openconnect(vendor_dir: &Path, source_dir: &Path, build_dir: &Path, install_dir: &Path) {
    let lib_dir = install_dir.join("lib");
    let shared_lib = lib_dir.join("libopenconnect.so");
    let static_lib = lib_dir.join("libopenconnect.a");

    if shared_lib.exists() && static_lib.exists() {
        return;
    }

    recreate_dir(source_dir);
    recreate_dir(build_dir);
    recreate_dir(install_dir);

    run(Command::new("cp")
        .arg("-a")
        .arg(format!("{}/.", vendor_dir.display()))
        .arg(source_dir));

    run(Command::new("./autogen.sh").current_dir(source_dir));

    let vpnc_script = vendor_dir.join("tests/scripts/vpnc-script");
    let configure = source_dir.join("configure");
    run(Command::new(configure)
        .current_dir(build_dir)
        .arg(format!("--prefix={}", install_dir.display()))
        .arg("--enable-static")
        .arg("--enable-shared")
        .arg("--without-gnutls")
        .arg("--with-openssl")
        .arg("--without-lz4")
        .arg("--without-libproxy")
        .arg("--without-stoken")
        .arg("--without-libpskc")
        .arg("--without-gssapi")
        .arg("--without-libpcsclite")
        .arg("--with-builtin-json")
        .arg("--disable-nls")
        .arg("--disable-docs")
        .arg(format!("--with-vpnc-script={}", vpnc_script.display())));

    let jobs = env::var("NUM_JOBS").unwrap_or_else(|_| "1".to_string());
    run(Command::new("make")
        .current_dir(build_dir)
        .arg(format!("-j{jobs}"))
        .arg("libopenconnect.la"));

    run(Command::new("make")
        .current_dir(build_dir)
        .arg("install-libLTLIBRARIES")
        .arg("install-includeHEADERS")
        .arg("install-pkgconfigDATA"));
}

fn generate_bindings(install_dir: &Path, out_dir: &Path) {
    let include_dir = install_dir.join("include");
    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .clang_arg(format!("-I{}", include_dir.display()))
        .allowlist_function("openconnect_get_version")
        .allowlist_function("openconnect_init_ssl")
        .allowlist_function("openconnect_vpninfo_new")
        .allowlist_function("openconnect_vpninfo_free")
        .allowlist_function("openconnect_set_protocol")
        .allowlist_function("openconnect_parse_url")
        .allowlist_function("openconnect_set_reported_os")
        .allowlist_function("openconnect_setup_cmd_pipe")
        .allowlist_function("openconnect_get_supported_protocols")
        .allowlist_function("openconnect_free_supported_protocols")
        .allowlist_function("openconnect_get_protocol")
        .allowlist_function("openconnect_get_dnsname")
        .allowlist_function("openconnect_get_urlpath")
        .allowlist_function("openconnect_get_port")
        .allowlist_function("openconnect_get_ifname")
        .allowlist_function("openconnect_get_ip_info")
        .allowlist_function("openconnect_obtain_cookie")
        .allowlist_function("openconnect_make_cstp_connection")
        .allowlist_function("openconnect_setup_tun_device")
        .allowlist_function("openconnect_setup_tun_fd")
        .allowlist_function("openconnect_setup_dtls")
        .allowlist_function("openconnect_mainloop")
        .allowlist_function("openconnect_get_cookie")
        .allowlist_function("openconnect_set_option_value")
        .allowlist_type("openconnect_info")
        .allowlist_type("openconnect_.*_vfn")
        .allowlist_type("oc_auth_form")
        .allowlist_type("oc_choice")
        .allowlist_type("oc_form_opt")
        .allowlist_type("oc_form_opt_select")
        .allowlist_type("oc_ip_info")
        .allowlist_type("oc_split_include")
        .allowlist_type("oc_vpn_proto")
        .allowlist_type("oc_vpn_option")
        .allowlist_var("OC_FORM_.*")
        .allowlist_var("OPENCONNECT_API_VERSION_.*");

    if let Some(gcc_include_dir) = gcc_include_dir() {
        builder = builder.clang_arg(format!("-isystem{}", gcc_include_dir.display()));
    }

    let bindings = builder
        .generate()
        .expect("failed to generate libopenconnect bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("failed to write bindings.rs");
}

fn gcc_include_dir() -> Option<PathBuf> {
    let output = Command::new("gcc")
        .arg("-print-file-name=include")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let path = String::from_utf8(output.stdout).ok()?;
    let path = PathBuf::from(path.trim());
    path.join("stddef.h").exists().then_some(path)
}

fn compile_progress_shim() {
    cc::Build::new()
        .file("csrc/progress_shim.c")
        .warnings(true)
        .compile("oc_oxide_progress_shim");
}

fn emit_link_directives(install_dir: &Path) {
    let lib_dir = install_dir.join("lib");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=dylib=openconnect");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_dir.display());
    println!("cargo:include={}", install_dir.join("include").display());
    println!("cargo:lib={}", lib_dir.display());
    println!("cargo:has_vendored_openconnect=1");
}

fn recreate_dir(path: &Path) {
    if path.exists() {
        std::fs::remove_dir_all(path)
            .unwrap_or_else(|err| panic!("failed to remove {}: {err}", path.display()));
    }
    std::fs::create_dir_all(path)
        .unwrap_or_else(|err| panic!("failed to create {}: {err}", path.display()));
}

fn run(command: &mut Command) {
    let status = command
        .status()
        .unwrap_or_else(|err| panic!("failed to run {command:?}: {err}"));

    if !status.success() {
        panic!("command failed with {status}: {command:?}");
    }
}
