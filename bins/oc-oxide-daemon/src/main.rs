use std::env;
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};

use oc_oxide_daemon::{
    default_daemon_socket_path, recover_system_runtime_journal_at_startup,
    serve_unix_socket_until_shutdown, DaemonWorkerController, SystemOpenConnectWorkerFactory,
    DAEMON_ROLE,
};

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

fn main() {
    if let Err(err) = run() {
        eprintln!("oc-oxide-daemon error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("serve") => run_serve(),
        Some("help") | Some("--help") | Some("-h") | None => {
            print_help();
            Ok(())
        }
        Some(command) => Err(format!("unknown oc-oxide-daemon command {command:?}").into()),
    }
}

fn print_help() {
    println!("{DAEMON_ROLE}");
    println!("oc-oxide-daemon serve");
}

fn run_serve() -> Result<(), Box<dyn Error>> {
    let socket_path = default_daemon_socket_path();
    install_shutdown_signal_handlers()?;
    recover_system_runtime_journal_at_startup()?;
    let worker_factory = SystemOpenConnectWorkerFactory::from_env()?;
    let controller = DaemonWorkerController::new(worker_factory);

    println!(
        "oc-oxide-daemon: serving JSON-line IPC on {}",
        socket_path.display()
    );
    serve_unix_socket_until_shutdown(socket_path, controller, &SHUTDOWN_REQUESTED)?;
    Ok(())
}

#[cfg(unix)]
fn install_shutdown_signal_handlers() -> Result<(), Box<dyn Error>> {
    SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
    let handler = handle_shutdown_signal as *const () as libc::sighandler_t;
    let int_result = unsafe { libc::signal(libc::SIGINT, handler) };
    let term_result = unsafe { libc::signal(libc::SIGTERM, handler) };
    if int_result == libc::SIG_ERR || term_result == libc::SIG_ERR {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
extern "C" fn handle_shutdown_signal(_signal: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

#[cfg(not(unix))]
fn install_shutdown_signal_handlers() -> Result<(), Box<dyn Error>> {
    Ok(())
}
