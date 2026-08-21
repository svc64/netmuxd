// Jackson Coxson
//
// Take over Apple's "Apple Mobile Device Service" (AMDS) by repointing the
// service's ImagePath at netmuxd, so the Service Control Manager launches
// netmuxd instead of `AppleMobileDeviceService.exe`.
//
// `install-service` saves the original ImagePath under
// HKLM\SOFTWARE\netmuxd so `uninstall-service` can put Apple's binary back.

#![cfg(target_os = "windows")]

use std::io;
use std::ptr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use log::{error, info, warn};

use super::ffi;

const AMDS_SERVICE_NAME: &str = "Apple Mobile Device Service";

// Where we stash Apple's original ImagePath so we can restore it.
const REG_SUBKEY: &str = r"SOFTWARE\netmuxd";
const REG_VALUE_ORIGINAL: &str = "OriginalAmdsImagePath";

// Service Control Manager / service access rights.
const SC_MANAGER_CONNECT: u32 = 0x0001;
const SERVICE_QUERY_CONFIG: u32 = 0x0001;
const SERVICE_CHANGE_CONFIG: u32 = 0x0002;
const SERVICE_QUERY_STATUS: u32 = 0x0004;
const SERVICE_START: u32 = 0x0010;
const SERVICE_STOP: u32 = 0x0020;

// The bundle of rights install/uninstall need: read+rewrite config and
// bounce the service so the change takes effect without a reboot.
const SERVICE_RECONFIG_ACCESS: u32 = SERVICE_QUERY_CONFIG
    | SERVICE_CHANGE_CONFIG
    | SERVICE_QUERY_STATUS
    | SERVICE_START
    | SERVICE_STOP;

// ChangeServiceConfigW: leave a field alone.
const SERVICE_NO_CHANGE: u32 = 0xffff_ffff;

// Service types / states / accepted controls.
const SERVICE_WIN32_OWN_PROCESS: u32 = 0x0000_0010;
const SERVICE_STOPPED: u32 = 0x0000_0001;
const SERVICE_START_PENDING: u32 = 0x0000_0002;
const SERVICE_STOP_PENDING: u32 = 0x0000_0003;
const SERVICE_RUNNING: u32 = 0x0000_0004;
const SERVICE_ACCEPT_STOP: u32 = 0x0000_0001;
const SERVICE_ACCEPT_SHUTDOWN: u32 = 0x0000_0004;

// Service control codes delivered to our handler.
const SERVICE_CONTROL_STOP: u32 = 0x0000_0001;
const SERVICE_CONTROL_INTERROGATE: u32 = 0x0000_0004;
const SERVICE_CONTROL_SHUTDOWN: u32 = 0x0000_0005;

// Win32 error codes.
const ERROR_BROKEN_PIPE: i32 = 109;
const ERROR_INSUFFICIENT_BUFFER: i32 = 122;
const ERROR_SERVICE_ALREADY_RUNNING: i32 = 1056;
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
const ERROR_SERVICE_CANNOT_ACCEPT_CTRL: i32 = 1061;
const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;

// Registry.
const HKEY_LOCAL_MACHINE: ffi::Handle = 0x8000_0002_usize as ffi::Handle;
const KEY_READ: u32 = 0x2_0019;
const KEY_WRITE: u32 = 0x2_0006;
const REG_SZ: u32 = 1;
const ERROR_SUCCESS: i32 = 0;
const ERROR_FILE_NOT_FOUND: i32 = 2;

#[repr(C)]
struct QueryServiceConfigW {
    dw_service_type: u32,
    dw_start_type: u32,
    dw_error_control: u32,
    lp_binary_path_name: *mut u16,
    lp_load_order_group: *mut u16,
    dw_tag_id: u32,
    lp_dependencies: *mut u16,
    lp_service_start_name: *mut u16,
    lp_display_name: *mut u16,
}

#[repr(C)]
struct ServiceStatus {
    dw_service_type: u32,
    dw_current_state: u32,
    dw_controls_accepted: u32,
    dw_win32_exit_code: u32,
    dw_service_specific_exit_code: u32,
    dw_check_point: u32,
    dw_wait_hint: u32,
}

impl Default for ServiceStatus {
    fn default() -> Self {
        Self {
            dw_service_type: SERVICE_WIN32_OWN_PROCESS,
            dw_current_state: SERVICE_STOPPED,
            dw_controls_accepted: 0,
            dw_win32_exit_code: 0,
            dw_service_specific_exit_code: 0,
            dw_check_point: 0,
            dw_wait_hint: 0,
        }
    }
}

#[repr(C)]
struct ServiceTableEntryW {
    lp_service_name: *const u16,
    lp_service_proc: Option<unsafe extern "system" fn(u32, *mut *mut u16)>,
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenSCManagerW(machine: *const u16, database: *const u16, access: u32) -> ffi::Handle;
    fn OpenServiceW(scm: ffi::Handle, name: *const u16, access: u32) -> ffi::Handle;
    fn CloseServiceHandle(handle: ffi::Handle) -> ffi::Bool;
    #[allow(clippy::too_many_arguments)]
    fn ChangeServiceConfigW(
        service: ffi::Handle,
        service_type: u32,
        start_type: u32,
        error_control: u32,
        binary_path: *const u16,
        load_order_group: *const u16,
        tag_id: *mut u32,
        dependencies: *const u16,
        start_name: *const u16,
        password: *const u16,
        display_name: *const u16,
    ) -> ffi::Bool;
    fn QueryServiceConfigW(
        service: ffi::Handle,
        config: *mut QueryServiceConfigW,
        buf_size: u32,
        bytes_needed: *mut u32,
    ) -> ffi::Bool;
    fn StartServiceW(service: ffi::Handle, num_args: u32, args: *const *const u16) -> ffi::Bool;
    fn ControlService(service: ffi::Handle, control: u32, status: *mut ServiceStatus) -> ffi::Bool;
    fn QueryServiceStatus(service: ffi::Handle, status: *mut ServiceStatus) -> ffi::Bool;

    fn StartServiceCtrlDispatcherW(table: *const ServiceTableEntryW) -> ffi::Bool;
    fn RegisterServiceCtrlHandlerW(
        name: *const u16,
        handler: Option<unsafe extern "system" fn(u32)>,
    ) -> ffi::Handle;
    fn SetServiceStatus(handle: ffi::Handle, status: *const ServiceStatus) -> ffi::Bool;

    fn RegOpenKeyExW(
        key: ffi::Handle,
        subkey: *const u16,
        options: u32,
        sam: u32,
        result: *mut ffi::Handle,
    ) -> i32;
    fn RegCreateKeyExW(
        key: ffi::Handle,
        subkey: *const u16,
        reserved: u32,
        class: *const u16,
        options: u32,
        sam: u32,
        security: *mut core::ffi::c_void,
        result: *mut ffi::Handle,
        disposition: *mut u32,
    ) -> i32;
    fn RegSetValueExW(
        key: ffi::Handle,
        name: *const u16,
        reserved: u32,
        value_type: u32,
        data: *const u8,
        data_len: u32,
    ) -> i32;
    fn RegQueryValueExW(
        key: ffi::Handle,
        name: *const u16,
        reserved: *mut u32,
        value_type: *mut u32,
        data: *mut u8,
        data_len: *mut u32,
    ) -> i32;
    fn RegDeleteValueW(key: ffi::Handle, name: *const u16) -> i32;
    fn RegCloseKey(key: ffi::Handle) -> i32;
}

/// Encode a `&str` as a NUL-terminated UTF-16 buffer for the wide Win32 APIs.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Read a NUL-terminated UTF-16 string from a raw pointer.
///
/// # Safety
/// `ptr` must be a valid, NUL-terminated wide string (or null).
unsafe fn read_wide(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    // Bound the scan so a corrupt/non-terminated buffer can't run away.
    while len < 32768 && unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    Some(String::from_utf16_lossy(slice))
}

/// RAII guard so every early-return path closes its SCM/service handle.
struct ScHandle(ffi::Handle);
impl Drop for ScHandle {
    fn drop(&mut self) {
        if !ffi::is_invalid(self.0) {
            unsafe { CloseServiceHandle(self.0) };
        }
    }
}

struct RegKey(ffi::Handle);
impl Drop for RegKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { RegCloseKey(self.0) };
        }
    }
}

/// Open the SCM and the AMDS service with `access`. Returns
/// `Ok(None)` if the service isn't installed on this machine.
fn open_amds(access: u32) -> io::Result<Option<(ScHandle, ScHandle)>> {
    let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if ffi::is_invalid(scm) {
        return Err(io::Error::last_os_error());
    }
    let scm = ScHandle(scm);

    let name = wide(AMDS_SERVICE_NAME);
    let service = unsafe { OpenServiceW(scm.0, name.as_ptr(), access) };
    if ffi::is_invalid(service) {
        let err = io::Error::last_os_error();
        return if err.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST) {
            Ok(None)
        } else {
            Err(err)
        };
    }
    Ok(Some((scm, ScHandle(service))))
}

/// Current `ImagePath` (binary path) of the given service.
fn query_binary_path(service: ffi::Handle) -> io::Result<String> {
    let mut needed: u32 = 0;
    // First call sizes the buffer; it "fails" with ERROR_INSUFFICIENT_BUFFER.
    let ok = unsafe { QueryServiceConfigW(service, ptr::null_mut(), 0, &mut needed) };
    if ok == ffi::FALSE {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER) {
            return Err(err);
        }
    }
    if needed == 0 {
        return Err(io::Error::other("QueryServiceConfig reported zero size"));
    }

    let mut buf = vec![0u8; needed as usize];
    let cfg = buf.as_mut_ptr() as *mut QueryServiceConfigW;
    let ok = unsafe { QueryServiceConfigW(service, cfg, needed, &mut needed) };
    if ok == ffi::FALSE {
        return Err(io::Error::last_os_error());
    }
    let path = unsafe { read_wide((*cfg).lp_binary_path_name) };
    path.ok_or_else(|| io::Error::other("service had no ImagePath"))
}

/// We put --service on the end, so this just makes sure we don't
/// re-overwrite again
fn is_netmuxd_binpath(binpath: &str) -> bool {
    binpath.to_lowercase().contains("--service")
}

fn save_original(binpath: &str) -> io::Result<()> {
    let subkey = wide(REG_SUBKEY);
    let mut key: ffi::Handle = ptr::null_mut();
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            ptr::null(),
            0,
            KEY_WRITE,
            ptr::null_mut(),
            &mut key,
            ptr::null_mut(),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc));
    }
    let key = RegKey(key);

    let name = wide(REG_VALUE_ORIGINAL);
    // REG_SZ data is the UTF-16 bytes including the NUL terminator.
    let data = wide(binpath);
    let byte_len = (data.len() * 2) as u32;
    let rc = unsafe {
        RegSetValueExW(
            key.0,
            name.as_ptr(),
            0,
            REG_SZ,
            data.as_ptr() as *const u8,
            byte_len,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc));
    }
    Ok(())
}

/// Read back the saved Apple ImagePath, if any.
fn load_original() -> io::Result<Option<String>> {
    let subkey = wide(REG_SUBKEY);
    let mut key: ffi::Handle = ptr::null_mut();
    let rc = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, KEY_READ, &mut key) };
    if rc == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc));
    }
    let key = RegKey(key);

    let name = wide(REG_VALUE_ORIGINAL);
    let mut byte_len: u32 = 0;
    let rc = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut byte_len,
        )
    };
    if rc == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc));
    }
    if byte_len == 0 {
        return Ok(None);
    }

    // Round up to whole u16s.
    let mut data = vec![0u16; byte_len.div_ceil(2) as usize];
    let mut len = (data.len() * 2) as u32;
    let rc = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            data.as_mut_ptr() as *mut u8,
            &mut len,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc));
    }
    // Trim the trailing NUL(s).
    while matches!(data.last(), Some(0)) {
        data.pop();
    }
    Ok(Some(String::from_utf16_lossy(&data)))
}

fn delete_original() {
    let subkey = wide(REG_SUBKEY);
    let mut key: ffi::Handle = ptr::null_mut();
    let rc = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, KEY_WRITE, &mut key) };
    if rc != ERROR_SUCCESS {
        return;
    }
    let key = RegKey(key);
    let name = wide(REG_VALUE_ORIGINAL);
    unsafe { RegDeleteValueW(key.0, name.as_ptr()) };
}

fn set_binary_path(service: ffi::Handle, binpath: &str) -> io::Result<()> {
    let wpath = wide(binpath);
    let ok = unsafe {
        ChangeServiceConfigW(
            service,
            SERVICE_NO_CHANGE,
            SERVICE_NO_CHANGE,
            SERVICE_NO_CHANGE,
            wpath.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        )
    };
    if ok == ffi::FALSE {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn bounce_service(service: ffi::Handle) {
    request_stop(service);
    wait_until_stopped(service);
    start_with_retry(service);
}

fn request_stop(service: ffi::Handle) {
    let mut status = ServiceStatus::default();
    let ok = unsafe { ControlService(service, SERVICE_CONTROL_STOP, &mut status) };
    if ok != ffi::FALSE {
        return;
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        // gucci
        Some(ERROR_SERVICE_NOT_ACTIVE) => {}
        // in the middle of a stop
        Some(ERROR_BROKEN_PIPE) => {}
        // in a transition
        Some(ERROR_SERVICE_CANNOT_ACCEPT_CTRL) => {}
        _ => warn!("service: stop request failed: {err}"),
    }
}

fn start_with_retry(service: ffi::Handle) {
    let mut last_err = None;
    for _ in 0..25 {
        let ok = unsafe { StartServiceW(service, 0, ptr::null()) };
        if ok != ffi::FALSE {
            info!("service: (re)started \"{AMDS_SERVICE_NAME}\"");
            return;
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(ERROR_SERVICE_ALREADY_RUNNING) {
            info!("service: \"{AMDS_SERVICE_NAME}\" already running");
            return;
        }
        last_err = Some(err);
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    warn!(
        "service: could not start \"{AMDS_SERVICE_NAME}\" after retrying: {}. Start it manually \
         with `sc start \"{AMDS_SERVICE_NAME}\"`, or it will start on next boot.",
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".to_string())
    );
}

fn wait_until_stopped(service: ffi::Handle) {
    for _ in 0..50 {
        let mut status = ServiceStatus::default();
        let ok = unsafe { QueryServiceStatus(service, &mut status) };
        if ok == ffi::FALSE || status.dw_current_state == SERVICE_STOPPED {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    warn!("service: timed out waiting for \"{AMDS_SERVICE_NAME}\" to stop");
}

fn build_binpath(extra_args: &[String]) -> io::Result<String> {
    let exe = std::env::current_exe()?;
    let exe = exe.to_string_lossy();
    let mut cmd = format!("\"{exe}\" --service");
    for arg in extra_args {
        // Quote args with spaces so the service command line round-trips.
        if arg.contains(' ') {
            cmd.push_str(&format!(" \"{arg}\""));
        } else {
            cmd.push(' ');
            cmd.push_str(arg);
        }
    }
    Ok(cmd)
}

pub fn install_service(extra_args: &[String]) -> i32 {
    let (_scm, service) = match open_amds(SERVICE_RECONFIG_ACCESS) {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            error!(
                "install-service: \"{AMDS_SERVICE_NAME}\" is not installed. Install Apple's \
                 Mobile Device Support first."
            );
            return 1;
        }
        Err(e) if e.raw_os_error() == Some(5) => {
            error!("install-service: access denied. Re-run from an elevated prompt.");
            return 1;
        }
        Err(e) => {
            error!("install-service: could not open the service: {e}");
            return 1;
        }
    };

    let new_binpath = match build_binpath(extra_args) {
        Ok(p) => p,
        Err(e) => {
            error!("install-service: could not resolve netmuxd's path: {e}");
            return 1;
        }
    };

    if let Ok(exe) = std::env::current_exe()
        && exe.to_string_lossy().to_lowercase().contains("\\users\\")
    {
        warn!(
            "install-service: netmuxd lives at {}, inside a user profile. \"{AMDS_SERVICE_NAME}\" \
             runs as a low-privilege service account that cannot execute files there, so the \
             service will fail to start with \"Access is denied\". Copy netmuxd.exe to a system \
             location such as C:\\Program Files\\netmuxd\\ and run install-service from that copy.",
            exe.display()
        );
    }

    match query_binary_path(service.0) {
        Ok(current) if is_netmuxd_binpath(&current) => {
            info!("install-service: service already points at netmuxd; refreshing config");
        }
        Ok(current) => {
            if let Err(e) = save_original(&current) {
                error!(
                    "install-service: failed to save the original ImagePath ({e}); aborting so it isn't lost"
                );
                return 1;
            }
            info!("install-service: saved Apple's ImagePath ({current})");
        }
        Err(e) => {
            warn!(
                "install-service: couldn't read the current ImagePath ({e}); continuing without a saved original"
            );
        }
    }

    if let Err(e) = set_binary_path(service.0, &new_binpath) {
        if e.raw_os_error() == Some(5) {
            error!("install-service: access denied changing the config. Re-run elevated.");
        } else {
            error!("install-service: ChangeServiceConfig failed: {e}");
        }
        return 1;
    }
    info!("install-service: repointed \"{AMDS_SERVICE_NAME}\" -> {new_binpath}");

    bounce_service(service.0);
    info!("install-service: done. netmuxd now owns the service; no further elevation needed.");
    0
}

pub fn uninstall_service() -> i32 {
    let original = match load_original() {
        Ok(Some(p)) => p,
        Ok(None) => {
            error!(
                "uninstall-service: no saved original ImagePath found. Either install-service was \
                 never run, or an update already reset the service. Nothing to restore."
            );
            return 1;
        }
        Err(e) => {
            error!("uninstall-service: could not read the saved original: {e}");
            return 1;
        }
    };

    let (_scm, service) = match open_amds(SERVICE_RECONFIG_ACCESS) {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            error!("uninstall-service: \"{AMDS_SERVICE_NAME}\" is not installed.");
            return 1;
        }
        Err(e) if e.raw_os_error() == Some(5) => {
            error!("uninstall-service: access denied. Re-run from an elevated (admin) prompt.");
            return 1;
        }
        Err(e) => {
            error!("uninstall-service: could not open the service: {e}");
            return 1;
        }
    };

    if let Err(e) = set_binary_path(service.0, &original) {
        error!("uninstall-service: failed to restore the original ImagePath: {e}");
        return 1;
    }
    info!("uninstall-service: restored \"{AMDS_SERVICE_NAME}\" -> {original}");

    bounce_service(service.0);
    delete_original();
    info!("uninstall-service: done. Apple's service is back.");
    0
}

static RUNNER: OnceLock<fn()> = OnceLock::new();
// SERVICE_STATUS_HANDLE from RegisterServiceCtrlHandlerW, stashed for the
// control handler (an `extern "system" fn` that can't capture state).
static STATUS_HANDLE: AtomicUsize = AtomicUsize::new(0);

fn report(state: u32, controls_accepted: u32, wait_hint: u32) {
    let handle = STATUS_HANDLE.load(Ordering::SeqCst) as ffi::Handle;
    if handle.is_null() {
        return;
    }
    let status = ServiceStatus {
        dw_service_type: SERVICE_WIN32_OWN_PROCESS,
        dw_current_state: state,
        dw_controls_accepted: controls_accepted,
        dw_win32_exit_code: 0,
        dw_service_specific_exit_code: 0,
        dw_check_point: 0,
        dw_wait_hint: wait_hint,
    };
    unsafe { SetServiceStatus(handle, &status) };
}

unsafe extern "system" fn service_ctrl_handler(control: u32) {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            report(SERVICE_STOP_PENDING, 0, 3000);
            std::thread::spawn(|| {
                // Give the handler a beat to return to the SCM first.
                std::thread::sleep(std::time::Duration::from_millis(200));
                report(SERVICE_STOPPED, 0, 0);
                std::process::exit(0);
            });
        }
        SERVICE_CONTROL_INTERROGATE => {
            report(
                SERVICE_RUNNING,
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
                0,
            );
        }
        _ => {}
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let name = wide(AMDS_SERVICE_NAME);
    let handle = unsafe { RegisterServiceCtrlHandlerW(name.as_ptr(), Some(service_ctrl_handler)) };
    if ffi::is_invalid(handle) {
        error!(
            "service: RegisterServiceCtrlHandler failed: {}",
            io::Error::last_os_error()
        );
        return;
    }
    STATUS_HANDLE.store(handle as usize, Ordering::SeqCst);

    report(SERVICE_START_PENDING, 0, 3000);
    report(
        SERVICE_RUNNING,
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        0,
    );

    if let Some(runner) = RUNNER.get() {
        // Blocks for the life of the service.
        runner();
    }

    report(SERVICE_STOPPED, 0, 0);
}

/// Entry point for `--service`. Hands control to the SCM dispatcher, which
/// calls [`service_main`] on its own thread; `runner` is the daemon loop.
///
/// If we weren't actually launched by the SCM (like if someone ran
/// `netmuxd --service` by hand), the dispatcher fails with
/// `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` and we fall back to running the
/// daemon directly so it's still usable/testable from a console.
pub fn run_as_service(runner: fn()) {
    let _ = RUNNER.set(runner);

    let name = wide(AMDS_SERVICE_NAME);
    let table = [
        ServiceTableEntryW {
            lp_service_name: name.as_ptr(),
            lp_service_proc: Some(service_main),
        },
        ServiceTableEntryW {
            lp_service_name: ptr::null(),
            lp_service_proc: None,
        },
    ];

    // Blocks until the service stops when launched by the SCM.
    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if ok == ffi::FALSE {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            warn!("--service: not launched by the Service Control Manager; running directly.");
        } else {
            warn!("--service: StartServiceCtrlDispatcher failed ({err}); running directly.");
        }
        runner();
    }
}
