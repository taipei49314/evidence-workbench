use crate::contracts::PythonAdmissionCheckState;
use anyhow::{Result, bail};
use std::path::Path;

pub const PROVE_FIXED_ARGUMENTS: &[&str] = &["-I", "-S", "-B", "-X", "utf8"];
pub const PROVE_SCRIPT: &str = concat!(
    "import os,socket,sys\n",
    "p=int(os.environ['EWB_PROVE_LOOPBACK_PORT'])\n",
    "m=os.environ['EWB_PROVE_MARKER']\n",
    "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n",
    "s.settimeout(2)\n",
    "try:\n",
    " s.connect(('127.0.0.1',p))\n",
    "except OSError:\n",
    " open(m,'w',encoding='ascii').write('denied\\n')\n",
    " sys.exit(0)\n",
    "else:\n",
    " sys.exit(3)"
);
pub const NETWORK_DENIED_EXIT: u32 = 0;
pub const NETWORK_CONNECTED_EXIT: u32 = 3;
pub const NETWORK_DENIED_MARKER: &[u8] = b"denied\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidualNetworkProof {
    pub job_assignment: PythonAdmissionCheckState,
    pub process_limit: PythonAdmissionCheckState,
    pub network_egress: PythonAdmissionCheckState,
}

impl ResidualNetworkProof {
    fn all_failed() -> Self {
        Self {
            job_assignment: PythonAdmissionCheckState::Failed,
            process_limit: PythonAdmissionCheckState::Failed,
            network_egress: PythonAdmissionCheckState::Failed,
        }
    }
}

pub fn observe_network_egress(
    in_appcontainer: bool,
    exit_code: u32,
    marker: &[u8],
    parent_accepted: bool,
) -> PythonAdmissionCheckState {
    if in_appcontainer
        && exit_code == NETWORK_DENIED_EXIT
        && marker == NETWORK_DENIED_MARKER
        && !parent_accepted
    {
        PythonAdmissionCheckState::Satisfied
    } else {
        PythonAdmissionCheckState::Failed
    }
}

pub fn prove_bound_python_network(
    launcher: &Path,
    scratch: &Path,
    profile_name: &str,
) -> Result<ResidualNetworkProof> {
    #[cfg(windows)]
    {
        prove_bound_python_network_windows(launcher, scratch, profile_name)
    }
    #[cfg(not(windows))]
    {
        let _ = (launcher, scratch, profile_name);
        bail!("python-admissions prove-network requires Windows AppContainers");
    }
}

#[cfg(windows)]
fn prove_bound_python_network_windows(
    launcher: &Path,
    scratch: &Path,
    profile_name: &str,
) -> Result<ResidualNetworkProof> {
    use std::net::{Ipv4Addr, TcpListener};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::System::JobObjects::{
        CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, SetInformationJobObject,
    };
    use windows_sys::Win32::System::Threading::{
        InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_JOB_LIST,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, ResumeThread, TerminateProcess,
        UpdateProcThreadAttribute, WaitForSingleObject,
    };

    if !launcher.is_file() {
        bail!("network prove launcher is not a regular file");
    }
    if !valid_profile_name(profile_name) {
        bail!("network prove AppContainer profile name is invalid");
    }
    fs::create_dir_all(scratch)?;
    let empty_path = scratch.join("empty-path");
    fs::create_dir_all(&empty_path)?;
    let temp = scratch.join("temp");
    fs::create_dir_all(&temp)?;
    let marker = temp.join("ewb-network-prove.txt");

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();

    let profile = match create_appcontainer_profile(profile_name) {
        Ok(profile) => profile,
        Err(_) => return Ok(ResidualNetworkProof::all_failed()),
    };
    let mut grant_paths = vec![
        launcher.to_path_buf(),
        scratch.to_path_buf(),
        empty_path.clone(),
        temp.clone(),
    ];
    if let Some(home) = launcher.parent() {
        grant_paths.push(home.to_path_buf());
        if let Ok(entries) = fs::read_dir(home) {
            for entry in entries.flatten() {
                grant_paths.push(entry.path());
            }
        }
    }
    for path in &grant_paths {
        if grant_appcontainer_access(path, profile.sid).is_err() {
            return Ok(ResidualNetworkProof::all_failed());
        }
    }

    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return Ok(ResidualNetworkProof::all_failed());
        }
        let job_guard = HandleGuard(job);
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        info.BasicLimitInformation.ActiveProcessLimit = 1;
        if SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            std::ptr::from_ref(&info).cast(),
            u32::try_from(std::mem::size_of_val(&info))?,
        ) == 0
        {
            return Ok(ResidualNetworkProof::all_failed());
        }

        let mut attribute_size = 0usize;
        let _ = InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut attribute_size);
        if attribute_size == 0 {
            return Ok(ResidualNetworkProof::all_failed());
        }
        let mut attribute_buffer = vec![0u8; attribute_size];
        if InitializeProcThreadAttributeList(
            attribute_buffer.as_mut_ptr().cast(),
            2,
            0,
            &mut attribute_size,
        ) == 0
        {
            return Ok(ResidualNetworkProof::all_failed());
        }
        let mut attributes = AttributeList(attribute_buffer);
        let mut job_list = [job];
        if UpdateProcThreadAttribute(
            attributes.0.as_mut_ptr().cast(),
            0,
            PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
            job_list.as_mut_ptr().cast(),
            std::mem::size_of_val(&job_list),
            std::ptr::null_mut(),
            std::ptr::null(),
        ) == 0
        {
            return Ok(ResidualNetworkProof::all_failed());
        }
        let mut capabilities = windows_sys::Win32::Security::SECURITY_CAPABILITIES {
            AppContainerSid: profile.sid,
            Capabilities: std::ptr::null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        };
        if UpdateProcThreadAttribute(
            attributes.0.as_mut_ptr().cast(),
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            std::ptr::from_mut(&mut capabilities).cast(),
            std::mem::size_of_val(&capabilities),
            std::ptr::null_mut(),
            std::ptr::null(),
        ) == 0
        {
            return Ok(ResidualNetworkProof::all_failed());
        }

        let occupant = match spawn_suspended_in_appcontainer(
            launcher,
            scratch,
            &empty_path,
            &temp,
            &marker,
            port,
            &attributes,
        ) {
            Ok(process) => process,
            Err(_) => return Ok(ResidualNetworkProof::all_failed()),
        };
        let mut in_job = 0i32;
        let assigned = IsProcessInJob(occupant.process, job, &mut in_job) != 0 && in_job != 0;
        let job_assignment = if assigned {
            PythonAdmissionCheckState::Satisfied
        } else {
            PythonAdmissionCheckState::Failed
        };
        let in_appcontainer = process_is_appcontainer(occupant.process);

        let second = spawn_suspended_in_appcontainer(
            launcher,
            scratch,
            &empty_path,
            &temp,
            &marker,
            port,
            &attributes,
        );
        let process_limit = match second {
            Ok(extra) => {
                let _ = TerminateProcess(extra.process, 1);
                PythonAdmissionCheckState::Failed
            }
            Err(_) => PythonAdmissionCheckState::Satisfied,
        };

        let _ = ResumeThread(occupant.thread);
        let mut accepted = false;
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if listener.accept().is_ok() {
                accepted = true;
            }
            let wait = WaitForSingleObject(occupant.process, 50);
            if wait == 0 {
                if listener.accept().is_ok() {
                    accepted = true;
                }
                break;
            }
            if Instant::now() >= deadline {
                let _ = TerminateProcess(occupant.process, 1);
                break;
            }
        }
        let exit_code = process_exit_code(occupant.process);
        let marker_bytes = fs::read(&marker).unwrap_or_default();
        let network_egress =
            observe_network_egress(in_appcontainer, exit_code, &marker_bytes, accepted);
        let _ = TerminateProcess(occupant.process, 1);
        drop(occupant);
        drop(job_guard);
        drop(profile);
        Ok(ResidualNetworkProof {
            job_assignment,
            process_limit,
            network_egress,
        })
    }
}

fn valid_profile_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ' '))
}

#[cfg(windows)]
struct HandleGuard(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
struct AttributeList(Vec<u8>);

#[cfg(windows)]
impl Drop for AttributeList {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::System::Threading::DeleteProcThreadAttributeList(
                self.0.as_mut_ptr().cast(),
            );
        }
    }
}

#[cfg(windows)]
struct SpawnedProcess {
    process: windows_sys::Win32::Foundation::HANDLE,
    thread: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl Drop for SpawnedProcess {
    fn drop(&mut self) {
        unsafe {
            let _ = windows_sys::Win32::Foundation::CloseHandle(self.thread);
            let _ = windows_sys::Win32::Foundation::CloseHandle(self.process);
        }
    }
}

#[cfg(windows)]
struct AppContainerProfile {
    name: Vec<u16>,
    sid: windows_sys::Win32::Security::PSID,
}

#[cfg(windows)]
impl Drop for AppContainerProfile {
    fn drop(&mut self) {
        unsafe {
            let _ = windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile(
                self.name.as_ptr(),
            );
            if !self.sid.is_null() {
                let _ = windows_sys::Win32::Security::FreeSid(self.sid);
            }
        }
    }
}

#[cfg(windows)]
fn create_appcontainer_profile(name: &str) -> Result<AppContainerProfile> {
    use windows_sys::Win32::Security::Isolation::{
        CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
    };

    let name_z = wide_z(name);
    let display = wide_z("ewb-prove");
    let description = wide_z("Evidence Workbench network prove");
    let mut sid = std::ptr::null_mut();
    let created = unsafe {
        CreateAppContainerProfile(
            name_z.as_ptr(),
            display.as_ptr(),
            description.as_ptr(),
            std::ptr::null(),
            0,
            &mut sid,
        )
    };
    const HRESULT_ALREADY_EXISTS: i32 = 0x8007_00B7u32 as i32;
    if created == 0 {
        return Ok(AppContainerProfile { name: name_z, sid });
    }
    if created != HRESULT_ALREADY_EXISTS {
        bail!("cannot create an AppContainer profile for network prove ({created})");
    }
    let derived = unsafe { DeriveAppContainerSidFromAppContainerName(name_z.as_ptr(), &mut sid) };
    if derived != 0 || sid.is_null() {
        bail!("cannot derive an AppContainer SID for network prove ({derived})");
    }
    Ok(AppContainerProfile { name: name_z, sid })
}

#[cfg(windows)]
fn grant_appcontainer_access(path: &Path, sid: windows_sys::Win32::Security::PSID) -> Result<()> {
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, SE_FILE_OBJECT,
        SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
        PSECURITY_DESCRIPTOR,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };

    let mut object = wide_z(path);
    let mut previous: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let queried = unsafe {
        GetNamedSecurityInfoW(
            object.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut previous,
        )
    };
    if queried != ERROR_SUCCESS {
        bail!("cannot read DACL for network prove materialization ({queried})");
    }
    let trustee = TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: 0,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_USER,
        ptstrName: sid.cast(),
    };
    let access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
        Trustee: trustee,
    };
    let mut updated: *mut ACL = std::ptr::null_mut();
    let merged = unsafe { SetEntriesInAclW(1, &access, dacl, &mut updated) };
    if merged != ERROR_SUCCESS {
        unsafe {
            let _ = LocalFree(previous);
        }
        bail!("cannot grant AppContainer access for network prove ({merged})");
    }
    let written = unsafe {
        SetNamedSecurityInfoW(
            object.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            updated,
            std::ptr::null_mut(),
        )
    };
    unsafe {
        let _ = LocalFree(updated.cast());
        let _ = LocalFree(previous);
    }
    if written != ERROR_SUCCESS {
        bail!("cannot apply AppContainer DACL for network prove ({written})");
    }
    Ok(())
}

#[cfg(windows)]
fn spawn_suspended_in_appcontainer(
    launcher: &Path,
    scratch: &Path,
    empty_path: &Path,
    temp: &Path,
    marker: &Path,
    port: u16,
    attributes: &AttributeList,
) -> Result<SpawnedProcess> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
        EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION, STARTUPINFOEXW,
    };

    let mut application = wide_z(launcher);
    let mut command = wide_z(command_line(launcher));
    let mut directory = wide_z(scratch);
    let environment = environment_block(empty_path, temp, marker, port)?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = u32::try_from(std::mem::size_of::<STARTUPINFOEXW>())?;
    startup.lpAttributeList = attributes.0.as_ptr() as *mut _;
    let mut information = PROCESS_INFORMATION::default();
    let created = unsafe {
        CreateProcessW(
            application.as_mut_ptr(),
            command.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_ptr().cast(),
            directory.as_mut_ptr(),
            std::ptr::from_ref(&startup.StartupInfo),
            &mut information,
        )
    };
    if created == 0 {
        bail!(
            "CreateProcessW with AppContainer SECURITY_CAPABILITIES failed ({})",
            unsafe { GetLastError() }
        );
    }
    Ok(SpawnedProcess {
        process: information.hProcess,
        thread: information.hThread,
    })
}

#[cfg(windows)]
fn process_is_appcontainer(process: windows_sys::Win32::Foundation::HANDLE) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_QUERY, TokenIsAppContainer,
    };
    use windows_sys::Win32::System::Threading::OpenProcessToken;

    let mut token = std::ptr::null_mut();
    let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
    if opened == 0 {
        return false;
    }
    let mut is_appcontainer = 0u32;
    let mut returned = 0u32;
    let queried = unsafe {
        GetTokenInformation(
            token,
            TokenIsAppContainer,
            std::ptr::from_mut(&mut is_appcontainer).cast(),
            u32::try_from(std::mem::size_of_val(&is_appcontainer)).unwrap_or(0),
            &mut returned,
        )
    };
    unsafe {
        let _ = CloseHandle(token);
    }
    queried != 0 && is_appcontainer != 0
}

#[cfg(windows)]
fn process_exit_code(process: windows_sys::Win32::Foundation::HANDLE) -> u32 {
    use windows_sys::Win32::System::Threading::GetExitCodeProcess;
    let mut exit_code = 1u32;
    let queried = unsafe { GetExitCodeProcess(process, &mut exit_code) };
    if queried == 0 {
        1
    } else {
        exit_code
    }
}

#[cfg(windows)]
fn command_line(launcher: &Path) -> String {
    let mut command = quote_windows_arg(&launcher.display().to_string());
    for argument in PROVE_FIXED_ARGUMENTS {
        command.push(' ');
        command.push_str(argument);
    }
    command.push_str(" -c ");
    command.push_str(&quote_windows_arg(PROVE_SCRIPT));
    command
}

#[cfg(windows)]
fn quote_windows_arg(value: &str) -> String {
    if !value.contains([' ', '"', '\n']) {
        return value.to_owned();
    }
    let mut quoted = String::from("\"");
    for ch in value.chars() {
        if ch == '"' {
            quoted.push('\\');
        }
        quoted.push(ch);
    }
    quoted.push('"');
    quoted
}

#[cfg(windows)]
fn wide_z(path: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(windows)]
fn environment_block(
    empty_path: &Path,
    temp: &Path,
    marker: &Path,
    port: u16,
) -> Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    let system_root = windows_directory()?;
    let system_drive = system_root
        .to_str()
        .and_then(|value| value.get(..2))
        .unwrap_or("C:")
        .to_owned();
    let port = port.to_string();
    let computer = std::env::var_os("COMPUTERNAME").unwrap_or_else(|| "localhost".into());
    let username = std::env::var_os("USERNAME").unwrap_or_else(|| "ewb".into());
    let userdomain = std::env::var_os("USERDOMAIN").unwrap_or_else(|| computer.clone());
    let mut block = Vec::new();
    for (name, value) in [
        ("PATH", empty_path.as_os_str()),
        ("SystemRoot", system_root.as_os_str()),
        ("WINDIR", system_root.as_os_str()),
        ("SystemDrive", std::ffi::OsStr::new(&system_drive)),
        ("TEMP", temp.as_os_str()),
        ("TMP", temp.as_os_str()),
        ("LOCALAPPDATA", temp.as_os_str()),
        ("USERPROFILE", temp.as_os_str()),
        ("COMPUTERNAME", computer.as_os_str()),
        ("USERNAME", username.as_os_str()),
        ("USERDOMAIN", userdomain.as_os_str()),
        ("EWB_PROVE_LOOPBACK_PORT", std::ffi::OsStr::new(&port)),
        ("EWB_PROVE_MARKER", marker.as_os_str()),
    ] {
        block.extend(name.encode_utf16());
        block.push(u16::from(b'='));
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

#[cfg(windows)]
fn windows_directory() -> Result<std::path::PathBuf> {
    use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
    let mut buffer = vec![0u16; 32768];
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 || length as usize >= buffer.len() {
        bail!("cannot resolve canonical Windows directory for network prove");
    }
    Ok(std::path::PathBuf::from(String::from_utf16(
        &buffer[..length as usize],
    )?))
}

#[cfg(windows)]
use std::fs;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_satisfied_requires_appcontainer_denied_marker_and_no_accept() {
        assert_eq!(
            observe_network_egress(true, NETWORK_DENIED_EXIT, NETWORK_DENIED_MARKER, false),
            PythonAdmissionCheckState::Satisfied
        );
        assert_eq!(
            observe_network_egress(true, NETWORK_DENIED_EXIT, NETWORK_DENIED_MARKER, true),
            PythonAdmissionCheckState::Failed
        );
        assert_eq!(
            observe_network_egress(true, NETWORK_CONNECTED_EXIT, NETWORK_DENIED_MARKER, false),
            PythonAdmissionCheckState::Failed
        );
        assert_eq!(
            observe_network_egress(true, NETWORK_DENIED_EXIT, b"", false),
            PythonAdmissionCheckState::Failed
        );
        assert_eq!(
            observe_network_egress(false, NETWORK_DENIED_EXIT, NETWORK_DENIED_MARKER, false),
            PythonAdmissionCheckState::Failed
        );
        assert_eq!(
            observe_network_egress(true, 1, NETWORK_DENIED_MARKER, false),
            PythonAdmissionCheckState::Failed
        );
    }

    #[cfg(windows)]
    #[test]
    fn where_exe_cannot_satisfy_network_protocol() {
        let launcher = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("where.exe");
        let scratch = tempfile::tempdir().unwrap();
        let profile = format!("ewb.prove.{}", uuid::Uuid::new_v4().simple());
        let proof = prove_bound_python_network(&launcher, scratch.path(), &profile).unwrap();
        assert_eq!(proof.network_egress, PythonAdmissionCheckState::Failed);
    }

    #[cfg(windows)]
    #[test]
    fn non_pe_launcher_fails_closed() {
        let scratch = tempfile::tempdir().unwrap();
        let launcher = scratch.path().join("python.exe");
        std::fs::write(&launcher, b"not-a-pe").unwrap();
        let profile = format!("ewb.prove.{}", uuid::Uuid::new_v4().simple());
        let proof = prove_bound_python_network(&launcher, scratch.path(), &profile).unwrap();
        assert_eq!(proof, ResidualNetworkProof::all_failed());
    }

    #[cfg(windows)]
    #[test]
    fn probe_pe_can_satisfy_job_limit_and_network() {
        let scratch = tempfile::tempdir().unwrap();
        let launcher = scratch.path().join("python.exe");
        compile_loopback_probe(&launcher);
        let profile = format!("ewb.prove.{}", uuid::Uuid::new_v4().simple());
        let proof = prove_bound_python_network(&launcher, scratch.path(), &profile).unwrap();
        assert_eq!(proof.job_assignment, PythonAdmissionCheckState::Satisfied);
        assert_eq!(proof.process_limit, PythonAdmissionCheckState::Satisfied);
        assert_eq!(proof.network_egress, PythonAdmissionCheckState::Satisfied);
    }

    #[cfg(windows)]
    fn compile_loopback_probe(destination: &Path) {
        let source = destination.with_extension("rs");
        std::fs::write(
            &source,
            r#"
use std::env;
use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

fn main() {
    let port: u16 = env::var("EWB_PROVE_LOOPBACK_PORT").unwrap().parse().unwrap();
    let marker = env::var("EWB_PROVE_MARKER").unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
        Ok(_) => std::process::exit(3),
        Err(_) => {
            fs::write(marker, b"denied\n").ok();
            std::process::exit(0);
        }
    }
}
"#,
        )
        .unwrap();
        let status = std::process::Command::new("rustc")
            .args(["--edition", "2021", "-C", "opt-level=1", "-o"])
            .arg(destination)
            .arg(&source)
            .status()
            .unwrap();
        assert!(status.success(), "rustc failed to build the loopback probe");
    }
}
