use crate::contracts::PythonAdmissionCheckState;
use anyhow::{Result, bail};
use std::path::Path;

pub const PROVE_FIXED_ARGUMENTS: &[&str] = &["-I", "-S", "-B", "-X", "utf8"];
pub const PROVE_SCRIPT: &str = "raise SystemExit(0)";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidualContainmentProof {
    pub job_assignment: PythonAdmissionCheckState,
    pub process_limit: PythonAdmissionCheckState,
}

impl ResidualContainmentProof {
    pub fn network_egress() -> PythonAdmissionCheckState {
        PythonAdmissionCheckState::Failed
    }
}

pub fn prove_bound_python(launcher: &Path, scratch: &Path) -> Result<ResidualContainmentProof> {
    #[cfg(windows)]
    {
        prove_bound_python_windows(launcher, scratch)
    }
    #[cfg(not(windows))]
    {
        let _ = (launcher, scratch);
        bail!("python-admissions prove-containment requires Windows Job Objects");
    }
}

#[cfg(windows)]
fn prove_bound_python_windows(launcher: &Path, scratch: &Path) -> Result<ResidualContainmentProof> {
    use windows_sys::Win32::System::JobObjects::{
        CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, SetInformationJobObject,
    };
    use windows_sys::Win32::System::Threading::{
        InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_JOB_LIST, ResumeThread,
        TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
    };

    if !launcher.is_file() {
        bail!("containment prove launcher is not a regular file");
    }
    fs::create_dir_all(scratch)?;
    let empty_path = scratch.join("empty-path");
    fs::create_dir_all(&empty_path)?;
    let temp = scratch.join("temp");
    fs::create_dir_all(&temp)?;

    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            bail!("cannot create a Windows Job Object for containment prove");
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
            bail!("cannot configure ActiveProcessLimit=1 on the prove Job Object");
        }

        let mut attribute_size = 0usize;
        let _ = InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attribute_size);
        if attribute_size == 0 {
            bail!("cannot size a PROC_THREAD_ATTRIBUTE_JOB_LIST attribute list");
        }
        let mut attribute_buffer = vec![0u8; attribute_size];
        if InitializeProcThreadAttributeList(
            attribute_buffer.as_mut_ptr().cast(),
            1,
            0,
            &mut attribute_size,
        ) == 0
        {
            bail!("cannot initialize a PROC_THREAD_ATTRIBUTE_JOB_LIST attribute list");
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
            bail!("cannot attach PROC_THREAD_ATTRIBUTE_JOB_LIST to the prove process");
        }

        let occupant =
            match spawn_suspended_in_job(launcher, scratch, &empty_path, &temp, &attributes) {
                Ok(process) => process,
                Err(_) => {
                    return Ok(ResidualContainmentProof {
                        job_assignment: PythonAdmissionCheckState::Failed,
                        process_limit: PythonAdmissionCheckState::Failed,
                    });
                }
            };
        let mut in_job = 0i32;
        let assigned = IsProcessInJob(occupant.process, job, &mut in_job) != 0 && in_job != 0;
        let job_assignment = if assigned {
            PythonAdmissionCheckState::Satisfied
        } else {
            PythonAdmissionCheckState::Failed
        };

        let second = spawn_suspended_in_job(launcher, scratch, &empty_path, &temp, &attributes);
        let process_limit = match second {
            Ok(extra) => {
                let _ = TerminateProcess(extra.process, 1);
                PythonAdmissionCheckState::Failed
            }
            Err(_) => PythonAdmissionCheckState::Satisfied,
        };

        let _ = ResumeThread(occupant.thread);
        let _ = WaitForSingleObject(occupant.process, 10_000);
        let _ = TerminateProcess(occupant.process, 1);
        drop(occupant);
        drop(job_guard);
        Ok(ResidualContainmentProof {
            job_assignment,
            process_limit,
        })
    }
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
fn spawn_suspended_in_job(
    launcher: &Path,
    scratch: &Path,
    empty_path: &Path,
    temp: &Path,
    attributes: &AttributeList,
) -> Result<SpawnedProcess> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, EXTENDED_STARTUPINFO_PRESENT,
        PROCESS_INFORMATION, STARTUPINFOEXW,
    };

    let mut application = wide_z(launcher);
    let mut command = wide_z(command_line(launcher));
    let mut directory = wide_z(scratch);
    let environment = environment_block(empty_path, temp)?;
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
            "CreateProcessW with PROC_THREAD_ATTRIBUTE_JOB_LIST failed ({})",
            unsafe { GetLastError() }
        );
    }
    Ok(SpawnedProcess {
        process: information.hProcess,
        thread: information.hThread,
    })
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
    if !value.contains([' ', '"']) {
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
fn environment_block(empty_path: &Path, temp: &Path) -> Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    let system_root = windows_directory()?;
    let mut block = Vec::new();
    for (name, value) in [
        ("PATH", empty_path.as_os_str()),
        ("SystemRoot", system_root.as_os_str()),
        ("WINDIR", system_root.as_os_str()),
        ("TEMP", temp.as_os_str()),
        ("TMP", temp.as_os_str()),
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
        bail!("cannot resolve canonical Windows directory for containment prove");
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

    #[cfg(windows)]
    #[test]
    fn creation_time_job_and_process_limit_use_real_pe() {
        let launcher = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("where.exe");
        let scratch = tempfile::tempdir().unwrap();
        let proof = prove_bound_python(&launcher, scratch.path()).unwrap();
        assert_eq!(proof.job_assignment, PythonAdmissionCheckState::Satisfied);
        assert_eq!(proof.process_limit, PythonAdmissionCheckState::Satisfied);
        assert_eq!(
            ResidualContainmentProof::network_egress(),
            PythonAdmissionCheckState::Failed
        );
    }

    #[cfg(windows)]
    #[test]
    fn non_pe_launcher_fails_closed() {
        let scratch = tempfile::tempdir().unwrap();
        let launcher = scratch.path().join("python.exe");
        std::fs::write(&launcher, b"not-a-pe").unwrap();
        let proof = prove_bound_python(&launcher, scratch.path()).unwrap();
        assert_eq!(proof.job_assignment, PythonAdmissionCheckState::Failed);
        assert_eq!(proof.process_limit, PythonAdmissionCheckState::Failed);
    }
}
