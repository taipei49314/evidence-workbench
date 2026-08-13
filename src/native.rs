use crate::contracts::{
    AdapterIdentity, ArtifactDescriptor, BinaryIdentity, InstrumentRun, Invocation, LimitationItem,
    Limitations, Locator, NativeAuthority, NativeObservation, NativeQualificationRef, NativeResult,
    ObservationSource, PlanRecordRef, RecorderIdentity, Subject, Termination, ToolRef,
    UpstreamPinRef,
};
use crate::git_subject;
use crate::manifests::{self, ToolManifest, TrustedManifest};
use crate::native_qualifications;
use crate::strict_json;
use crate::workspace::{self, Workspace};
use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use uuid::Uuid;
use wait_timeout::ChildExt;

const PROBE_TIMEOUT_MS: u64 = 3_000;
const MAX_CAPTURE_BYTES: u64 = 32 * 1024 * 1024;
// SHA-256 of the empty byte sequence. The isolated PATH directory is required
// to have no entries, so its name records the only admitted contents.
const EMPTY_PATH_CONTENT_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub available: bool,
    pub manifest_id: String,
    pub version_probe_executed: bool,
    pub executable: Option<String>,
    pub executable_sha256: Option<String>,
    pub supporting_files_sha256: Option<String>,
    pub supporting_file_count: u64,
    pub reported_version: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug)]
struct DirectResult {
    started_at: String,
    finished_at: String,
    termination: Termination,
    stdout_path: Option<PathBuf>,
    stderr_path: Option<PathBuf>,
}

struct ExecutionRootGuard<'a> {
    workspace: &'a Workspace,
    root: Option<PathBuf>,
}

impl Drop for ExecutionRootGuard<'_> {
    fn drop(&mut self) {
        if let Some(root) = &self.root {
            let _ = cleanup_execution_root(self.workspace, root);
        }
    }
}

#[derive(Debug)]
struct OwnedEmptyPath {
    path: PathBuf,
}

#[cfg(windows)]
fn verify_windows_bare_name_search_surface(invocation: &Invocation) -> Result<()> {
    use windows_sys::Win32::System::SystemInformation::{
        GetSystemDirectoryW, GetWindowsDirectoryW,
    };
    fn queried_directory(
        query: unsafe extern "system" fn(*mut u16, u32) -> u32,
    ) -> Result<PathBuf> {
        let mut buffer = vec![0u16; 32768];
        // SAFETY: buffer is writable for its declared length.
        let length = unsafe { query(buffer.as_mut_ptr(), buffer.len() as u32) };
        if length == 0 || length as usize >= buffer.len() {
            bail!("cannot resolve a Windows CreateProcess search directory");
        }
        Ok(PathBuf::from(String::from_utf16(
            &buffer[..length as usize],
        )?))
    }
    let application = Path::new(&invocation.argv[0])
        .parent()
        .context("qualified executable has no application directory")?;
    let current = Path::new(&invocation.cwd);
    let system = queried_directory(GetSystemDirectoryW)?;
    let windows = queried_directory(GetWindowsDirectoryW)?;
    let mut directories = vec![
        application.to_owned(),
        current.to_owned(),
        system.clone(),
        system.join("downlevel"),
        windows.join("System"),
        windows.join("SysWOW64"),
        windows,
    ];
    directories.sort_by_key(|path| path.to_string_lossy().to_ascii_lowercase());
    directories.dedup_by(|left, right| {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    });
    for directory in directories {
        if !directory.is_dir() {
            continue;
        }
        let metadata = fs::symlink_metadata(&directory)?;
        if metadata.file_type().is_symlink() || is_windows_reparse(&metadata) {
            bail!("Windows CreateProcess search directory is a link or reparse point");
        }
        for name in ["git.exe", "docker.exe", "podman.exe"] {
            if directory.join(name).try_exists()? {
                bail!(
                    "qualified TomorrowCI operation found ambient {name} on the Windows bare-name search surface"
                );
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn canonical_windows_directory() -> Result<PathBuf> {
    use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
    let mut buffer = vec![0u16; 32768];
    // SAFETY: buffer is writable for its declared length.
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 || length as usize >= buffer.len() {
        bail!("cannot resolve canonical Windows directory");
    }
    let directory = PathBuf::from(String::from_utf16(&buffer[..length as usize])?);
    let metadata = fs::symlink_metadata(&directory)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || is_windows_reparse(&metadata) {
        bail!("canonical Windows directory is not a real directory");
    }
    Ok(directory)
}

#[cfg(not(windows))]
fn verify_windows_bare_name_search_surface(_invocation: &Invocation) -> Result<()> {
    Ok(())
}

impl OwnedEmptyPath {
    fn create(workspace: &Workspace) -> Result<Self> {
        let parent = workspace.state.join("tmp");
        let metadata = fs::symlink_metadata(&parent)
            .context("cannot inspect EWB temporary directory for isolated PATH")?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || is_windows_reparse(&metadata)
        {
            bail!("EWB isolated PATH parent must be a real directory");
        }

        let path = parent.join(format!(
            "empty-path-sha256-{EMPTY_PATH_CONTENT_SHA256}-{}",
            Uuid::new_v4().simple()
        ));
        fs::create_dir(&path).context("cannot create EWB-owned isolated PATH")?;
        let owned = Self { path };
        owned.verify_empty()?;
        Ok(owned)
    }

    fn verify_empty(&self) -> Result<()> {
        let metadata =
            fs::symlink_metadata(&self.path).context("cannot inspect EWB-owned isolated PATH")?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || is_windows_reparse(&metadata)
        {
            bail!("EWB-owned isolated PATH is not a real directory");
        }
        if fs::read_dir(&self.path)?.next().transpose()?.is_some() {
            bail!("EWB-owned isolated PATH is not empty");
        }
        Ok(())
    }
}

impl Drop for OwnedEmptyPath {
    fn drop(&mut self) {
        // Never recurse here: if anything appeared after the emptiness check,
        // leave it in place rather than deleting material EWB did not create.
        let _ = fs::remove_dir(&self.path);
    }
}

pub struct ExecutionRequest {
    pub run_id: String,
    pub source_plan_ref: PlanRecordRef,
    pub tool_ref: ToolRef,
    pub upstream_pin_ref: UpstreamPinRef,
    pub native_qualification_ref: Option<NativeQualificationRef>,
    pub identity: BinaryIdentity,
    pub recorder: RecorderIdentity,
    pub adapter: AdapterIdentity,
    pub subject: Subject,
    pub parameters: BTreeMap<String, String>,
    pub invocation: Invocation,
}

pub fn recorder_identity() -> Result<RecorderIdentity> {
    let executable = std::env::current_exe()?.canonicalize()?;
    let (sha256, _) = workspace::digest_file(&executable)?;
    Ok(RecorderIdentity {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        executable_sha256: sha256,
    })
}

pub fn adapter_identity(
    manifest: &TrustedManifest,
    recorder: &RecorderIdentity,
) -> AdapterIdentity {
    AdapterIdentity {
        id: manifest.manifest.adapter.id.clone(),
        version: manifest.manifest.adapter.version.clone(),
        implementation_sha256: recorder.executable_sha256.clone(),
    }
}

pub fn probe(manifest: &TrustedManifest) -> ProbeResult {
    inspect_or_probe(manifest, true)
}

pub fn inspect(manifest: &TrustedManifest) -> ProbeResult {
    inspect_or_probe(manifest, false)
}

fn inspect_or_probe(manifest: &TrustedManifest, probe_version: bool) -> ProbeResult {
    match resolve_tool_identity(&manifest.manifest, probe_version) {
        Ok(identity) => ProbeResult {
            available: true,
            manifest_id: manifest.manifest.manifest_id.clone(),
            version_probe_executed: probe_version
                && manifest.manifest.identity_contract.version_probe.is_some(),
            executable: Some(identity.path),
            executable_sha256: Some(identity.sha256),
            supporting_files_sha256: identity.supporting_files_sha256,
            supporting_file_count: identity.supporting_file_count,
            reported_version: identity.reported_version,
            error: None,
        },
        Err(error) => ProbeResult {
            available: false,
            manifest_id: manifest.manifest.manifest_id.clone(),
            version_probe_executed: false,
            executable: None,
            executable_sha256: None,
            supporting_files_sha256: None,
            supporting_file_count: 0,
            reported_version: None,
            error: Some(format!("{error:#}")),
        },
    }
}

pub fn resolve_tool_identity(
    manifest: &ToolManifest,
    probe_version: bool,
) -> Result<BinaryIdentity> {
    if let Some(distribution) = &manifest.identity_contract.python_distribution {
        bail!(
            "Python adapter {distribution} is not execution-ready: a complete immutable interpreter, runtime, distribution, and transitive-dependency snapshot is required; planning is disabled"
        );
    }
    let path = find_executable(&manifest.identity_contract.executable_candidates)?;
    let lower = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if lower == "cmd" || lower == "bat" {
        bail!(
            "shell-script executables are not accepted: {}",
            path.display()
        );
    }
    let (sha256, size_bytes) = workspace::digest_file(&path)?;
    if !manifest.identity_contract.allowed_binary_sha256.is_empty()
        && !manifest
            .identity_contract
            .allowed_binary_sha256
            .iter()
            .any(|allowed| allowed == &sha256)
    {
        bail!(
            "resolved executable bytes are not admitted by the trusted manifest: {}",
            path.display()
        );
    }
    let (supporting_files_sha256, supporting_file_count) = (None, 0);
    let reported_version = if probe_version {
        manifest
            .identity_contract
            .version_probe
            .as_ref()
            .and_then(|probe| run_version_probe(&path, &probe.arguments).ok())
            .flatten()
    } else {
        None
    };
    Ok(BinaryIdentity {
        path: path.display().to_string(),
        sha256,
        size_bytes,
        supporting_files_sha256,
        supporting_file_count,
        reported_version,
        source_path: path.display().to_string(),
        snapshot_artifact_id: String::new(),
    })
}

pub fn snapshot_tool_identity(
    workspace: &Workspace,
    manifest: &ToolManifest,
) -> Result<BinaryIdentity> {
    require_windows_execution_boundary(
        "native execution planning is disabled on this platform until descriptor-based exec removes path replacement races",
    )?;
    let discovered = resolve_tool_identity(manifest, false)?;
    let (artifact, staged) =
        workspace.import_native_snapshot(Path::new(&discovered.source_path))?;
    Ok(BinaryIdentity {
        path: staged.display().to_string(),
        sha256: artifact.digest.value,
        size_bytes: artifact.byte_length,
        supporting_files_sha256: None,
        supporting_file_count: 0,
        reported_version: None,
        source_path: discovered.source_path,
        snapshot_artifact_id: artifact.artifact_id,
    })
}

pub fn snapshot_qualified_tool_identity(
    workspace: &Workspace,
    manifest: &ToolManifest,
    qualification: &crate::contracts::NativeDeliveryQualificationRecord,
    plan_id: &str,
) -> Result<BinaryIdentity> {
    require_windows_execution_boundary(
        "qualified native execution planning requires the Windows handle boundary",
    )?;
    if manifest.manifest_id != "tomorrowci-lab"
        || manifest.invocation_contract.operation != "tomorrowci_trust_audit"
        || qualification.payload.qualification.tool_manifest_id != manifest.manifest_id
        || qualification.payload.qualification.operation != manifest.invocation_contract.operation
    {
        bail!("native qualification cannot be used for this trusted manifest operation");
    }
    let executable = native_qualifications::executable_artifact(qualification)?;
    if !manifest
        .identity_contract
        .allowed_binary_sha256
        .iter()
        .any(|allowed| allowed == &executable.sha256)
    {
        bail!("qualified executable is outside the trusted manifest allowlist");
    }
    let (artifact, staged) = workspace.materialize_qualified_application(
        plan_id,
        &executable.artifact_id,
        "tomorrowci.exe",
    )?;
    if artifact.digest.value != executable.sha256 || artifact.byte_length != executable.byte_length
    {
        bail!("qualified application bytes diverge from the durable qualification record");
    }
    Ok(BinaryIdentity {
        path: staged.display().to_string(),
        sha256: artifact.digest.value,
        size_bytes: artifact.byte_length,
        supporting_files_sha256: None,
        supporting_file_count: 0,
        reported_version: None,
        source_path: "tomorrowci.exe".to_owned(),
        snapshot_artifact_id: artifact.artifact_id,
    })
}

pub fn verify_qualified_application_identity(
    workspace: &Workspace,
    identity: &BinaryIdentity,
    expected_plan_id: Option<&str>,
) -> Result<()> {
    let plan_id = qualified_application_plan_id(identity)?;
    if expected_plan_id.is_some_and(|expected| expected != plan_id) {
        bail!("qualified application directory does not match its plan ID");
    }
    validate_qualified_application_path_shape(workspace, identity, plan_id)?;
    let executable = Path::new(&identity.path);
    validate_absolute_inventory_ancestors(executable)?;
    let application = executable
        .parent()
        .context("qualified launcher has no application directory")?;
    validate_windows_single_link(executable)?;
    let applications_root = workspace.state.join("staged").join("applications");
    let digest_root = applications_root.join("sha256");
    let digest_directory = digest_root.join(&identity.sha256);
    if application.parent() != Some(digest_directory.as_path())
        || digest_directory.parent() != Some(digest_root.as_path())
        || digest_root.parent() != Some(applications_root.as_path())
        || applications_root.parent() != Some(workspace.state.join("staged").as_path())
    {
        bail!("qualified application parent chain is outside the exact EWB hierarchy");
    }
    let staged_root = workspace.state.join("staged");
    for path in [
        workspace.state.as_path(),
        staged_root.as_path(),
        applications_root.as_path(),
        digest_root.as_path(),
        digest_directory.as_path(),
        application,
        executable,
    ] {
        let metadata =
            fs::symlink_metadata(path).context("cannot inspect qualified application inventory")?;
        if metadata.file_type().is_symlink() || is_windows_reparse(&metadata) {
            bail!("qualified application inventory contains a link or reparse point");
        }
        if path == executable && !metadata.is_file() {
            bail!("qualified application launcher is not a regular file");
        }
        if path != executable && !metadata.is_dir() {
            bail!("qualified application parent chain contains a non-directory");
        }
    }
    let entries = fs::read_dir(application)?.collect::<Result<Vec<_>, _>>()?;
    if entries.len() != 1
        || entries[0]
            .file_name()
            .to_string_lossy()
            .to_ascii_lowercase()
            != "tomorrowci.exe"
        || entries[0].file_name() != std::ffi::OsStr::new("tomorrowci.exe")
    {
        bail!(
            "qualified application inventory must contain only tomorrowci.exe; app-local Git, Docker, Podman, and DLL shims are forbidden"
        );
    }
    let (digest, length) = workspace::digest_file(executable)?;
    if digest != identity.sha256 || length != identity.size_bytes {
        bail!("qualified application launcher bytes changed");
    }
    Ok(())
}

fn validate_absolute_inventory_ancestors(executable: &Path) -> Result<()> {
    if !executable.is_absolute() {
        bail!("qualified application path must be absolute");
    }
    let ancestors = executable.ancestors().collect::<Vec<_>>();
    for path in ancestors.iter().rev() {
        let metadata = fs::symlink_metadata(path).with_context(|| {
            format!("cannot inspect qualified path ancestor {}", path.display())
        })?;
        if metadata.file_type().is_symlink() || is_windows_reparse(&metadata) {
            bail!("qualified application absolute ancestor is a link or reparse point");
        }
        if *path == executable {
            if !metadata.is_file() {
                bail!("qualified application launcher is not a regular file");
            }
        } else if !metadata.is_dir() {
            bail!("qualified application absolute ancestor is not a directory");
        }
    }
    Ok(())
}

fn qualified_application_plan_id(identity: &BinaryIdentity) -> Result<&str> {
    Path::new(&identity.path)
        .parent()
        .and_then(Path::file_name)
        .and_then(|value| value.to_str())
        .context("qualified application plan ID is not UTF-8")
}

pub fn validate_qualified_application_path_shape(
    workspace: &Workspace,
    identity: &BinaryIdentity,
    expected_plan_id: &str,
) -> Result<()> {
    workspace::validate_prefixed_id(expected_plan_id, "plan_")?;
    if qualified_application_plan_id(identity)? != expected_plan_id {
        bail!("qualified application directory does not match its source plan ID");
    }
    let executable = Path::new(&identity.path);
    let expected = workspace.qualified_application_executable_path(
        expected_plan_id,
        &identity.sha256,
        "tomorrowci.exe",
    )?;
    if executable != expected {
        bail!("qualified launcher is outside its content-addressed private application directory");
    }
    Ok(())
}

#[cfg(windows)]
fn validate_windows_single_link(path: &Path) -> Result<()> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let file = open_native_read_no_write_share(path)?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file is a live Windows file handle and information is writable.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) };
    if ok == 0 || size_of::<BY_HANDLE_FILE_INFORMATION>() == 0 {
        bail!("cannot query qualified launcher link identity");
    }
    if information.nNumberOfLinks != 1 {
        bail!("qualified application launcher must be a private single-link copy");
    }
    Ok(())
}

#[cfg(not(windows))]
fn validate_windows_single_link(_path: &Path) -> Result<()> {
    Ok(())
}

fn require_windows_execution_boundary(message: &str) -> Result<()> {
    if cfg!(windows) {
        Ok(())
    } else {
        bail!(message.to_owned())
    }
}

pub fn build_invocation(
    manifest: &TrustedManifest,
    identity: &BinaryIdentity,
    subject: &Subject,
    parameters: &BTreeMap<String, String>,
    workspace: &Workspace,
    timeout_ms: u64,
) -> Result<Invocation> {
    if !manifest.manifest.enabled_by_default
        || manifest.manifest.invocation_contract.operation == "catalog_only"
    {
        bail!("tool is cataloged but execution is not implemented in this MVP");
    }
    if timeout_ms == 0 || timeout_ms > 3_600_000 {
        bail!("timeout must be between 1 ms and 1 hour");
    }

    let executable = identity.path.clone();
    let mut argv = vec![executable];
    let cwd = match manifest.manifest.invocation_contract.operation.as_str() {
        "greenwash_exact_range" => {
            let root = git_subject::root(subject)?;
            let head = git_subject::head(subject)?;
            let base = parameters
                .get("base_revision")
                .ok_or_else(|| anyhow::anyhow!("base_revision is required"))?;
            let separator = match parameters.get("comparison").map(String::as_str) {
                Some("three_dot") => "...",
                Some("two_dot") => "..",
                _ => bail!("invalid Greenwash comparison"),
            };
            argv.extend([
                "check".to_owned(),
                format!("{base}{separator}{head}"),
                "--format".to_owned(),
                "json".to_owned(),
                "--repo".to_owned(),
                root.display().to_string(),
            ]);
            root
        }
        "repopass_local_inspect" => {
            let root = git_subject::root(subject)?;
            argv.extend([
                "--output".to_owned(),
                "json".to_owned(),
                "--offline".to_owned(),
                "--non-interactive".to_owned(),
                "inspect".to_owned(),
                root.display().to_string(),
            ]);
            root
        }
        "trust_meter_measure" => {
            let root = git_subject::root(subject)?;
            argv.extend([
                root.display().to_string(),
                "--json".to_owned(),
                "--threshold".to_owned(),
                parameters
                    .get("threshold")
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("threshold missing after validation"))?,
                "--phase".to_owned(),
                parameters
                    .get("phase")
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("phase missing after validation"))?,
            ]);
            root
        }
        "phaseledger_measure" => {
            let execution_path = match subject {
                Subject::Artifact { snapshot, .. } => PathBuf::from(&snapshot.execution_path),
                _ => bail!("phaseledger requires an artifact subject"),
            };
            argv.extend([
                "measure".to_owned(),
                execution_path.display().to_string(),
                "--strict".to_owned(),
            ]);
            workspace.root.clone()
        }
        "stateweaver_foundation_verify" => {
            if !matches!(subject, Subject::SelfFoundation { .. }) {
                bail!("StateWeaver foundation adapter only accepts its fixed self subject");
            }
            argv.extend([
                "--json".to_owned(),
                "foundation".to_owned(),
                "verify".to_owned(),
            ]);
            workspace.root.clone()
        }
        "tomorrowci_trust_audit" => {
            if !matches!(subject, Subject::SelfFoundation { .. }) {
                bail!("TomorrowCI trust adapter only accepts its fixed self subject");
            }
            argv.extend(["trust".to_owned(), "--json".to_owned()]);
            Path::new(&identity.path)
                .parent()
                .context("qualified TomorrowCI launcher has no application directory")?
                .to_owned()
        }
        other => bail!("unsupported trusted adapter operation: {other}"),
    };

    Ok(Invocation {
        mode: "direct_exec".to_owned(),
        argv,
        cwd: cwd.display().to_string(),
        timeout_ms,
        required_capabilities: manifest
            .manifest
            .invocation_contract
            .required_capabilities
            .clone(),
    })
}

pub fn validate_capability_approval(invocation: &Invocation, allowed: &[String]) -> Result<()> {
    let required: BTreeSet<_> = invocation.required_capabilities.iter().cloned().collect();
    let mut approved = BTreeSet::new();
    for capability in allowed {
        if !valid_capability(capability) || !required.contains(capability) {
            bail!("unknown or unnecessary capability approval: {capability:?}");
        }
        if !approved.insert(capability.clone()) {
            bail!("duplicate capability approval: {capability}");
        }
    }
    let missing: Vec<_> = required.difference(&approved).cloned().collect();
    if !missing.is_empty() {
        bail!(
            "missing explicit capability approval: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

pub fn execute(
    workspace: &Workspace,
    manifest: &TrustedManifest,
    request: ExecutionRequest,
) -> Result<InstrumentRun> {
    let ExecutionRequest {
        run_id,
        source_plan_ref,
        tool_ref,
        upstream_pin_ref,
        native_qualification_ref,
        identity,
        recorder,
        adapter,
        subject,
        parameters,
        invocation,
    } = request;
    let (materialized_subject, execution_root) = materialize_subject(workspace, &subject)?;
    let mut execution_guard = ExecutionRootGuard {
        workspace,
        root: execution_root,
    };
    let mut invocation = invocation;
    rewrite_invocation_subject(&manifest.manifest, &mut invocation, &materialized_subject)?;
    let mut native_handle = open_verified_native(&identity)?;
    verify_open_native(&mut native_handle, &identity)?;
    let direct = run_direct(
        workspace,
        &manifest.manifest.invocation_contract.operation,
        &invocation,
    )?;
    let native_unchanged = verify_open_native(&mut native_handle, &identity).is_ok();
    let subject_unchanged = verify_subject_after(workspace, &materialized_subject).is_ok();
    let mut artifacts = Vec::new();
    if let Some(path) = &direct.stdout_path {
        artifacts.push(workspace.import_artifact(
            path,
            vec!["native_stdout".to_owned()],
            "application/octet-stream".to_owned(),
            "process_stdout",
            "raw_stream_capture",
        )?);
    }
    if let Some(path) = &direct.stderr_path {
        artifacts.push(workspace.import_artifact(
            path,
            vec!["native_stderr".to_owned()],
            "application/octet-stream".to_owned(),
            "process_stderr",
            "raw_stream_capture",
        )?);
    }
    for path in [direct.stdout_path.as_ref(), direct.stderr_path.as_ref()]
        .into_iter()
        .flatten()
    {
        let _ = fs::remove_file(path);
    }

    let mut native_result = extract_native_result(
        workspace,
        &manifest.manifest,
        &direct.termination,
        &artifacts,
    );
    if !native_unchanged || !subject_unchanged {
        native_result = NativeResult::NotReported {
            reason: "contract_mismatch".to_owned(),
            observations: Vec::new(),
        };
    }
    if let Some(root) = execution_guard.root.take() {
        cleanup_execution_root(workspace, &root)?;
    }
    let mut limitation_items = manifests::limitation_items(manifest);
    limitation_items.push(LimitationItem {
        namespace: "evidence_workbench".to_owned(),
        code: "minimized_environment_not_os_sandbox".to_owned(),
        statement: "The native process receives a minimized environment, but it still runs with the current user's operating-system authority.".to_owned(),
        origin: "adapter".to_owned(),
        source: format!("recorder:sha256:{}", recorder.executable_sha256),
    });
    limitation_items.push(LimitationItem {
        namespace: "evidence_workbench".to_owned(),
        code: "child_process_tree_not_contained".to_owned(),
        statement: "Timeout termination targets the direct child; this MVP does not claim operating-system process-tree containment.".to_owned(),
        origin: "adapter".to_owned(),
        source: format!("recorder:sha256:{}", recorder.executable_sha256),
    });
    if identity.supporting_files_sha256.is_some() {
        limitation_items.push(LimitationItem {
            namespace: "evidence_workbench".to_owned(),
            code: "transitive_runtime_dependencies_not_pinned".to_owned(),
            statement: "The native launcher and its own Python distribution tree are pinned, but transitive interpreter and dependency files are not part of this v1 identity.".to_owned(),
            origin: "adapter".to_owned(),
            source: format!("recorder:sha256:{}", recorder.executable_sha256),
        });
    }

    Ok(InstrumentRun {
        schema_version: "instrument_run/v1".to_owned(),
        run_id,
        source_plan_ref,
        tool_ref,
        upstream_pin_ref,
        native_qualification_ref,
        resolved_tool_identity: identity,
        recorder_identity: recorder,
        adapter,
        subject,
        parameters,
        invocation,
        started_at: direct.started_at,
        finished_at: direct.finished_at,
        termination: direct.termination,
        artifacts,
        native_result,
        native_authority: NativeAuthority::NotReported {
            reason: "native_authority_not_configured".to_owned(),
            claims: Vec::new(),
        },
        limitations: Limitations::Reported {
            items: limitation_items,
        },
    })
}

fn materialize_subject(
    workspace: &Workspace,
    subject: &Subject,
) -> Result<(Subject, Option<PathBuf>)> {
    match subject {
        Subject::Git { .. } => {
            let root = git_subject::materialize(workspace, subject)?;
            Ok((subject.clone(), Some(root)))
        }
        Subject::Artifact { snapshot, .. } => {
            let record = workspace.load_artifact(&snapshot.artifact_id)?;
            if record.artifact.digest.value != snapshot.sha256
                || record.artifact.byte_length != snapshot.byte_length
            {
                bail!("artifact snapshot identity mismatch");
            }
            let source = workspace.verify_descriptor(&record.artifact)?;
            let destination = PathBuf::from(&snapshot.execution_path);
            let root = destination
                .parent()
                .ok_or_else(|| anyhow::anyhow!("artifact execution path has no parent"))?;
            if root.exists() {
                bail!("planned artifact execution root already exists");
            }
            fs::create_dir(root)?;
            fs::copy(source, &destination)?;
            workspace::digest_file(&destination).and_then(|(digest, length)| {
                if digest != snapshot.sha256 || length != snapshot.byte_length {
                    bail!("artifact execution copy mismatch")
                }
                Ok(())
            })?;
            Ok((subject.clone(), Some(root.to_owned())))
        }
        Subject::SelfFoundation { .. } => Ok((subject.clone(), None)),
    }
}

fn rewrite_invocation_subject(
    manifest: &ToolManifest,
    invocation: &mut Invocation,
    subject: &Subject,
) -> Result<()> {
    match manifest.invocation_contract.operation.as_str() {
        "greenwash_exact_range" => {
            let root = git_subject::root(subject)?.display().to_string();
            invocation.cwd = root.clone();
            let position = invocation
                .argv
                .iter()
                .position(|value| value == "--repo")
                .ok_or_else(|| anyhow::anyhow!("Greenwash invocation lacks --repo"))?;
            invocation.argv[position + 1] = root;
        }
        "repopass_local_inspect" => {
            let root = git_subject::root(subject)?.display().to_string();
            invocation.cwd = root.clone();
            let last = invocation.argv.len() - 1;
            invocation.argv[last] = root;
        }
        "trust_meter_measure" => {
            let root = git_subject::root(subject)?.display().to_string();
            invocation.cwd = root.clone();
            invocation.argv[1] = root;
        }
        _ => {}
    }
    Ok(())
}

fn verify_subject_after(workspace: &Workspace, subject: &Subject) -> Result<()> {
    match subject {
        Subject::Git { .. } => git_subject::verify_materialized(subject),
        Subject::Artifact {
            sha256,
            byte_length,
            snapshot,
            ..
        } => {
            let (actual, length) = workspace::digest_file(Path::new(&snapshot.execution_path))?;
            if &actual != sha256 || &length != byte_length {
                bail!("artifact subject changed during execution");
            }
            let _ = workspace;
            Ok(())
        }
        Subject::SelfFoundation { .. } => Ok(()),
    }
}

fn cleanup_execution_root(workspace: &Workspace, root: &Path) -> Result<()> {
    let executions = workspace.state.join("executions");
    let parent = root
        .parent()
        .ok_or_else(|| anyhow::anyhow!("execution root has no parent"))?;
    if parent != executions {
        bail!("refusing to clean execution path outside EWB executions directory");
    }
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() || is_windows_reparse(&metadata) {
        bail!("refusing to clean linked execution root");
    }
    fs::remove_dir_all(root)?;
    Ok(())
}

fn open_verified_native(identity: &BinaryIdentity) -> Result<File> {
    let path = Path::new(&identity.path);
    let mut file = open_native_read_no_write_share(path)?;
    verify_open_native(&mut file, identity)?;
    Ok(file)
}

fn verify_open_native(file: &mut File, identity: &BinaryIdentity) -> Result<()> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        length += read as u64;
    }
    if hex::encode(hasher.finalize()) != identity.sha256 || length != identity.size_bytes {
        bail!("staged native executable changed during execution");
    }
    Ok(())
}

#[cfg(windows)]
fn open_native_read_no_write_share(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 1;
    Ok(OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)?)
}

#[cfg(not(windows))]
fn open_native_read_no_write_share(path: &Path) -> Result<File> {
    Ok(File::open(path)?)
}

fn extract_native_result(
    workspace: &Workspace,
    manifest: &ToolManifest,
    termination: &Termination,
    artifacts: &[ArtifactDescriptor],
) -> NativeResult {
    if !matches!(termination, Termination::Exited { .. }) {
        return NativeResult::NotReported {
            reason: "process_not_exited".to_owned(),
            observations: Vec::new(),
        };
    }
    if manifest.native_observation_contracts.is_empty() {
        return NativeResult::NotReported {
            reason: "native_result_absent".to_owned(),
            observations: Vec::new(),
        };
    }

    let mut observations = Vec::new();
    for contract in &manifest.native_observation_contracts {
        let artifact = match artifacts.iter().find(|artifact| {
            artifact
                .roles
                .iter()
                .any(|role| role == &contract.artifact_role)
        }) {
            Some(artifact) => artifact,
            None => {
                return NativeResult::NotReported {
                    reason: "artifact_missing".to_owned(),
                    observations: Vec::new(),
                };
            }
        };
        let bytes = match workspace.read_verified_descriptor(artifact) {
            Ok(bytes) => bytes,
            Err(_) => {
                return NativeResult::NotReported {
                    reason: "artifact_missing".to_owned(),
                    observations: Vec::new(),
                };
            }
        };
        let extracted = match contract.format.as_str() {
            "json" => extract_json(&bytes, &contract.selector),
            "text_prefix" => extract_text_prefix(&bytes, &contract.selector),
            _ => Err(anyhow::anyhow!("unsupported native observation format")),
        };
        let (value, locator) = match extracted {
            Ok(extracted) => extracted,
            Err(_) => {
                return NativeResult::NotReported {
                    reason: if contract.format == "json" {
                        "parse_error".to_owned()
                    } else {
                        "contract_mismatch".to_owned()
                    },
                    observations: Vec::new(),
                };
            }
        };
        observations.push(NativeObservation {
            namespace: contract.namespace.clone(),
            name: contract.name.clone(),
            value,
            source: ObservationSource::Artifact {
                artifact_id: artifact.artifact_id.clone(),
                locator,
            },
            projection_only: true,
        });
    }

    NativeResult::Reported { observations }
}

fn extract_json(bytes: &[u8], selector: &str) -> Result<(Value, Locator)> {
    let value = strict_json::parse_strict(bytes)?;
    let selected = strict_json::pointer(&value, selector)?.clone();
    Ok((
        selected,
        Locator {
            kind: "json_pointer".to_owned(),
            value: selector.to_owned(),
        },
    ))
}

fn extract_text_prefix(bytes: &[u8], prefix: &str) -> Result<(Value, Locator)> {
    let text = std::str::from_utf8(bytes).context("native text output is not UTF-8")?;
    let mut offset = 0_usize;
    for line in text.split_inclusive('\n') {
        let body = line.trim_end_matches(['\r', '\n']);
        if let Some(value) = body.strip_prefix(prefix) {
            let leading = body.len() - value.len();
            let trimmed = value.trim();
            let trim_start = value.len() - value.trim_start().len();
            let start = offset + leading + trim_start;
            let end = start + trimmed.len();
            return Ok((
                Value::String(trimmed.to_owned()),
                Locator {
                    kind: "byte_range".to_owned(),
                    value: format!("{start}:{end}"),
                },
            ));
        }
        offset += line.len();
    }
    bail!("native text prefix not found")
}

fn run_direct(
    workspace: &Workspace,
    operation: &str,
    invocation: &Invocation,
) -> Result<DirectResult> {
    if invocation.mode != "direct_exec" || invocation.argv.is_empty() {
        bail!("invalid direct invocation");
    }
    let qualified_identity = if operation == "tomorrowci_trust_audit" {
        Some(qualified_identity_from_invocation(workspace, invocation)?)
    } else {
        None
    };
    if let Some(identity) = &qualified_identity {
        verify_qualified_application_identity(workspace, identity, None)?;
        verify_windows_bare_name_search_surface(invocation)?;
    }
    let mut command = Command::new(&invocation.argv[0]);
    command
        .args(&invocation.argv[1..])
        .current_dir(&invocation.cwd)
        .stdin(Stdio::null());
    apply_minimal_environment(&mut command);
    let isolated_path = apply_operation_environment(workspace, operation, &mut command)?;
    if let Some(isolated_path) = &isolated_path {
        // Re-check immediately before opening captures and spawning so a
        // populated or replaced path fails closed instead of becoming an
        // executable search surface.
        isolated_path.verify_empty()?;
    }
    if let Some(identity) = &qualified_identity {
        verify_qualified_application_identity(workspace, identity, None)?;
        verify_windows_bare_name_search_surface(invocation)?;
    }

    let stdout_path = workspace
        .state
        .join("tmp")
        .join(format!("stdout-{}.tmp", Uuid::new_v4().simple()));
    let stderr_path = workspace
        .state
        .join("tmp")
        .join(format!("stderr-{}.tmp", Uuid::new_v4().simple()));
    let stdout = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&stdout_path)?;
    let stderr = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&stderr_path)?;
    let started_at = now();
    let started = Instant::now();
    command
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = fs::remove_file(&stdout_path);
            let _ = fs::remove_file(&stderr_path);
            return Ok(DirectResult {
                started_at,
                finished_at: now(),
                termination: Termination::SpawnError {
                    error_code: error
                        .raw_os_error()
                        .map(|code| code.to_string())
                        .unwrap_or_else(|| error.kind().to_string()),
                    message: error.to_string(),
                },
                stdout_path: None,
                stderr_path: None,
            });
        }
    };

    let timeout = Duration::from_millis(invocation.timeout_ms);
    let mut termination = loop {
        if let Some(status) = child.wait_timeout(Duration::from_millis(50))? {
            break match status.code() {
                Some(exit_code) => Termination::Exited { exit_code },
                None => Termination::Signaled {
                    signal: "platform_signal_or_exception".to_owned(),
                },
            };
        }
        let output_size = file_length(&stdout_path).saturating_add(file_length(&stderr_path));
        if output_size > MAX_CAPTURE_BYTES {
            let _ = child.kill();
            let _ = child.wait();
            break Termination::Interrupted {
                reason: format!("native_output_exceeded_{MAX_CAPTURE_BYTES}_bytes"),
            };
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            break Termination::TimedOut {
                timeout_ms: invocation.timeout_ms,
            };
        }
    };

    if let Some(identity) = &qualified_identity
        && verify_qualified_application_identity(workspace, identity, None).is_err()
    {
        termination = Termination::Interrupted {
            reason: "qualified_application_inventory_changed".to_owned(),
        };
    }
    if qualified_identity.is_some() && verify_windows_bare_name_search_surface(invocation).is_err()
    {
        termination = Termination::Interrupted {
            reason: "qualified_windows_search_surface_changed".to_owned(),
        };
    }
    if let Some(isolated_path) = &isolated_path
        && isolated_path.verify_empty().is_err()
    {
        termination = Termination::Interrupted {
            reason: "qualified_empty_path_inventory_changed".to_owned(),
        };
    }

    sync_file(&stdout_path)?;
    sync_file(&stderr_path)?;
    let output_size = file_length(&stdout_path).saturating_add(file_length(&stderr_path));
    if output_size > MAX_CAPTURE_BYTES {
        termination = Termination::Interrupted {
            reason: format!("native_output_exceeded_{MAX_CAPTURE_BYTES}_bytes"),
        };
        let _ = fs::remove_file(&stdout_path);
        let _ = fs::remove_file(&stderr_path);
        return Ok(DirectResult {
            started_at,
            finished_at: now(),
            termination,
            stdout_path: None,
            stderr_path: None,
        });
    }
    Ok(DirectResult {
        started_at,
        finished_at: now(),
        termination,
        stdout_path: Some(stdout_path),
        stderr_path: Some(stderr_path),
    })
}

fn qualified_identity_from_invocation(
    _workspace: &Workspace,
    invocation: &Invocation,
) -> Result<BinaryIdentity> {
    let path = Path::new(&invocation.argv[0]);
    let (sha256, size_bytes) = workspace::digest_file(path)?;
    Ok(BinaryIdentity {
        path: invocation.argv[0].clone(),
        sha256,
        size_bytes,
        supporting_files_sha256: None,
        supporting_file_count: 0,
        reported_version: None,
        source_path: "tomorrowci.exe".to_owned(),
        snapshot_artifact_id: "artifact_00000000000000000000000000000000".to_owned(),
    })
}

fn run_version_probe(path: &Path, arguments: &[String]) -> Result<Option<String>> {
    let directory = tempfile::tempdir()?;
    let stdout_path = directory.path().join("stdout");
    let stderr_path = directory.path().join("stderr");
    let stdout = File::create(&stdout_path)?;
    let stderr = File::create(&stderr_path)?;
    let mut command = Command::new(path);
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    apply_minimal_environment(&mut command);
    let mut child = command.spawn()?;
    let status = match child.wait_timeout(Duration::from_millis(PROBE_TIMEOUT_MS))? {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            bail!("version probe timed out");
        }
    };
    if !status.success() {
        return Ok(None);
    }
    let mut bytes = fs::read(stdout_path)?;
    if bytes.is_empty() {
        bytes = fs::read(stderr_path)?;
    }
    if bytes.len() > 4096 {
        bail!("version probe output exceeded 4096 bytes");
    }
    let text = String::from_utf8(bytes)?;
    Ok(text
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| {
            let trimmed = line.trim();
            trimmed.chars().take(512).collect::<String>()
        }))
}

fn find_executable(candidates: &[String]) -> Result<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let extensions = executable_extensions();
    for candidate in candidates {
        for directory in std::env::split_paths(&path) {
            let direct = directory.join(candidate);
            if direct.is_file() {
                return direct
                    .canonicalize()
                    .context("cannot canonicalize executable");
            }
            if Path::new(candidate).extension().is_none() {
                for extension in &extensions {
                    let extended = directory.join(format!("{candidate}{extension}"));
                    if extended.is_file() {
                        return extended
                            .canonicalize()
                            .context("cannot canonicalize executable");
                    }
                }
            }
        }
    }
    bail!("executable not found on PATH: {}", candidates.join(" or "))
}

#[allow(dead_code)]
fn fingerprint_python_distribution(executable: &Path, distribution: &str) -> Result<(String, u64)> {
    let executable_directory = executable
        .parent()
        .ok_or_else(|| anyhow::anyhow!("native executable has no parent directory"))?;
    let environment_root = executable_directory
        .parent()
        .ok_or_else(|| anyhow::anyhow!("native executable has no environment root"))?;
    let mut site_packages_candidates = vec![environment_root.join("Lib").join("site-packages")];
    let unix_lib = environment_root.join("lib");
    if unix_lib.is_dir() {
        for entry in fs::read_dir(&unix_lib)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with("python") {
                site_packages_candidates.push(entry.path().join("site-packages"));
            }
        }
    }
    let site_packages = site_packages_candidates
        .into_iter()
        .find(|candidate| candidate.is_dir())
        .ok_or_else(|| anyhow::anyhow!("site-packages was not found beside the native launcher"))?;

    let normalized = distribution.to_ascii_lowercase().replace('-', "_");
    let alternate = normalized.replace('_', "-");
    let mut roots = Vec::new();
    for entry in fs::read_dir(&site_packages)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        let normalized_name = name.replace('-', "_");
        if (normalized_name.contains(&normalized) || name.contains(&alternate))
            && (name.starts_with("__editable__") || name.ends_with(".pth"))
        {
            bail!(
                "editable Python distribution detected; install an immutable wheel/snapshot before planning"
            );
        }
        if normalized_name == normalized
            || normalized_name == format!("{normalized}.py")
            || (normalized_name.starts_with(&format!("{normalized}-"))
                && normalized_name.ends_with(".dist_info"))
            || (name.starts_with(&format!("{alternate}-")) && name.ends_with(".dist-info"))
        {
            roots.push(entry.path());
        }
    }
    if roots.is_empty() {
        bail!("distribution package and dist-info paths were not found");
    }
    for root in &roots {
        let direct_url = root.join("direct_url.json");
        if direct_url.is_file() {
            let bytes = fs::read(&direct_url)?;
            if let Ok(value) = strict_json::parse_strict(&bytes)
                && value.pointer("/dir_info/editable") == Some(&Value::Bool(true))
            {
                bail!(
                    "editable Python distribution detected; install an immutable wheel/snapshot before planning"
                );
            }
        }
    }

    let mut files = Vec::new();
    for root in roots {
        collect_identity_files(&site_packages, &root, &mut files)?;
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files.dedup_by(|left, right| left.0 == right.0);
    if files.is_empty() {
        bail!("distribution supporting tree contains no identity files");
    }
    let mut hasher = Sha256::new();
    for (relative, path) in &files {
        let (digest, length) = workspace::digest_file(path)?;
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        hasher.update(length.to_le_bytes());
        hasher.update(digest.as_bytes());
        hasher.update([0xff]);
    }
    Ok((hex::encode(hasher.finalize()), files.len() as u64))
}

#[allow(dead_code)]
fn collect_identity_files(
    base: &Path,
    path: &Path,
    output: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || is_windows_reparse(&metadata) {
        bail!("supporting identity tree contains a link or reparse point");
    }
    if metadata.is_file() {
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if extension.eq_ignore_ascii_case("pyc") || extension.eq_ignore_ascii_case("pyo") {
            return Ok(());
        }
        let relative = path
            .strip_prefix(base)?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("supporting identity path is not UTF-8"))?
            .replace('\\', "/");
        output.push((relative, path.to_owned()));
        return Ok(());
    }
    if metadata.is_dir() {
        if path
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name == "__pycache__")
        {
            return Ok(());
        }
        for entry in fs::read_dir(path)? {
            collect_identity_files(base, &entry?.path(), output)?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_windows_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x0000_0400 != 0
}

#[cfg(not(windows))]
fn is_windows_reparse(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(windows)]
fn executable_extensions() -> Vec<String> {
    std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_owned())
        .split(';')
        .filter(|extension| {
            !extension.eq_ignore_ascii_case(".bat") && !extension.eq_ignore_ascii_case(".cmd")
        })
        .map(|extension| extension.to_ascii_lowercase())
        .collect()
}

#[cfg(not(windows))]
fn executable_extensions() -> Vec<String> {
    Vec::new()
}

fn apply_minimal_environment(command: &mut Command) {
    const ALLOWED: &[&str] = &[
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "TMPDIR",
        "HOME",
        "USERPROFILE",
        "XDG_CONFIG_HOME",
        "LANG",
        "LC_ALL",
    ];
    let values: Vec<(&str, OsString)> = ALLOWED
        .iter()
        .filter_map(|name| std::env::var_os(name).map(|value| (*name, value)))
        .collect();
    command.env_clear();
    for (name, value) in values {
        command.env(name, value);
    }
}

fn apply_operation_environment(
    workspace: &Workspace,
    operation: &str,
    command: &mut Command,
) -> Result<Option<OwnedEmptyPath>> {
    if operation != "tomorrowci_trust_audit" {
        return Ok(None);
    }

    let empty_path = OwnedEmptyPath::create(workspace)?;
    command.env("PATH", single_entry_path_value(&empty_path.path)?);
    #[cfg(windows)]
    {
        let windows = canonical_windows_directory()?;
        command
            .env("PATHEXT", ".EXE")
            .env("SystemRoot", &windows)
            .env("WINDIR", &windows);
    }
    #[cfg(not(windows))]
    command.env_remove("PATHEXT");
    Ok(Some(empty_path))
}

fn single_entry_path_value(path: &Path) -> Result<OsString> {
    let value = std::env::join_paths([path])
        .context("EWB-owned empty PATH cannot be represented as one search entry")?;
    let entries = std::env::split_paths(&value).collect::<Vec<_>>();
    if entries.len() != 1 || entries[0] != path {
        bail!("EWB-owned empty PATH did not round-trip as one exact search entry");
    }
    Ok(value)
}

fn valid_capability(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn file_length(path: &Path) -> u64 {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0)
}

fn sync_file(path: &Path) -> Result<()> {
    // Windows requires a write-capable handle for FlushFileBuffers/sync_all.
    OpenOptions::new().write(true).open(path)?.sync_all()?;
    Ok(())
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use tempfile::TempDir;

    #[test]
    fn capability_names_are_strict_ascii() {
        assert!(valid_capability("read_subject"));
        assert!(!valid_capability("read-subject"));
        assert!(!valid_capability("READ_SUBJECT"));
        assert!(!valid_capability("*"));
    }

    #[test]
    fn empty_path_encoding_is_exactly_one_search_entry() {
        let temp = tempfile::TempDir::new().unwrap();
        let normal = temp.path().join("empty");
        fs::create_dir(&normal).unwrap();
        let encoded = single_entry_path_value(&normal).unwrap();
        assert_eq!(
            std::env::split_paths(&encoded).collect::<Vec<_>>(),
            [normal]
        );

        #[cfg(windows)]
        {
            let unsafe_path = temp.path().join("semi;colon");
            fs::create_dir(&unsafe_path).unwrap();
            let encoded = single_entry_path_value(&unsafe_path).unwrap();
            assert_eq!(
                std::env::split_paths(&encoded).collect::<Vec<_>>(),
                [unsafe_path]
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn qualified_private_application_rejects_extra_entries_and_hardlinks() {
        let temp = TempDir::new().unwrap();
        let workspace_root = temp.path().join("workspace");
        fs::create_dir(&workspace_root).unwrap();
        let workspace = Workspace::init(&workspace_root).unwrap();
        let source = temp.path().join("tomorrowci.exe");
        fs::copy(std::env::current_exe().unwrap(), &source).unwrap();
        let artifact = workspace
            .import_artifact(
                &source,
                vec![
                    "native_executable_snapshot".to_owned(),
                    "native_qualification_evidence".to_owned(),
                ],
                "application/x-executable".to_owned(),
                "native_file",
                "byte_for_byte_copy",
            )
            .unwrap();
        let plan_id = "plan_11111111111111111111111111111111";
        let (_, path) = workspace
            .materialize_qualified_application(plan_id, &artifact.artifact_id, "tomorrowci.exe")
            .unwrap();
        let identity = BinaryIdentity {
            path: path.display().to_string(),
            sha256: artifact.digest.value,
            size_bytes: artifact.byte_length,
            supporting_files_sha256: None,
            supporting_file_count: 0,
            reported_version: None,
            source_path: "tomorrowci.exe".to_owned(),
            snapshot_artifact_id: artifact.artifact_id,
        };
        verify_qualified_application_identity(&workspace, &identity, Some(plan_id)).unwrap();

        let application = path.parent().unwrap();
        for name in [
            "git.exe",
            "docker.exe",
            "podman.exe",
            "VCRUNTIME140.dll",
            "KERNEL32.dll",
        ] {
            let hostile = application.join(name);
            fs::write(&hostile, b"hostile").unwrap();
            assert!(
                verify_qualified_application_identity(&workspace, &identity, Some(plan_id))
                    .is_err()
            );
            fs::remove_file(hostile).unwrap();
        }

        let alias = temp.path().join("launcher-hardlink.exe");
        fs::hard_link(&path, &alias).unwrap();
        assert!(
            verify_qualified_application_identity(&workspace, &identity, Some(plan_id)).is_err()
        );
        fs::remove_file(alias).unwrap();
        verify_qualified_application_identity(&workspace, &identity, Some(plan_id)).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn tomorrowci_operation_does_not_launch_adversarial_path_shims() {
        let temp = TempDir::new().unwrap();
        let workspace_root = temp.path().join("workspace");
        fs::create_dir(&workspace_root).unwrap();
        let workspace = Workspace::init(&workspace_root).unwrap();

        let hostile_path = temp.path().join("hostile-path");
        fs::create_dir(&hostile_path).unwrap();
        let test_binary = std::env::current_exe().unwrap();
        for name in ["git.exe", "docker.exe", "podman.exe"] {
            fs::copy(&test_binary, hostile_path.join(name)).unwrap();
        }
        let marker = temp.path().join("ambient-shim-launched");

        let system_root = std::env::var_os("SystemRoot").unwrap();
        let mut command = Command::new(PathBuf::from(system_root).join("System32/cmd.exe"));
        command
            .args([
                "/D",
                "/C",
                "git --exact native::tests::adversarial_path_shim_child & docker --exact native::tests::adversarial_path_shim_child & podman --exact native::tests::adversarial_path_shim_child & exit /b 0",
            ])
            .current_dir(&workspace.root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        apply_minimal_environment(&mut command);
        // Model a fully adversarial ambient PATH before the operation-specific
        // boundary replaces it.
        command
            .env("PATH", &hostile_path)
            .env("PATHEXT", ".EXE")
            .env("EWB_ADVERSARIAL_SHIM_MARKER", &marker);

        let isolated =
            apply_operation_environment(&workspace, "tomorrowci_trust_audit", &mut command)
                .unwrap()
                .unwrap();
        isolated.verify_empty().unwrap();
        assert!(isolated.path.starts_with(workspace.state.join("tmp")));
        assert!(
            isolated
                .path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .contains(EMPTY_PATH_CONTENT_SHA256)
        );

        let status = command.status().unwrap();
        assert!(status.success());
        assert!(
            !marker.exists(),
            "TomorrowCI operation launched a binary from ambient PATH"
        );
        let isolated_path = isolated.path.clone();
        drop(isolated);
        assert!(!isolated_path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn adversarial_path_shim_child() {
        if let Some(marker) = std::env::var_os("EWB_ADVERSARIAL_SHIM_MARKER") {
            fs::write(marker, b"launched").unwrap();
        }
    }
}
