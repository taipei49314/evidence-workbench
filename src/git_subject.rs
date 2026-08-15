use crate::contracts::{GitPlanToolIdentity, Revision, Subject, SubjectSnapshot};
use crate::workspace::Workspace;
use anyhow::{Context, Result, bail};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
#[cfg(windows)]
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug)]
pub struct PlannedGit {
    /// Canonical host-installation path used only while planning. Git for
    /// Windows is not a self-contained executable, so the staged byte copy is
    /// evidence, not something EWB claims can be launched independently.
    pub path: PathBuf,
    pub identity: GitPlanToolIdentity,
    locked_source: File,
}

pub fn snapshot_plan_tool(workspace: &Workspace) -> Result<PlannedGit> {
    require_windows_planning("Git subject planning is disabled outside Windows in this MVP")?;
    let source = find_git_on_path()?;
    let mut locked_source = open_git_read_no_write_share(&source)?;
    let (source_sha256, source_size_bytes) = digest_open_file(&mut locked_source)?;
    let (artifact, staged) = workspace.import_git_plan_launcher_snapshot(&source)?;
    if artifact.digest.value != source_sha256 || artifact.byte_length != source_size_bytes {
        bail!("Git launcher changed while its plan-time identity was captured");
    }
    let identity = GitPlanToolIdentity {
        source_path: source.display().to_string(),
        source_sha256,
        source_size_bytes,
        snapshot_artifact_id: artifact.artifact_id,
        staged_path: staged.display().to_string(),
        use_scope: "plan_only_locked_source".to_owned(),
        runtime_closure: "host_installation_not_snapshotted_never_used_at_execute".to_owned(),
    };
    Ok(PlannedGit {
        path: source,
        identity,
        locked_source,
    })
}

fn require_windows_planning(message: &str) -> Result<()> {
    if cfg!(windows) {
        Ok(())
    } else {
        bail!(message.to_owned())
    }
}

impl PlannedGit {
    fn verify_locked_source(&self) -> Result<()> {
        let mut file = self.locked_source.try_clone()?;
        let (digest, length) = digest_open_file(&mut file)?;
        if digest != self.identity.source_sha256 || length != self.identity.source_size_bytes {
            bail!("plan-time Git launcher changed while the subject snapshot was created");
        }
        Ok(())
    }
}

fn digest_open_file(file: &mut File) -> Result<(String, u64)> {
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
        length = length
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("Git launcher length overflow"))?;
    }
    Ok((hex::encode(hasher.finalize()), length))
}

#[cfg(windows)]
fn open_git_read_no_write_share(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    Ok(OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)?)
}

#[cfg(not(windows))]
fn open_git_read_no_write_share(path: &Path) -> Result<File> {
    Ok(File::open(path)?)
}

fn find_git_on_path() -> Result<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(if cfg!(windows) { "git.exe" } else { "git" });
        if candidate.is_file() {
            return candidate
                .canonicalize()
                .context("cannot canonicalize Git executable");
        }
    }
    bail!("Git executable not found on PATH")
}

pub fn resolve(path: &Path) -> Result<Subject> {
    resolve_inner(path, None, None)
}

pub fn snapshot(
    path: &Path,
    base: Option<&str>,
    workspace: &Workspace,
    plan_id: &str,
    git: &PlannedGit,
) -> Result<Subject> {
    git.verify_locked_source()?;
    let result = resolve_inner(path, Some((workspace, plan_id, git)), base);
    let unchanged = git.verify_locked_source();
    match (result, unchanged) {
        (Ok(subject), Ok(())) => Ok(subject),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(changed)) => Err(error.context(changed.to_string())),
    }
}

fn resolve_inner(
    path: &Path,
    snapshot: Option<(&Workspace, &str, &PlannedGit)>,
    base: Option<&str>,
) -> Result<Subject> {
    let requested = path
        .canonicalize()
        .with_context(|| format!("cannot resolve subject path {}", path.display()))?;
    if !requested.is_dir() {
        bail!("subject path is not a directory: {}", requested.display());
    }

    let git = snapshot.map(|(_, _, git)| git.path.as_path());
    let root_text = git_text(git, &requested, &["rev-parse", "--show-toplevel"])?;
    let root = PathBuf::from(root_text.trim())
        .canonicalize()
        .context("cannot canonicalize Git worktree root")?;
    let status = git_bytes(
        git,
        &root,
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    if !status.is_empty() {
        bail!(
            "MVP requires a clean Git subject; commit, stash, or remove all tracked and untracked changes"
        );
    }

    let object_format = git_text(git, &root, &["rev-parse", "--show-object-format"])
        .unwrap_or_else(|_| "sha1".to_owned());
    let algorithm = match object_format.trim() {
        "sha1" => "git-sha1",
        "sha256" => "git-sha256",
        other => bail!("unsupported Git object format: {other}"),
    };
    let head = git_text(git, &root, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    let head = head.trim().to_ascii_lowercase();
    validate_oid(&head, algorithm)?;

    let repository = git_text(git, &root, &["config", "--get", "remote.origin.url"])
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("file:{}", root.display()));

    let mut revisions = vec![Revision {
        role: "subject".to_owned(),
        algorithm: algorithm.to_owned(),
        value: head.clone(),
    }];
    if let Some(base) = base {
        validate_oid(base, algorithm)?;
        assert_revision(git, &root, base)?;
        revisions.push(Revision {
            role: "base".to_owned(),
            algorithm: algorithm.to_owned(),
            value: base.to_owned(),
        });
    }
    let snapshot = match snapshot {
        Some((workspace, plan_id, git)) => Some(create_bundle_snapshot(
            workspace, plan_id, &root, &head, base, git,
        )?),
        None => None,
    };
    Ok(Subject::Git {
        repository,
        original_root: root.display().to_string(),
        revisions,
        worktree_state: "clean".to_owned(),
        snapshot,
    })
}

fn create_bundle_snapshot(
    workspace: &Workspace,
    plan_id: &str,
    root: &Path,
    head: &str,
    base: Option<&str>,
    git: &PlannedGit,
) -> Result<SubjectSnapshot> {
    let temporary = workspace
        .state
        .join("tmp")
        .join(format!("{plan_id}.bundle"));
    let collector = workspace.state.join("tmp").join(format!("{plan_id}.git"));
    let init = hardened_git(&git.path)
        .arg("-c")
        .arg("init.templateDir=")
        .args(["init", "--quiet", "--bare"])
        .arg(command_path(&collector))
        .output()?;
    if !init.status.success() {
        let _ = std::fs::remove_dir_all(&collector);
        bail!(
            "cannot initialize private Git bundle collector: {}",
            String::from_utf8_lossy(&init.stderr).trim()
        );
    }
    let fetch_ref = |oid: &str, name: &str| -> Result<()> {
        let spec = format!("{oid}:refs/ewb/{name}");
        let output = safe_git(&git.path, &collector)
            .args(["fetch", "--quiet", "--no-tags", "--no-write-fetch-head"])
            .arg(command_path(root))
            .arg(spec)
            .output()?;
        if !output.status.success() {
            bail!("cannot fetch exact {name} revision into private bundle collector");
        }
        Ok(())
    };
    let result = (|| -> Result<()> {
        fetch_ref(head, "subject")?;
        if let Some(base) = base {
            fetch_ref(base, "base")?;
        }
        let mut command = safe_git(&git.path, &collector);
        command
            .args(["bundle", "create"])
            .arg(command_path(&temporary))
            .arg("refs/ewb/subject");
        if base.is_some() {
            command.arg("refs/ewb/base");
        }
        let output = command
            .output()
            .context("failed to launch git bundle create")?;
        if !output.status.success() {
            bail!(
                "git bundle creation failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let verify = safe_git(&git.path, &collector)
            .args(["bundle", "verify"])
            .arg(command_path(&temporary))
            .output()?;
        if !verify.status.success() {
            bail!(
                "created Git bundle failed verification: {}",
                String::from_utf8_lossy(&verify.stderr).trim()
            );
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&collector);
    if let Err(error) = result {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    let artifact = match workspace.import_artifact(
        &temporary,
        vec!["git_subject_bundle".to_owned()],
        "application/vnd.git.bundle".to_owned(),
        "native_file",
        "byte_for_byte_copy",
    ) {
        Ok(artifact) => artifact,
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
    };
    let _ = std::fs::remove_file(&temporary);
    let (tree_artifact, tree_sha256, tree_byte_length, tree_file_count) =
        create_tree_snapshot(workspace, plan_id, root, head, git)?;
    Ok(SubjectSnapshot {
        artifact_id: artifact.artifact_id,
        sha256: artifact.digest.value,
        byte_length: artifact.byte_length,
        execution_path: workspace.execution_path(plan_id)?.display().to_string(),
        tree_artifact_id: Some(tree_artifact),
        tree_sha256: Some(tree_sha256),
        tree_byte_length: Some(tree_byte_length),
        tree_file_count: Some(tree_file_count),
        git_plan_tool: Some(git.identity.clone()),
    })
}

fn create_tree_snapshot(
    workspace: &Workspace,
    plan_id: &str,
    source_root: &Path,
    head: &str,
    git: &PlannedGit,
) -> Result<(String, String, u64, u64)> {
    let checkout = workspace
        .state
        .join("tmp")
        .join(format!("{plan_id}-checkout"));
    let archive = workspace
        .state
        .join("tmp")
        .join(format!("{plan_id}-tree.ewbtree"));
    let result = (|| -> Result<(String, String, u64, u64)> {
        fs::create_dir(&checkout)?;
        let init = hardened_git(&git.path)
            .arg("-c")
            .arg("init.templateDir=")
            .arg("-C")
            .arg(command_path(&checkout))
            .args(["init", "--quiet"])
            .output()?;
        if !init.status.success() {
            bail!("cannot initialize private plan-time checkout");
        }
        let fetch = safe_git(&git.path, &checkout)
            .args(["fetch", "--quiet", "--no-tags", "--no-write-fetch-head"])
            .arg(command_path(source_root))
            .arg(format!("{head}:refs/ewb/subject"))
            .output()?;
        if !fetch.status.success() {
            bail!("cannot fetch exact subject into private plan-time checkout");
        }
        let checkout_status = safe_git(&git.path, &checkout)
            .args(["checkout", "--quiet", "--detach", head])
            .output()?;
        if !checkout_status.status.success() {
            bail!("cannot checkout exact subject during planning");
        }
        let git_dir = checkout.join(".git");
        if git_dir.exists() {
            fs::remove_dir_all(&git_dir)?;
        }
        let (tree_sha256, tree_file_count, tree_byte_length) =
            write_tree_archive(&checkout, &archive)?;
        let artifact = workspace.import_artifact(
            &archive,
            vec!["git_execution_tree".to_owned()],
            "application/vnd.evidence-workbench.tree-v1".to_owned(),
            "native_file",
            "byte_for_byte_copy",
        )?;
        Ok((
            artifact.artifact_id,
            tree_sha256,
            tree_byte_length,
            tree_file_count,
        ))
    })();
    let _ = fs::remove_dir_all(&checkout);
    let _ = fs::remove_file(&archive);
    result
}

fn write_tree_archive(root: &Path, archive: &Path) -> Result<(String, u64, u64)> {
    let mut files = Vec::new();
    collect_tree_files(root, root, &mut files, true)?;
    files.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    let mut output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(archive)?;
    output.write_all(b"EWBTREE1\0")?;
    let mut tree_hasher = Sha256::new();
    let mut total = 0_u64;
    for (relative, path) in &files {
        let name = relative.as_bytes();
        validate_relative_tree_path(relative)?;
        if name.len() > 16 * 1024 {
            bail!("Git tree entry name is too long");
        }
        let length = fs::metadata(path)?.len();
        output.write_all(&(name.len() as u32).to_le_bytes())?;
        output.write_all(name)?;
        output.write_all(&length.to_le_bytes())?;
        tree_hasher.update((name.len() as u32).to_le_bytes());
        tree_hasher.update(name);
        tree_hasher.update(length.to_le_bytes());
        let mut input = fs::File::open(path)?;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            output.write_all(&buffer[..read])?;
            tree_hasher.update(&buffer[..read]);
            total = total
                .checked_add(read as u64)
                .ok_or_else(|| anyhow::anyhow!("Git tree byte count overflow"))?;
        }
    }
    output.sync_all()?;
    Ok((
        hex::encode(tree_hasher.finalize()),
        files.len() as u64,
        total,
    ))
}

#[derive(Debug, PartialEq, Eq)]
struct TreeIdentity {
    sha256: String,
    byte_length: u64,
    file_count: u64,
}

fn parse_tree_archive(
    bytes: &[u8],
    mut visit: impl FnMut(&str, &[u8]) -> Result<()>,
) -> Result<TreeIdentity> {
    if !bytes.starts_with(b"EWBTREE1\0") {
        bail!("invalid Git execution-tree archive");
    }
    let mut position = 9_usize;
    let mut hasher = Sha256::new();
    let mut count = 0_u64;
    let mut total = 0_u64;
    let mut previous_name: Option<Vec<u8>> = None;
    while position < bytes.len() {
        let name_length_bytes = take_archive_bytes(bytes, &mut position, 4)?;
        let name_length =
            u32::from_le_bytes(name_length_bytes.try_into().expect("four bytes")) as usize;
        if name_length == 0 || name_length > 16 * 1024 {
            bail!("unsafe Git tree entry name length");
        }
        let name_bytes = take_archive_bytes(bytes, &mut position, name_length)?;
        if previous_name
            .as_deref()
            .is_some_and(|previous| previous >= name_bytes)
        {
            bail!("Git execution-tree entries are not uniquely sorted");
        }
        let name = std::str::from_utf8(name_bytes)?;
        validate_relative_tree_path(name)?;
        let length_bytes = take_archive_bytes(bytes, &mut position, 8)?;
        let length = u64::from_le_bytes(length_bytes.try_into().expect("eight bytes"));
        let content_length = usize::try_from(length)
            .context("Git execution-tree entry is too large for this platform")?;
        let content = take_archive_bytes(bytes, &mut position, content_length)?;

        hasher.update((name_length as u32).to_le_bytes());
        hasher.update(name_bytes);
        hasher.update(length.to_le_bytes());
        hasher.update(content);
        total = total
            .checked_add(length)
            .ok_or_else(|| anyhow::anyhow!("Git tree byte count overflow"))?;
        count = count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Git tree file count overflow"))?;
        visit(name, content)?;
        previous_name = Some(name_bytes.to_vec());
    }
    Ok(TreeIdentity {
        sha256: hex::encode(hasher.finalize()),
        byte_length: total,
        file_count: count,
    })
}

fn take_archive_bytes<'a>(
    bytes: &'a [u8],
    position: &mut usize,
    length: usize,
) -> Result<&'a [u8]> {
    let end = position
        .checked_add(length)
        .ok_or_else(|| anyhow::anyhow!("Git execution-tree offset overflow"))?;
    let value = bytes
        .get(*position..end)
        .ok_or_else(|| anyhow::anyhow!("truncated Git execution-tree archive"))?;
    *position = end;
    Ok(value)
}

fn collect_tree_files(
    base: &Path,
    path: &Path,
    output: &mut Vec<(String, PathBuf)>,
    skip_git: bool,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if is_reparse(&metadata) {
        bail!("Git execution tree contains a link or reparse point");
    }
    if metadata.is_file() {
        let relative = path
            .strip_prefix(base)?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Git tree path is not UTF-8"))?
            .replace('\\', "/");
        if relative
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        {
            bail!("unsafe Git tree path");
        }
        output.push((relative, path.to_owned()));
    } else if metadata.is_dir() {
        if skip_git
            && path != base
            && path.file_name().and_then(|name| name.to_str()) == Some(".git")
        {
            return Ok(());
        }
        for entry in fs::read_dir(path)? {
            collect_tree_files(base, &entry?.path(), output, skip_git)?;
        }
    }
    Ok(())
}

fn extract_planned_tree(
    workspace: &Workspace,
    snapshot: &SubjectSnapshot,
    destination: &Path,
) -> Result<()> {
    let artifact_id = snapshot
        .tree_artifact_id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Git subject lacks execution-tree artifact"))?;
    let record = workspace.load_artifact(artifact_id)?;
    let bytes = workspace.read_verified_descriptor(&record.artifact)?;
    if record.artifact.roles != ["git_execution_tree"]
        || record.artifact.media_type != "application/vnd.evidence-workbench.tree-v1"
    {
        bail!("Git execution-tree artifact contract mismatch");
    }
    let identity = parse_tree_archive(&bytes, |name, content| {
        let target = destination.join(name.replace('/', std::path::MAIN_SEPARATOR_STR));
        let parent = target
            .parent()
            .ok_or_else(|| anyhow::anyhow!("tree entry has no parent"))?;
        fs::create_dir_all(parent)?;
        ensure_real_tree_parent(destination, parent)?;
        let mut output = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&target)?;
        output.write_all(content)?;
        output.sync_all()?;
        Ok(())
    })?;
    if snapshot.tree_sha256.as_deref() != Some(&identity.sha256)
        || snapshot.tree_file_count != Some(identity.file_count)
        || snapshot.tree_byte_length != Some(identity.byte_length)
    {
        bail!("Git execution-tree archive does not match planned identity");
    }
    Ok(())
}

fn ensure_real_tree_parent(root: &Path, parent: &Path) -> Result<()> {
    let relative = parent.strip_prefix(root)?;
    let mut current = root.to_owned();
    for component in relative.components() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current)?;
        if !metadata.is_dir() || is_reparse(&metadata) {
            bail!("Git execution-tree parent is linked or not a directory");
        }
    }
    Ok(())
}

fn hash_materialized_tree(root: &Path) -> Result<(String, u64, u64)> {
    let mut files = Vec::new();
    collect_tree_files(root, root, &mut files, false)?;
    files.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    for (relative, path) in &files {
        let name = relative.as_bytes();
        let length = fs::metadata(path)?.len();
        hasher.update((name.len() as u32).to_le_bytes());
        hasher.update(name);
        hasher.update(length.to_le_bytes());
        let mut input = fs::File::open(path)?;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        total += length;
    }
    Ok((hex::encode(hasher.finalize()), files.len() as u64, total))
}

fn validate_relative_tree_path(value: &str) -> Result<()> {
    if value.is_empty()
        || value.contains('\\')
        || value.starts_with('/')
        || value.contains(':')
        || value
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        || value.split('/').next() == Some(".git")
    {
        bail!("unsafe Git execution-tree path");
    }
    Ok(())
}

/// Re-derive every Git-specific snapshot binding from exact stored bytes.
/// This is used both before execution and when a persisted run is loaded.
pub fn validate_planned_snapshot(
    workspace: &Workspace,
    snapshot: &SubjectSnapshot,
    revisions: &[Revision],
) -> Result<()> {
    let bundle = workspace.load_artifact(&snapshot.artifact_id)?;
    if bundle.artifact.digest.value != snapshot.sha256
        || bundle.artifact.byte_length != snapshot.byte_length
        || bundle.artifact.roles != ["git_subject_bundle"]
        || bundle.artifact.media_type != "application/vnd.git.bundle"
        || bundle.artifact.origin != "native_file"
        || bundle.artifact.capture.mode != "byte_for_byte_copy"
        || !bundle.artifact.transforms.is_empty()
    {
        bail!("Git subject bundle snapshot identity mismatch");
    }
    let bundle_bytes = workspace.read_verified_descriptor(&bundle.artifact)?;
    validate_bundle_revisions(&bundle_bytes, revisions)?;

    let tree_artifact_id = snapshot
        .tree_artifact_id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Git subject lacks execution-tree artifact"))?;
    let tree = workspace.load_artifact(tree_artifact_id)?;
    if tree.artifact.roles != ["git_execution_tree"]
        || tree.artifact.media_type != "application/vnd.evidence-workbench.tree-v1"
        || tree.artifact.origin != "native_file"
        || tree.artifact.capture.mode != "byte_for_byte_copy"
        || !tree.artifact.transforms.is_empty()
    {
        bail!("Git execution-tree artifact contract mismatch");
    }
    let tree_bytes = workspace.read_verified_descriptor(&tree.artifact)?;
    let identity = parse_tree_archive(&tree_bytes, |_name, _content| Ok(()))?;
    if snapshot.tree_sha256.as_deref() != Some(&identity.sha256)
        || snapshot.tree_byte_length != Some(identity.byte_length)
        || snapshot.tree_file_count != Some(identity.file_count)
    {
        bail!("Git execution-tree artifact does not match recorded identity");
    }

    let git = snapshot
        .git_plan_tool
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Git subject lacks plan-time Git identity"))?;
    if git.use_scope != "plan_only_locked_source"
        || git.runtime_closure != "host_installation_not_snapshotted_never_used_at_execute"
    {
        bail!("Git plan tool scope or runtime-closure contract mismatch");
    }
    if git.source_path.trim().is_empty() {
        bail!("Git plan tool source path is empty");
    }
    crate::workspace::validate_sha256(&git.source_sha256)?;
    let launcher = workspace.load_artifact(&git.snapshot_artifact_id)?;
    if launcher.artifact.digest.value != git.source_sha256
        || launcher.artifact.byte_length != git.source_size_bytes
        || launcher.artifact.roles != ["git_plan_launcher_snapshot"]
        || launcher.artifact.media_type != "application/x-executable"
        || launcher.artifact.origin != "native_file"
        || launcher.artifact.capture.mode != "byte_for_byte_copy"
        || !launcher.artifact.transforms.is_empty()
    {
        bail!("Git plan launcher snapshot identity mismatch");
    }
    let source_extension = Path::new(&git.source_path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let expected_staged =
        workspace.staged_git_plan_launcher_path(&git.source_sha256, source_extension)?;
    if Path::new(&git.staged_path) != expected_staged {
        bail!("Git plan launcher staged path is outside its content-addressed location");
    }
    crate::workspace::verify_private_file(
        &expected_staged,
        &git.source_sha256,
        git.source_size_bytes,
    )
    .context(
        "staged Git plan launcher bytes do not match recorded identity or private single-link contract",
    )?;
    Ok(())
}

fn validate_bundle_revisions(bytes: &[u8], revisions: &[Revision]) -> Result<()> {
    let header_end = bytes
        .windows(2)
        .position(|window| window == b"\n\n")
        .ok_or_else(|| anyhow::anyhow!("Git bundle lacks a complete header"))?;
    let pack = bytes
        .get(header_end + 2..)
        .ok_or_else(|| anyhow::anyhow!("Git bundle is truncated"))?;
    if !pack.starts_with(b"PACK") {
        bail!("Git bundle lacks an embedded pack");
    }
    let header = std::str::from_utf8(&bytes[..header_end])?;
    let mut lines = header.lines();
    match lines.next() {
        Some("# v2 git bundle" | "# v3 git bundle") => {}
        _ => bail!("unsupported Git bundle header"),
    }

    let mut expected = BTreeMap::new();
    for revision in revisions {
        let reference = match revision.role.as_str() {
            "subject" => "refs/ewb/subject",
            "base" => "refs/ewb/base",
            other => bail!("unsupported planned Git revision role: {other}"),
        };
        if expected
            .insert(reference, revision.value.as_str())
            .is_some()
        {
            bail!("duplicate planned Git revision role");
        }
    }
    if !expected.contains_key("refs/ewb/subject") {
        bail!("planned Git revisions lack the subject revision");
    }

    let mut actual = BTreeMap::new();
    for line in lines {
        if line.starts_with('@') {
            continue;
        }
        if line.starts_with('-') {
            bail!("Git subject bundle is not self-contained");
        }
        let (oid, reference) = line
            .split_once(' ')
            .ok_or_else(|| anyhow::anyhow!("malformed Git bundle reference header"))?;
        if !matches!(reference, "refs/ewb/subject" | "refs/ewb/base") {
            bail!("Git bundle contains an unexpected reference");
        }
        if actual.insert(reference, oid).is_some() {
            bail!("Git bundle contains a duplicate reference");
        }
    }
    if actual != expected {
        bail!("Git bundle references do not match recorded exact revisions");
    }
    Ok(())
}

pub fn materialize(workspace: &Workspace, subject: &Subject) -> Result<PathBuf> {
    let snapshot = match subject {
        Subject::Git {
            snapshot: Some(snapshot),
            ..
        } => snapshot,
        Subject::Git { snapshot: None, .. } => bail!("Git subject has no planned bundle snapshot"),
        _ => bail!("tool requires a Git subject"),
    };
    let revisions = match subject {
        Subject::Git { revisions, .. } => revisions,
        _ => unreachable!("subject was matched as Git above"),
    };
    validate_planned_snapshot(workspace, snapshot, revisions)?;
    let destination = PathBuf::from(&snapshot.execution_path);
    if destination.exists() {
        bail!("planned Git execution root already exists");
    }
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow::anyhow!("execution root has no parent"))?;
    if parent != workspace.state.join("executions") {
        bail!("Git execution root is outside EWB state");
    }
    let parent_meta = std::fs::symlink_metadata(parent)?;
    if !parent_meta.is_dir() || is_reparse(&parent_meta) {
        bail!("Git execution parent is not a real directory");
    }
    std::fs::create_dir(&destination)?;
    let materialized = extract_planned_tree(workspace, snapshot, &destination);
    if let Err(error) = materialized {
        let _ = std::fs::remove_dir_all(&destination);
        return Err(error);
    }
    let (digest, count, length) = match hash_materialized_tree(&destination) {
        Ok(identity) => identity,
        Err(error) => {
            let _ = std::fs::remove_dir_all(&destination);
            return Err(error).context("cannot verify materialized Git execution tree");
        }
    };
    if snapshot.tree_sha256.as_deref() != Some(&digest)
        || snapshot.tree_file_count != Some(count)
        || snapshot.tree_byte_length != Some(length)
    {
        let _ = std::fs::remove_dir_all(&destination);
        bail!("materialized Git execution tree does not match planned identity");
    }
    Ok(destination)
}

pub fn verify_materialized(subject: &Subject) -> Result<()> {
    let snapshot = match subject {
        Subject::Git {
            snapshot: Some(snapshot),
            ..
        } => snapshot,
        _ => bail!("Git subject has no planned execution tree"),
    };
    let (digest, count, length) = hash_materialized_tree(Path::new(&snapshot.execution_path))?;
    if snapshot.tree_sha256.as_deref() != Some(&digest)
        || snapshot.tree_file_count != Some(count)
        || snapshot.tree_byte_length != Some(length)
    {
        bail!("materialized Git execution tree changed during execution");
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x0000_0400 != 0
}

#[cfg(not(windows))]
fn is_reparse(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

pub fn assert_revision(git: Option<&Path>, root: &Path, revision: &str) -> Result<()> {
    let expression = format!("{revision}^{{commit}}");
    let output = safe_git(git.unwrap_or_else(|| Path::new("git")), root)
        .args(["cat-file", "-e"])
        .arg(&expression)
        .output()
        .context("failed to launch git cat-file")?;
    if !output.status.success() {
        bail!("Git revision is not a commit in the resolved subject: {revision}");
    }
    Ok(())
}

pub fn root(subject: &Subject) -> Result<PathBuf> {
    match subject {
        Subject::Git {
            snapshot: Some(snapshot),
            ..
        } => Ok(PathBuf::from(&snapshot.execution_path)),
        Subject::Git { snapshot: None, .. } => bail!("Git subject has no planned execution root"),
        _ => bail!("tool requires a Git subject"),
    }
}

pub fn head(subject: &Subject) -> Result<&str> {
    match subject {
        Subject::Git { revisions, .. } => revisions
            .iter()
            .find(|revision| revision.role == "subject")
            .map(|revision| revision.value.as_str())
            .ok_or_else(|| anyhow::anyhow!("Git subject has no subject revision")),
        _ => bail!("tool requires a Git subject"),
    }
}

fn git_text(git: Option<&Path>, path: &Path, args: &[&str]) -> Result<String> {
    let bytes = git_bytes(git, path, args)?;
    String::from_utf8(bytes).context("git emitted non-UTF-8 output")
}

fn git_bytes(git: Option<&Path>, path: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = safe_git(git.unwrap_or_else(|| Path::new("git")), path)
        .args(args)
        .output()
        .context("failed to launch git")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git command failed: {}", stderr.trim());
    }
    Ok(output.stdout)
}

fn safe_git(git: &Path, path: &Path) -> Command {
    let mut command = hardened_git(git);
    command.arg("-C").arg(command_path(path));
    command
}

fn hardened_git(git: &Path) -> Command {
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let mut command = Command::new(git);
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", null)
        .arg("-c")
        .arg(format!("core.hooksPath={null}"))
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("filter.lfs.required=false")
        .arg("-c")
        .arg("filter.lfs.smudge=")
        .arg("-c")
        .arg("filter.lfs.clean=");
    command
}

#[cfg(windows)]
fn command_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text))
}

#[cfg(not(windows))]
fn command_path(path: &Path) -> PathBuf {
    path.to_owned()
}

fn validate_oid(value: &str, algorithm: &str) -> Result<()> {
    let expected = match algorithm {
        "git-sha1" => 40,
        "git-sha256" => 64,
        _ => bail!("unsupported Git object algorithm"),
    };
    if value.len() != expected
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("invalid exact Git object id");
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn retained_git_handle_denies_write_and_delete_sharing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("git.exe");
        fs::write(&path, b"fixture Git launcher").unwrap();
        let handle = open_git_read_no_write_share(&path).unwrap();

        assert!(OpenOptions::new().write(true).open(&path).is_err());
        assert!(fs::remove_file(&path).is_err());

        drop(handle);
        fs::remove_file(&path).unwrap();
    }
}
