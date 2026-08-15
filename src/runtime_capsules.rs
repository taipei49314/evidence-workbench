use crate::contracts::{
    ArtifactDescriptor, CapsuleClosureState, CapsuleLauncher, CapsuleLauncherKind,
    CapsuleOperationScope, CapsulePlatform, CapsuleReadiness, CapsuleReadinessState,
    CapsuleSupportingFile, CapsuleTransitiveClosure, ContractAuthorityEffect, Digest,
    ExternalPlatformAssumption, PlatformAssumptionState, RuntimeCapsule,
    RuntimeCapsuleFileSnapshot, RuntimeCapsuleRecord, RuntimeCapsuleRecordPayload,
};
use crate::data_contract_validation;
use crate::workspace::{self, Workspace};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct RuntimeCapsuleVerification {
    pub capsule_id: String,
    pub record_digest: String,
    pub descriptor_sha256: String,
    pub readiness: CapsuleReadinessState,
    pub blocker_codes: Vec<String>,
    pub descriptor_claimed_readiness: CapsuleReadinessState,
    pub descriptor_blocker_codes: Vec<String>,
    pub execution_admission: &'static str,
    pub host_os_matches: bool,
    pub host_arch_matches: bool,
    pub tool_manifest_id: String,
    pub operations: Vec<String>,
    pub verified_file_count: u64,
    pub authority_effect: &'static str,
}

pub fn admit(
    workspace: &Workspace,
    descriptor: &Path,
    root: &Path,
) -> Result<RuntimeCapsuleRecord> {
    let descriptor = canonical_regular_file(descriptor, "runtime capsule descriptor")?;
    let root = canonical_real_directory(root, "runtime capsule root")?;
    let descriptor_bytes =
        fs::read(&descriptor).context("cannot read runtime capsule descriptor")?;
    let capsule = data_contract_validation::parse_runtime_capsule(&descriptor_bytes)?;

    let destination = workspace
        .state
        .join("capsules")
        .join(format!("{}.json", capsule.capsule_id));
    if destination.exists() {
        bail!(
            "runtime capsule {} is already present in the trusted workspace registry",
            capsule.capsule_id
        );
    }

    validate_inventory_digest(&capsule)?;
    verify_qualification_evidence(workspace, &capsule)?;
    let sources = verify_source_tree(&root, &capsule)?;

    let descriptor_artifact = workspace.import_artifact(
        &descriptor,
        vec!["runtime_capsule_descriptor".to_owned()],
        "application/vnd.evidence-workbench.runtime-capsule-v1+json".to_owned(),
        "native_file",
        "byte_for_byte_copy",
    )?;

    let launcher_source = sources
        .get(&capsule.launcher.path)
        .expect("validated launcher source is present");
    let launcher_artifact = workspace.import_artifact(
        launcher_source,
        vec!["runtime_capsule_launcher".to_owned()],
        "application/x-executable".to_owned(),
        "native_file",
        "byte_for_byte_copy",
    )?;
    let launcher = RuntimeCapsuleFileSnapshot {
        path: capsule.launcher.path.clone(),
        role: "launcher".to_owned(),
        artifact_id: launcher_artifact.artifact_id,
        digest: launcher_artifact.digest,
        byte_length: launcher_artifact.byte_length,
    };

    let mut supporting_files = Vec::with_capacity(capsule.supporting_files.len());
    for declared in &capsule.supporting_files {
        let source = sources
            .get(&declared.path)
            .expect("validated supporting source is present");
        let artifact = workspace.import_artifact(
            source,
            vec!["runtime_capsule_supporting_file".to_owned()],
            "application/octet-stream".to_owned(),
            "native_file",
            "byte_for_byte_copy",
        )?;
        supporting_files.push(RuntimeCapsuleFileSnapshot {
            path: declared.path.clone(),
            role: declared.role.clone(),
            artifact_id: artifact.artifact_id,
            digest: artifact.digest,
            byte_length: artifact.byte_length,
        });
    }

    let payload = RuntimeCapsuleRecordPayload {
        descriptor_sha256: descriptor_artifact.digest.value,
        descriptor_artifact_id: descriptor_artifact.artifact_id,
        launcher,
        supporting_files,
        capsule,
    };
    let record = RuntimeCapsuleRecord {
        schema_version: "runtime_capsule_record/v1".to_owned(),
        capsule_id: payload.capsule.capsule_id.clone(),
        record_digest: workspace::digest_serialized(&payload)?,
        payload,
    };
    verify_record(workspace, &record)?;
    workspace.write_runtime_capsule(&record)?;
    Ok(record)
}

pub fn load_verified(workspace: &Workspace, capsule_id: &str) -> Result<RuntimeCapsuleRecord> {
    let record = workspace.load_runtime_capsule(capsule_id)?;
    verify_record(workspace, &record)?;
    Ok(record)
}

pub fn list_verified(workspace: &Workspace) -> Result<Vec<RuntimeCapsuleRecord>> {
    let records = workspace.list_runtime_capsules()?;
    for record in &records {
        verify_record(workspace, record)?;
    }
    Ok(records)
}

pub fn verify(workspace: &Workspace, capsule_id: &str) -> Result<RuntimeCapsuleVerification> {
    let record = load_verified(workspace, capsule_id)?;
    let capsule = &record.payload.capsule;
    Ok(RuntimeCapsuleVerification {
        capsule_id: record.capsule_id,
        record_digest: record.record_digest,
        descriptor_sha256: record.payload.descriptor_sha256,
        readiness: CapsuleReadinessState::FailClosed,
        blocker_codes: vec!["python_runtime_qualification_not_connected".to_owned()],
        descriptor_claimed_readiness: capsule.readiness.state.clone(),
        descriptor_blocker_codes: capsule.readiness.blocker_codes.clone(),
        execution_admission: "not_granted_by_runtime_capsule",
        host_os_matches: capsule.platform.os == std::env::consts::OS,
        host_arch_matches: capsule.platform.arch == std::env::consts::ARCH,
        tool_manifest_id: capsule.operation_scope.tool_manifest_id.clone(),
        operations: capsule.operation_scope.operations.clone(),
        verified_file_count: 1 + capsule.supporting_files.len() as u64,
        authority_effect: "none",
    })
}

pub fn planning_blocker(
    workspace: &Workspace,
    capsule_id: Option<&str>,
    tool_manifest_id: &str,
    operation: &str,
) -> Result<()> {
    let capsule_id = capsule_id.ok_or_else(|| {
        anyhow::anyhow!(
            "{tool_manifest_id} planning remains fail_closed: runtime_capsule_required; admit an exact-byte capsule and pass --runtime-capsule <capsule_id>"
        )
    })?;
    let record = load_verified(workspace, capsule_id)?;
    let capsule = &record.payload.capsule;
    if capsule.operation_scope.tool_manifest_id != tool_manifest_id
        || !capsule
            .operation_scope
            .operations
            .iter()
            .any(|candidate| candidate == operation)
    {
        bail!(
            "{tool_manifest_id} planning remains fail_closed: runtime_capsule_scope_mismatch; capsule {capsule_id} does not admit operation {operation}"
        );
    }
    if capsule.platform.os != std::env::consts::OS
        || capsule.platform.arch != std::env::consts::ARCH
    {
        bail!(
            "{tool_manifest_id} planning remains fail_closed: runtime_capsule_platform_mismatch; capsule {capsule_id} targets {}/{} but this host is {}/{}",
            capsule.platform.os,
            capsule.platform.arch,
            std::env::consts::OS,
            std::env::consts::ARCH
        );
    }
    bail!(
        "{tool_manifest_id} planning remains fail_closed: python_runtime_qualification_not_connected; capsule {capsule_id} record {} is an exact-byte inventory only, and descriptor-claimed readiness does not grant execution admission",
        record.record_digest
    )
}

/// Inventory a closed root into a `runtime-capsule/v1` descriptor.
///
/// This is a snapshot producer, not admission and not readiness. The
/// descriptor is always `fail_closed`: a complete file list does not
/// authorize planning or execution.
pub fn snapshot_descriptor(
    root: &Path,
    launcher: Option<&str>,
    tool_manifest_id: &str,
    operation: &str,
    abi: &str,
) -> Result<RuntimeCapsule> {
    let root = canonical_real_directory(root, "runtime capsule root")?;
    let files = collect_regular_files(&root)?;
    if files.is_empty() {
        bail!("runtime capsule root contains no regular files");
    }

    let launcher_path = resolve_launcher_path(&files, launcher)?;
    let launcher_source = files
        .get(&launcher_path)
        .expect("launcher path exists after resolution");
    let (launcher_digest, launcher_length) = workspace::digest_file(launcher_source)?;
    if launcher_length == 0 {
        bail!("capsule launcher must contain bytes");
    }

    let mut supporting_files = Vec::new();
    for (path, source) in &files {
        if path == &launcher_path {
            continue;
        }
        let (digest, byte_length) = workspace::digest_file(source)?;
        supporting_files.push(CapsuleSupportingFile {
            path: path.clone(),
            role: supporting_role(path),
            byte_length,
            digest: Digest {
                algorithm: "sha256".to_owned(),
                value: digest,
            },
        });
    }

    let has_stdlib = files.keys().any(|path| is_stdlib_marker(path));
    let has_first_party = files
        .keys()
        .any(|path| path.to_ascii_lowercase().contains("phaseledger"))
        || tool_manifest_id != "phaseledger";

    let mut missing_paths = Vec::new();
    let mut blocker_codes = vec![
        "python_capsule_execution_containment_unimplemented".to_owned(),
        "qualification_missing".to_owned(),
        "external_platform_assumption_unresolved".to_owned(),
    ];
    if !has_stdlib {
        missing_paths.push("Lib/encodings/__init__.py".to_owned());
        blocker_codes.push("python_stdlib_not_included".to_owned());
        blocker_codes.push("runtime_closure_incomplete".to_owned());
    }
    if !has_first_party {
        blocker_codes.push("python_first_party_package_missing".to_owned());
    }
    blocker_codes.sort();
    blocker_codes.dedup();

    let inventoried_file_count =
        u64::try_from(supporting_files.len()).context("supporting-file inventory is too large")?;
    let declared_file_count = inventoried_file_count + u64::try_from(missing_paths.len())?;
    let inventory_digest = workspace::digest_serialized(&supporting_files)?;
    let (closure_state, missing_paths) = if missing_paths.is_empty() {
        (CapsuleClosureState::Complete, Vec::new())
    } else {
        (CapsuleClosureState::Incomplete, missing_paths)
    };

    let mut identity = Sha256::new();
    for part in [
        "runtime-capsule-snapshot/v1",
        tool_manifest_id,
        operation,
        std::env::consts::OS,
        std::env::consts::ARCH,
        abi,
        &launcher_path,
        &launcher_digest,
        &inventory_digest,
    ] {
        identity.update(part.as_bytes());
        identity.update([0]);
    }
    let capsule_id = format!("capsule_{}", hex::encode(&identity.finalize()[..16]));

    let capsule = RuntimeCapsule {
        schema_version: "runtime-capsule/v1".to_owned(),
        capsule_id,
        platform: CapsulePlatform {
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            abi: abi.to_owned(),
        },
        launcher: CapsuleLauncher {
            kind: CapsuleLauncherKind::Interpreter,
            path: launcher_path,
            byte_length: launcher_length,
            digest: Digest {
                algorithm: "sha256".to_owned(),
                value: launcher_digest,
            },
        },
        supporting_files,
        transitive_closure: CapsuleTransitiveClosure {
            state: closure_state,
            inventory_digest: Digest {
                algorithm: "sha256".to_owned(),
                value: inventory_digest,
            },
            declared_file_count,
            inventoried_file_count,
            missing_paths,
        },
        external_platform_assumptions: vec![ExternalPlatformAssumption {
            code: "host_interpreter_copy".to_owned(),
            statement: "Files were copied from a host interpreter or a local tree. This is not a qualified embeddable distribution.".to_owned(),
            state: PlatformAssumptionState::Unresolved,
        }],
        operation_scope: CapsuleOperationScope {
            tool_manifest_id: tool_manifest_id.to_owned(),
            operations: vec![operation.to_owned()],
        },
        qualification_evidence: Vec::new(),
        readiness: CapsuleReadiness {
            state: CapsuleReadinessState::FailClosed,
            blocker_codes,
        },
        authority_effect: ContractAuthorityEffect::None,
    };
    data_contract_validation::validate_runtime_capsule(&capsule)?;
    Ok(capsule)
}

fn resolve_launcher_path(
    files: &BTreeMap<String, PathBuf>,
    requested: Option<&str>,
) -> Result<String> {
    if let Some(requested) = requested {
        if !files.contains_key(requested) {
            bail!("requested launcher {requested} is not in the runtime root");
        }
        return Ok(requested.to_owned());
    }
    for candidate in ["python.exe", "python"] {
        if files.contains_key(candidate) {
            return Ok(candidate.to_owned());
        }
    }
    bail!("runtime root has no python.exe or python launcher; pass --launcher");
}

fn supporting_role(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    if lower.contains("phaseledger") {
        "first_party_package".to_owned()
    } else if lower.ends_with(".dll") || lower.ends_with(".pyd") || lower.ends_with(".zip") {
        "interpreter_runtime".to_owned()
    } else if lower.starts_with("lib/") || lower.starts_with("dlls/") {
        "interpreter_stdlib".to_owned()
    } else {
        "supporting_file".to_owned()
    }
}

fn is_stdlib_marker(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower == "lib/encodings/__init__.py"
        || (lower.starts_with("python") && lower.ends_with(".zip") && !lower.contains('/'))
}

fn verify_record(workspace: &Workspace, record: &RuntimeCapsuleRecord) -> Result<()> {
    if record.schema_version != "runtime_capsule_record/v1"
        || record.capsule_id != record.payload.capsule.capsule_id
    {
        bail!("runtime capsule record identity mismatch");
    }
    workspace::validate_prefixed_id(&record.capsule_id, "capsule_")?;
    workspace::validate_sha256(&record.payload.descriptor_sha256)?;
    if workspace::digest_serialized(&record.payload)? != record.record_digest {
        bail!("runtime capsule record digest mismatch");
    }
    data_contract_validation::validate_runtime_capsule(&record.payload.capsule)?;
    validate_inventory_digest(&record.payload.capsule)?;

    let descriptor = verify_artifact_snapshot(
        workspace,
        &record.payload.descriptor_artifact_id,
        &record.payload.descriptor_sha256,
        None,
        "runtime_capsule_descriptor",
    )?;
    let parsed = data_contract_validation::parse_runtime_capsule(
        &workspace.read_verified_descriptor(&descriptor)?,
    )?;
    if parsed != record.payload.capsule {
        bail!("runtime capsule descriptor bytes do not match the registered capsule");
    }

    verify_declared_snapshot(
        workspace,
        &record.payload.launcher,
        &record.payload.capsule.launcher.path,
        &record.payload.capsule.launcher.digest.value,
        record.payload.capsule.launcher.byte_length,
        "runtime_capsule_launcher",
    )?;
    if record.payload.launcher.role != "launcher" {
        bail!("runtime capsule launcher snapshot role mismatch");
    }
    if record.payload.supporting_files.len() != record.payload.capsule.supporting_files.len() {
        bail!("runtime capsule supporting snapshot count mismatch");
    }
    for (snapshot, declared) in record
        .payload
        .supporting_files
        .iter()
        .zip(&record.payload.capsule.supporting_files)
    {
        if snapshot.role != declared.role {
            bail!("runtime capsule supporting snapshot role mismatch");
        }
        verify_declared_snapshot(
            workspace,
            snapshot,
            &declared.path,
            &declared.digest.value,
            declared.byte_length,
            "runtime_capsule_supporting_file",
        )?;
    }
    verify_qualification_evidence(workspace, &record.payload.capsule)
}

fn verify_declared_snapshot(
    workspace: &Workspace,
    snapshot: &RuntimeCapsuleFileSnapshot,
    expected_path: &str,
    expected_digest: &str,
    expected_length: u64,
    artifact_role: &str,
) -> Result<()> {
    if snapshot.path != expected_path
        || snapshot.digest.algorithm != "sha256"
        || snapshot.digest.value != expected_digest
        || snapshot.byte_length != expected_length
    {
        bail!("runtime capsule file snapshot does not match its declaration");
    }
    verify_artifact_snapshot(
        workspace,
        &snapshot.artifact_id,
        &snapshot.digest.value,
        Some(snapshot.byte_length),
        artifact_role,
    )?;
    Ok(())
}

fn verify_artifact_snapshot(
    workspace: &Workspace,
    artifact_id: &str,
    expected_digest: &str,
    expected_length: Option<u64>,
    expected_role: &str,
) -> Result<ArtifactDescriptor> {
    let record = workspace.load_artifact(artifact_id)?;
    let artifact = record.artifact;
    if artifact.digest.value != expected_digest
        || expected_length.is_some_and(|length| artifact.byte_length != length)
        || artifact.roles != [expected_role]
        || artifact.origin != "native_file"
        || artifact.capture.mode != "byte_for_byte_copy"
    {
        bail!("runtime capsule artifact snapshot identity mismatch");
    }
    Ok(artifact)
}

fn verify_qualification_evidence(workspace: &Workspace, capsule: &RuntimeCapsule) -> Result<()> {
    for evidence in &capsule.qualification_evidence {
        let record = workspace
            .load_artifact(&evidence.artifact_id)
            .with_context(|| {
                format!(
                    "qualification evidence {} is not present in this workspace",
                    evidence.artifact_id
                )
            })?;
        if record.artifact.digest != evidence.digest {
            bail!("runtime capsule qualification evidence digest mismatch");
        }
    }
    Ok(())
}

fn validate_inventory_digest(capsule: &RuntimeCapsule) -> Result<()> {
    if capsule
        .supporting_files
        .windows(2)
        .any(|pair| pair[0].path >= pair[1].path)
    {
        bail!("runtime capsule supporting files must be ordered by path");
    }
    let actual = workspace::digest_serialized(&capsule.supporting_files)?;
    if capsule.transitive_closure.inventory_digest.value != actual {
        bail!(
            "runtime capsule inventory digest mismatch; expected SHA-256 of the compact JSON supporting_files array in lexicographic path order"
        );
    }
    Ok(())
}

fn verify_source_tree(root: &Path, capsule: &RuntimeCapsule) -> Result<BTreeMap<String, PathBuf>> {
    let actual = collect_regular_files(root)?;
    let mut expected = BTreeSet::new();
    expected.insert(capsule.launcher.path.clone());
    for file in &capsule.supporting_files {
        expected.insert(file.path.clone());
    }
    let actual_names = actual.keys().cloned().collect::<BTreeSet<_>>();
    if actual_names != expected {
        let missing = expected
            .difference(&actual_names)
            .cloned()
            .collect::<Vec<_>>();
        let extra = actual_names
            .difference(&expected)
            .cloned()
            .collect::<Vec<_>>();
        bail!(
            "runtime capsule root does not exactly match its inventory; missing={missing:?}, extra={extra:?}"
        );
    }

    #[cfg(windows)]
    {
        let mut folded = BTreeSet::new();
        for path in &expected {
            if !folded.insert(path.to_ascii_lowercase()) {
                bail!("runtime capsule paths collide under Windows case folding");
            }
        }
    }

    verify_source_file(
        actual
            .get(&capsule.launcher.path)
            .expect("launcher exists after inventory comparison"),
        &capsule.launcher.digest.value,
        capsule.launcher.byte_length,
    )?;
    for file in &capsule.supporting_files {
        verify_source_file(
            actual
                .get(&file.path)
                .expect("supporting file exists after inventory comparison"),
            &file.digest.value,
            file.byte_length,
        )?;
    }
    Ok(actual)
}

fn verify_source_file(path: &Path, digest: &str, length: u64) -> Result<()> {
    let (actual_digest, actual_length) = workspace::digest_file(path)?;
    if actual_digest != digest || actual_length != length {
        bail!(
            "runtime capsule source bytes do not match the descriptor: {}",
            path.display()
        );
    }
    Ok(())
}

fn collect_regular_files(root: &Path) -> Result<BTreeMap<String, PathBuf>> {
    let mut files = BTreeMap::new();
    collect_directory(root, root, &mut files)?;
    Ok(files)
}

fn collect_directory(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if is_reparse(&metadata) {
            bail!("runtime capsule roots cannot contain links or reparse points");
        }
        if metadata.is_dir() {
            collect_directory(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .expect("walked path remains under capsule root");
            let name = portable_relative_path(relative)?;
            if files.insert(name, path).is_some() {
                bail!("duplicate runtime capsule path");
            }
        } else {
            bail!("runtime capsule roots may contain only regular files and directories");
        }
    }
    Ok(())
}

fn portable_relative_path(path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => parts.push(
                value
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("runtime capsule path is not UTF-8"))?,
            ),
            _ => bail!("runtime capsule path is not a portable relative path"),
        }
    }
    Ok(parts.join("/"))
}

fn canonical_regular_file(path: &Path, label: &str) -> Result<PathBuf> {
    let supplied_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {label} {}", path.display()))?;
    if !supplied_metadata.is_file() || is_reparse(&supplied_metadata) {
        bail!("{label} must be a regular non-link file");
    }
    let path = path
        .canonicalize()
        .with_context(|| format!("cannot resolve {label} {}", path.display()))?;
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || is_reparse(&metadata) {
        bail!("{label} must be a regular non-link file");
    }
    Ok(path)
}

fn canonical_real_directory(path: &Path, label: &str) -> Result<PathBuf> {
    let supplied_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {label} {}", path.display()))?;
    if !supplied_metadata.is_dir() || is_reparse(&supplied_metadata) {
        bail!("{label} must be a real directory, not a link or reparse point");
    }
    let path = path
        .canonicalize()
        .with_context(|| format!("cannot resolve {label} {}", path.display()))?;
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_dir() || is_reparse(&metadata) {
        bail!("{label} must be a real directory, not a link or reparse point");
    }
    Ok(path)
}

#[cfg(windows)]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::fs;
    use tempfile::TempDir;

    const CAPSULE_ID: &str = "capsule_11111111111111111111111111111111";

    struct Fixture {
        _temp: TempDir,
        workspace: Workspace,
        root: PathBuf,
        descriptor: PathBuf,
    }

    fn fixture(ready: bool) -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let workspace_root = temp.path().join("workspace");
        fs::create_dir(&workspace_root).unwrap();
        let workspace = Workspace::init(&workspace_root).unwrap();
        let root = temp.path().join("runtime");
        fs::create_dir_all(root.join("Lib")).unwrap();
        fs::write(root.join("python.exe"), b"launcher").unwrap();
        fs::write(root.join("Lib/phaseledger.py"), b"module").unwrap();
        let (launcher_digest, launcher_length) =
            workspace::digest_file(&root.join("python.exe")).unwrap();
        let (module_digest, module_length) =
            workspace::digest_file(&root.join("Lib/phaseledger.py")).unwrap();

        let qualification_evidence = if ready {
            let evidence_path = temp.path().join("qualification.json");
            fs::write(&evidence_path, br#"{"qualified":true}"#).unwrap();
            let artifact = workspace
                .import_artifact(
                    &evidence_path,
                    vec!["qualification_evidence".to_owned()],
                    "application/json".to_owned(),
                    "native_file",
                    "byte_for_byte_copy",
                )
                .unwrap();
            json!([{
                "kind": "qualification_run",
                "artifact_id": artifact.artifact_id,
                "digest": artifact.digest,
                "observed_at": "2026-08-14T00:00:00Z",
                "scope": "phaseledger strict measure fixture"
            }])
        } else {
            json!([])
        };
        let readiness = if ready {
            json!({"state":"ready","blocker_codes":[]})
        } else {
            json!({"state":"fail_closed","blocker_codes":["qualification_missing"]})
        };
        let mut value = json!({
            "schema_version": "runtime-capsule/v1",
            "capsule_id": CAPSULE_ID,
            "platform": {
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
                "abi": "cp313-test"
            },
            "launcher": {
                "kind": "interpreter",
                "path": "python.exe",
                "byte_length": launcher_length,
                "digest": {"algorithm":"sha256","value":launcher_digest}
            },
            "supporting_files": [{
                "path": "Lib/phaseledger.py",
                "role": "first_party_package",
                "byte_length": module_length,
                "digest": {"algorithm":"sha256","value":module_digest}
            }],
            "transitive_closure": {
                "state": "complete",
                "inventory_digest": {"algorithm":"sha256","value":"00".repeat(32)},
                "declared_file_count": 1,
                "inventoried_file_count": 1,
                "missing_paths": []
            },
            "external_platform_assumptions": [],
            "operation_scope": {
                "tool_manifest_id": "phaseledger",
                "operations": ["phaseledger_measure"]
            },
            "qualification_evidence": qualification_evidence,
            "readiness": readiness,
            "authority_effect": "none"
        });
        let parsed: RuntimeCapsule = serde_json::from_value(value.clone()).unwrap();
        value["transitive_closure"]["inventory_digest"]["value"] =
            Value::String(workspace::digest_serialized(&parsed.supporting_files).unwrap());
        let descriptor = temp.path().join("runtime-capsule.json");
        fs::write(&descriptor, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        Fixture {
            _temp: temp,
            workspace,
            root,
            descriptor,
        }
    }

    #[test]
    fn admits_and_reverifies_ewb_owned_exact_bytes() {
        let fixture = fixture(true);
        let record = admit(&fixture.workspace, &fixture.descriptor, &fixture.root).unwrap();

        assert_eq!(record.capsule_id, CAPSULE_ID);
        let verified = verify(&fixture.workspace, CAPSULE_ID).unwrap();
        assert_eq!(verified.verified_file_count, 2);
        assert_eq!(verified.readiness, CapsuleReadinessState::FailClosed);
        assert_eq!(
            verified.blocker_codes,
            ["python_runtime_qualification_not_connected"]
        );
        assert_eq!(
            verified.descriptor_claimed_readiness,
            CapsuleReadinessState::Ready
        );
        assert!(verified.descriptor_blocker_codes.is_empty());
        assert_eq!(
            verified.execution_admission,
            "not_granted_by_runtime_capsule"
        );
        assert_eq!(verified.authority_effect, "none");
        assert_eq!(list_verified(&fixture.workspace).unwrap().len(), 1);
    }

    #[test]
    fn rejects_uninventoried_runtime_files() {
        let fixture = fixture(false);
        fs::write(fixture.root.join("ambient.pth"), b"import ambient").unwrap();

        let error = admit(&fixture.workspace, &fixture.descriptor, &fixture.root).unwrap_err();

        assert!(format!("{error:#}").contains("does not exactly match its inventory"));
        assert!(
            fixture
                .workspace
                .list_runtime_capsules()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn rejects_source_hash_mismatch_before_registry_write() {
        let fixture = fixture(false);
        fs::write(fixture.root.join("Lib/phaseledger.py"), b"forged").unwrap();

        let error = admit(&fixture.workspace, &fixture.descriptor, &fixture.root).unwrap_err();

        assert!(format!("{error:#}").contains("source bytes do not match"));
        assert!(
            fixture
                .workspace
                .list_runtime_capsules()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn detects_object_and_registry_tampering() {
        let fixture = fixture(true);
        let record = admit(&fixture.workspace, &fixture.descriptor, &fixture.root).unwrap();
        let launcher_object = fixture
            .workspace
            .object_path(&record.payload.launcher.digest.value)
            .unwrap();
        fs::write(&launcher_object, b"tampered").unwrap();
        assert!(load_verified(&fixture.workspace, CAPSULE_ID).is_err());

        fs::write(&launcher_object, b"launcher").unwrap();
        let record_path = fixture
            .workspace
            .state
            .join("capsules")
            .join(format!("{CAPSULE_ID}.json"));
        let mut value: Value = serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
        value["payload"]["capsule"]["platform"]["abi"] = json!("forged-abi");
        fs::write(record_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        let error = load_verified(&fixture.workspace, CAPSULE_ID).unwrap_err();
        assert!(format!("{error:#}").contains("record digest mismatch"));
    }

    #[test]
    fn descriptor_ready_capsule_still_reaches_not_connected_blocker_without_planning() {
        let fixture = fixture(true);
        admit(&fixture.workspace, &fixture.descriptor, &fixture.root).unwrap();

        let error = planning_blocker(
            &fixture.workspace,
            Some(CAPSULE_ID),
            "phaseledger",
            "phaseledger_measure",
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("python_runtime_qualification_not_connected"));
        assert!(
            fixture
                .workspace
                .state
                .join("plans")
                .read_dir()
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn snapshot_is_fail_closed_and_admits_without_planning() {
        let temp = tempfile::tempdir().unwrap();
        let workspace_root = temp.path().join("workspace");
        fs::create_dir(&workspace_root).unwrap();
        let workspace = Workspace::init(&workspace_root).unwrap();
        let root = temp.path().join("runtime");
        fs::create_dir_all(root.join("Lib")).unwrap();
        fs::write(root.join("python.exe"), b"launcher").unwrap();
        fs::write(root.join("Lib/phaseledger.py"), b"module").unwrap();

        let capsule = snapshot_descriptor(
            &root,
            None,
            "phaseledger",
            "phaseledger_measure",
            "host-cpython",
        )
        .unwrap();

        assert_eq!(capsule.readiness.state, CapsuleReadinessState::FailClosed);
        assert!(
            capsule
                .readiness
                .blocker_codes
                .iter()
                .any(|code| code == "python_capsule_execution_containment_unimplemented")
        );
        assert!(
            capsule
                .readiness
                .blocker_codes
                .iter()
                .any(|code| code == "python_stdlib_not_included")
        );
        assert_eq!(capsule.authority_effect, ContractAuthorityEffect::None);
        assert_eq!(
            capsule.transitive_closure.state,
            CapsuleClosureState::Incomplete
        );

        let descriptor = temp.path().join("runtime-capsule.json");
        fs::write(&descriptor, serde_json::to_vec_pretty(&capsule).unwrap()).unwrap();
        let record = admit(&workspace, &descriptor, &root).unwrap();
        let error = planning_blocker(
            &workspace,
            Some(&record.capsule_id),
            "phaseledger",
            "phaseledger_measure",
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("python_runtime_qualification_not_connected"));
    }

    #[test]
    fn snapshot_marks_stdlib_complete_when_encodings_is_present() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("runtime");
        fs::create_dir_all(root.join("Lib/encodings")).unwrap();
        fs::write(root.join("python.exe"), b"launcher").unwrap();
        fs::write(root.join("Lib/encodings/__init__.py"), b"enc").unwrap();
        fs::write(root.join("Lib/phaseledger.py"), b"module").unwrap();

        let capsule = snapshot_descriptor(
            &root,
            None,
            "phaseledger",
            "phaseledger_measure",
            "host-cpython",
        )
        .unwrap();

        assert_eq!(
            capsule.transitive_closure.state,
            CapsuleClosureState::Complete
        );
        assert!(
            !capsule
                .readiness
                .blocker_codes
                .iter()
                .any(|code| code == "python_stdlib_not_included")
        );
        assert_eq!(capsule.readiness.state, CapsuleReadinessState::FailClosed);
    }
}
