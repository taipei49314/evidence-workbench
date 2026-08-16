use crate::contracts::{
    CapsuleLauncherKind, ContractAuthorityEffect, Digest, ExactArtifactBinding,
    ExactCapsuleFileBinding, PythonCapsuleRef, PythonEnvironmentContract,
    PythonEnvironmentVariable, PythonHostPlatform, PythonLaunchContract, PythonPlatformObservation,
    PythonPrivateLayout, PythonQualificationCheck, PythonQualificationCheckState,
    PythonQualificationState, PythonQualificationStateValue, PythonRuntimeInputs,
    PythonRuntimeQualification, PythonRuntimeQualificationRecord, PythonTargetPlatform,
    PythonWheelRecordBinding, PythonWrapperBinding, RuntimeCapsuleRecord, ToolRef, UpstreamPinRef,
};
use crate::upstream_pins::{
    self, AuthorityEffect, ReadinessState, RuntimeKind, TargetArch, TargetOs,
};
use crate::{manifests, native, runtime_capsules, workspace};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use uuid::Uuid;

pub const WRAPPER_CONTRACT_ID: &str = "evidence-workbench-python-runtime-wrapper/v1";
pub const WRAPPER_SHA256: &str = "0bb5b8795ad0c97eb8ec94f898d7215eabe19891a70740bccee3d834a98deb9b";
pub const WRAPPER_BYTES: &[u8] = include_bytes!("../assets/python-runtime-wrapper-v1.py");

pub const CHECK_CODES: &[&str] = &[
    "cpython_archive_semantics",
    "os_network_egress_denial",
    "python_active_process_limit_one",
    "python_creation_time_job_assignment",
    "python_launch_harness",
    "python_path_configuration_isolation",
    "python_private_materialization",
    "wheel_record_closure",
];

const FIXED_ARGUMENTS: &[&str] = &["-I", "-S", "-B", "-X", "utf8"];

#[derive(Debug, Serialize)]
pub struct PythonQualificationVerification {
    pub qualification_id: String,
    pub record_digest: String,
    pub capsule_id: String,
    pub tool_manifest_id: String,
    pub operation: String,
    pub qualification_state: &'static str,
    pub blocker_codes: Vec<String>,
    pub execution_admission: &'static str,
    pub authority_effect: &'static str,
}

pub fn create(
    workspace: &workspace::Workspace,
    capsule_id: &str,
    cpython_archive_artifact_id: &str,
    path_configuration: &str,
    wheel_artifact_ids: &[String],
    installed_record_paths: &[String],
) -> Result<PythonRuntimeQualificationRecord> {
    if std::env::consts::OS != "windows" || std::env::consts::ARCH != "x86_64" {
        bail!("Python runtime qualification creation requires a Windows x86_64 host");
    }
    validate_embedded_wrapper_contract()?;
    if wheel_artifact_ids.is_empty() || wheel_artifact_ids.len() != installed_record_paths.len() {
        bail!(
            "Python runtime qualification requires equal non-empty --wheel-artifact and --installed-record-path sets"
        );
    }

    let capsule_record = runtime_capsules::load_verified(workspace, capsule_id)?;
    let capsule = &capsule_record.payload.capsule;
    if capsule.operation_scope.operations.len() != 1 {
        bail!("Python runtime qualification requires a capsule scoped to exactly one operation");
    }
    if capsule.platform.os != "windows" || capsule.platform.arch != "x86_64" {
        bail!("Python runtime qualification requires an exact Windows x86_64 capsule target");
    }
    if capsule.launcher.kind != CapsuleLauncherKind::Interpreter {
        bail!("Python runtime qualification requires an interpreter capsule launcher");
    }

    let tool_manifest_id = &capsule.operation_scope.tool_manifest_id;
    let operation = &capsule.operation_scope.operations[0];
    let manifest = manifests::get(tool_manifest_id)?;
    if manifest
        .manifest
        .identity_contract
        .python_distribution
        .is_none()
        || manifest.manifest.invocation_contract.operation != *operation
    {
        bail!("runtime capsule scope does not match one exact embedded Python operation");
    }
    let pin = upstream_pins::get_for_tool(tool_manifest_id)?;
    validate_fail_closed_python_pin(&pin)?;

    // Resolve and re-hash every caller-selected reference before creating the
    // fixed wrapper artifact or any qualification registry record.
    let cpython_archive = exact_artifact_binding(workspace, cpython_archive_artifact_id)?;
    if cpython_archive.byte_length == 0 {
        bail!("CPython archive artifact must contain bytes");
    }
    let path_configuration = exact_capsule_file_binding(
        workspace,
        &capsule_record,
        path_configuration,
        "Python path configuration",
    )?;
    validate_path_configuration_path(&path_configuration.path)?;
    if path_configuration.artifact.byte_length == 0 {
        bail!("Python path configuration snapshot must contain bytes");
    }

    let mut wheel_records = Vec::with_capacity(wheel_artifact_ids.len());
    let mut wheel_ids = BTreeSet::new();
    let mut record_paths = BTreeSet::new();
    let mut folded_paths = BTreeSet::new();
    folded_paths.insert(path_configuration.path.to_ascii_lowercase());
    for (wheel_id, installed_path) in wheel_artifact_ids.iter().zip(installed_record_paths) {
        if !wheel_ids.insert(wheel_id.as_str()) {
            bail!("wheel artifact ids must be unique");
        }
        validate_installed_record_path(installed_path)?;
        if !record_paths.insert(installed_path.as_str())
            || !folded_paths.insert(installed_path.to_ascii_lowercase())
        {
            bail!("installed RECORD paths must be unique without Windows case collisions");
        }
        let wheel = exact_artifact_binding(workspace, wheel_id)?;
        if wheel.byte_length == 0 {
            bail!("wheel artifacts must contain bytes");
        }
        let installed_record = exact_capsule_file_binding(
            workspace,
            &capsule_record,
            installed_path,
            "installed wheel RECORD",
        )?;
        if installed_record.artifact.byte_length == 0 {
            bail!("installed RECORD snapshots must contain bytes");
        }
        wheel_records.push(PythonWheelRecordBinding {
            wheel,
            installed_record,
        });
    }
    wheel_records.sort_by(|left, right| {
        (
            left.wheel.digest.value.as_str(),
            left.installed_record.path.as_str(),
        )
            .cmp(&(
                right.wheel.digest.value.as_str(),
                right.installed_record.path.as_str(),
            ))
    });
    validate_creation_input_uniqueness(&cpython_archive, &path_configuration, &wheel_records)?;
    let recorder_identity = native::recorder_identity()?;

    let qualification_id = format!("qualification_{}", Uuid::new_v4().simple());
    let destination = workspace
        .state
        .join("python-qualifications")
        .join(format!("{qualification_id}.json"));
    if destination.exists() {
        bail!("Python runtime qualification id already exists");
    }

    let wrapper_descriptor = workspace.import_artifact_bytes(
        WRAPPER_BYTES,
        vec!["python_runtime_qualification_wrapper".to_owned()],
        "text/x-python".to_owned(),
        "native_file",
        "byte_for_byte_copy",
    )?;
    let wrapper = PythonWrapperBinding {
        contract_id: WRAPPER_CONTRACT_ID.to_owned(),
        artifact: exact_artifact_binding(workspace, &wrapper_descriptor.artifact_id)?,
    };

    let payload = PythonRuntimeQualification {
        schema_version: "python_runtime_qualification/v1".to_owned(),
        observed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        capsule_ref: PythonCapsuleRef {
            id: capsule_record.capsule_id.clone(),
            record_digest: capsule_record.record_digest.clone(),
        },
        tool_ref: ToolRef {
            manifest_id: manifest.manifest.manifest_id.clone(),
            manifest_sha256: manifest.sha256,
        },
        upstream_pin_ref: UpstreamPinRef {
            tool_manifest_id: pin.pin.tool_manifest_id.clone(),
            pin_sha256: pin.sha256,
        },
        operation: operation.clone(),
        recorder_identity,
        platform_observation: PythonPlatformObservation {
            target: PythonTargetPlatform {
                os: capsule.platform.os.clone(),
                arch: capsule.platform.arch.clone(),
                abi: capsule.platform.abi.clone(),
            },
            host: PythonHostPlatform {
                os: std::env::consts::OS.to_owned(),
                arch: std::env::consts::ARCH.to_owned(),
            },
        },
        runtime_inputs: PythonRuntimeInputs {
            cpython_archive,
            path_configuration,
            wheel_records,
            wrapper,
        },
        launch_contract: fixed_launch_contract(),
        checks: fixed_incomplete_checks(),
        qualification_state: PythonQualificationState {
            state: PythonQualificationStateValue::Incomplete,
            blocker_codes: CHECK_CODES.iter().map(|code| (*code).to_owned()).collect(),
        },
        authority_effect: ContractAuthorityEffect::None,
    };
    validate_payload(&payload)?;
    validate_references(workspace, &payload)?;

    let record = PythonRuntimeQualificationRecord {
        schema_version: "python_runtime_qualification_record/v1".to_owned(),
        qualification_id: qualification_id.clone(),
        record_digest: workspace::digest_serialized(&payload)?,
        payload,
    };
    verify_record(workspace, &record)?;
    workspace.write_python_runtime_qualification(&record)?;
    load_verified(workspace, &qualification_id)
}

pub fn load_verified(
    workspace: &workspace::Workspace,
    qualification_id: &str,
) -> Result<PythonRuntimeQualificationRecord> {
    let record = workspace.load_python_runtime_qualification(qualification_id)?;
    verify_record(workspace, &record)?;
    Ok(record)
}

pub fn list_verified(
    workspace: &workspace::Workspace,
) -> Result<Vec<PythonRuntimeQualificationRecord>> {
    let records = workspace.list_python_runtime_qualifications()?;
    for record in &records {
        verify_record(workspace, record)?;
    }
    Ok(records)
}

pub fn verify(
    workspace: &workspace::Workspace,
    qualification_id: &str,
) -> Result<PythonQualificationVerification> {
    let record = load_verified(workspace, qualification_id)?;
    Ok(PythonQualificationVerification {
        qualification_id: record.qualification_id,
        record_digest: record.record_digest,
        capsule_id: record.payload.capsule_ref.id,
        tool_manifest_id: record.payload.tool_ref.manifest_id,
        operation: record.payload.operation,
        qualification_state: "incomplete",
        blocker_codes: record.payload.qualification_state.blocker_codes,
        execution_admission: "not_granted_by_incomplete_python_runtime_qualification",
        authority_effect: "none",
    })
}

pub fn validate_payload(payload: &PythonRuntimeQualification) -> Result<()> {
    if payload.schema_version != "python_runtime_qualification/v1" {
        bail!("unsupported Python runtime qualification schema");
    }
    DateTime::parse_from_rfc3339(&payload.observed_at)
        .context("Python runtime qualification observed_at is not RFC 3339")?;
    workspace::validate_prefixed_id(&payload.capsule_ref.id, "capsule_")?;
    workspace::validate_sha256(&payload.capsule_ref.record_digest)?;
    manifests::validate_id(&payload.tool_ref.manifest_id)?;
    workspace::validate_sha256(&payload.tool_ref.manifest_sha256)?;
    if payload.upstream_pin_ref.tool_manifest_id != payload.tool_ref.manifest_id {
        bail!("Python runtime qualification tool and upstream pin refs diverge");
    }
    workspace::validate_sha256(&payload.upstream_pin_ref.pin_sha256)?;
    validate_identifier(&payload.operation, "operation")?;
    if payload.recorder_identity.version.is_empty()
        || payload.recorder_identity.version.trim() != payload.recorder_identity.version
    {
        bail!("Python runtime qualification recorder version is invalid");
    }
    workspace::validate_sha256(&payload.recorder_identity.executable_sha256)?;
    if payload.platform_observation.target.os != "windows"
        || payload.platform_observation.target.arch != "x86_64"
        || payload.platform_observation.host.os != "windows"
        || payload.platform_observation.host.arch != "x86_64"
    {
        bail!("Python runtime qualification platform observation must be Windows x86_64");
    }
    validate_platform_component(&payload.platform_observation.target.abi, "target ABI")?;

    validate_exact_artifact_binding(&payload.runtime_inputs.cpython_archive, "CPython archive")?;
    if payload.runtime_inputs.cpython_archive.byte_length == 0 {
        bail!("CPython archive artifact must contain bytes");
    }
    validate_exact_capsule_file_binding(
        &payload.runtime_inputs.path_configuration,
        "Python path configuration",
    )?;
    validate_path_configuration_path(&payload.runtime_inputs.path_configuration.path)?;
    if payload.runtime_inputs.wheel_records.is_empty() {
        bail!("Python runtime qualification must bind at least one wheel and RECORD");
    }

    let mut artifact_ids = BTreeSet::new();
    artifact_ids.insert(
        payload
            .runtime_inputs
            .cpython_archive
            .artifact_ref
            .artifact_id
            .as_str(),
    );
    if !artifact_ids.insert(
        payload
            .runtime_inputs
            .path_configuration
            .artifact
            .artifact_ref
            .artifact_id
            .as_str(),
    ) {
        bail!("Python runtime qualification artifact ids must be unique");
    }
    let mut record_paths = BTreeSet::new();
    let mut folded_paths = BTreeSet::new();
    folded_paths.insert(
        payload
            .runtime_inputs
            .path_configuration
            .path
            .to_ascii_lowercase(),
    );
    let mut previous_key: Option<(&str, &str)> = None;
    for wheel_record in &payload.runtime_inputs.wheel_records {
        validate_exact_artifact_binding(&wheel_record.wheel, "wheel")?;
        validate_exact_capsule_file_binding(&wheel_record.installed_record, "installed RECORD")?;
        validate_installed_record_path(&wheel_record.installed_record.path)?;
        if wheel_record.wheel.byte_length == 0
            || wheel_record.installed_record.artifact.byte_length == 0
        {
            bail!("wheel and installed RECORD bindings must contain bytes");
        }
        if !artifact_ids.insert(wheel_record.wheel.artifact_ref.artifact_id.as_str())
            || !artifact_ids.insert(
                wheel_record
                    .installed_record
                    .artifact
                    .artifact_ref
                    .artifact_id
                    .as_str(),
            )
        {
            bail!("Python runtime qualification artifact ids must be unique");
        }
        if !record_paths.insert(wheel_record.installed_record.path.as_str())
            || !folded_paths.insert(wheel_record.installed_record.path.to_ascii_lowercase())
        {
            bail!("installed RECORD paths must be unique without Windows case collisions");
        }
        let key = (
            wheel_record.wheel.digest.value.as_str(),
            wheel_record.installed_record.path.as_str(),
        );
        if previous_key.is_some_and(|previous| previous >= key) {
            bail!("wheel records must be in canonical digest/path order");
        }
        previous_key = Some(key);
    }
    if payload.runtime_inputs.wrapper.contract_id != WRAPPER_CONTRACT_ID {
        bail!("Python runtime wrapper contract id is not exact");
    }
    validate_embedded_wrapper_contract()?;
    validate_exact_artifact_binding(&payload.runtime_inputs.wrapper.artifact, "wrapper")?;
    if payload.runtime_inputs.wrapper.artifact.digest.value != WRAPPER_SHA256
        || payload.runtime_inputs.wrapper.artifact.byte_length != WRAPPER_BYTES.len() as u64
        || !artifact_ids.insert(
            payload
                .runtime_inputs
                .wrapper
                .artifact
                .artifact_ref
                .artifact_id
                .as_str(),
        )
    {
        bail!(
            "Python runtime wrapper binding must match the fixed bytes and be uniquely identified"
        );
    }

    if payload.launch_contract != fixed_launch_contract() {
        bail!("Python runtime qualification launch contract drifted from the fixed v1 contract");
    }
    let expected_codes = CHECK_CODES
        .iter()
        .map(|code| (*code).to_owned())
        .collect::<Vec<_>>();
    if payload.checks.len() != CHECK_CODES.len()
        || payload
            .checks
            .iter()
            .zip(CHECK_CODES)
            .any(|(check, expected)| {
                check.code != *expected
                    || check.state != PythonQualificationCheckState::NotImplemented
                    || !check.evidence_refs.is_empty()
            })
    {
        bail!("Python runtime qualification checks must be the fixed unimplemented v1 set");
    }
    if payload.qualification_state.state != PythonQualificationStateValue::Incomplete
        || payload.qualification_state.blocker_codes != expected_codes
    {
        bail!("Python runtime qualification v1 must remain incomplete with every check blocked");
    }
    if payload.authority_effect != ContractAuthorityEffect::None {
        bail!("Python runtime qualification cannot change authority");
    }
    Ok(())
}

fn verify_record(
    workspace: &workspace::Workspace,
    record: &PythonRuntimeQualificationRecord,
) -> Result<()> {
    workspace::validate_prefixed_id(&record.qualification_id, "qualification_")?;
    if record.schema_version != "python_runtime_qualification_record/v1"
        || record.record_digest != workspace::digest_serialized(&record.payload)?
    {
        bail!("Python runtime qualification record identity or typed payload digest mismatch");
    }
    validate_payload(&record.payload)?;
    validate_references(workspace, &record.payload)
}

fn validate_references(
    workspace: &workspace::Workspace,
    payload: &PythonRuntimeQualification,
) -> Result<()> {
    let capsule_record = runtime_capsules::load_verified(workspace, &payload.capsule_ref.id)?;
    if payload.capsule_ref.record_digest != capsule_record.record_digest {
        bail!("Python runtime qualification capsule record reference changed");
    }
    let capsule = &capsule_record.payload.capsule;
    if capsule.operation_scope.operations.len() != 1
        || capsule.operation_scope.tool_manifest_id != payload.tool_ref.manifest_id
        || capsule.operation_scope.operations[0] != payload.operation
        || capsule.platform.os != payload.platform_observation.target.os
        || capsule.platform.arch != payload.platform_observation.target.arch
        || capsule.platform.abi != payload.platform_observation.target.abi
        || capsule.launcher.kind != CapsuleLauncherKind::Interpreter
    {
        bail!("Python runtime qualification capsule scope or target binding changed");
    }

    let manifest = manifests::get_by_ref(&payload.tool_ref)?;
    if manifest
        .manifest
        .identity_contract
        .python_distribution
        .is_none()
        || manifest.manifest.invocation_contract.operation != payload.operation
    {
        bail!("Python runtime qualification no longer matches an exact Python manifest operation");
    }
    let pin = upstream_pins::get_for_tool(&payload.upstream_pin_ref.tool_manifest_id)?;
    if pin.sha256 != payload.upstream_pin_ref.pin_sha256 {
        bail!("Python runtime qualification upstream pin reference changed");
    }
    validate_fail_closed_python_pin(&pin)?;

    if payload.platform_observation.host.os != std::env::consts::OS
        || payload.platform_observation.host.arch != std::env::consts::ARCH
    {
        bail!("Python runtime qualification host observation does not match this verifier host");
    }
    let current_recorder = native::recorder_identity()?;
    if current_recorder != payload.recorder_identity {
        bail!("Python runtime qualification recorder identity changed");
    }

    verify_exact_artifact_binding(
        workspace,
        &payload.runtime_inputs.cpython_archive,
        "CPython archive",
    )?;
    verify_exact_capsule_file_binding(
        workspace,
        &capsule_record,
        &payload.runtime_inputs.path_configuration,
        "Python path configuration",
    )?;
    for wheel_record in &payload.runtime_inputs.wheel_records {
        verify_exact_artifact_binding(workspace, &wheel_record.wheel, "wheel")?;
        verify_exact_capsule_file_binding(
            workspace,
            &capsule_record,
            &wheel_record.installed_record,
            "installed RECORD",
        )?;
    }
    verify_wrapper_binding(workspace, &payload.runtime_inputs.wrapper)
}

fn validate_fail_closed_python_pin(pin: &upstream_pins::TrustedUpstreamPin) -> Result<()> {
    if pin.pin.runtime.kind != RuntimeKind::Python
        || !matches!(pin.pin.runtime.target_os, TargetOs::Any | TargetOs::Windows)
        || !matches!(
            pin.pin.runtime.target_arch,
            TargetArch::Any | TargetArch::X86_64
        )
        || pin.pin.execution_readiness.state != ReadinessState::FailClosed
        || pin.pin.admission.authority_effect != AuthorityEffect::None
    {
        bail!("Python runtime qualification requires the exact fail-closed Python upstream pin");
    }
    Ok(())
}

fn exact_artifact_binding(
    workspace: &workspace::Workspace,
    artifact_id: &str,
) -> Result<ExactArtifactBinding> {
    let record = workspace.load_artifact(artifact_id)?;
    Ok(ExactArtifactBinding {
        artifact_ref: crate::contracts::ArtifactRecordRef {
            artifact_id: record.artifact.artifact_id,
            record_digest: record.record_digest,
        },
        digest: record.artifact.digest,
        byte_length: record.artifact.byte_length,
    })
}

fn exact_capsule_file_binding(
    workspace: &workspace::Workspace,
    capsule: &RuntimeCapsuleRecord,
    path: &str,
    label: &str,
) -> Result<ExactCapsuleFileBinding> {
    validate_qualification_path(path, label)?;
    let matches = capsule
        .payload
        .supporting_files
        .iter()
        .filter(|snapshot| snapshot.path == path)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!("{label} must name exactly one supporting-file snapshot in the capsule");
    }
    let snapshot = matches[0];
    let artifact = exact_artifact_binding(workspace, &snapshot.artifact_id)?;
    if artifact.digest != snapshot.digest || artifact.byte_length != snapshot.byte_length {
        bail!("{label} capsule snapshot and exact artifact binding diverge");
    }
    Ok(ExactCapsuleFileBinding {
        path: path.to_owned(),
        artifact,
    })
}

fn verify_exact_artifact_binding(
    workspace: &workspace::Workspace,
    binding: &ExactArtifactBinding,
    label: &str,
) -> Result<()> {
    let actual = exact_artifact_binding(workspace, &binding.artifact_ref.artifact_id)
        .with_context(|| format!("cannot re-verify {label} artifact"))?;
    if actual != *binding {
        bail!("{label} exact artifact binding changed");
    }
    Ok(())
}

fn verify_exact_capsule_file_binding(
    workspace: &workspace::Workspace,
    capsule: &RuntimeCapsuleRecord,
    binding: &ExactCapsuleFileBinding,
    label: &str,
) -> Result<()> {
    let actual = exact_capsule_file_binding(workspace, capsule, &binding.path, label)?;
    if actual != *binding {
        bail!("{label} exact capsule-file binding changed");
    }
    Ok(())
}

fn verify_wrapper_binding(
    workspace: &workspace::Workspace,
    wrapper: &PythonWrapperBinding,
) -> Result<()> {
    validate_embedded_wrapper_contract()?;
    if wrapper.contract_id != WRAPPER_CONTRACT_ID {
        bail!("Python runtime wrapper contract id changed");
    }
    verify_exact_artifact_binding(workspace, &wrapper.artifact, "Python runtime wrapper")?;
    let record = workspace.load_artifact(&wrapper.artifact.artifact_ref.artifact_id)?;
    if record.artifact.roles != ["python_runtime_qualification_wrapper"]
        || record.artifact.media_type != "text/x-python"
        || record.artifact.origin != "native_file"
        || record.artifact.capture.mode != "byte_for_byte_copy"
        || !record.artifact.transforms.is_empty()
        || workspace.read_verified_descriptor(&record.artifact)? != WRAPPER_BYTES
    {
        bail!("Python runtime wrapper artifact does not match its exact embedded contract");
    }
    Ok(())
}

fn validate_embedded_wrapper_contract() -> Result<()> {
    let actual = hex::encode(Sha256::digest(WRAPPER_BYTES));
    if actual != WRAPPER_SHA256 {
        bail!("embedded Python runtime wrapper bytes changed without a new wrapper contract id");
    }
    Ok(())
}

fn validate_creation_input_uniqueness(
    cpython_archive: &ExactArtifactBinding,
    path_configuration: &ExactCapsuleFileBinding,
    wheel_records: &[PythonWheelRecordBinding],
) -> Result<()> {
    let mut artifact_ids = BTreeSet::new();
    artifact_ids.insert(cpython_archive.artifact_ref.artifact_id.as_str());
    if !artifact_ids.insert(
        path_configuration
            .artifact
            .artifact_ref
            .artifact_id
            .as_str(),
    ) {
        bail!("Python runtime qualification input artifact ids must be unique");
    }
    for wheel_record in wheel_records {
        if !artifact_ids.insert(wheel_record.wheel.artifact_ref.artifact_id.as_str())
            || !artifact_ids.insert(
                wheel_record
                    .installed_record
                    .artifact
                    .artifact_ref
                    .artifact_id
                    .as_str(),
            )
        {
            bail!("Python runtime qualification input artifact ids must be unique");
        }
    }
    Ok(())
}

fn validate_exact_artifact_binding(binding: &ExactArtifactBinding, label: &str) -> Result<()> {
    workspace::validate_prefixed_id(&binding.artifact_ref.artifact_id, "artifact_")?;
    workspace::validate_sha256(&binding.artifact_ref.record_digest)?;
    validate_digest(&binding.digest, label)?;
    if binding.byte_length == 0 {
        bail!("{label} binding must contain bytes");
    }
    Ok(())
}

fn validate_exact_capsule_file_binding(
    binding: &ExactCapsuleFileBinding,
    label: &str,
) -> Result<()> {
    validate_qualification_path(&binding.path, label)?;
    validate_exact_artifact_binding(&binding.artifact, label)
}

fn validate_digest(digest: &Digest, label: &str) -> Result<()> {
    if digest.algorithm != "sha256" {
        bail!("{label} digest must use SHA-256");
    }
    workspace::validate_sha256(&digest.value)
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
        && !value.starts_with(['_', '-'])
        && !value.ends_with(['_', '-']);
    if !valid {
        bail!("invalid Python qualification {label}");
    }
    Ok(())
}

fn validate_platform_component(value: &str, label: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
        && value.trim_matches(['_', '-', '.']) == value;
    if !valid {
        bail!("invalid Python qualification {label}");
    }
    Ok(())
}

fn validate_qualification_path(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
        || value.contains('\\')
        || value.contains(':')
        || value.starts_with('/')
        || value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        bail!("{label} must be a printable ASCII normalized relative capsule path");
    }
    Ok(())
}

fn validate_path_configuration_path(path: &str) -> Result<()> {
    validate_qualification_path(path, "Python path configuration")?;
    let filename = path
        .rsplit('/')
        .next()
        .expect("validated path has a filename");
    let lowercase = filename.to_ascii_lowercase();
    if !lowercase.starts_with("python") || !lowercase.ends_with("._pth") {
        bail!("Python path configuration must be a python*._pth capsule snapshot");
    }
    Ok(())
}

fn validate_installed_record_path(path: &str) -> Result<()> {
    validate_qualification_path(path, "installed RECORD")?;
    let parent = path
        .strip_suffix("/RECORD")
        .context("installed RECORD path must end in .dist-info/RECORD")?;
    let dist_info = parent
        .rsplit('/')
        .next()
        .expect("validated RECORD parent is non-empty");
    if !dist_info.ends_with(".dist-info") || dist_info == ".dist-info" {
        bail!("installed RECORD path must end in .dist-info/RECORD");
    }
    Ok(())
}

pub fn fixed_launch_contract() -> PythonLaunchContract {
    PythonLaunchContract {
        mode: "direct_exec".to_owned(),
        launcher_source: "capsule_launcher".to_owned(),
        fixed_arguments: FIXED_ARGUMENTS
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect(),
        wrapper_source: "qualified_wrapper".to_owned(),
        argument_tail: "trusted_adapter_derived_only".to_owned(),
        cwd: "ewb_owned_private_scratch".to_owned(),
        environment: PythonEnvironmentContract {
            inheritance: "none".to_owned(),
            variables: vec![
                PythonEnvironmentVariable {
                    name: "PATH".to_owned(),
                    source: "ewb_owned_empty_directory".to_owned(),
                },
                PythonEnvironmentVariable {
                    name: "SystemRoot".to_owned(),
                    source: "canonical_host_system_root".to_owned(),
                },
                PythonEnvironmentVariable {
                    name: "TEMP".to_owned(),
                    source: "ewb_owned_private_scratch".to_owned(),
                },
                PythonEnvironmentVariable {
                    name: "TMP".to_owned(),
                    source: "ewb_owned_private_scratch".to_owned(),
                },
                PythonEnvironmentVariable {
                    name: "WINDIR".to_owned(),
                    source: "canonical_host_windows_directory".to_owned(),
                },
            ],
            other_variables: "absent".to_owned(),
        },
        layout: PythonPrivateLayout {
            runtime: "runtime".to_owned(),
            subject: "subject".to_owned(),
            scratch: "scratch".to_owned(),
            wrapper: "wrapper/python-runtime-wrapper-v1.py".to_owned(),
        },
    }
}

fn fixed_incomplete_checks() -> Vec<PythonQualificationCheck> {
    CHECK_CODES
        .iter()
        .map(|code| PythonQualificationCheck {
            code: (*code).to_owned(),
            state: PythonQualificationCheckState::NotImplemented,
            evidence_refs: Vec::new(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_contract_validation::{
        parse_python_runtime_qualification, parse_python_runtime_qualification_record,
    };
    use serde_json::{Value, json};

    const QUALIFICATION_EXAMPLE: &[u8] =
        include_bytes!("../contracts/examples/python-runtime-qualification-v1.example.json");
    const RECORD_EXAMPLE: &[u8] =
        include_bytes!("../contracts/examples/python-runtime-qualification-record-v1.example.json");

    fn example() -> PythonRuntimeQualification {
        parse_python_runtime_qualification(QUALIFICATION_EXAMPLE).unwrap()
    }

    fn second_wheel(
        source: &PythonWheelRecordBinding,
        wheel_id: &str,
        record_id: &str,
        path: &str,
        digest: &str,
    ) -> PythonWheelRecordBinding {
        let mut value = source.clone();
        value.wheel.artifact_ref.artifact_id = wheel_id.to_owned();
        value.wheel.digest.value = digest.to_owned();
        value.installed_record.artifact.artifact_ref.artifact_id = record_id.to_owned();
        value.installed_record.path = path.to_owned();
        value
    }

    #[test]
    fn v1_has_no_success_state_or_requirements_met_escape_hatch() {
        let payload = example();
        let value = serde_json::to_value(&payload).unwrap();
        let rendered = serde_json::to_string(&value).unwrap();
        assert!(!rendered.contains("verified"));
        assert!(!rendered.contains("requirements_met"));
        assert!(!rendered.contains("\"state\":\"failed\""));
        assert!(rendered.contains("\"state\":\"not_implemented\""));
        assert!(rendered.contains("\"state\":\"incomplete\""));

        let mut forged = value.clone();
        forged["checks"][0]["state"] = json!("verified");
        assert!(serde_json::from_value::<PythonRuntimeQualification>(forged).is_err());

        let mut forged = value;
        forged["qualification_state"]["state"] = json!("ready");
        assert!(serde_json::from_value::<PythonRuntimeQualification>(forged).is_err());

        let mut forged: Value = serde_json::from_slice(QUALIFICATION_EXAMPLE).unwrap();
        forged["qualification_state"]["requirements_met"] = json!(false);
        assert!(serde_json::from_value::<PythonRuntimeQualification>(forged).is_err());
    }

    #[test]
    fn qualification_paths_reject_absolute_parent_separator_colon_control_and_unicode() {
        for malicious in [
            "/python313._pth",
            "../python313._pth",
            "runtime/../python313._pth",
            "runtime\\python313._pth",
            "C:/python313._pth",
            "runtime//python313._pth",
            "runtime/./python313._pth",
            "python\u{1}313._pth",
            "pythön313._pth",
        ] {
            let mut payload = example();
            payload.runtime_inputs.path_configuration.path = malicious.to_owned();
            assert!(
                validate_payload(&payload).is_err(),
                "accepted malicious path {malicious:?}"
            );
        }

        for malicious in [
            "/pkg.dist-info/RECORD",
            "../pkg.dist-info/RECORD",
            "site/../pkg.dist-info/RECORD",
            "site\\pkg.dist-info\\RECORD",
            "C:/pkg.dist-info/RECORD",
            "site/pkg.dist-info/record",
            "site/RECORD",
        ] {
            let mut payload = example();
            payload.runtime_inputs.wheel_records[0]
                .installed_record
                .path = malicious.to_owned();
            assert!(
                validate_payload(&payload).is_err(),
                "accepted malicious RECORD path {malicious:?}"
            );
        }
    }

    #[test]
    fn wheel_records_reject_case_collisions_duplicates_and_noncanonical_order() {
        let base = example();
        let source = base.runtime_inputs.wheel_records[0].clone();

        let mut case_collision = base.clone();
        case_collision
            .runtime_inputs
            .wheel_records
            .push(second_wheel(
                &source,
                "artifact_66666666666666666666666666666666",
                "artifact_77777777777777777777777777777777",
                "site/PHASELEDGER-0.6.0.dist-info/RECORD",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ));
        assert!(validate_payload(&case_collision).is_err());

        let mut duplicate_wheel = base.clone();
        duplicate_wheel
            .runtime_inputs
            .wheel_records
            .push(second_wheel(
                &source,
                &source.wheel.artifact_ref.artifact_id,
                "artifact_77777777777777777777777777777777",
                "site/second-1.0.dist-info/RECORD",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ));
        assert!(validate_payload(&duplicate_wheel).is_err());

        let mut unordered = base;
        unordered.runtime_inputs.wheel_records.push(second_wheel(
            &source,
            "artifact_66666666666666666666666666666666",
            "artifact_77777777777777777777777777777777",
            "site/second-1.0.dist-info/RECORD",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ));
        assert!(validate_payload(&unordered).is_err());
    }

    #[test]
    fn launch_environment_binding_and_lengths_are_exact() {
        let mut payload = example();
        payload.launch_contract.fixed_arguments.swap(0, 1);
        assert!(validate_payload(&payload).is_err());

        let mut payload = example();
        payload.launch_contract.environment.variables.swap(0, 1);
        assert!(validate_payload(&payload).is_err());

        let mut payload = example();
        payload.launch_contract.environment.inheritance = "ambient".to_owned();
        assert!(validate_payload(&payload).is_err());

        let mut payload = example();
        payload
            .runtime_inputs
            .path_configuration
            .artifact
            .byte_length = 0;
        assert!(validate_payload(&payload).is_err());
    }

    #[test]
    fn strict_record_parser_binds_version_and_typed_payload_digest() {
        parse_python_runtime_qualification_record(RECORD_EXAMPLE).unwrap();

        let mut value: Value = serde_json::from_slice(RECORD_EXAMPLE).unwrap();
        value["schema_version"] = json!("python_runtime_qualification_record/v2");
        assert!(
            parse_python_runtime_qualification_record(&serde_json::to_vec(&value).unwrap())
                .is_err()
        );

        let mut value: Value = serde_json::from_slice(RECORD_EXAMPLE).unwrap();
        value["payload"]["operation"] = json!("forged_operation");
        assert!(
            parse_python_runtime_qualification_record(&serde_json::to_vec(&value).unwrap())
                .is_err()
        );

        let duplicate = String::from_utf8(RECORD_EXAMPLE.to_vec())
            .unwrap()
            .replacen(
                "\"schema_version\": \"python_runtime_qualification_record/v1\"",
                "\"schema_version\": \"python_runtime_qualification_record/v1\", \"schema_version\": \"python_runtime_qualification_record/v1\"",
                1,
            );
        assert!(parse_python_runtime_qualification_record(duplicate.as_bytes()).is_err());
    }

    #[test]
    fn embedded_wrapper_bytes_are_lf_stable_and_fail_closed() {
        validate_embedded_wrapper_contract().unwrap();
        assert_eq!(WRAPPER_BYTES.len(), 261);
        assert_eq!(hex::encode(Sha256::digest(WRAPPER_BYTES)), WRAPPER_SHA256);
        assert!(!WRAPPER_BYTES.contains(&b'\r'));
        let text = std::str::from_utf8(WRAPPER_BYTES).unwrap();
        assert!(text.contains("execution is not implemented"));
        assert!(text.contains("raise SystemExit"));
    }
}
