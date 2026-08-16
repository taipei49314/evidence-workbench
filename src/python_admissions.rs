use crate::contracts::{
    ArtifactRecordRef, ContractAuthorityEffect, ExactArtifactBinding, NativeQualificationRef,
    PythonAdmissionCheck, PythonAdmissionCheckState, PythonAdmissionRef, PythonAdmissionState,
    PythonAdmissionStateValue, PythonRuntimeExecutionAdmission,
    PythonRuntimeExecutionAdmissionRecord, PythonRuntimeQualification, ToolRef, UpstreamPinRef,
};
#[cfg(windows)]
use crate::python_containment;
use crate::python_qualifications;
use crate::workspace::Workspace;
use crate::{manifests, native, runtime_capsules, workspace};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

pub const ALLOWED_OPERATIONS: &[&str] = &["trust_meter_measure", "phaseledger_measure"];

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

pub const RESIDUAL_CONTAINMENT_CODES: &[&str] = &[
    "os_network_egress_denial",
    "python_active_process_limit_one",
    "python_creation_time_job_assignment",
];

const IMPLEMENTABLE_CODES: &[&str] = &[
    "cpython_archive_semantics",
    "python_launch_harness",
    "python_path_configuration_isolation",
    "python_private_materialization",
    "wheel_record_closure",
];

#[derive(Debug, Serialize)]
pub struct PythonAdmissionVerification {
    pub admission_id: String,
    pub record_digest: String,
    pub inventory_qualification_id: String,
    pub tool_manifest_id: String,
    pub operation: String,
    pub admission_state: &'static str,
    pub blocker_codes: Vec<String>,
    pub execution_admission: &'static str,
    pub authority_effect: &'static str,
}

pub fn validate_payload(payload: &PythonRuntimeExecutionAdmission) -> Result<()> {
    match payload.schema_version.as_str() {
        "python_runtime_execution_admission/v1" => validate_v1_payload(payload),
        "python_runtime_execution_admission/v2" => validate_v2_payload(payload),
        _ => bail!("unsupported Python runtime execution admission schema"),
    }
}

fn validate_common_payload(payload: &PythonRuntimeExecutionAdmission) -> Result<()> {
    DateTime::parse_from_rfc3339(&payload.observed_at)
        .context("Python runtime execution admission observed_at is not RFC 3339")?;
    workspace::validate_prefixed_id(
        &payload.inventory_qualification_ref.qualification_id,
        "qualification_",
    )?;
    workspace::validate_sha256(&payload.inventory_qualification_ref.record_digest)?;
    manifests::validate_id(&payload.tool_ref.manifest_id)?;
    workspace::validate_sha256(&payload.tool_ref.manifest_sha256)?;
    if payload.upstream_pin_ref.tool_manifest_id != payload.tool_ref.manifest_id {
        bail!("Python execution admission tool and upstream pin refs diverge");
    }
    workspace::validate_sha256(&payload.upstream_pin_ref.pin_sha256)?;
    if !ALLOWED_OPERATIONS.contains(&payload.operation.as_str()) {
        bail!(
            "Python execution admission operation {} is outside the vertical-slice allowlist",
            payload.operation
        );
    }
    if payload.recorder_identity.version.is_empty()
        || payload.recorder_identity.version.trim() != payload.recorder_identity.version
    {
        bail!("Python execution admission recorder version is invalid");
    }
    workspace::validate_sha256(&payload.recorder_identity.executable_sha256)?;
    if payload.platform_observation.target.os != "windows"
        || payload.platform_observation.target.arch != "x86_64"
        || payload.platform_observation.host.os != "windows"
        || payload.platform_observation.host.arch != "x86_64"
    {
        bail!("Python execution admission platform observation must be Windows x86_64");
    }
    if payload.authority_effect != ContractAuthorityEffect::None {
        bail!("Python execution admission authority_effect must be none");
    }
    if payload.admission_state.state != PythonAdmissionStateValue::NotGranted {
        bail!("python_runtime_execution_admission cannot represent a granted admission");
    }
    if payload.checks.len() != CHECK_CODES.len() {
        bail!("Python execution admission must record exactly the eight closed checks");
    }
    let mut expected_blockers = BTreeSet::new();
    for (index, expected) in CHECK_CODES.iter().enumerate() {
        let check = &payload.checks[index];
        if check.code != *expected {
            bail!("Python execution admission checks must stay in canonical order");
        }
        if check.state != PythonAdmissionCheckState::Satisfied {
            expected_blockers.insert(check.code.clone());
        }
        for evidence in &check.evidence_refs {
            workspace::validate_prefixed_id(&evidence.artifact_id, "artifact_")?;
            workspace::validate_sha256(&evidence.record_digest)?;
        }
    }
    if payload.admission_state.blocker_codes.len() != expected_blockers.len()
        || payload
            .admission_state
            .blocker_codes
            .iter()
            .any(|code| !expected_blockers.contains(code))
    {
        bail!("Python execution admission blocker_codes must match unsatisfied checks");
    }
    let mut previous: Option<&str> = None;
    for code in &payload.admission_state.blocker_codes {
        if let Some(prior) = previous {
            if code.as_str() <= prior {
                bail!("Python execution admission blocker_codes must be unique and sorted");
            }
        }
        previous = Some(code);
    }
    Ok(())
}

fn validate_v1_payload(payload: &PythonRuntimeExecutionAdmission) -> Result<()> {
    if payload.source_admission_ref.is_some() {
        bail!("python_runtime_execution_admission/v1 cannot cite a source admission");
    }
    validate_common_payload(payload)?;
    for (index, expected) in CHECK_CODES.iter().enumerate() {
        let check = &payload.checks[index];
        if RESIDUAL_CONTAINMENT_CODES.contains(&check.code.as_str())
            && check.state == PythonAdmissionCheckState::Satisfied
        {
            bail!(
                "Python execution admission cannot mark residual containment check {} satisfied",
                check.code
            );
        }
        let _ = expected;
    }
    for residual in RESIDUAL_CONTAINMENT_CODES {
        if !payload
            .admission_state
            .blocker_codes
            .iter()
            .any(|code| code == residual)
        {
            bail!("Python execution admission must retain residual containment blocker {residual}");
        }
    }
    Ok(())
}

fn validate_v2_payload(payload: &PythonRuntimeExecutionAdmission) -> Result<()> {
    let Some(source) = &payload.source_admission_ref else {
        bail!("python_runtime_execution_admission/v2 must cite a verified v1 admission");
    };
    workspace::validate_prefixed_id(&source.admission_id, "admission_")?;
    workspace::validate_sha256(&source.record_digest)?;
    validate_common_payload(payload)?;
    for check in &payload.checks {
        if RESIDUAL_CONTAINMENT_CODES.contains(&check.code.as_str())
            && check.state == PythonAdmissionCheckState::NotImplemented
        {
            bail!(
                "python_runtime_execution_admission/v2 cannot record residual check {} as not_implemented",
                check.code
            );
        }
    }
    if payload.checks[1].state == PythonAdmissionCheckState::Satisfied {
        bail!(
            "python_runtime_execution_admission/v2 cannot mark residual containment check os_network_egress_denial satisfied"
        );
    }
    if !payload
        .admission_state
        .blocker_codes
        .iter()
        .any(|code| code == "os_network_egress_denial")
    {
        bail!(
            "python_runtime_execution_admission/v2 must retain residual containment blocker os_network_egress_denial"
        );
    }
    Ok(())
}

pub fn admit(
    workspace: &Workspace,
    inventory_qualification_id: &str,
) -> Result<PythonRuntimeExecutionAdmissionRecord> {
    let inventory_record =
        python_qualifications::load_verified(workspace, inventory_qualification_id)?;
    python_qualifications::validate_payload(&inventory_record.payload)?;
    if inventory_record.payload.qualification_state.state
        != crate::contracts::PythonQualificationStateValue::Incomplete
    {
        bail!("Python execution admission cannot promote an incomplete inventory qualification");
    }
    if !ALLOWED_OPERATIONS.contains(&inventory_record.payload.operation.as_str()) {
        bail!(
            "Python execution admission is only defined for trust_meter_measure and phaseledger_measure"
        );
    }

    let recorder = native::recorder_identity()?;
    let proofs = evaluate_implementable_proofs(workspace, &inventory_record.payload)?;
    let residual = evaluate_residual_checks();
    let mut checks = Vec::new();
    for code in CHECK_CODES {
        let (state, evidence_refs) = if RESIDUAL_CONTAINMENT_CODES.contains(code) {
            (
                residual
                    .get(*code)
                    .cloned()
                    .unwrap_or(PythonAdmissionCheckState::Failed),
                Vec::new(),
            )
        } else {
            proofs
                .get(*code)
                .cloned()
                .unwrap_or((PythonAdmissionCheckState::Failed, Vec::new()))
        };
        checks.push(PythonAdmissionCheck {
            code: (*code).to_owned(),
            state,
            evidence_refs,
        });
    }
    let blocker_codes = checks
        .iter()
        .filter(|check| check.state != PythonAdmissionCheckState::Satisfied)
        .map(|check| check.code.clone())
        .collect();

    let payload = PythonRuntimeExecutionAdmission {
        schema_version: "python_runtime_execution_admission/v1".to_owned(),
        observed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        source_admission_ref: None,
        inventory_qualification_ref: NativeQualificationRef {
            qualification_id: inventory_record.qualification_id.clone(),
            record_digest: inventory_record.record_digest.clone(),
        },
        tool_ref: ToolRef {
            manifest_id: inventory_record.payload.tool_ref.manifest_id.clone(),
            manifest_sha256: inventory_record.payload.tool_ref.manifest_sha256.clone(),
        },
        upstream_pin_ref: UpstreamPinRef {
            tool_manifest_id: inventory_record
                .payload
                .upstream_pin_ref
                .tool_manifest_id
                .clone(),
            pin_sha256: inventory_record.payload.upstream_pin_ref.pin_sha256.clone(),
        },
        operation: inventory_record.payload.operation.clone(),
        recorder_identity: recorder,
        platform_observation: inventory_record.payload.platform_observation.clone(),
        checks,
        admission_state: PythonAdmissionState {
            state: PythonAdmissionStateValue::NotGranted,
            blocker_codes,
        },
        authority_effect: ContractAuthorityEffect::None,
    };
    validate_payload(&payload)?;

    let record = PythonRuntimeExecutionAdmissionRecord {
        schema_version: "python_runtime_execution_admission_record/v1".to_owned(),
        admission_id: format!("admission_{}", Uuid::new_v4().simple()),
        record_digest: workspace::digest_serialized(&payload)?,
        payload,
    };
    workspace.write_python_runtime_execution_admission(&record)?;
    verify_record(workspace, &record)?;
    Ok(record)
}

pub fn prove_containment(
    workspace: &Workspace,
    admission_id: &str,
) -> Result<PythonRuntimeExecutionAdmissionRecord> {
    #[cfg(not(windows))]
    {
        let _ = (workspace, admission_id);
        bail!("python-admissions prove-containment requires Windows Job Objects");
    }
    #[cfg(windows)]
    {
        prove_containment_windows(workspace, admission_id)
    }
}

#[cfg(windows)]
fn prove_containment_windows(
    workspace: &Workspace,
    admission_id: &str,
) -> Result<PythonRuntimeExecutionAdmissionRecord> {
    let source = load_verified(workspace, admission_id)?;
    if source.payload.schema_version != "python_runtime_execution_admission/v1" {
        bail!("python-admissions prove-containment cites a v1 admission only");
    }
    let inventory = python_qualifications::load_verified(
        workspace,
        &source.payload.inventory_qualification_ref.qualification_id,
    )?;
    if inventory.record_digest != source.payload.inventory_qualification_ref.record_digest {
        bail!("Python containment prove inventory qualification digest mismatch");
    }
    let capsule = runtime_capsules::load_verified(workspace, &inventory.payload.capsule_ref.id)?;
    if capsule.record_digest != inventory.payload.capsule_ref.record_digest {
        bail!("Python containment prove capsule digest mismatch");
    }
    let launcher = workspace.load_artifact(&capsule.payload.launcher.artifact_id)?;
    let root = workspace
        .state
        .join("tmp")
        .join(format!("containment-{}", Uuid::new_v4().simple()));
    fs::create_dir(&root).context("cannot create private containment prove root")?;
    let _cleanup = TmpRoot(root.clone());
    let launcher_path = root.join("python.exe");
    copy_verified_create_new(workspace, &launcher, &launcher_path)?;
    let scratch = root.join("scratch");
    fs::create_dir(&scratch)?;
    let proof = python_containment::prove_bound_python(&launcher_path, &scratch)?;

    let mut checks = source.payload.checks.clone();
    for check in &mut checks {
        match check.code.as_str() {
            "os_network_egress_denial" => {
                check.state = python_containment::ResidualContainmentProof::network_egress();
                check.evidence_refs.clear();
            }
            "python_active_process_limit_one" => {
                check.state = proof.process_limit.clone();
                check.evidence_refs.clear();
            }
            "python_creation_time_job_assignment" => {
                check.state = proof.job_assignment.clone();
                check.evidence_refs.clear();
            }
            _ => {}
        }
    }
    let blocker_codes = checks
        .iter()
        .filter(|check| check.state != PythonAdmissionCheckState::Satisfied)
        .map(|check| check.code.clone())
        .collect();
    let recorder = native::recorder_identity()?;
    let payload = PythonRuntimeExecutionAdmission {
        schema_version: "python_runtime_execution_admission/v2".to_owned(),
        observed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        source_admission_ref: Some(PythonAdmissionRef {
            admission_id: source.admission_id.clone(),
            record_digest: source.record_digest.clone(),
        }),
        inventory_qualification_ref: source.payload.inventory_qualification_ref.clone(),
        tool_ref: source.payload.tool_ref.clone(),
        upstream_pin_ref: source.payload.upstream_pin_ref.clone(),
        operation: source.payload.operation.clone(),
        recorder_identity: recorder,
        platform_observation: source.payload.platform_observation.clone(),
        checks,
        admission_state: PythonAdmissionState {
            state: PythonAdmissionStateValue::NotGranted,
            blocker_codes,
        },
        authority_effect: ContractAuthorityEffect::None,
    };
    validate_payload(&payload)?;
    let record = PythonRuntimeExecutionAdmissionRecord {
        schema_version: "python_runtime_execution_admission_record/v2".to_owned(),
        admission_id: format!("admission_{}", Uuid::new_v4().simple()),
        record_digest: workspace::digest_serialized(&payload)?,
        payload,
    };
    workspace.write_python_runtime_execution_admission(&record)?;
    verify_record(workspace, &record)?;
    Ok(record)
}

type CheckOutcome = (PythonAdmissionCheckState, Vec<ArtifactRecordRef>);

fn evaluate_implementable_proofs(
    workspace: &Workspace,
    inventory: &PythonRuntimeQualification,
) -> Result<BTreeMap<&'static str, CheckOutcome>> {
    let capsule = runtime_capsules::load_verified(workspace, &inventory.capsule_ref.id)?;
    if capsule.record_digest != inventory.capsule_ref.record_digest {
        bail!("Python execution admission inventory capsule digest mismatch");
    }
    let launcher_name = Path::new(&capsule.payload.launcher.path)
        .file_name()
        .and_then(|name| name.to_str())
        .context("capsule launcher path must have a UTF-8 file name")?;

    let archive = load_binding(workspace, &inventory.runtime_inputs.cpython_archive)?;
    let path_config = load_binding(
        workspace,
        &inventory.runtime_inputs.path_configuration.artifact,
    )?;
    let wrapper = load_binding(workspace, &inventory.runtime_inputs.wrapper.artifact)?;
    let mut wheel_pairs = Vec::new();
    for pair in &inventory.runtime_inputs.wheel_records {
        wheel_pairs.push((
            load_binding(workspace, &pair.wheel)?,
            load_binding(workspace, &pair.installed_record.artifact)?,
        ));
    }

    let archive_proof = prove_cpython_archive(&archive.1, launcher_name);
    let stdlib_name = archive_proof.as_ref().ok().cloned();
    let path_text = std::str::from_utf8(&path_config.1)
        .map_err(|_| anyhow::anyhow!("path configuration is not UTF-8"));
    let path_proof =
        path_text.and_then(|text| prove_path_configuration(text, stdlib_name.as_deref()));
    let launch_proof = prove_launch_harness(inventory, &wrapper.1);
    let wheel_proof = prove_wheel_record_closure(&wheel_pairs);
    let materialization_proof = prove_private_materialization(
        workspace,
        &capsule.payload.launcher.artifact_id,
        inventory,
        &archive.0,
        &path_config.0,
        &wrapper.0,
        &wheel_pairs,
    );

    let mut proofs = BTreeMap::new();
    proofs.insert(
        "cpython_archive_semantics",
        outcome(
            archive_proof.err(),
            vec![ref_of(&inventory.runtime_inputs.cpython_archive)],
        ),
    );
    proofs.insert(
        "python_path_configuration_isolation",
        outcome(
            path_proof.err(),
            vec![ref_of(
                &inventory.runtime_inputs.path_configuration.artifact,
            )],
        ),
    );
    proofs.insert(
        "python_launch_harness",
        outcome(
            launch_proof.err(),
            vec![ref_of(&inventory.runtime_inputs.wrapper.artifact)],
        ),
    );
    proofs.insert(
        "wheel_record_closure",
        outcome(
            wheel_proof.err(),
            inventory
                .runtime_inputs
                .wheel_records
                .iter()
                .flat_map(|pair| [ref_of(&pair.wheel), ref_of(&pair.installed_record.artifact)])
                .collect(),
        ),
    );
    proofs.insert(
        "python_private_materialization",
        outcome(
            materialization_proof.err(),
            materialization_evidence(inventory),
        ),
    );
    for code in IMPLEMENTABLE_CODES {
        proofs
            .entry(*code)
            .or_insert((PythonAdmissionCheckState::Failed, Vec::new()));
    }
    Ok(proofs)
}

fn evaluate_residual_checks() -> BTreeMap<&'static str, PythonAdmissionCheckState> {
    let mut checks = BTreeMap::new();
    for code in RESIDUAL_CONTAINMENT_CODES {
        checks.insert(*code, prove_residual(code));
    }
    checks
}

fn prove_residual(_code: &str) -> PythonAdmissionCheckState {
    // Spawnless admit cannot CreateProcess-assign python.exe, apply a network
    // filter to that process, or observe an ActiveProcessLimit of one on it.
    // An empty Job Object is not those proofs. Residual checks stay failed.
    PythonAdmissionCheckState::Failed
}

fn outcome(error: Option<anyhow::Error>, evidence: Vec<ArtifactRecordRef>) -> CheckOutcome {
    match error {
        None => (PythonAdmissionCheckState::Satisfied, evidence),
        Some(_) => (PythonAdmissionCheckState::Failed, Vec::new()),
    }
}

fn ref_of(binding: &ExactArtifactBinding) -> ArtifactRecordRef {
    binding.artifact_ref.clone()
}

fn materialization_evidence(inventory: &PythonRuntimeQualification) -> Vec<ArtifactRecordRef> {
    let mut refs = vec![
        ref_of(&inventory.runtime_inputs.cpython_archive),
        ref_of(&inventory.runtime_inputs.path_configuration.artifact),
        ref_of(&inventory.runtime_inputs.wrapper.artifact),
    ];
    for pair in &inventory.runtime_inputs.wheel_records {
        refs.push(ref_of(&pair.wheel));
        refs.push(ref_of(&pair.installed_record.artifact));
    }
    refs
}

fn load_binding(
    workspace: &Workspace,
    binding: &ExactArtifactBinding,
) -> Result<(crate::contracts::ArtifactRecord, Vec<u8>)> {
    let record = workspace.load_artifact(&binding.artifact_ref.artifact_id)?;
    if record.record_digest != binding.artifact_ref.record_digest
        || record.artifact.digest != binding.digest
        || record.artifact.byte_length != binding.byte_length
    {
        bail!("Python execution admission artifact binding changed");
    }
    let bytes = workspace.read_verified_descriptor(&record.artifact)?;
    Ok((record, bytes))
}

fn prove_cpython_archive(bytes: &[u8], launcher_name: &str) -> Result<String> {
    if bytes.len() as u64 > 64 * 1024 * 1024 {
        bail!("CPython archive exceeds the admission size bound");
    }
    let members = inspect_zip(bytes, "CPython archive")?;
    let mut launcher = false;
    let mut stdlib = None;
    for (name, member) in &members {
        let basename = name.rsplit('/').next().unwrap_or(name);
        if basename.eq_ignore_ascii_case(launcher_name) {
            if name.contains('/') || launcher {
                bail!("CPython archive launcher member is duplicated or nested");
            }
            if member.is_empty() {
                bail!("CPython archive launcher member is empty");
            }
            launcher = true;
        }
        if is_stdlib_zip_name(basename) {
            if name.contains('/') || stdlib.is_some() {
                bail!("CPython archive stdlib zip is duplicated or nested");
            }
            if member.is_empty() {
                bail!("CPython archive stdlib zip is empty");
            }
            stdlib = Some(basename.to_owned());
        }
        if basename.rsplit('.').next() == Some("exe")
            && !basename.eq_ignore_ascii_case("python.exe")
            && !basename.eq_ignore_ascii_case("pythonw.exe")
        {
            bail!("CPython archive contains an unexpected executable {basename}");
        }
    }
    if !launcher {
        bail!("CPython archive is missing launcher {launcher_name}");
    }
    stdlib.context("CPython archive is missing a python3XX.zip stdlib member")
}

fn prove_path_configuration(text: &str, stdlib_name: Option<&str>) -> Result<()> {
    if text.contains('\0') || text.contains('\\') {
        bail!("path configuration contains NUL or backslash");
    }
    let mut saw_stdlib = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let lowered = line.to_ascii_lowercase();
        if lowered.starts_with("import ")
            || lowered.contains("sitecustomize")
            || lowered.contains("usercustomize")
            || lowered.contains("site-packages")
            || lowered.contains("appdata")
            || Path::new(line).is_absolute()
            || line.contains(':')
            || line.contains("..")
        {
            bail!("path configuration admits site, sitecustomize, or an ambient path");
        }
        if is_stdlib_zip_name(line) {
            if let Some(expected) = stdlib_name {
                if line != expected {
                    bail!("path configuration stdlib zip does not match the CPython archive");
                }
            }
            saw_stdlib = true;
            continue;
        }
        if line == "site" || line == "." {
            continue;
        }
        bail!("path configuration line {line:?} is outside the isolated allowlist");
    }
    if !saw_stdlib {
        bail!("path configuration must name a python3XX.zip stdlib member");
    }
    Ok(())
}

fn prove_launch_harness(
    inventory: &PythonRuntimeQualification,
    wrapper_bytes: &[u8],
) -> Result<()> {
    if inventory.launch_contract != python_qualifications::fixed_launch_contract() {
        bail!("Python launch harness is not the fixed isolated contract");
    }
    if inventory.runtime_inputs.wrapper.contract_id != python_qualifications::WRAPPER_CONTRACT_ID
        || inventory.runtime_inputs.wrapper.artifact.digest.value
            != python_qualifications::WRAPPER_SHA256
        || inventory.runtime_inputs.wrapper.artifact.byte_length
            != python_qualifications::WRAPPER_BYTES.len() as u64
        || wrapper_bytes != python_qualifications::WRAPPER_BYTES
    {
        bail!("Python launch harness wrapper bytes do not match the embedded contract");
    }
    Ok(())
}

fn prove_wheel_record_closure(
    pairs: &[(
        (crate::contracts::ArtifactRecord, Vec<u8>),
        (crate::contracts::ArtifactRecord, Vec<u8>),
    )],
) -> Result<()> {
    if pairs.is_empty() {
        bail!("wheel RECORD closure requires at least one wheel pair");
    }
    for (wheel, installed) in pairs {
        let members = inspect_zip(&wheel.1, "wheel")?;
        let wheel_record = members
            .iter()
            .find(|(name, _)| name.ends_with(".dist-info/RECORD"))
            .context("wheel is missing a .dist-info/RECORD")?;
        let wheel_entries = parse_record(&wheel_record.1)?;
        let installed_entries = parse_record(&installed.1)?;
        if wheel_entries.is_empty() || installed_entries.is_empty() {
            bail!("wheel or installed RECORD is empty");
        }
        let mut seen = BTreeSet::new();
        for (path, hash, size) in &wheel_entries {
            if !seen.insert(path.to_ascii_lowercase()) {
                bail!("wheel RECORD contains a case-folded path collision");
            }
            if path.ends_with("/RECORD") || path == "RECORD" {
                continue;
            }
            let member = members
                .iter()
                .find(|(name, _)| name == path)
                .with_context(|| format!("wheel RECORD path {path} is missing from the wheel"))?;
            if member.1.len() as u64 != *size {
                bail!("wheel RECORD size does not match member {path}");
            }
            if hash != &record_hash(&member.1) {
                bail!("wheel RECORD digest does not match member {path}");
            }
            let installed = installed_entries
                .iter()
                .find(|(installed_path, _, _)| installed_path == path)
                .with_context(|| format!("installed RECORD is missing wheel path {path}"))?;
            if installed.1 != *hash || installed.2 != *size {
                bail!("installed RECORD does not match wheel RECORD for {path}");
            }
        }
        for (path, _, _) in &installed_entries {
            if path.ends_with("/RECORD") || path == "RECORD" {
                continue;
            }
            if !wheel_entries
                .iter()
                .any(|(wheel_path, _, _)| wheel_path == path)
            {
                bail!("installed RECORD contains extra path {path}");
            }
        }
        for (name, _) in &members {
            if name.ends_with("/RECORD") || name == "RECORD" {
                continue;
            }
            if !wheel_entries.iter().any(|(path, _, _)| path == name) {
                bail!("wheel contains extra member {name} not listed in RECORD");
            }
        }
    }
    Ok(())
}

fn prove_private_materialization(
    workspace: &Workspace,
    launcher_artifact_id: &str,
    inventory: &PythonRuntimeQualification,
    archive: &crate::contracts::ArtifactRecord,
    path_config: &crate::contracts::ArtifactRecord,
    wrapper: &crate::contracts::ArtifactRecord,
    wheel_pairs: &[(
        (crate::contracts::ArtifactRecord, Vec<u8>),
        (crate::contracts::ArtifactRecord, Vec<u8>),
    )],
) -> Result<()> {
    let launcher = workspace.load_artifact(launcher_artifact_id)?;
    let mut expected = vec![
        ("launcher".to_owned(), launcher),
        ("cpython-archive.zip".to_owned(), archive.clone()),
        ("python._pth".to_owned(), path_config.clone()),
        ("wrapper.py".to_owned(), wrapper.clone()),
    ];
    for (index, (wheel, _)) in wheel_pairs.iter().enumerate() {
        expected.push((format!("wheel-{index}.whl"), wheel.0.clone()));
        let installed = workspace.load_artifact(
            &inventory.runtime_inputs.wheel_records[index]
                .installed_record
                .artifact
                .artifact_ref
                .artifact_id,
        )?;
        expected.push((format!("record-{index}.RECORD"), installed));
    }

    let root = workspace
        .state
        .join("tmp")
        .join(format!("admission-{}", Uuid::new_v4().simple()));
    fs::create_dir(&root).context("cannot create private admission materialization root")?;
    let _cleanup = TmpRoot(root.clone());
    reject_reparse(&root, true)?;

    let mut pre = BTreeMap::new();
    for (name, record) in &expected {
        let destination = root.join(name);
        copy_verified_create_new(workspace, record, &destination)?;
        pre.insert(name.clone(), record.artifact.digest.value.clone());
    }

    let mut post = BTreeMap::new();
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || is_reparse(&metadata) {
            bail!("private admission root contains a link or reparse point");
        }
        if !metadata.is_file() {
            bail!("private admission root contains an unexpected directory");
        }
        if !is_single_link(&entry.path())? {
            bail!("private admission file is not a single-link copy");
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("private admission file name is not UTF-8"))?;
        let bytes = fs::read(entry.path())?;
        post.insert(name, hex::encode(Sha256::digest(&bytes)));
    }
    if pre != post {
        bail!("private admission materialization inventory changed");
    }
    Ok(())
}

fn copy_verified_create_new(
    workspace: &Workspace,
    record: &crate::contracts::ArtifactRecord,
    destination: &Path,
) -> Result<()> {
    let bytes = workspace.read_verified_descriptor(&record.artifact)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .context("cannot create a private single-link admission copy")?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    let metadata = fs::symlink_metadata(destination)?;
    if !metadata.is_file() || is_reparse(&metadata) || !is_single_link(destination)? {
        bail!("private admission copy is not a regular single-link file");
    }
    if hex::encode(Sha256::digest(&bytes)) != record.artifact.digest.value
        || bytes.len() as u64 != record.artifact.byte_length
    {
        bail!("private admission copy digest mismatch");
    }
    Ok(())
}

struct TmpRoot(PathBuf);

impl Drop for TmpRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn inspect_zip(bytes: &[u8], label: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .with_context(|| format!("{label} is not a valid ZIP"))?;
    if archive.is_empty() || archive.len() > 4096 {
        bail!("{label} ZIP entry count is outside the admitted range");
    }
    let mut names = BTreeSet::new();
    let mut members = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        if entry.encrypted() {
            bail!("{label} ZIP contains encrypted content");
        }
        let name = entry.name().replace('\\', "/");
        if !names.insert(name.to_ascii_lowercase()) {
            bail!("{label} ZIP contains a case-folded path collision");
        }
        let enclosed = entry
            .enclosed_name()
            .with_context(|| format!("{label} ZIP contains a traversal path"))?;
        if enclosed
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            bail!("{label} ZIP entry path is not canonical");
        }
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            bail!("{label} ZIP contains a symbolic link");
        }
        if entry.is_dir() {
            continue;
        }
        if entry.size() > 64 * 1024 * 1024 {
            bail!("{label} ZIP member exceeds the admission size bound");
        }
        let mut member = Vec::new();
        entry.read_to_end(&mut member)?;
        if member.len() as u64 != entry.size() {
            bail!("{label} ZIP member decompression length mismatch");
        }
        members.push((name, member));
    }
    Ok(members)
}

fn parse_record(bytes: &[u8]) -> Result<Vec<(String, String, u64)>> {
    let text = std::str::from_utf8(bytes).context("RECORD is not UTF-8")?;
    if text.contains('\0') {
        bail!("RECORD contains NUL");
    }
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() != 3 {
            bail!("RECORD line is not path,hash,size");
        }
        let path = parts[0].replace('\\', "/");
        if path.is_empty()
            || path.starts_with('/')
            || path.contains("..")
            || Path::new(&path).is_absolute()
        {
            bail!("RECORD path is not a relative canonical member");
        }
        if !seen.insert(path.to_ascii_lowercase()) {
            bail!("RECORD contains a case-folded path collision");
        }
        let size = if parts[2].is_empty() {
            0
        } else {
            parts[2]
                .parse::<u64>()
                .context("RECORD size is not an integer")?
        };
        entries.push((path, parts[1].to_owned(), size));
    }
    Ok(entries)
}

fn record_hash(bytes: &[u8]) -> String {
    format!("sha256={}", urlsafe_b64_nopad(&Sha256::digest(bytes)))
}

fn urlsafe_b64_nopad(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut index = 0;
    while index < bytes.len() {
        let b0 = bytes[index];
        let b1 = if index + 1 < bytes.len() {
            bytes[index + 1]
        } else {
            0
        };
        let b2 = if index + 2 < bytes.len() {
            bytes[index + 2]
        } else {
            0
        };
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        if index + 1 < bytes.len() {
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        }
        if index + 2 < bytes.len() {
            out.push(TABLE[(n & 63) as usize] as char);
        }
        index += 3;
    }
    out
}

fn is_stdlib_zip_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() == 13
        && bytes.starts_with(b"python3")
        && bytes.ends_with(b".zip")
        && bytes[7].is_ascii_digit()
        && bytes[8].is_ascii_digit()
}

fn reject_reparse(path: &Path, directory: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if is_reparse(&metadata) || metadata.file_type().is_symlink() {
        bail!("admission path is a link or reparse point");
    }
    if directory && !metadata.is_dir() {
        bail!("admission path is not a directory");
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(windows)]
fn is_single_link(path: &Path) -> Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let file = fs::File::open(path).context("cannot open admission file to query link count")?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file owns a live Windows handle and information is writable.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error())
            .context("cannot query admission file link count");
    }
    Ok(information.nNumberOfLinks == 1)
}

#[cfg(unix)]
fn is_single_link(path: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    Ok(fs::symlink_metadata(path)?.nlink() == 1)
}

#[cfg(not(any(windows, unix)))]
fn is_single_link(_path: &Path) -> Result<bool> {
    Ok(true)
}

pub fn load_verified(
    workspace: &Workspace,
    admission_id: &str,
) -> Result<PythonRuntimeExecutionAdmissionRecord> {
    let record = workspace.load_python_runtime_execution_admission(admission_id)?;
    verify_record(workspace, &record)?;
    Ok(record)
}

pub fn list_verified(workspace: &Workspace) -> Result<Vec<PythonRuntimeExecutionAdmissionRecord>> {
    workspace
        .list_python_runtime_execution_admissions()?
        .into_iter()
        .map(|record| {
            verify_record(workspace, &record)?;
            Ok(record)
        })
        .collect()
}

pub fn verify(workspace: &Workspace, admission_id: &str) -> Result<PythonAdmissionVerification> {
    let record = load_verified(workspace, admission_id)?;
    Ok(verification(&record))
}

pub fn bind_for_plan(
    workspace: &Workspace,
    admission_id: Option<&str>,
    tool_manifest_id: &str,
    operation: &str,
) -> Result<Option<PythonAdmissionRef>> {
    let Some(admission_id) = admission_id else {
        return Ok(None);
    };
    if !ALLOWED_OPERATIONS.contains(&operation) {
        bail!("--python-admission is only accepted by trust_meter_measure or phaseledger_measure");
    }
    let record = load_verified(workspace, admission_id)?;
    if record.payload.tool_ref.manifest_id != tool_manifest_id
        || record.payload.operation != operation
    {
        bail!("Python execution admission does not bind this tool operation");
    }
    Ok(Some(PythonAdmissionRef {
        admission_id: record.admission_id,
        record_digest: record.record_digest,
    }))
}

pub fn validate_bound_ref(
    workspace: &Workspace,
    admission_ref: Option<&PythonAdmissionRef>,
    tool_manifest_id: &str,
    operation: &str,
) -> Result<()> {
    match admission_ref {
        None => Ok(()),
        Some(reference) => {
            if !ALLOWED_OPERATIONS.contains(&operation) {
                bail!("Python execution admission refs are not valid for {operation}");
            }
            let record = load_verified(workspace, &reference.admission_id)?;
            if record.record_digest != reference.record_digest {
                bail!(
                    "Python execution admission digest does not match the caller-retained digest"
                );
            }
            if record.payload.tool_ref.manifest_id != tool_manifest_id
                || record.payload.operation != operation
            {
                bail!("Python execution admission does not bind this tool operation");
            }
            if record.payload.admission_state.state != PythonAdmissionStateValue::NotGranted {
                bail!("stored Python execution admission escaped not_granted");
            }
            Ok(())
        }
    }
}

pub fn reject_inventory_as_admission(qualification_id: &str) -> Result<()> {
    if qualification_id.starts_with("qualification_") {
        bail!(
            "incomplete python_runtime_qualification/v1 record {qualification_id} cannot be used as a python_runtime_execution_admission"
        );
    }
    Ok(())
}

fn verify_record(
    workspace: &Workspace,
    record: &PythonRuntimeExecutionAdmissionRecord,
) -> Result<()> {
    let expected_record_schema = match record.payload.schema_version.as_str() {
        "python_runtime_execution_admission/v1" => {
            "python_runtime_execution_admission_record/v1"
        }
        "python_runtime_execution_admission/v2" => {
            "python_runtime_execution_admission_record/v2"
        }
        _ => bail!("unsupported Python runtime execution admission schema"),
    };
    if record.schema_version != expected_record_schema {
        bail!("Python execution admission record schema does not match its payload");
    }
    workspace::validate_prefixed_id(&record.admission_id, "admission_")?;
    workspace::validate_sha256(&record.record_digest)?;
    validate_payload(&record.payload)?;
    if workspace::digest_serialized(&record.payload)? != record.record_digest {
        bail!("Python execution admission record typed payload digest mismatch");
    }
    let inventory = python_qualifications::load_verified(
        workspace,
        &record.payload.inventory_qualification_ref.qualification_id,
    )?;
    if inventory.record_digest != record.payload.inventory_qualification_ref.record_digest {
        bail!("Python execution admission inventory qualification digest mismatch");
    }
    if inventory.payload.tool_ref.manifest_id != record.payload.tool_ref.manifest_id
        || inventory.payload.operation != record.payload.operation
    {
        bail!("Python execution admission inventory scope does not match the admission");
    }
    if let Some(source) = &record.payload.source_admission_ref {
        if record.payload.schema_version != "python_runtime_execution_admission/v2" {
            bail!("only python_runtime_execution_admission/v2 may cite a source admission");
        }
        let cited = load_verified(workspace, &source.admission_id)?;
        if cited.record_digest != source.record_digest {
            bail!("Python containment prove source admission digest mismatch");
        }
        if cited.payload.schema_version != "python_runtime_execution_admission/v1" {
            bail!("Python containment prove must cite a v1 admission");
        }
        if cited.payload.inventory_qualification_ref != record.payload.inventory_qualification_ref
            || cited.payload.tool_ref != record.payload.tool_ref
            || cited.payload.operation != record.payload.operation
        {
            bail!("Python containment prove source admission scope does not match");
        }
    }
    Ok(())
}

fn verification(record: &PythonRuntimeExecutionAdmissionRecord) -> PythonAdmissionVerification {
    PythonAdmissionVerification {
        admission_id: record.admission_id.clone(),
        record_digest: record.record_digest.clone(),
        inventory_qualification_id: record
            .payload
            .inventory_qualification_ref
            .qualification_id
            .clone(),
        tool_manifest_id: record.payload.tool_ref.manifest_id.clone(),
        operation: record.payload.operation.clone(),
        admission_state: "not_granted",
        blocker_codes: record.payload.admission_state.blocker_codes.clone(),
        execution_admission: "not_granted_by_residual_python_containment_blockers",
        authority_effect: "none",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_contract_validation::{
        parse_python_runtime_execution_admission, parse_python_runtime_execution_admission_record,
        parse_python_runtime_qualification,
    };
    use serde_json::{Value, json};
    use std::io::{Cursor, Write};

    const ADMISSION_EXAMPLE: &[u8] =
        include_bytes!("../contracts/examples/python-runtime-execution-admission-v1.example.json");
    const ADMISSION_RECORD_EXAMPLE: &[u8] = include_bytes!(
        "../contracts/examples/python-runtime-execution-admission-record-v1.example.json"
    );

    fn example_payload() -> PythonRuntimeExecutionAdmission {
        parse_python_runtime_execution_admission(ADMISSION_EXAMPLE).unwrap()
    }

    #[test]
    fn v1_has_no_granted_or_ready_escape_hatch() {
        let mut payload = example_payload();
        let mut value = serde_json::to_value(&payload).unwrap();
        value["admission_state"]["state"] = json!("granted");
        assert!(
            parse_python_runtime_execution_admission(&serde_json::to_vec(&value).unwrap()).is_err()
        );
        value["admission_state"]["state"] = json!("ready");
        assert!(
            parse_python_runtime_execution_admission(&serde_json::to_vec(&value).unwrap()).is_err()
        );
        payload.admission_state.state = PythonAdmissionStateValue::NotGranted;
        validate_payload(&payload).unwrap();
    }

    #[test]
    fn residual_checks_fail_closed_without_spawning_python() {
        let residual = evaluate_residual_checks();
        assert_eq!(residual.len(), RESIDUAL_CONTAINMENT_CODES.len());
        for code in RESIDUAL_CONTAINMENT_CODES {
            assert_eq!(
                residual.get(*code),
                Some(&PythonAdmissionCheckState::Failed),
                "{code}"
            );
            assert_ne!(
                residual.get(*code),
                Some(&PythonAdmissionCheckState::Satisfied)
            );
        }
        assert_eq!(
            prove_residual("unknown_residual"),
            PythonAdmissionCheckState::Failed
        );
    }

    #[test]
    fn v2_allows_job_and_process_limit_satisfied_but_not_granted() {
        let payload =
            parse_python_runtime_execution_admission(include_bytes!(
                "../contracts/examples/python-runtime-execution-admission-v2.example.json"
            ))
            .unwrap();
        assert_eq!(payload.schema_version, "python_runtime_execution_admission/v2");
        assert_eq!(
            payload.admission_state.state,
            PythonAdmissionStateValue::NotGranted
        );
        assert_eq!(
            payload.admission_state.blocker_codes,
            vec!["os_network_egress_denial".to_owned()]
        );
        let mut granted = serde_json::to_value(&payload).unwrap();
        granted["admission_state"]["state"] = json!("granted");
        assert!(
            parse_python_runtime_execution_admission(&serde_json::to_vec(&granted).unwrap())
                .is_err()
        );
        let mut network = payload.clone();
        network.checks[1].state = PythonAdmissionCheckState::Satisfied;
        network.admission_state.blocker_codes.clear();
        assert!(
            validate_payload(&network)
                .unwrap_err()
                .to_string()
                .contains("os_network_egress_denial")
        );
    }

    #[test]
    fn residual_containment_cannot_be_marked_satisfied() {
        let mut payload = example_payload();
        payload.checks[1].state = PythonAdmissionCheckState::Satisfied;
        payload
            .admission_state
            .blocker_codes
            .retain(|code| code != "os_network_egress_denial");
        assert!(
            validate_payload(&payload)
                .unwrap_err()
                .to_string()
                .contains(
                    "cannot mark residual containment check os_network_egress_denial satisfied"
                )
        );
    }

    #[test]
    fn digest_mismatch_and_payload_tamper_fail_closed() {
        let record =
            parse_python_runtime_execution_admission_record(ADMISSION_RECORD_EXAMPLE).unwrap();
        let mut value = serde_json::to_value(&record).unwrap();
        value["record_digest"] = json!("00".repeat(32));
        assert!(
            parse_python_runtime_execution_admission_record(&serde_json::to_vec(&value).unwrap())
                .unwrap_err()
                .to_string()
                .contains("digest mismatch")
        );
        value = serde_json::to_value(&record).unwrap();
        value["payload"]["operation"] = json!("greenwash_exact_range");
        assert!(
            parse_python_runtime_execution_admission_record(&serde_json::to_vec(&value).unwrap())
                .is_err()
        );
    }

    #[test]
    fn incomplete_inventory_payload_is_not_an_admission() {
        let inventory =
            include_bytes!("../contracts/examples/python-runtime-qualification-v1.example.json");
        assert!(parse_python_runtime_execution_admission(inventory).is_err());
        assert!(
            reject_inventory_as_admission("qualification_00000000000000000000000000000000")
                .unwrap_err()
                .to_string()
                .contains("cannot be used as a python_runtime_execution_admission")
        );
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let raw = String::from_utf8(ADMISSION_RECORD_EXAMPLE.to_vec()).unwrap();
        let duplicate = raw.replace(
            "\"schema_version\": \"python_runtime_execution_admission_record/v1\"",
            "\"schema_version\": \"python_runtime_execution_admission_record/v1\", \"schema_version\": \"python_runtime_execution_admission_record/v1\"",
        );
        assert!(parse_python_runtime_execution_admission_record(duplicate.as_bytes()).is_err());
    }

    #[test]
    fn example_typed_digest_matches_record() {
        let record =
            parse_python_runtime_execution_admission_record(ADMISSION_RECORD_EXAMPLE).unwrap();
        assert_eq!(
            record.record_digest,
            workspace::digest_serialized(&record.payload).unwrap()
        );
    }

    #[test]
    fn unknown_success_state_is_not_in_the_type() {
        let names = ["verified", "ready", "granted", "requirements_met"];
        let value: Value = serde_json::from_slice(ADMISSION_EXAMPLE).unwrap();
        for name in names {
            let mut forged = value.clone();
            forged["admission_state"]["state"] = json!(name);
            assert!(
                parse_python_runtime_execution_admission(&serde_json::to_vec(&forged).unwrap())
                    .is_err(),
                "{name} must stay unrepresentable"
            );
        }
    }

    #[test]
    fn bind_for_plan_rejects_operations_outside_the_vertical_slice() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = Workspace::init(temporary.path()).unwrap();
        let error = bind_for_plan(
            &workspace,
            Some("admission_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "greenwash",
            "greenwash_exact_range",
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("only accepted by trust_meter_measure or phaseledger_measure"),
            "{error}"
        );
    }

    #[test]
    fn validate_bound_ref_rejects_missing_or_mismatched_admission_without_granting() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = Workspace::init(temporary.path()).unwrap();
        assert!(
            validate_bound_ref(
                &workspace,
                Some(&PythonAdmissionRef {
                    admission_id: "admission_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                    record_digest: "00".repeat(32),
                }),
                "phaseledger",
                "phaseledger_measure",
            )
            .is_err()
        );
        assert!(list_verified(&workspace).unwrap().is_empty());
    }

    fn write_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        use zip::write::SimpleFileOptions;
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            for (name, bytes) in files {
                writer
                    .start_file(
                        *name,
                        SimpleFileOptions::default()
                            .compression_method(zip::CompressionMethod::Deflated),
                    )
                    .unwrap();
                writer.write_all(bytes).unwrap();
            }
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn closed_wheel(payload: &[u8]) -> (Vec<u8>, String) {
        let record = format!(
            "pkg/__init__.py,{},{}\n",
            record_hash(payload),
            payload.len()
        );
        let wheel = write_zip(&[
            ("pkg/__init__.py", payload),
            ("pkg-1.0.dist-info/RECORD", record.as_bytes()),
        ]);
        (wheel, record)
    }

    #[test]
    fn cpython_archive_requires_launcher_and_stdlib_zip() {
        let good = write_zip(&[("python.exe", b"launcher"), ("python313.zip", b"stdlib")]);
        assert!(is_stdlib_zip_name("python313.zip"));
        assert!(is_stdlib_zip_name("python310.zip"));
        assert!(!is_stdlib_zip_name("python3.zip"));
        assert!(!is_stdlib_zip_name("python3133.zip"));
        assert!(!is_stdlib_zip_name("Python313.zip"));
        assert_eq!(
            prove_cpython_archive(&good, "python.exe").unwrap(),
            "python313.zip"
        );
        let missing_stdlib = write_zip(&[("python.exe", b"launcher")]);
        assert!(prove_cpython_archive(&missing_stdlib, "python.exe").is_err());
        let extra_exe = write_zip(&[
            ("python.exe", b"launcher"),
            ("python313.zip", b"stdlib"),
            ("cmd.exe", b"nope"),
        ]);
        assert!(prove_cpython_archive(&extra_exe, "python.exe").is_err());
        assert!(prove_cpython_archive(b"not a zip", "python.exe").is_err());
        let traversal = write_zip(&[("../python.exe", b"launcher"), ("python313.zip", b"stdlib")]);
        assert!(prove_cpython_archive(&traversal, "python.exe").is_err());
        let collision = write_zip(&[
            ("python.exe", b"launcher"),
            ("Python.exe", b"other"),
            ("python313.zip", b"stdlib"),
        ]);
        assert!(prove_cpython_archive(&collision, "python.exe").is_err());
    }

    #[test]
    fn path_configuration_rejects_site_and_sitecustomize() {
        prove_path_configuration("python313.zip\nsite\n", Some("python313.zip")).unwrap();
        prove_path_configuration("python313.zip\n.\n", Some("python313.zip")).unwrap();
        assert!(
            prove_path_configuration("python313.zip\nimport site\n", Some("python313.zip"))
                .is_err()
        );
        assert!(
            prove_path_configuration("python313.zip\nsitecustomize\n", Some("python313.zip"))
                .is_err()
        );
        assert!(
            prove_path_configuration(
                "python313.zip\nC:/Users/me/AppData/Roaming/Python\n",
                Some("python313.zip")
            )
            .is_err()
        );
        assert!(prove_path_configuration("site\n", Some("python313.zip")).is_err());
    }

    #[test]
    fn wheel_record_closure_matches_members_and_rejects_tamper() {
        let payload = b"print('ok')\n";
        let (wheel, record) = closed_wheel(payload);
        assert!(prove_wheel_record_bytes(&wheel, record.as_bytes()).is_ok());
        let mut tampered = record.clone();
        tampered.push_str("extra.py,sha256=abcd,1\n");
        assert!(prove_wheel_record_bytes(&wheel, tampered.as_bytes()).is_err());
        let mismatch = record.replace(
            &record_hash(payload),
            "sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        assert!(prove_wheel_record_bytes(&wheel, mismatch.as_bytes()).is_err());
        let extra_member = write_zip(&[
            ("pkg/__init__.py", payload),
            ("extra.py", b"nope"),
            ("pkg-1.0.dist-info/RECORD", record.as_bytes()),
        ]);
        assert!(prove_wheel_record_bytes(&extra_member, record.as_bytes()).is_err());
    }

    #[test]
    fn launch_harness_requires_fixed_contract_and_embedded_wrapper_bytes() {
        let inventory = parse_python_runtime_qualification(include_bytes!(
            "../contracts/examples/python-runtime-qualification-v1.example.json"
        ))
        .unwrap();
        prove_launch_harness(&inventory, python_qualifications::WRAPPER_BYTES).unwrap();
        assert!(prove_launch_harness(&inventory, b"tampered-wrapper").is_err());
        let mut swapped = inventory.clone();
        swapped.runtime_inputs.wrapper.artifact.digest.value = "00".repeat(32);
        assert!(prove_launch_harness(&swapped, python_qualifications::WRAPPER_BYTES).is_err());
        let mut drifted = inventory;
        drifted.launch_contract.fixed_arguments = vec!["-I".to_owned()];
        assert!(prove_launch_harness(&drifted, python_qualifications::WRAPPER_BYTES).is_err());
    }

    fn prove_wheel_record_bytes(wheel: &[u8], installed: &[u8]) -> Result<()> {
        let dummy = dummy_record(wheel);
        let installed_record = dummy_record(installed);
        prove_wheel_record_closure(&[(
            (dummy, wheel.to_vec()),
            (installed_record, installed.to_vec()),
        )])
    }

    fn dummy_descriptor() -> crate::contracts::ArtifactDescriptor {
        crate::contracts::ArtifactDescriptor {
            artifact_id: "artifact_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            roles: vec!["fixture".to_owned()],
            media_type: "application/octet-stream".to_owned(),
            byte_length: 1,
            digest: crate::contracts::Digest {
                algorithm: "sha256".to_owned(),
                value: "11".repeat(32),
            },
            storage: crate::contracts::ArtifactStorage {
                uri: "cas:sha256:11".to_owned(),
            },
            origin: "native_file".to_owned(),
            capture: crate::contracts::ArtifactCapture {
                mode: "byte_for_byte_copy".to_owned(),
            },
            transforms: Vec::new(),
        }
    }

    fn dummy_record(bytes: &[u8]) -> crate::contracts::ArtifactRecord {
        let mut descriptor = dummy_descriptor();
        descriptor.digest.value = hex::encode(Sha256::digest(bytes));
        descriptor.byte_length = bytes.len() as u64;
        crate::contracts::ArtifactRecord {
            schema_version: "artifact_record/v1".to_owned(),
            record_digest: "22".repeat(32),
            artifact: descriptor,
        }
    }

    #[test]
    fn private_materialization_copies_exact_bytes_and_cleans_up() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = Workspace::init(temporary.path()).unwrap();
        let source = temporary.path().join("payload.bin");
        fs::write(&source, b"exact-copy").unwrap();
        let imported = workspace
            .import_artifact(
                &source,
                vec!["fixture".to_owned()],
                "application/octet-stream".to_owned(),
                "native_file",
                "byte_for_byte_copy",
            )
            .unwrap();
        let record = workspace.load_artifact(&imported.artifact_id).unwrap();
        let root = workspace
            .state
            .join("tmp")
            .join("admission-materialization-test");
        fs::create_dir(&root).unwrap();
        let dest = root.join("copy.bin");
        copy_verified_create_new(&workspace, &record, &dest).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"exact-copy");
        assert!(is_single_link(&dest).unwrap());
        let alias = root.join("hardlink.bin");
        fs::hard_link(&dest, &alias).unwrap();
        assert!(!is_single_link(&dest).unwrap());
        fs::remove_file(&alias).unwrap();
        assert!(is_single_link(&dest).unwrap());
        fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    #[cfg(windows)]
    fn closed_embed_admission() -> (
        tempfile::TempDir,
        Workspace,
        PythonRuntimeExecutionAdmissionRecord,
    ) {
        closed_embed_admission_with_launcher(b"embed-launcher")
    }

    #[cfg(windows)]
    fn closed_embed_admission_with_launcher(
        launcher: &[u8],
    ) -> (
        tempfile::TempDir,
        Workspace,
        PythonRuntimeExecutionAdmissionRecord,
    ) {
        use crate::contracts::RuntimeCapsule;

        let temporary = tempfile::tempdir().unwrap();
        let workspace = Workspace::init(temporary.path()).unwrap();
        let payload = b"print('phaseledger')\n";
        let (wheel, record) = closed_wheel(payload);
        let archive = write_zip(&[
            ("python.exe", launcher),
            ("python313.zip", b"stdlib-bytes"),
        ]);
        let path_configuration = b"python313.zip\nsite\n";

        let evidence_path = temporary.path().join("descriptor-claim.json");
        fs::write(&evidence_path, br#"{"descriptor_claim":"ready"}"#).unwrap();
        let evidence = workspace
            .import_artifact(
                &evidence_path,
                vec!["qualification_evidence".to_owned()],
                "application/json".to_owned(),
                "native_file",
                "byte_for_byte_copy",
            )
            .unwrap();

        let capsule_root = temporary.path().join("python-capsule-root");
        fs::create_dir_all(capsule_root.join("site/phaseledger-0.6.0.dist-info")).unwrap();
        fs::write(capsule_root.join("python.exe"), launcher).unwrap();
        fs::write(capsule_root.join("python313._pth"), path_configuration).unwrap();
        fs::write(
            capsule_root.join("site/phaseledger-0.6.0.dist-info/RECORD"),
            record.as_bytes(),
        )
        .unwrap();

        let capsule_id = "capsule_41414141414141414141414141414141";
        let mut descriptor = json!({
            "schema_version": "runtime-capsule/v1",
            "capsule_id": capsule_id,
            "platform": {"os":"windows","arch":"x86_64","abi":"cp313-win_amd64"},
            "launcher": {
                "kind": "interpreter",
                "path": "python.exe",
                "byte_length": launcher.len(),
                "digest": {"algorithm":"sha256","value":hex::encode(Sha256::digest(launcher))}
            },
            "supporting_files": [
                {
                    "path": "python313._pth",
                    "role": "path_configuration",
                    "byte_length": path_configuration.len(),
                    "digest": {"algorithm":"sha256","value":hex::encode(Sha256::digest(path_configuration))}
                },
                {
                    "path": "site/phaseledger-0.6.0.dist-info/RECORD",
                    "role": "installed_record",
                    "byte_length": record.len(),
                    "digest": {"algorithm":"sha256","value":hex::encode(Sha256::digest(record.as_bytes()))}
                }
            ],
            "transitive_closure": {
                "state": "complete",
                "inventory_digest": {"algorithm":"sha256","value":"00".repeat(32)},
                "declared_file_count": 2,
                "inventoried_file_count": 2,
                "missing_paths": []
            },
            "external_platform_assumptions": [],
            "operation_scope": {
                "tool_manifest_id": "phaseledger",
                "operations": ["phaseledger_measure"]
            },
            "qualification_evidence": [{
                "kind": "qualification_run",
                "artifact_id": evidence.artifact_id,
                "digest": evidence.digest,
                "observed_at": "2026-08-16T00:00:00Z",
                "scope": "descriptor-only readiness claim"
            }],
            "readiness": {"state":"ready","blocker_codes":[]},
            "authority_effect": "none"
        });
        let parsed: RuntimeCapsule = serde_json::from_value(descriptor.clone()).unwrap();
        descriptor["transitive_closure"]["inventory_digest"]["value"] =
            json!(workspace::digest_serialized(&parsed.supporting_files).unwrap());
        let descriptor_path = temporary.path().join("python-runtime-capsule.json");
        fs::write(
            &descriptor_path,
            serde_json::to_vec_pretty(&descriptor).unwrap(),
        )
        .unwrap();
        runtime_capsules::admit(&workspace, &descriptor_path, &capsule_root).unwrap();

        let archive_path = temporary.path().join("python-embed.zip");
        fs::write(&archive_path, &archive).unwrap();
        let archive_artifact = workspace
            .import_artifact(
                &archive_path,
                vec!["runtime_input".to_owned()],
                "application/zip".to_owned(),
                "native_file",
                "byte_for_byte_copy",
            )
            .unwrap();
        let wheel_path = temporary.path().join("phaseledger.whl");
        fs::write(&wheel_path, &wheel).unwrap();
        let wheel_artifact = workspace
            .import_artifact(
                &wheel_path,
                vec!["runtime_input".to_owned()],
                "application/zip".to_owned(),
                "native_file",
                "byte_for_byte_copy",
            )
            .unwrap();

        let inventory = python_qualifications::create(
            &workspace,
            capsule_id,
            &archive_artifact.artifact_id,
            "python313._pth",
            &[wheel_artifact.artifact_id],
            &["site/phaseledger-0.6.0.dist-info/RECORD".to_owned()],
        )
        .unwrap();
        let admission = admit(&workspace, &inventory.qualification_id).unwrap();
        (temporary, workspace, admission)
    }

    #[cfg(windows)]
    #[test]
    fn closed_embed_satisfies_implementable_proofs_but_stays_not_granted() {
        let (_temporary, workspace, admission) = closed_embed_admission();
        assert_eq!(
            admission.payload.admission_state.state,
            PythonAdmissionStateValue::NotGranted
        );
        assert_eq!(
            admission.payload.authority_effect,
            ContractAuthorityEffect::None
        );
        let check = |code: &str| {
            admission
                .payload
                .checks
                .iter()
                .find(|check| check.code == code)
                .unwrap()
                .state
                .clone()
        };
        assert_eq!(
            check("cpython_archive_semantics"),
            PythonAdmissionCheckState::Satisfied
        );
        assert_eq!(
            check("wheel_record_closure"),
            PythonAdmissionCheckState::Satisfied
        );
        assert_eq!(
            check("python_launch_harness"),
            PythonAdmissionCheckState::Satisfied
        );
        assert_eq!(
            check("python_path_configuration_isolation"),
            PythonAdmissionCheckState::Satisfied
        );
        assert_eq!(
            check("python_private_materialization"),
            PythonAdmissionCheckState::Satisfied
        );
        assert_eq!(
            check("os_network_egress_denial"),
            PythonAdmissionCheckState::Failed
        );
        assert_eq!(
            check("python_active_process_limit_one"),
            PythonAdmissionCheckState::Failed
        );
        assert_eq!(
            check("python_creation_time_job_assignment"),
            PythonAdmissionCheckState::Failed
        );
        assert_eq!(
            admission.payload.admission_state.blocker_codes,
            vec![
                "os_network_egress_denial".to_owned(),
                "python_active_process_limit_one".to_owned(),
                "python_creation_time_job_assignment".to_owned(),
            ]
        );
        for directory in ["plans", "runs", "executions"] {
            assert_eq!(
                fs::read_dir(workspace.state.join(directory))
                    .unwrap()
                    .count(),
                0
            );
        }
        let leftovers = fs::read_dir(workspace.state.join("tmp"))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("admission-")
            })
            .count();
        assert_eq!(leftovers, 0);
        let pin = crate::upstream_pins::get_for_tool("phaseledger").unwrap();
        assert_eq!(
            pin.pin.execution_readiness.state,
            crate::upstream_pins::ReadinessState::FailClosed
        );
        assert!(crate::upstream_pins::require_ready_for_planning("phaseledger").is_err());
        assert!(
            !crate::manifests::get("phaseledger")
                .unwrap()
                .manifest
                .enabled_by_default
        );
        let trust_meter = crate::upstream_pins::get_for_tool("trust-meter").unwrap();
        assert_eq!(
            trust_meter.pin.execution_readiness.state,
            crate::upstream_pins::ReadinessState::FailClosed
        );
        assert!(
            trust_meter
                .pin
                .execution_readiness
                .blocker_codes
                .iter()
                .any(|code| code == "ambient_ancestor_config_not_isolated")
        );
    }

    #[cfg(windows)]
    #[test]
    fn prove_containment_on_fake_launcher_stays_not_granted() {
        let (_temporary, workspace, admission) = closed_embed_admission();
        let proved = prove_containment(&workspace, &admission.admission_id).unwrap();
        assert_eq!(
            proved.payload.schema_version,
            "python_runtime_execution_admission/v2"
        );
        assert_eq!(
            proved.payload.admission_state.state,
            PythonAdmissionStateValue::NotGranted
        );
        assert_eq!(
            proved.payload.source_admission_ref.as_ref().unwrap().admission_id,
            admission.admission_id
        );
        let check = |code: &str| {
            proved
                .payload
                .checks
                .iter()
                .find(|check| check.code == code)
                .unwrap()
                .state
                .clone()
        };
        assert_eq!(
            check("os_network_egress_denial"),
            PythonAdmissionCheckState::Failed
        );
        assert_eq!(
            check("python_active_process_limit_one"),
            PythonAdmissionCheckState::Failed
        );
        assert_eq!(
            check("python_creation_time_job_assignment"),
            PythonAdmissionCheckState::Failed
        );
        for directory in ["plans", "runs", "executions"] {
            assert_eq!(
                fs::read_dir(workspace.state.join(directory))
                    .unwrap()
                    .count(),
                0
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn prove_containment_assigns_real_pe_at_create_process() {
        let launcher = fs::read(
            PathBuf::from(std::env::var_os("SystemRoot").unwrap())
                .join("System32")
                .join("where.exe"),
        )
        .unwrap();
        let (_temporary, workspace, admission) = closed_embed_admission_with_launcher(&launcher);
        let proved = prove_containment(&workspace, &admission.admission_id).unwrap();
        let check = |code: &str| {
            proved
                .payload
                .checks
                .iter()
                .find(|check| check.code == code)
                .unwrap()
                .state
                .clone()
        };
        assert_eq!(
            check("python_creation_time_job_assignment"),
            PythonAdmissionCheckState::Satisfied
        );
        assert_eq!(
            check("python_active_process_limit_one"),
            PythonAdmissionCheckState::Satisfied
        );
        assert_eq!(
            check("os_network_egress_denial"),
            PythonAdmissionCheckState::Failed
        );
        assert_eq!(
            proved.payload.admission_state.state,
            PythonAdmissionStateValue::NotGranted
        );
        assert_eq!(
            proved.payload.admission_state.blocker_codes,
            vec!["os_network_egress_denial".to_owned()]
        );
        assert!(crate::upstream_pins::require_ready_for_planning("phaseledger").is_err());
    }
}
