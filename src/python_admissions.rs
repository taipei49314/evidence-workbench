use crate::contracts::{
    ContractAuthorityEffect, NativeQualificationRef, PythonAdmissionCheck,
    PythonAdmissionCheckState, PythonAdmissionRef, PythonAdmissionState,
    PythonAdmissionStateValue, PythonRuntimeExecutionAdmission,
    PythonRuntimeExecutionAdmissionRecord, ToolRef, UpstreamPinRef,
};
use crate::python_qualifications;
use crate::{manifests, native, workspace};
use crate::workspace::Workspace;
use anyhow::{Context, Result, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use std::collections::BTreeSet;
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
    if payload.schema_version != "python_runtime_execution_admission/v1" {
        bail!("unsupported Python runtime execution admission schema");
    }
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
        bail!("python_runtime_execution_admission/v1 cannot represent a granted admission");
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
        if RESIDUAL_CONTAINMENT_CODES.contains(&check.code.as_str())
            && check.state == PythonAdmissionCheckState::Satisfied
        {
            bail!(
                "Python execution admission cannot mark residual containment check {} satisfied",
                check.code
            );
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
    let _ = IMPLEMENTABLE_CODES;
    Ok(())
}

pub fn admit(workspace: &Workspace, inventory_qualification_id: &str) -> Result<PythonRuntimeExecutionAdmissionRecord> {
    let inventory_record = python_qualifications::load_verified(workspace, inventory_qualification_id)?;
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
    let launch = &inventory_record.payload.launch_contract;
    let launch_isolated = launch.mode == "direct_exec"
        && launch.fixed_arguments == ["-I", "-S", "-B", "-X", "utf8"]
        && launch.environment.inheritance == "none"
        && launch.environment.other_variables == "absent"
        && launch
            .environment
            .variables
            .iter()
            .any(|variable| variable.name == "PATH" && variable.source == "ewb_owned_empty_directory");
    let path_artifact = workspace.load_artifact(
        &inventory_record
            .payload
            .runtime_inputs
            .path_configuration
            .artifact
            .artifact_ref
            .artifact_id,
    )?;
    let path_bytes = workspace.verify_descriptor(&path_artifact.artifact)?;
    let path_text = std::fs::read_to_string(&path_bytes).unwrap_or_default();
    let path_isolated = !path_text.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == "import site" || trimmed.starts_with("import site ")
    });

    let mut checks = Vec::new();
    for code in CHECK_CODES {
        let state = match *code {
            "python_launch_harness" if launch_isolated => PythonAdmissionCheckState::Satisfied,
            "python_path_configuration_isolation" if path_isolated => {
                PythonAdmissionCheckState::Satisfied
            }
            _ => PythonAdmissionCheckState::NotImplemented,
        };
        checks.push(PythonAdmissionCheck {
            code: (*code).to_owned(),
            state,
            evidence_refs: Vec::new(),
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
                bail!("Python execution admission digest does not match the caller-retained digest");
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
    if record.schema_version != "python_runtime_execution_admission_record/v1" {
        bail!("unsupported Python runtime execution admission record schema");
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
    };
    use serde_json::{Value, json};

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
    fn residual_containment_cannot_be_marked_satisfied() {
        let mut payload = example_payload();
        payload.checks[1].state = PythonAdmissionCheckState::Satisfied;
        payload.admission_state.blocker_codes.retain(|code| code != "os_network_egress_denial");
        assert!(validate_payload(&payload).unwrap_err().to_string().contains(
            "cannot mark residual containment check os_network_egress_denial satisfied"
        ));
    }

    #[test]
    fn digest_mismatch_and_payload_tamper_fail_closed() {
        let record = parse_python_runtime_execution_admission_record(ADMISSION_RECORD_EXAMPLE)
            .unwrap();
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
        let inventory = include_bytes!(
            "../contracts/examples/python-runtime-qualification-v1.example.json"
        );
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
        let record = parse_python_runtime_execution_admission_record(ADMISSION_RECORD_EXAMPLE)
            .unwrap();
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
}
