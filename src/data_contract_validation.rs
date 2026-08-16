use crate::contracts::{
    AuditReceipt, AuditTopology, CapsuleClosureState, CapsuleReadinessState, ContractArtifactRef,
    Digest, EvidenceHandoff, IdeHandoff, PhaseledgerCallerObservation, PlanRecordRef,
    PlatformAssumptionState, PythonRuntimeExecutionAdmission,
    PythonRuntimeExecutionAdmissionRecord, PythonRuntimeQualification,
    PythonRuntimeQualificationRecord, RunRecordRef, RuntimeCapsule, SubjectCandidate,
};
use crate::strict_json;
use anyhow::{Context, Result, bail};
use chrono::DateTime;
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub fn parse_subject_candidate(bytes: &[u8]) -> Result<SubjectCandidate> {
    let candidate = parse_contract(bytes, "subject candidate")?;
    validate_subject_candidate(&candidate)?;
    Ok(candidate)
}

pub fn parse_runtime_capsule(bytes: &[u8]) -> Result<RuntimeCapsule> {
    let capsule = parse_contract(bytes, "runtime capsule")?;
    validate_runtime_capsule(&capsule)?;
    Ok(capsule)
}

pub fn parse_python_runtime_qualification(bytes: &[u8]) -> Result<PythonRuntimeQualification> {
    let qualification = parse_contract(bytes, "Python runtime qualification")?;
    crate::python_qualifications::validate_payload(&qualification)?;
    Ok(qualification)
}

pub fn parse_python_runtime_qualification_record(
    bytes: &[u8],
) -> Result<PythonRuntimeQualificationRecord> {
    let record: PythonRuntimeQualificationRecord =
        parse_contract(bytes, "Python runtime qualification record")?;
    if record.schema_version != "python_runtime_qualification_record/v1" {
        bail!("unsupported Python runtime qualification record schema");
    }
    validate_prefixed_id(
        &record.qualification_id,
        "qualification_",
        "Python runtime qualification id",
    )?;
    validate_sha256(&record.record_digest, "Python runtime qualification record")?;
    crate::python_qualifications::validate_payload(&record.payload)?;
    let actual = hex::encode(Sha256::digest(serde_json::to_vec(&record.payload)?));
    if actual != record.record_digest {
        bail!("Python runtime qualification record typed payload digest mismatch");
    }
    Ok(record)
}

pub fn parse_python_runtime_execution_admission(
    bytes: &[u8],
) -> Result<PythonRuntimeExecutionAdmission> {
    let admission = parse_contract(bytes, "Python runtime execution admission")?;
    crate::python_admissions::validate_payload(&admission)?;
    Ok(admission)
}

pub fn parse_python_runtime_execution_admission_record(
    bytes: &[u8],
) -> Result<PythonRuntimeExecutionAdmissionRecord> {
    let record: PythonRuntimeExecutionAdmissionRecord =
        parse_contract(bytes, "Python runtime execution admission record")?;
    if record.schema_version != "python_runtime_execution_admission_record/v1"
        && record.schema_version != "python_runtime_execution_admission_record/v2"
    {
        bail!("unsupported Python runtime execution admission record schema");
    }
    validate_prefixed_id(&record.admission_id, "admission_", "Python execution admission id")?;
    validate_sha256(&record.record_digest, "Python execution admission record")?;
    crate::python_admissions::validate_payload(&record.payload)?;
    let actual = hex::encode(Sha256::digest(serde_json::to_vec(&record.payload)?));
    if actual != record.record_digest {
        bail!("Python execution admission record typed payload digest mismatch");
    }
    Ok(record)
}

pub fn parse_phaseledger_caller_observation(bytes: &[u8]) -> Result<PhaseledgerCallerObservation> {
    let observation = parse_contract(bytes, "Phaseledger caller observation")?;
    crate::caller_observations::validate(&observation)?;
    Ok(observation)
}

pub fn parse_ide_handoff(bytes: &[u8]) -> Result<IdeHandoff> {
    let handoff = parse_contract(bytes, "IDE handoff")?;
    validate_ide_handoff(&handoff)?;
    Ok(handoff)
}

pub fn parse_evidence_handoff(bytes: &[u8]) -> Result<EvidenceHandoff> {
    let handoff = parse_contract(bytes, "evidence handoff")?;
    validate_evidence_handoff(&handoff)?;
    Ok(handoff)
}

pub fn parse_audit_topology(bytes: &[u8]) -> Result<AuditTopology> {
    let topology = parse_contract(bytes, "audit topology")?;
    validate_audit_topology(&topology)?;
    Ok(topology)
}

pub fn parse_audit_receipt(bytes: &[u8]) -> Result<AuditReceipt> {
    let receipt = parse_contract(bytes, "audit receipt")?;
    validate_audit_receipt(&receipt)?;
    Ok(receipt)
}

pub fn parse_cli_envelope(bytes: &[u8]) -> Result<serde_json::Value> {
    let value = strict_json::parse_strict(bytes).context("invalid EWB CLI envelope")?;
    validate_cli_envelope(&value)?;
    Ok(value)
}

pub fn validate_cli_envelope(value: &serde_json::Value) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("EWB CLI envelope must be an object"))?;
    match object.get("ok") {
        Some(serde_json::Value::Bool(true)) => {
            validate_exact_object_keys(object, &["ok", "command", "data"], "success envelope")?;
            let command = object
                .get("command")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("success envelope command must be a string"))?;
            validate_cli_command(command)?;
        }
        Some(serde_json::Value::Bool(false)) => {
            validate_exact_object_keys(object, &["ok", "error"], "failure envelope")?;
            let error = object
                .get("error")
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| anyhow::anyhow!("failure envelope error must be an object"))?;
            validate_exact_object_keys(error, &["code", "message"], "CLI error")?;
            let code = error
                .get("code")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("CLI error code must be a string"))?;
            validate_cli_error_code(code)?;
            let message = error
                .get("message")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("CLI error message must be a string"))?;
            if message.is_empty() {
                bail!("CLI error message must not be empty");
            }
        }
        _ => bail!("EWB CLI envelope ok must be a boolean"),
    }
    Ok(())
}

fn parse_contract<T: DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T> {
    let value = strict_json::parse_strict(bytes).with_context(|| format!("invalid {label}"))?;
    serde_json::from_value(value).with_context(|| format!("invalid {label} shape"))
}

pub fn validate_subject_candidate(candidate: &SubjectCandidate) -> Result<()> {
    if candidate.schema_version != "subject-candidate/v1" {
        bail!("unsupported subject candidate schema");
    }
    validate_prefixed_id(&candidate.candidate_id, "candidate_", "candidate id")?;
    if candidate.producer.id != "github-radar" {
        bail!("subject-candidate/v1 is restricted to github-radar observations");
    }
    validate_nonempty(&candidate.producer.version, "producer version")?;
    if candidate.producer.version.contains('\0') {
        bail!("producer version cannot contain the candidate-id field separator");
    }
    validate_github_repository_url(&candidate.repository_url)?;
    validate_git_sha1(&candidate.resolved_source.commit_sha, "resolved commit")?;
    validate_git_sha1(&candidate.resolved_source.tree_sha, "resolved tree")?;
    validate_timestamp(&candidate.observed_at, "candidate observation time")?;
    validate_contract_artifact_ref(&candidate.source_artifact, "source artifact")?;
    let seed = [
        "subject-candidate/v1",
        "github-radar",
        candidate.producer.version.as_str(),
        candidate.repository_url.as_str(),
        candidate.resolved_source.commit_sha.as_str(),
        candidate.resolved_source.tree_sha.as_str(),
        candidate.source_artifact.artifact_id.as_str(),
        candidate.source_artifact.digest.value.as_str(),
    ]
    .join("\0");
    let expected_id = format!(
        "candidate_{}",
        &hex::encode(Sha256::digest(seed.as_bytes()))[..32]
    );
    if candidate.candidate_id != expected_id {
        bail!("subject candidate id does not match its content-derived identity");
    }
    if candidate.limitations.is_empty() {
        bail!("an untrusted subject candidate must report at least one limitation");
    }
    let mut limitation_codes = BTreeSet::new();
    for limitation in &candidate.limitations {
        validate_identifier(&limitation.code, 64, "candidate limitation code")?;
        validate_nonempty(&limitation.statement, "candidate limitation statement")?;
        if !limitation_codes.insert(limitation.code.as_str()) {
            bail!("candidate limitation codes must be unique");
        }
    }
    Ok(())
}

pub fn validate_runtime_capsule(capsule: &RuntimeCapsule) -> Result<()> {
    if capsule.schema_version != "runtime-capsule/v1" {
        bail!("unsupported runtime capsule schema");
    }
    validate_prefixed_id(&capsule.capsule_id, "capsule_", "capsule id")?;
    validate_platform_component(&capsule.platform.os, "platform OS")?;
    validate_platform_component(&capsule.platform.arch, "platform architecture")?;
    validate_platform_component(&capsule.platform.abi, "platform ABI")?;
    validate_capsule_path(&capsule.launcher.path, "launcher path")?;
    if capsule.launcher.byte_length == 0 {
        bail!("capsule launcher must contain bytes");
    }
    validate_digest(&capsule.launcher.digest, "launcher")?;

    let mut inventory_paths = BTreeSet::new();
    for file in &capsule.supporting_files {
        validate_capsule_path(&file.path, "supporting file path")?;
        if file.path == capsule.launcher.path {
            bail!("launcher must not be duplicated in the supporting-file inventory");
        }
        if !inventory_paths.insert(file.path.as_str()) {
            bail!("supporting-file paths must be unique");
        }
        validate_identifier(&file.role, 64, "supporting file role")?;
        validate_digest(&file.digest, "supporting file")?;
    }

    validate_digest(
        &capsule.transitive_closure.inventory_digest,
        "runtime inventory",
    )?;
    let actual_inventory_count = u64::try_from(capsule.supporting_files.len())
        .context("supporting-file inventory is too large")?;
    if capsule
        .supporting_files
        .windows(2)
        .any(|pair| pair[0].path >= pair[1].path)
    {
        bail!("runtime capsule supporting files must be ordered by path");
    }
    let inventory_bytes = serde_json::to_vec(&capsule.supporting_files)?;
    let actual_inventory_digest = hex::encode(Sha256::digest(inventory_bytes));
    if capsule.transitive_closure.inventory_digest.value != actual_inventory_digest {
        bail!("runtime capsule supporting-file inventory digest mismatch");
    }
    if capsule.transitive_closure.inventoried_file_count != actual_inventory_count {
        bail!("transitive closure count does not match the supporting-file inventory");
    }
    if capsule.transitive_closure.declared_file_count
        < capsule.transitive_closure.inventoried_file_count
    {
        bail!("declared runtime closure cannot be smaller than its inventory");
    }
    let mut missing_paths = BTreeSet::new();
    for path in &capsule.transitive_closure.missing_paths {
        validate_capsule_path(path, "missing closure path")?;
        if inventory_paths.contains(path.as_str()) || !missing_paths.insert(path.as_str()) {
            bail!("missing closure paths must be unique and absent from the inventory");
        }
    }
    match capsule.transitive_closure.state {
        CapsuleClosureState::Complete => {
            if capsule.transitive_closure.declared_file_count
                != capsule.transitive_closure.inventoried_file_count
                || !capsule.transitive_closure.missing_paths.is_empty()
            {
                bail!("a complete runtime closure must account for every declared file");
            }
        }
        CapsuleClosureState::Incomplete => {
            if capsule.transitive_closure.declared_file_count
                == capsule.transitive_closure.inventoried_file_count
                && capsule.transitive_closure.missing_paths.is_empty()
            {
                bail!("an incomplete runtime closure must identify an accounting gap");
            }
        }
    }

    let mut assumption_codes = BTreeSet::new();
    let mut has_unresolved_assumption = false;
    for assumption in &capsule.external_platform_assumptions {
        validate_identifier(&assumption.code, 64, "platform assumption code")?;
        validate_nonempty(&assumption.statement, "platform assumption statement")?;
        if !assumption_codes.insert(assumption.code.as_str()) {
            bail!("external platform assumption codes must be unique");
        }
        has_unresolved_assumption |= assumption.state == PlatformAssumptionState::Unresolved;
    }

    validate_tool_id(&capsule.operation_scope.tool_manifest_id)?;
    if capsule.operation_scope.operations.is_empty() {
        bail!("runtime capsule operation scope must not be empty");
    }
    let mut operations = BTreeSet::new();
    for operation in &capsule.operation_scope.operations {
        validate_identifier(operation, 64, "operation id")?;
        if !operations.insert(operation.as_str()) {
            bail!("runtime capsule operation ids must be unique");
        }
    }

    let mut qualification_artifacts = BTreeSet::new();
    for evidence in &capsule.qualification_evidence {
        validate_artifact_id(&evidence.artifact_id)?;
        validate_digest(&evidence.digest, "qualification evidence")?;
        validate_timestamp(
            &evidence.observed_at,
            "qualification evidence observation time",
        )?;
        validate_nonempty(&evidence.scope, "qualification evidence scope")?;
        if !qualification_artifacts.insert(evidence.artifact_id.as_str()) {
            bail!("qualification evidence artifact ids must be unique");
        }
    }

    let mut blockers = BTreeSet::new();
    for blocker in &capsule.readiness.blocker_codes {
        validate_identifier(blocker, 64, "runtime readiness blocker")?;
        if !blockers.insert(blocker.as_str()) {
            bail!("runtime readiness blockers must be unique");
        }
    }
    match capsule.readiness.state {
        CapsuleReadinessState::Ready => {
            if capsule.transitive_closure.state != CapsuleClosureState::Complete {
                bail!("runtime closure is incomplete; capsule must fail closed");
            }
            if has_unresolved_assumption {
                bail!("unresolved external platform assumptions must fail closed");
            }
            if capsule.qualification_evidence.is_empty() {
                bail!("a ready runtime capsule requires qualification evidence");
            }
            if !capsule.readiness.blocker_codes.is_empty() {
                bail!("a ready runtime capsule cannot carry blockers");
            }
        }
        CapsuleReadinessState::FailClosed => {
            if capsule.readiness.blocker_codes.is_empty() {
                bail!("a fail-closed runtime capsule must identify a blocker");
            }
            if capsule.transitive_closure.state == CapsuleClosureState::Incomplete
                && !blockers.contains("runtime_closure_incomplete")
            {
                bail!("incomplete runtime closure must carry runtime_closure_incomplete");
            }
            if has_unresolved_assumption
                && !blockers.contains("external_platform_assumption_unresolved")
            {
                bail!(
                    "unresolved platform assumptions must carry external_platform_assumption_unresolved"
                );
            }
        }
    }
    Ok(())
}

pub fn validate_ide_handoff(handoff: &IdeHandoff) -> Result<()> {
    if handoff.schema_version != "ide-handoff/v1" {
        bail!("unsupported IDE handoff schema");
    }
    validate_prefixed_id(&handoff.handoff_id, "handoff_", "handoff id")?;
    validate_timestamp(&handoff.created_at, "IDE handoff creation time")?;
    if handoff.plan_refs.is_empty()
        && handoff.run_refs.is_empty()
        && handoff.artifact_refs.is_empty()
    {
        bail!("IDE handoff must reference at least one EWB record");
    }

    let mut plan_ids = BTreeSet::new();
    for reference in &handoff.plan_refs {
        validate_prefixed_id(&reference.plan_id, "plan_", "plan id")?;
        validate_sha256(&reference.record_digest, "plan record")?;
        if !plan_ids.insert(reference.plan_id.as_str()) {
            bail!("IDE handoff plan ids must be unique");
        }
    }
    let mut run_ids = BTreeSet::new();
    for reference in &handoff.run_refs {
        validate_prefixed_id(&reference.run_id, "run_", "run id")?;
        validate_sha256(&reference.record_digest, "run record")?;
        if !run_ids.insert(reference.run_id.as_str()) {
            bail!("IDE handoff run ids must be unique");
        }
    }
    let mut artifact_ids = BTreeSet::new();
    for reference in &handoff.artifact_refs {
        validate_artifact_id(&reference.artifact_id)?;
        validate_sha256(&reference.record_digest, "artifact record")?;
        if !artifact_ids.insert(reference.artifact_id.as_str()) {
            bail!("IDE handoff artifact ids must be unique");
        }
    }

    let mut namespace_run_ids = BTreeSet::new();
    for entry in &handoff.native_namespaces {
        validate_prefixed_id(&entry.run_id, "run_", "native namespace run id")?;
        if !namespace_run_ids.insert(entry.run_id.as_str()) {
            bail!("IDE handoff may provide one native namespace map per run");
        }
        let mut namespaces = BTreeSet::new();
        for namespace in &entry.namespaces {
            validate_identifier(namespace, 64, "native namespace")?;
            if !namespaces.insert(namespace.as_str()) {
                bail!("native namespaces must be unique within a run");
            }
        }
    }
    let mut authority_run_ids = BTreeSet::new();
    for entry in &handoff.native_authority_availability {
        validate_prefixed_id(&entry.run_id, "run_", "native authority run id")?;
        if !authority_run_ids.insert(entry.run_id.as_str()) {
            bail!("IDE handoff may provide one authority availability per run");
        }
    }
    if namespace_run_ids != run_ids || authority_run_ids != run_ids {
        bail!("native namespace and authority availability maps must match exact run refs");
    }
    Ok(())
}

pub fn validate_evidence_handoff(handoff: &EvidenceHandoff) -> Result<()> {
    if handoff.schema_version != "evidence-handoff/v1" {
        bail!("unsupported evidence handoff schema");
    }
    validate_prefixed_id(&handoff.handoff_id, "handoff_", "handoff id")?;
    validate_timestamp(&handoff.created_at, "evidence handoff creation time")?;
    validate_prefixed_id(
        &handoff.producer_plan_ref.plan_id,
        "plan_",
        "producer plan id",
    )?;
    validate_sha256(
        &handoff.producer_plan_ref.record_digest,
        "producer plan record",
    )?;
    validate_prefixed_id(&handoff.producer_run_ref.run_id, "run_", "producer run id")?;
    validate_sha256(
        &handoff.producer_run_ref.record_digest,
        "producer run record",
    )?;
    validate_artifact_id(&handoff.artifact_ref.artifact_id)?;
    validate_sha256(&handoff.artifact_ref.record_digest, "artifact record")?;
    Ok(())
}

pub fn validate_audit_topology(topology: &AuditTopology) -> Result<()> {
    if topology.schema_version != "audit-topology/v1" {
        bail!("unsupported audit topology schema");
    }
    validate_prefixed_id(&topology.topology_id, "topology_", "audit topology id")?;
    if topology.steps.is_empty() {
        bail!("audit topology must contain at least one step");
    }

    let mut step_ids = BTreeSet::new();
    let mut plan_ids = BTreeSet::new();
    let mut previous_step_id = None;
    for step in &topology.steps {
        validate_prefixed_id(&step.step_id, "step_", "audit topology step id")?;
        if previous_step_id.is_some_and(|previous| previous >= step.step_id.as_str()) {
            bail!("audit topology steps must be ordered by unique step id");
        }
        previous_step_id = Some(step.step_id.as_str());
        if !step_ids.insert(step.step_id.as_str()) {
            bail!("audit topology step ids must be unique");
        }
        validate_plan_record_ref(&step.plan_ref, "audit topology plan")?;
        if !plan_ids.insert(step.plan_ref.plan_id.as_str()) {
            bail!("audit topology plan ids must be unique");
        }

        let mut predecessor_ids = BTreeSet::new();
        let mut previous_predecessor_id = None;
        for predecessor_id in &step.predecessor_step_ids {
            validate_prefixed_id(
                predecessor_id,
                "step_",
                "audit topology predecessor step id",
            )?;
            if predecessor_id == &step.step_id {
                bail!("audit topology step cannot depend on itself");
            }
            if previous_predecessor_id.is_some_and(|previous| previous >= predecessor_id.as_str()) {
                bail!("audit topology predecessor ids must be ordered and unique");
            }
            previous_predecessor_id = Some(predecessor_id.as_str());
            if !predecessor_ids.insert(predecessor_id.as_str()) {
                bail!("audit topology predecessor ids must be unique within a step");
            }
        }
    }

    for step in &topology.steps {
        for predecessor_id in &step.predecessor_step_ids {
            if !step_ids.contains(predecessor_id.as_str()) {
                bail!("audit topology predecessor references an unknown step");
            }
        }
    }

    let mut in_degree = topology
        .steps
        .iter()
        .map(|step| (step.step_id.clone(), step.predecessor_step_ids.len()))
        .collect::<BTreeMap<_, _>>();
    let mut successors = BTreeMap::<String, Vec<String>>::new();
    for step in &topology.steps {
        for predecessor_id in &step.predecessor_step_ids {
            successors
                .entry(predecessor_id.clone())
                .or_default()
                .push(step.step_id.clone());
        }
    }
    let mut ready = in_degree
        .iter()
        .filter_map(|(step_id, degree)| (*degree == 0).then_some(step_id.clone()))
        .collect::<BTreeSet<_>>();
    let mut visited = 0usize;
    while let Some(step_id) = ready.pop_first() {
        visited += 1;
        if let Some(next_steps) = successors.get(&step_id) {
            for next_step_id in next_steps {
                let degree = in_degree
                    .get_mut(next_step_id)
                    .expect("validated successor must be a topology step");
                *degree -= 1;
                if *degree == 0 {
                    ready.insert(next_step_id.clone());
                }
            }
        }
    }
    if visited != topology.steps.len() {
        bail!("audit topology predecessor graph must be acyclic");
    }
    Ok(())
}

pub fn validate_audit_receipt(receipt: &AuditReceipt) -> Result<()> {
    if receipt.schema_version != "audit-receipt/v1" {
        bail!("unsupported audit receipt schema");
    }
    validate_prefixed_id(
        &receipt.topology_ref.topology_id,
        "topology_",
        "audit receipt topology id",
    )?;
    validate_sha256(
        &receipt.topology_ref.topology_digest,
        "audit receipt topology",
    )?;
    if receipt.recorded_runs.is_empty() {
        bail!("audit receipt must reference at least one recorded run");
    }

    let mut step_ids = BTreeSet::new();
    let mut plan_ids = BTreeSet::new();
    let mut run_ids = BTreeSet::new();
    let mut previous_step_id = None;
    for recorded_run in &receipt.recorded_runs {
        validate_prefixed_id(&recorded_run.step_id, "step_", "audit receipt step id")?;
        if previous_step_id.is_some_and(|previous| previous >= recorded_run.step_id.as_str()) {
            bail!("audit receipt recorded runs must be ordered by unique step id");
        }
        previous_step_id = Some(recorded_run.step_id.as_str());
        if !step_ids.insert(recorded_run.step_id.as_str()) {
            bail!("audit receipt step ids must be unique");
        }
        validate_plan_record_ref(&recorded_run.plan_ref, "audit receipt plan")?;
        if !plan_ids.insert(recorded_run.plan_ref.plan_id.as_str()) {
            bail!("audit receipt plan ids must be unique");
        }
        validate_run_record_ref(&recorded_run.run_ref, "audit receipt run")?;
        if !run_ids.insert(recorded_run.run_ref.run_id.as_str()) {
            bail!("audit receipt run ids must be unique");
        }
    }
    Ok(())
}

pub fn validate_audit_receipt_against_topology(
    receipt: &AuditReceipt,
    topology: &AuditTopology,
) -> Result<()> {
    validate_audit_topology(topology)?;
    validate_audit_receipt(receipt)?;
    if receipt.topology_ref.topology_id != topology.topology_id {
        bail!("audit receipt topology id does not match the referenced topology");
    }
    let topology_bytes =
        serde_json::to_vec(topology).context("serialize typed audit topology for digest")?;
    let topology_digest = hex::encode(Sha256::digest(topology_bytes));
    if receipt.topology_ref.topology_digest != topology_digest {
        bail!("audit receipt topology digest does not match the referenced topology");
    }

    let topology_steps = topology
        .steps
        .iter()
        .map(|step| (step.step_id.as_str(), step))
        .collect::<BTreeMap<_, _>>();
    for recorded_run in &receipt.recorded_runs {
        let topology_step = topology_steps
            .get(recorded_run.step_id.as_str())
            .ok_or_else(|| anyhow::anyhow!("audit receipt references an unknown topology step"))?;
        if recorded_run.plan_ref != topology_step.plan_ref {
            bail!("audit receipt plan reference does not match its topology step");
        }
    }
    Ok(())
}

fn validate_plan_record_ref(reference: &PlanRecordRef, label: &str) -> Result<()> {
    validate_prefixed_id(&reference.plan_id, "plan_", &format!("{label} id"))?;
    validate_sha256(&reference.record_digest, label)
}

fn validate_run_record_ref(reference: &RunRecordRef, label: &str) -> Result<()> {
    validate_prefixed_id(&reference.run_id, "run_", &format!("{label} id"))?;
    validate_sha256(&reference.record_digest, label)
}

fn validate_contract_artifact_ref(reference: &ContractArtifactRef, label: &str) -> Result<()> {
    validate_artifact_id(&reference.artifact_id)?;
    validate_digest(&reference.digest, label)
}

fn validate_digest(digest: &Digest, label: &str) -> Result<()> {
    if digest.algorithm != "sha256" {
        bail!("{label} digest must use sha256");
    }
    validate_sha256(&digest.value, label)
}

fn validate_artifact_id(value: &str) -> Result<()> {
    validate_prefixed_id(value, "artifact_", "artifact id")
}

fn validate_prefixed_id(value: &str, prefix: &str, label: &str) -> Result<()> {
    let suffix = value
        .strip_prefix(prefix)
        .ok_or_else(|| anyhow::anyhow!("invalid {label}"))?;
    if suffix.len() != 32 || !is_lower_hex(suffix) {
        bail!("invalid {label}");
    }
    Ok(())
}

fn validate_git_sha1(value: &str, label: &str) -> Result<()> {
    if value.len() != 40 || !is_lower_hex(value) {
        bail!("{label} must be a lowercase 40-hex Git object id");
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64 || !is_lower_hex(value) {
        bail!("{label} must use a lowercase 64-hex SHA-256 digest");
    }
    Ok(())
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_timestamp(value: &str, label: &str) -> Result<()> {
    DateTime::parse_from_rfc3339(value).with_context(|| format!("{label} is not RFC 3339"))?;
    Ok(())
}

fn validate_nonempty(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.trim() != value {
        bail!("{label} must be a non-empty trimmed string");
    }
    Ok(())
}

fn validate_identifier(value: &str, max_length: usize, label: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= max_length
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
        && !value.starts_with(['_', '-'])
        && !value.ends_with(['_', '-']);
    if !valid {
        bail!("invalid {label}");
    }
    Ok(())
}

fn validate_exact_object_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    expected: &[&str],
    label: &str,
) -> Result<()> {
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        bail!("{label} fields do not match ewb-cli-envelope/v1");
    }
    Ok(())
}

fn validate_cli_command(value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.split('.').all(|component| {
            let mut bytes = component.bytes();
            matches!(bytes.next(), Some(first) if first.is_ascii_lowercase())
                && bytes.all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'_' | b'-')
                })
        });
    if !valid {
        bail!("invalid EWB CLI command identifier");
    }
    Ok(())
}

fn validate_cli_error_code(value: &str) -> Result<()> {
    let mut bytes = value.bytes();
    let valid = value.len() <= 64
        && matches!(bytes.next(), Some(first) if first.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
    if !valid {
        bail!("invalid EWB CLI error code");
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
        bail!("invalid {label}");
    }
    Ok(())
}

fn validate_tool_id(value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-');
    if !valid {
        bail!("invalid tool manifest id");
    }
    Ok(())
}

fn validate_github_repository_url(value: &str) -> Result<()> {
    let repository = value
        .strip_prefix("https://github.com/")
        .ok_or_else(|| anyhow::anyhow!("subject candidate repository must use GitHub HTTPS"))?;
    let parts = repository.split('/').collect::<Vec<_>>();
    if parts.len() != 2
        || parts.iter().any(|part| {
            part.is_empty()
                || matches!(*part, "." | "..")
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        bail!("subject candidate repository must be an exact GitHub repository URL");
    }
    Ok(())
}

fn validate_capsule_path(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.contains('\\')
        || value.contains(':')
        || value.starts_with('/')
        || value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        bail!("{label} must be a normalized relative capsule path");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const SUBJECT_EXAMPLE: &[u8] =
        include_bytes!("../contracts/examples/subject-candidate-v1.example.json");
    const CAPSULE_EXAMPLE: &[u8] =
        include_bytes!("../contracts/examples/runtime-capsule-v1.example.json");
    const PYTHON_QUALIFICATION_EXAMPLE: &[u8] =
        include_bytes!("../contracts/examples/python-runtime-qualification-v1.example.json");
    const PYTHON_QUALIFICATION_RECORD_EXAMPLE: &[u8] =
        include_bytes!("../contracts/examples/python-runtime-qualification-record-v1.example.json");
    const PYTHON_ADMISSION_EXAMPLE: &[u8] = include_bytes!(
        "../contracts/examples/python-runtime-execution-admission-v1.example.json"
    );
    const PYTHON_ADMISSION_RECORD_EXAMPLE: &[u8] = include_bytes!(
        "../contracts/examples/python-runtime-execution-admission-record-v1.example.json"
    );
    const PYTHON_ADMISSION_V2_EXAMPLE: &[u8] = include_bytes!(
        "../contracts/examples/python-runtime-execution-admission-v2.example.json"
    );
    const PYTHON_ADMISSION_RECORD_V2_EXAMPLE: &[u8] = include_bytes!(
        "../contracts/examples/python-runtime-execution-admission-record-v2.example.json"
    );
    const PHASELEDGER_CALLER_OBSERVATION_EXAMPLE: &[u8] =
        include_bytes!("../contracts/examples/phaseledger-caller-observation-v1.example.json");
    const HANDOFF_EXAMPLE: &[u8] =
        include_bytes!("../contracts/examples/ide-handoff-v1.example.json");
    const EVIDENCE_HANDOFF_EXAMPLE: &[u8] =
        include_bytes!("../contracts/examples/evidence-handoff-v1.example.json");
    const EVIDENCE_HANDOFF_RECORD_EXAMPLE: &[u8] =
        include_bytes!("../contracts/examples/evidence-handoff-record-v1.example.json");
    const AUDIT_TOPOLOGY_EXAMPLE: &[u8] =
        include_bytes!("../contracts/examples/audit-topology-v1.example.json");
    const AUDIT_RECEIPT_EXAMPLE: &[u8] =
        include_bytes!("../contracts/examples/audit-receipt-v1.example.json");
    const CLI_SUCCESS_EXAMPLE: &[u8] =
        include_bytes!("../contracts/examples/ewb-cli-envelope-v1.success.example.json");
    const CLI_FAILURE_EXAMPLE: &[u8] =
        include_bytes!("../contracts/examples/ewb-cli-envelope-v1.failure.example.json");

    #[test]
    fn examples_parse_strictly_and_validate_semantics() {
        parse_subject_candidate(SUBJECT_EXAMPLE).expect("valid subject candidate example");
        parse_runtime_capsule(CAPSULE_EXAMPLE).expect("valid runtime capsule example");
        parse_python_runtime_qualification(PYTHON_QUALIFICATION_EXAMPLE)
            .expect("valid incomplete Python runtime qualification example");
        parse_python_runtime_qualification_record(PYTHON_QUALIFICATION_RECORD_EXAMPLE)
            .expect("valid incomplete Python runtime qualification record example");
        parse_python_runtime_execution_admission(PYTHON_ADMISSION_EXAMPLE)
            .expect("valid not-granted Python execution admission example");
        parse_python_runtime_execution_admission_record(PYTHON_ADMISSION_RECORD_EXAMPLE)
            .expect("valid not-granted Python execution admission record example");
        parse_python_runtime_execution_admission(PYTHON_ADMISSION_V2_EXAMPLE)
            .expect("valid not-granted Python execution admission v2 example");
        parse_python_runtime_execution_admission_record(PYTHON_ADMISSION_RECORD_V2_EXAMPLE)
            .expect("valid not-granted Python execution admission record v2 example");
        parse_phaseledger_caller_observation(PHASELEDGER_CALLER_OBSERVATION_EXAMPLE)
            .expect("valid Phaseledger caller observation example");
        parse_ide_handoff(HANDOFF_EXAMPLE).expect("valid IDE handoff example");
        parse_evidence_handoff(EVIDENCE_HANDOFF_EXAMPLE).expect("valid evidence handoff example");
        let record_value = strict_json::parse_strict(EVIDENCE_HANDOFF_RECORD_EXAMPLE)
            .expect("strict evidence handoff record example");
        let record: crate::contracts::EvidenceHandoffRecord =
            serde_json::from_value(record_value).expect("closed evidence handoff record example");
        validate_evidence_handoff(&record.handoff).expect("valid wrapped handoff semantics");
        assert_eq!(record.schema_version, "evidence_handoff_record/v1");
        assert_eq!(
            record.record_digest,
            crate::workspace::digest_serialized(&record.handoff).unwrap()
        );
        let topology =
            parse_audit_topology(AUDIT_TOPOLOGY_EXAMPLE).expect("valid audit topology example");
        let receipt =
            parse_audit_receipt(AUDIT_RECEIPT_EXAMPLE).expect("valid audit receipt example");
        validate_audit_receipt_against_topology(&receipt, &topology)
            .expect("audit receipt example matches its exact topology");
        parse_cli_envelope(CLI_SUCCESS_EXAMPLE).expect("valid CLI success envelope example");
        parse_cli_envelope(CLI_FAILURE_EXAMPLE).expect("valid CLI failure envelope example");
    }

    #[test]
    fn cli_envelope_is_closed_discriminated_and_strict() {
        for data in [
            json!(null),
            json!(true),
            json!("native"),
            json!([]),
            json!({}),
        ] {
            validate_cli_envelope(&json!({
                "ok": true,
                "command": "runs.show",
                "data": data
            }))
            .expect("opaque command data remains envelope-valid");
        }

        let invalid = [
            json!(null),
            json!([]),
            json!({"ok": true, "command": "runs.show"}),
            json!({"ok": true, "data": {}}),
            json!({"ok": "true", "command": "runs.show", "data": {}}),
            json!({"ok": true, "command": "runs.show", "data": {}, "schema_version": "ewb-cli-envelope/v1"}),
            json!({"ok": true, "command": "runs.show", "data": {}, "error": {"code": "command_failed", "message": "x"}}),
            json!({"ok": true, "command": "", "data": {}}),
            json!({"ok": true, "command": "Runs.show", "data": {}}),
            json!({"ok": true, "command": "runs..show", "data": {}}),
            json!({"ok": false}),
            json!({"ok": false, "error": []}),
            json!({"ok": false, "error": {"message": "x"}}),
            json!({"ok": false, "error": {"code": "command_failed"}}),
            json!({"ok": false, "error": {"code": "command_failed", "message": "x", "detail": "extra"}}),
            json!({"ok": false, "error": {"code": "command-failed", "message": "x"}}),
            json!({"ok": false, "error": {"code": "Command_failed", "message": "x"}}),
            json!({"ok": false, "error": {"code": "command_failed", "message": ""}}),
            json!({"ok": false, "error": {"code": "command_failed", "message": 1}}),
            json!({"ok": false, "error": {"code": "command_failed", "message": "x"}, "data": {}}),
        ];
        for value in invalid {
            assert!(
                validate_cli_envelope(&value).is_err(),
                "accepted invalid CLI envelope: {value}"
            );
        }

        assert!(
            parse_cli_envelope(br#"{"ok":true,"command":"runs.show","data":{},"ok":false}"#)
                .is_err()
        );
        assert!(parse_cli_envelope(br#"{"ok":true,"command":"runs.show","data":{}} {}"#).is_err());
    }

    #[test]
    fn contracts_reject_unknown_fields_and_duplicate_keys() {
        let mut candidate: Value = serde_json::from_slice(SUBJECT_EXAMPLE).unwrap();
        candidate["aggregate_verdict"] = json!("pass");
        assert!(parse_subject_candidate(&serde_json::to_vec(&candidate).unwrap()).is_err());

        let handoff_with_argv = br#"{
          "schema_version":"ide-handoff/v1",
          "handoff_id":"handoff_00000000000000000000000000000000",
          "created_at":"2026-08-14T00:00:00Z",
          "plan_refs":[],"run_refs":[],"artifact_refs":[],
          "native_namespaces":[],"native_authority_availability":[],
          "authority_effect":"none","argv":["cmd.exe"]
        }"#;
        assert!(parse_ide_handoff(handoff_with_argv).is_err());
        let mut evidence_handoff: Value = serde_json::from_slice(EVIDENCE_HANDOFF_EXAMPLE).unwrap();
        evidence_handoff["argv"] = json!(["cmd.exe"]);
        assert!(parse_evidence_handoff(&serde_json::to_vec(&evidence_handoff).unwrap()).is_err());
        assert!(
            parse_subject_candidate(br#"{"schema_version":"a","schema_version":"b"}"#).is_err()
        );
        assert!(
            parse_evidence_handoff(
                br#"{"schema_version":"evidence-handoff/v1","schema_version":"evidence-handoff/v1"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn candidate_never_supplies_admission_or_authority() {
        let mut candidate: Value = serde_json::from_slice(SUBJECT_EXAMPLE).unwrap();
        candidate["producer"]["id"] = json!("another-scanner");
        assert!(parse_subject_candidate(&serde_json::to_vec(&candidate).unwrap()).is_err());

        let mut candidate: Value = serde_json::from_slice(SUBJECT_EXAMPLE).unwrap();
        candidate["limitations"] = json!([]);
        assert!(parse_subject_candidate(&serde_json::to_vec(&candidate).unwrap()).is_err());

        let mut candidate: Value = serde_json::from_slice(SUBJECT_EXAMPLE).unwrap();
        candidate["producer"]["version"] = json!("0.1.0\0forged");
        assert!(parse_subject_candidate(&serde_json::to_vec(&candidate).unwrap()).is_err());
    }

    #[test]
    fn incomplete_or_unqualified_capsule_cannot_be_ready() {
        let mut capsule: Value = serde_json::from_slice(CAPSULE_EXAMPLE).unwrap();
        capsule["transitive_closure"]["state"] = json!("incomplete");
        capsule["transitive_closure"]["declared_file_count"] = json!(2);
        capsule["transitive_closure"]["missing_paths"] = json!(["runtime/missing.dll"]);
        assert!(parse_runtime_capsule(&serde_json::to_vec(&capsule).unwrap()).is_err());

        let mut capsule: Value = serde_json::from_slice(CAPSULE_EXAMPLE).unwrap();
        capsule["qualification_evidence"] = json!([]);
        assert!(parse_runtime_capsule(&serde_json::to_vec(&capsule).unwrap()).is_err());

        let mut capsule: Value = serde_json::from_slice(CAPSULE_EXAMPLE).unwrap();
        capsule["external_platform_assumptions"][0]["state"] = json!("unresolved");
        assert!(parse_runtime_capsule(&serde_json::to_vec(&capsule).unwrap()).is_err());
    }

    #[test]
    fn fail_closed_capsule_names_closure_and_platform_blockers() {
        let mut capsule: Value = serde_json::from_slice(CAPSULE_EXAMPLE).unwrap();
        capsule["transitive_closure"]["state"] = json!("incomplete");
        capsule["transitive_closure"]["declared_file_count"] = json!(2);
        capsule["transitive_closure"]["missing_paths"] = json!(["runtime/missing.dll"]);
        capsule["external_platform_assumptions"][0]["state"] = json!("unresolved");
        capsule["readiness"]["state"] = json!("fail_closed");
        capsule["readiness"]["blocker_codes"] = json!([
            "runtime_closure_incomplete",
            "external_platform_assumption_unresolved"
        ]);
        parse_runtime_capsule(&serde_json::to_vec(&capsule).unwrap())
            .expect("explicitly blocked incomplete capsule");
    }

    #[test]
    fn ide_handoff_is_reference_only_and_run_metadata_is_exact() {
        let mut handoff: Value = serde_json::from_slice(HANDOFF_EXAMPLE).unwrap();
        handoff["aggregate_verdict"] = json!("pass");
        assert!(parse_ide_handoff(&serde_json::to_vec(&handoff).unwrap()).is_err());

        let mut handoff: Value = serde_json::from_slice(HANDOFF_EXAMPLE).unwrap();
        handoff["native_authority_availability"][0]["run_id"] =
            json!("run_ffffffffffffffffffffffffffffffff");
        assert!(parse_ide_handoff(&serde_json::to_vec(&handoff).unwrap()).is_err());
    }

    #[test]
    fn evidence_handoff_is_closed_reference_only_and_non_authoritative() {
        let parsed = parse_evidence_handoff(EVIDENCE_HANDOFF_EXAMPLE).unwrap();
        assert_eq!(
            parsed.relationship,
            crate::contracts::EvidenceHandoffRelationship::CapturedRunArtifact
        );
        assert_eq!(
            parsed.consumer_treatment,
            crate::contracts::EvidenceConsumerTreatment::UntrustedExactBytes
        );
        assert_eq!(
            parsed.authority_effect,
            crate::contracts::ContractAuthorityEffect::None
        );

        for forbidden in [
            "argv",
            "command",
            "parameters",
            "capabilities",
            "status",
            "verdict",
            "passed",
            "score",
            "authority",
            "native_authority",
            "artifact_sha256",
            "byte_length",
            "media_type",
            "tool_ref",
            "consumer_run_ref",
            "accepted",
            "ready",
        ] {
            let mut handoff: Value = serde_json::from_slice(EVIDENCE_HANDOFF_EXAMPLE).unwrap();
            handoff[forbidden] = json!("forbidden");
            assert!(
                parse_evidence_handoff(&serde_json::to_vec(&handoff).unwrap()).is_err(),
                "accepted forbidden field {forbidden}"
            );
        }

        let invalid_mutations = [
            ("/schema_version", json!("evidence-handoff/v2")),
            ("/handoff_id", json!("handoff_NOT_LOWER_HEX")),
            ("/created_at", json!("not-a-time")),
            (
                "/producer_plan_ref/plan_id",
                json!("run_11111111111111111111111111111111"),
            ),
            ("/producer_plan_ref/record_digest", json!("11")),
            (
                "/producer_run_ref/run_id",
                json!("plan_22222222222222222222222222222222"),
            ),
            ("/producer_run_ref/record_digest", json!("22")),
            (
                "/artifact_ref/artifact_id",
                json!("artifact_ABCDEFABCDEFABCDEFABCDEFABCDEFAB"),
            ),
            ("/artifact_ref/record_digest", json!("33")),
            ("/relationship", json!("derived_verdict")),
            ("/consumer_treatment", json!("trusted_projection")),
            ("/authority_effect", json!("reported")),
        ];
        for (pointer, replacement) in invalid_mutations {
            let mut handoff: Value = serde_json::from_slice(EVIDENCE_HANDOFF_EXAMPLE).unwrap();
            *handoff.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                parse_evidence_handoff(&serde_json::to_vec(&handoff).unwrap()).is_err(),
                "accepted invalid field {pointer}"
            );
        }

        let mut nested_extra: Value = serde_json::from_slice(EVIDENCE_HANDOFF_EXAMPLE).unwrap();
        nested_extra["producer_run_ref"]["status"] = json!("pass");
        assert!(parse_evidence_handoff(&serde_json::to_vec(&nested_extra).unwrap()).is_err());

        let mut trailing = EVIDENCE_HANDOFF_EXAMPLE.to_vec();
        trailing.extend_from_slice(b" {}");
        assert!(parse_evidence_handoff(&trailing).is_err());

        let nested_duplicate = String::from_utf8(EVIDENCE_HANDOFF_EXAMPLE.to_vec())
            .unwrap()
            .replace(
                "\"record_digest\": \"1111111111111111111111111111111111111111111111111111111111111111\"",
                "\"record_digest\": \"1111111111111111111111111111111111111111111111111111111111111111\", \"record_digest\": \"1111111111111111111111111111111111111111111111111111111111111111\"",
            );
        assert!(parse_evidence_handoff(nested_duplicate.as_bytes()).is_err());
    }

    #[test]
    fn audit_topology_is_an_exact_plan_dag_without_policy_or_results() {
        let parsed = parse_audit_topology(AUDIT_TOPOLOGY_EXAMPLE).unwrap();
        assert_eq!(
            parsed.authority_effect,
            crate::contracts::ContractAuthorityEffect::None
        );

        for forbidden in [
            "aggregate_overall",
            "overall",
            "overall_status",
            "pass",
            "fail",
            "passed",
            "status",
            "outcome",
            "verdict",
            "score",
            "rank",
            "trust",
            "certification",
            "success",
            "completed",
            "ready",
            "native_result",
            "native_authority",
            "authority",
            "command",
            "argv",
            "parameters",
            "capabilities",
            "condition",
            "when",
            "on_success",
            "on_failure",
            "retry",
            "subject",
            "artifact_role",
            "artifact_ref",
            "handoff_ref",
            "source_run_ref",
            "dependency_artifact",
            "required",
            "optional",
        ] {
            let mut topology: Value = serde_json::from_slice(AUDIT_TOPOLOGY_EXAMPLE).unwrap();
            topology[forbidden] = json!("forbidden");
            assert!(
                parse_audit_topology(&serde_json::to_vec(&topology).unwrap()).is_err(),
                "accepted forbidden topology field {forbidden}"
            );

            let mut nested: Value = serde_json::from_slice(AUDIT_TOPOLOGY_EXAMPLE).unwrap();
            nested["steps"][0][forbidden] = json!("forbidden");
            assert!(
                parse_audit_topology(&serde_json::to_vec(&nested).unwrap()).is_err(),
                "accepted forbidden topology step field {forbidden}"
            );
        }

        for (pointer, replacement) in [
            ("/schema_version", json!("audit-topology/v2")),
            ("/topology_id", json!("topology_NOT_LOWER_HEX")),
            ("/steps/0/step_id", json!("overall_pass")),
            (
                "/steps/0/plan_ref/plan_id",
                json!("run_11111111111111111111111111111111"),
            ),
            ("/steps/0/plan_ref/record_digest", json!("11")),
            ("/authority_effect", json!("reported")),
        ] {
            let mut topology: Value = serde_json::from_slice(AUDIT_TOPOLOGY_EXAMPLE).unwrap();
            *topology.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                parse_audit_topology(&serde_json::to_vec(&topology).unwrap()).is_err(),
                "accepted invalid topology field {pointer}"
            );
        }

        let mut empty: Value = serde_json::from_slice(AUDIT_TOPOLOGY_EXAMPLE).unwrap();
        empty["steps"] = json!([]);
        assert!(parse_audit_topology(&serde_json::to_vec(&empty).unwrap()).is_err());

        let mut duplicate_step: Value = serde_json::from_slice(AUDIT_TOPOLOGY_EXAMPLE).unwrap();
        let first_step = duplicate_step["steps"][0].clone();
        duplicate_step["steps"]
            .as_array_mut()
            .unwrap()
            .push(first_step);
        assert!(parse_audit_topology(&serde_json::to_vec(&duplicate_step).unwrap()).is_err());

        let mut duplicate_plan: Value = serde_json::from_slice(AUDIT_TOPOLOGY_EXAMPLE).unwrap();
        let first_plan = duplicate_plan["steps"][0]["plan_ref"].clone();
        duplicate_plan["steps"][1]["plan_ref"] = first_plan;
        assert!(parse_audit_topology(&serde_json::to_vec(&duplicate_plan).unwrap()).is_err());

        let mut unordered_steps: Value = serde_json::from_slice(AUDIT_TOPOLOGY_EXAMPLE).unwrap();
        unordered_steps["steps"].as_array_mut().unwrap().swap(0, 1);
        assert!(parse_audit_topology(&serde_json::to_vec(&unordered_steps).unwrap()).is_err());

        let mut unknown_predecessor: Value =
            serde_json::from_slice(AUDIT_TOPOLOGY_EXAMPLE).unwrap();
        unknown_predecessor["steps"][1]["predecessor_step_ids"] =
            json!(["step_ffffffffffffffffffffffffffffffff"]);
        assert!(parse_audit_topology(&serde_json::to_vec(&unknown_predecessor).unwrap()).is_err());

        let mut self_predecessor: Value = serde_json::from_slice(AUDIT_TOPOLOGY_EXAMPLE).unwrap();
        self_predecessor["steps"][1]["predecessor_step_ids"] =
            json!(["step_22222222222222222222222222222222"]);
        assert!(parse_audit_topology(&serde_json::to_vec(&self_predecessor).unwrap()).is_err());

        let mut duplicate_predecessor: Value =
            serde_json::from_slice(AUDIT_TOPOLOGY_EXAMPLE).unwrap();
        duplicate_predecessor["steps"][2]["predecessor_step_ids"] = json!([
            "step_11111111111111111111111111111111",
            "step_11111111111111111111111111111111"
        ]);
        assert!(
            parse_audit_topology(&serde_json::to_vec(&duplicate_predecessor).unwrap()).is_err()
        );

        let mut unordered_predecessors: Value =
            serde_json::from_slice(AUDIT_TOPOLOGY_EXAMPLE).unwrap();
        unordered_predecessors["steps"][2]["predecessor_step_ids"] = json!([
            "step_22222222222222222222222222222222",
            "step_11111111111111111111111111111111"
        ]);
        assert!(
            parse_audit_topology(&serde_json::to_vec(&unordered_predecessors).unwrap()).is_err()
        );

        let mut disconnected_cycle: Value = serde_json::from_slice(AUDIT_TOPOLOGY_EXAMPLE).unwrap();
        disconnected_cycle["steps"][1]["predecessor_step_ids"] =
            json!(["step_33333333333333333333333333333333"]);
        disconnected_cycle["steps"][2]["predecessor_step_ids"] =
            json!(["step_22222222222222222222222222222222"]);
        assert!(parse_audit_topology(&serde_json::to_vec(&disconnected_cycle).unwrap()).is_err());

        let duplicate_key = String::from_utf8(AUDIT_TOPOLOGY_EXAMPLE.to_vec())
            .unwrap()
            .replacen(
                "\"schema_version\": \"audit-topology/v1\"",
                "\"schema_version\": \"audit-topology/v1\", \"schema_version\": \"audit-topology/v1\"",
                1,
            );
        assert!(parse_audit_topology(duplicate_key.as_bytes()).is_err());
        let mut trailing = AUDIT_TOPOLOGY_EXAMPLE.to_vec();
        trailing.extend_from_slice(b" {}");
        assert!(parse_audit_topology(&trailing).is_err());
    }

    #[test]
    fn audit_receipt_is_a_non_authoritative_partial_exact_reference_set() {
        let topology = parse_audit_topology(AUDIT_TOPOLOGY_EXAMPLE).unwrap();
        let receipt = parse_audit_receipt(AUDIT_RECEIPT_EXAMPLE).unwrap();
        validate_audit_receipt_against_topology(&receipt, &topology).unwrap();
        assert_eq!(
            receipt.authority_effect,
            crate::contracts::ContractAuthorityEffect::None
        );

        // A receipt may reference a run whose own termination is timed_out or
        // spawn_error. That fact stays in the run record and cannot become a
        // success, failure, or copied termination field here.
        for forbidden in [
            "aggregate_overall",
            "overall",
            "overall_status",
            "pass",
            "fail",
            "passed",
            "status",
            "outcome",
            "verdict",
            "score",
            "rank",
            "trust",
            "certification",
            "success",
            "completed",
            "ready",
            "termination",
            "native_result",
            "native_authority",
            "authority",
            "command",
            "argv",
            "parameters",
            "capabilities",
            "condition",
            "when",
            "on_success",
            "on_failure",
            "retry",
            "subject",
            "artifact_role",
            "artifact_ref",
            "handoff_ref",
            "required",
            "optional",
        ] {
            let mut receipt: Value = serde_json::from_slice(AUDIT_RECEIPT_EXAMPLE).unwrap();
            receipt[forbidden] = json!("forbidden");
            assert!(
                parse_audit_receipt(&serde_json::to_vec(&receipt).unwrap()).is_err(),
                "accepted forbidden receipt field {forbidden}"
            );

            let mut nested: Value = serde_json::from_slice(AUDIT_RECEIPT_EXAMPLE).unwrap();
            nested["recorded_runs"][0][forbidden] = json!("forbidden");
            assert!(
                parse_audit_receipt(&serde_json::to_vec(&nested).unwrap()).is_err(),
                "accepted forbidden recorded-run field {forbidden}"
            );
        }

        for (pointer, replacement) in [
            ("/schema_version", json!("audit-receipt/v2")),
            ("/topology_ref/topology_id", json!("topology_NOT_LOWER_HEX")),
            ("/topology_ref/topology_digest", json!("00")),
            ("/recorded_runs/0/step_id", json!("overall_pass")),
            (
                "/recorded_runs/0/plan_ref/plan_id",
                json!("run_11111111111111111111111111111111"),
            ),
            ("/recorded_runs/0/plan_ref/record_digest", json!("11")),
            (
                "/recorded_runs/0/run_ref/run_id",
                json!("plan_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ),
            ("/recorded_runs/0/run_ref/record_digest", json!("aa")),
            ("/authority_effect", json!("reported")),
        ] {
            let mut receipt: Value = serde_json::from_slice(AUDIT_RECEIPT_EXAMPLE).unwrap();
            *receipt.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                parse_audit_receipt(&serde_json::to_vec(&receipt).unwrap()).is_err(),
                "accepted invalid receipt field {pointer}"
            );
        }

        let mut empty: Value = serde_json::from_slice(AUDIT_RECEIPT_EXAMPLE).unwrap();
        empty["recorded_runs"] = json!([]);
        assert!(parse_audit_receipt(&serde_json::to_vec(&empty).unwrap()).is_err());

        let mut duplicate_step: Value = serde_json::from_slice(AUDIT_RECEIPT_EXAMPLE).unwrap();
        let first_run = duplicate_step["recorded_runs"][0].clone();
        duplicate_step["recorded_runs"]
            .as_array_mut()
            .unwrap()
            .push(first_run);
        assert!(parse_audit_receipt(&serde_json::to_vec(&duplicate_step).unwrap()).is_err());

        let mut duplicate_plan: Value = serde_json::from_slice(AUDIT_RECEIPT_EXAMPLE).unwrap();
        let first_plan = duplicate_plan["recorded_runs"][0]["plan_ref"].clone();
        duplicate_plan["recorded_runs"][1]["plan_ref"] = first_plan;
        assert!(parse_audit_receipt(&serde_json::to_vec(&duplicate_plan).unwrap()).is_err());

        let mut duplicate_run: Value = serde_json::from_slice(AUDIT_RECEIPT_EXAMPLE).unwrap();
        let first_run = duplicate_run["recorded_runs"][0]["run_ref"].clone();
        duplicate_run["recorded_runs"][1]["run_ref"] = first_run;
        assert!(parse_audit_receipt(&serde_json::to_vec(&duplicate_run).unwrap()).is_err());

        let mut unordered: Value = serde_json::from_slice(AUDIT_RECEIPT_EXAMPLE).unwrap();
        unordered["recorded_runs"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        assert!(parse_audit_receipt(&serde_json::to_vec(&unordered).unwrap()).is_err());

        let mut partial: Value = serde_json::from_slice(AUDIT_RECEIPT_EXAMPLE).unwrap();
        partial["recorded_runs"] = json!([{
            "step_id": "step_33333333333333333333333333333333",
            "plan_ref": {
                "plan_id": "plan_33333333333333333333333333333333",
                "record_digest": "3333333333333333333333333333333333333333333333333333333333333333"
            },
            "run_ref": {
                "run_id": "run_cccccccccccccccccccccccccccccccc",
                "record_digest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            }
        }]);
        let partial = parse_audit_receipt(&serde_json::to_vec(&partial).unwrap()).unwrap();
        validate_audit_receipt_against_topology(&partial, &topology)
            .expect("a receipt subset need not copy predecessor runs");

        let mut unknown_step: Value = serde_json::from_slice(AUDIT_RECEIPT_EXAMPLE).unwrap();
        unknown_step["recorded_runs"][1]["step_id"] =
            json!("step_ffffffffffffffffffffffffffffffff");
        let unknown_step =
            parse_audit_receipt(&serde_json::to_vec(&unknown_step).unwrap()).unwrap();
        assert!(validate_audit_receipt_against_topology(&unknown_step, &topology).is_err());

        let mut wrong_plan: Value = serde_json::from_slice(AUDIT_RECEIPT_EXAMPLE).unwrap();
        wrong_plan["recorded_runs"][1]["plan_ref"]["record_digest"] =
            json!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        let wrong_plan = parse_audit_receipt(&serde_json::to_vec(&wrong_plan).unwrap()).unwrap();
        assert!(validate_audit_receipt_against_topology(&wrong_plan, &topology).is_err());

        let mut wrong_topology_id: Value = serde_json::from_slice(AUDIT_RECEIPT_EXAMPLE).unwrap();
        wrong_topology_id["topology_ref"]["topology_id"] =
            json!("topology_ffffffffffffffffffffffffffffffff");
        let wrong_topology_id =
            parse_audit_receipt(&serde_json::to_vec(&wrong_topology_id).unwrap()).unwrap();
        assert!(validate_audit_receipt_against_topology(&wrong_topology_id, &topology).is_err());

        let mut wrong_topology_digest: Value =
            serde_json::from_slice(AUDIT_RECEIPT_EXAMPLE).unwrap();
        wrong_topology_digest["topology_ref"]["topology_digest"] =
            json!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let wrong_topology_digest =
            parse_audit_receipt(&serde_json::to_vec(&wrong_topology_digest).unwrap()).unwrap();
        assert!(
            validate_audit_receipt_against_topology(&wrong_topology_digest, &topology).is_err()
        );

        let duplicate_key = String::from_utf8(AUDIT_RECEIPT_EXAMPLE.to_vec())
            .unwrap()
            .replacen(
                "\"schema_version\": \"audit-receipt/v1\"",
                "\"schema_version\": \"audit-receipt/v1\", \"schema_version\": \"audit-receipt/v1\"",
                1,
            );
        assert!(parse_audit_receipt(duplicate_key.as_bytes()).is_err());
        let mut trailing = AUDIT_RECEIPT_EXAMPLE.to_vec();
        trailing.extend_from_slice(b" {}");
        assert!(parse_audit_receipt(&trailing).is_err());
    }

    #[test]
    fn audit_receipt_does_not_promote_a_spawn_error_run_into_a_result() {
        let run: crate::contracts::InstrumentRun = serde_json::from_slice(include_bytes!(
            "../contracts/examples/instrument-run-v1.example.json"
        ))
        .unwrap();
        assert!(matches!(
            &run.termination,
            crate::contracts::Termination::SpawnError { .. }
        ));

        let topology = crate::contracts::AuditTopology {
            schema_version: "audit-topology/v1".to_owned(),
            topology_id: "topology_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_owned(),
            steps: vec![crate::contracts::AuditTopologyStep {
                step_id: "step_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_owned(),
                plan_ref: run.source_plan_ref.clone(),
                predecessor_step_ids: Vec::new(),
            }],
            authority_effect: crate::contracts::ContractAuthorityEffect::None,
        };
        validate_audit_topology(&topology).unwrap();
        let topology_digest = crate::workspace::digest_serialized(&topology).unwrap();
        let receipt = crate::contracts::AuditReceipt {
            schema_version: "audit-receipt/v1".to_owned(),
            topology_ref: crate::contracts::AuditTopologyRef {
                topology_id: topology.topology_id.clone(),
                topology_digest,
            },
            recorded_runs: vec![crate::contracts::AuditRecordedRun {
                step_id: topology.steps[0].step_id.clone(),
                plan_ref: run.source_plan_ref.clone(),
                run_ref: crate::contracts::RunRecordRef {
                    run_id: run.run_id.clone(),
                    record_digest: crate::workspace::digest_serialized(&run).unwrap(),
                },
            }],
            authority_effect: crate::contracts::ContractAuthorityEffect::None,
        };
        validate_audit_receipt_against_topology(&receipt, &topology).unwrap();

        let receipt_value = serde_json::to_value(receipt).unwrap();
        assert!(receipt_value.get("termination").is_none());
        assert!(receipt_value.get("success").is_none());
        assert!(receipt_value.get("verdict").is_none());
    }

    #[test]
    fn every_new_schema_closes_all_object_shapes() {
        for raw in [
            include_str!("../contracts/subject-candidate-v1.schema.json"),
            include_str!("../contracts/runtime-capsule-v1.schema.json"),
            include_str!("../contracts/python-runtime-qualification-v1.schema.json"),
            include_str!("../contracts/python-runtime-qualification-record-v1.schema.json"),
            include_str!("../contracts/python-runtime-execution-admission-v1.schema.json"),
            include_str!("../contracts/python-runtime-execution-admission-record-v1.schema.json"),
            include_str!("../contracts/python-runtime-execution-admission-v2.schema.json"),
            include_str!("../contracts/python-runtime-execution-admission-record-v2.schema.json"),
            include_str!("../contracts/phaseledger-caller-observation-v1.schema.json"),
            include_str!("../contracts/native-delivery-qualification-v1.schema.json"),
            include_str!("../contracts/ide-handoff-v1.schema.json"),
            include_str!("../contracts/evidence-handoff-v1.schema.json"),
            include_str!("../contracts/evidence-handoff-record-v1.schema.json"),
            include_str!("../contracts/audit-topology-v1.schema.json"),
            include_str!("../contracts/audit-receipt-v1.schema.json"),
            include_str!("../contracts/build-identity-v1.schema.json"),
            include_str!("../contracts/ewb-cli-envelope-v1.schema.json"),
        ] {
            let schema: Value = serde_json::from_str(raw).expect("valid JSON Schema JSON");
            assert_objects_are_closed(&schema);
        }
    }

    #[test]
    fn required_nullable_native_qualification_and_source_plan_fields_are_exact() {
        let run: Value = serde_json::from_slice(include_bytes!(
            "../contracts/examples/instrument-run-v1.example.json"
        ))
        .unwrap();
        let parsed: crate::contracts::InstrumentRun = serde_json::from_value(run.clone()).unwrap();
        assert!(parsed.native_qualification_ref.is_none());
        assert!(parsed.python_admission_ref.is_none());

        let mut missing_native = run.clone();
        missing_native
            .as_object_mut()
            .unwrap()
            .remove("native_qualification_ref");
        assert!(serde_json::from_value::<crate::contracts::InstrumentRun>(missing_native).is_err());

        let mut missing_plan = run.clone();
        missing_plan
            .as_object_mut()
            .unwrap()
            .remove("source_plan_ref");
        assert!(serde_json::from_value::<crate::contracts::InstrumentRun>(missing_plan).is_err());

        let mut missing_upstream = run.clone();
        missing_upstream
            .as_object_mut()
            .unwrap()
            .remove("upstream_pin_ref");
        assert!(
            serde_json::from_value::<crate::contracts::InstrumentRun>(missing_upstream).is_err()
        );

        let mut plan = json!({
            "tool_ref": run["tool_ref"].clone(),
            "upstream_pin_ref": run["upstream_pin_ref"].clone(),
            "native_qualification_ref": null,
            "python_admission_ref": null,
            "resolved_tool_identity": run["resolved_tool_identity"].clone(),
            "recorder_identity": run["recorder_identity"].clone(),
            "adapter": run["adapter"].clone(),
            "subject": run["subject"].clone(),
            "invocation": run["invocation"].clone(),
            "parameters": run["parameters"].clone(),
            "created_at": "2026-08-13T11:59:00Z"
        });
        let parsed: crate::contracts::PlanPayload = serde_json::from_value(plan.clone()).unwrap();
        assert!(parsed.native_qualification_ref.is_none());
        assert!(parsed.python_admission_ref.is_none());
        plan.as_object_mut()
            .unwrap()
            .remove("native_qualification_ref");
        assert!(serde_json::from_value::<crate::contracts::PlanPayload>(plan).is_err());

        let mut missing_python = run.clone();
        missing_python
            .as_object_mut()
            .unwrap()
            .remove("python_admission_ref");
        assert!(
            serde_json::from_value::<crate::contracts::InstrumentRun>(missing_python).is_err()
        );
    }

    fn assert_objects_are_closed(value: &Value) {
        match value {
            Value::Object(object) => {
                if object.get("type") == Some(&Value::String("object".to_owned())) {
                    assert_eq!(
                        object.get("additionalProperties"),
                        Some(&Value::Bool(false)),
                        "object schema is not closed: {value}"
                    );
                }
                for child in object.values() {
                    assert_objects_are_closed(child);
                }
            }
            Value::Array(items) => {
                for item in items {
                    assert_objects_are_closed(item);
                }
            }
            _ => {}
        }
    }
}
