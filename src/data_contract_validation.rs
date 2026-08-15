use crate::contracts::{
    CapsuleClosureState, CapsuleReadinessState, ContractArtifactRef, Digest, EvidenceHandoff,
    IdeHandoff, PlatformAssumptionState, RuntimeCapsule, SubjectCandidate,
};
use crate::strict_json;
use anyhow::{Context, Result, bail};
use chrono::DateTime;
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;

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
    const HANDOFF_EXAMPLE: &[u8] =
        include_bytes!("../contracts/examples/ide-handoff-v1.example.json");
    const EVIDENCE_HANDOFF_EXAMPLE: &[u8] =
        include_bytes!("../contracts/examples/evidence-handoff-v1.example.json");
    const CLI_SUCCESS_EXAMPLE: &[u8] =
        include_bytes!("../contracts/examples/ewb-cli-envelope-v1.success.example.json");
    const CLI_FAILURE_EXAMPLE: &[u8] =
        include_bytes!("../contracts/examples/ewb-cli-envelope-v1.failure.example.json");

    #[test]
    fn examples_parse_strictly_and_validate_semantics() {
        parse_subject_candidate(SUBJECT_EXAMPLE).expect("valid subject candidate example");
        parse_runtime_capsule(CAPSULE_EXAMPLE).expect("valid runtime capsule example");
        parse_ide_handoff(HANDOFF_EXAMPLE).expect("valid IDE handoff example");
        parse_evidence_handoff(EVIDENCE_HANDOFF_EXAMPLE).expect("valid evidence handoff example");
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
    fn every_new_schema_closes_all_object_shapes() {
        for raw in [
            include_str!("../contracts/subject-candidate-v1.schema.json"),
            include_str!("../contracts/runtime-capsule-v1.schema.json"),
            include_str!("../contracts/native-delivery-qualification-v1.schema.json"),
            include_str!("../contracts/ide-handoff-v1.schema.json"),
            include_str!("../contracts/evidence-handoff-v1.schema.json"),
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
        plan.as_object_mut()
            .unwrap()
            .remove("native_qualification_ref");
        assert!(serde_json::from_value::<crate::contracts::PlanPayload>(plan).is_err());
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
