use crate::manifests;
use anyhow::{Context, Result, bail};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidatePin {
    pub schema_version: String,
    pub tool_manifest_id: String,
    pub repository_url: String,
    pub source: CandidateSource,
    pub candidate: CandidateArtifact,
    pub runtime_target: RuntimeTarget,
    pub inventory: CandidateInventory,
    pub native_posture: NativePosture,
    pub provenance: CandidateProvenance,
    pub workbench_admission: WorkbenchAdmission,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateSource {
    pub commit_sha: String,
    pub tree_sha: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateArtifact {
    pub payload_manifest_sha256: String,
    pub receipt_sha256: String,
    pub actions_artifact_id: String,
    pub actions_artifact_name: String,
    pub actions_artifact_sha256: String,
    pub workflow_run_id: String,
    pub workflow_run_url: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTarget {
    pub os: String,
    pub arch: String,
    pub implementation: String,
    pub python_version: String,
    pub python_abi: String,
    pub interpreter_included: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateInventory {
    pub workspace_wheels: u64,
    pub vendored_runtime_wheels: u64,
    pub manifest_artifacts: u64,
    pub checksum_entries: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePosture {
    pub status: String,
    pub release_eligible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateProvenance {
    pub attestation_actions_artifact_id: String,
    pub attestation_actions_artifact_sha256: String,
    pub attestation_bundle_sha256: String,
    pub download_verification_actions_artifact_id: String,
    pub download_verification_actions_artifact_sha256: String,
    pub download_verification_receipt_sha256: String,
    pub signer_workflow: String,
    pub signer_digest: String,
    pub deny_self_hosted_runners: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkbenchAdmission {
    pub implementation_state: String,
    pub evidence_integrity_state: String,
    pub checksum_entries_verified: u64,
    pub attestation_verified: bool,
    pub attestation_subject_sha256: String,
    pub verified_at: String,
    pub authority_effect: String,
}

#[derive(Debug, Clone)]
pub struct TrustedCandidatePin {
    pub pin: CandidatePin,
    pub sha256: String,
    pub raw: &'static str,
}

#[derive(Clone, Copy)]
struct EmbeddedCandidatePin {
    raw: &'static str,
}

const EMBEDDED: &[EmbeddedCandidatePin] = &[EmbeddedCandidatePin {
    raw: include_str!("../candidate-pins/stateweaver-foundation.json"),
}];

pub fn all() -> Result<Vec<TrustedCandidatePin>> {
    let mut pins = Vec::new();
    let mut tool_ids = BTreeSet::new();
    for embedded in EMBEDDED {
        let pin: CandidatePin =
            serde_json::from_str(embedded.raw).context("embedded candidate pin is invalid JSON")?;
        validate(&pin)?;
        manifests::get(&pin.tool_manifest_id).with_context(|| {
            format!(
                "candidate pin references unknown tool manifest {}",
                pin.tool_manifest_id
            )
        })?;
        if !tool_ids.insert(pin.tool_manifest_id.clone()) {
            bail!(
                "duplicate candidate pin for tool manifest {}",
                pin.tool_manifest_id
            );
        }
        pins.push(TrustedCandidatePin {
            pin,
            sha256: hex::encode(Sha256::digest(embedded.raw.as_bytes())),
            raw: embedded.raw,
        });
    }
    pins.sort_by(|left, right| left.pin.tool_manifest_id.cmp(&right.pin.tool_manifest_id));
    Ok(pins)
}

pub fn get_for_tool(tool_manifest_id: &str) -> Result<Option<TrustedCandidatePin>> {
    Ok(all()?
        .into_iter()
        .find(|entry| entry.pin.tool_manifest_id == tool_manifest_id))
}

pub fn summary(pin: &TrustedCandidatePin) -> Value {
    json!({
        "candidate_pin_sha256": pin.sha256,
        "source_commit": pin.pin.source.commit_sha,
        "payload_manifest_sha256": pin.pin.candidate.payload_manifest_sha256,
        "native_status": pin.pin.native_posture.status,
        "release_eligible": pin.pin.native_posture.release_eligible,
        "implementation_state": pin.pin.workbench_admission.implementation_state,
        "evidence_integrity_state": pin.pin.workbench_admission.evidence_integrity_state,
        "authority_effect": pin.pin.workbench_admission.authority_effect,
        "execution_readiness": execution_readiness(pin)
    })
}

pub fn execution_readiness(pin: &TrustedCandidatePin) -> Value {
    let mut reason_codes = vec![
        "candidate_is_not_execution_capsule",
        "python_runtime_snapshot_unimplemented",
    ];
    if !pin.pin.runtime_target.interpreter_included {
        reason_codes.push("python_interpreter_not_in_candidate");
    }
    let host_os = std::env::consts::OS;
    if pin.pin.runtime_target.os != host_os {
        reason_codes.push("runtime_target_mismatch");
    }
    if !cfg!(windows) {
        reason_codes.push("descriptor_exec_unimplemented");
    }
    json!({
        "state": "fail_closed",
        "blocker_codes": reason_codes,
        "host_os": host_os,
        "candidate_os": pin.pin.runtime_target.os,
        "remote_availability": "not_checked"
    })
}

fn validate(pin: &CandidatePin) -> Result<()> {
    if pin.schema_version != "candidate_pin/v1" {
        bail!("unsupported candidate pin schema");
    }
    manifests::validate_id(&pin.tool_manifest_id)?;
    let repository = pin
        .repository_url
        .strip_prefix("https://github.com/")
        .ok_or_else(|| anyhow::anyhow!("candidate repository must use GitHub HTTPS"))?;
    let repository_parts = repository.split('/').collect::<Vec<_>>();
    if repository_parts.len() != 2
        || repository_parts.iter().any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        bail!("candidate repository URL must be an exact GitHub HTTPS URL");
    }
    validate_git_sha1(&pin.source.commit_sha, "source commit")?;
    validate_git_sha1(&pin.source.tree_sha, "source tree")?;
    validate_sha256(
        &pin.candidate.payload_manifest_sha256,
        "candidate payload manifest",
    )?;
    validate_sha256(&pin.candidate.receipt_sha256, "candidate receipt")?;
    validate_sha256(&pin.candidate.actions_artifact_sha256, "Actions artifact")?;
    validate_sha256(
        &pin.workbench_admission.attestation_subject_sha256,
        "attestation subject",
    )?;
    for (value, label) in [
        (
            pin.provenance.attestation_actions_artifact_sha256.as_str(),
            "attestation Actions artifact",
        ),
        (
            pin.provenance.attestation_bundle_sha256.as_str(),
            "attestation bundle",
        ),
        (
            pin.provenance
                .download_verification_actions_artifact_sha256
                .as_str(),
            "download-verification Actions artifact",
        ),
        (
            pin.provenance.download_verification_receipt_sha256.as_str(),
            "download-verification receipt",
        ),
    ] {
        validate_sha256(value, label)?;
    }
    if pin.workbench_admission.attestation_subject_sha256 != pin.candidate.payload_manifest_sha256 {
        bail!("attestation subject does not match the exact payload manifest");
    }
    validate_decimal_id(&pin.candidate.actions_artifact_id, "Actions artifact")?;
    validate_decimal_id(&pin.candidate.workflow_run_id, "workflow run")?;
    validate_decimal_id(
        &pin.provenance.attestation_actions_artifact_id,
        "attestation Actions artifact",
    )?;
    validate_decimal_id(
        &pin.provenance.download_verification_actions_artifact_id,
        "download-verification Actions artifact",
    )?;
    DateTime::parse_from_rfc3339(&pin.candidate.expires_at)
        .context("candidate expiry is not RFC 3339")?;
    DateTime::parse_from_rfc3339(&pin.workbench_admission.verified_at)
        .context("candidate admission time is not RFC 3339")?;
    if pin.inventory.workspace_wheels == 0
        || pin.inventory.vendored_runtime_wheels == 0
        || pin.inventory.manifest_artifacts == 0
        || pin.inventory.checksum_entries == 0
        || pin.inventory.checksum_entries != pin.workbench_admission.checksum_entries_verified
    {
        bail!("candidate inventory and verified checksum accounting do not match");
    }
    if pin.candidate.actions_artifact_name.is_empty()
        || pin.native_posture.status.is_empty()
        || pin.runtime_target.os.is_empty()
        || pin.runtime_target.arch.is_empty()
        || pin.runtime_target.implementation.is_empty()
        || pin.runtime_target.python_version.is_empty()
        || pin.runtime_target.python_abi.is_empty()
    {
        bail!("candidate identity, runtime, or native posture is incomplete");
    }
    if pin.workbench_admission.implementation_state != "candidate_complete"
        || pin.workbench_admission.evidence_integrity_state != "verified_at_admission"
        || !pin.workbench_admission.attestation_verified
        || pin.workbench_admission.authority_effect != "none"
    {
        bail!("candidate admission would overstate implementation or authority");
    }
    if pin.provenance.signer_digest != pin.source.commit_sha
        || !pin.provenance.deny_self_hosted_runners
        || !pin
            .provenance
            .signer_workflow
            .starts_with(&format!("github.com/{repository}/.github/workflows/"))
        || pin.provenance.signer_workflow.contains(char::is_whitespace)
        || pin.candidate.workflow_run_url
            != format!(
                "{}/actions/runs/{}",
                pin.repository_url, pin.candidate.workflow_run_id
            )
    {
        bail!("candidate provenance is not bound to the exact source and workflow run");
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
        bail!("{label} must be a lowercase SHA-256 digest");
    }
    Ok(())
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_decimal_id(value: &str, label: &str) -> Result<()> {
    let parsed = value
        .parse::<u64>()
        .with_context(|| format!("{label} id is not an unsigned decimal integer"))?;
    if parsed == 0 || value.starts_with('0') {
        bail!("{label} id is not canonical");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stateweaver_candidate_is_exact_and_non_authoritative() {
        let pin = get_for_tool("stateweaver-foundation")
            .expect("candidate registry")
            .expect("StateWeaver pin");
        assert_eq!(
            pin.pin.source.commit_sha,
            "598753d182dda65c73a313e9efbf20b826942f0a"
        );
        assert_eq!(
            pin.pin.candidate.payload_manifest_sha256,
            "8c7c77d59d4cf3abdcadcce3f2d110ca085789da1ec14a2301245f3418b78bc3"
        );
        assert_eq!(pin.pin.inventory.checksum_entries, 113);
        assert!(!pin.pin.runtime_target.interpreter_included);
        assert!(!pin.pin.native_posture.release_eligible);
        assert_eq!(pin.pin.workbench_admission.authority_effect, "none");
        assert_eq!(execution_readiness(&pin)["state"], "fail_closed");
    }

    #[test]
    fn candidate_pin_rejects_unknown_fields_and_digest_drift() {
        let trusted = get_for_tool("stateweaver-foundation")
            .expect("candidate registry")
            .expect("StateWeaver pin");
        let mut unknown: Value = serde_json::from_str(trusted.raw).unwrap();
        unknown["unexpected"] = json!(true);
        assert!(serde_json::from_value::<CandidatePin>(unknown).is_err());

        let mut drifted = trusted.pin;
        drifted.candidate.payload_manifest_sha256 = "A".repeat(64);
        assert!(validate(&drifted).is_err());
    }
}
