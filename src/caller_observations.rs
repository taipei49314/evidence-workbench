use crate::contracts::{ContractAuthorityEffect, PhaseledgerCallerObservation};
use crate::workspace;
use anyhow::{Result, bail};
use serde_json::{Value, json};

const FORBIDDEN_CHECK_NAMES: &[&str] = &[
    "passed",
    "overall_score",
    "advisory_gate_met",
    "threshold_met",
    "all_metrics_passed",
];

const REQUIRED_CLAIM_TOKENS: &[&str] = &["untrusted_exact_bytes", "authority_effect none"];

pub fn validate(observation: &PhaseledgerCallerObservation) -> Result<()> {
    if observation.schema_version != "phaseledger-caller-observation/v1" {
        bail!("unsupported Phaseledger caller observation schema");
    }
    if observation.phase.trim().is_empty() || observation.claim.trim().is_empty() {
        bail!("Phaseledger caller observation phase and claim must be nonempty");
    }
    if !observation.artifact_present {
        bail!("Phaseledger caller observation must cite a present exact artifact");
    }
    workspace::validate_prefixed_id(&observation.cited_artifact.artifact_id, "artifact_")?;
    workspace::validate_sha256(&observation.artifact_sha256)?;
    if observation.cited_artifact.digest.algorithm != "sha256" {
        bail!("Phaseledger caller observation digest algorithm must be sha256");
    }
    workspace::validate_sha256(&observation.cited_artifact.digest.value)?;
    if observation.artifact_sha256 != observation.cited_artifact.digest.value {
        bail!(
            "Phaseledger caller observation artifact_sha256 must equal the cited artifact digest"
        );
    }
    if observation.cited_artifact.byte_length == 0 {
        bail!("Phaseledger caller observation cited artifact must contain bytes");
    }
    if !observation
        .claim
        .contains(&observation.cited_artifact.artifact_id)
    {
        bail!("Phaseledger caller observation claim must name the cited artifact id");
    }
    if !observation
        .claim
        .contains(&observation.cited_artifact.digest.value)
    {
        bail!("Phaseledger caller observation claim must name the cited artifact digest");
    }
    for token in REQUIRED_CLAIM_TOKENS {
        if !observation.claim.contains(token) {
            bail!("Phaseledger caller observation claim must include {token}");
        }
    }
    if observation.checks.is_empty() {
        bail!("Phaseledger caller observation must include caller-authored checks");
    }
    let mut names = std::collections::BTreeSet::new();
    for check in &observation.checks {
        if check.name.trim().is_empty() || check.name.trim() != check.name {
            bail!("Phaseledger caller observation check names must be nonempty and trimmed");
        }
        if FORBIDDEN_CHECK_NAMES.contains(&check.name.as_str()) {
            bail!(
                "Phaseledger caller observation must not copy Trust Meter field {} into checks",
                check.name
            );
        }
        if !names.insert(check.name.as_str()) {
            bail!("Phaseledger caller observation check names must be unique");
        }
    }
    if observation.unsupported.freshness != "unsupported"
        || observation.unsupported.producer_run_scope != "unsupported"
    {
        bail!("Phaseledger 0.6.0 freshness and producer-run scope remain unsupported");
    }
    if observation.authority_effect != ContractAuthorityEffect::None {
        bail!("Phaseledger caller observation authority_effect must be none");
    }
    Ok(())
}

pub fn map_to_phaseledger_v1(observation: &PhaseledgerCallerObservation) -> Result<Value> {
    validate(observation)?;
    Ok(json!({
        "phase": observation.phase,
        "claim": observation.claim,
        "artifact_present": true,
        "artifact_sha256": observation.artifact_sha256,
        "checks": observation
            .checks
            .iter()
            .map(|check| json!({"name": check.name, "passed": check.passed}))
            .collect::<Vec<_>>(),
    }))
}

pub fn reject_ewb_synthesized_trust_meter_fields(source: &str) -> Result<()> {
    let lowered = source.to_ascii_lowercase();
    if lowered.contains("advisory_gate_met")
        && (lowered.contains("phaseledger") && lowered.contains("observation"))
        && (lowered.contains("write") || lowered.contains("synthesize") || lowered.contains("copy"))
    {
        bail!("EWB must not synthesize Trust Meter projections into Phaseledger observations");
    }
    Ok(())
}

pub fn forbidden_check_names() -> &'static [&'static str] {
    FORBIDDEN_CHECK_NAMES
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::PhaseledgerCallerCheck;
    use crate::data_contract_validation::parse_phaseledger_caller_observation;
    use serde_json::json;

    const EXAMPLE: &[u8] =
        include_bytes!("../contracts/examples/phaseledger-caller-observation-v1.example.json");

    fn example() -> PhaseledgerCallerObservation {
        parse_phaseledger_caller_observation(EXAMPLE).unwrap()
    }

    #[test]
    fn example_is_valid_and_maps_to_phaseledger_native_shape() {
        let observation = example();
        validate(&observation).unwrap();
        let native = map_to_phaseledger_v1(&observation).unwrap();
        assert_eq!(native["artifact_sha256"], observation.artifact_sha256);
        assert!(native.get("cited_artifact").is_none());
        assert!(native.get("unsupported").is_none());
        assert!(native.get("authority_effect").is_none());
        assert!(native.get("schema_version").is_none());
    }

    #[test]
    fn digest_mismatch_fails_closed() {
        let mut observation = example();
        observation.artifact_sha256 = "00".repeat(32);
        assert!(
            validate(&observation)
                .unwrap_err()
                .to_string()
                .contains("must equal the cited artifact digest")
        );
    }

    #[test]
    fn trust_meter_field_names_cannot_become_checks() {
        for name in FORBIDDEN_CHECK_NAMES {
            let mut observation = example();
            observation.checks = vec![PhaseledgerCallerCheck {
                name: (*name).to_owned(),
                passed: true,
            }];
            assert!(
                validate(&observation)
                    .unwrap_err()
                    .to_string()
                    .contains("must not copy Trust Meter field"),
                "{name}"
            );
        }
    }

    #[test]
    fn claim_must_cite_exact_bytes_and_no_authority() {
        let mut observation = example();
        observation.claim = "artifact looks good".to_owned();
        assert!(validate(&observation).is_err());
    }

    #[test]
    fn granted_or_freshness_fields_are_rejected() {
        let mut value = serde_json::from_slice::<Value>(EXAMPLE).unwrap();
        value["authority_effect"] = json!("transferred");
        assert!(
            parse_phaseledger_caller_observation(&serde_json::to_vec(&value).unwrap()).is_err()
        );
        value = serde_json::from_slice::<Value>(EXAMPLE).unwrap();
        value["unsupported"]["freshness"] = json!("producer_run_timestamp");
        assert!(
            parse_phaseledger_caller_observation(&serde_json::to_vec(&value).unwrap()).is_err()
        );
    }
}
