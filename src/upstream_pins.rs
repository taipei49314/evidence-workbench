use crate::{candidate_pins, manifests};
use anyhow::{Context, Result, bail};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamPin {
    pub schema_version: String,
    pub tool_manifest_id: String,
    pub repository_url: String,
    pub source: UpstreamSource,
    pub software_version: String,
    pub release: Option<ReleaseRef>,
    pub evidence: Vec<EvidenceRef>,
    pub runtime: RuntimeClosure,
    pub native_posture: NativePosture,
    pub execution_readiness: ExecutionReadiness,
    pub admission: Admission,
    pub license_spdx: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamSource {
    pub default_branch: String,
    pub commit_sha: String,
    pub tree_sha: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRef {
    pub channel: ReleaseChannel,
    pub version: String,
    pub tag: String,
    pub release_id: Option<String>,
    pub subject_commit_sha: String,
    pub subject_tree_sha: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub kind: EvidenceKind,
    pub id: String,
    pub name: String,
    pub subject_commit_sha: String,
    pub sha256: Option<String>,
    pub size_bytes: Option<u64>,
    pub status: EvidenceStatus,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosure {
    pub kind: RuntimeKind,
    pub target_os: TargetOs,
    pub target_arch: TargetArch,
    pub version_constraint: Option<String>,
    pub interpreter_included: bool,
    pub transitive_dependencies_included: bool,
    pub self_contained: bool,
    pub external_tools: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePosture {
    pub status: NativeStatus,
    pub release_eligible: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReadiness {
    pub state: ReadinessState,
    pub scope: String,
    pub blocker_codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub evidence_integrity_state: EvidenceIntegrityState,
    pub authority_effect: AuthorityEffect,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    WorkflowRun,
    ActionsArtifact,
    ReleaseAsset,
    NativeExecutable,
    SourceRelease,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseChannel {
    Tag,
    GithubRelease,
    CandidateRelease,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Success,
    Failure,
    Blocked,
    Published,
    VerifiedAtAdmission,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKind {
    Native,
    Python,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetOs {
    Any,
    Linux,
    Windows,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetArch {
    Any,
    X86_64,
}

impl TargetOs {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Linux => "linux",
            Self::Windows => "windows",
        }
    }
}

impl TargetArch {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::X86_64 => "x86_64",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessState {
    Ready,
    FailClosed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceIntegrityState {
    SourceVerified,
    PublishedChecksumsVerified,
    VerifiedAtAdmission,
    UpstreamReported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityEffect {
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeStatus {
    AlphaSourceVerified,
    CandidateOnlyNotReleaseAuthorized,
    CandidateReadyForExternalQualification,
    CurrentSourceVerifiedReleaseBlocked,
    ReleasedAlphaNonCertifying,
    SourceQualificationBlocked,
    SourceVerified,
    SourceVerifiedAdvisoryMeasure,
    SourceVerifiedAuthorizationRequired,
}

#[derive(Debug, Clone)]
pub struct TrustedUpstreamPin {
    pub pin: UpstreamPin,
    pub sha256: String,
    pub raw: &'static str,
}

#[derive(Clone, Copy)]
struct EmbeddedUpstreamPin {
    raw: &'static str,
}

const EMBEDDED: &[EmbeddedUpstreamPin] = &[
    EmbeddedUpstreamPin {
        raw: include_str!("../upstream-pins/charterlock.json"),
    },
    EmbeddedUpstreamPin {
        raw: include_str!("../upstream-pins/greenwash.json"),
    },
    EmbeddedUpstreamPin {
        raw: include_str!("../upstream-pins/normshift.json"),
    },
    EmbeddedUpstreamPin {
        raw: include_str!("../upstream-pins/nullbench.json"),
    },
    EmbeddedUpstreamPin {
        raw: include_str!("../upstream-pins/phaseledger.json"),
    },
    EmbeddedUpstreamPin {
        raw: include_str!("../upstream-pins/repopass-inspect.json"),
    },
    EmbeddedUpstreamPin {
        raw: include_str!("../upstream-pins/smallestlie.json"),
    },
    EmbeddedUpstreamPin {
        raw: include_str!("../upstream-pins/stateweaver-foundation.json"),
    },
    EmbeddedUpstreamPin {
        raw: include_str!("../upstream-pins/tomorrowci-lab.json"),
    },
    EmbeddedUpstreamPin {
        raw: include_str!("../upstream-pins/trust-meter.json"),
    },
    EmbeddedUpstreamPin {
        raw: include_str!("../upstream-pins/unasked.json"),
    },
    EmbeddedUpstreamPin {
        raw: include_str!("../upstream-pins/walkaround.json"),
    },
];

pub fn all() -> Result<Vec<TrustedUpstreamPin>> {
    let manifests = manifests::production_all()?;
    let manifest_ids = manifests
        .iter()
        .map(|entry| entry.manifest.manifest_id.clone())
        .collect::<BTreeSet<_>>();
    let mut pins = Vec::new();
    let mut pin_ids = BTreeSet::new();
    for embedded in EMBEDDED {
        let pin: UpstreamPin =
            serde_json::from_str(embedded.raw).context("embedded upstream pin is invalid JSON")?;
        validate(&pin)?;
        let manifest = manifests::get(&pin.tool_manifest_id).with_context(|| {
            format!(
                "upstream pin references unknown tool manifest {}",
                pin.tool_manifest_id
            )
        })?;
        validate_readiness_against_manifest(&pin, &manifest)?;
        if !pin_ids.insert(pin.tool_manifest_id.clone()) {
            bail!(
                "duplicate upstream pin for tool manifest {}",
                pin.tool_manifest_id
            );
        }
        pins.push(TrustedUpstreamPin {
            pin,
            sha256: hex::encode(Sha256::digest(embedded.raw.as_bytes())),
            raw: embedded.raw,
        });
    }
    if pin_ids != manifest_ids {
        let missing = manifest_ids
            .difference(&pin_ids)
            .cloned()
            .collect::<Vec<_>>();
        let extra = pin_ids
            .difference(&manifest_ids)
            .cloned()
            .collect::<Vec<_>>();
        bail!(
            "upstream pin coverage must equal trusted manifest coverage; missing={missing:?} extra={extra:?}"
        );
    }
    pins.sort_by(|left, right| left.pin.tool_manifest_id.cmp(&right.pin.tool_manifest_id));
    cross_validate_stateweaver(&pins)?;
    Ok(pins)
}

pub fn get_for_tool(tool_manifest_id: &str) -> Result<TrustedUpstreamPin> {
    manifests::validate_id(tool_manifest_id)?;
    all()?
        .into_iter()
        .find(|entry| entry.pin.tool_manifest_id == tool_manifest_id)
        .ok_or_else(|| anyhow::anyhow!("missing trusted upstream pin: {tool_manifest_id}"))
}

pub fn summary(pin: &TrustedUpstreamPin) -> Value {
    json!({
        "upstream_pin_sha256": pin.sha256,
        "source_commit": pin.pin.source.commit_sha,
        "source_tree": pin.pin.source.tree_sha,
        "software_version": pin.pin.software_version,
        "native_status": pin.pin.native_posture.status,
        "release_eligible": pin.pin.native_posture.release_eligible,
        "evidence_integrity_state": pin.pin.admission.evidence_integrity_state,
        "authority_effect": pin.pin.admission.authority_effect,
        "execution_readiness": pin.pin.execution_readiness,
        "license_spdx": pin.pin.license_spdx,
    })
}

fn validate(pin: &UpstreamPin) -> Result<()> {
    if pin.schema_version != "upstream_pin/v1" {
        bail!("unsupported upstream pin schema");
    }
    manifests::validate_id(&pin.tool_manifest_id)?;
    validate_repository_url(&pin.repository_url)?;
    if pin.source.default_branch.is_empty()
        || pin.source.default_branch.contains(char::is_whitespace)
        || pin.software_version.is_empty()
        || pin.execution_readiness.scope.is_empty()
        || pin.license_spdx.is_empty()
    {
        bail!("upstream pin contains an empty identity or posture field");
    }
    validate_git_sha1(&pin.source.commit_sha, "source commit")?;
    validate_git_sha1(&pin.source.tree_sha, "source tree")?;
    if let Some(release) = &pin.release {
        if release.version.is_empty() || release.tag.is_empty() {
            bail!("upstream release identity is incomplete");
        }
        validate_git_sha1(&release.subject_commit_sha, "release source commit")?;
        validate_git_sha1(&release.subject_tree_sha, "release source tree")?;
        if let Some(id) = &release.release_id {
            validate_decimal_id(id, "release")?;
        }
    }
    if pin.evidence.is_empty() {
        bail!("upstream pin must retain at least one exact evidence reference");
    }
    let mut evidence_ids = BTreeSet::new();
    for evidence in &pin.evidence {
        if evidence.id.is_empty() || evidence.name.is_empty() {
            bail!("upstream evidence identity is incomplete");
        }
        validate_git_sha1(&evidence.subject_commit_sha, "evidence subject commit")?;
        if !evidence_ids.insert((format!("{:?}", evidence.kind), evidence.id.as_str())) {
            bail!("upstream evidence identity is duplicated");
        }
        if matches!(
            evidence.kind,
            EvidenceKind::WorkflowRun | EvidenceKind::ActionsArtifact | EvidenceKind::ReleaseAsset
        ) {
            validate_decimal_id(&evidence.id, "evidence")?;
        }
        if let Some(digest) = &evidence.sha256 {
            validate_sha256(digest, "evidence")?;
        }
        if let Some(expires_at) = &evidence.expires_at {
            DateTime::parse_from_rfc3339(expires_at).context("evidence expiry is not RFC 3339")?;
        }
    }
    let external_tools = pin.runtime.external_tools.iter().collect::<BTreeSet<_>>();
    if external_tools.len() != pin.runtime.external_tools.len()
        || pin
            .runtime
            .external_tools
            .iter()
            .any(|value| value.is_empty())
    {
        bail!("upstream runtime closure is invalid");
    }
    if pin.admission.authority_effect != AuthorityEffect::None {
        bail!("upstream evidence must never grant workbench authority");
    }
    if pin.admission.evidence_integrity_state == EvidenceIntegrityState::PublishedChecksumsVerified
        && !pin.evidence.iter().any(|evidence| {
            evidence.kind == EvidenceKind::ReleaseAsset
                && evidence.name.eq_ignore_ascii_case("sha256sums.txt")
                && evidence.sha256.is_some()
        })
    {
        bail!("published-checksum integrity must bind the exact checksum asset");
    }
    match pin.execution_readiness.state {
        ReadinessState::Ready if !pin.execution_readiness.blocker_codes.is_empty() => {
            bail!("ready upstream delivery cannot retain execution blockers")
        }
        ReadinessState::FailClosed if pin.execution_readiness.blocker_codes.is_empty() => {
            bail!("fail-closed upstream delivery must name at least one blocker")
        }
        ReadinessState::Ready | ReadinessState::FailClosed => {}
    }
    let blocker_codes = pin
        .execution_readiness
        .blocker_codes
        .iter()
        .collect::<BTreeSet<_>>();
    if blocker_codes.len() != pin.execution_readiness.blocker_codes.len()
        || pin.execution_readiness.blocker_codes.iter().any(|code| {
            code.is_empty()
                || code.starts_with('-')
                || code.ends_with('-')
                || !code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
    {
        bail!("upstream blocker code is not canonical snake_case");
    }
    Ok(())
}

fn validate_readiness_against_manifest(
    pin: &UpstreamPin,
    manifest: &manifests::TrustedManifest,
) -> Result<()> {
    let ready = pin.execution_readiness.state == ReadinessState::Ready;
    if ready {
        bail!("no current upstream delivery has a complete immutable runtime closure");
    }
    if manifest.manifest.enabled_by_default {
        bail!("a fail-closed upstream delivery cannot have an enabled production adapter");
    }
    Ok(())
}

fn cross_validate_stateweaver(pins: &[TrustedUpstreamPin]) -> Result<()> {
    let upstream = pins
        .iter()
        .find(|entry| entry.pin.tool_manifest_id == "stateweaver-foundation")
        .context("StateWeaver upstream pin missing")?;
    let candidate = candidate_pins::get_for_tool("stateweaver-foundation")?
        .context("StateWeaver detailed candidate pin missing")?;
    let artifact = upstream
        .pin
        .evidence
        .iter()
        .find(|evidence| evidence.kind == EvidenceKind::ActionsArtifact)
        .context("StateWeaver generic Actions artifact missing")?;
    let expected_runtime_constraint = format!(
        "{} {} {}",
        candidate.pin.runtime_target.implementation,
        candidate.pin.runtime_target.python_version,
        candidate.pin.runtime_target.python_abi
    );
    if upstream.pin.repository_url != candidate.pin.repository_url
        || upstream.pin.source.commit_sha != candidate.pin.source.commit_sha
        || upstream.pin.source.tree_sha != candidate.pin.source.tree_sha
        || artifact.id != candidate.pin.candidate.actions_artifact_id
        || artifact.name != candidate.pin.candidate.actions_artifact_name
        || artifact.subject_commit_sha != candidate.pin.source.commit_sha
        || artifact.sha256.as_deref() != Some(&candidate.pin.candidate.actions_artifact_sha256)
        || artifact.expires_at.as_deref() != Some(&candidate.pin.candidate.expires_at)
        || upstream.pin.runtime.kind != RuntimeKind::Python
        || upstream.pin.runtime.target_os.as_str() != candidate.pin.runtime_target.os.as_str()
        || upstream.pin.runtime.target_arch.as_str() != candidate.pin.runtime_target.arch.as_str()
        || !upstream
            .pin
            .runtime
            .version_constraint
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case(&expected_runtime_constraint))
        || upstream.pin.runtime.interpreter_included
            != candidate.pin.runtime_target.interpreter_included
        || serde_json::to_value(&upstream.pin.native_posture.status)?
            != Value::String(candidate.pin.native_posture.status.clone())
        || upstream.pin.native_posture.release_eligible
            != Some(candidate.pin.native_posture.release_eligible)
        || upstream.pin.admission.authority_effect != AuthorityEffect::None
        || candidate.pin.workbench_admission.authority_effect != "none"
    {
        bail!("generic StateWeaver upstream pin diverges from candidate_pin/v1");
    }
    Ok(())
}

fn validate_repository_url(value: &str) -> Result<()> {
    let repository = value
        .strip_prefix("https://github.com/")
        .ok_or_else(|| anyhow::anyhow!("upstream repository must use GitHub HTTPS"))?;
    let parts = repository.split('/').collect::<Vec<_>>();
    if parts.len() != 2
        || parts.iter().any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        bail!("upstream repository URL must be an exact GitHub HTTPS URL");
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
    fn registry_covers_all_manifests_without_authority_or_aggregate_pass() {
        let pins = all().expect("upstream pin registry");
        assert_eq!(pins.len(), 12);
        assert_eq!(manifests::production_all().unwrap().len(), pins.len());
        for pin in &pins {
            assert_eq!(pin.pin.admission.authority_effect, AuthorityEffect::None);
            assert!(serde_json::to_value(&pin.pin.native_posture.status).unwrap() != json!("PASS"));
        }
        let ready = pins
            .iter()
            .filter(|pin| pin.pin.execution_readiness.state == ReadinessState::Ready)
            .collect::<Vec<_>>();
        assert!(ready.is_empty());
    }

    #[test]
    fn unknown_fields_and_authority_laundering_are_rejected() {
        let trusted = get_for_tool("unasked").unwrap();
        let mut unknown: Value = serde_json::from_str(trusted.raw).unwrap();
        unknown["aggregate_pass"] = json!(true);
        assert!(serde_json::from_value::<UpstreamPin>(unknown).is_err());
        let mut laundered = serde_json::to_value(trusted.pin).unwrap();
        laundered["admission"]["authority_effect"] = json!("verified");
        assert!(serde_json::from_value::<UpstreamPin>(laundered).is_err());
    }

    #[test]
    fn admission_catalog_pins_are_exact_fail_closed_and_cannot_launder_authority() {
        let expected = [
            (
                "walkaround",
                "0ecf7b206201fb670778639e4bf04ed58b6a797c",
                "eb6dea58f0e4db601be7dfae28c56d0c72b59bd3",
                "31724500299",
            ),
            (
                "charterlock",
                "0e0c9188474ea977d550ffc50a8095e1203d63c7",
                "ecfed649b5da34ee01764134975f9a02262a9076",
                "31724051397",
            ),
        ];

        for (tool_id, commit, tree, workflow_run) in expected {
            let trusted = get_for_tool(tool_id).expect("trusted admission pin");
            assert_eq!(trusted.pin.source.commit_sha, commit);
            assert_eq!(trusted.pin.source.tree_sha, tree);
            assert!(trusted.pin.release.is_none());
            assert_eq!(trusted.pin.evidence.len(), 1);
            assert_eq!(trusted.pin.evidence[0].kind, EvidenceKind::WorkflowRun);
            assert_eq!(trusted.pin.evidence[0].id, workflow_run);
            assert_eq!(
                trusted.pin.execution_readiness.state,
                ReadinessState::FailClosed
            );
            assert_eq!(
                trusted.pin.admission.authority_effect,
                AuthorityEffect::None
            );

            let manifest = manifests::get(tool_id).expect("trusted admission manifest");
            assert!(!manifest.manifest.enabled_by_default);
            assert_eq!(
                manifest.manifest.invocation_contract.operation,
                "catalog_only"
            );
            assert_eq!(manifest.manifest.authority_contract.mode, "not_reported");

            let mut laundered = serde_json::to_value(&trusted.pin).unwrap();
            laundered["admission"]["authority_effect"] = json!("verified");
            assert!(serde_json::from_value::<UpstreamPin>(laundered).is_err());
        }
    }

    #[test]
    fn stateweaver_overlapping_candidate_fields_are_cross_bound() {
        let pins = all().expect("upstream registry");
        let stateweaver = pins
            .iter()
            .find(|pin| pin.pin.tool_manifest_id == "stateweaver-foundation")
            .expect("StateWeaver upstream pin");
        let candidate = candidate_pins::get_for_tool("stateweaver-foundation")
            .unwrap()
            .expect("StateWeaver candidate pin");
        assert_eq!(stateweaver.pin.repository_url, candidate.pin.repository_url);
        let artifact = stateweaver
            .pin
            .evidence
            .iter()
            .find(|evidence| evidence.kind == EvidenceKind::ActionsArtifact)
            .unwrap();
        assert_eq!(artifact.name, candidate.pin.candidate.actions_artifact_name);
        assert_eq!(
            artifact.expires_at.as_deref(),
            Some(candidate.pin.candidate.expires_at.as_str())
        );
        assert_eq!(
            stateweaver.pin.runtime.interpreter_included,
            candidate.pin.runtime_target.interpreter_included
        );
        assert_eq!(
            stateweaver.pin.native_posture.release_eligible,
            Some(candidate.pin.native_posture.release_eligible)
        );
    }
}
