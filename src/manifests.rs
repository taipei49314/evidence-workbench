use crate::contracts::{Digest, LimitationItem, ToolRef};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolManifest {
    pub schema_version: String,
    pub manifest_id: String,
    pub display_name: String,
    pub stability: String,
    pub enabled_by_default: bool,
    pub adapter: ManifestAdapter,
    pub identity_contract: IdentityContract,
    pub subject_kind: String,
    pub invocation_contract: InvocationContract,
    pub artifact_contracts: Vec<ArtifactContract>,
    pub native_observation_contracts: Vec<ObservationContract>,
    pub exit_code_contract: ExitCodeContract,
    pub authority_contract: AuthorityContract,
    pub limitations: Vec<ManifestLimitation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestAdapter {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityContract {
    pub executable_candidates: Vec<String>,
    pub version_probe: Option<VersionProbe>,
    pub binary_digest_required: bool,
    #[serde(default)]
    pub allowed_binary_sha256: Vec<String>,
    pub python_distribution: Option<String>,
    pub supporting_tree_digest_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionProbe {
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationContract {
    pub mode: String,
    pub operation: String,
    pub parameters: Vec<ParameterContract>,
    pub required_capabilities: Vec<String>,
    pub target_code_execution: String,
    pub network: String,
    pub filesystem_write: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterContract {
    pub name: String,
    pub required: bool,
    pub kind: String,
    pub default: Option<String>,
    pub allowed_values: Vec<String>,
    pub minimum: Option<i64>,
    pub maximum: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactContract {
    pub role: String,
    pub discovery: String,
    pub required_when: String,
    pub byte_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationContract {
    pub namespace: String,
    pub name: String,
    pub artifact_role: String,
    pub format: String,
    pub selector: String,
    pub required_when: String,
    pub unknown_value_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitCodeContract {
    pub entries: Vec<ExitCodeEntry>,
    pub unknown_code_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitCodeEntry {
    pub code: i32,
    pub native_meaning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityContract {
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestLimitation {
    pub code: String,
    pub statement: String,
}

#[derive(Clone, Copy)]
struct EmbeddedManifest {
    raw: &'static str,
}

const PRODUCTION_EMBEDDED: &[EmbeddedManifest] = &[
    EmbeddedManifest {
        raw: include_str!("../manifests/charterlock.json"),
    },
    EmbeddedManifest {
        raw: include_str!("../manifests/greenwash.json"),
    },
    EmbeddedManifest {
        raw: include_str!("../manifests/repopass-inspect.json"),
    },
    EmbeddedManifest {
        raw: include_str!("../manifests/trust-meter.json"),
    },
    EmbeddedManifest {
        raw: include_str!("../manifests/phaseledger.json"),
    },
    EmbeddedManifest {
        raw: include_str!("../manifests/stateweaver-foundation.json"),
    },
    EmbeddedManifest {
        raw: include_str!("../manifests/unasked.json"),
    },
    EmbeddedManifest {
        raw: include_str!("../manifests/walkaround.json"),
    },
    EmbeddedManifest {
        raw: include_str!("../manifests/tomorrowci-lab.json"),
    },
    EmbeddedManifest {
        raw: include_str!("../manifests/normshift.json"),
    },
    EmbeddedManifest {
        raw: include_str!("../manifests/smallestlie.json"),
    },
    EmbeddedManifest {
        raw: include_str!("../manifests/nullbench.json"),
    },
];

#[derive(Debug, Clone)]
pub struct TrustedManifest {
    pub manifest: ToolManifest,
    pub sha256: String,
    pub raw: &'static str,
}

pub fn all() -> Result<Vec<TrustedManifest>> {
    load_embedded(PRODUCTION_EMBEDDED.iter())
}

pub fn production_all() -> Result<Vec<TrustedManifest>> {
    load_embedded(PRODUCTION_EMBEDDED.iter())
}

fn load_embedded<'a>(
    embedded_manifests: impl Iterator<Item = &'a EmbeddedManifest>,
) -> Result<Vec<TrustedManifest>> {
    let mut manifests = Vec::new();
    let mut ids = BTreeSet::new();
    for embedded in embedded_manifests {
        let manifest: ToolManifest =
            serde_json::from_str(embedded.raw).context("embedded tool manifest is invalid JSON")?;
        validate_manifest(&manifest)?;
        if !ids.insert(manifest.manifest_id.clone()) {
            bail!("duplicate embedded manifest id: {}", manifest.manifest_id);
        }
        let sha256 = hex::encode(Sha256::digest(embedded.raw.as_bytes()));
        manifests.push(TrustedManifest {
            manifest,
            sha256,
            raw: embedded.raw,
        });
    }
    manifests.sort_by(|left, right| left.manifest.manifest_id.cmp(&right.manifest.manifest_id));
    Ok(manifests)
}

pub fn get(id: &str) -> Result<TrustedManifest> {
    validate_id(id)?;
    all()?
        .into_iter()
        .find(|entry| entry.manifest.manifest_id == id)
        .ok_or_else(|| anyhow::anyhow!("unknown trusted tool manifest: {id}"))
}

pub fn get_by_ref(tool_ref: &ToolRef) -> Result<TrustedManifest> {
    let manifest = get(&tool_ref.manifest_id)?;
    if tool_ref.manifest_sha256 != manifest.sha256 {
        bail!(
            "tool reference does not match the exact embedded manifest: {}",
            tool_ref.manifest_id
        );
    }
    Ok(manifest)
}

pub fn validate_id(id: &str) -> Result<()> {
    let valid = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !valid || id.starts_with('-') || id.ends_with('-') {
        bail!("invalid ASCII tool id: {id:?}");
    }
    Ok(())
}

pub fn adapter_implemented(manifest: &ToolManifest) -> bool {
    manifest.invocation_contract.operation != "catalog_only"
}

pub fn validate_manifest(manifest: &ToolManifest) -> Result<()> {
    if manifest.schema_version != "tool_manifest/v1" {
        bail!("unsupported manifest schema for {}", manifest.manifest_id);
    }
    validate_id(&manifest.manifest_id)?;
    if !matches!(manifest.stability.as_str(), "stable" | "experimental") {
        bail!(
            "manifest {} has an unsupported stability",
            manifest.manifest_id
        );
    }
    if manifest.invocation_contract.mode != "direct_exec" {
        bail!("manifest {} must use direct_exec", manifest.manifest_id);
    }
    if !manifest.identity_contract.binary_digest_required {
        bail!(
            "manifest {} must require a binary digest",
            manifest.manifest_id
        );
    }
    if manifest.identity_contract.supporting_tree_digest_required
        && manifest.identity_contract.python_distribution.is_none()
    {
        bail!(
            "manifest {} requires an unspecified supporting tree",
            manifest.manifest_id
        );
    }
    if manifest.identity_contract.executable_candidates.is_empty() {
        bail!(
            "manifest {} has no executable candidate",
            manifest.manifest_id
        );
    }
    if manifest.enabled_by_default
        && manifest.identity_contract.python_distribution.is_none()
        && manifest.identity_contract.allowed_binary_sha256.is_empty()
    {
        bail!(
            "enabled native manifest {} must admit exact executable bytes",
            manifest.manifest_id
        );
    }
    let mut allowed_binary_digests = BTreeSet::new();
    for digest in &manifest.identity_contract.allowed_binary_sha256 {
        let valid = digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
        if !valid || !allowed_binary_digests.insert(digest) {
            bail!(
                "manifest {} has an invalid or duplicate allowed binary digest",
                manifest.manifest_id
            );
        }
    }
    for candidate in &manifest.identity_contract.executable_candidates {
        if candidate.contains('/')
            || candidate.contains('\\')
            || candidate.contains(char::is_whitespace)
        {
            bail!(
                "manifest {} has unsafe executable candidate",
                manifest.manifest_id
            );
        }
        let lower = candidate.to_ascii_lowercase();
        if lower.ends_with(".cmd") || lower.ends_with(".bat") {
            bail!(
                "manifest {} names a shell script executable",
                manifest.manifest_id
            );
        }
    }
    for artifact in &manifest.artifact_contracts {
        if artifact.byte_policy != "exact" {
            bail!(
                "manifest {} permits transformed native bytes",
                manifest.manifest_id
            );
        }
    }
    if manifest.exit_code_contract.unknown_code_policy != "preserve_unrecognized" {
        bail!(
            "manifest {} would flatten an unknown exit code",
            manifest.manifest_id
        );
    }
    if manifest.authority_contract.mode != "not_reported" {
        bail!("v1 only accepts native authority extraction; none is configured yet");
    }
    Ok(())
}

pub fn validate_parameters(
    manifest: &ToolManifest,
    supplied: &[String],
) -> Result<BTreeMap<String, String>> {
    let contracts: BTreeMap<_, _> = manifest
        .invocation_contract
        .parameters
        .iter()
        .map(|parameter| (parameter.name.as_str(), parameter))
        .collect();
    let mut values = BTreeMap::new();
    for item in supplied {
        let (name, value) = item
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("parameter must be NAME=VALUE: {item:?}"))?;
        let contract = contracts.get(name).ok_or_else(|| {
            anyhow::anyhow!("unknown parameter for {}: {name}", manifest.manifest_id)
        })?;
        if values.insert(name.to_owned(), value.to_owned()).is_some() {
            bail!("duplicate parameter: {name}");
        }
        validate_parameter(contract, value)?;
    }
    for contract in contracts.values() {
        if !values.contains_key(&contract.name) {
            if let Some(default) = &contract.default {
                values.insert(contract.name.clone(), default.clone());
            } else if contract.required {
                bail!("missing required parameter: {}", contract.name);
            }
        }
    }
    Ok(values)
}

fn validate_parameter(contract: &ParameterContract, value: &str) -> Result<()> {
    match contract.kind.as_str() {
        "git_revision" => {
            let valid = (value.len() == 40 || value.len() == 64)
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
            if !valid {
                bail!(
                    "{} must be a lowercase 40- or 64-hex object id",
                    contract.name
                );
            }
        }
        "enum" => {
            if !contract
                .allowed_values
                .iter()
                .any(|allowed| allowed == value)
            {
                bail!("{} has an unsupported value", contract.name);
            }
        }
        "integer" => {
            let parsed: i64 = value.parse().context("parameter is not an integer")?;
            if contract.minimum.is_some_and(|minimum| parsed < minimum)
                || contract.maximum.is_some_and(|maximum| parsed > maximum)
            {
                bail!("{} is outside its permitted range", contract.name);
            }
        }
        "identifier" => {
            let valid = !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
            if !valid {
                bail!("{} must be a short ASCII identifier", contract.name);
            }
        }
        other => bail!("unsupported parameter kind: {other}"),
    }
    Ok(())
}

pub fn limitation_items(manifest: &TrustedManifest) -> Vec<LimitationItem> {
    manifest
        .manifest
        .limitations
        .iter()
        .enumerate()
        .map(|(index, limitation)| LimitationItem {
            namespace: manifest.manifest.manifest_id.clone(),
            code: limitation.code.clone(),
            statement: limitation.statement.clone(),
            origin: "manifest".to_owned(),
            source: format!(
                "embedded-manifest:sha256:{}#/limitations/{index}",
                manifest.sha256
            ),
        })
        .collect()
}

pub fn manifest_digest(manifest: &TrustedManifest) -> Digest {
    Digest {
        algorithm: "sha256".to_owned(),
        value: manifest.sha256.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_registry_stays_at_twelve_and_repopass_stays_disabled() {
        assert_eq!(PRODUCTION_EMBEDDED.len(), 12);
        assert_eq!(production_all().expect("production manifests").len(), 12);
        let repopass: ToolManifest = serde_json::from_str(
            PRODUCTION_EMBEDDED
                .iter()
                .find(|embedded| embedded.raw.contains("\"repopass-inspect\""))
                .expect("RepoPassport production manifest")
                .raw,
        )
        .expect("valid production manifest");
        assert!(!repopass.enabled_by_default);
    }

    #[test]
    fn admission_catalog_manifests_stay_schema_valid_disabled_and_non_authoritative() {
        for tool_id in ["walkaround", "charterlock"] {
            let trusted = get(tool_id).expect("trusted admission manifest");
            assert_eq!(trusted.manifest.schema_version, "tool_manifest/v1");
            assert!(!trusted.manifest.enabled_by_default);
            assert_eq!(
                trusted.manifest.invocation_contract.operation,
                "catalog_only"
            );
            assert!(trusted.manifest.native_observation_contracts.is_empty());
            assert!(trusted.manifest.exit_code_contract.entries.is_empty());
            assert_eq!(trusted.manifest.authority_contract.mode, "not_reported");

            let mut laundered = trusted.manifest.clone();
            laundered.authority_contract.mode = "verified".to_owned();
            assert!(validate_manifest(&laundered).is_err());
        }
    }
}
