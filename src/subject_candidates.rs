use crate::contracts::{ArtifactDescriptor, SubjectCandidateRecord, SubjectCandidateRecordPayload};
use crate::data_contract_validation;
use crate::workspace::{self, Workspace};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const CANDIDATE_ROLE: &str = "subject_candidate_descriptor";
const CANDIDATE_MEDIA_TYPE: &str = "application/vnd.evidence-workbench.subject-candidate-v1+json";

#[derive(Debug, Serialize)]
pub struct SubjectCandidateVerification {
    pub candidate_id: String,
    pub record_digest: String,
    pub candidate_sha256: String,
    pub candidate_artifact_id: String,
    pub source_artifact_id: String,
    pub source_artifact_record_digest: String,
    pub repository_url: String,
    pub commit_sha: String,
    pub tree_sha: String,
    pub trust_state: &'static str,
    pub admission_requirement: &'static str,
    pub authority_effect: &'static str,
    pub verified: bool,
}

pub fn import(workspace: &Workspace, descriptor: &Path) -> Result<SubjectCandidateRecord> {
    let descriptor = canonical_regular_file(descriptor, "subject candidate descriptor")?;
    let bytes = read_stable_bytes(&descriptor)?;
    let candidate = data_contract_validation::parse_subject_candidate(&bytes)?;
    let destination = workspace
        .state
        .join("candidates")
        .join(format!("{}.json", candidate.candidate_id));
    if destination.exists() {
        bail!(
            "subject candidate {} is already present in this workspace registry",
            candidate.candidate_id
        );
    }

    // Resolve and re-hash the complete source descriptor and object before any
    // candidate bytes or registry state are committed.
    let source = verify_source_artifact_binding(workspace, &candidate.source_artifact)?;
    let candidate_sha256 = hex::encode(Sha256::digest(&bytes));
    let candidate_artifact = workspace.import_artifact_bytes(
        &bytes,
        vec![CANDIDATE_ROLE.to_owned()],
        CANDIDATE_MEDIA_TYPE.to_owned(),
        "native_file",
        "byte_for_byte_copy",
    )?;
    if candidate_artifact.digest.value != candidate_sha256 {
        bail!("captured subject candidate bytes changed during import");
    }
    let payload = SubjectCandidateRecordPayload {
        candidate_sha256,
        candidate_artifact_id: candidate_artifact.artifact_id,
        source_artifact_record_digest: source.record_digest,
        candidate,
    };
    let record = SubjectCandidateRecord {
        schema_version: "subject_candidate_record/v1".to_owned(),
        candidate_id: payload.candidate.candidate_id.clone(),
        record_digest: workspace::digest_serialized(&payload)?,
        payload,
    };
    verify_record(workspace, &record)?;
    workspace.write_subject_candidate(&record)?;
    Ok(record)
}

pub fn load_verified(workspace: &Workspace, candidate_id: &str) -> Result<SubjectCandidateRecord> {
    let record = workspace.load_subject_candidate(candidate_id)?;
    verify_record(workspace, &record)?;
    Ok(record)
}

pub fn list_verified(workspace: &Workspace) -> Result<Vec<SubjectCandidateRecord>> {
    let records = workspace.list_subject_candidates()?;
    for record in &records {
        verify_record(workspace, record)?;
    }
    Ok(records)
}

pub fn verify(workspace: &Workspace, candidate_id: &str) -> Result<SubjectCandidateVerification> {
    let record = load_verified(workspace, candidate_id)?;
    let candidate = &record.payload.candidate;
    Ok(SubjectCandidateVerification {
        candidate_id: record.candidate_id.clone(),
        record_digest: record.record_digest.clone(),
        candidate_sha256: record.payload.candidate_sha256.clone(),
        candidate_artifact_id: record.payload.candidate_artifact_id.clone(),
        source_artifact_id: candidate.source_artifact.artifact_id.clone(),
        source_artifact_record_digest: record.payload.source_artifact_record_digest.clone(),
        repository_url: candidate.repository_url.clone(),
        commit_sha: candidate.resolved_source.commit_sha.clone(),
        tree_sha: candidate.resolved_source.tree_sha.clone(),
        trust_state: "untrusted_candidate",
        admission_requirement: "ewb_reresolve_commit_and_tree",
        authority_effect: "none",
        verified: true,
    })
}

fn verify_record(workspace: &Workspace, record: &SubjectCandidateRecord) -> Result<()> {
    if record.schema_version != "subject_candidate_record/v1"
        || record.candidate_id != record.payload.candidate.candidate_id
    {
        bail!("subject candidate record identity mismatch");
    }
    workspace::validate_prefixed_id(&record.candidate_id, "candidate_")?;
    workspace::validate_sha256(&record.payload.candidate_sha256)?;
    workspace::validate_sha256(&record.payload.source_artifact_record_digest)?;
    if workspace::digest_serialized(&record.payload)? != record.record_digest {
        bail!("subject candidate record digest mismatch");
    }
    data_contract_validation::validate_subject_candidate(&record.payload.candidate)?;
    let source =
        verify_source_artifact_binding(workspace, &record.payload.candidate.source_artifact)?;
    if source.record_digest != record.payload.source_artifact_record_digest {
        bail!("subject candidate source artifact record digest mismatch");
    }

    let descriptor = verify_candidate_artifact(workspace, record)?;
    let bytes = workspace.read_verified_descriptor(&descriptor)?;
    if hex::encode(Sha256::digest(&bytes)) != record.payload.candidate_sha256 {
        bail!("subject candidate descriptor digest mismatch");
    }
    let parsed = data_contract_validation::parse_subject_candidate(&bytes)?;
    if parsed != record.payload.candidate {
        bail!("subject candidate descriptor bytes do not match the registry record");
    }
    Ok(())
}

fn verify_source_artifact_binding(
    workspace: &Workspace,
    reference: &crate::contracts::ContractArtifactRef,
) -> Result<crate::contracts::ArtifactRecord> {
    let record = workspace
        .load_artifact(&reference.artifact_id)
        .with_context(|| {
            format!(
                "subject candidate source artifact {} is not present in this workspace",
                reference.artifact_id
            )
        })?;
    if record.artifact.digest != reference.digest {
        bail!("subject candidate source artifact digest mismatch");
    }
    if record.artifact.roles != ["github_discovery"]
        || record.artifact.origin != "native_file"
        || record.artifact.capture.mode != "byte_for_byte_copy"
        || !record.artifact.transforms.is_empty()
    {
        bail!(
            "subject candidate source artifact must be an exact github_discovery byte-for-byte native file capture"
        );
    }
    // Read through the verified descriptor, rather than accepting the record's
    // metadata alone. This re-hashes the exact source object bytes on every path.
    workspace.read_verified_descriptor(&record.artifact)?;
    Ok(record)
}

fn verify_candidate_artifact(
    workspace: &Workspace,
    record: &SubjectCandidateRecord,
) -> Result<ArtifactDescriptor> {
    let artifact = workspace
        .load_artifact(&record.payload.candidate_artifact_id)?
        .artifact;
    if artifact.digest.algorithm != "sha256"
        || artifact.digest.value != record.payload.candidate_sha256
        || artifact.roles != [CANDIDATE_ROLE]
        || artifact.media_type != CANDIDATE_MEDIA_TYPE
        || artifact.origin != "native_file"
        || artifact.capture.mode != "byte_for_byte_copy"
        || !artifact.transforms.is_empty()
    {
        bail!("subject candidate artifact snapshot identity mismatch");
    }
    Ok(artifact)
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

fn read_stable_bytes(path: &Path) -> Result<Vec<u8>> {
    let before = fs::metadata(path)?;
    let bytes = fs::read(path)?;
    let after = fs::metadata(path)?;
    if before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || u64::try_from(bytes.len()).ok() != Some(before.len())
    {
        bail!("subject candidate descriptor changed while it was being read");
    }
    Ok(bytes)
}

#[cfg(windows)]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x0000_0400 != 0
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

    struct Fixture {
        _temp: TempDir,
        workspace: Workspace,
        descriptor: PathBuf,
        candidate_id: String,
        source_artifact_id: String,
        source_digest: String,
    }

    fn fixture() -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("workspace");
        fs::create_dir(&root).unwrap();
        let workspace = Workspace::init(&root).unwrap();
        let report = temp.path().join("report.json");
        fs::write(&report, br#"{"observed":"github"}"#).unwrap();
        let source = workspace
            .import_artifact(
                &report,
                vec!["github_discovery".to_owned()],
                "application/json".to_owned(),
                "native_file",
                "byte_for_byte_copy",
            )
            .unwrap();
        let seed = [
            "subject-candidate/v1",
            "github-radar",
            "0.1.0",
            "https://github.com/owner/repo",
            &"1".repeat(40),
            &"2".repeat(40),
            &source.artifact_id,
            &source.digest.value,
        ]
        .join("\0");
        let candidate_id = format!(
            "candidate_{}",
            &hex::encode(Sha256::digest(seed.as_bytes()))[..32]
        );
        let candidate = json!({
            "schema_version": "subject-candidate/v1",
            "candidate_id": candidate_id,
            "producer": {"id": "github-radar", "version": "0.1.0"},
            "repository_url": "https://github.com/owner/repo",
            "resolved_source": {"commit_sha":"1".repeat(40),"tree_sha":"2".repeat(40)},
            "observed_at": "2026-08-14T00:00:00Z",
            "source_artifact": {"artifact_id": source.artifact_id,"digest":source.digest},
            "limitations": [{"code":"discovery_only","statement":"Untrusted discovery."}],
            "trust_state": "untrusted_candidate",
            "admission_requirement": "ewb_reresolve_commit_and_tree",
            "authority_effect": "none"
        });
        let descriptor = temp.path().join("candidate.json");
        fs::write(&descriptor, serde_json::to_vec_pretty(&candidate).unwrap()).unwrap();
        Fixture {
            _temp: temp,
            workspace,
            descriptor,
            candidate_id,
            source_artifact_id: candidate["source_artifact"]["artifact_id"]
                .as_str()
                .unwrap()
                .to_owned(),
            source_digest: candidate["source_artifact"]["digest"]["value"]
                .as_str()
                .unwrap()
                .to_owned(),
        }
    }

    #[test]
    fn detects_candidate_object_and_record_tampering() {
        let fixture = fixture();
        let record = import(&fixture.workspace, &fixture.descriptor).unwrap();
        let candidate_object = fixture
            .workspace
            .object_path(&record.payload.candidate_sha256)
            .unwrap();
        let original = fs::read(&candidate_object).unwrap();
        fs::write(&candidate_object, vec![b'x'; original.len()]).unwrap();
        assert!(load_verified(&fixture.workspace, &fixture.candidate_id).is_err());

        fs::write(&candidate_object, original).unwrap();
        let record_path = fixture
            .workspace
            .state
            .join("candidates")
            .join(format!("{}.json", fixture.candidate_id));
        let mut value: Value = serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
        value["payload"]["candidate"]["resolved_source"]["tree_sha"] =
            Value::String("f".repeat(40));
        fs::write(record_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        let error = load_verified(&fixture.workspace, &fixture.candidate_id).unwrap_err();
        assert!(format!("{error:#}").contains("record digest mismatch"));
    }

    #[test]
    fn detects_source_object_and_descriptor_swaps() {
        let fixture = fixture();
        import(&fixture.workspace, &fixture.descriptor).unwrap();
        let source_object = fixture
            .workspace
            .object_path(&fixture.source_digest)
            .unwrap();
        let original = fs::read(&source_object).unwrap();
        fs::write(&source_object, vec![b'z'; original.len()]).unwrap();
        assert!(load_verified(&fixture.workspace, &fixture.candidate_id).is_err());

        fs::write(&source_object, original).unwrap();
        let source_record_path = fixture
            .workspace
            .state
            .join("artifacts")
            .join(format!("{}.json", fixture.source_artifact_id));
        let mut value: Value =
            serde_json::from_slice(&fs::read(&source_record_path).unwrap()).unwrap();
        value["artifact"]["media_type"] = json!("text/plain");
        let descriptor: ArtifactDescriptor =
            serde_json::from_value(value["artifact"].clone()).unwrap();
        value["record_digest"] = Value::String(workspace::digest_serialized(&descriptor).unwrap());
        fs::write(
            source_record_path,
            serde_json::to_vec_pretty(&value).unwrap(),
        )
        .unwrap();
        let error = load_verified(&fixture.workspace, &fixture.candidate_id).unwrap_err();
        assert!(format!("{error:#}").contains("source artifact record digest mismatch"));
    }

    #[test]
    fn rejects_registry_record_swapped_under_another_filename() {
        let fixture = fixture();
        import(&fixture.workspace, &fixture.descriptor).unwrap();
        let original = fixture
            .workspace
            .state
            .join("candidates")
            .join(format!("{}.json", fixture.candidate_id));
        let swapped_id = "candidate_ffffffffffffffffffffffffffffffff";
        let swapped = fixture
            .workspace
            .state
            .join("candidates")
            .join(format!("{swapped_id}.json"));
        fs::copy(original, swapped).unwrap();

        let error = load_verified(&fixture.workspace, swapped_id).unwrap_err();
        assert!(format!("{error:#}").contains("filename identity mismatch"));
    }
}
