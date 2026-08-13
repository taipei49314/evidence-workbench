use crate::contracts::{
    NativeDeliveryQualification, NativeDeliveryQualificationRecord,
    NativeDeliveryQualificationRecordPayload, NativeQualificationRef, QualificationArtifactRef,
    QualificationFile,
};
use crate::strict_json;
use crate::upstream_pins::{self, AuthorityEffect, ReadinessState};
use crate::workspace::{self, Workspace};
use anyhow::{Context, Result, bail};
use chrono::DateTime;
use chrono::{SecondsFormat, Utc};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Component, Path, PathBuf};

const TOMORROWCI_OPERATION: &str = "tomorrowci_trust_audit";
const TOMORROWCI_STATUS: &str = "CANDIDATE_ONLY_NOT_RELEASE_AUTHORIZED";
const PE_VERIFIER: &str = "evidence-workbench-builtin-pe-parser/v1";
const PE_VERIFIER_SHA256: &str = "4f3f1b06c9f1fba489776059672a516598fab7f67e25f23a88a4582ff029b323";
const REQUIRED_IMPORTS: &[&str] = &[
    "API-MS-WIN-CORE-SYNCH-L1-2-0.DLL",
    "BCRYPTPRIMITIVES.DLL",
    "KERNEL32.DLL",
    "NTDLL.DLL",
];
const PROHIBITED_APP_LOCAL: &[&str] = &[
    "API-MS-WIN-CORE-SYNCH-L1-2-0.DLL",
    "BCRYPTPRIMITIVES.DLL",
    "DOCKER.EXE",
    "GIT.EXE",
    "KERNEL32.DLL",
    "NTDLL.DLL",
    "PODMAN.EXE",
    "VCRUNTIME140.DLL",
];

#[derive(Debug, serde::Serialize)]
pub struct QualificationVerification {
    pub qualification_id: String,
    pub record_digest: String,
    pub tool_manifest_id: String,
    pub operation: String,
    pub upstream_pin_sha256: String,
    pub executable_sha256: String,
    pub platform_matches: bool,
    pub authority_effect: &'static str,
    pub candidate_only: bool,
}

pub fn admit(
    workspace: &Workspace,
    descriptor: &Path,
    root: &Path,
) -> Result<NativeDeliveryQualificationRecord> {
    let descriptor = canonical_regular_file(descriptor, "qualification descriptor")?;
    let root = canonical_real_directory(root, "qualification root")?;
    let bytes = fs::read(&descriptor).context("cannot read qualification descriptor")?;
    let value = strict_json::parse_strict(&bytes)?;
    let qualification: NativeDeliveryQualification = serde_json::from_value(value)
        .context("qualification descriptor violates native_delivery_qualification/v1")?;
    let qualification_id = qualification_id_for_bytes(&bytes);
    let destination = workspace
        .state
        .join("qualifications")
        .join(format!("{qualification_id}.json"));
    if destination.exists() {
        bail!("native qualification is already admitted");
    }
    validate_semantics(&qualification)?;
    let pin = upstream_pins::get_for_tool(&qualification.tool_manifest_id)?;
    if qualification.upstream_pin_sha256 != pin.sha256
        || pin.pin.source.commit_sha != qualification.source_commit_sha
        || pin.pin.source.tree_sha != qualification.source_tree_sha
        || pin.pin.execution_readiness.state != ReadinessState::Ready
        || pin.pin.admission.authority_effect != AuthorityEffect::None
    {
        bail!("qualification does not bind the exact ready upstream pin");
    }
    validate_against_pin(&qualification, &pin)?;
    let evidence = read_declared_evidence(&root, &qualification)?;
    verify_evidence_semantics(&evidence, &qualification)?;
    let artifacts = import_declared_artifacts(workspace, &qualification, &evidence)?;
    let descriptor_artifact = workspace.import_artifact_bytes(
        &bytes,
        vec!["native_qualification_descriptor".to_owned()],
        "application/vnd.evidence-workbench.native-delivery-qualification-v1+json".to_owned(),
        "native_file",
        "byte_for_byte_copy",
    )?;
    let descriptor = QualificationArtifactRef {
        role: "qualification_descriptor".to_owned(),
        artifact_id: descriptor_artifact.artifact_id,
        sha256: descriptor_artifact.digest.value,
        byte_length: descriptor_artifact.byte_length,
    };
    let payload = NativeDeliveryQualificationRecordPayload {
        admitted_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        descriptor,
        artifacts,
        qualification,
    };
    let record = NativeDeliveryQualificationRecord {
        schema_version: "native_delivery_qualification_record/v1".to_owned(),
        qualification_id,
        record_digest: workspace::digest_serialized(&payload)?,
        payload,
    };
    verify_record(workspace, &record)?;
    workspace.write_native_qualification(&record)?;
    Ok(record)
}

pub fn load_verified(
    workspace: &Workspace,
    qualification_id: &str,
) -> Result<NativeDeliveryQualificationRecord> {
    let record = workspace.load_native_qualification(qualification_id)?;
    verify_record(workspace, &record)?;
    Ok(record)
}

pub fn verify(workspace: &Workspace, qualification_id: &str) -> Result<QualificationVerification> {
    let record = load_verified(workspace, qualification_id)?;
    let executable = executable_artifact(&record)?;
    Ok(QualificationVerification {
        qualification_id: record.qualification_id.clone(),
        record_digest: record.record_digest.clone(),
        tool_manifest_id: record.payload.qualification.tool_manifest_id.clone(),
        operation: record.payload.qualification.operation.clone(),
        upstream_pin_sha256: record.payload.qualification.upstream_pin_sha256.clone(),
        executable_sha256: executable.sha256.clone(),
        platform_matches: host_platform_matches(&record.payload.qualification),
        authority_effect: "none",
        candidate_only: true,
    })
}

pub fn bind_for_plan(
    workspace: &Workspace,
    qualification_id: Option<&str>,
    tool_manifest_id: &str,
    operation: &str,
) -> Result<Option<NativeQualificationRef>> {
    if tool_manifest_id != "tomorrowci-lab" {
        if qualification_id.is_some() {
            bail!("--runtime-qualification is only accepted by an operation that requires it");
        }
        return Ok(None);
    }
    let id = qualification_id.ok_or_else(|| {
        anyhow::anyhow!(
            "tomorrowci-lab planning requires --runtime-qualification <qualification_id>"
        )
    })?;
    let record = load_verified(workspace, id)?;
    if record.payload.qualification.tool_manifest_id != tool_manifest_id
        || record.payload.qualification.operation != operation
        || !host_platform_matches(&record.payload.qualification)
    {
        bail!("native qualification scope or platform does not admit this plan");
    }
    preflight_os_boundary(&record.payload.qualification)?;
    Ok(Some(NativeQualificationRef {
        qualification_id: id.to_owned(),
        record_digest: record.record_digest,
    }))
}

pub fn validate_bound_ref(
    workspace: &Workspace,
    reference: Option<&NativeQualificationRef>,
    tool_manifest_id: &str,
    operation: &str,
    expected_upstream_pin_sha256: &str,
    executable_sha256: &str,
    execution_preflight: bool,
) -> Result<()> {
    if tool_manifest_id != "tomorrowci-lab" {
        if reference.is_some() {
            bail!("plan binds a native qualification for an operation that does not accept one");
        }
        return Ok(());
    }
    let reference = reference.context("TomorrowCI plan omits its durable native qualification")?;
    let record = load_verified(workspace, &reference.qualification_id)?;
    if record.record_digest != reference.record_digest
        || record.payload.qualification.tool_manifest_id != tool_manifest_id
        || record.payload.qualification.operation != operation
        || record.payload.qualification.upstream_pin_sha256 != expected_upstream_pin_sha256
        || executable_artifact(&record)?.sha256 != executable_sha256
        || (execution_preflight && !host_platform_matches(&record.payload.qualification))
    {
        bail!("native qualification reference does not match exact plan semantics");
    }
    if execution_preflight {
        preflight_os_boundary(&record.payload.qualification)?;
    }
    Ok(())
}

pub fn executable_artifact(
    record: &NativeDeliveryQualificationRecord,
) -> Result<&QualificationArtifactRef> {
    let matches = record
        .payload
        .artifacts
        .iter()
        .filter(|artifact| artifact.role == "windows_executable")
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!("qualification must bind exactly one Windows executable");
    }
    Ok(matches[0])
}

fn verify_record(workspace: &Workspace, record: &NativeDeliveryQualificationRecord) -> Result<()> {
    validate_semantics(&record.payload.qualification)?;
    DateTime::parse_from_rfc3339(&record.payload.admitted_at)
        .context("qualification record admitted_at is not RFC 3339")?;
    if record.schema_version != "native_delivery_qualification_record/v1"
        || record.record_digest != workspace::digest_serialized(&record.payload)?
    {
        bail!("native qualification record digest or identity mismatch");
    }
    let pin = upstream_pins::get_for_tool(&record.payload.qualification.tool_manifest_id)?;
    if pin.sha256 != record.payload.qualification.upstream_pin_sha256
        || pin.pin.execution_readiness.state != ReadinessState::Ready
        || pin.pin.admission.authority_effect != AuthorityEffect::None
        || pin.pin.source.commit_sha != record.payload.qualification.source_commit_sha
        || pin.pin.source.tree_sha != record.payload.qualification.source_tree_sha
    {
        bail!("native qualification no longer matches the exact ready upstream pin");
    }
    let all_artifacts =
        std::iter::once(&record.payload.descriptor).chain(record.payload.artifacts.iter());
    for artifact in all_artifacts {
        let stored = workspace.load_artifact(&artifact.artifact_id)?;
        if stored.artifact.digest.value != artifact.sha256
            || stored.artifact.byte_length != artifact.byte_length
        {
            bail!("native qualification CAS artifact changed");
        }
    }
    let descriptor_record = workspace.load_artifact(&record.payload.descriptor.artifact_id)?;
    let descriptor_bytes = workspace.read_verified_descriptor(&descriptor_record.artifact)?;
    let descriptor_value = strict_json::parse_strict(&descriptor_bytes)?;
    let descriptor: NativeDeliveryQualification = serde_json::from_value(descriptor_value)
        .context("persisted qualification descriptor violates its strict contract")?;
    if descriptor != record.payload.qualification
        || record.qualification_id != qualification_id_for_bytes(&descriptor_bytes)
    {
        bail!("persisted qualification descriptor bytes diverge from the record payload");
    }
    validate_record_artifact_mapping(workspace, record)?;
    verify_cas_evidence_semantics(workspace, record)?;
    validate_against_pin(&record.payload.qualification, &pin)?;
    let report_role = &record.payload.qualification.pe_imports.report_role;
    if !record
        .payload
        .artifacts
        .iter()
        .any(|entry| &entry.role == report_role)
    {
        bail!("PE verifier report is outside the qualification artifact inventory");
    }
    Ok(())
}

fn validate_record_artifact_mapping(
    workspace: &Workspace,
    record: &NativeDeliveryQualificationRecord,
) -> Result<()> {
    let expected = record
        .payload
        .qualification
        .files
        .iter()
        .map(|file| (file.role.as_str(), (file.sha256.as_str(), file.byte_length)))
        .collect::<std::collections::BTreeMap<_, _>>();
    let actual = record
        .payload
        .artifacts
        .iter()
        .map(|artifact| {
            (
                artifact.role.as_str(),
                (artifact.sha256.as_str(), artifact.byte_length),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    if expected != actual || expected.len() != record.payload.artifacts.len() {
        bail!("qualification descriptor files and CAS artifact refs diverge");
    }
    for artifact in &record.payload.artifacts {
        let stored = workspace.load_artifact(&artifact.artifact_id)?;
        let expected_roles = if artifact.role == "windows_executable" {
            vec![
                "native_executable_snapshot".to_owned(),
                "native_qualification_evidence".to_owned(),
            ]
        } else {
            vec!["native_qualification_evidence".to_owned()]
        };
        let expected_media = if artifact.role == "windows_executable" {
            "application/x-executable"
        } else {
            "application/octet-stream"
        };
        if stored.artifact.roles != expected_roles
            || stored.artifact.media_type != expected_media
            || stored.artifact.origin != "native_file"
            || stored.artifact.capture.mode != "byte_for_byte_copy"
            || !stored.artifact.transforms.is_empty()
        {
            bail!("qualification CAS artifact metadata is outside its exact contract");
        }
    }
    if descriptor_record_contract(workspace, &record.payload.descriptor).is_err() {
        bail!("qualification descriptor CAS metadata is outside its exact contract");
    }
    Ok(())
}

fn descriptor_record_contract(
    workspace: &Workspace,
    descriptor: &QualificationArtifactRef,
) -> Result<()> {
    let stored = workspace.load_artifact(&descriptor.artifact_id)?;
    if stored.artifact.roles != ["native_qualification_descriptor"]
        || stored.artifact.media_type
            != "application/vnd.evidence-workbench.native-delivery-qualification-v1+json"
        || stored.artifact.digest.value != descriptor.sha256
        || stored.artifact.byte_length != descriptor.byte_length
        || stored.artifact.origin != "native_file"
        || stored.artifact.capture.mode != "byte_for_byte_copy"
    {
        bail!("qualification descriptor metadata mismatch");
    }
    Ok(())
}

fn verify_cas_evidence_semantics(
    workspace: &Workspace,
    record: &NativeDeliveryQualificationRecord,
) -> Result<()> {
    let mut evidence = BTreeMap::new();
    for file in &record.payload.qualification.files {
        let artifact = record
            .payload
            .artifacts
            .iter()
            .find(|artifact| artifact.role == file.role)
            .context("qualification CAS artifact is missing")?;
        let stored = workspace.load_artifact(&artifact.artifact_id)?;
        let bytes = workspace.read_verified_descriptor(&stored.artifact)?;
        if evidence.insert(file.role.clone(), bytes).is_some() {
            bail!("qualification CAS evidence roles are not unique");
        }
    }
    verify_evidence_semantics(&evidence, &record.payload.qualification)
}

fn validate_against_pin(
    qualification: &NativeDeliveryQualification,
    pin: &upstream_pins::TrustedUpstreamPin,
) -> Result<()> {
    let evidence_keys = pin
        .pin
        .evidence
        .iter()
        .map(|entry| (format!("{:?}", entry.kind), entry.id.as_str()))
        .collect::<BTreeSet<_>>();
    if evidence_keys.len() != pin.pin.evidence.len() || pin.pin.evidence.len() != 6 {
        bail!("TomorrowCI ready upstream evidence set is not exact and unique");
    }
    if pin.pin.repository_url != "https://github.com/taipei49314/tomorrowci-lab"
        || pin.pin.source.default_branch != "master"
        || pin.pin.software_version != "0.2.0-alpha.1"
        || pin.pin.release.is_some()
        || pin.pin.license_spdx != "Apache-2.0"
        || pin.pin.source.commit_sha != qualification.source_commit_sha
        || pin.pin.source.tree_sha != qualification.source_tree_sha
        || pin.pin.native_posture.status
            != upstream_pins::NativeStatus::CandidateOnlyNotReleaseAuthorized
        || pin.pin.native_posture.release_eligible != Some(false)
        || pin.pin.runtime.kind != upstream_pins::RuntimeKind::Native
        || pin.pin.runtime.target_os != upstream_pins::TargetOs::Windows
        || pin.pin.runtime.target_arch != upstream_pins::TargetArch::X86_64
        || !pin.pin.runtime.self_contained
        || !pin.pin.runtime.transitive_dependencies_included
        || !pin.pin.runtime.external_tools.is_empty()
        || pin.pin.execution_readiness.state != ReadinessState::Ready
        || pin.pin.execution_readiness.scope
            != "fixed_trust_json_candidate_only_with_durable_local_qualification_and_private_launcher_inventory"
        || pin.pin.admission.authority_effect != AuthorityEffect::None
    {
        bail!("TomorrowCI upstream pin posture/runtime/readiness contract is inconsistent");
    }
    let workflow = pin
        .pin
        .evidence
        .iter()
        .find(|entry| entry.kind == upstream_pins::EvidenceKind::WorkflowRun)
        .context("ready upstream pin omits its workflow run")?;
    let actions = pin
        .pin
        .evidence
        .iter()
        .find(|entry| entry.kind == upstream_pins::EvidenceKind::ActionsArtifact)
        .context("ready upstream pin omits its Actions artifact")?;
    let executable = qualification_file(qualification, "windows_executable")?;
    let archive = qualification_file(qualification, "windows_archive")?;
    let candidate = qualification_file(qualification, "candidate_manifest")?;
    let ledger = qualification_file(qualification, "checksum_ledger")?;
    let pin_executable = pin
        .pin
        .evidence
        .iter()
        .find(|entry| entry.kind == upstream_pins::EvidenceKind::NativeExecutable)
        .context("ready upstream pin omits its executable evidence")?;
    let pin_archive = pin
        .pin
        .evidence
        .iter()
        .find(|entry| entry.kind == upstream_pins::EvidenceKind::CandidateArchive)
        .context("ready upstream pin omits its candidate archive evidence")?;
    let pin_candidate = pin
        .pin
        .evidence
        .iter()
        .find(|entry| entry.kind == upstream_pins::EvidenceKind::CandidateManifest)
        .context("ready upstream pin omits its candidate manifest evidence")?;
    let pin_ledger = pin
        .pin
        .evidence
        .iter()
        .find(|entry| entry.kind == upstream_pins::EvidenceKind::ChecksumLedger)
        .context("ready upstream pin omits its checksum ledger evidence")?;
    if workflow.id != qualification.workflow_run_id
        || workflow.name != "release-candidate"
        || workflow.subject_commit_sha != qualification.source_commit_sha
        || workflow.status != upstream_pins::EvidenceStatus::Success
        || actions.id != qualification.actions_artifact_id
        || actions.name != qualification.actions_artifact_name
        || actions.subject_commit_sha != qualification.source_commit_sha
        || actions.sha256.as_deref() != Some(&qualification.actions_artifact_container_sha256)
        || actions.size_bytes != Some(90_623_321)
        || actions.status != upstream_pins::EvidenceStatus::Success
        || actions.expires_at.as_deref() != Some(&qualification.actions_artifact_expires_at)
        || pin_candidate.name != "candidate-manifest.json"
        || pin_candidate.subject_commit_sha != qualification.source_commit_sha
        || pin_candidate.sha256.as_deref() != Some(&candidate.sha256)
        || pin_candidate.size_bytes != Some(candidate.byte_length)
        || pin_candidate.status != upstream_pins::EvidenceStatus::VerifiedAtAdmission
        || pin_ledger.name != "SHA256SUMS.txt"
        || pin_ledger.subject_commit_sha != qualification.source_commit_sha
        || pin_ledger.sha256.as_deref() != Some(&ledger.sha256)
        || pin_ledger.size_bytes != Some(ledger.byte_length)
        || pin_ledger.status != upstream_pins::EvidenceStatus::VerifiedAtAdmission
        || pin_archive.name != "tomorrowci-v0.2.0-alpha.1-x86_64-pc-windows-msvc.zip"
        || pin_archive.subject_commit_sha != qualification.source_commit_sha
        || pin_executable.sha256.as_deref() != Some(&executable.sha256)
        || pin_executable.size_bytes != Some(executable.byte_length)
        || pin_executable.name != "tomorrowci.exe"
        || pin_executable.subject_commit_sha != qualification.source_commit_sha
        || pin_executable.status != upstream_pins::EvidenceStatus::VerifiedAtAdmission
        || pin_archive.sha256.as_deref() != Some(&archive.sha256)
        || pin_archive.size_bytes != Some(archive.byte_length)
        || pin_archive.status != upstream_pins::EvidenceStatus::VerifiedAtAdmission
    {
        bail!("qualification provenance fields diverge from exact upstream evidence refs");
    }
    Ok(())
}

fn read_declared_evidence(
    root: &Path,
    qualification: &NativeDeliveryQualification,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut evidence = BTreeMap::new();
    for expected in &qualification.files {
        validate_relative_file_name(&expected.role)?;
        let bytes = read_declared_file(root, expected)?;
        if evidence.insert(expected.role.clone(), bytes).is_some() {
            bail!("qualification artifact roles must be unique");
        }
    }
    Ok(evidence)
}

fn import_declared_artifacts(
    workspace: &Workspace,
    qualification: &NativeDeliveryQualification,
    evidence: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<QualificationArtifactRef>> {
    let mut imported_artifacts = Vec::new();
    for expected in &qualification.files {
        let bytes = evidence
            .get(&expected.role)
            .context("validated qualification artifact bytes are missing")?;
        let roles = if expected.role == "windows_executable" {
            vec![
                "native_executable_snapshot".to_owned(),
                "native_qualification_evidence".to_owned(),
            ]
        } else {
            vec!["native_qualification_evidence".to_owned()]
        };
        let imported = workspace.import_artifact_bytes(
            bytes,
            roles,
            if expected.role == "windows_executable" {
                "application/x-executable".to_owned()
            } else {
                "application/octet-stream".to_owned()
            },
            "native_file",
            "byte_for_byte_copy",
        )?;
        if imported.digest.value != expected.sha256 || imported.byte_length != expected.byte_length
        {
            bail!("qualification artifact descriptor does not match admitted exact bytes");
        }
        imported_artifacts.push(QualificationArtifactRef {
            role: expected.role.clone(),
            artifact_id: imported.artifact_id,
            sha256: imported.digest.value,
            byte_length: imported.byte_length,
        });
    }
    imported_artifacts.sort_by(|left, right| left.role.cmp(&right.role));
    Ok(imported_artifacts)
}

fn verify_evidence_semantics(
    evidence: &BTreeMap<String, Vec<u8>>,
    qualification: &NativeDeliveryQualification,
) -> Result<()> {
    let candidate = qualification_file(qualification, "candidate_manifest")?;
    let candidate_bytes = evidence_bytes(evidence, &candidate.role)?;
    let candidate_json = strict_json::parse_strict(candidate_bytes)?;
    if candidate_json
        .pointer("/kind")
        .and_then(|value| value.as_str())
        != Some("tomorrowci.release-candidate.v1")
        || candidate_json
            .pointer("/source/commit")
            .and_then(|value| value.as_str())
            != Some(&qualification.source_commit_sha)
        || candidate_json.pointer("/source/dirty") != Some(&serde_json::Value::Bool(false))
        || candidate_json
            .pointer("/workflow/run_id")
            .and_then(|value| value.as_u64())
            != qualification.workflow_run_id.parse::<u64>().ok()
        || candidate_json
            .pointer("/status")
            .and_then(|value| value.as_str())
            != Some(TOMORROWCI_STATUS)
        || candidate_json.pointer("/promotion/authorized") != Some(&serde_json::Value::Bool(false))
    {
        bail!("candidate manifest semantics do not match the qualification");
    }
    let archive = qualification_file(qualification, "windows_archive")?;
    let executable = qualification_file(qualification, "windows_executable")?;
    let executable_bytes = evidence_bytes(evidence, &executable.role)?;
    let parsed_pe = parse_pe_imports(executable_bytes)?;
    let qualified_imports = qualification
        .pe_imports
        .imports
        .iter()
        .map(|value| value.to_ascii_uppercase())
        .collect::<BTreeSet<_>>();
    if parsed_pe.machine != 0x8664
        || parsed_pe.imports != qualified_imports
        || parsed_pe.delay_import_count != 0
    {
        bail!("exact executable PE machine/import tables do not match the qualification");
    }
    let payload = candidate_json
        .pointer("/payload")
        .and_then(|value| value.as_array())
        .context("candidate manifest payload is absent")?;
    let archive_name = Path::new(&archive.path)
        .file_name()
        .and_then(|value| value.to_str())
        .context("Windows archive name is not UTF-8")?;
    let archive_bytes = evidence_bytes(evidence, &archive.role)?;
    let matching = payload
        .iter()
        .filter(|entry| {
            entry.pointer("/name").and_then(|value| value.as_str()) == Some(archive_name)
        })
        .collect::<Vec<_>>();
    let expected_archive_digest = format!("sha256:{}", archive.sha256);
    if matching.len() != 1
        || matching[0]
            .pointer("/sha256")
            .and_then(|value| value.as_str())
            != Some(expected_archive_digest.as_str())
        || matching[0]
            .pointer("/size")
            .and_then(|value| value.as_u64())
            != Some(archive.byte_length)
    {
        bail!("candidate manifest does not bind the admitted Windows archive");
    }

    let ledger = qualification_file(qualification, "checksum_ledger")?;
    let ledger_bytes = evidence_bytes(evidence, &ledger.role)?;
    let ledger_text = std::str::from_utf8(ledger_bytes).context("checksum ledger is not UTF-8")?;
    let expected_ledger_line = format!("{}  {}", archive.sha256, archive_name);
    if ledger_text
        .lines()
        .filter(|line| *line == expected_ledger_line)
        .count()
        != 1
    {
        bail!("checksum ledger does not bind the Windows archive exactly once");
    }
    if executable.sha256 == archive.sha256 {
        bail!("archive container digest and extracted executable digest were conflated");
    }
    verify_windows_archive_member(archive_bytes, executable)?;

    let report_file = qualification_file(qualification, &qualification.pe_imports.report_role)?;
    let report_bytes = evidence_bytes(evidence, &report_file.role)?;
    let report_value = strict_json::parse_strict(report_bytes)?;
    let report: PeImportReport = serde_json::from_value(report_value)
        .context("PE import report violates its closed evidence contract")?;
    let report_imports = report
        .imports
        .iter()
        .map(|value| value.to_ascii_uppercase())
        .collect::<BTreeSet<_>>();
    validate_pe_report(
        &report,
        qualification,
        executable,
        &report_imports,
        &qualified_imports,
    )?;
    Ok(())
}

fn evidence_bytes<'a>(evidence: &'a BTreeMap<String, Vec<u8>>, role: &str) -> Result<&'a [u8]> {
    evidence
        .get(role)
        .map(Vec::as_slice)
        .with_context(|| format!("qualification evidence role {role} is absent"))
}

fn validate_pe_report(
    report: &PeImportReport,
    qualification: &NativeDeliveryQualification,
    executable: &QualificationFile,
    report_imports: &BTreeSet<String>,
    qualified_imports: &BTreeSet<String>,
) -> Result<()> {
    if report.schema_version != "pe_import_report/v1"
        || report.executable_sha256 != executable.sha256
        || report.verifier_contract_id != qualification.pe_imports.verifier_contract_id
        || report.verifier_contract_sha256 != qualification.pe_imports.verifier_contract_sha256
        || report_imports != qualified_imports
        || !report.delay_imports.is_empty()
    {
        bail!("PE import report does not match the qualified executable boundary");
    }
    Ok(())
}

fn verify_windows_archive_member(bytes: &[u8], executable: &QualificationFile) -> Result<()> {
    const EXPECTED: &str = "tomorrowci-v0.2.0-alpha.1-x86_64-pc-windows-msvc/tomorrowci.exe";
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .context("Windows candidate archive is not a valid ZIP")?;
    if archive.is_empty() || archive.len() > 64 {
        bail!("Windows candidate ZIP entry count is outside the admitted range");
    }
    let mut names = BTreeSet::new();
    let mut executable_bytes = None;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        if entry.encrypted() {
            bail!("Windows candidate ZIP contains encrypted content");
        }
        let name = entry.name().replace('\\', "/");
        let casefolded = name.to_ascii_lowercase();
        if !names.insert(casefolded) {
            bail!("Windows candidate ZIP contains a case-folded path collision");
        }
        let enclosed = entry
            .enclosed_name()
            .context("Windows candidate ZIP contains a traversal path")?;
        if enclosed
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            bail!("Windows candidate ZIP entry path is not canonical");
        }
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            bail!("Windows candidate ZIP contains a symbolic link");
        }
        if name.eq_ignore_ascii_case(EXPECTED) {
            if name != EXPECTED || executable_bytes.is_some() || entry.is_dir() {
                bail!("Windows candidate ZIP executable member is duplicated or non-canonical");
            }
            if entry
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 != 0o100000)
            {
                bail!("Windows candidate ZIP executable member is not a regular file");
            }
            if entry.size() != executable.byte_length || entry.size() > 16 * 1024 * 1024 {
                bail!("Windows candidate ZIP executable length is not admitted");
            }
            let mut member = Vec::with_capacity(entry.size() as usize);
            entry
                .by_ref()
                .take(executable.byte_length.saturating_add(1))
                .read_to_end(&mut member)?;
            if member.len() as u64 != executable.byte_length {
                bail!("Windows candidate ZIP executable decompression length mismatch");
            }
            executable_bytes = Some(member);
        }
    }
    let executable_bytes =
        executable_bytes.context("Windows candidate ZIP executable is absent")?;
    if hex::encode(Sha256::digest(&executable_bytes)) != executable.sha256 {
        bail!("Windows candidate ZIP member does not match the admitted executable bytes");
    }
    Ok(())
}

#[derive(Debug)]
struct ParsedPe {
    machine: u16,
    imports: BTreeSet<String>,
    delay_import_count: usize,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PeImportReport {
    schema_version: String,
    executable_sha256: String,
    verifier_contract_id: String,
    verifier_contract_sha256: String,
    imports: Vec<String>,
    delay_imports: Vec<String>,
}

fn parse_pe_imports(bytes: &[u8]) -> Result<ParsedPe> {
    fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
        let slice = bytes
            .get(offset..offset.checked_add(2).context("PE offset overflow")?)
            .context("truncated PE u16")?;
        Ok(u16::from_le_bytes([slice[0], slice[1]]))
    }
    fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
        let slice = bytes
            .get(offset..offset.checked_add(4).context("PE offset overflow")?)
            .context("truncated PE u32")?;
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }
    #[derive(Clone, Copy)]
    struct Section {
        virtual_address: u32,
        virtual_size: u32,
        raw_offset: u32,
        raw_size: u32,
    }
    fn rva_to_offset(rva: u32, sections: &[Section], bytes_len: usize) -> Result<usize> {
        for section in sections {
            let span = section.virtual_size.max(section.raw_size);
            if rva >= section.virtual_address && rva < section.virtual_address.saturating_add(span)
            {
                let delta = rva - section.virtual_address;
                if delta >= section.raw_size {
                    bail!("PE RVA points outside raw section bytes");
                }
                let offset = section
                    .raw_offset
                    .checked_add(delta)
                    .context("PE section offset overflow")? as usize;
                if offset >= bytes_len {
                    bail!("PE RVA maps beyond file bytes");
                }
                return Ok(offset);
            }
        }
        bail!("PE RVA is outside admitted sections")
    }
    fn read_ascii_name(bytes: &[u8], offset: usize) -> Result<String> {
        let remaining = bytes
            .get(offset..)
            .context("PE name offset is out of bounds")?;
        let end = remaining
            .iter()
            .position(|byte| *byte == 0)
            .context("PE import name is not NUL terminated")?;
        if end == 0 || end > 260 {
            bail!("PE import name length is invalid");
        }
        let name = std::str::from_utf8(&remaining[..end])?;
        if !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            bail!("PE import name contains non-portable characters");
        }
        Ok(name.to_ascii_uppercase())
    }

    if bytes.get(0..2) != Some(b"MZ") {
        bail!("qualified executable lacks an MZ header");
    }
    let pe_offset = read_u32(bytes, 0x3c)? as usize;
    if bytes.get(pe_offset..pe_offset.saturating_add(4)) != Some(b"PE\0\0") {
        bail!("qualified executable lacks a PE signature");
    }
    let coff = pe_offset.checked_add(4).context("PE offset overflow")?;
    let machine = read_u16(bytes, coff)?;
    let section_count = read_u16(bytes, coff + 2)? as usize;
    if section_count == 0 || section_count > 96 {
        bail!("PE section count is outside the admitted range");
    }
    let optional_size = read_u16(bytes, coff + 16)? as usize;
    let optional = coff.checked_add(20).context("PE offset overflow")?;
    if read_u16(bytes, optional)? != 0x20b {
        bail!("qualified executable is not PE32+");
    }
    if optional_size < 240 || bytes.get(optional..optional + optional_size).is_none() {
        bail!("PE optional header is truncated");
    }
    let number_of_directories = read_u32(bytes, optional + 108)?;
    if number_of_directories < 2 {
        bail!("PE import data directory is absent");
    }
    let import_rva = read_u32(bytes, optional + 120)?;
    let import_size = read_u32(bytes, optional + 124)?;
    let (delay_rva, delay_size) = if number_of_directories > 13 {
        (
            read_u32(bytes, optional + 216)?,
            read_u32(bytes, optional + 220)?,
        )
    } else {
        (0, 0)
    };
    if import_rva == 0 || import_size < 20 {
        bail!("PE import table is empty");
    }
    let section_table = optional + optional_size;
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let offset = section_table
            .checked_add(index.checked_mul(40).context("PE section overflow")?)
            .context("PE section overflow")?;
        if bytes.get(offset..offset + 40).is_none() {
            bail!("PE section table is truncated");
        }
        sections.push(Section {
            virtual_size: read_u32(bytes, offset + 8)?,
            virtual_address: read_u32(bytes, offset + 12)?,
            raw_size: read_u32(bytes, offset + 16)?,
            raw_offset: read_u32(bytes, offset + 20)?,
        });
    }
    let import_offset = rva_to_offset(import_rva, &sections, bytes.len())?;
    let max_descriptors = (import_size as usize / 20).min(4096);
    let mut imports = BTreeSet::new();
    let mut terminated = false;
    for index in 0..max_descriptors {
        let offset = import_offset
            .checked_add(index.checked_mul(20).context("PE import overflow")?)
            .context("PE import overflow")?;
        let original_thunk = read_u32(bytes, offset)?;
        let timestamp = read_u32(bytes, offset + 4)?;
        let forwarder = read_u32(bytes, offset + 8)?;
        let name_rva = read_u32(bytes, offset + 12)?;
        let first_thunk = read_u32(bytes, offset + 16)?;
        if original_thunk == 0
            && timestamp == 0
            && forwarder == 0
            && name_rva == 0
            && first_thunk == 0
        {
            terminated = true;
            break;
        }
        if name_rva == 0 {
            bail!("PE import descriptor omits its module name");
        }
        let name_offset = rva_to_offset(name_rva, &sections, bytes.len())?;
        let name = read_ascii_name(bytes, name_offset)?;
        // PE linkers may emit duplicate descriptors with case variants. The
        // admitted boundary is the exact case-folded module set.
        imports.insert(name);
    }
    if !terminated || imports.is_empty() {
        bail!("PE import descriptors are unterminated or empty");
    }
    let delay_import_count = if delay_rva == 0 && delay_size == 0 {
        0
    } else {
        if delay_rva == 0 || delay_size < 32 {
            bail!("PE delay-import directory is malformed");
        }
        let delay_offset = rva_to_offset(delay_rva, &sections, bytes.len())?;
        let mut count = 0usize;
        let mut terminated = false;
        for index in 0..(delay_size as usize / 32).min(4096) {
            let offset = delay_offset
                .checked_add(index.checked_mul(32).context("PE delay import overflow")?)
                .context("PE delay import overflow")?;
            let descriptor = bytes
                .get(offset..offset + 32)
                .context("truncated delay import")?;
            if descriptor.iter().all(|byte| *byte == 0) {
                terminated = true;
                break;
            }
            count += 1;
        }
        if !terminated {
            bail!("PE delay-import descriptors are unterminated");
        }
        count
    };
    Ok(ParsedPe {
        machine,
        imports,
        delay_import_count,
    })
}

fn qualification_file<'a>(
    qualification: &'a NativeDeliveryQualification,
    role: &str,
) -> Result<&'a QualificationFile> {
    let matches = qualification
        .files
        .iter()
        .filter(|file| file.role == role)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!("qualification must bind exactly one {role} file");
    }
    Ok(matches[0])
}

fn read_declared_file(root: &Path, file: &QualificationFile) -> Result<Vec<u8>> {
    let path = canonical_regular_file(&root.join(&file.path), "qualification evidence")?;
    if !path.starts_with(root) {
        bail!("qualification evidence escaped its admitted root");
    }
    let bytes = fs::read(path)?;
    let digest = hex::encode(Sha256::digest(&bytes));
    if digest != file.sha256 || bytes.len() as u64 != file.byte_length {
        bail!("qualification evidence bytes do not match their descriptor");
    }
    Ok(bytes)
}

fn validate_semantics(qualification: &NativeDeliveryQualification) -> Result<()> {
    if qualification.schema_version != "native_delivery_qualification/v1"
        || qualification.tool_manifest_id != "tomorrowci-lab"
        || qualification.operation != TOMORROWCI_OPERATION
        || qualification.candidate_status != TOMORROWCI_STATUS
        || qualification.promotion_authorized
        || qualification.authority_effect != "none"
    {
        bail!("qualification would widen TomorrowCI candidate authority or operation scope");
    }
    validate_sha256(&qualification.upstream_pin_sha256)?;
    validate_sha256(&qualification.actions_artifact_container_sha256)?;
    validate_sha256(&qualification.pe_imports.verifier_contract_sha256)?;
    validate_git_sha(&qualification.source_commit_sha)?;
    validate_git_sha(&qualification.source_tree_sha)?;
    validate_decimal(&qualification.workflow_run_id)?;
    validate_decimal(&qualification.actions_artifact_id)?;
    DateTime::parse_from_rfc3339(&qualification.actions_artifact_expires_at)
        .context("Actions artifact expiry is not RFC 3339")?;
    DateTime::parse_from_rfc3339(&qualification.declared_at)
        .context("qualification declared_at is not RFC 3339")?;
    if qualification.actions_artifact_name != "release-candidate-dist-attempt-1"
        || qualification.pe_imports.verifier_contract_id != PE_VERIFIER
        || qualification.pe_imports.verifier_contract_sha256 != PE_VERIFIER_SHA256
        || qualification.platform.os != "windows"
        || qualification.platform.arch != "x86_64"
        || qualification.platform.minimum_version != "10.0"
        || qualification.platform.module_resolution != "windows_os_loader_api_set_boundary"
    {
        bail!("qualification platform or Actions identity is outside the admitted contract");
    }
    let imports = qualification
        .pe_imports
        .imports
        .iter()
        .map(|name| name.to_ascii_uppercase())
        .collect::<BTreeSet<_>>();
    let required = REQUIRED_IMPORTS
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    let required_order = REQUIRED_IMPORTS
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    if imports != required
        || qualification.pe_imports.imports != required_order
        || imports.len() != qualification.pe_imports.imports.len()
    {
        bail!("PE import inventory is not the exact admitted Windows OS boundary");
    }
    let prohibited = qualification
        .pe_imports
        .prohibited_app_local_names
        .iter()
        .map(|name| name.to_ascii_uppercase())
        .collect::<BTreeSet<_>>();
    let required_prohibited = PROHIBITED_APP_LOCAL
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    let required_prohibited_order = PROHIBITED_APP_LOCAL
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    if prohibited != required_prohibited
        || qualification.pe_imports.prohibited_app_local_names != required_prohibited_order
        || prohibited.len() != qualification.pe_imports.prohibited_app_local_names.len()
    {
        bail!("qualification omits a prohibited app-local search name");
    }
    if qualification.pe_imports.report_role != "pe_import_report" {
        bail!("qualification PE report role is not canonical");
    }
    let mut artifact_roles = BTreeSet::new();
    let mut file_paths = BTreeSet::new();
    for artifact in &qualification.files {
        if !artifact_roles.insert(artifact.role.as_str()) {
            bail!("qualification artifact roles must be unique");
        }
        validate_sha256(&artifact.sha256)?;
        let path = Path::new(&artifact.path);
        if path.is_absolute()
            || artifact.path.contains('\\')
            || artifact.path.contains(':')
            || artifact.path.bytes().any(|byte| byte.is_ascii_control())
            || path.components().any(|component| {
                !matches!(component, Component::Normal(segment)
                        if segment != "." && segment != ".."
                            && !segment.is_empty()
                            && segment.to_string_lossy().bytes().all(|byte|
                                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')))
            })
        {
            bail!("qualification file path must be relative and traversal-free");
        }
        let casefolded = artifact.path.replace('\\', "/").to_ascii_lowercase();
        if !file_paths.insert(casefolded) {
            bail!("qualification file paths collide under Windows case folding");
        }
    }
    let exact_paths = [
        ("candidate_manifest", "candidate-manifest.json"),
        ("checksum_ledger", "SHA256SUMS.txt"),
        (
            "windows_archive",
            "tomorrowci-v0.2.0-alpha.1-x86_64-pc-windows-msvc.zip",
        ),
        ("windows_executable", "tomorrowci.exe"),
        ("pe_import_report", "pe-import-report.json"),
    ];
    for (role, path) in exact_paths {
        if qualification_file(qualification, role)?.path != path {
            bail!("qualification role does not use its canonical evidence path");
        }
    }
    let required_roles = [
        "candidate_manifest",
        "checksum_ledger",
        "pe_import_report",
        "windows_archive",
        "windows_executable",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if artifact_roles != required_roles {
        bail!("qualification exact artifact inventory is incomplete");
    }
    Ok(())
}

fn host_platform_matches(qualification: &NativeDeliveryQualification) -> bool {
    cfg!(windows)
        && std::env::consts::ARCH == "x86_64"
        && qualification.platform.os == "windows"
        && qualification.platform.arch == "x86_64"
}

fn preflight_os_boundary(qualification: &NativeDeliveryQualification) -> Result<()> {
    if !host_platform_matches(qualification) {
        bail!("qualified TomorrowCI operation requires Windows x86_64");
    }
    #[cfg(windows)]
    {
        use std::mem::size_of;
        use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
        use windows_sys::Win32::System::SystemInformation::{
            GetNativeSystemInfo, GetSystemDirectoryW, OSVERSIONINFOW, PROCESSOR_ARCHITECTURE_AMD64,
            SYSTEM_INFO,
        };
        let mut system = SYSTEM_INFO::default();
        // SAFETY: system points to writable SYSTEM_INFO storage.
        unsafe { GetNativeSystemInfo(&mut system) };
        // SAFETY: GetNativeSystemInfo initializes the architecture union view.
        let native_arch = unsafe { system.Anonymous.Anonymous.wProcessorArchitecture };
        if native_arch != PROCESSOR_ARCHITECTURE_AMD64 {
            bail!("qualified TomorrowCI operation requires a native AMD64 Windows host");
        }
        let mut version = OSVERSIONINFOW {
            dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
            ..Default::default()
        };
        // SAFETY: version points to a correctly sized writable OSVERSIONINFOW.
        let status = unsafe { RtlGetVersion(&mut version) };
        if status < 0 || version.dwMajorVersion < 10 {
            bail!("qualified TomorrowCI operation requires Windows 10 or newer");
        }
        let mut buffer = vec![0u16; 32768];
        // SAFETY: buffer is writable for its declared length.
        let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
        if length == 0 || length as usize >= buffer.len() {
            bail!("cannot resolve the canonical Windows system directory");
        }
        let system_directory = PathBuf::from(String::from_utf16(&buffer[..length as usize])?);
        let metadata = fs::symlink_metadata(&system_directory)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
            bail!("canonical Windows system directory is not a real directory");
        }
    }
    // The PE parser establishes the exact x86_64 import boundary from the
    // admitted executable. KERNEL32/NTDLL/BCRYPTPRIMITIVES and the API-set are
    // Windows loader contracts, not app-local files and not an all-KnownDLLs
    // claim. We deliberately do not trust SystemRoot/WINDIR environment paths.
    Ok(())
}

fn canonical_regular_file(path: &Path, label: &str) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("cannot inspect {label}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
        bail!("{label} must be a regular non-link file");
    }
    path.canonicalize()
        .with_context(|| format!("cannot resolve {label}"))
}

fn canonical_real_directory(path: &Path, label: &str) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("cannot inspect {label}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
        bail!("{label} must be a real directory");
    }
    path.canonicalize()
        .with_context(|| format!("cannot resolve {label}"))
}

fn validate_relative_file_name(value: &str) -> Result<()> {
    let path = Path::new(value);
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
        || value.contains('/')
        || value.contains('\\')
    {
        bail!("qualification artifact role is not a simple relative name");
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("qualification digest is not lowercase SHA-256");
    }
    Ok(())
}

fn validate_git_sha(value: &str) -> Result<()> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("qualification Git identity is not lowercase SHA-1");
    }
    Ok(())
}

fn validate_decimal(value: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("qualification numeric identity is not canonical decimal");
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x0000_0400 != 0
}

#[cfg(not(windows))]
fn is_reparse(_metadata: &fs::Metadata) -> bool {
    false
}

fn qualification_id_for_bytes(bytes: &[u8]) -> String {
    let digest = hex::encode(Sha256::digest(bytes));
    format!("qualification_{}", &digest[..32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn forged_pe_report_unknown_claim_and_nonempty_delay_imports_are_rejected() {
        let report = serde_json::json!({
            "schema_version":"pe_import_report/v1",
            "executable_sha256":"00".repeat(32),
            "verifier_contract_id":PE_VERIFIER,
            "verifier_contract_sha256":PE_VERIFIER_SHA256,
            "imports":["KERNEL32.DLL"],
            "delay_imports":[]
        });
        let mut value = report.clone();
        value["aggregate_pass"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<PeImportReport>(value)
                .expect_err("unknown authority-like field must fail")
                .to_string()
                .contains("unknown field")
        );
        let mut value = report;
        value["delay_imports"] = serde_json::json!(["EVIL.DLL"]);
        let typed: PeImportReport = serde_json::from_value(value).unwrap();
        let qualification: NativeDeliveryQualification = serde_json::from_str(include_str!(
            "../contracts/examples/native-delivery-qualification-v1.example.json"
        ))
        .unwrap();
        let executable = qualification_file(&qualification, "windows_executable").unwrap();
        let report_imports = typed
            .imports
            .iter()
            .map(|value| value.to_ascii_uppercase())
            .collect::<BTreeSet<_>>();
        let qualified_imports = qualification
            .pe_imports
            .imports
            .iter()
            .map(|value| value.to_ascii_uppercase())
            .collect::<BTreeSet<_>>();
        assert!(
            validate_pe_report(
                &typed,
                &qualification,
                executable,
                &report_imports,
                &qualified_imports,
            )
            .is_err()
        );
    }

    #[test]
    fn zip_member_must_match_the_admitted_executable() {
        use zip::write::SimpleFileOptions;
        let payload = b"synthetic executable bytes";
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            writer
                .start_file(
                    "tomorrowci-v0.2.0-alpha.1-x86_64-pc-windows-msvc/tomorrowci.exe",
                    SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Deflated),
                )
                .unwrap();
            writer.write_all(payload).unwrap();
            writer.finish().unwrap();
        }
        let archive = cursor.into_inner();
        let exact = QualificationFile {
            role: "windows_executable".to_owned(),
            path: "tomorrowci.exe".to_owned(),
            sha256: hex::encode(Sha256::digest(payload)),
            byte_length: payload.len() as u64,
        };
        verify_windows_archive_member(&archive, &exact).unwrap();
        let mut forged = exact;
        forged.sha256 = "00".repeat(32);
        assert!(verify_windows_archive_member(&archive, &forged).is_err());
    }
}
