use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Digest {
    pub algorithm: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactStorage {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactCapture {
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDescriptor {
    pub artifact_id: String,
    pub roles: Vec<String>,
    pub media_type: String,
    pub byte_length: u64,
    pub digest: Digest,
    pub storage: ArtifactStorage,
    pub origin: String,
    pub capture: ArtifactCapture,
    pub transforms: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    pub role: String,
    pub algorithm: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Subject {
    Git {
        repository: String,
        original_root: String,
        revisions: Vec<Revision>,
        worktree_state: String,
        snapshot: Option<SubjectSnapshot>,
    },
    Artifact {
        sha256: String,
        byte_length: u64,
        media_type: String,
        source_run_id: Option<String>,
        source_artifact_id: String,
        snapshot: SubjectSnapshot,
    },
    SelfFoundation {
        tool_manifest_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubjectSnapshot {
    /// Exact Git bundle retained as transport/provenance for Git subjects.
    pub artifact_id: String,
    pub sha256: String,
    pub byte_length: u64,
    pub execution_path: String,
    /// Exact deterministic checkout image used for Git execution without invoking Git.
    pub tree_artifact_id: Option<String>,
    pub tree_sha256: Option<String>,
    pub tree_byte_length: Option<u64>,
    pub tree_file_count: Option<u64>,
    /// Plan-time Git provenance. The staged launcher is never executed after planning.
    pub git_plan_tool: Option<GitPlanToolIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GitPlanToolIdentity {
    pub source_path: String,
    pub source_sha256: String,
    pub source_size_bytes: u64,
    pub snapshot_artifact_id: String,
    pub staged_path: String,
    pub use_scope: String,
    pub runtime_closure: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolRef {
    pub manifest_id: String,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BinaryIdentity {
    /// EWB-owned staged executable path. Native PATH is never consulted at execution.
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub supporting_files_sha256: Option<String>,
    pub supporting_file_count: u64,
    pub reported_version: Option<String>,
    pub source_path: String,
    pub snapshot_artifact_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecorderIdentity {
    pub version: String,
    pub executable_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdapterIdentity {
    pub id: String,
    pub version: String,
    pub implementation_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    pub mode: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub timeout_ms: u64,
    pub required_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Termination {
    Exited { exit_code: i32 },
    Signaled { signal: String },
    TimedOut { timeout_ms: u64 },
    SpawnError { error_code: String, message: String },
    Interrupted { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Locator {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservationSource {
    Artifact {
        artifact_id: String,
        locator: Locator,
    },
    ProcessExit {
        field: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NativeObservation {
    pub namespace: String,
    pub name: String,
    pub value: Value,
    pub source: ObservationSource,
    pub projection_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "availability", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeResult {
    Reported {
        observations: Vec<NativeObservation>,
    },
    NotReported {
        reason: String,
        observations: Vec<NativeObservation>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "availability", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeAuthority {
    Reported {
        claims: Vec<NativeAuthorityClaim>,
    },
    NotReported {
        reason: String,
        claims: Vec<NativeAuthorityClaim>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NativeAuthorityClaim {
    pub namespace: String,
    pub name: String,
    pub value: Value,
    pub scope: String,
    pub source: ObservationSource,
    pub projection_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LimitationItem {
    pub namespace: String,
    pub code: String,
    pub statement: String,
    pub origin: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "availability", rename_all = "snake_case", deny_unknown_fields)]
pub enum Limitations {
    Reported { items: Vec<LimitationItem> },
    NotReported { items: Vec<LimitationItem> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InstrumentRun {
    pub schema_version: String,
    pub run_id: String,
    pub tool_ref: ToolRef,
    pub resolved_tool_identity: BinaryIdentity,
    pub recorder_identity: RecorderIdentity,
    pub adapter: AdapterIdentity,
    pub subject: Subject,
    pub parameters: BTreeMap<String, String>,
    pub invocation: Invocation,
    pub started_at: String,
    pub finished_at: String,
    pub termination: Termination,
    pub artifacts: Vec<ArtifactDescriptor>,
    pub native_result: NativeResult,
    pub native_authority: NativeAuthority,
    pub limitations: Limitations,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RunRecord {
    pub schema_version: String,
    pub record_digest: String,
    pub run: InstrumentRun,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PlanPayload {
    pub tool_ref: ToolRef,
    pub resolved_tool_identity: BinaryIdentity,
    pub recorder_identity: RecorderIdentity,
    pub adapter: AdapterIdentity,
    pub subject: Subject,
    pub invocation: Invocation,
    pub parameters: BTreeMap<String, String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PlanRecord {
    pub schema_version: String,
    pub plan_id: String,
    pub record_digest: String,
    pub payload: PlanPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRecord {
    pub schema_version: String,
    pub record_digest: String,
    pub artifact: ArtifactDescriptor,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubjectCandidate {
    pub schema_version: String,
    pub candidate_id: String,
    pub producer: SubjectCandidateProducer,
    pub repository_url: String,
    pub resolved_source: ResolvedGitSource,
    pub observed_at: String,
    pub source_artifact: ContractArtifactRef,
    pub limitations: Vec<ContractLimitation>,
    pub trust_state: SubjectCandidateTrustState,
    pub admission_requirement: SubjectCandidateAdmissionRequirement,
    pub authority_effect: ContractAuthorityEffect,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubjectCandidateProducer {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolvedGitSource {
    pub commit_sha: String,
    pub tree_sha: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContractArtifactRef {
    pub artifact_id: String,
    pub digest: Digest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContractLimitation {
    pub code: String,
    pub statement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubjectCandidateTrustState {
    UntrustedCandidate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubjectCandidateAdmissionRequirement {
    EwbReresolveCommitAndTree,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContractAuthorityEffect {
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCapsule {
    pub schema_version: String,
    pub capsule_id: String,
    pub platform: CapsulePlatform,
    pub launcher: CapsuleLauncher,
    pub supporting_files: Vec<CapsuleSupportingFile>,
    pub transitive_closure: CapsuleTransitiveClosure,
    pub external_platform_assumptions: Vec<ExternalPlatformAssumption>,
    pub operation_scope: CapsuleOperationScope,
    pub qualification_evidence: Vec<CapsuleQualificationEvidence>,
    pub readiness: CapsuleReadiness,
    pub authority_effect: ContractAuthorityEffect,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCapsuleFileSnapshot {
    pub path: String,
    pub role: String,
    pub artifact_id: String,
    pub digest: Digest,
    pub byte_length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCapsuleRecordPayload {
    /// SHA-256 of the exact descriptor bytes supplied to `capsules admit`.
    pub descriptor_sha256: String,
    pub descriptor_artifact_id: String,
    pub launcher: RuntimeCapsuleFileSnapshot,
    pub supporting_files: Vec<RuntimeCapsuleFileSnapshot>,
    pub capsule: RuntimeCapsule,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCapsuleRecord {
    pub schema_version: String,
    pub capsule_id: String,
    /// Binds the parsed descriptor, its exact source bytes, and every EWB-owned
    /// exact-byte file snapshot. This is the future plan/run binding identity.
    pub record_digest: String,
    pub payload: RuntimeCapsuleRecordPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapsulePlatform {
    pub os: String,
    pub arch: String,
    pub abi: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapsuleLauncher {
    pub kind: CapsuleLauncherKind,
    pub path: String,
    pub byte_length: u64,
    pub digest: Digest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleLauncherKind {
    Interpreter,
    NativeLauncher,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapsuleSupportingFile {
    pub path: String,
    pub role: String,
    pub byte_length: u64,
    pub digest: Digest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapsuleTransitiveClosure {
    pub state: CapsuleClosureState,
    pub inventory_digest: Digest,
    pub declared_file_count: u64,
    pub inventoried_file_count: u64,
    pub missing_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleClosureState {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalPlatformAssumption {
    pub code: String,
    pub statement: String,
    pub state: PlatformAssumptionState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlatformAssumptionState {
    VerifiedByQualification,
    RequiredPreflight,
    Unresolved,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapsuleOperationScope {
    pub tool_manifest_id: String,
    pub operations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapsuleQualificationEvidence {
    pub kind: CapsuleQualificationEvidenceKind,
    pub artifact_id: String,
    pub digest: Digest,
    pub observed_at: String,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleQualificationEvidenceKind {
    QualificationRun,
    PlatformProbe,
    PreflightRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapsuleReadiness {
    pub state: CapsuleReadinessState,
    pub blocker_codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleReadinessState {
    Ready,
    FailClosed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdeHandoff {
    pub schema_version: String,
    pub handoff_id: String,
    pub created_at: String,
    pub plan_refs: Vec<PlanRecordRef>,
    pub run_refs: Vec<RunRecordRef>,
    pub artifact_refs: Vec<ArtifactRecordRef>,
    pub native_namespaces: Vec<RunNativeNamespaces>,
    pub native_authority_availability: Vec<RunNativeAuthorityAvailability>,
    pub authority_effect: ContractAuthorityEffect,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlanRecordRef {
    pub plan_id: String,
    pub record_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunRecordRef {
    pub run_id: String,
    pub record_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRecordRef {
    pub artifact_id: String,
    pub record_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunNativeNamespaces {
    pub run_id: String,
    pub namespaces: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunNativeAuthorityAvailability {
    pub run_id: String,
    pub availability: NativeAuthorityAvailability,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NativeAuthorityAvailability {
    Reported,
    NotReported,
}
