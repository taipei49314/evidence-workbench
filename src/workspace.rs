use crate::contracts::{
    ArtifactCapture, ArtifactDescriptor, ArtifactRecord, ArtifactStorage, Digest,
    EvidenceHandoffRecord, NativeDeliveryQualificationRecord, PlanPayload, PlanRecord,
    PythonRuntimeQualificationRecord, RunRecord, RuntimeCapsuleRecord, SubjectCandidateRecord,
};
use crate::run_validation;
use crate::strict_json;
use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use uuid::Uuid;

const MARKER: &str = "WORKSPACE.json";
const STATE_DIR: &str = ".ewb";

#[derive(Debug, Clone)]
pub struct Workspace {
    pub root: PathBuf,
    pub state: PathBuf,
}

pub struct PlanExecutionLock {
    path: PathBuf,
    file: Option<File>,
}

impl Drop for PlanExecutionLock {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = fs::remove_file(&self.path);
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceMarker {
    schema_version: String,
    authority_policy: String,
}

impl Workspace {
    pub fn init(root: &Path) -> Result<Self> {
        let root = prepare_workspace_root(root)?;
        let workspace = Self {
            state: root.join(STATE_DIR),
            root,
        };
        ensure_real_dir(&workspace.state)?;
        for name in [
            "objects",
            "artifacts",
            "plans",
            "runs",
            "tmp",
            "manifests",
            "staged",
            "executions",
            "locks",
            "capsules",
            "candidates",
            "qualifications",
            "python-qualifications",
            "handoffs",
        ] {
            ensure_real_dir(&workspace.state.join(name))?;
        }
        ensure_real_dir(&workspace.state.join("objects").join("sha256"))?;

        let marker = workspace.state.join(MARKER);
        if marker.exists() {
            workspace.validate_marker()?;
        } else {
            let value = WorkspaceMarker {
                schema_version: "evidence_workbench_workspace/v1".to_owned(),
                authority_policy: "native_only_no_aggregate_verdict".to_owned(),
            };
            if let Err(error) = workspace.write_json_atomic(&marker, &value, true) {
                if marker.exists() {
                    workspace.validate_marker()?;
                } else {
                    return Err(error);
                }
            }
        }
        workspace.validate_layout()?;
        Ok(workspace)
    }

    pub fn open(root: Option<&Path>) -> Result<Self> {
        let root = Self::find_root(root)?.ok_or_else(|| {
            anyhow::anyhow!("no initialized .ewb workspace found; run `ewb init`")
        })?;
        let workspace = Self {
            state: root.join(STATE_DIR),
            root,
        };
        workspace.validate_layout()?;
        workspace.validate_marker()?;
        Ok(workspace)
    }

    pub fn find_root(root: Option<&Path>) -> Result<Option<PathBuf>> {
        let start = match root {
            Some(path) => path
                .canonicalize()
                .with_context(|| format!("cannot resolve workspace path {}", path.display()))?,
            None => std::env::current_dir()
                .context("cannot read current directory")?
                .canonicalize()
                .context("cannot resolve current directory")?,
        };
        let mut cursor = Some(start.as_path());
        while let Some(path) = cursor {
            let state = path.join(STATE_DIR);
            match fs::symlink_metadata(&state) {
                Ok(_) => return Ok(Some(path.to_owned())),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("cannot inspect workspace state entry {}", state.display())
                    });
                }
            }
            if root.is_some() {
                break;
            }
            cursor = path.parent();
        }
        Ok(None)
    }

    pub fn is_initialized(root: &Path) -> bool {
        root.join(STATE_DIR).join(MARKER).is_file()
    }

    pub fn validate_layout(&self) -> Result<()> {
        validate_real_dir(&self.state)?;
        for name in [
            "objects",
            "artifacts",
            "plans",
            "runs",
            "tmp",
            "manifests",
            "staged",
            "executions",
            "locks",
            "capsules",
            "candidates",
            "qualifications",
            "python-qualifications",
            "handoffs",
        ] {
            validate_real_dir(&self.state.join(name))?;
        }
        validate_real_dir(&self.state.join("objects").join("sha256"))?;
        Ok(())
    }

    fn validate_marker(&self) -> Result<()> {
        let bytes = fs::read(self.state.join(MARKER)).context("cannot read workspace marker")?;
        let value = strict_json::parse_strict(&bytes)?;
        let marker: WorkspaceMarker = serde_json::from_value(value)?;
        if marker.schema_version != "evidence_workbench_workspace/v1"
            || marker.authority_policy != "native_only_no_aggregate_verdict"
        {
            bail!("workspace marker has an unsupported contract");
        }
        Ok(())
    }

    pub fn write_plan(&self, plan_id: &str, payload: PlanPayload) -> Result<PlanRecord> {
        validate_prefixed_id(plan_id, "plan_")?;
        run_validation::validate_plan(self, plan_id, &payload)?;
        let digest = digest_serialized(&payload)?;
        let record = PlanRecord {
            schema_version: "plan_record/v1".to_owned(),
            plan_id: plan_id.to_owned(),
            record_digest: digest,
            payload,
        };
        let path = self.state.join("plans").join(format!("{plan_id}.json"));
        self.write_json_atomic(&path, &record, true)?;
        Ok(record)
    }

    pub fn load_plan(&self, plan_id: &str) -> Result<PlanRecord> {
        validate_prefixed_id(plan_id, "plan_")?;
        let path = self.state.join("plans").join(format!("{plan_id}.json"));
        let record: PlanRecord = read_strict_json(&path)?;
        if record.schema_version != "plan_record/v1" || record.plan_id != plan_id {
            bail!("plan record identity mismatch");
        }
        let actual = digest_serialized(&record.payload)?;
        if actual != record.record_digest {
            bail!("plan record digest mismatch; the plan is stale or modified");
        }
        Ok(record)
    }

    pub fn load_plan_verified(&self, plan_id: &str) -> Result<PlanRecord> {
        let record = self.load_plan(plan_id)?;
        run_validation::validate_plan_record(self, plan_id, &record.payload)?;
        Ok(record)
    }

    pub fn list_plans_verified(&self) -> Result<Vec<PlanRecord>> {
        registry_record_ids(&self.state.join("plans"), "plan_", "plan")?
            .into_iter()
            .map(|plan_id| self.load_plan_verified(&plan_id))
            .collect()
    }

    pub fn write_run(&self, run: crate::contracts::InstrumentRun) -> Result<RunRecord> {
        run_validation::validate(self, &run)?;
        let digest = digest_serialized(&run)?;
        let record = RunRecord {
            schema_version: "run_record/v1".to_owned(),
            record_digest: digest,
            run,
        };
        let path = self
            .state
            .join("runs")
            .join(format!("{}.json", record.run.run_id));
        self.write_json_atomic(&path, &record, true)?;
        Ok(record)
    }

    pub fn write_native_qualification(
        &self,
        record: &NativeDeliveryQualificationRecord,
    ) -> Result<()> {
        validate_prefixed_id(&record.qualification_id, "qualification_")?;
        let path = self
            .state
            .join("qualifications")
            .join(format!("{}.json", record.qualification_id));
        self.write_json_atomic(&path, record, true)
    }

    pub fn load_native_qualification(
        &self,
        qualification_id: &str,
    ) -> Result<NativeDeliveryQualificationRecord> {
        validate_prefixed_id(qualification_id, "qualification_")?;
        let path = self
            .state
            .join("qualifications")
            .join(format!("{qualification_id}.json"));
        let record: NativeDeliveryQualificationRecord = read_strict_json(&path)?;
        if record.schema_version != "native_delivery_qualification_record/v1"
            || record.qualification_id != qualification_id
            || digest_serialized(&record.payload)? != record.record_digest
        {
            bail!("native delivery qualification record identity or digest mismatch");
        }
        Ok(record)
    }

    pub fn list_native_qualifications(&self) -> Result<Vec<NativeDeliveryQualificationRecord>> {
        registry_record_ids(
            &self.state.join("qualifications"),
            "qualification_",
            "native qualification",
        )?
        .into_iter()
        .map(|qualification_id| self.load_native_qualification(&qualification_id))
        .collect()
    }

    pub fn load_run(&self, run_id: &str) -> Result<RunRecord> {
        validate_prefixed_id(run_id, "run_")?;
        let path = self.state.join("runs").join(format!("{run_id}.json"));
        let record: RunRecord = read_strict_json(&path)?;
        if record.schema_version != "run_record/v1" || record.run.run_id != run_id {
            bail!("run record identity mismatch");
        }
        if digest_serialized(&record.run)? != record.record_digest {
            bail!("run record digest mismatch");
        }
        run_validation::validate(self, &record.run)?;
        Ok(record)
    }

    pub fn list_runs(&self) -> Result<Vec<RunRecord>> {
        let mut records = Vec::new();
        for entry in fs::read_dir(self.state.join("runs"))? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let id = path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or_else(|| anyhow::anyhow!("run record has a non-UTF-8 filename"))?;
            records.push(self.load_run(id)?);
        }
        records.sort_by(|left, right| left.run.started_at.cmp(&right.run.started_at));
        Ok(records)
    }

    pub(crate) fn write_evidence_handoff(&self, record: &EvidenceHandoffRecord) -> Result<()> {
        validate_prefixed_id(&record.handoff.handoff_id, "handoff_")?;
        if record.schema_version != "evidence_handoff_record/v1"
            || digest_serialized(&record.handoff)? != record.record_digest
        {
            bail!("evidence handoff record identity or digest mismatch");
        }
        crate::data_contract_validation::validate_evidence_handoff(&record.handoff)?;
        let path = self
            .state
            .join("handoffs")
            .join(format!("{}.json", record.handoff.handoff_id));
        self.write_json_atomic(&path, record, true)
    }

    pub(crate) fn load_evidence_handoff(&self, handoff_id: &str) -> Result<EvidenceHandoffRecord> {
        validate_prefixed_id(handoff_id, "handoff_")?;
        let path = self
            .state
            .join("handoffs")
            .join(format!("{handoff_id}.json"));
        let record: EvidenceHandoffRecord = read_strict_json(&path)?;
        if record.schema_version != "evidence_handoff_record/v1"
            || record.handoff.handoff_id != handoff_id
            || digest_serialized(&record.handoff)? != record.record_digest
        {
            bail!("evidence handoff record identity or digest mismatch");
        }
        Ok(record)
    }

    pub(crate) fn evidence_handoff_ids(&self) -> Result<Vec<String>> {
        registry_record_ids(&self.state.join("handoffs"), "handoff_", "evidence handoff")
    }

    pub fn write_runtime_capsule(&self, record: &RuntimeCapsuleRecord) -> Result<()> {
        validate_prefixed_id(&record.capsule_id, "capsule_")?;
        let path = self
            .state
            .join("capsules")
            .join(format!("{}.json", record.capsule_id));
        self.write_json_atomic(&path, record, true)
    }

    pub fn load_runtime_capsule(&self, capsule_id: &str) -> Result<RuntimeCapsuleRecord> {
        validate_prefixed_id(capsule_id, "capsule_")?;
        let path = self
            .state
            .join("capsules")
            .join(format!("{capsule_id}.json"));
        read_strict_json(&path)
    }

    pub fn list_runtime_capsules(&self) -> Result<Vec<RuntimeCapsuleRecord>> {
        let mut records = Vec::new();
        for entry in fs::read_dir(self.state.join("capsules"))? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let id = path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or_else(|| {
                    anyhow::anyhow!("runtime capsule record has a non-UTF-8 filename")
                })?;
            records.push(self.load_runtime_capsule(id)?);
        }
        records.sort_by(|left, right| left.capsule_id.cmp(&right.capsule_id));
        Ok(records)
    }

    pub fn write_subject_candidate(&self, record: &SubjectCandidateRecord) -> Result<()> {
        validate_prefixed_id(&record.candidate_id, "candidate_")?;
        let path = self
            .state
            .join("candidates")
            .join(format!("{}.json", record.candidate_id));
        self.write_json_atomic(&path, record, true)
    }

    pub fn load_subject_candidate(&self, candidate_id: &str) -> Result<SubjectCandidateRecord> {
        validate_prefixed_id(candidate_id, "candidate_")?;
        let path = self
            .state
            .join("candidates")
            .join(format!("{candidate_id}.json"));
        let record: SubjectCandidateRecord = read_strict_json(&path)?;
        if record.candidate_id != candidate_id {
            bail!("subject candidate record filename identity mismatch");
        }
        Ok(record)
    }

    pub fn list_subject_candidates(&self) -> Result<Vec<SubjectCandidateRecord>> {
        let mut records = Vec::new();
        for entry in fs::read_dir(self.state.join("candidates"))? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.is_file() || is_reparse(&metadata) {
                bail!("subject candidate registry may contain only regular non-link files");
            }
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                bail!("subject candidate registry contains an unexpected file");
            }
            let id = path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or_else(|| {
                    anyhow::anyhow!("subject candidate record has a non-UTF-8 filename")
                })?;
            records.push(self.load_subject_candidate(id)?);
        }
        records.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
        Ok(records)
    }

    pub fn import_artifact(
        &self,
        source: &Path,
        roles: Vec<String>,
        media_type: String,
        origin: &str,
        capture_mode: &str,
    ) -> Result<ArtifactDescriptor> {
        validate_artifact_capture_contract(&roles, &media_type, origin, capture_mode)?;
        let source_meta = fs::symlink_metadata(source)
            .with_context(|| format!("cannot stat artifact source {}", source.display()))?;
        if !source_meta.is_file() || is_reparse(&source_meta) {
            bail!("artifact source must be a regular non-link file");
        }
        let source_modified = source_meta.modified().ok();
        let source_length = source_meta.len();

        let temp_path = self
            .state
            .join("tmp")
            .join(format!("object-{}.tmp", Uuid::new_v4().simple()));
        let mut input = File::open(source)?;
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)?;
        let mut hasher = Sha256::new();
        let mut length = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            output.write_all(&buffer[..read])?;
            hasher.update(&buffer[..read]);
            length += read as u64;
        }
        output.sync_all()?;
        drop(output);

        let after = fs::metadata(source)?;
        if after.len() != source_length || after.modified().ok() != source_modified {
            let _ = fs::remove_file(&temp_path);
            bail!("artifact source changed while it was being captured");
        }

        let digest = hex::encode(hasher.finalize());
        let object_path = self.object_path(&digest)?;
        ensure_real_dir(object_path.parent().expect("object path has parent"))?;
        commit_content_object(&temp_path, &object_path, &digest, length)?;

        let descriptor = ArtifactDescriptor {
            artifact_id: format!("artifact_{}", Uuid::new_v4().simple()),
            roles,
            media_type,
            byte_length: length,
            digest: Digest {
                algorithm: "sha256".to_owned(),
                value: digest.clone(),
            },
            storage: ArtifactStorage {
                uri: format!("ewb:sha256:{digest}"),
            },
            origin: origin.to_owned(),
            capture: ArtifactCapture {
                mode: capture_mode.to_owned(),
            },
            transforms: Vec::new(),
        };
        self.write_artifact_record(&descriptor)?;
        Ok(descriptor)
    }

    /// Commit bytes that the caller has already read and validated. This is used
    /// by strict JSON registries so malformed input can fail before any CAS or
    /// artifact record is created, while the bytes parsed are exactly the bytes
    /// captured.
    pub fn import_artifact_bytes(
        &self,
        bytes: &[u8],
        roles: Vec<String>,
        media_type: String,
        origin: &str,
        capture_mode: &str,
    ) -> Result<ArtifactDescriptor> {
        validate_artifact_capture_contract(&roles, &media_type, origin, capture_mode)?;
        let length = u64::try_from(bytes.len()).context("artifact byte length overflow")?;
        let digest = hex::encode(Sha256::digest(bytes));
        let temp_path = self
            .state
            .join("tmp")
            .join(format!("object-{}.tmp", Uuid::new_v4().simple()));
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)?;
        output.write_all(bytes)?;
        output.sync_all()?;
        drop(output);

        let object_path = self.object_path(&digest)?;
        ensure_real_dir(object_path.parent().expect("object path has parent"))?;
        commit_content_object(&temp_path, &object_path, &digest, length)?;
        let descriptor = ArtifactDescriptor {
            artifact_id: format!("artifact_{}", Uuid::new_v4().simple()),
            roles,
            media_type,
            byte_length: length,
            digest: Digest {
                algorithm: "sha256".to_owned(),
                value: digest.clone(),
            },
            storage: ArtifactStorage {
                uri: format!("ewb:sha256:{digest}"),
            },
            origin: origin.to_owned(),
            capture: ArtifactCapture {
                mode: capture_mode.to_owned(),
            },
            transforms: Vec::new(),
        };
        self.write_artifact_record(&descriptor)?;
        Ok(descriptor)
    }

    fn write_artifact_record(&self, descriptor: &ArtifactDescriptor) -> Result<ArtifactRecord> {
        validate_prefixed_id(&descriptor.artifact_id, "artifact_")?;
        let record = ArtifactRecord {
            schema_version: "artifact_record/v1".to_owned(),
            record_digest: digest_serialized(descriptor)?,
            artifact: descriptor.clone(),
        };
        let path = self
            .state
            .join("artifacts")
            .join(format!("{}.json", descriptor.artifact_id));
        self.write_json_atomic(&path, &record, true)?;
        Ok(record)
    }

    pub fn load_artifact(&self, artifact_id: &str) -> Result<ArtifactRecord> {
        validate_prefixed_id(artifact_id, "artifact_")?;
        let path = self
            .state
            .join("artifacts")
            .join(format!("{artifact_id}.json"));
        let record: ArtifactRecord = read_strict_json(&path)?;
        if record.schema_version != "artifact_record/v1"
            || record.artifact.artifact_id != artifact_id
            || digest_serialized(&record.artifact)? != record.record_digest
        {
            bail!("artifact record identity or digest mismatch");
        }
        self.verify_descriptor(&record.artifact)?;
        Ok(record)
    }

    pub fn list_artifacts(&self) -> Result<Vec<ArtifactRecord>> {
        registry_record_ids(&self.state.join("artifacts"), "artifact_", "artifact")?
            .into_iter()
            .map(|artifact_id| self.load_artifact(&artifact_id))
            .collect()
    }

    pub fn write_python_runtime_qualification(
        &self,
        record: &PythonRuntimeQualificationRecord,
    ) -> Result<()> {
        validate_prefixed_id(&record.qualification_id, "qualification_")?;
        let path = self
            .state
            .join("python-qualifications")
            .join(format!("{}.json", record.qualification_id));
        self.write_json_atomic(&path, record, true)
    }

    pub fn load_python_runtime_qualification(
        &self,
        qualification_id: &str,
    ) -> Result<PythonRuntimeQualificationRecord> {
        validate_prefixed_id(qualification_id, "qualification_")?;
        let path = self
            .state
            .join("python-qualifications")
            .join(format!("{qualification_id}.json"));
        let record: PythonRuntimeQualificationRecord = read_strict_json(&path)?;
        if record.schema_version != "python_runtime_qualification_record/v1"
            || record.qualification_id != qualification_id
            || digest_serialized(&record.payload)? != record.record_digest
        {
            bail!("Python runtime qualification record identity or digest mismatch");
        }
        Ok(record)
    }

    pub fn list_python_runtime_qualifications(
        &self,
    ) -> Result<Vec<PythonRuntimeQualificationRecord>> {
        registry_record_ids(
            &self.state.join("python-qualifications"),
            "qualification_",
            "Python runtime qualification",
        )?
        .into_iter()
        .map(|qualification_id| self.load_python_runtime_qualification(&qualification_id))
        .collect()
    }

    pub fn verify_descriptor(&self, descriptor: &ArtifactDescriptor) -> Result<PathBuf> {
        run_validation::validate_artifact_descriptor(descriptor)?;
        let path = self.object_path(&descriptor.digest.value)?;
        self.validate_object_storage_path(&path)?;
        let metadata = fs::symlink_metadata(&path).context("artifact object is missing")?;
        if !metadata.is_file() || is_reparse(&metadata) {
            bail!("artifact object is not a regular non-link file");
        }
        verify_file(&path, &descriptor.digest.value, descriptor.byte_length)?;
        Ok(path)
    }

    /// Read exactly the bytes named by an artifact descriptor and verify those
    /// same bytes before returning them to a parser.
    ///
    /// On Windows the underlying handle permits read sharing only. That keeps
    /// another process from opening the object for write or delete while the
    /// bytes are being read and hashed. On every platform the digest and length
    /// are computed from the returned byte vector, eliminating a
    /// verify-then-reopen gap.
    pub fn read_verified_descriptor(&self, descriptor: &ArtifactDescriptor) -> Result<Vec<u8>> {
        run_validation::validate_artifact_descriptor(descriptor)?;
        let path = self.object_path(&descriptor.digest.value)?;
        self.validate_object_storage_path(&path)?;
        read_verified_file(&path, &descriptor.digest.value, descriptor.byte_length)
            .with_context(|| format!("cannot read verified artifact object {}", path.display()))
    }

    /// Copy one verified CAS object into the private execution input path for a
    /// specific plan. The destination is derived here rather than accepted from
    /// the caller, and the CAS object is read, hashed, and copied through the
    /// same handle so execution never follows a path after a separate verify.
    pub(crate) fn materialize_artifact_execution_input(
        &self,
        plan_id: &str,
        descriptor: &ArtifactDescriptor,
    ) -> Result<PathBuf> {
        validate_prefixed_id(plan_id, "plan_")?;
        run_validation::validate_artifact_descriptor(descriptor)?;

        let source_path = self.object_path(&descriptor.digest.value)?;
        self.validate_object_storage_path(&source_path)?;
        let path_metadata = fs::symlink_metadata(&source_path)
            .with_context(|| format!("cannot inspect artifact object {}", source_path.display()))?;
        if !path_metadata.is_file() || is_reparse(&path_metadata) {
            bail!("artifact object is not a regular single-link file");
        }
        let mut source = open_artifact_read_no_write_share(&source_path)
            .with_context(|| format!("cannot open artifact object {}", source_path.display()))?;
        let source_metadata = source.metadata()?;
        if !source_metadata.is_file()
            || is_reparse(&source_metadata)
            || !file_has_single_link(&source, &source_metadata)?
        {
            bail!("artifact object is not a regular single-link file");
        }
        if source_metadata.len() != descriptor.byte_length {
            bail!("artifact bytes do not match their recorded digest and length");
        }

        validate_real_dir(&self.state)?;
        let executions = self.state.join("executions");
        validate_real_dir(&executions)?;
        let root = self.execution_path(plan_id)?;
        fs::create_dir(&root).with_context(|| {
            format!(
                "cannot create new private artifact execution root {}",
                root.display()
            )
        })?;

        let materialized = (|| -> Result<PathBuf> {
            validate_real_dir(&root)?;
            let destination = root.join("input");
            let mut output = create_private_file(&destination).with_context(|| {
                format!(
                    "cannot create private artifact execution input {}",
                    destination.display()
                )
            })?;

            let mut hasher = Sha256::new();
            let mut length = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = source.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                output.write_all(&buffer[..read])?;
                hasher.update(&buffer[..read]);
                length = length
                    .checked_add(read as u64)
                    .ok_or_else(|| anyhow::anyhow!("artifact byte length overflow"))?;
                if length > descriptor.byte_length {
                    bail!("artifact bytes do not match their recorded digest and length");
                }
            }
            output.sync_all()?;
            let output_metadata = output.metadata()?;
            if !output_metadata.is_file()
                || is_reparse(&output_metadata)
                || !file_has_single_link(&output, &output_metadata)?
            {
                bail!("private artifact execution input must be a regular single-link file");
            }
            let source_digest = hex::encode(hasher.finalize());
            if length != descriptor.byte_length || source_digest != descriptor.digest.value {
                bail!("artifact bytes do not match their recorded digest and length");
            }

            output.seek(SeekFrom::Start(0))?;
            let mut output_hasher = Sha256::new();
            let mut output_length = 0_u64;
            loop {
                let read = output.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                output_hasher.update(&buffer[..read]);
                output_length = output_length
                    .checked_add(read as u64)
                    .ok_or_else(|| anyhow::anyhow!("artifact byte length overflow"))?;
                if output_length > descriptor.byte_length {
                    bail!("artifact execution copy does not match its recorded identity");
                }
            }
            if output_length != descriptor.byte_length
                || hex::encode(output_hasher.finalize()) != descriptor.digest.value
            {
                bail!("artifact execution copy does not match its recorded identity");
            }
            drop(output);

            validate_real_dir(&root)?;
            verify_file(
                &destination,
                &descriptor.digest.value,
                descriptor.byte_length,
            )?;
            let entries = fs::read_dir(&root)?.collect::<Result<Vec<_>, _>>()?;
            if entries.len() != 1 || entries[0].file_name() != std::ffi::OsStr::new("input") {
                bail!("private artifact execution root inventory is not input-only");
            }
            Ok(destination)
        })();

        match materialized {
            Ok(destination) => Ok(destination),
            Err(error) => {
                if let Err(cleanup_error) = rollback_artifact_execution_root(&executions, &root) {
                    return Err(anyhow::anyhow!(
                        "artifact input materialization failed: {error:#}; also failed to roll back private artifact execution root: {cleanup_error:#}"
                    ));
                }
                Err(error)
            }
        }
    }

    fn validate_object_storage_path(&self, object_path: &Path) -> Result<()> {
        validate_real_dir(&self.state)?;
        let objects = self.state.join("objects");
        validate_real_dir(&objects)?;
        let algorithm = objects.join("sha256");
        validate_real_dir(&algorithm)?;
        let shard = object_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("artifact object path has no shard directory"))?;
        if shard.parent() != Some(algorithm.as_path()) {
            bail!("artifact object path is outside the workspace CAS shard layout");
        }
        validate_real_dir(shard)?;
        Ok(())
    }

    pub fn object_path(&self, digest: &str) -> Result<PathBuf> {
        validate_sha256(digest)?;
        Ok(self
            .state
            .join("objects")
            .join("sha256")
            .join(&digest[..2])
            .join(&digest[2..]))
    }

    pub fn staged_executable_path(&self, digest: &str, extension: &str) -> Result<PathBuf> {
        self.staged_path("native", digest, extension)
    }

    pub fn staged_git_plan_launcher_path(&self, digest: &str, extension: &str) -> Result<PathBuf> {
        self.staged_path("git-plan", digest, extension)
    }

    pub fn qualified_application_executable_path(
        &self,
        plan_id: &str,
        digest: &str,
        filename: &str,
    ) -> Result<PathBuf> {
        validate_prefixed_id(plan_id, "plan_")?;
        validate_sha256(digest)?;
        if filename.is_empty()
            || filename.contains('/')
            || filename.contains('\\')
            || matches!(filename, "." | "..")
        {
            bail!("qualified application filename is unsafe");
        }
        Ok(self
            .state
            .join("staged")
            .join("applications")
            .join("sha256")
            .join(digest)
            .join(plan_id)
            .join(filename))
    }

    pub fn materialize_qualified_application(
        &self,
        plan_id: &str,
        artifact_id: &str,
        filename: &str,
    ) -> Result<(ArtifactDescriptor, PathBuf)> {
        let record = self.load_artifact(artifact_id)?;
        let bytes = self.read_verified_descriptor(&record.artifact)?;
        let destination = self.qualified_application_executable_path(
            plan_id,
            &record.artifact.digest.value,
            filename,
        )?;
        let application = destination
            .parent()
            .context("qualified application path has no parent")?;
        let staged = self.state.join("staged");
        validate_real_dir(&staged)?;
        let applications = staged.join("applications");
        ensure_real_dir(&applications)?;
        let algorithm = applications.join("sha256");
        ensure_real_dir(&algorithm)?;
        let digest_directory = algorithm.join(&record.artifact.digest.value);
        ensure_real_dir(&digest_directory)?;
        fs::create_dir(application)
            .context("cannot create private qualified application directory")?;
        validate_real_dir(application)?;
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&destination)?;
        output.write_all(&bytes)?;
        output.sync_all()?;
        drop(output);
        verify_file(
            &destination,
            &record.artifact.digest.value,
            record.artifact.byte_length,
        )?;
        let entries = fs::read_dir(application)?.collect::<Result<Vec<_>, _>>()?;
        if entries.len() != 1 || entries[0].file_name() != std::ffi::OsStr::new(filename) {
            bail!("qualified application directory inventory is not launcher-only");
        }
        Ok((record.artifact, destination))
    }

    fn staged_path(&self, prefix: &str, digest: &str, extension: &str) -> Result<PathBuf> {
        validate_sha256(digest)?;
        let suffix = if extension.is_empty() {
            String::new()
        } else {
            format!(".{extension}")
        };
        Ok(self
            .state
            .join("staged")
            .join(format!("{prefix}-{digest}{suffix}")))
    }

    pub fn import_native_snapshot(&self, source: &Path) -> Result<(ArtifactDescriptor, PathBuf)> {
        self.import_staged_executable(source, "native_executable_snapshot", "native")
    }

    pub fn import_git_plan_launcher_snapshot(
        &self,
        source: &Path,
    ) -> Result<(ArtifactDescriptor, PathBuf)> {
        self.import_staged_executable(source, "git_plan_launcher_snapshot", "git-plan")
    }

    fn import_staged_executable(
        &self,
        source: &Path,
        role: &str,
        prefix: &str,
    ) -> Result<(ArtifactDescriptor, PathBuf)> {
        let artifact = self.import_artifact(
            source,
            vec![role.to_owned()],
            "application/x-executable".to_owned(),
            "native_file",
            "byte_for_byte_copy",
        )?;
        let extension = source
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        validate_sha256(&artifact.digest.value)?;
        let suffix = if extension.is_empty() {
            String::new()
        } else {
            format!(".{extension}")
        };
        let staged = self
            .state
            .join("staged")
            .join(format!("{prefix}-{}{suffix}", artifact.digest.value));
        let object = self.verify_descriptor(&artifact)?;
        validate_real_dir(&self.state.join("staged"))?;
        if staged.exists() {
            verify_file(&staged, &artifact.digest.value, artifact.byte_length)?;
        } else {
            let temporary = self
                .state
                .join("tmp")
                .join(format!("native-{}.tmp", Uuid::new_v4().simple()));
            fs::copy(&object, &temporary).context("cannot prepare executable snapshot")?;
            fs::set_permissions(&temporary, fs::metadata(source)?.permissions())?;
            OpenOptions::new()
                .write(true)
                .open(&temporary)?
                .sync_all()?;
            match fs::hard_link(&temporary, &staged) {
                Ok(()) => {}
                Err(_error) if staged.is_file() => {
                    verify_file(&staged, &artifact.digest.value, artifact.byte_length)
                        .context("concurrently staged executable differs")?;
                }
                Err(error) => {
                    let _ = fs::remove_file(&temporary);
                    return Err(error).context("cannot atomically stage executable snapshot");
                }
            }
            let _ = fs::remove_file(&temporary);
            verify_file(&staged, &artifact.digest.value, artifact.byte_length)?;
        }
        Ok((artifact, staged))
    }

    pub fn execution_path(&self, plan_id: &str) -> Result<PathBuf> {
        validate_prefixed_id(plan_id, "plan_")?;
        Ok(self.state.join("executions").join(plan_id))
    }

    pub fn acquire_plan_lock(&self, plan_id: &str) -> Result<PlanExecutionLock> {
        validate_prefixed_id(plan_id, "plan_")?;
        validate_real_dir(&self.state.join("locks"))?;
        let path = self.state.join("locks").join(format!("{plan_id}.lock"));
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .context("this plan is currently executing")?;
        Ok(PlanExecutionLock {
            path,
            file: Some(file),
        })
    }

    fn write_json_atomic<T: Serialize>(
        &self,
        destination: &Path,
        value: &T,
        unique: bool,
    ) -> Result<()> {
        self.validate_layout_shallow()?;
        let bytes = serde_json::to_vec_pretty(value)?;
        let temporary = self
            .state
            .join("tmp")
            .join(format!("record-{}.tmp", Uuid::new_v4().simple()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        if unique {
            if let Err(error) = retry_transient(|| publish_file_no_replace(&temporary, destination))
            {
                if let Err(cleanup_error) = retry_transient(|| fs::remove_file(&temporary)) {
                    return Err(error).with_context(|| {
                        format!(
                            "cannot atomically create record {}; cleanup of unpublished temporary file {} also failed: {cleanup_error}",
                            destination.display(),
                            temporary.display()
                        )
                    });
                }
                return Err(error).with_context(|| {
                    format!("cannot atomically create record {}", destination.display())
                });
            }
        } else if let Err(error) = fs::rename(&temporary, destination) {
            let _ = fs::remove_file(&temporary);
            return Err(error).with_context(|| {
                format!("cannot atomically commit record {}", destination.display())
            });
        }
        Ok(())
    }

    fn validate_layout_shallow(&self) -> Result<()> {
        validate_real_dir(&self.state)?;
        validate_real_dir(&self.state.join("tmp"))?;
        Ok(())
    }
}

fn validate_artifact_capture_contract(
    roles: &[String],
    media_type: &str,
    origin: &str,
    capture_mode: &str,
) -> Result<()> {
    if roles.is_empty() {
        bail!("artifact must have at least one role");
    }
    let mut unique_roles = BTreeSet::new();
    for role in roles {
        let valid = !role.is_empty()
            && role.len() <= 64
            && role
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
        if !valid || !unique_roles.insert(role) {
            bail!("artifact roles must be unique lowercase ASCII identifiers");
        }
    }
    if media_type.is_empty() || media_type.trim() != media_type {
        bail!("artifact media type must be a non-empty trimmed string");
    }
    if !matches!(origin, "native_file" | "process_stdout" | "process_stderr") {
        bail!("artifact origin is outside the v1 contract");
    }
    if !matches!(capture_mode, "byte_for_byte_copy" | "raw_stream_capture") {
        bail!("artifact capture mode is outside the v1 contract");
    }
    Ok(())
}

fn rollback_artifact_execution_root(executions: &Path, root: &Path) -> Result<()> {
    if root.parent() != Some(executions) {
        bail!("refusing to roll back a path outside EWB executions storage");
    }
    validate_real_dir(executions)?;
    match fs::symlink_metadata(root) {
        Ok(metadata) => {
            if !metadata.is_dir() || is_reparse(&metadata) {
                bail!("refusing to roll back a linked artifact execution root");
            }
            fs::remove_dir_all(root).with_context(|| {
                format!(
                    "cannot remove failed artifact execution root {}",
                    root.display()
                )
            })?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "cannot inspect failed artifact execution root {}",
                    root.display()
                )
            });
        }
    }
    Ok(())
}

pub fn digest_file(path: &Path) -> Result<(String, u64)> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || is_reparse(&metadata) {
        bail!("identity target must be a regular non-link file");
    }
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        length += read as u64;
    }
    Ok((hex::encode(hasher.finalize()), length))
}

/// Re-hash an EWB-owned private file while holding one read handle (without
/// write/delete sharing on Windows) and requiring that no second hard-link
/// name exists.
pub fn verify_private_file(path: &Path, expected_digest: &str, expected_length: u64) -> Result<()> {
    verify_file(path, expected_digest, expected_length)
}

pub fn digest_serialized<T: Serialize>(value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn new_plan_id() -> String {
    format!("plan_{}", Uuid::new_v4().simple())
}

pub fn new_run_id() -> String {
    format!("run_{}", Uuid::new_v4().simple())
}

pub fn new_handoff_id() -> String {
    format!("handoff_{}", Uuid::new_v4().simple())
}

pub fn validate_prefixed_id(value: &str, prefix: &str) -> Result<()> {
    let suffix = value
        .strip_prefix(prefix)
        .ok_or_else(|| anyhow::anyhow!("identifier has the wrong prefix"))?;
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("invalid storage identifier");
    }
    Ok(())
}

pub fn validate_sha256(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("invalid lowercase SHA-256 digest");
    }
    Ok(())
}

fn read_strict_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let path_metadata = fs::symlink_metadata(path)?;
    if !path_metadata.is_file() || is_reparse(&path_metadata) {
        bail!("record must be a regular single-link file");
    }
    let mut file = open_artifact_read_no_write_share(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || is_reparse(&metadata) || !file_has_single_link(&file, &metadata)? {
        bail!("record must be a regular single-link file");
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let value = strict_json::parse_strict(&bytes)?;
    Ok(serde_json::from_value(value)?)
}

fn registry_record_ids(directory: &Path, prefix: &str, label: &str) -> Result<Vec<String>> {
    validate_real_dir(directory)?;
    let mut ids = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || is_reparse(&metadata) {
            bail!("{label} registry may contain only regular non-link JSON files");
        }
        let filename = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("{label} registry contains a non-UTF-8 filename"))?;
        let id = filename
            .strip_suffix(".json")
            .ok_or_else(|| anyhow::anyhow!("{label} registry contains an unexpected file"))?;
        validate_prefixed_id(id, prefix)
            .with_context(|| format!("{label} registry contains an invalid record filename"))?;
        ids.push(id.to_owned());
    }
    ids.sort();
    Ok(ids)
}

fn ensure_real_dir(path: &Path) -> Result<()> {
    if path.exists() {
        validate_real_dir(path)
    } else {
        let create_result = retry_transient(|| fs::create_dir(path));
        if !path.is_dir() {
            create_result.with_context(|| format!("cannot create directory {}", path.display()))?;
        }
        validate_real_dir(path)
    }
}

fn prepare_workspace_root(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        bail!("workspace root cannot be empty");
    }
    if path.exists() {
        validate_real_directory_chain(path)?;
        return path
            .canonicalize()
            .with_context(|| format!("cannot resolve workspace root {}", path.display()));
    }

    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("workspace root must name one directory"))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    validate_real_directory_chain(parent)?;
    let parent = parent
        .canonicalize()
        .with_context(|| format!("cannot resolve workspace parent {}", parent.display()))?;
    validate_real_dir(&parent)?;

    // Create only the requested leaf. Missing parent chains are rejected instead of
    // silently broadening `init` into a recursive filesystem mutation.
    let root = parent.join(name);
    match retry_transient(|| fs::create_dir(&root)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("cannot create workspace root {}", root.display()));
        }
    }
    validate_real_dir(&root)?;
    let canonical = root
        .canonicalize()
        .with_context(|| format!("cannot resolve workspace root {}", root.display()))?;
    if canonical.parent() != Some(parent.as_path()) {
        bail!("workspace root resolved outside its exact parent");
    }
    Ok(canonical)
}

fn validate_real_directory_chain(path: &Path) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut ancestors = absolute.ancestors().collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        validate_real_dir(ancestor)?;
    }
    Ok(())
}

fn validate_real_dir(path: &Path) -> Result<()> {
    let metadata = retry_transient(|| fs::symlink_metadata(path))
        .with_context(|| format!("cannot inspect directory {}", path.display()))?;
    if !metadata.is_dir() || is_reparse(&metadata) {
        bail!(
            "storage directory must be a real directory, not a link or reparse point: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn file_has_single_link(file: &File, _metadata: &fs::Metadata) -> Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file owns a live Windows file handle and information is writable.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) };
    if ok == 0 {
        return Err(io::Error::last_os_error()).context("cannot query file link identity");
    }
    Ok(information.nNumberOfLinks == 1)
}

#[cfg(unix)]
fn file_has_single_link(_file: &File, metadata: &fs::Metadata) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    Ok(metadata.nlink() == 1)
}

#[cfg(not(any(unix, windows)))]
fn file_has_single_link(_file: &File, _metadata: &fs::Metadata) -> Result<bool> {
    Ok(false)
}

#[derive(Debug)]
struct MultipleLinkNames;

impl std::fmt::Display for MultipleLinkNames {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("private file must be a regular single-link file")
    }
}

impl std::error::Error for MultipleLinkNames {}

fn open_verified_private_file(path: &Path) -> Result<File> {
    let path_metadata = fs::symlink_metadata(path)?;
    if !path_metadata.is_file() || is_reparse(&path_metadata) {
        bail!("private file must be a regular single-link file");
    }
    let file = open_artifact_read_no_write_share(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || is_reparse(&metadata) {
        bail!("private file must be a regular single-link file");
    }
    if !file_has_single_link(&file, &metadata)? {
        return Err(MultipleLinkNames.into());
    }
    Ok(file)
}

fn verify_open_private_file(
    mut file: File,
    expected_digest: &str,
    expected_length: u64,
) -> Result<()> {
    let mut hasher = Sha256::new();
    let mut actual_length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        actual_length = actual_length
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("private file byte length overflow"))?;
    }
    let actual_digest = hex::encode(hasher.finalize());
    if actual_digest != expected_digest || actual_length != expected_length {
        bail!("artifact bytes do not match their recorded digest and length");
    }
    Ok(())
}

fn verify_file(path: &Path, expected_digest: &str, expected_length: u64) -> Result<()> {
    verify_open_private_file(
        open_verified_private_file(path)?,
        expected_digest,
        expected_length,
    )
}

fn read_verified_file(path: &Path, expected_digest: &str, expected_length: u64) -> Result<Vec<u8>> {
    let path_metadata = fs::symlink_metadata(path)?;
    if !path_metadata.is_file() || is_reparse(&path_metadata) {
        bail!("artifact object is not a regular single-link file");
    }
    let mut file = open_artifact_read_no_write_share(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || is_reparse(&metadata) || !file_has_single_link(&file, &metadata)? {
        bail!("artifact object is not a regular single-link file");
    }
    if metadata.len() != expected_length {
        bail!("artifact bytes do not match their recorded digest and length");
    }

    let capacity = usize::try_from(expected_length)
        .context("artifact is too large to address on this platform")?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .context("cannot allocate buffer for artifact bytes")?;
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let next_length = length
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("artifact byte length overflow"))?;
        if next_length > expected_length {
            bail!("artifact bytes do not match their recorded digest and length");
        }
        hasher.update(&buffer[..read]);
        bytes.extend_from_slice(&buffer[..read]);
        length = next_length;
    }

    if length != expected_length || hex::encode(hasher.finalize()) != expected_digest {
        bail!("artifact bytes do not match their recorded digest and length");
    }
    Ok(bytes)
}

#[cfg(windows)]
fn create_private_file(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;

    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN)
        .open(path)?)
}

#[cfg(not(windows))]
fn create_private_file(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)?)
}

#[cfg(windows)]
fn open_artifact_read_no_write_share(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;

    Ok(OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN)
        .open(path)?)
}

#[cfg(not(windows))]
fn open_artifact_read_no_write_share(path: &Path) -> Result<File> {
    Ok(File::open(path)?)
}

fn commit_content_object(
    temporary: &Path,
    destination: &Path,
    expected_digest: &str,
    expected_length: u64,
) -> Result<()> {
    match retry_transient(|| publish_file_no_replace(temporary, destination)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            retry_transient(|| fs::remove_file(temporary)).with_context(|| {
                format!(
                    "artifact object already exists, but loser temporary file {} could not be removed",
                    temporary.display()
                )
            })?;
            verify_existing_content_object(destination, expected_digest, expected_length)
        }
        Err(error) => {
            if let Err(cleanup_error) = retry_transient(|| fs::remove_file(temporary)) {
                return Err(error).with_context(|| {
                    format!(
                        "cannot atomically publish artifact object {}; cleanup of unpublished temporary file {} also failed: {cleanup_error}",
                        destination.display(),
                        temporary.display()
                    )
                });
            }
            Err(error).with_context(|| {
                format!(
                    "cannot atomically publish artifact object {}",
                    destination.display()
                )
            })
        }
    }
}

fn verify_existing_content_object(
    destination: &Path,
    expected_digest: &str,
    expected_length: u64,
) -> Result<()> {
    for attempt in 0..25 {
        match open_verified_private_file(destination) {
            Ok(file) => {
                return verify_open_private_file(file, expected_digest, expected_length)
                    .with_context(|| {
                        format!(
                            "existing artifact object {} failed immutable-byte verification",
                            destination.display()
                        )
                    });
            }
            Err(error) if is_retryable_existing_object_open(&error) && attempt < 24 => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "cannot open existing artifact object {} for verification",
                        destination.display()
                    )
                });
            }
        }
    }
    unreachable!("bounded existing-object verification loop always returns")
}

fn has_transient_io_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<io::Error>())
        .any(is_transient)
}

#[cfg(windows)]
fn is_retryable_existing_object_open(error: &anyhow::Error) -> bool {
    has_transient_io_error(error)
}

#[cfg(not(windows))]
fn is_retryable_existing_object_open(error: &anyhow::Error) -> bool {
    // The portable no-replace fallback briefly has two names between link and
    // unlink. Bound that publication window, but never accept a persistent
    // external hard link as a valid object.
    has_transient_io_error(error) || error.downcast_ref::<MultipleLinkNames>().is_some()
}

#[cfg(windows)]
fn publish_file_no_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::MoveFileExW;

    fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
        let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if wide.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows path contains an embedded NUL",
            ));
        }
        wide.push(0);
        Ok(wide)
    }

    let source = wide_path(source)?;
    let destination = wide_path(destination)?;
    // Flags zero is a same-volume move with no replacement or copy fallback.
    // Success consumes the source name, so no hard-link cleanup window exists.
    let moved = unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), 0) };
    if moved == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn publish_file_no_replace(source: &Path, destination: &Path) -> io::Result<()> {
    // Stable Rust has no portable rename-without-replacement primitive. Keep the
    // existing same-filesystem hard-link fallback, but roll the destination back
    // if unlinking the source fails instead of reporting a clean commit with two
    // names. Callers retain an explicit error if rollback itself is impossible.
    fs::hard_link(source, destination)?;
    if let Err(unlink_error) = fs::remove_file(source) {
        return match fs::remove_file(destination) {
            Ok(()) => Err(io::Error::new(
                unlink_error.kind(),
                format!(
                    "could not remove source after no-replace link; destination was rolled back: {unlink_error}"
                ),
            )),
            Err(rollback_error) => Err(io::Error::other(format!(
                "could not remove source after no-replace link ({unlink_error}); destination rollback also failed ({rollback_error})"
            ))),
        };
    }
    Ok(())
}

fn retry_transient<T>(mut operation: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    for attempt in 0..25 {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) if is_transient(&error) && attempt < 24 => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("bounded transient retry loop always returns")
}

fn is_transient(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::Interrupted
    ) || is_windows_sharing_or_lock_violation(error)
}

#[cfg(windows)]
fn is_windows_sharing_or_lock_violation(error: &io::Error) -> bool {
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_LOCK_VIOLATION: i32 = 33;
    matches!(
        error.raw_os_error(),
        Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
    )
}

#[cfg(not(windows))]
fn is_windows_sharing_or_lock_violation(_error: &io::Error) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_replace_publish_consumes_source_and_creates_single_link() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source.tmp");
        let destination = temporary.path().join("destination.json");
        let expected = b"complete record\n";
        fs::write(&source, expected).unwrap();

        publish_file_no_replace(&source, &destination).unwrap();

        assert!(!source.exists());
        assert_eq!(fs::read(&destination).unwrap(), expected);
        let file = File::open(&destination).unwrap();
        let metadata = file.metadata().unwrap();
        assert!(file_has_single_link(&file, &metadata).unwrap());
    }

    #[test]
    fn no_replace_publish_preserves_existing_destination() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source.tmp");
        let destination = temporary.path().join("destination.json");
        fs::write(&source, b"replacement").unwrap();
        fs::write(&destination, b"sentinel").unwrap();

        let error = publish_file_no_replace(&source, &destination).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&destination).unwrap(), b"sentinel");
        assert_eq!(fs::read(&source).unwrap(), b"replacement");
    }

    #[cfg(windows)]
    #[test]
    fn existing_cas_verification_retries_a_transient_share_lock() {
        use std::os::windows::fs::OpenOptionsExt;
        use std::sync::mpsc;

        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("object.tmp");
        let destination = temporary.path().join("object");
        let expected = b"one immutable object";
        fs::write(&source, expected).unwrap();
        fs::write(&destination, expected).unwrap();
        let digest = hex::encode(Sha256::digest(expected));
        let locked = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&destination)
            .unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let releaser = thread::spawn(move || {
            ready_tx.send(()).unwrap();
            thread::sleep(Duration::from_millis(50));
            drop(locked);
        });
        ready_rx.recv().unwrap();

        commit_content_object(&source, &destination, &digest, expected.len() as u64).unwrap();

        releaser.join().unwrap();
        assert!(!source.exists());
        assert_eq!(fs::read(&destination).unwrap(), expected);
    }

    #[cfg(unix)]
    #[test]
    fn existing_cas_verification_waits_for_the_fallback_publish_link_to_clear() {
        let temporary = tempfile::tempdir().unwrap();
        let destination = temporary.path().join("object");
        let winner_temporary = temporary.path().join("winner-object.tmp");
        let expected = b"one immutable object";
        fs::write(&destination, expected).unwrap();
        fs::hard_link(&destination, &winner_temporary).unwrap();
        let digest = hex::encode(Sha256::digest(expected));
        let releaser = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            fs::remove_file(winner_temporary).unwrap();
        });

        verify_existing_content_object(&destination, &digest, expected.len() as u64).unwrap();

        releaser.join().unwrap();
        verify_file(&destination, &digest, expected.len() as u64).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn existing_cas_verification_rejects_a_persistent_external_hard_link() {
        let temporary = tempfile::tempdir().unwrap();
        let destination = temporary.path().join("object");
        let external_alias = temporary.path().join("external-alias");
        let expected = b"one immutable object";
        fs::write(&destination, expected).unwrap();
        fs::hard_link(&destination, &external_alias).unwrap();
        let digest = hex::encode(Sha256::digest(expected));

        let error = verify_existing_content_object(
            &destination,
            &digest,
            u64::try_from(expected.len()).unwrap(),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("regular single-link file"));
    }

    #[test]
    fn verified_descriptor_returns_the_exact_hashed_bytes() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = Workspace::init(temporary.path()).unwrap();
        let source = temporary.path().join("native-output.json");
        let expected = br#"{"verdict":"native"}"#;
        fs::write(&source, expected).unwrap();
        let descriptor = workspace
            .import_artifact(
                &source,
                vec!["native_stdout".to_owned()],
                "application/json".to_owned(),
                "process_stdout",
                "raw_stream_capture",
            )
            .unwrap();

        let actual = workspace.read_verified_descriptor(&descriptor).unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn verified_descriptor_rejects_same_length_object_tampering() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = Workspace::init(temporary.path()).unwrap();
        let source = temporary.path().join("native-output.txt");
        fs::write(&source, b"native").unwrap();
        let descriptor = workspace
            .import_artifact(
                &source,
                vec!["native_stdout".to_owned()],
                "text/plain".to_owned(),
                "process_stdout",
                "raw_stream_capture",
            )
            .unwrap();
        let object = workspace.object_path(&descriptor.digest.value).unwrap();
        fs::write(object, b"forged").unwrap();

        let error = workspace.read_verified_descriptor(&descriptor).unwrap_err();

        assert!(
            format!("{error:#}")
                .contains("artifact bytes do not match their recorded digest and length")
        );
    }

    #[test]
    fn verified_descriptor_rejects_claimed_length_mismatch() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = Workspace::init(temporary.path()).unwrap();
        let source = temporary.path().join("native-output.txt");
        fs::write(&source, b"native").unwrap();
        let mut descriptor = workspace
            .import_artifact(
                &source,
                vec!["native_stdout".to_owned()],
                "text/plain".to_owned(),
                "process_stdout",
                "raw_stream_capture",
            )
            .unwrap();
        descriptor.byte_length += 1;

        let error = workspace.read_verified_descriptor(&descriptor).unwrap_err();

        assert!(
            format!("{error:#}")
                .contains("artifact bytes do not match their recorded digest and length")
        );
    }

    #[cfg(windows)]
    #[test]
    fn artifact_read_handle_denies_concurrent_write_and_delete() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("object");
        fs::write(&path, b"native").unwrap();
        let handle = open_artifact_read_no_write_share(&path).unwrap();

        assert!(OpenOptions::new().write(true).open(&path).is_err());
        assert!(fs::remove_file(&path).is_err());

        drop(handle);
        fs::write(&path, b"updated").unwrap();
    }

    #[test]
    fn artifact_execution_inputs_are_private_plan_scoped_copies() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = Workspace::init(temporary.path()).unwrap();
        let source = temporary.path().join("handoff.json");
        let expected = br#"{"native":"exact"}"#;
        fs::write(&source, expected).unwrap();
        let descriptor = workspace
            .import_artifact(
                &source,
                vec!["handoff_input".to_owned()],
                "application/json".to_owned(),
                "native_file",
                "byte_for_byte_copy",
            )
            .unwrap();
        let first_plan = "plan_11111111111111111111111111111111";
        let second_plan = "plan_22222222222222222222222222222222";

        let first = workspace
            .materialize_artifact_execution_input(first_plan, &descriptor)
            .unwrap();
        let second = workspace
            .materialize_artifact_execution_input(second_plan, &descriptor)
            .unwrap();

        assert_eq!(
            first,
            workspace.execution_path(first_plan).unwrap().join("input")
        );
        assert_eq!(
            second,
            workspace.execution_path(second_plan).unwrap().join("input")
        );
        assert_eq!(fs::read(&first).unwrap(), expected);
        assert_eq!(fs::read(&second).unwrap(), expected);
        verify_private_file(&first, &descriptor.digest.value, descriptor.byte_length).unwrap();
        verify_private_file(&second, &descriptor.digest.value, descriptor.byte_length).unwrap();

        fs::write(&first, b"private mutation").unwrap();
        assert_eq!(fs::read(&second).unwrap(), expected);
        assert_eq!(
            workspace.read_verified_descriptor(&descriptor).unwrap(),
            expected
        );
    }

    #[test]
    fn artifact_execution_materialization_never_overwrites_a_preexisting_root() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = Workspace::init(temporary.path()).unwrap();
        let source = temporary.path().join("input.bin");
        fs::write(&source, b"exact").unwrap();
        let descriptor = workspace
            .import_artifact(
                &source,
                vec!["handoff_input".to_owned()],
                "application/octet-stream".to_owned(),
                "native_file",
                "byte_for_byte_copy",
            )
            .unwrap();
        let plan_id = "plan_33333333333333333333333333333333";
        let root = workspace.execution_path(plan_id).unwrap();
        fs::create_dir(&root).unwrap();
        let sentinel = root.join("do-not-overwrite");
        fs::write(&sentinel, b"owned").unwrap();

        let error = workspace
            .materialize_artifact_execution_input(plan_id, &descriptor)
            .unwrap_err();

        assert!(format!("{error:#}").contains("cannot create new private artifact execution root"));
        assert_eq!(fs::read(sentinel).unwrap(), b"owned");
        assert!(!root.join("input").exists());
    }

    #[test]
    fn artifact_execution_materialization_rolls_back_a_failed_copy() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = Workspace::init(temporary.path()).unwrap();
        let source = temporary.path().join("input.bin");
        fs::write(&source, b"native").unwrap();
        let descriptor = workspace
            .import_artifact(
                &source,
                vec!["handoff_input".to_owned()],
                "application/octet-stream".to_owned(),
                "native_file",
                "byte_for_byte_copy",
            )
            .unwrap();
        let object = workspace.object_path(&descriptor.digest.value).unwrap();
        fs::write(&object, b"forged").unwrap();
        let plan_id = "plan_44444444444444444444444444444444";

        let error = workspace
            .materialize_artifact_execution_input(plan_id, &descriptor)
            .unwrap_err();

        assert!(
            format!("{error:#}")
                .contains("artifact bytes do not match their recorded digest and length")
        );
        assert!(!workspace.execution_path(plan_id).unwrap().exists());
    }

    #[test]
    fn artifact_execution_materialization_rejects_a_hardlinked_cas_object() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = Workspace::init(temporary.path()).unwrap();
        let source = temporary.path().join("input.bin");
        fs::write(&source, b"native").unwrap();
        let descriptor = workspace
            .import_artifact(
                &source,
                vec!["handoff_input".to_owned()],
                "application/octet-stream".to_owned(),
                "native_file",
                "byte_for_byte_copy",
            )
            .unwrap();
        let object = workspace.object_path(&descriptor.digest.value).unwrap();
        let alias = temporary.path().join("external-object-alias");
        fs::hard_link(&object, &alias).unwrap();
        let plan_id = "plan_55555555555555555555555555555555";

        let error = workspace
            .materialize_artifact_execution_input(plan_id, &descriptor)
            .unwrap_err();

        assert!(format!("{error:#}").contains("single-link"));
        assert!(!workspace.execution_path(plan_id).unwrap().exists());
    }
}
