use crate::contracts::{
    ArtifactCapture, ArtifactDescriptor, ArtifactRecord, ArtifactStorage, Digest,
    NativeDeliveryQualificationRecord, PlanPayload, PlanRecord, RunRecord, RuntimeCapsuleRecord,
    SubjectCandidateRecord,
};
use crate::run_validation;
use crate::strict_json;
use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
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
        let root = root
            .canonicalize()
            .with_context(|| format!("cannot resolve workspace root {}", root.display()))?;
        if !root.is_dir() {
            bail!("workspace root is not a directory");
        }
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
            if state.is_dir() {
                let workspace = Self {
                    root: path.to_owned(),
                    state,
                };
                workspace.validate_layout()?;
                workspace.validate_marker()?;
                return Ok(workspace);
            }
            if root.is_some() {
                break;
            }
            cursor = path.parent();
        }
        bail!("no initialized .ewb workspace found; run `ewb init`");
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

    pub fn verify_descriptor(&self, descriptor: &ArtifactDescriptor) -> Result<PathBuf> {
        run_validation::validate_artifact_descriptor(descriptor)?;
        let path = self.object_path(&descriptor.digest.value)?;
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
        read_verified_file(&path, &descriptor.digest.value, descriptor.byte_length)
            .with_context(|| format!("cannot read verified artifact object {}", path.display()))
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
            // Linking a fully synced temp file provides create-new semantics on both
            // Unix and Windows; unlike rename, it cannot replace a concurrent record.
            if let Err(error) = retry_transient(|| fs::hard_link(&temporary, destination)) {
                let _ = retry_transient(|| fs::remove_file(&temporary));
                return Err(error).with_context(|| {
                    format!("cannot atomically create record {}", destination.display())
                });
            }
            retry_transient(|| fs::remove_file(&temporary))?;
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
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || is_reparse(&metadata) {
        bail!("record must be a regular non-link file");
    }
    let bytes = fs::read(path)?;
    let value = strict_json::parse_strict(&bytes)?;
    Ok(serde_json::from_value(value)?)
}

fn ensure_real_dir(path: &Path) -> Result<()> {
    if path.exists() {
        validate_real_dir(path)
    } else {
        if let Err(error) = retry_transient(|| fs::create_dir(path))
            && !path.is_dir()
        {
            return Err(error)
                .with_context(|| format!("cannot create directory {}", path.display()));
        }
        validate_real_dir(path)
    }
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

fn verify_file(path: &Path, expected_digest: &str, expected_length: u64) -> Result<()> {
    let (actual_digest, actual_length) = digest_file(path)?;
    if actual_digest != expected_digest || actual_length != expected_length {
        bail!("artifact bytes do not match their recorded digest and length");
    }
    Ok(())
}

fn read_verified_file(path: &Path, expected_digest: &str, expected_length: u64) -> Result<Vec<u8>> {
    let mut file = open_artifact_read_no_write_share(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || is_reparse(&metadata) {
        bail!("artifact object is not a regular non-link file");
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
    for attempt in 0..25 {
        if destination.is_file() {
            let _ = retry_transient(|| fs::remove_file(temporary));
            return verify_file(destination, expected_digest, expected_length);
        }
        match fs::rename(temporary, destination) {
            Ok(()) => return Ok(()),
            Err(error) if is_transient(&error) && attempt < 24 => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                if destination.is_file() {
                    let _ = retry_transient(|| fs::remove_file(temporary));
                    return verify_file(destination, expected_digest, expected_length);
                }
                let _ = retry_transient(|| fs::remove_file(temporary));
                return Err(error).context("cannot atomically commit artifact object");
            }
        }
    }
    unreachable!("bounded object commit loop always returns")
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
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
