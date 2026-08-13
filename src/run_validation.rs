use crate::contracts::{
    ArtifactDescriptor, InstrumentRun, Limitations, Locator, NativeAuthority, NativeObservation,
    NativeResult, ObservationSource, PlanPayload, Subject, Termination,
};
use crate::manifests::{self, ObservationContract, ToolManifest};
use crate::native;
use crate::strict_json;
use crate::workspace::{self, Workspace};
use anyhow::{Context, Result, bail};
use chrono::DateTime;
use serde_json::Value;
use std::collections::BTreeSet;

const MAX_TIMEOUT_MS: u64 = 3_600_000;

pub fn validate(workspace: &Workspace, run: &InstrumentRun) -> Result<()> {
    if run.schema_version != "instrument_run/v1" {
        bail!("unsupported instrument run schema");
    }
    workspace::validate_prefixed_id(&run.run_id, "run_")?;

    let trusted = manifests::get_by_ref(&run.tool_ref)?;
    let manifest = &trusted.manifest;
    if !manifest.enabled_by_default || manifest.invocation_contract.operation == "catalog_only" {
        bail!("instrument run refers to a catalog-only tool");
    }
    if manifest.identity_contract.python_distribution.is_some() {
        bail!(
            "instrument run uses a Python adapter whose immutable runtime snapshot is not implemented"
        );
    }
    require_windows_execution_boundary(
        "native instrument runs are unsupported until descriptor-based exec is implemented",
    )?;
    if run.adapter.id != manifest.adapter.id || run.adapter.version != manifest.adapter.version {
        bail!("run adapter identity does not match its embedded manifest");
    }

    validate_tool_identity(workspace, &run.resolved_tool_identity, manifest)?;

    validate_nonempty(&run.recorder_identity.version, "recorder version")?;
    validate_sha256(&run.recorder_identity.executable_sha256)?;
    validate_sha256(&run.adapter.implementation_sha256)?;
    if run.adapter.implementation_sha256 != run.recorder_identity.executable_sha256 {
        bail!("adapter implementation is not bound to the recorded recorder bytes");
    }

    validate_subject(workspace, &run.subject, manifest)?;
    validate_parameters(manifest, &run.parameters)?;
    validate_invocation(workspace, run, &trusted)?;
    validate_timestamps(run)?;
    validate_termination(&run.termination, run.invocation.timeout_ms)?;
    validate_artifacts(workspace, run, manifest)?;
    validate_native_result(workspace, run, manifest)?;
    validate_native_authority(&run.native_authority, manifest)?;
    validate_limitations(&run.limitations)?;
    Ok(())
}

pub fn validate_plan(workspace: &Workspace, plan_id: &str, plan: &PlanPayload) -> Result<()> {
    workspace::validate_prefixed_id(plan_id, "plan_")?;
    let trusted = manifests::get_by_ref(&plan.tool_ref)?;
    let manifest = &trusted.manifest;
    if !manifest.enabled_by_default || manifest.invocation_contract.operation == "catalog_only" {
        bail!("plan refers to a catalog-only tool");
    }
    if manifest.identity_contract.python_distribution.is_some() {
        bail!("plan uses a Python adapter whose immutable runtime snapshot is not implemented");
    }
    require_windows_execution_boundary(
        "native execution plans are unsupported until descriptor-based exec is implemented",
    )?;

    if plan.adapter.id != manifest.adapter.id || plan.adapter.version != manifest.adapter.version {
        bail!("plan adapter identity does not match its embedded manifest");
    }
    validate_nonempty(&plan.recorder_identity.version, "recorder version")?;
    validate_sha256(&plan.recorder_identity.executable_sha256)?;
    validate_sha256(&plan.adapter.implementation_sha256)?;
    if plan.adapter.implementation_sha256 != plan.recorder_identity.executable_sha256 {
        bail!("plan adapter implementation is not bound to its recorder bytes");
    }
    validate_tool_identity(workspace, &plan.resolved_tool_identity, manifest)?;
    validate_subject(workspace, &plan.subject, manifest)?;
    let expected_root = workspace.execution_path(plan_id)?;
    match &plan.subject {
        Subject::Git {
            snapshot: Some(snapshot),
            ..
        } if std::path::Path::new(&snapshot.execution_path) == expected_root => {}
        Subject::Artifact { snapshot, .. }
            if std::path::Path::new(&snapshot.execution_path) == expected_root.join("input") => {}
        Subject::SelfFoundation { .. } => {}
        _ => bail!("plan subject snapshot path does not match its plan ID"),
    }
    validate_parameters(manifest, &plan.parameters)?;
    let expected = native::build_invocation(
        &trusted,
        &plan.resolved_tool_identity,
        &plan.subject,
        &plan.parameters,
        workspace,
        plan.invocation.timeout_ms,
    )?;
    if plan.invocation != expected {
        bail!("plan invocation does not match its trusted adapter contract");
    }
    DateTime::parse_from_rfc3339(&plan.created_at)
        .context("plan created_at is not an RFC 3339 timestamp")?;
    Ok(())
}

fn require_windows_execution_boundary(message: &str) -> Result<()> {
    if cfg!(windows) {
        Ok(())
    } else {
        bail!(message.to_owned())
    }
}

fn validate_tool_identity(
    workspace: &Workspace,
    identity: &crate::contracts::BinaryIdentity,
    manifest: &ToolManifest,
) -> Result<()> {
    validate_sha256(&identity.sha256)?;
    if !manifest.identity_contract.allowed_binary_sha256.is_empty()
        && !manifest
            .identity_contract
            .allowed_binary_sha256
            .iter()
            .any(|allowed| allowed == &identity.sha256)
    {
        bail!("resolved tool identity is outside the manifest binary allowlist");
    }
    validate_nonempty(&identity.path, "resolved tool path")?;
    if manifest.identity_contract.python_distribution.is_none() {
        if identity.supporting_files_sha256.is_some() || identity.supporting_file_count != 0 {
            bail!("self-contained native identity cannot claim a supporting Python tree");
        }
    } else if manifest.identity_contract.supporting_tree_digest_required
        && identity.supporting_files_sha256.is_none()
    {
        bail!("tool identity omits its required supporting tree");
    }
    if identity.reported_version.is_some() {
        bail!("reviewable plans do not execute or record a native version probe");
    }
    validate_nonempty(&identity.source_path, "native source provenance path")?;
    let source_path = std::path::Path::new(&identity.source_path);
    let source_name = source_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow::anyhow!("native source provenance has no UTF-8 filename"))?;
    let source_stem = source_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if !manifest
        .identity_contract
        .executable_candidates
        .iter()
        .any(|candidate| candidate == source_name || candidate == source_stem)
    {
        bail!("native source provenance does not name a trusted executable candidate");
    }
    workspace::validate_prefixed_id(&identity.snapshot_artifact_id, "artifact_")?;
    let native_snapshot = workspace.load_artifact(&identity.snapshot_artifact_id)?;
    if native_snapshot.artifact.digest.value != identity.sha256
        || native_snapshot.artifact.byte_length != identity.size_bytes
        || native_snapshot.artifact.roles != ["native_executable_snapshot"]
        || native_snapshot.artifact.media_type != "application/x-executable"
        || native_snapshot.artifact.origin != "native_file"
        || native_snapshot.artifact.capture.mode != "byte_for_byte_copy"
    {
        bail!("native executable snapshot does not match recorded identity");
    }
    let staged_path = std::path::Path::new(&identity.path);
    let extension = staged_path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if matches!(extension.to_ascii_lowercase().as_str(), "cmd" | "bat") {
        bail!("shell-script executable snapshots are not accepted");
    }
    let source_extension = source_path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if !extension.eq_ignore_ascii_case(source_extension) {
        bail!("staged executable extension does not match its source provenance");
    }
    if staged_path != workspace.staged_executable_path(&identity.sha256, extension)? {
        bail!("staged executable path is outside its content-addressed location");
    }
    let (staged_digest, staged_length) = workspace::digest_file(staged_path)?;
    if staged_digest != identity.sha256 || staged_length != identity.size_bytes {
        bail!("staged executable bytes do not match recorded identity");
    }
    Ok(())
}

pub fn validate_artifact_descriptor(descriptor: &ArtifactDescriptor) -> Result<()> {
    workspace::validate_prefixed_id(&descriptor.artifact_id, "artifact_")?;
    if descriptor.roles.is_empty() {
        bail!("artifact must have at least one role");
    }
    let mut roles = BTreeSet::new();
    for role in &descriptor.roles {
        if !valid_identifier(role, 64) || !roles.insert(role.as_str()) {
            bail!("artifact roles must be unique lowercase ASCII identifiers");
        }
    }
    if descriptor.media_type.is_empty() || descriptor.media_type.trim() != descriptor.media_type {
        bail!("artifact media type must be a non-empty trimmed string");
    }
    if descriptor.digest.algorithm != "sha256" || !descriptor.transforms.is_empty() {
        bail!("artifact violates the exact-byte SHA-256 contract");
    }
    validate_sha256(&descriptor.digest.value)?;
    if descriptor.storage.uri != format!("ewb:sha256:{}", descriptor.digest.value) {
        bail!("artifact storage URI does not match its digest");
    }
    match descriptor.origin.as_str() {
        "native_file" if descriptor.capture.mode == "byte_for_byte_copy" => {}
        "process_stdout" | "process_stderr" if descriptor.capture.mode == "raw_stream_capture" => {}
        "native_file" | "process_stdout" | "process_stderr" => {
            bail!("artifact origin and capture mode are inconsistent")
        }
        _ => bail!("artifact origin is outside the v1 contract"),
    }
    if !matches!(
        descriptor.capture.mode.as_str(),
        "byte_for_byte_copy" | "raw_stream_capture"
    ) {
        bail!("artifact capture mode is outside the v1 contract");
    }
    Ok(())
}

fn validate_subject(
    workspace: &Workspace,
    subject: &Subject,
    manifest: &ToolManifest,
) -> Result<()> {
    let kind = match subject {
        Subject::Git {
            repository,
            original_root,
            revisions,
            worktree_state,
            snapshot,
        } => {
            validate_nonempty(repository, "Git repository")?;
            validate_nonempty(original_root, "Git original root")?;
            let snapshot = snapshot
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("run Git subject requires a bundle snapshot"))?;
            workspace::validate_prefixed_id(&snapshot.artifact_id, "artifact_")?;
            validate_sha256(&snapshot.sha256)?;
            validate_nonempty(&snapshot.execution_path, "Git snapshot execution path")?;
            validate_execution_path(workspace, &snapshot.execution_path, false)?;
            if worktree_state != "clean" || revisions.is_empty() {
                bail!("Git subject must be a clean, exactly revised worktree");
            }
            let mut roles = BTreeSet::new();
            for revision in revisions {
                validate_nonempty(&revision.role, "revision role")?;
                if !roles.insert(revision.role.as_str()) {
                    bail!("revision roles must be unique");
                }
                let length = match revision.algorithm.as_str() {
                    "git-sha1" => 40,
                    "git-sha256" => 64,
                    _ => bail!("unsupported Git revision algorithm"),
                };
                validate_lower_hex(&revision.value, length, "Git revision")?;
            }
            crate::git_subject::validate_planned_snapshot(workspace, snapshot, revisions)?;
            "git"
        }
        Subject::Artifact {
            sha256,
            byte_length,
            media_type,
            source_run_id,
            source_artifact_id,
            snapshot,
            ..
        } => {
            if snapshot.tree_artifact_id.is_some()
                || snapshot.tree_sha256.is_some()
                || snapshot.tree_byte_length.is_some()
                || snapshot.tree_file_count.is_some()
                || snapshot.git_plan_tool.is_some()
            {
                bail!("artifact subject cannot contain Git snapshot metadata");
            }
            validate_sha256(sha256)?;
            validate_nonempty(media_type, "artifact subject media type")?;
            workspace::validate_prefixed_id(source_artifact_id, "artifact_")?;
            workspace::validate_prefixed_id(&snapshot.artifact_id, "artifact_")?;
            validate_sha256(&snapshot.sha256)?;
            validate_nonempty(&snapshot.execution_path, "artifact snapshot execution path")?;
            validate_execution_path(workspace, &snapshot.execution_path, true)?;
            if snapshot.artifact_id != *source_artifact_id
                || snapshot.sha256 != *sha256
                || snapshot.byte_length != *byte_length
            {
                bail!("artifact subject snapshot does not match source artifact identity");
            }
            let record = workspace.load_artifact(source_artifact_id)?;
            if record.artifact.digest.value != *sha256
                || record.artifact.byte_length != *byte_length
                || record.artifact.media_type != *media_type
            {
                bail!("artifact subject stored bytes do not match recorded identity");
            }
            if source_run_id.is_some() {
                bail!("instrument_run/v1 does not support asserted artifact run lineage");
            }
            "artifact"
        }
        Subject::SelfFoundation { tool_manifest_id } => {
            if tool_manifest_id != &manifest.manifest_id {
                bail!("self-foundation subject does not name its exact tool manifest");
            }
            "self_foundation"
        }
    };
    if kind != manifest.subject_kind {
        bail!("run subject kind does not match its embedded manifest");
    }
    Ok(())
}

fn validate_execution_path(workspace: &Workspace, value: &str, artifact_input: bool) -> Result<()> {
    let path = std::path::Path::new(value);
    let plan_root = if artifact_input {
        if path.file_name().and_then(|name| name.to_str()) != Some("input") {
            bail!("artifact execution path must end in input");
        }
        path.parent()
            .ok_or_else(|| anyhow::anyhow!("artifact execution path has no plan root"))?
    } else {
        path
    };
    if plan_root.parent() != Some(workspace.state.join("executions").as_path()) {
        bail!("subject execution path is outside the EWB executions directory");
    }
    let plan_id = plan_root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("execution plan id is not UTF-8"))?;
    workspace::validate_prefixed_id(plan_id, "plan_")
}

fn validate_invocation(
    workspace: &Workspace,
    run: &InstrumentRun,
    trusted: &crate::manifests::TrustedManifest,
) -> Result<()> {
    let manifest = &trusted.manifest;
    let invocation = &run.invocation;
    if invocation.mode != "direct_exec" || invocation.argv.is_empty() {
        bail!("run invocation must be non-empty direct_exec");
    }
    if invocation.argv[0] != run.resolved_tool_identity.path {
        bail!("invocation executable does not match the resolved tool identity");
    }
    if invocation
        .argv
        .iter()
        .any(|argument| argument.contains('\0'))
    {
        bail!("invocation arguments cannot contain NUL");
    }
    validate_nonempty(&invocation.cwd, "invocation cwd")?;
    if invocation.timeout_ms == 0 || invocation.timeout_ms > MAX_TIMEOUT_MS {
        bail!("run timeout is outside the v1 range");
    }
    let required: BTreeSet<_> = invocation.required_capabilities.iter().collect();
    if required.len() != invocation.required_capabilities.len()
        || invocation
            .required_capabilities
            .iter()
            .any(|capability| !valid_identifier(capability, 64))
    {
        bail!("required capabilities must be unique lowercase ASCII identifiers");
    }
    let expected: BTreeSet<_> = manifest
        .invocation_contract
        .required_capabilities
        .iter()
        .collect();
    if required != expected {
        bail!("run capabilities do not match the exact embedded manifest");
    }
    let expected = native::build_invocation(
        trusted,
        &run.resolved_tool_identity,
        &run.subject,
        &run.parameters,
        workspace,
        invocation.timeout_ms,
    )?;
    if invocation != &expected {
        bail!("run invocation does not match its trusted adapter contract");
    }
    Ok(())
}

fn validate_parameters(
    manifest: &ToolManifest,
    parameters: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    let supplied = parameters
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>();
    let normalized = manifests::validate_parameters(manifest, &supplied)?;
    if &normalized != parameters {
        bail!("parameters do not match the trusted manifest defaults and constraints");
    }
    Ok(())
}

fn validate_timestamps(run: &InstrumentRun) -> Result<()> {
    let started = DateTime::parse_from_rfc3339(&run.started_at)
        .context("run started_at is not an RFC 3339 timestamp")?;
    let finished = DateTime::parse_from_rfc3339(&run.finished_at)
        .context("run finished_at is not an RFC 3339 timestamp")?;
    if finished < started {
        bail!("run finished before it started");
    }
    Ok(())
}

fn validate_termination(termination: &Termination, invocation_timeout_ms: u64) -> Result<()> {
    match termination {
        Termination::Exited { .. } => {}
        Termination::Signaled { signal } => validate_nonempty(signal, "termination signal")?,
        Termination::TimedOut { timeout_ms } => {
            if *timeout_ms == 0 || *timeout_ms != invocation_timeout_ms {
                bail!("timeout termination does not match the invocation timeout");
            }
        }
        Termination::SpawnError {
            error_code,
            message,
        } => {
            validate_nonempty(error_code, "spawn error code")?;
            validate_nonempty(message, "spawn error message")?;
        }
        Termination::Interrupted { reason } => validate_nonempty(reason, "interruption reason")?,
    }
    Ok(())
}

fn validate_artifacts(
    workspace: &Workspace,
    run: &InstrumentRun,
    manifest: &ToolManifest,
) -> Result<()> {
    let mut ids = BTreeSet::new();
    let mut roles = BTreeSet::new();
    for artifact in &run.artifacts {
        validate_artifact_descriptor(artifact)?;
        let committed = workspace.load_artifact(&artifact.artifact_id)?;
        if committed.artifact != *artifact {
            bail!("run artifact descriptor does not match its committed capture record");
        }
        if !ids.insert(artifact.artifact_id.as_str()) {
            bail!("run artifact IDs must be unique");
        }
        for role in &artifact.roles {
            if !roles.insert(role.as_str()) {
                bail!("a run artifact role must resolve to exactly one artifact");
            }
            let matches: Vec<_> = manifest
                .artifact_contracts
                .iter()
                .filter(|contract| contract.role == *role)
                .collect();
            if matches.len() != 1 {
                bail!("run artifact role is not uniquely declared by its embedded manifest");
            }
            let contract = matches[0];
            if contract.byte_policy != "exact" {
                bail!("run artifact role does not preserve exact bytes");
            }
            match (contract.discovery.as_str(), role.as_str()) {
                ("captured_stream", "native_stdout")
                    if artifact.origin == "process_stdout"
                        && artifact.capture.mode == "raw_stream_capture" => {}
                ("captured_stream", "native_stderr")
                    if artifact.origin == "process_stderr"
                        && artifact.capture.mode == "raw_stream_capture" => {}
                _ => bail!("run artifact role, origin, and capture mode are inconsistent"),
            }
        }
        workspace.verify_descriptor(artifact)?;
    }
    Ok(())
}

fn validate_native_result(
    workspace: &Workspace,
    run: &InstrumentRun,
    manifest: &ToolManifest,
) -> Result<()> {
    match &run.native_result {
        NativeResult::NotReported {
            reason,
            observations,
        } => {
            if !observations.is_empty() {
                bail!("not_reported native result must have no observations");
            }
            if !matches!(
                reason.as_str(),
                "process_not_exited"
                    | "native_result_absent"
                    | "artifact_missing"
                    | "parse_error"
                    | "contract_mismatch"
                    | "unrecognized"
            ) {
                bail!("native result has an unsupported not_reported reason");
            }
        }
        NativeResult::Reported { observations } => {
            if !matches!(run.termination, Termination::Exited { .. }) {
                bail!("native observations cannot be reported for a non-exited process");
            }
            if observations.is_empty()
                || observations.len() != manifest.native_observation_contracts.len()
            {
                bail!("reported native observations do not match the embedded manifest");
            }
            let mut identities = BTreeSet::new();
            for observation in observations {
                if !identities.insert((observation.namespace.as_str(), observation.name.as_str())) {
                    bail!("native observation identities must be unique");
                }
            }
            for contract in &manifest.native_observation_contracts {
                let mut matches = observations.iter().filter(|observation| {
                    observation.namespace == contract.namespace && observation.name == contract.name
                });
                let observation = matches
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("native observation contract is missing"))?;
                if matches.next().is_some() {
                    bail!("native observation contract was reported more than once");
                }
                validate_observation(workspace, run, manifest, contract, observation)?;
            }
        }
    }
    Ok(())
}

fn validate_observation(
    workspace: &Workspace,
    run: &InstrumentRun,
    manifest: &ToolManifest,
    contract: &ObservationContract,
    observation: &NativeObservation,
) -> Result<()> {
    if !observation.projection_only {
        bail!("native observation must remain projection_only");
    }
    let (artifact_id, locator) = match &observation.source {
        ObservationSource::Artifact {
            artifact_id,
            locator,
        } => (artifact_id, locator),
        ObservationSource::ProcessExit { .. } => {
            bail!("process-exit projections are unsupported in instrument_run/v1")
        }
    };

    let artifact_contracts: Vec<_> = manifest
        .artifact_contracts
        .iter()
        .filter(|artifact| artifact.role == contract.artifact_role)
        .collect();
    if artifact_contracts.len() != 1
        || artifact_contracts[0].byte_policy != "exact"
        || artifact_contracts[0].discovery != "captured_stream"
    {
        bail!("native observation is not backed by one exact captured-stream contract");
    }

    let role_artifacts: Vec<_> = run
        .artifacts
        .iter()
        .filter(|artifact| {
            artifact
                .roles
                .iter()
                .any(|role| role == &contract.artifact_role)
        })
        .collect();
    if role_artifacts.len() != 1 || role_artifacts[0].artifact_id != *artifact_id {
        bail!("native observation does not resolve one exact in-run source artifact");
    }
    let artifact = role_artifacts[0];
    match contract.artifact_role.as_str() {
        "native_stdout"
            if artifact.origin == "process_stdout"
                && artifact.capture.mode == "raw_stream_capture" => {}
        "native_stderr"
            if artifact.origin == "process_stderr"
                && artifact.capture.mode == "raw_stream_capture" => {}
        _ => bail!("native observation source role is not backed by its raw process stream"),
    }

    let bytes = workspace
        .read_verified_descriptor(artifact)
        .context("cannot read and verify native artifact bytes")?;
    let (expected_value, expected_locator) = extract(contract, &bytes)?;
    if locator != &expected_locator {
        bail!("native observation locator does not match exact re-extraction");
    }
    if observation.value != expected_value {
        bail!("native observation value does not match exact re-extraction");
    }
    Ok(())
}

fn extract(contract: &ObservationContract, bytes: &[u8]) -> Result<(Value, Locator)> {
    match contract.format.as_str() {
        "json" => {
            let value = strict_json::parse_strict(bytes)?;
            let selected = strict_json::pointer(&value, &contract.selector)?.clone();
            Ok((
                selected,
                Locator {
                    kind: "json_pointer".to_owned(),
                    value: contract.selector.clone(),
                },
            ))
        }
        "text_prefix" => extract_text_prefix(bytes, &contract.selector),
        _ => bail!("unsupported native observation projection format"),
    }
}

fn extract_text_prefix(bytes: &[u8], prefix: &str) -> Result<(Value, Locator)> {
    let text = std::str::from_utf8(bytes).context("native text output is not UTF-8")?;
    let mut offset = 0_usize;
    for line in text.split_inclusive('\n') {
        let body = line.trim_end_matches(['\r', '\n']);
        if let Some(value) = body.strip_prefix(prefix) {
            let leading = body.len() - value.len();
            let trim_start = value.len() - value.trim_start().len();
            let trimmed = value.trim();
            let start = offset + leading + trim_start;
            let end = start + trimmed.len();
            return Ok((
                Value::String(trimmed.to_owned()),
                Locator {
                    kind: "byte_range".to_owned(),
                    value: format!("{start}:{end}"),
                },
            ));
        }
        offset += line.len();
    }
    bail!("native text prefix not found")
}

fn validate_native_authority(authority: &NativeAuthority, manifest: &ToolManifest) -> Result<()> {
    if manifest.authority_contract.mode != "not_reported" {
        bail!("embedded v1 manifest has an unsupported authority contract");
    }
    match authority {
        NativeAuthority::Reported { .. } => {
            bail!("embedded v1 manifests do not authorize native authority claims")
        }
        NativeAuthority::NotReported { reason, claims } => {
            validate_nonempty(reason, "native authority not_reported reason")?;
            if !claims.is_empty() {
                bail!("not_reported native authority must have no claims");
            }
        }
    }
    Ok(())
}

fn validate_limitations(limitations: &Limitations) -> Result<()> {
    let items = match limitations {
        Limitations::Reported { items } if !items.is_empty() => items,
        Limitations::Reported { .. } => bail!("reported limitations must contain an item"),
        Limitations::NotReported { items } if items.is_empty() => return Ok(()),
        Limitations::NotReported { .. } => {
            bail!("not_reported limitations must contain no items")
        }
    };
    let mut identities = BTreeSet::new();
    for item in items {
        validate_nonempty(&item.namespace, "limitation namespace")?;
        validate_nonempty(&item.code, "limitation code")?;
        validate_nonempty(&item.statement, "limitation statement")?;
        validate_nonempty(&item.source, "limitation source")?;
        if !matches!(item.origin.as_str(), "native" | "manifest" | "adapter") {
            bail!("limitation origin is outside the v1 contract");
        }
        if !identities.insert((
            item.namespace.as_str(),
            item.code.as_str(),
            item.source.as_str(),
        )) {
            bail!("limitation identities must be unique");
        }
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<()> {
    validate_lower_hex(value, 64, "SHA-256 digest")
}

fn validate_lower_hex(value: &str, length: usize, label: &str) -> Result<()> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("invalid lowercase {label}");
    }
    Ok(())
}

fn validate_nonempty(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.trim() != value {
        bail!("{label} must be a non-empty trimmed string");
    }
    Ok(())
}

fn valid_identifier(value: &str, max_length: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}
