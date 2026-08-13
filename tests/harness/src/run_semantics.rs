use crate::contracts::{
    AdapterIdentity, BinaryIdentity, InstrumentRun, Invocation, Limitations, Locator,
    NativeAuthority, NativeAuthorityClaim, NativeObservation, NativeResult, ObservationSource,
    PlanPayload, PlanRecord, PlanRecordRef, RecorderIdentity, Revision, Subject, Termination,
    ToolRef,
};
use crate::manifests;
use crate::workspace::{self, Workspace};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use tempfile::TempDir;

fn valid_run(temp: &TempDir) -> (Workspace, InstrumentRun) {
    let workspace = Workspace::init(temp.path()).unwrap();
    let output = temp.path().join("native-stdout.json");
    fs::write(&output, br#"{"status":"inspected"}"#).unwrap();
    let artifact = workspace
        .import_artifact(
            &output,
            vec!["native_stdout".to_owned()],
            "application/json".to_owned(),
            "process_stdout",
            "raw_stream_capture",
        )
        .unwrap();
    let native_source = temp.path().join("ewb-test-native.exe");
    fs::write(&native_source, b"native fixture").unwrap();
    let native_snapshot = workspace
        .import_artifact(
            &native_source,
            vec!["native_executable_snapshot".to_owned()],
            "application/x-executable".to_owned(),
            "native_file",
            "byte_for_byte_copy",
        )
        .unwrap();
    let staged = workspace
        .staged_executable_path(&native_snapshot.digest.value, "exe")
        .unwrap();
    fs::copy(&native_source, &staged).unwrap();
    let bundle_source = temp.path().join("subject.bundle");
    let subject_oid = "55".repeat(20);
    fs::write(
        &bundle_source,
        format!("# v2 git bundle\n{subject_oid} refs/ewb/subject\n\nPACKfixture"),
    )
    .unwrap();
    let bundle = workspace
        .import_artifact(
            &bundle_source,
            vec!["git_subject_bundle".to_owned()],
            "application/vnd.git.bundle".to_owned(),
            "native_file",
            "byte_for_byte_copy",
        )
        .unwrap();
    let tree_content = b"evidence\n";
    let tree_name = b"evidence.txt";
    let mut tree_bytes = b"EWBTREE1\0".to_vec();
    tree_bytes.extend_from_slice(&(tree_name.len() as u32).to_le_bytes());
    tree_bytes.extend_from_slice(tree_name);
    tree_bytes.extend_from_slice(&(tree_content.len() as u64).to_le_bytes());
    tree_bytes.extend_from_slice(tree_content);
    let tree_digest = hex::encode(Sha256::digest(&tree_bytes[9..]));
    let tree_source = temp.path().join("subject.ewbtree");
    fs::write(&tree_source, &tree_bytes).unwrap();
    let tree = workspace
        .import_artifact(
            &tree_source,
            vec!["git_execution_tree".to_owned()],
            "application/vnd.evidence-workbench.tree-v1".to_owned(),
            "native_file",
            "byte_for_byte_copy",
        )
        .unwrap();
    let git_source = temp.path().join("git.exe");
    fs::write(&git_source, b"Git plan launcher fixture").unwrap();
    let (git_launcher, git_staged) = workspace
        .import_git_plan_launcher_snapshot(&git_source)
        .unwrap();
    let manifest = manifests::get("test-execution-boundary").unwrap();
    let recorder_digest = "11".repeat(32);
    let observation = NativeObservation {
        namespace: "ewb_test_fixture".to_owned(),
        name: "native_status".to_owned(),
        value: json!("inspected"),
        source: ObservationSource::Artifact {
            artifact_id: artifact.artifact_id.clone(),
            locator: Locator {
                kind: "json_pointer".to_owned(),
                value: "/status".to_owned(),
            },
        },
        projection_only: true,
    };
    let run = InstrumentRun {
        schema_version: "instrument_run/v1".to_owned(),
        run_id: format!("run_{}", "22".repeat(16)),
        source_plan_ref: PlanRecordRef {
            plan_id: format!("plan_{}", "99".repeat(16)),
            record_digest: "00".repeat(32),
        },
        tool_ref: ToolRef {
            manifest_id: manifest.manifest.manifest_id.clone(),
            manifest_sha256: manifest.sha256,
        },
        upstream_pin_ref: crate::upstream_pins::fixture_ref(),
        native_qualification_ref: None,
        resolved_tool_identity: BinaryIdentity {
            path: staged.display().to_string(),
            sha256: native_snapshot.digest.value.clone(),
            size_bytes: native_snapshot.byte_length,
            supporting_files_sha256: None,
            supporting_file_count: 0,
            reported_version: None,
            source_path: native_source.display().to_string(),
            snapshot_artifact_id: native_snapshot.artifact_id,
        },
        recorder_identity: RecorderIdentity {
            version: "0.1.0".to_owned(),
            executable_sha256: recorder_digest.clone(),
        },
        adapter: AdapterIdentity {
            id: manifest.manifest.adapter.id,
            version: manifest.manifest.adapter.version,
            implementation_sha256: recorder_digest,
        },
        subject: Subject::Git {
            repository: "https://example.invalid/repo.git".to_owned(),
            original_root: "C:\\original\\repo".to_owned(),
            revisions: vec![Revision {
                role: "subject".to_owned(),
                algorithm: "git-sha1".to_owned(),
                value: subject_oid,
            }],
            worktree_state: "clean".to_owned(),
            snapshot: Some(crate::contracts::SubjectSnapshot {
                artifact_id: bundle.artifact_id.clone(),
                sha256: bundle.digest.value.clone(),
                byte_length: bundle.byte_length,
                execution_path: workspace
                    .execution_path(&format!("plan_{}", "99".repeat(16)))
                    .unwrap()
                    .display()
                    .to_string(),
                tree_artifact_id: Some(tree.artifact_id),
                tree_sha256: Some(tree_digest),
                tree_byte_length: Some(tree_content.len() as u64),
                tree_file_count: Some(1),
                git_plan_tool: Some(crate::contracts::GitPlanToolIdentity {
                    source_path: git_source.display().to_string(),
                    source_sha256: git_launcher.digest.value,
                    source_size_bytes: git_launcher.byte_length,
                    snapshot_artifact_id: git_launcher.artifact_id,
                    staged_path: git_staged.display().to_string(),
                    use_scope: "plan_only_locked_source".to_owned(),
                    runtime_closure: "host_installation_not_snapshotted_never_used_at_execute"
                        .to_owned(),
                }),
            }),
        },
        parameters: std::collections::BTreeMap::new(),
        invocation: Invocation {
            mode: "direct_exec".to_owned(),
            argv: vec![
                staged.display().to_string(),
                "--output".to_owned(),
                "json".to_owned(),
                "--offline".to_owned(),
                "--non-interactive".to_owned(),
                "inspect".to_owned(),
                workspace
                    .execution_path(&format!("plan_{}", "99".repeat(16)))
                    .unwrap()
                    .display()
                    .to_string(),
            ],
            cwd: workspace
                .execution_path(&format!("plan_{}", "99".repeat(16)))
                .unwrap()
                .display()
                .to_string(),
            timeout_ms: 30_000,
            required_capabilities: vec!["read_subject".to_owned()],
        },
        started_at: "2026-08-13T12:00:00Z".to_owned(),
        finished_at: "2026-08-13T12:00:01Z".to_owned(),
        termination: Termination::Exited { exit_code: 1 },
        artifacts: vec![artifact],
        native_result: NativeResult::Reported {
            observations: vec![observation],
        },
        native_authority: NativeAuthority::NotReported {
            reason: "native_authority_not_configured".to_owned(),
            claims: Vec::new(),
        },
        limitations: Limitations::NotReported { items: Vec::new() },
    };
    let mut run = run;
    let plan_payload = PlanPayload {
        tool_ref: run.tool_ref.clone(),
        upstream_pin_ref: run.upstream_pin_ref.clone(),
        native_qualification_ref: run.native_qualification_ref.clone(),
        resolved_tool_identity: run.resolved_tool_identity.clone(),
        recorder_identity: run.recorder_identity.clone(),
        adapter: run.adapter.clone(),
        subject: run.subject.clone(),
        invocation: run.invocation.clone(),
        parameters: run.parameters.clone(),
        created_at: "2026-08-13T11:59:00Z".to_owned(),
    };
    let record_digest = workspace::digest_serialized(&plan_payload).unwrap();
    let plan = PlanRecord {
        schema_version: "plan_record/v1".to_owned(),
        plan_id: run.source_plan_ref.plan_id.clone(),
        record_digest: record_digest.clone(),
        payload: plan_payload,
    };
    fs::write(
        workspace
            .state
            .join("plans")
            .join(format!("{}.json", plan.plan_id)),
        serde_json::to_vec_pretty(&plan).unwrap(),
    )
    .unwrap();
    run.source_plan_ref.record_digest = record_digest;
    (workspace, run)
}

fn observation_mut(run: &mut InstrumentRun) -> &mut NativeObservation {
    match &mut run.native_result {
        NativeResult::Reported { observations } => &mut observations[0],
        NativeResult::NotReported { .. } => panic!("fixture must report an observation"),
    }
}

#[test]
fn write_run_rejects_forged_native_authority() {
    let temp = TempDir::new().unwrap();
    let (workspace, mut run) = valid_run(&temp);
    let observation = observation_mut(&mut run).clone();
    run.native_authority = NativeAuthority::Reported {
        claims: vec![NativeAuthorityClaim {
            namespace: "greenwash".to_owned(),
            name: "release_authority".to_owned(),
            value: json!(true),
            scope: "repository".to_owned(),
            source: observation.source,
            projection_only: true,
        }],
    };

    let error = workspace.write_run(run).unwrap_err().to_string();
    assert!(error.contains("do not authorize native authority claims"));
}

#[test]
fn write_run_rejects_forged_observation_value() {
    let temp = TempDir::new().unwrap();
    let (workspace, mut run) = valid_run(&temp);
    observation_mut(&mut run).value = json!("pass");

    let error = workspace.write_run(run).unwrap_err().to_string();
    assert!(error.contains("value does not match exact re-extraction"));
}

#[test]
fn write_run_rejects_forged_locator_and_process_exit_projection() {
    let temp = TempDir::new().unwrap();
    let (workspace, mut run) = valid_run(&temp);
    match &mut observation_mut(&mut run).source {
        ObservationSource::Artifact { locator, .. } => locator.value = "/accepted".to_owned(),
        ObservationSource::ProcessExit { .. } => unreachable!(),
    }
    let error = workspace.write_run(run.clone()).unwrap_err().to_string();
    assert!(error.contains("locator does not match exact re-extraction"));

    observation_mut(&mut run).source = ObservationSource::ProcessExit {
        field: "termination.exit_code".to_owned(),
    };
    let error = workspace.write_run(run).unwrap_err().to_string();
    assert!(error.contains("process-exit projections are unsupported"));
}

#[test]
fn load_run_revalidates_semantics_even_after_digest_is_recomputed() {
    let temp = TempDir::new().unwrap();
    let (workspace, run) = valid_run(&temp);
    let mut record = workspace.write_run(run).unwrap();
    observation_mut(&mut record.run).value = Value::String("pass".to_owned());
    record.record_digest = workspace::digest_serialized(&record.run).unwrap();
    let path = workspace
        .state
        .join("runs")
        .join(format!("{}.json", record.run.run_id));
    fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();

    let error = workspace
        .load_run(&record.run.run_id)
        .unwrap_err()
        .to_string();
    assert!(error.contains("value does not match exact re-extraction"));
}

#[test]
fn write_run_rejects_forged_source_plan_digest() {
    let temp = TempDir::new().unwrap();
    let (workspace, mut run) = valid_run(&temp);
    run.source_plan_ref.record_digest = "ff".repeat(32);
    let error = workspace.write_run(run).unwrap_err().to_string();
    assert!(error.contains("source plan digest"));
}

#[test]
fn write_run_rejects_input_divergence_from_source_plan() {
    let temp = TempDir::new().unwrap();
    let (workspace, mut run) = valid_run(&temp);
    run.recorder_identity.version = "0.1.1".to_owned();
    let error = workspace.write_run(run).unwrap_err().to_string();
    assert!(error.contains("does not inherit its execution inputs"));
}

#[test]
fn load_run_rejects_revision_rewritten_after_record_digest_is_recomputed() {
    let temp = TempDir::new().unwrap();
    let (workspace, run) = valid_run(&temp);
    let mut record = workspace.write_run(run).unwrap();
    match &mut record.run.subject {
        Subject::Git { revisions, .. } => revisions[0].value = "66".repeat(20),
        _ => panic!("fixture must use a Git subject"),
    }
    record.record_digest = workspace::digest_serialized(&record.run).unwrap();
    let path = workspace
        .state
        .join("runs")
        .join(format!("{}.json", record.run.run_id));
    fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();

    let error = workspace
        .load_run(&record.run.run_id)
        .unwrap_err()
        .to_string();
    assert!(error.contains("bundle references do not match recorded exact revisions"));
}

#[test]
fn load_run_rejects_tree_identity_rewritten_after_record_digest_is_recomputed() {
    let temp = TempDir::new().unwrap();
    let (workspace, run) = valid_run(&temp);
    let mut record = workspace.write_run(run).unwrap();
    match &mut record.run.subject {
        Subject::Git {
            snapshot: Some(snapshot),
            ..
        } => snapshot.tree_sha256 = Some("ff".repeat(32)),
        _ => panic!("fixture must use a snapshotted Git subject"),
    }
    record.record_digest = workspace::digest_serialized(&record.run).unwrap();
    let path = workspace
        .state
        .join("runs")
        .join(format!("{}.json", record.run.run_id));
    fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();

    let error = workspace
        .load_run(&record.run.run_id)
        .unwrap_err()
        .to_string();
    assert!(error.contains("execution-tree artifact does not match recorded identity"));
}

#[test]
fn write_run_rebinds_tool_reference_to_the_embedded_manifest() {
    let temp = TempDir::new().unwrap();
    let (workspace, mut run) = valid_run(&temp);
    run.tool_ref.manifest_sha256 = "ff".repeat(32);

    let error = workspace.write_run(run).unwrap_err().to_string();
    assert!(error.contains("exact embedded manifest"));
}
