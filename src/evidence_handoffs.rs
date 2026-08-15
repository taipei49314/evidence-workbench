use crate::contracts::{
    ArtifactRecord, ArtifactRecordRef, ContractAuthorityEffect, EvidenceConsumerTreatment,
    EvidenceHandoff, EvidenceHandoffRecord, EvidenceHandoffRelationship, PlanRecordRef, RunRecord,
    RunRecordRef,
};
use crate::{data_contract_validation, workspace};
use anyhow::{Result, bail};
use chrono::{SecondsFormat, Utc};

pub fn create(
    workspace: &workspace::Workspace,
    source_run_id: &str,
    source_run_digest: &str,
    artifact_id: &str,
) -> Result<EvidenceHandoffRecord> {
    workspace::validate_sha256(source_run_digest)?;
    let run = workspace.load_run(source_run_id)?;
    if run.record_digest != source_run_digest {
        bail!("source run digest does not match the retained producer run record");
    }
    let artifact = verify_run_artifact(workspace, &run, artifact_id)?;

    let handoff = EvidenceHandoff {
        schema_version: "evidence-handoff/v1".to_owned(),
        handoff_id: workspace::new_handoff_id(),
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        producer_plan_ref: run.run.source_plan_ref.clone(),
        producer_run_ref: RunRecordRef {
            run_id: run.run.run_id.clone(),
            record_digest: run.record_digest,
        },
        artifact_ref: ArtifactRecordRef {
            artifact_id: artifact.artifact.artifact_id,
            record_digest: artifact.record_digest,
        },
        relationship: EvidenceHandoffRelationship::CapturedRunArtifact,
        consumer_treatment: EvidenceConsumerTreatment::UntrustedExactBytes,
        authority_effect: ContractAuthorityEffect::None,
    };
    let record = EvidenceHandoffRecord {
        schema_version: "evidence_handoff_record/v1".to_owned(),
        record_digest: workspace::digest_serialized(&handoff)?,
        handoff,
    };
    verify_record_lineage(workspace, &record)?;
    let handoff_id = record.handoff.handoff_id.clone();
    workspace.write_evidence_handoff(&record)?;
    load_verified(workspace, &handoff_id)
}

pub fn list_verified(workspace: &workspace::Workspace) -> Result<Vec<EvidenceHandoffRecord>> {
    workspace
        .evidence_handoff_ids()?
        .into_iter()
        .map(|handoff_id| load_verified(workspace, &handoff_id))
        .collect()
}

pub fn load_verified(
    workspace: &workspace::Workspace,
    handoff_id: &str,
) -> Result<EvidenceHandoffRecord> {
    let record = workspace.load_evidence_handoff(handoff_id)?;
    verify_record_lineage(workspace, &record)?;
    Ok(record)
}

pub fn verify(
    workspace: &workspace::Workspace,
    handoff_id: &str,
    handoff_digest: &str,
) -> Result<EvidenceHandoffRecord> {
    workspace::validate_sha256(handoff_digest)?;
    let record = workspace.load_evidence_handoff(handoff_id)?;
    if record.record_digest != handoff_digest {
        bail!("handoff digest does not match the retained handoff record");
    }
    verify_record_lineage(workspace, &record)?;
    Ok(record)
}

fn verify_record_lineage(
    workspace: &workspace::Workspace,
    record: &EvidenceHandoffRecord,
) -> Result<()> {
    data_contract_validation::validate_evidence_handoff(&record.handoff)?;

    let run = workspace.load_run(&record.handoff.producer_run_ref.run_id)?;
    if run.record_digest != record.handoff.producer_run_ref.record_digest {
        bail!("producer run record digest does not match the evidence handoff");
    }
    if run.run.source_plan_ref != record.handoff.producer_plan_ref {
        bail!("producer run source plan does not match the evidence handoff");
    }

    let plan = workspace.load_plan_verified(&record.handoff.producer_plan_ref.plan_id)?;
    let actual_plan_ref = PlanRecordRef {
        plan_id: plan.plan_id,
        record_digest: plan.record_digest,
    };
    if actual_plan_ref != record.handoff.producer_plan_ref {
        bail!("producer plan record does not match the evidence handoff");
    }

    let artifact = verify_run_artifact(workspace, &run, &record.handoff.artifact_ref.artifact_id)?;
    if artifact.record_digest != record.handoff.artifact_ref.record_digest {
        bail!("artifact record digest does not match the evidence handoff");
    }
    Ok(())
}

fn verify_run_artifact(
    workspace: &workspace::Workspace,
    run: &RunRecord,
    artifact_id: &str,
) -> Result<ArtifactRecord> {
    let artifact = workspace.load_artifact(artifact_id)?;
    let mut matches = run
        .run
        .artifacts
        .iter()
        .filter(|descriptor| descriptor.artifact_id == artifact_id);
    let captured = matches
        .next()
        .ok_or_else(|| anyhow::anyhow!("artifact is not captured by the producer run"))?;
    if matches.next().is_some() {
        bail!("artifact must appear exactly once in the producer run");
    }
    if captured != &artifact.artifact {
        bail!("producer run artifact descriptor does not match the artifact record");
    }
    Ok(artifact)
}
