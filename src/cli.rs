use crate::contracts::{
    ArtifactDescriptor, PlanPayload, PlanRecordRef, Subject, ToolRef, UpstreamPinRef,
};
use crate::{
    candidate_pins, git_subject, manifests, native, native_qualifications, runtime_capsules,
    subject_candidates, upstream_pins, workspace,
};
use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(
    name = "ewb",
    version,
    about = "Authority-preserving evidence workbench"
)]
pub struct Cli {
    /// Emit one stable JSON value on stdout.
    #[arg(long, global = true)]
    pub json: bool,

    /// Workspace root containing .ewb. Commands otherwise search upward.
    #[arg(long, global = true, value_name = "PATH")]
    pub workspace: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Initialize an evidence workspace without modifying any target repository.
    Init,
    /// Report workspace health, trusted adapters, and missing native tools.
    Doctor,
    /// Resolve immutable subjects.
    Subjects(SubjectsCommand),
    /// Inspect and probe embedded trusted tool manifests.
    Tools(ToolsCommand),
    /// Admit and verify exact-byte runtime capsules in the workspace registry.
    Capsules(CapsulesCommand),
    /// Admit durable native-delivery qualification evidence from exact local bytes.
    Qualifications(QualificationsCommand),
    /// Import and inspect untrusted exact-byte GitHub discovery candidates.
    Candidates(CandidatesCommand),
    /// Plan, execute, and inspect authority-preserving runs.
    Runs(RunsCommand),
    /// Import and verify exact-byte artifacts.
    Artifacts(ArtifactsCommand),
}

#[derive(Debug, Args)]
pub struct SubjectsCommand {
    #[command(subcommand)]
    pub command: SubjectsSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum SubjectsSubcommand {
    /// Resolve a clean Git worktree to its exact commit object.
    Resolve {
        #[arg(long, value_name = "PATH")]
        path: PathBuf,
    },
}

#[derive(Debug, Args)]
pub struct ToolsCommand {
    #[command(subcommand)]
    pub command: ToolsSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ToolsSubcommand {
    /// List all embedded trusted adapters, including disabled catalog entries.
    List,
    /// Show one exact embedded manifest and any separately pinned upstream candidate.
    Show { id: String },
    /// Probe an executable directly. Omit ID to probe enabled adapters.
    Probe { id: Option<String> },
}

#[derive(Debug, Args)]
pub struct CapsulesCommand {
    #[command(subcommand)]
    pub command: CapsulesSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum CapsulesSubcommand {
    /// Import an explicit local descriptor and its exact closed runtime tree.
    Admit {
        #[arg(long, value_name = "FILE")]
        descriptor: PathBuf,
        #[arg(long, value_name = "DIRECTORY")]
        root: PathBuf,
    },
    /// List verified capsules in this workspace's trusted registry.
    List,
    /// Show and re-verify one complete capsule record.
    Show { capsule_id: String },
    /// Re-hash the descriptor, launcher, support tree, and qualification evidence.
    Verify { capsule_id: String },
    /// Inventory a closed root into a fail-closed runtime-capsule/v1 file.
    /// Does not admit the capsule, does not plan, and never reports ready.
    Snapshot {
        #[arg(long, value_name = "DIRECTORY")]
        root: PathBuf,
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        #[arg(long)]
        tool: String,
        #[arg(long)]
        operation: String,
        #[arg(long)]
        launcher: Option<String>,
        #[arg(long, default_value = "host-cpython")]
        abi: String,
    },
}

#[derive(Debug, Args)]
pub struct CandidatesCommand {
    #[command(subcommand)]
    pub command: CandidatesSubcommand,
}

#[derive(Debug, Args)]
pub struct QualificationsCommand {
    #[command(subcommand)]
    pub command: QualificationsSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum QualificationsSubcommand {
    /// Import a strict descriptor and all named evidence into the local CAS.
    Admit {
        #[arg(long, value_name = "FILE")]
        descriptor: PathBuf,
        #[arg(long, value_name = "DIRECTORY")]
        root: PathBuf,
    },
    /// Show and re-verify one complete qualification record.
    Show { qualification_id: String },
    /// Re-hash every durable CAS reference and all semantic bindings.
    Verify { qualification_id: String },
}

#[derive(Debug, Subcommand)]
pub enum CandidatesSubcommand {
    /// Import exact subject-candidate/v1 bytes bound to an existing source artifact.
    Import {
        #[arg(long, value_name = "FILE")]
        file: PathBuf,
    },
    /// List and re-verify every untrusted candidate in this workspace.
    List,
    /// Show one complete candidate record after re-verification.
    Show { candidate_id: String },
    /// Re-hash the candidate bytes, source artifact, and registry record.
    Verify { candidate_id: String },
}

#[derive(Debug, Args)]
pub struct RunsCommand {
    #[command(subcommand)]
    pub command: RunsSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum RunsSubcommand {
    /// Create a reviewable immutable plan. This never launches the native tool.
    Plan {
        #[arg(long)]
        tool: String,
        /// Clean Git subject for git-scoped adapters.
        #[arg(long, value_name = "PATH")]
        subject: Option<PathBuf>,
        /// Exact input artifact for artifact-scoped adapters.
        #[arg(long, value_name = "FILE")]
        input: Option<PathBuf>,
        #[arg(long, default_value = "application/json")]
        input_media_type: String,
        /// Adapter parameter in NAME=VALUE form. Only manifest-declared names are accepted.
        #[arg(long = "param", value_name = "NAME=VALUE")]
        parameters: Vec<String>,
        #[arg(long, default_value_t = 300_000)]
        timeout_ms: u64,
        /// Exact capsule already admitted to this workspace. Python planning still fails closed
        /// until OS-enforced execution containment is implemented.
        #[arg(long, value_name = "CAPSULE_ID")]
        runtime_capsule: Option<String>,
        /// Durable local native-delivery qualification required by qualified native operations.
        #[arg(long, value_name = "QUALIFICATION_ID")]
        runtime_qualification: Option<String>,
    },
    /// Execute a previously reviewed plan after explicit capability approval.
    Execute {
        #[arg(long)]
        plan: String,
        /// Exact digest returned by `runs plan`; binds execution to the reviewed bytes.
        #[arg(long)]
        plan_digest: String,
        /// Approve exactly one manifest-required capability. Repeat as needed.
        #[arg(long = "allow")]
        allowed: Vec<String>,
    },
    /// List committed runs. Corrupt committed records fail closed.
    List,
    /// Show and re-verify a committed run and all referenced artifact bytes.
    Show { run_id: String },
}

#[derive(Debug, Args)]
pub struct ArtifactsCommand {
    #[command(subcommand)]
    pub command: ArtifactsSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ArtifactsSubcommand {
    /// Import exact bytes into the content-addressed store.
    Add {
        #[arg(long, value_name = "FILE")]
        file: PathBuf,
        #[arg(long)]
        role: String,
        #[arg(long, default_value = "application/octet-stream")]
        media_type: String,
    },
    /// Recompute an artifact's length and SHA-256 from stored bytes.
    Verify { artifact_id: String },
}

#[derive(Debug)]
pub struct CommandOutcome {
    pub command: &'static str,
    pub data: Value,
    pub exit_code: i32,
}

pub fn dispatch(cli: &Cli) -> Result<CommandOutcome> {
    match &cli.command {
        Command::Init => init(cli),
        Command::Doctor => doctor(cli),
        Command::Subjects(command) => subjects(command),
        Command::Tools(command) => tools(command),
        Command::Capsules(command) => capsules(cli, command),
        Command::Qualifications(command) => qualifications(cli, command),
        Command::Candidates(command) => candidates(cli, command),
        Command::Runs(command) => runs(cli, command),
        Command::Artifacts(command) => artifacts(cli, command),
    }
}

fn init(cli: &Cli) -> Result<CommandOutcome> {
    let root = requested_path(cli)?;
    let workspace = workspace::Workspace::init(&root)?;
    let candidate_pins = candidate_pins::all()?;
    let upstream_pins = upstream_pins::all()?;
    let manifests = manifests::all()?
        .into_iter()
        .map(|entry| {
            let candidate = candidate_pins
                .iter()
                .find(|pin| pin.pin.tool_manifest_id == entry.manifest.manifest_id)
                .map(candidate_pins::summary);
            let upstream = upstream_pins
                .iter()
                .find(|pin| pin.pin.tool_manifest_id == entry.manifest.manifest_id)
                .map(upstream_pins::summary);
            json!({
                "manifest_id": entry.manifest.manifest_id,
                "sha256": entry.sha256,
                "adapter_implemented": manifests::adapter_implemented(&entry.manifest),
                "planning_supported": entry.manifest.enabled_by_default
                    && entry.manifest.identity_contract.python_distribution.is_none()
                    && cfg!(windows),
                "upstream_candidate": candidate,
                "upstream_pin": upstream
            })
        })
        .collect::<Vec<_>>();
    success(
        "init",
        json!({
            "root": workspace.root,
            "state_directory": workspace.state,
            "authority_policy": "native_only_no_aggregate_verdict",
            "trusted_embedded_manifests": manifests
        }),
    )
}

fn doctor(cli: &Cli) -> Result<CommandOutcome> {
    let requested_root = requested_root(cli)?;
    let root = workspace::Workspace::find_root(cli.workspace.as_deref())?.unwrap_or(requested_root);
    let initialized = workspace::Workspace::is_initialized(&root);
    let workspace_check = if initialized {
        match workspace::Workspace::open(Some(&root)) {
            Ok(_) => json!({"healthy": true, "error": null}),
            Err(error) => json!({"healthy": false, "error": error.to_string()}),
        }
    } else {
        json!({"healthy": false, "error": "not_initialized"})
    };
    let probes = manifests::all()?
        .into_iter()
        .filter(|entry| {
            entry.manifest.enabled_by_default && entry.manifest.manifest_id != "tomorrowci-lab"
        })
        .map(|entry| native::inspect(&entry))
        .collect::<Vec<_>>();
    let candidate_pins = candidate_pins::all()?
        .iter()
        .map(candidate_pins::summary)
        .collect::<Vec<_>>();
    let upstream_pins = upstream_pins::all()?
        .iter()
        .map(upstream_pins::summary)
        .collect::<Vec<_>>();
    success(
        "doctor",
        json!({
            "workspace_root": root,
            "initialized": initialized,
            "workspace_check": workspace_check,
            "native_tools": probes,
            "upstream_candidates": candidate_pins,
            "upstream_deliveries": upstream_pins,
            "trust_model": {
                "manifest_source": "embedded_trusted_only",
                "candidate_pin_source": "embedded_trusted_only",
                "upstream_pin_source": "embedded_trusted_only",
                "aggregate_verdict": false,
                "os_sandbox_claimed": false,
                "dirty_git_subjects_accepted": false
            }
        }),
    )
}

fn subjects(command: &SubjectsCommand) -> Result<CommandOutcome> {
    match &command.command {
        SubjectsSubcommand::Resolve { path } => success(
            "subjects.resolve",
            serde_json::to_value(git_subject::resolve(path)?)?,
        ),
    }
}

fn tools(command: &ToolsCommand) -> Result<CommandOutcome> {
    match &command.command {
        ToolsSubcommand::List => {
            let candidate_pins = candidate_pins::all()?;
            let upstream_pins = upstream_pins::all()?;
            let values = manifests::all()?
                .into_iter()
                .map(|entry| {
                    let candidate = candidate_pins
                        .iter()
                        .find(|pin| pin.pin.tool_manifest_id == entry.manifest.manifest_id)
                        .map(candidate_pins::summary);
                    let upstream = upstream_pins
                        .iter()
                        .find(|pin| pin.pin.tool_manifest_id == entry.manifest.manifest_id)
                        .map(upstream_pins::summary);
                    json!({
                        "manifest_id": entry.manifest.manifest_id,
                        "display_name": entry.manifest.display_name,
                        "stability": entry.manifest.stability,
                        "adapter_implemented": manifests::adapter_implemented(&entry.manifest),
                        "planning_supported": entry.manifest.enabled_by_default
                            && entry.manifest.identity_contract.python_distribution.is_none()
                            && cfg!(windows),
                        "subject_kind": entry.manifest.subject_kind,
                        "required_capabilities": entry.manifest.invocation_contract.required_capabilities,
                        "manifest_sha256": entry.sha256,
                        "upstream_candidate": candidate,
                        "upstream_pin": upstream
                    })
                })
                .collect::<Vec<_>>();
            success("tools.list", json!(values))
        }
        ToolsSubcommand::Show { id } => {
            let entry = manifests::get(id)?;
            let candidate = candidate_pins::get_for_tool(id)?;
            let upstream = upstream_pins::all()?
                .into_iter()
                .find(|pin| pin.pin.tool_manifest_id == *id);
            success(
                "tools.show",
                json!({
                    "manifest_sha256": entry.sha256,
                    "manifest": entry.manifest,
                    "candidate_pin_sha256": candidate.as_ref().map(|pin| pin.sha256.as_str()),
                    "candidate_pin": candidate.as_ref().map(|pin| &pin.pin),
                    "candidate_summary": candidate.as_ref().map(candidate_pins::summary)
                    ,"upstream_pin_sha256": upstream.as_ref().map(|pin| pin.sha256.as_str())
                    ,"upstream_pin": upstream.as_ref().map(|pin| &pin.pin)
                    ,"upstream_summary": upstream.as_ref().map(upstream_pins::summary)
                }),
            )
        }
        ToolsSubcommand::Probe { id } => {
            let entries = match id {
                Some(id) => {
                    let entry = manifests::get(id)?;
                    if !entry.manifest.enabled_by_default {
                        bail!("tool execution readiness is fail_closed; native probe is disabled");
                    }
                    if entry.manifest.manifest_id == "tomorrowci-lab" {
                        bail!(
                            "TomorrowCI is qualification-gated; tools probe cannot resolve PATH or execute outside a bound reviewed plan"
                        );
                    }
                    vec![entry]
                }
                None => manifests::all()?
                    .into_iter()
                    .filter(|entry| {
                        entry.manifest.enabled_by_default
                            && entry.manifest.manifest_id != "tomorrowci-lab"
                    })
                    .collect(),
            };
            let probes = entries.iter().map(native::probe).collect::<Vec<_>>();
            success("tools.probe", json!(probes))
        }
    }
}

fn capsules(cli: &Cli, command: &CapsulesCommand) -> Result<CommandOutcome> {
    if let CapsulesSubcommand::Snapshot {
        root,
        out,
        tool,
        operation,
        launcher,
        abi,
    } = &command.command
    {
        let capsule =
            runtime_capsules::snapshot_descriptor(root, launcher.as_deref(), tool, operation, abi)?;
        if let Some(parent) = out.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            fs::create_dir_all(parent).context("cannot create snapshot output directory")?;
        }
        fs::write(out, serde_json::to_vec_pretty(&capsule)?)
            .context("cannot write runtime capsule snapshot")?;
        return success("capsules.snapshot", serde_json::to_value(capsule)?);
    }

    let workspace = open_workspace(cli)?;
    match &command.command {
        CapsulesSubcommand::Admit { descriptor, root } => success(
            "capsules.admit",
            serde_json::to_value(runtime_capsules::admit(&workspace, descriptor, root)?)?,
        ),
        CapsulesSubcommand::List => success(
            "capsules.list",
            serde_json::to_value(runtime_capsules::list_verified(&workspace)?)?,
        ),
        CapsulesSubcommand::Show { capsule_id } => success(
            "capsules.show",
            serde_json::to_value(runtime_capsules::load_verified(&workspace, capsule_id)?)?,
        ),
        CapsulesSubcommand::Verify { capsule_id } => success(
            "capsules.verify",
            serde_json::to_value(runtime_capsules::verify(&workspace, capsule_id)?)?,
        ),
        CapsulesSubcommand::Snapshot { .. } => {
            unreachable!("snapshot handled before workspace open")
        }
    }
}

fn qualifications(cli: &Cli, command: &QualificationsCommand) -> Result<CommandOutcome> {
    let workspace = open_workspace(cli)?;
    match &command.command {
        QualificationsSubcommand::Admit { descriptor, root } => success(
            "qualifications.admit",
            native_qualifications::admit(&workspace, descriptor, root)?,
        ),
        QualificationsSubcommand::Show { qualification_id } => success(
            "qualifications.show",
            native_qualifications::load_verified(&workspace, qualification_id)?,
        ),
        QualificationsSubcommand::Verify { qualification_id } => success(
            "qualifications.verify",
            native_qualifications::verify(&workspace, qualification_id)?,
        ),
    }
}

fn candidates(cli: &Cli, command: &CandidatesCommand) -> Result<CommandOutcome> {
    let workspace = open_workspace(cli)?;
    match &command.command {
        CandidatesSubcommand::Import { file } => success(
            "candidates.import",
            serde_json::to_value(subject_candidates::import(&workspace, file)?)?,
        ),
        CandidatesSubcommand::List => success(
            "candidates.list",
            serde_json::to_value(subject_candidates::list_verified(&workspace)?)?,
        ),
        CandidatesSubcommand::Show { candidate_id } => success(
            "candidates.show",
            serde_json::to_value(subject_candidates::load_verified(&workspace, candidate_id)?)?,
        ),
        CandidatesSubcommand::Verify { candidate_id } => success(
            "candidates.verify",
            serde_json::to_value(subject_candidates::verify(&workspace, candidate_id)?)?,
        ),
    }
}

fn runs(cli: &Cli, command: &RunsCommand) -> Result<CommandOutcome> {
    let workspace = open_workspace(cli)?;
    match &command.command {
        RunsSubcommand::Plan {
            tool,
            subject,
            input,
            input_media_type,
            parameters,
            timeout_ms,
            runtime_capsule,
            runtime_qualification,
        } => {
            let manifest = manifests::get(tool)?;
            if manifest.manifest.manifest_id == "phaseledger"
                && manifest
                    .manifest
                    .identity_contract
                    .python_distribution
                    .is_some()
            {
                runtime_capsules::planning_blocker(
                    &workspace,
                    runtime_capsule.as_deref(),
                    &manifest.manifest.manifest_id,
                    &manifest.manifest.invocation_contract.operation,
                )?;
                unreachable!("Python planning blocker always fails closed");
            }
            if runtime_capsule.is_some() {
                bail!(
                    "--runtime-capsule planning inspection is currently restricted to phaseledger"
                );
            }
            if !manifest.manifest.enabled_by_default {
                bail!("tool is cataloged but its execution adapter is disabled in this MVP");
            }
            let upstream =
                upstream_pins::require_ready_for_planning(&manifest.manifest.manifest_id)?;
            let parameters = manifests::validate_parameters(&manifest.manifest, parameters)?;
            let plan_id = workspace::new_plan_id();
            let native_qualification_ref = native_qualifications::bind_for_plan(
                &workspace,
                runtime_qualification.as_deref(),
                &manifest.manifest.manifest_id,
                &manifest.manifest.invocation_contract.operation,
            )?;
            // Fail closed on an unsnapshottable runtime before creating subject artifacts.
            let identity = if let Some(reference) = &native_qualification_ref {
                let qualification =
                    native_qualifications::load_verified(&workspace, &reference.qualification_id)?;
                native::snapshot_qualified_tool_identity(
                    &workspace,
                    &manifest.manifest,
                    &qualification,
                    &plan_id,
                )?
            } else {
                native::snapshot_tool_identity(&workspace, &manifest.manifest)?
            };
            let planned_git = if manifest.manifest.subject_kind == "git" {
                Some(git_subject::snapshot_plan_tool(&workspace)?)
            } else {
                None
            };
            let subject = resolve_plan_subject(
                &workspace,
                &plan_id,
                &manifest.manifest.subject_kind,
                &manifest.manifest.manifest_id,
                subject.as_deref(),
                input.as_deref(),
                input_media_type,
                parameters.get("base_revision").map(String::as_str),
                planned_git.as_ref(),
            )?;
            // A plan snapshots but never launches the native executable, including its version probe.
            let recorder = native::recorder_identity()?;
            let adapter = native::adapter_identity(&manifest, &recorder);
            let invocation = native::build_invocation(
                &manifest,
                &identity,
                &subject,
                &parameters,
                &workspace,
                *timeout_ms,
            )?;
            let payload = PlanPayload {
                tool_ref: ToolRef {
                    manifest_id: manifest.manifest.manifest_id.clone(),
                    manifest_sha256: manifest.sha256,
                },
                upstream_pin_ref: UpstreamPinRef {
                    tool_manifest_id: upstream.pin.tool_manifest_id,
                    pin_sha256: upstream.sha256,
                },
                native_qualification_ref,
                resolved_tool_identity: identity,
                recorder_identity: recorder,
                adapter,
                subject,
                invocation,
                parameters,
                created_at: now(),
            };
            let plan = workspace.write_plan(&plan_id, payload)?;
            success("runs.plan", serde_json::to_value(plan)?)
        }
        RunsSubcommand::Execute {
            plan,
            plan_digest,
            allowed,
        } => {
            let plan = workspace.load_plan(plan)?;
            workspace::validate_sha256(plan_digest)?;
            if plan.record_digest != *plan_digest {
                bail!("plan digest does not match the reviewed plan bytes");
            }
            crate::run_validation::validate_plan(&workspace, &plan.plan_id, &plan.payload)?;
            let _execution_lock = workspace.acquire_plan_lock(&plan.plan_id)?;
            let manifest = manifests::get(&plan.payload.tool_ref.manifest_id)?;
            if manifest.sha256 != plan.payload.tool_ref.manifest_sha256 {
                bail!("trusted manifest changed after planning");
            }
            let recorder = native::recorder_identity()?;
            if recorder != plan.payload.recorder_identity {
                bail!("recorder or adapter implementation changed after planning");
            }
            let adapter = native::adapter_identity(&manifest, &recorder);
            if adapter != plan.payload.adapter {
                bail!("adapter identity changed after planning");
            }
            let identity = plan.payload.resolved_tool_identity.clone();
            let subject = plan.payload.subject.clone();
            let invocation = native::build_invocation(
                &manifest,
                &identity,
                &subject,
                &plan.payload.parameters,
                &workspace,
                plan.payload.invocation.timeout_ms,
            )?;
            if invocation != plan.payload.invocation {
                bail!("adapter invocation changed after planning");
            }
            native::validate_capability_approval(&invocation, allowed)?;
            let run = native::execute(
                &workspace,
                &manifest,
                native::ExecutionRequest {
                    run_id: workspace::new_run_id(),
                    source_plan_ref: PlanRecordRef {
                        plan_id: plan.plan_id.clone(),
                        record_digest: plan.record_digest.clone(),
                    },
                    tool_ref: plan.payload.tool_ref,
                    upstream_pin_ref: plan.payload.upstream_pin_ref,
                    native_qualification_ref: plan.payload.native_qualification_ref,
                    identity,
                    recorder,
                    adapter,
                    subject,
                    parameters: plan.payload.parameters,
                    invocation,
                },
            )?;
            let wrapper_exit = if matches!(
                run.termination,
                crate::contracts::Termination::Exited { .. }
            ) {
                0
            } else {
                4
            };
            let record = workspace.write_run(run)?;
            Ok(CommandOutcome {
                command: "runs.execute",
                data: serde_json::to_value(record)?,
                exit_code: wrapper_exit,
            })
        }
        RunsSubcommand::List => success("runs.list", serde_json::to_value(workspace.list_runs()?)?),
        RunsSubcommand::Show { run_id } => success(
            "runs.show",
            serde_json::to_value(workspace.load_run(run_id)?)?,
        ),
    }
}

fn artifacts(cli: &Cli, command: &ArtifactsCommand) -> Result<CommandOutcome> {
    let workspace = open_workspace(cli)?;
    match &command.command {
        ArtifactsSubcommand::Add {
            file,
            role,
            media_type,
        } => {
            validate_role(role)?;
            let descriptor = workspace.import_artifact(
                file,
                vec![role.clone()],
                media_type.clone(),
                "native_file",
                "byte_for_byte_copy",
            )?;
            success("artifacts.add", serde_json::to_value(descriptor)?)
        }
        ArtifactsSubcommand::Verify { artifact_id } => {
            let record = workspace.load_artifact(artifact_id)?;
            success(
                "artifacts.verify",
                json!({
                    "artifact_id": artifact_id,
                    "verified": true,
                    "digest": record.artifact.digest,
                    "byte_length": record.artifact.byte_length
                }),
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_plan_subject(
    workspace: &workspace::Workspace,
    plan_id: &str,
    subject_kind: &str,
    manifest_id: &str,
    subject: Option<&Path>,
    input: Option<&Path>,
    input_media_type: &str,
    base_revision: Option<&str>,
    planned_git: Option<&git_subject::PlannedGit>,
) -> Result<Subject> {
    match subject_kind {
        "git" => {
            if input.is_some() {
                bail!("git-scoped adapter does not accept --input");
            }
            let path = subject.ok_or_else(|| anyhow::anyhow!("--subject is required"))?;
            git_subject::snapshot(
                path,
                base_revision,
                workspace,
                plan_id,
                planned_git.ok_or_else(|| anyhow::anyhow!("Git plan tool was not prepared"))?,
            )
        }
        "artifact" => {
            if subject.is_some() {
                bail!("artifact-scoped adapter does not accept --subject");
            }
            let file = input.ok_or_else(|| anyhow::anyhow!("--input is required"))?;
            let artifact = workspace.import_artifact(
                file,
                vec!["handoff_input".to_owned()],
                input_media_type.to_owned(),
                "native_file",
                "byte_for_byte_copy",
            )?;
            Ok(artifact_subject(
                &artifact,
                workspace
                    .execution_path(plan_id)?
                    .join("input")
                    .display()
                    .to_string(),
            ))
        }
        "self_foundation" => {
            if subject.is_some() || input.is_some() {
                bail!("self-foundation adapter accepts neither --subject nor --input");
            }
            Ok(Subject::SelfFoundation {
                tool_manifest_id: manifest_id.to_owned(),
            })
        }
        other => bail!("unsupported manifest subject kind: {other}"),
    }
}

fn artifact_subject(artifact: &ArtifactDescriptor, execution_path: String) -> Subject {
    Subject::Artifact {
        sha256: artifact.digest.value.clone(),
        byte_length: artifact.byte_length,
        media_type: artifact.media_type.clone(),
        source_run_id: None,
        source_artifact_id: artifact.artifact_id.clone(),
        snapshot: crate::contracts::SubjectSnapshot {
            artifact_id: artifact.artifact_id.clone(),
            sha256: artifact.digest.value.clone(),
            byte_length: artifact.byte_length,
            execution_path,
            tree_artifact_id: None,
            tree_sha256: None,
            tree_byte_length: None,
            tree_file_count: None,
            git_plan_tool: None,
        },
    }
}

fn open_workspace(cli: &Cli) -> Result<workspace::Workspace> {
    workspace::Workspace::open(cli.workspace.as_deref())
}

fn requested_root(cli: &Cli) -> Result<PathBuf> {
    let path = match &cli.workspace {
        Some(path) => path.clone(),
        None => std::env::current_dir()?,
    };
    path.canonicalize()
        .with_context(|| format!("cannot resolve workspace root {}", path.display()))
}

fn requested_path(cli: &Cli) -> Result<PathBuf> {
    match &cli.workspace {
        Some(path) => Ok(path.clone()),
        None => Ok(std::env::current_dir()?),
    }
}

fn validate_role(role: &str) -> Result<()> {
    let valid = !role.is_empty()
        && role.len() <= 64
        && role
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
    if !valid {
        bail!("artifact role must be a short lowercase ASCII identifier");
    }
    Ok(())
}

fn success<T: Serialize>(command: &'static str, data: T) -> Result<CommandOutcome> {
    Ok(CommandOutcome {
        command,
        data: serde_json::to_value(data)?,
        exit_code: 0,
    })
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}
