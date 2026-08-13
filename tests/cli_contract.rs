use assert_cmd::Command;
use evidence_workbench::contracts::PlanRecord;
use evidence_workbench::manifests;
use evidence_workbench::workspace::digest_serialized;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::process::Stdio;
use std::sync::OnceLock;
use tempfile::TempDir;

fn binary(name: &str) -> PathBuf {
    if name == "ewb" {
        return test_harness_binary().clone();
    }
    if name == "ewb-fake-native" {
        return fake_native_binary().clone();
    }
    assert_cmd::cargo::cargo_bin(name)
}

fn test_harness_binary() -> &'static PathBuf {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY.get_or_init(|| {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fake = fake_native_binary();
        let fake_digest = hex::encode(Sha256::digest(
            fs::read(fake).expect("read internal fake native for exact admission"),
        ));
        let manifest = root.join("tests/harness/Cargo.toml");
        let target_dir = root.join("target/internal-test-harness");
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
        let built = ProcessCommand::new(cargo)
            .arg("build")
            .arg("--quiet")
            .arg("--manifest-path")
            .arg(&manifest)
            .arg("--target-dir")
            .arg(&target_dir)
            .env("EWB_TEST_NATIVE_SHA256", fake_digest)
            .status()
            .expect("build package-excluded EWB integration harness");
        assert!(built.success(), "EWB integration harness build failed");
        let extension = if cfg!(windows) { ".exe" } else { "" };
        let binary = target_dir
            .join("debug")
            .join(format!("ewb-test-harness{extension}"));
        assert!(binary.is_file(), "EWB integration harness binary is absent");
        binary
    })
}

fn fake_native_binary() -> &'static PathBuf {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY.get_or_init(|| {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let output_dir = root.join("target").join("internal-test-support");
        fs::create_dir_all(&output_dir).expect("create internal test-support output");
        let extension = if cfg!(windows) { ".exe" } else { "" };
        let output = output_dir.join(format!(
            "ewb-fake-native-{}{}",
            std::process::id(),
            extension
        ));
        let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
        let compiled = ProcessCommand::new(rustc)
            .args(["--edition=2024"])
            .arg(root.join("tests/support/fake_native.rs"))
            .arg("-o")
            .arg(&output)
            .output()
            .expect("compile internal fake native");
        assert!(
            compiled.status.success(),
            "fake native compilation failed: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        output
    })
}

fn ewb() -> Command {
    Command::new(binary("ewb"))
}

fn production_ewb() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin("ewb"))
}

fn run_json(command: &mut Command) -> (i32, Value, String) {
    let output = command.output().expect("run command");
    let code = output.status.code().unwrap_or(-999);
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 JSON stdout");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    let value: Value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
        panic!("stdout is not exactly one JSON value: {error}: {stdout:?}")
    });
    (code, value, stderr)
}

fn init(root: &Path) {
    let (code, value, stderr) =
        run_json(ewb().arg("--json").arg("--workspace").arg(root).arg("init"));
    assert_eq!(code, 0, "{value:?} {stderr}");
    assert_eq!(value["ok"], true);
}

fn git(root: &Path, args: &[&str]) -> String {
    let output = ProcessCommand::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn make_repo(parent: &Path) -> (PathBuf, String) {
    let root = parent.join("subject repo");
    fs::create_dir(&root).unwrap();
    git(&root, &["init", "--quiet"]);
    git(
        &root,
        &["config", "user.email", "ewb-tests@example.invalid"],
    );
    git(&root, &["config", "user.name", "EWB Tests"]);
    fs::write(root.join("evidence.txt"), b"evidence\n").unwrap();
    git(&root, &["add", "evidence.txt"]);
    git(&root, &["commit", "--quiet", "-m", "fixture"]);
    let head = git(&root, &["rev-parse", "HEAD"]);
    (root, head)
}

fn install_fake(directory: &Path) -> PathBuf {
    fs::create_dir_all(directory).unwrap();
    let extension = if cfg!(windows) { ".exe" } else { "" };
    let destination = directory.join(format!("greenwash{extension}"));
    fs::copy(binary("ewb-fake-native"), &destination).unwrap();
    let execution_boundary = directory.join(format!("ewb-test-native{extension}"));
    fs::copy(binary("ewb-fake-native"), &execution_boundary).unwrap();
    let tomorrowci = directory.join(format!("tomorrowci{extension}"));
    fs::copy(binary("ewb-fake-native"), &tomorrowci).unwrap();
    let package = directory
        .parent()
        .unwrap()
        .join("Lib")
        .join("site-packages")
        .join("greenwash");
    fs::create_dir_all(&package).unwrap();
    fs::write(package.join("__init__.py"), b"__version__ = 'fixture'\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&destination).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&destination, permissions).unwrap();
    }
    execution_boundary
}

fn test_path(fake_directory: &Path) -> OsString {
    let mut paths = vec![fake_directory.to_path_buf()];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    std::env::join_paths(paths).unwrap()
}

fn plan_execution_boundary(
    workspace: &Path,
    repo: &Path,
    _head: &str,
    fake_directory: &Path,
) -> Value {
    plan_execution_boundary_with_timeout(workspace, repo, fake_directory, 300_000)
}

fn plan_execution_boundary_with_timeout(
    workspace: &Path,
    repo: &Path,
    fake_directory: &Path,
    timeout_ms: u64,
) -> Value {
    let (code, value, stderr) = run_json(
        ewb()
            .current_dir(workspace)
            .env("PATH", test_path(fake_directory))
            .arg("--json")
            .arg("--workspace")
            .arg(workspace)
            .args([
                "runs",
                "plan",
                "--tool",
                "test-execution-boundary",
                "--subject",
            ])
            .arg(repo)
            .args(["--timeout-ms", &timeout_ms.to_string()]),
    );
    assert_eq!(code, 0, "{value:?} {stderr}");
    value
}

fn execute_execution_boundary(
    workspace: &Path,
    plan: &Value,
    fake_directory: &Path,
) -> (i32, Value, String) {
    let plan_id = plan["data"]["plan_id"].as_str().unwrap();
    let plan_digest = plan["data"]["record_digest"].as_str().unwrap();
    run_json(
        ewb()
            .env("PATH", test_path(fake_directory))
            .args(["--json", "--workspace"])
            .arg(workspace)
            .args([
                "runs",
                "execute",
                "--plan",
                plan_id,
                "--plan-digest",
                plan_digest,
                "--allow",
                "read_subject",
            ]),
    )
}

fn tree_snapshot(root: &Path) -> BTreeMap<String, String> {
    fn walk(base: &Path, path: &Path, output: &mut BTreeMap<String, String>) {
        let mut entries: Vec<_> = fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let relative = path.strip_prefix(base).unwrap().display().to_string();
            if path.is_dir() {
                output.insert(relative.clone(), "dir".to_owned());
                walk(base, &path, output);
            } else {
                let bytes = fs::read(&path).unwrap();
                output.insert(relative, hex::encode(Sha256::digest(bytes)));
            }
        }
    }
    let mut output = BTreeMap::new();
    walk(root, root, &mut output);
    output
}

#[test]
fn json_mode_wraps_argument_errors_without_stderr_noise() {
    let (code, value, stderr) = run_json(ewb().args(["--json", "not-a-command"]));
    assert_eq!(code, 2);
    assert_eq!(value["ok"], false);
    assert!(stderr.is_empty(), "stderr was not pure: {stderr:?}");
}

#[test]
fn doctor_is_read_only() {
    let temp = TempDir::new().unwrap();
    init(temp.path());
    let fake_dir = temp.path().join("fake-bin");
    install_fake(&fake_dir);
    let before = tree_snapshot(&temp.path().join(".ewb"));
    let (code, value, stderr) = run_json(
        ewb()
            .current_dir(temp.path())
            .env("PATH", test_path(&fake_dir))
            .args(["--json", "--workspace"])
            .arg(temp.path())
            .arg("doctor"),
    );
    assert_eq!(code, 0, "{value:?} {stderr}");
    assert_eq!(value["data"]["initialized"], true);
    let native_tools = value["data"]["native_tools"].as_array().unwrap();
    assert!(native_tools.iter().all(|probe| {
        probe["manifest_id"] == "test-execution-boundary"
            && probe["version_probe_executed"] == false
    }));
    let stateweaver = value["data"]["upstream_candidates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["source_commit"] == "598753d182dda65c73a313e9efbf20b826942f0a")
        .expect("StateWeaver candidate admission");
    assert_eq!(stateweaver["implementation_state"], "candidate_complete");
    assert_eq!(stateweaver["authority_effect"], "none");
    assert_eq!(stateweaver["execution_readiness"]["state"], "fail_closed");
    assert!(!temp.path().join(".fake-version-probe-ran").exists());
    assert_eq!(before, tree_snapshot(&temp.path().join(".ewb")));
}

#[test]
fn upstream_registry_projects_twelve_production_pins_without_authority_or_shared_pass() {
    let production = manifests::production_all().unwrap();
    assert_eq!(production.len(), 12);

    let (code, listed, stderr) = run_json(ewb().args(["--json", "tools", "list"]));
    assert_eq!(code, 0, "{listed:?} {stderr}");
    let rows = listed["data"].as_array().unwrap();
    let pinned = rows
        .iter()
        .filter(|row| !row["upstream_pin"].is_null())
        .collect::<Vec<_>>();
    assert_eq!(pinned.len(), 12);
    for row in &pinned {
        assert_eq!(row["upstream_pin"]["authority_effect"], "none");
        assert_ne!(row["upstream_pin"]["native_status"], "PASS");
    }
    let ready = pinned
        .iter()
        .filter(|row| row["upstream_pin"]["execution_readiness"]["state"] == "ready")
        .collect::<Vec<_>>();
    assert!(ready.is_empty());

    let temp = TempDir::new().unwrap();
    let (code, initialized, stderr) = run_json(
        ewb()
            .args(["--json", "--workspace"])
            .arg(temp.path())
            .arg("init"),
    );
    assert_eq!(code, 0, "{initialized:?} {stderr}");
    let initialized_pins = initialized["data"]["trusted_embedded_manifests"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| !row["upstream_pin"].is_null())
        .count();
    assert_eq!(initialized_pins, 12);

    for manifest in production {
        let (code, shown, stderr) =
            run_json(ewb().args(["--json", "tools", "show", &manifest.manifest.manifest_id]));
        assert_eq!(code, 0, "{shown:?} {stderr}");
        assert_eq!(
            shown["data"]["upstream_pin"]["tool_manifest_id"],
            manifest.manifest.manifest_id
        );
        assert_eq!(
            shown["data"]["upstream_pin"]["admission"]["authority_effect"],
            "none"
        );
    }
}

#[test]
fn test_support_execution_fixture_is_not_presented_as_upstream_production() {
    let (code, listed, stderr) = run_json(ewb().args(["--json", "tools", "list"]));
    assert_eq!(code, 0, "{listed:?} {stderr}");
    let fixture = listed["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["manifest_id"] == "test-execution-boundary")
        .expect("test-support execution fixture");
    assert_eq!(fixture["stability"], "experimental");
    assert_eq!(fixture["upstream_candidate"], Value::Null);
    assert_eq!(fixture["upstream_pin"], Value::Null);

    let (code, shown, stderr) =
        run_json(ewb().args(["--json", "tools", "show", "test-execution-boundary"]));
    assert_eq!(code, 0, "{shown:?} {stderr}");
    let expected = hex::encode(Sha256::digest(
        fs::read(binary("ewb-fake-native")).expect("read fake native"),
    ));
    assert_eq!(
        shown["data"]["manifest"]["identity_contract"]["allowed_binary_sha256"][0],
        expected
    );
}

#[test]
fn production_binary_never_contains_the_internal_harness_registry() {
    let (code, listed, stderr) = run_json(production_ewb().args(["--json", "tools", "list"]));
    assert_eq!(code, 0, "{listed:?} {stderr}");
    let rows = listed["data"].as_array().unwrap();
    assert_eq!(rows.len(), 12);
    assert!(
        rows.iter()
            .all(|row| row["manifest_id"] != "test-execution-boundary")
    );

    let (code, shown, stderr) =
        run_json(production_ewb().args(["--json", "tools", "show", "test-execution-boundary"]));
    assert_eq!(code, 2, "{shown:?} {stderr}");
    assert_eq!(shown["ok"], false);
    assert!(
        shown["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown trusted tool manifest")
    );
}

#[test]
fn stateweaver_candidate_completion_is_separate_from_execution_readiness() {
    let (code, listed, stderr) = run_json(ewb().args(["--json", "tools", "list"]));
    assert_eq!(code, 0, "{listed:?} {stderr}");
    let stateweaver = listed["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["manifest_id"] == "stateweaver-foundation")
        .expect("StateWeaver tool");
    assert_eq!(stateweaver["planning_supported"], false);
    assert_eq!(
        stateweaver["upstream_candidate"]["implementation_state"],
        "candidate_complete"
    );
    assert_eq!(
        stateweaver["upstream_candidate"]["evidence_integrity_state"],
        "verified_at_admission"
    );
    assert_eq!(
        stateweaver["upstream_candidate"]["native_status"],
        "CANDIDATE_READY_FOR_EXTERNAL_QUALIFICATION"
    );
    assert_eq!(stateweaver["upstream_candidate"]["release_eligible"], false);
    assert_eq!(
        stateweaver["upstream_candidate"]["execution_readiness"]["state"],
        "fail_closed"
    );

    let (code, shown, stderr) =
        run_json(ewb().args(["--json", "tools", "show", "stateweaver-foundation"]));
    assert_eq!(code, 0, "{shown:?} {stderr}");
    assert_eq!(
        shown["data"]["candidate_pin"]["source"]["commit_sha"],
        "598753d182dda65c73a313e9efbf20b826942f0a"
    );
    assert_eq!(
        shown["data"]["candidate_pin"]["candidate"]["payload_manifest_sha256"],
        "8c7c77d59d4cf3abdcadcce3f2d110ca085789da1ec14a2301245f3418b78bc3"
    );
    assert_eq!(
        shown["data"]["candidate_pin"]["workbench_admission"]["authority_effect"],
        "none"
    );
}

#[test]
fn stateweaver_plan_fails_before_writing_without_runtime_capsule() {
    let temp = TempDir::new().unwrap();
    init(temp.path());
    let before = tree_snapshot(&temp.path().join(".ewb"));
    let (code, failure, stderr) = run_json(
        ewb()
            .args(["--json", "--workspace"])
            .arg(temp.path())
            .args(["runs", "plan", "--tool", "stateweaver-foundation"]),
    );
    assert_eq!(code, 2, "{failure:?} {stderr}");
    assert_eq!(failure["ok"], false);
    assert!(
        failure["error"]["message"]
            .as_str()
            .unwrap()
            .contains("execution adapter is disabled")
    );
    assert_eq!(before, tree_snapshot(&temp.path().join(".ewb")));
}

#[test]
fn admitted_native_delivery_rejects_same_name_with_different_bytes() {
    let temp = TempDir::new().unwrap();
    init(temp.path());
    let fake_dir = temp.path().join("fake-bin");
    install_fake(&fake_dir);
    let before = tree_snapshot(&temp.path().join(".ewb"));
    let (code, failure, stderr) = run_json(
        ewb()
            .env("PATH", test_path(&fake_dir))
            .args(["--json", "--workspace"])
            .arg(temp.path())
            .args(["runs", "plan", "--tool", "tomorrowci-lab"]),
    );
    assert_eq!(code, 2, "{failure:?} {stderr}");
    assert!(
        failure["error"]["message"]
            .as_str()
            .unwrap()
            .contains("execution adapter is disabled")
    );
    assert_eq!(before, tree_snapshot(&temp.path().join(".ewb")));
}

#[test]
fn tomorrowci_fails_before_writing_until_vcruntime_closure_is_bound() {
    let temp = TempDir::new().unwrap();
    init(temp.path());
    let before = tree_snapshot(&temp.path().join(".ewb"));
    let (code, failure, stderr) = run_json(
        ewb()
            .args(["--json", "--workspace"])
            .arg(temp.path())
            .args(["runs", "plan", "--tool", "tomorrowci-lab"]),
    );
    assert_eq!(code, 2, "{failure:?} {stderr}");
    assert!(
        failure["error"]["message"]
            .as_str()
            .unwrap()
            .contains("execution adapter is disabled")
    );
    assert_eq!(before, tree_snapshot(&temp.path().join(".ewb")));

    let (code, shown, stderr) = run_json(ewb().args(["--json", "tools", "show", "tomorrowci-lab"]));
    assert_eq!(code, 0, "{shown:?} {stderr}");
    assert_eq!(
        shown["data"]["upstream_pin"]["execution_readiness"]["state"],
        "fail_closed"
    );
    assert!(
        shown["data"]["upstream_pin"]["execution_readiness"]["blocker_codes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|code| code == "unbound_vcruntime140_dll")
    );
}

#[test]
fn fail_closed_tools_cannot_execute_through_version_probe() {
    let temp = TempDir::new().unwrap();
    let fake_dir = temp.path().join("fake-bin");
    install_fake(&fake_dir);
    let marker = temp.path().join(".fake-version-probe-ran");
    let (code, failure, stderr) = run_json(
        ewb()
            .current_dir(temp.path())
            .env("PATH", test_path(&fake_dir))
            .args(["--json", "tools", "probe", "tomorrowci-lab"]),
    );
    assert_eq!(code, 2, "{failure:?} {stderr}");
    assert!(
        failure["error"]["message"]
            .as_str()
            .unwrap()
            .contains("native probe is disabled")
    );
    assert!(!marker.exists());

    let (code, probes, stderr) = run_json(
        ewb()
            .current_dir(temp.path())
            .env("PATH", test_path(&fake_dir))
            .args(["--json", "tools", "probe"]),
    );
    assert_eq!(code, 0, "{probes:?} {stderr}");
    let entries = probes["data"].as_array().unwrap();
    assert!(
        entries
            .iter()
            .all(|entry| entry["manifest_id"] == "test-execution-boundary")
    );
    assert!(
        marker.exists(),
        "only the explicit debug test fixture may probe"
    );
}

#[test]
fn artifact_store_preserves_arbitrary_bytes_and_detects_tampering() {
    let temp = TempDir::new().unwrap();
    init(temp.path());
    let source = temp.path().join("raw.bin");
    let bytes: Vec<u8> = (0_u8..=255).collect();
    fs::write(&source, &bytes).unwrap();
    let (code, added, stderr) = run_json(
        ewb()
            .args(["--json", "--workspace"])
            .arg(temp.path())
            .args(["artifacts", "add", "--file"])
            .arg(&source)
            .args([
                "--role",
                "fixture",
                "--media-type",
                "application/octet-stream",
            ]),
    );
    assert_eq!(code, 0, "{added:?} {stderr}");
    let artifact = &added["data"];
    let id = artifact["artifact_id"].as_str().unwrap();
    let digest = artifact["digest"]["value"].as_str().unwrap();
    let object = temp
        .path()
        .join(".ewb/objects/sha256")
        .join(&digest[..2])
        .join(&digest[2..]);
    assert_eq!(fs::read(&object).unwrap(), bytes);

    let (code, verified, stderr) = run_json(
        ewb()
            .args(["--json", "--workspace"])
            .arg(temp.path())
            .args(["artifacts", "verify", id]),
    );
    assert_eq!(code, 0, "{verified:?} {stderr}");
    assert_eq!(verified["data"]["verified"], true);

    fs::write(&object, b"tampered").unwrap();
    let (code, failure, _) = run_json(
        ewb()
            .args(["--json", "--workspace"])
            .arg(temp.path())
            .args(["artifacts", "verify", id]),
    );
    assert_ne!(code, 0);
    assert_eq!(failure["ok"], false);
}

#[test]
fn artifact_contract_rejects_empty_media_type() {
    let temp = TempDir::new().unwrap();
    init(temp.path());
    let source = temp.path().join("raw.bin");
    fs::write(&source, b"evidence").unwrap();
    let (code, value, stderr) = run_json(
        ewb()
            .args(["--json", "--workspace"])
            .arg(temp.path())
            .args(["artifacts", "add", "--file"])
            .arg(&source)
            .args(["--role", "fixture", "--media-type", ""]),
    );
    assert_eq!(code, 2, "{value:?} {stderr}");
    assert_eq!(value["ok"], false);
    assert!(
        temp.path()
            .join(".ewb/artifacts")
            .read_dir()
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn plan_never_launches_native_tool_and_execute_preserves_native_block() {
    let temp = TempDir::new().unwrap();
    init(temp.path());
    let (repo, head) = make_repo(temp.path());
    let fake_dir = temp.path().join("fake-bin");
    install_fake(&fake_dir);
    let planned = plan_execution_boundary(temp.path(), &repo, &head, &fake_dir);
    assert!(
        !temp.path().join(".fake-version-probe-ran").exists(),
        "runs plan launched the native version probe"
    );
    let plan_id = planned["data"]["plan_id"].as_str().unwrap();
    let plan_digest = planned["data"]["record_digest"].as_str().unwrap();

    let (missing_code, missing, _) = run_json(
        ewb()
            .env("PATH", test_path(&fake_dir))
            .args(["--json", "--workspace"])
            .arg(temp.path())
            .args([
                "runs",
                "execute",
                "--plan",
                plan_id,
                "--plan-digest",
                plan_digest,
            ]),
    );
    assert_ne!(missing_code, 0);
    assert!(
        missing["error"]["message"]
            .as_str()
            .unwrap()
            .contains("missing explicit capability")
    );

    let (code, executed, stderr) = run_json(
        ewb()
            .env("PATH", test_path(&fake_dir))
            .args(["--json", "--workspace"])
            .arg(temp.path())
            .args([
                "runs",
                "execute",
                "--plan",
                plan_id,
                "--plan-digest",
                plan_digest,
                "--allow",
                "read_subject",
            ]),
    );
    assert_eq!(code, 0, "{executed:?} {stderr}");
    let run = &executed["data"]["run"];
    assert_eq!(run["termination"]["kind"], "exited");
    assert_eq!(run["termination"]["exit_code"], 1);
    assert_eq!(run["native_result"]["availability"], "reported");
    assert_eq!(
        run["native_result"]["observations"][0]["value"],
        "inspected"
    );
    assert_eq!(run["native_authority"]["availability"], "not_reported");
    for forbidden in [
        "status",
        "verdict",
        "passed",
        "aggregate_verdict",
        "overall_status",
    ] {
        assert!(
            run.get(forbidden).is_none(),
            "forbidden aggregate field: {forbidden}"
        );
    }
}

#[test]
fn execute_rejects_stale_subject_and_stale_native_binary() {
    let temp = TempDir::new().unwrap();
    init(temp.path());
    let (repo, head) = make_repo(temp.path());
    let fake_dir = temp.path().join("fake-bin");
    let fake = install_fake(&fake_dir);

    let first = plan_execution_boundary(temp.path(), &repo, &head, &fake_dir);
    let first_id = first["data"]["plan_id"].as_str().unwrap();
    let first_digest = first["data"]["record_digest"].as_str().unwrap();
    fs::write(repo.join("evidence.txt"), b"dirty\n").unwrap();
    let (code, failure, _) = run_json(
        ewb()
            .env("PATH", test_path(&fake_dir))
            .args(["--json", "--workspace"])
            .arg(temp.path())
            .args([
                "runs",
                "execute",
                "--plan",
                first_id,
                "--plan-digest",
                first_digest,
                "--allow",
                "read_subject",
            ]),
    );
    assert_eq!(
        code, 0,
        "snapshot should survive original worktree drift: {failure:?}"
    );

    fs::write(repo.join("evidence.txt"), b"evidence\n").unwrap();
    let second = plan_execution_boundary(temp.path(), &repo, &head, &fake_dir);
    let second_id = second["data"]["plan_id"].as_str().unwrap();
    let second_digest = second["data"]["record_digest"].as_str().unwrap();
    OpenOptions::new()
        .append(true)
        .open(&fake)
        .unwrap()
        .write_all(b"\0")
        .unwrap();
    let (code, failure, _) = run_json(
        ewb()
            .env("PATH", test_path(&fake_dir))
            .args(["--json", "--workspace"])
            .arg(temp.path())
            .args([
                "runs",
                "execute",
                "--plan",
                second_id,
                "--plan-digest",
                second_digest,
                "--allow",
                "read_subject",
            ]),
    );
    assert_eq!(
        code, 0,
        "staged native should survive source launcher drift: {failure:?}"
    );
}

#[test]
fn execute_ignores_git_path_replacement_after_plan() {
    let temp = TempDir::new().unwrap();
    init(temp.path());
    let (repo, head) = make_repo(temp.path());
    let fake_dir = temp.path().join("fake-bin");
    install_fake(&fake_dir);
    let planned = plan_execution_boundary(temp.path(), &repo, &head, &fake_dir);

    let hostile_path = temp.path().join("hostile-path");
    fs::create_dir(&hostile_path).unwrap();
    fs::write(hostile_path.join("git.exe"), b"must never execute").unwrap();
    let plan_id = planned["data"]["plan_id"].as_str().unwrap();
    let plan_digest = planned["data"]["record_digest"].as_str().unwrap();
    let (code, value, stderr) = run_json(
        ewb()
            .env("PATH", &hostile_path)
            .args(["--json", "--workspace"])
            .arg(temp.path())
            .args([
                "runs",
                "execute",
                "--plan",
                plan_id,
                "--plan-digest",
                plan_digest,
                "--allow",
                "read_subject",
            ]),
    );
    assert_eq!(code, 0, "{value:?} {stderr}");
    assert_eq!(
        value["data"]["run"]["native_result"]["availability"],
        "reported"
    );
}

#[test]
fn execute_rejects_staged_git_identity_tamper_without_spawning() {
    let temp = TempDir::new().unwrap();
    init(temp.path());
    let (repo, head) = make_repo(temp.path());
    let fake_dir = temp.path().join("fake-bin");
    install_fake(&fake_dir);
    let planned = plan_execution_boundary(temp.path(), &repo, &head, &fake_dir);
    let staged = PathBuf::from(
        planned["data"]["payload"]["subject"]["snapshot"]["git_plan_tool"]["staged_path"]
            .as_str()
            .unwrap(),
    );
    fs::write(&staged, b"tampered Git identity evidence").unwrap();

    let (code, value, _) = execute_execution_boundary(temp.path(), &planned, &fake_dir);
    assert_eq!(code, 2, "{value:?}");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Git plan launcher bytes")
    );
    assert_eq!(
        fs::read_dir(temp.path().join(".ewb/runs")).unwrap().count(),
        0
    );
    assert_eq!(
        fs::read_dir(temp.path().join(".ewb/locks"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn execute_requires_the_reviewed_plan_digest_and_revalidates_plan_semantics() {
    let temp = TempDir::new().unwrap();
    init(temp.path());
    let (repo, head) = make_repo(temp.path());
    let fake_dir = temp.path().join("fake-bin");
    install_fake(&fake_dir);

    let planned = plan_execution_boundary(temp.path(), &repo, &head, &fake_dir);
    let plan_id = planned["data"]["plan_id"].as_str().unwrap();
    let reviewed_digest = planned["data"]["record_digest"].as_str().unwrap();
    let path = temp
        .path()
        .join(".ewb/plans")
        .join(format!("{plan_id}.json"));
    let mut record: PlanRecord = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    record.payload.invocation.argv.push("--forged".to_owned());
    record.record_digest = digest_serialized(&record.payload).unwrap();
    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();

    let execute = |digest: &str| {
        run_json(
            ewb()
                .env("PATH", test_path(&fake_dir))
                .args(["--json", "--workspace"])
                .arg(temp.path())
                .args([
                    "runs",
                    "execute",
                    "--plan",
                    plan_id,
                    "--plan-digest",
                    digest,
                    "--allow",
                    "read_subject",
                ]),
        )
    };

    let (code, value, _) = execute(reviewed_digest);
    assert_eq!(code, 2, "{value:?}");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("reviewed plan bytes")
    );

    let (code, value, _) = execute(&record.record_digest);
    assert_eq!(code, 2, "{value:?}");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("trusted adapter contract")
    );
    assert_eq!(
        fs::read_dir(temp.path().join(".ewb/runs")).unwrap().count(),
        0
    );
}

#[test]
fn storage_ids_reject_traversal() {
    let temp = TempDir::new().unwrap();
    init(temp.path());
    for malicious in [
        "../outside",
        "..\\outside",
        "C:outside",
        "artifact_../../outside",
    ] {
        let (code, value, _) = run_json(
            ewb()
                .args(["--json", "--workspace"])
                .arg(temp.path())
                .args(["artifacts", "verify", malicious]),
        );
        assert_ne!(code, 0, "accepted {malicious:?}: {value:?}");
    }
}

#[test]
fn malformed_native_json_and_timeout_never_create_a_result_or_authority() {
    let temp = TempDir::new().unwrap();
    init(temp.path());
    let (repo, _) = make_repo(temp.path());
    let fake_dir = temp.path().join("fake-bin");
    install_fake(&fake_dir);

    fs::write(repo.join(".fake-mode"), b"duplicate-json\n").unwrap();
    git(&repo, &["add", ".fake-mode"]);
    git(&repo, &["commit", "--quiet", "-m", "duplicate fixture"]);
    let duplicate_head = git(&repo, &["rev-parse", "HEAD"]);
    let duplicate_plan = plan_execution_boundary(temp.path(), &repo, &duplicate_head, &fake_dir);
    let (code, run, stderr) = execute_execution_boundary(temp.path(), &duplicate_plan, &fake_dir);
    assert_eq!(code, 0, "{run:?} {stderr}");
    assert_eq!(
        run["data"]["run"]["native_result"]["availability"],
        "not_reported"
    );
    assert_eq!(run["data"]["run"]["native_result"]["reason"], "parse_error");
    assert_eq!(
        run["data"]["run"]["native_authority"]["availability"],
        "not_reported"
    );

    fs::write(repo.join(".fake-mode"), b"hang\n").unwrap();
    git(&repo, &["add", ".fake-mode"]);
    git(&repo, &["commit", "--quiet", "-m", "timeout fixture"]);
    let _timeout_head = git(&repo, &["rev-parse", "HEAD"]);
    let timeout_plan = plan_execution_boundary_with_timeout(temp.path(), &repo, &fake_dir, 100);
    let (code, run, _) = execute_execution_boundary(temp.path(), &timeout_plan, &fake_dir);
    assert_eq!(code, 4);
    assert_eq!(run["data"]["run"]["termination"]["kind"], "timed_out");
    assert_eq!(
        run["data"]["run"]["native_result"]["availability"],
        "not_reported"
    );
    assert_eq!(
        run["data"]["run"]["native_authority"]["availability"],
        "not_reported"
    );
}

#[test]
fn staged_native_tamper_rejects_and_subject_mutation_suppresses_result() {
    let temp = TempDir::new().unwrap();
    init(temp.path());
    let (repo, head) = make_repo(temp.path());
    let fake_dir = temp.path().join("fake-bin");
    install_fake(&fake_dir);

    let planned = plan_execution_boundary(temp.path(), &repo, &head, &fake_dir);
    let staged = PathBuf::from(
        planned["data"]["payload"]["resolved_tool_identity"]["path"]
            .as_str()
            .unwrap(),
    );
    fs::write(&staged, b"tampered staged executable").unwrap();
    let (code, value, _) = execute_execution_boundary(temp.path(), &planned, &fake_dir);
    assert_eq!(code, 2, "{value:?}");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("staged executable")
    );
    assert_eq!(
        fs::read_dir(temp.path().join(".ewb/runs")).unwrap().count(),
        0
    );
    assert_eq!(
        fs::read_dir(temp.path().join(".ewb/locks"))
            .unwrap()
            .count(),
        0
    );

    // Restore by planning a distinct executable snapshot after replacing the source.
    fs::copy(binary("ewb-fake-native"), &staged).unwrap();
    fs::copy(
        binary("ewb-fake-native"),
        fake_dir.join(if cfg!(windows) {
            "ewb-test-native.exe"
        } else {
            "ewb-test-native"
        }),
    )
    .unwrap();
    fs::write(repo.join(".fake-mode"), b"mutate-subject\n").unwrap();
    git(&repo, &["add", ".fake-mode"]);
    git(&repo, &["commit", "--quiet", "-m", "mutation fixture"]);
    let head = git(&repo, &["rev-parse", "HEAD"]);
    let planned = plan_execution_boundary(temp.path(), &repo, &head, &fake_dir);
    let plan_id = planned["data"]["plan_id"].as_str().unwrap();
    let (code, value, stderr) = execute_execution_boundary(temp.path(), &planned, &fake_dir);
    assert_eq!(code, 0, "{value:?} {stderr}");
    assert_eq!(
        value["data"]["run"]["native_result"]["availability"],
        "not_reported"
    );
    assert_eq!(
        value["data"]["run"]["native_result"]["reason"],
        "contract_mismatch"
    );
    assert!(!temp.path().join(".ewb/executions").join(plan_id).exists());
    assert_eq!(
        fs::read_dir(temp.path().join(".ewb/locks"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn oversized_native_output_is_interrupted_without_importing_capture() {
    let temp = TempDir::new().unwrap();
    init(temp.path());
    let (repo, _) = make_repo(temp.path());
    let fake_dir = temp.path().join("fake-bin");
    install_fake(&fake_dir);

    fs::write(repo.join(".fake-mode"), b"oversized-output\n").unwrap();
    git(&repo, &["add", ".fake-mode"]);
    git(
        &repo,
        &["commit", "--quiet", "-m", "oversized output fixture"],
    );
    let head = git(&repo, &["rev-parse", "HEAD"]);
    let plan = plan_execution_boundary(temp.path(), &repo, &head, &fake_dir);
    let (code, run, stderr) = execute_execution_boundary(temp.path(), &plan, &fake_dir);
    assert_eq!(code, 4, "{run:?} {stderr}");
    let run = &run["data"]["run"];
    assert_eq!(run["termination"]["kind"], "interrupted");
    assert_eq!(
        run["termination"]["reason"],
        "native_output_exceeded_33554432_bytes"
    );
    assert_eq!(run["artifacts"].as_array().unwrap().len(), 0);
    assert_eq!(run["native_result"]["availability"], "not_reported");
    assert_eq!(run["native_result"]["reason"], "process_not_exited");
    assert_eq!(run["native_authority"]["availability"], "not_reported");
    // Planning commits native, bundle, tree, and Git-plan identity artifacts;
    // interrupted oversized streams must not add stdout/stderr captures.
    let roles: Vec<Vec<String>> = fs::read_dir(temp.path().join(".ewb/artifacts"))
        .unwrap()
        .map(|entry| {
            let bytes = fs::read(entry.unwrap().path()).unwrap();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            value["artifact"]["roles"]
                .as_array()
                .unwrap()
                .iter()
                .map(|role| role.as_str().unwrap().to_owned())
                .collect()
        })
        .collect();
    assert!(
        roles
            .iter()
            .any(|value| value == &["native_executable_snapshot"])
    );
    assert!(roles.iter().any(|value| value == &["git_subject_bundle"]));
    assert!(roles.iter().any(|value| value == &["git_execution_tree"]));
    assert!(
        roles
            .iter()
            .any(|value| value == &["git_plan_launcher_snapshot"])
    );
    assert!(
        !roles
            .iter()
            .flatten()
            .any(|role| matches!(role.as_str(), "native_stdout" | "native_stderr"))
    );
    assert_eq!(
        fs::read_dir(temp.path().join(".ewb/tmp")).unwrap().count(),
        0
    );
}

#[test]
fn concurrent_init_and_artifact_adds_commit_only_complete_records() {
    let temp = TempDir::new().unwrap();
    let mut initializers = Vec::new();
    for _ in 0..8 {
        initializers.push(
            ProcessCommand::new(binary("ewb"))
                .args(["--json", "--workspace"])
                .arg(temp.path())
                .arg("init")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    for child in initializers {
        assert!(child.wait_with_output().unwrap().status.success());
    }

    let source = temp.path().join("concurrent.bin");
    let bytes = b"one immutable object, many records\0\xff";
    fs::write(&source, bytes).unwrap();
    let mut children = Vec::new();
    for _ in 0..12 {
        children.push(
            ProcessCommand::new(binary("ewb"))
                .args(["--json", "--workspace"])
                .arg(temp.path())
                .args(["artifacts", "add", "--file"])
                .arg(&source)
                .args(["--role", "concurrent_fixture"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut digests = std::collections::BTreeSet::new();
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        ids.insert(value["data"]["artifact_id"].as_str().unwrap().to_owned());
        digests.insert(
            value["data"]["digest"]["value"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    assert_eq!(ids.len(), 12);
    assert_eq!(digests.len(), 1);
    assert_eq!(
        fs::read_dir(temp.path().join(".ewb/artifacts"))
            .unwrap()
            .count(),
        12
    );
    assert_eq!(
        fs::read_dir(temp.path().join(".ewb/tmp")).unwrap().count(),
        0
    );
}
