use evidence_workbench::native_qualifications::{admit, executable_artifact, load_verified};
use evidence_workbench::workspace::{self, Workspace};
use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/tomorrowci-qualification"
);

fn portable_candidate_root(temp: &TempDir) -> PathBuf {
    let fixture = Path::new(FIXTURE);
    let root = temp.path().join("candidate");
    fs::create_dir(&root).unwrap();
    for name in [
        "candidate-manifest.json",
        "SHA256SUMS.txt",
        "tomorrowci-v0.2.0-alpha.1-x86_64-pc-windows-msvc.zip",
        "pe-import-report.json",
        "native-delivery-qualification.json",
    ] {
        fs::copy(fixture.join(name), root.join(name)).unwrap();
    }
    let archive_bytes =
        fs::read(root.join("tomorrowci-v0.2.0-alpha.1-x86_64-pc-windows-msvc.zip")).unwrap();
    let mut archive = zip::ZipArchive::new(Cursor::new(archive_bytes)).unwrap();
    let mut entry = archive
        .by_name("tomorrowci-v0.2.0-alpha.1-x86_64-pc-windows-msvc/tomorrowci.exe")
        .unwrap();
    let mut executable = fs::File::create(root.join("tomorrowci.exe")).unwrap();
    std::io::copy(&mut entry, &mut executable).unwrap();
    executable.flush().unwrap();
    root
}

fn workspace(temp: &TempDir) -> Workspace {
    let root = temp.path().join("workspace");
    fs::create_dir(&root).unwrap();
    Workspace::init(&root).unwrap()
}

#[test]
fn exact_candidate_admits_reloads_and_rejects_record_tamper() {
    let temp = TempDir::new().unwrap();
    let root = portable_candidate_root(&temp);
    let workspace = workspace(&temp);
    let record = admit(
        &workspace,
        &root.join("native-delivery-qualification.json"),
        &root,
    )
    .unwrap();
    assert_eq!(
        record.qualification_id,
        "qualification_6813f0009eda332b202be9f5b2bbc925"
    );
    load_verified(&workspace, &record.qualification_id).unwrap();

    let mut forged = record.clone();
    forged.payload.qualification.declared_at = "2026-08-14T00:00:00Z".to_owned();
    forged.record_digest = workspace::digest_serialized(&forged.payload).unwrap();
    fs::write(
        workspace
            .state
            .join("qualifications")
            .join(format!("{}.json", forged.qualification_id)),
        serde_json::to_vec_pretty(&forged).unwrap(),
    )
    .unwrap();
    assert!(load_verified(&workspace, &forged.qualification_id).is_err());
}

#[test]
fn exact_candidate_rejects_cas_tamper_on_reload() {
    let temp = TempDir::new().unwrap();
    let root = portable_candidate_root(&temp);
    let workspace = workspace(&temp);
    let record = admit(
        &workspace,
        &root.join("native-delivery-qualification.json"),
        &root,
    )
    .unwrap();
    let executable = executable_artifact(&record).unwrap();
    let object = workspace.object_path(&executable.sha256).unwrap();
    let mut bytes = fs::read(&object).unwrap();
    bytes[0] ^= 0xff;
    fs::write(object, bytes).unwrap();
    assert!(load_verified(&workspace, &record.qualification_id).is_err());
}

#[test]
fn invalid_candidate_fails_before_creating_admission_artifacts_or_objects() {
    let temp = TempDir::new().unwrap();
    let root = portable_candidate_root(&temp);
    let workspace = workspace(&temp);
    let before_objects = fs::read_dir(workspace.state.join("objects/sha256"))
        .unwrap()
        .count();
    let before_artifacts = fs::read_dir(workspace.state.join("artifacts"))
        .unwrap()
        .count();
    let before_qualifications = fs::read_dir(workspace.state.join("qualifications"))
        .unwrap()
        .count();
    let report = root.join("pe-import-report.json");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    value["aggregate_pass"] = serde_json::json!(true);
    fs::write(&report, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    assert!(
        admit(
            &workspace,
            &root.join("native-delivery-qualification.json"),
            &root,
        )
        .is_err()
    );
    assert_eq!(
        fs::read_dir(workspace.state.join("objects/sha256"))
            .unwrap()
            .count(),
        before_objects
    );
    assert_eq!(
        fs::read_dir(workspace.state.join("artifacts"))
            .unwrap()
            .count(),
        before_artifacts
    );
    assert_eq!(
        fs::read_dir(workspace.state.join("qualifications"))
            .unwrap()
            .count(),
        before_qualifications
    );
}

#[test]
fn locally_cached_candidate_rederives_when_available() {
    let root = PathBuf::from(
        "C:/Users/G713RW/Documents/New project/.toolcache/tomorrowci-master-candidate-31734705578",
    );
    if !root.join("native-delivery-qualification.json").is_file() {
        return;
    }
    let temp = TempDir::new().unwrap();
    let workspace = workspace(&temp);
    let record = admit(
        &workspace,
        &root.join("native-delivery-qualification.json"),
        &root,
    )
    .unwrap();
    assert_eq!(
        record.qualification_id,
        "qualification_6813f0009eda332b202be9f5b2bbc925"
    );
}
