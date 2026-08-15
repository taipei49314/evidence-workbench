use std::env;
use std::fs;
use std::path::PathBuf;

mod build_metadata;

const COMMIT: &str = "EWB_BUILD_VCS_COMMIT";
const TREE: &str = "EWB_BUILD_VCS_TREE";
const DIRTY: &str = "EWB_BUILD_VCS_DIRTY";
const TAG: &str = "EWB_BUILD_VCS_TAG";

fn main() {
    for name in [COMMIT, TREE, DIRTY, TAG] {
        println!("cargo:rerun-if-env-changed={name}");
    }

    let commit = read_env(COMMIT);
    let tree = read_env(TREE);
    let dirty = read_env(DIRTY);
    let tag = read_env(TAG);
    let metadata = build_metadata::validate(commit, tree, dirty, tag)
        .unwrap_or_else(|error| panic!("invalid EWB build metadata: {error}"));

    let generated = format!(
        "const RECORDED_VCS_COMMIT: Option<&str> = {};\n\
         const RECORDED_VCS_TREE: Option<&str> = {};\n\
         const RECORDED_VCS_DIRTY: Option<bool> = {};\n\
         const RECORDED_VCS_TAG: Option<&str> = {};\n",
        rust_string_option(metadata.commit.as_deref()),
        rust_string_option(metadata.tree.as_deref()),
        rust_bool_option(metadata.dirty),
        rust_string_option(metadata.tag.as_deref()),
    );
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo must set OUT_DIR"))
        .join("build_identity.rs");
    fs::write(output, generated).expect("write validated build identity constants");
}

fn read_env(name: &str) -> Option<String> {
    match env::var(name) {
        Ok(value) => Some(value),
        Err(env::VarError::NotPresent) => None,
        Err(env::VarError::NotUnicode(_)) => panic!("{name} must be valid UTF-8"),
    }
}

fn rust_string_option(value: Option<&str>) -> String {
    match value {
        Some(value) => format!("Some({value:?})"),
        None => "None".to_owned(),
    }
}

fn rust_bool_option(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "Some(true)",
        Some(false) => "Some(false)",
        None => "None",
    }
}
