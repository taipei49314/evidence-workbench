use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::Path;

include!(concat!(env!("OUT_DIR"), "/build_identity.rs"));

#[cfg(test)]
#[path = "../build_metadata.rs"]
mod build_metadata;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildIdentity {
    pub schema_version: String,
    pub package: BuildPackage,
    pub executable: ExecutableIdentity,
    pub target: BuildTarget,
    pub vcs_base: VcsBase,
    pub authority_effect: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildPackage {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutableIdentity {
    pub observation_scope: String,
    pub sha256: String,
    pub byte_length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildTarget {
    pub os: String,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VcsBase {
    pub reporting_state: String,
    pub scope: String,
    pub commit: Option<String>,
    pub tree: Option<String>,
    pub dirty: Option<bool>,
    pub exact_tag: Option<String>,
}

pub fn current() -> Result<BuildIdentity> {
    let executable_path = std::env::current_exe().context("cannot locate current executable")?;
    let mut executable = open_current_executable(&executable_path)?;
    let mut digest = Sha256::new();
    let mut byte_length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = executable
            .read(&mut buffer)
            .context("cannot read current executable file")?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        byte_length = byte_length
            .checked_add(u64::try_from(read).expect("read length fits u64"))
            .context("current executable length overflow")?;
    }

    let vcs_base = match (
        RECORDED_VCS_COMMIT,
        RECORDED_VCS_TREE,
        RECORDED_VCS_DIRTY,
        RECORDED_VCS_TAG,
    ) {
        (Some(commit), Some(tree), Some(dirty), exact_tag) => VcsBase {
            reporting_state: "builder_asserted".to_owned(),
            scope: "builder_recorded_vcs_base".to_owned(),
            commit: Some(commit.to_owned()),
            tree: Some(tree.to_owned()),
            dirty: Some(dirty),
            exact_tag: exact_tag.map(str::to_owned),
        },
        (None, None, None, None) => VcsBase {
            reporting_state: "not_reported".to_owned(),
            scope: "not_reported".to_owned(),
            commit: None,
            tree: None,
            dirty: None,
            exact_tag: None,
        },
        _ => unreachable!("build.rs emits complete or absent VCS metadata"),
    };

    Ok(BuildIdentity {
        schema_version: "build_identity/v1".to_owned(),
        package: BuildPackage {
            name: env!("CARGO_PKG_NAME").to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        executable: ExecutableIdentity {
            observation_scope: "current_executable_file_at_query".to_owned(),
            sha256: hex::encode(digest.finalize()),
            byte_length,
        },
        target: BuildTarget {
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
        },
        vcs_base,
        authority_effect: "none".to_owned(),
    })
}

fn open_current_executable(path: &Path) -> Result<File> {
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect current executable file {}", path.display()))?;
    if !path_metadata.is_file() || is_reparse(&path_metadata) {
        anyhow::bail!("current executable path must be a regular non-link file");
    }

    let options = OpenOptions::new();
    #[cfg(windows)]
    let mut options = {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        let mut options = options;
        options
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        options
    };
    #[cfg(not(windows))]
    let mut options = options;
    let file = options
        .read(true)
        .open(path)
        .with_context(|| format!("cannot open current executable file {}", path.display()))?;
    let metadata = file
        .metadata()
        .context("cannot inspect opened current executable file")?;
    if !metadata.is_file() || is_reparse(&metadata) {
        anyhow::bail!("opened current executable must be a regular non-link file");
    }
    Ok(file)
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
