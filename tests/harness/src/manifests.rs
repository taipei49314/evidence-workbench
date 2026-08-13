#[path = "../../../src/manifests.rs"]
mod production;

pub use production::{
    ObservationContract, ToolManifest, TrustedManifest, adapter_implemented, limitation_items,
    production_all, validate_id, validate_manifest, validate_parameters,
};

use crate::contracts::ToolRef;
use anyhow::{Result, bail};
use sha2::{Digest as _, Sha256};
use std::sync::OnceLock;

fn fixture() -> Result<TrustedManifest> {
    static RAW: OnceLock<&'static str> = OnceLock::new();
    let raw = *RAW.get_or_init(|| {
        let rendered = include_str!("../../fixtures/execution-boundary-manifest.json")
            .replace("__EWB_TEST_NATIVE_SHA256__", env!("EWB_TEST_NATIVE_SHA256"));
        Box::leak(rendered.into_boxed_str())
    });
    let manifest: ToolManifest = serde_json::from_str(raw)?;
    validate_manifest(&manifest)?;
    Ok(TrustedManifest {
        manifest,
        sha256: hex::encode(Sha256::digest(raw.as_bytes())),
        raw,
    })
}

pub fn all() -> Result<Vec<TrustedManifest>> {
    let mut entries = production::all()?;
    let fixture = fixture()?;
    if entries
        .iter()
        .any(|entry| entry.manifest.manifest_id == fixture.manifest.manifest_id)
    {
        bail!("integration fixture shadows a production manifest");
    }
    entries.push(fixture);
    entries.sort_by(|left, right| left.manifest.manifest_id.cmp(&right.manifest.manifest_id));
    Ok(entries)
}

pub fn get(id: &str) -> Result<TrustedManifest> {
    validate_id(id)?;
    all()?
        .into_iter()
        .find(|entry| entry.manifest.manifest_id == id)
        .ok_or_else(|| anyhow::anyhow!("unknown trusted tool manifest: {id}"))
}

pub fn get_by_ref(tool_ref: &ToolRef) -> Result<TrustedManifest> {
    let manifest = get(&tool_ref.manifest_id)?;
    if tool_ref.manifest_sha256 != manifest.sha256 {
        bail!(
            "tool reference does not match the exact embedded manifest: {}",
            tool_ref.manifest_id
        );
    }
    Ok(manifest)
}
