#[path = "../../../src/upstream_pins.rs"]
mod production;

pub use production::{
    Admission, AuthorityEffect, EvidenceIntegrityState, EvidenceKind, EvidenceRef, EvidenceStatus,
    ExecutionReadiness, NativePosture, NativeStatus, ReadinessState, ReleaseChannel, ReleaseRef,
    RuntimeClosure, RuntimeKind, TargetArch, TargetOs, TrustedUpstreamPin, UpstreamPin,
    UpstreamSource, all, get_for_tool, summary,
};

use anyhow::Result;
use sha2::{Digest as _, Sha256};

pub fn require_ready_for_planning(tool_manifest_id: &str) -> Result<TrustedUpstreamPin> {
    if tool_manifest_id == "test-execution-boundary" {
        let raw = fixture_raw();
        return Ok(TrustedUpstreamPin {
            pin: serde_json::from_str(raw)?,
            sha256: hex::encode(Sha256::digest(raw.as_bytes())),
            raw,
        });
    }
    production::require_ready_for_planning(tool_manifest_id)
}

pub fn fixture_ref() -> crate::contracts::UpstreamPinRef {
    let pin = require_ready_for_planning("test-execution-boundary").expect("fixture upstream pin");
    crate::contracts::UpstreamPinRef {
        tool_manifest_id: pin.pin.tool_manifest_id,
        pin_sha256: pin.sha256,
    }
}

fn fixture_raw() -> &'static str {
    r#"{"schema_version":"upstream_pin/v1","tool_manifest_id":"test-execution-boundary","repository_url":"https://github.com/example/ewb-test-fixture","source":{"default_branch":"main","commit_sha":"1111111111111111111111111111111111111111","tree_sha":"2222222222222222222222222222222222222222"},"software_version":"test-only","release":null,"evidence":[{"kind":"source_release","id":"test-fixture","name":"package-excluded-test-fixture","subject_commit_sha":"1111111111111111111111111111111111111111","sha256":"3333333333333333333333333333333333333333333333333333333333333333","size_bytes":1,"status":"verified_at_admission","expires_at":null}],"runtime":{"kind":"native","target_os":"windows","target_arch":"x86_64","version_constraint":"test-only","interpreter_included":true,"transitive_dependencies_included":true,"self_contained":true,"external_tools":[]},"native_posture":{"status":"SOURCE_VERIFIED","release_eligible":false},"execution_readiness":{"state":"ready","scope":"package_excluded_test_execution_boundary","blocker_codes":[]},"admission":{"evidence_integrity_state":"verified_at_admission","authority_effect":"none"},"license_spdx":"Apache-2.0"}"#
}
