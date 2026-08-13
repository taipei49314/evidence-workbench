#![allow(dead_code)]

#[path = "../../../src/candidate_pins.rs"]
pub mod candidate_pins;
#[path = "../../../src/cli.rs"]
pub mod cli;
#[path = "../../../src/contracts.rs"]
pub mod contracts;
#[path = "../../../src/data_contract_validation.rs"]
pub mod data_contract_validation;
#[path = "../../../src/git_subject.rs"]
pub mod git_subject;
#[path = "manifests.rs"]
pub mod manifests;
#[path = "../../../src/native.rs"]
pub mod native;
#[path = "../../../src/run_validation.rs"]
pub mod run_validation;
#[path = "../../../src/runtime_capsules.rs"]
pub mod runtime_capsules;
#[path = "../../../src/strict_json.rs"]
pub mod strict_json;
#[path = "../../../src/subject_candidates.rs"]
pub mod subject_candidates;
#[path = "../../../src/upstream_pins.rs"]
pub mod upstream_pins;
#[path = "../../../src/workspace.rs"]
pub mod workspace;

#[cfg(test)]
mod run_semantics;
