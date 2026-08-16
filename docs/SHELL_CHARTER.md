# Evidence Workbench shell charter

The workbench is transport and orchestration. It is not an authority.

## Non-negotiable rules

1. Only a native verifier may emit its native result or native authority claim.
2. The workbench never creates an aggregate `PASS`, `FAIL`, score, rank, or certification.
3. Every projected native value points to exact stored bytes by artifact ID, SHA-256, and a JSON pointer or byte range.
4. Artifact handoff preserves the same bytes, digest, and length. Parse-and-reserialize is not handoff.
5. A downstream tool receives upstream output as untrusted input and performs its own admission.
6. Exit codes are recorded exactly. They are never normalized across tools.
7. `BLOCKED`, `UNKNOWN`, `UNSUPPORTED`, `INCONCLUSIVE`, missing output, parse failure, timeout, and spawn failure never become a pass.
8. Authority is never inferred from a tool name, manifest, exit code, checksum, signature presence, or a native verdict.
9. Plans bind the trusted manifest, recorder and adapter implementation, EWB-owned native launcher snapshot, exact subject snapshot, parameters, and direct argv. Execution requires the exact digest returned with the reviewed plan and revalidates those semantics before spawn.
10. Git planning uses a fixed, locked Git identity to create an exact bundle plus deterministic plain-tree artifact. Git execution is Rust-only materialization and pre/post verification of that tree; the bundle is retained for provenance, and execute never launches Git or consults PATH. Artifact execution streams the exact verified CAS object through one source handle into a plan-scoped `create_new` private single-link copy; it never hardlinks, reflinks, parses, or reserializes the input. The original worktree/input is never executed.
11. Python runtime capsules are inventory only. Descriptor-claimed readiness never grants EWB execution admission. `python_runtime_qualification/v1` can record only incomplete, non-authorizing bindings and is not connected to plan or run schemas. `python_runtime_execution_admission/v1` is a sibling binder that may cite that inventory; it cannot grant execution while residual OS-containment checks remain, and it cannot mark those residual checks satisfied. An incomplete inventory record cannot be substituted for an admission record. Python adapters remain fail closed until an operation-scoped admission is granted and the exact upstream pin is `ready`.
12. Capability approval controls which trusted adapter operation EWB will launch. It is not an operating-system sandbox.
13. A candidate pin records exact upstream source, delivery, and integrity-admission facts separately from the executable tool manifest. It supplies no native result or authority and never makes a non-runnable delivery executable.
14. Every production tool has one exact `upstream_pin/v1`. Source completion, CI success, release publication, checksum integrity, native posture, and execution readiness remain separate fields; only an admitted operation-specific runtime closure may be `ready`.
15. An upstream pin always has `authority_effect: none`. Readiness cannot be inferred from a release, Actions artifact, attestation, checksum, native posture label, or process exit.
16. A runnable adapter that references external tools must either bind their exact bytes or deliberately make them unavailable and preserve the resulting native `BLOCKED` observations. It may not silently inherit ambient PATH executables.
17. Every production plan and run binds the exact embedded upstream-pin digest. A qualification-gated operation also binds a durable local qualification record ID and digest; manifest enablement alone never authorizes execution.
18. Qualified native execution uses a private, content-addressed, launcher-only application directory and an EWB-owned empty PATH, checking exact inventories before and after spawn. Remaining same-user namespace races are limitations, not OS-containment claims.
19. Every run names the exact durable source plan ID and digest, and must inherit that plan's tool, upstream/qualification refs, identities, subject, parameters, and invocation without substitution.
20. `runs plan --input-artifact` selects one exact existing artifact ID without searching runs or handoffs. `instrument_run/v1` binds its ID, byte digest, length, and media type but does not claim to bind the enclosing artifact-record digest, roles, origin, capture metadata, transforms, or producer lineage; `source_run_id` remains null.
21. The Trust Meter → Phaseledger vertical slice is exact transport only. Caller-retained `record_digest` values from create/execute/handoff responses are the only acceptable later verify inputs. Downstream tools receive exact artifact ID, descriptor digest, and CAS bytes. EWB never copies Trust Meter `passed`, `overall_score`, or `advisory_gate_met` into a Phaseledger observation. `phaseledger-caller-observation/v1` is a caller cite contract, not a Phaseledger native schema and not an EWB-authored file. Handoff records are auditor lineage; they are not plan inputs. Empty PATH or a Job Object is not an OS sandbox.

## Native-result vocabulary

`instrument_run/v1` has an operational `termination` and two separate native planes:

- `native_result`: namespaced projections from exact native output bytes;
- `native_authority`: only claims explicitly extracted from native bytes.

There is deliberately no shared `status`, `verdict`, `passed`, or `overall_status` field.
