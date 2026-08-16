# Integration data contracts

These contracts are transport boundaries. They do not create a shared verdict or
authority.

- `ewb-cli-envelope/v1` closes the common `--json` success and failure objects
  without changing the established CLI bytes. Its version is selected out of
  band rather than carried in a new top-level field. Success contains exactly
  `ok`, `command`, and opaque command-owned `data`; failure contains exactly
  `ok` and a closed `error` object with `code` and `message`. The envelope's
  `ok` reports EWB command completion, never a native result, aggregate verdict,
  or authority claim. Process exit remains a separate transport signal; in
  particular, `runs execute` can commit an `ok: true` run envelope and exit `4`
  when the native process did not exit normally.
- `subject-candidate/v1` carries an untrusted `github-radar` discovery. EWB must
  independently resolve the exact commit and tree before admission. Its
  `candidate_id` is the first 128 bits of SHA-256 over the NUL-joined schema,
  producer id/version, repository URL, commit, tree, source artifact id, and
  source SHA-256; the source must be an existing exact-byte EWB artifact with
  the sole `github_discovery` role.
- `runtime-capsule/v1` inventories the launcher and its transitive supporting
  files for one platform and operation scope. Incomplete closure, unresolved
  platform assumptions, or missing qualification evidence cannot be `ready`.
  `supporting_files` must be ordered lexicographically by `path`, and
  `transitive_closure.inventory_digest` is SHA-256 of that array serialized as
  compact JSON from the typed field order. The launcher is bound separately and
  is not counted in that digest.
- `python_runtime_qualification/v1` is an EWB-created, Windows x86-64,
  single-operation inventory binding. It binds the exact runtime-capsule record,
  embedded manifest and fail-closed upstream pin, EWB recorder, CPython archive
  artifact, `python*._pth` capsule snapshot, canonical wheel/installed-RECORD
  pairs, fixed wrapper artifact, declarative isolated argv/environment/layout,
  and exactly eight checks. Every check is schema-closed to
  `not_implemented`; the only qualification state is `incomplete` with all
  eight check codes as sorted blockers. It has no successful state and
  `authority_effect` is `none`.
- `python_runtime_qualification_record/v1` wraps that payload under an opaque
  `qualification_<32hex>` locator. Its `record_digest` is SHA-256 over compact
  typed payload JSON, not the enclosing registry file. Artifact bindings pair
  the existing raw-digest `ArtifactRecordRef` with a `Digest` for original
  artifact bytes and an exact byte length. The ID and hashes prove neither
  producer authenticity nor execution readiness.
- `ide-handoff/v1` gives an IDE immutable plan, run, and artifact references plus
  native namespace and authority-availability metadata. It carries no command,
  arbitrary argument vector, aggregate verdict, or synthesized pass state. It
  remains a backward-compatible, reference-only optional projection; it is not
  the canonical integration carrier. The canonical boundary is the EWB JSON
  envelope, exact CAS artifacts, and immutable plan/run identities and digests.
- `evidence-handoff/v1` is a reference-only descriptor for exactly one producer
  plan record, producer run record, and captured artifact record. Its
  relationship is fixed to `captured_run_artifact`; a consumer must treat the
  referenced artifact as `untrusted_exact_bytes`, and `authority_effect` is
  fixed to `none`. It cannot carry a command, argument vector, parameters,
  capabilities, status, verdict, pass state, score, or authority claim. Parsing
  validates the closed shape, IDs, digests, and timestamp only. The
  `evidence_handoff_record/v1` workspace registry separately reloads all three
  records, verifies the run-to-plan link, confirms that the complete artifact
  descriptor occurs exactly once in the run, and re-verifies its CAS bytes on
  create, list, show, and verify. Each referenced `record_digest` is EWB's
  SHA-256 over compact typed JSON: `PlanPayload`, `InstrumentRun`, or
  `ArtifactDescriptor`, respectively. The handoff registry record digest is the
  same construction over its `EvidenceHandoff` object. None is the raw SHA-256
  of an enclosing registry-record file. `handoff_id` is only an opaque typed ID
  in v1; it is not a content digest, authenticity proof, or source of trust.
  Strict Rust loading requires the registry filename to match the wrapped
  handoff ID.
- `audit-topology/v1` is a closed portable grouping of claimed exact
  `PlanRecordRef` values in a static DAG. Every step has a typed opaque step ID,
  one claimed plan ID and plan-record digest, and zero or more declared
  predecessor step IDs. If a future workspace-aware carrier verifies the
  reference, that exact referenced plan remains the sole binding for
  its tool, subject or artifact input, parameters, capabilities, and direct
  invocation; the topology cannot restate or override any of them. A
  predecessor is only a structural declaration. Standalone parsing does not
  prove temporal planning, capture, or execution order, and array position has
  no such meaning. Steps and each predecessor list use canonical lexicographic
  ID order so a single typed value has one compact serialization. Immutability
  follows only if a future carrier retains and verifies that exact value and its
  digest. There are no
  required/optional, condition, retry, artifact-role selector, result, status,
  completeness, or authority fields.
- `audit-receipt/v1` is a portable reference object for one exact typed audit
  topology and a canonical, nonempty, possibly incomplete subset of its steps'
  plan/run record references. Its topology digest is SHA-256 over the compact
  typed `AuditTopology` JSON field order, not the raw bytes of a topology file.
  A receipt intentionally has no receipt ID or timestamp; a future outer
  registry, if implemented, must own record identity and capture metadata.
  Standalone parsing checks only the closed shape, typed IDs, digests,
  uniqueness, and canonical order. Cross-contract validation additionally
  checks the topology ID/digest, step membership, and exact plan-ref equality.
  It does not access a workspace and therefore does not prove that a plan or run
  exists, that the run names the plan, that predecessors ran first, or that any
  artifact lineage is valid. The receipt can reference a run whose termination
  was nonzero, timed out, or failed to spawn without copying or interpreting
  that fact. It cannot carry a native result, termination, aggregate overall,
  pass/fail, verdict, score, rank, trust, certification, command, argv,
  condition, capability, or authority claim. `authority_effect` is fixed to
  `none`.

The typed `topology_digest` binds only the serialized topology value's integrity
and identity. It is not producer authenticity, proof of plan existence or
review, or a source of native or workbench authority.

These two audit contracts define no CLI, workspace registry, initialization,
execution, scheduling, or record-verification behavior. Artifact data flow
continues to use separately verified `evidence-handoff/v1` records; neither
contract selects an artifact by role or infers a handoff from a run.

Every object shape is closed with `additionalProperties: false`. Rust parsing
also rejects duplicate JSON keys and applies semantic cross-field validation.

`python_runtime_execution_admission/v1` is a sibling of the incomplete
inventory qualification. It cites one `python_runtime_qualification_record/v1`
by ID and caller-retained digest, binds one allowlisted operation
(`trust_meter_measure` or `phaseledger_measure`), and records the same eight
check codes. Implementable checks may be `satisfied`, `not_implemented`, or
`failed`. `python-admissions admit` now proves the five implementable
checks from exact CAS bytes without spawning Python: CPython zip
semantics, wheel/RECORD closure, isolated `_pth` grammar, the fixed
launch contract plus embedded wrapper digest, and a disposable private
materialization with pre/post inventory. Residual containment checks
(`os_network_egress_denial`, `python_active_process_limit_one`,
`python_creation_time_job_assignment`) are recorded as `failed` because
spawnless `admit` cannot CreateProcess-assign `python.exe`, apply a
network filter to that process, or observe an ActiveProcessLimit of one
on it. An empty Job Object is not those proofs. Residual checks cannot
be `satisfied`. The only admission state is `not_granted`, and
`authority_effect` is `none`. Inventory
presence does not grant admission. `python_runtime_execution_admission_record/v1`
wraps that payload under an opaque `admission_<32hex>` locator; its
`record_digest` is SHA-256 over compact typed payload JSON.

`python_runtime_execution_admission/v2` is a prove record, not an execution
permit. `python-admissions prove-containment --admission` cites one verified
v1 admission and may start the bound `python.exe` with fixed
`-I -S -B -X utf8 -c raise SystemExit(0)` only to CreateProcess-assign it
through `PROC_THREAD_ATTRIBUTE_JOB_LIST` and observe ActiveProcessLimit=1.
`admit` never calls that path and still does not spawn Python. Job-assignment
and process-limit checks may be `satisfied`. `os_network_egress_denial`
stays `failed` because a Job Object is not a network filter. The only
admission state is still `not_granted`. An empty Job Object or a post-start
`AssignProcessToJobObject` is not creation-time assignment.

`python_runtime_execution_admission/v3` is a prove-network record, not an
execution permit. `python-admissions prove-network --admission` cites one
verified v2 admission and may start the bound `python.exe` with fixed
`-I -S -B -X utf8` plus a loopback connect script only to CreateProcess it
through `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` (AppContainer, zero
capabilities) together with the same creation-time Job Object limits.
`os_network_egress_denial` may be `satisfied` only when the process token is
an AppContainer, the child exits the denied-connect protocol, and the parent
listener never accepts. `admit` and `prove-containment` never call that path.
v2 still cannot mark network denial satisfied. The only admission state is
still `not_granted`. A Job Object, an empty PATH, or an AppContainer SID
without the connect observation is not network denial. WFP is out of scope.

An immutable Python runtime snapshot is not implemented.
`python_runtime_qualification/v1` and `python_runtime_execution_admission/v1`
through `/v3` are not that snapshot. A later snapshot would have to bind
the official CPython embed archive digest, the admitted isolated `_pth`,
and each wheel/RECORD pair by artifact ID, SHA-256, and length. The
disposable EWB prove root is not that binding. This does not close
`python_runtime_snapshot_unimplemented` or set pin `ready`. See
[`docs/verification/python-runtime-snapshot.md`](verification/python-runtime-snapshot.md).

`phaseledger-caller-observation/v1` is a caller-authored cite contract for a
future Phaseledger 0.6.0 observation file. It requires a present exact artifact
ID, matching SHA-256, a claim that names that ID/digest plus
`untrusted_exact_bytes` and `authority_effect none`, and caller-authored
checks whose names cannot be Trust Meter fields (`passed`, `overall_score`,
`advisory_gate_met`, `threshold_met`, `all_metrics_passed`). Freshness and
producer-run scope are explicitly `unsupported`. EWB does not write this
object and does not map Trust Meter projections into it. Mapping to native
Phaseledger `measure` JSON is a caller responsibility.

Trust Meter → Phaseledger vertical-slice completion requires all of the
following on a fresh workspace. None of these is implied by a schema existing
or a registry record being present:

1. Every plan, run, and handoff retains the `record_digest` returned at create
   time. Later `show` output cannot replace that caller-retained digest.
2. Downstream inputs are exact artifact ID, descriptor digest, and CAS bytes.
   Role, tool name, and registry presence do not identify a producer.
3. `handoffs create` still requires the artifact to appear exactly once in the
   producer run's recorded artifacts.
4. Digest mismatch, CAS tamper, missing predecessor records, spawn failure,
   timeout, and unknown native exits fail closed.
5. EWB has no path that writes Trust Meter `passed`, `overall_score`, or
   `advisory_gate_met` into a Phaseledger observation.
6. Phaseledger `VERDICT:` and exit remain native envelope fields. EWB `ok`
   reports command completion only.
7. After restart, `handoffs verify`, `artifacts verify`, and `runs show` agree
   on the same IDs and caller-retained digests.
8. Non-TomorrowCI tools stay `fail_closed` and `enabled_by_default: false`
   until an operation-scoped admission is granted and the exact pin blockers
   are actually closed. Residual containment blockers remain named; they are
   not an OS sandbox. `python_runtime_snapshot_unimplemented` remains; the
   prove root is not that snapshot.

`ewb runs plan --input-artifact` remains a separate surface from
`ewb handoffs`. A handoff ID is not an artifact ID. Planning does not scan
`.ewb/handoffs`.

The Trust Meter machine adapter is `--json-v1 --no-config` only. That closed
interface selects Trust Meter's fixed `builtin-static-v1` collectors. Ambient
ancestor `.trust-meter.toml` is not a measurement input. Exact `--config` file
binding remains reserved. Selectors are `/result/advisory_gate_met`,
`/result/threshold_met`, and `/result/overall_score`; `/passed` is not a
selector. Pin `execution_readiness` stays `fail_closed` in this slice.

The Python qualification registry is `.ewb/python-qualifications`. The Python
execution-admission registry is `.ewb/python-admissions`. Upgrading
an existing workspace requires rerunning idempotent `ewb init` once; reads fail
closed if the directory is absent, linked, contains an unexpected entry, or if
any listed record/reference/CAS object fails re-verification. `create`, `list`,
`show`, and `verify` never spawn a process and never write a plan, run, or
execution directory. `create` writes only the exact embedded wrapper artifact
and its own atomic unique registry record after caller-input preflight. That
inventory command still does not change readiness. `python-admissions admit`
writes a sibling not-granted record and may bind `python_admission_ref` on a
plan/run; it does not set `enabled_by_default` or pin `ready`. `NativeQualificationRef`
remains TomorrowCI-only.

Runtime-capsule descriptor readiness is not EWB execution admission. Capsule
verification reports the descriptor values only as `descriptor_claimed_*` and
reports fixed EWB admission as `fail_closed` /
`python_runtime_qualification_not_connected`. Python planning ignores the
descriptor claim and remains blocked because this incomplete qualification
registry is intentionally not connected to planning.

`ewb handoffs create` requires `--source-run <RUN_ID>`,
`--source-run-digest <SHA256>`, and `--artifact <ARTIFACT_ID>`. It accepts no
plan reference, command, argument vector, or authority input. It requires the
caller-retained producer-run digest, derives the plan reference from that
verified run, and derives the artifact record digest from the exact matching
workspace record. Create performs that complete preflight before its atomic
unique write, then reloads and re-verifies the persisted record before
returning. `handoffs verify` additionally requires the caller-retained handoff
digest. `handoffs show` and `list` are inspection surfaces, but repeat the same
full workspace-lineage and exact-byte checks. A successful EWB command only
means those checks completed; it is not a native or aggregate verdict.

`ewb runs plan --input-artifact <ARTIFACT_ID>` is a separate artifact-subject
selection surface, not a handoff lookup. For an artifact-scoped adapter it
reloads the named `artifact_record/v1`, re-verifies its exact CAS bytes, and
reuses the selected descriptor without importing or reserializing bytes. The
existing `Subject::Artifact` v1 plan fields bind only the exact artifact ID,
SHA-256, byte length, media type, execution path, and `source_run_id: null`.
They do not bind the enclosing artifact record digest, roles, origin, capture
mode, transforms, or producer provenance. No run or handoff registry is scanned
and no producer is inferred. The plan-time semantic validator reloads the same
artifact binding before the plan is committed. Execution separately copies the
CAS bytes through one verified handle into a plan-scoped private `create_new`
file; it never hardlinks, reflinks, parses, or reserializes the input.

`--input <FILE>` remains the distinct new-import path. Its default media type is
`application/json`, and `--input-media-type` is accepted only with that option.
`--input-artifact` is mutually exclusive with both `--input` and `--subject`.

`ewb candidates import --file <FILE>` first parses the exact descriptor bytes
and verifies the full source artifact record digest, descriptor digest, object
length, and object SHA-256 in the same workspace. Only then does it copy the
unchanged candidate bytes into EWB-owned CAS and create
`subject_candidate_record/v1` under `.ewb/candidates`. The record digest binds
the parsed candidate, exact descriptor hash and artifact id, and source
artifact record digest. `candidates list`, `show`, and `verify` repeat those
checks and cannot resolve, clone, admit, plan, or execute a subject.

`ewb capsules admit --descriptor <FILE> --root <DIRECTORY>` additionally proves
that the root contains exactly the launcher and inventoried files, rejects links
and reparse points, verifies every length and SHA-256, verifies all qualification
artifact references already held by the workspace, and copies each exact file
into EWB-owned content-addressed storage. The registry record digest binds the
exact descriptor bytes, parsed contract, and every snapshot. Admission and
qualification evidence retain `authority_effect: none`.

`native_delivery_qualification/v1` binds one qualified native operation to exact
local evidence. `qualifications admit` imports the raw descriptor, candidate
manifest, checksum ledger, Windows archive, extracted EXE, and PE report into
the workspace CAS. Its record ID derives from the raw descriptor bytes. EWB
re-parses candidate/checksum evidence and independently derives the PE32+ x86-64
import table and empty delay-import table from the exact EXE at admission and
every load. Plans and runs bind both this record digest and the exact embedded
upstream-pin digest; remote Actions expiry is provenance, never a runtime input.

This pre-release `instrument_run/v1` contract is replaced in 0.2 to require
`source_plan_ref`, `upstream_pin_ref`, and `native_qualification_ref` (nullable
only for operations that do not use a native qualification). Run loading
revalidates the durable source plan ID/digest and requires every execution input
to match that plan exactly. Older envelopes are rejected instead of silently
receiving an authority-bearing default.

The PE evidence field `verifier_contract_sha256` is the SHA-256 of the closed
verifier contract identifier, not an implementation-binary identity. The
current EWB implementation independently re-parses the exact EXE during every
admission and reload; plan/run records separately bind the EWB recorder and
adapter implementation digest.
