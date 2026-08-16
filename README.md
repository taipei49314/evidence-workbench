# Evidence Workbench

Evidence Workbench (`ewb`) is a thin execution and artifact shell for Nelson's evidence-first tools. It plans direct invocations, pins immutable subjects and tool identities, captures exact native bytes, and records namespaced native observations.

It is deliberately **not** a verifier, certification service, monorepo, shared runtime, or aggregate scoring engine. The governing rules are in [`docs/SHELL_CHARTER.md`](docs/SHELL_CHARTER.md).

## Current v0.2 scope

The embedded `upstream_pin/v1` registry covers all twelve trusted tool manifests with an exact source commit/tree, delivery evidence, native posture, runtime closure, and a separate execution-readiness decision. `tools list`, `tools show`, `doctor`, and `init` expose those records. Every pin has `authority_effect: none`; a CI result, checksum, release, or attestation cannot make an adapter authoritative.

| Tool ID | Native role | Windows execution readiness |
|---|---|---|
| `walkaround` | Session admission | Fail closed: catalog only; Python capsule, mutable session subject, and capability-separated operations are missing |
| `charterlock` | Exam-charter admission | Fail closed: catalog only; Python capsule, bound multi-artifact inputs, and capability-separated operations are missing |
| `tomorrowci-lab` | Fixed trust-behavior audit | Ready only with an exact durable local qualification; fixed candidate `trust --json`, Windows 10 x86_64, authority none |
| `stateweaver-foundation` | Fixed synthetic foundation verification | Fail closed: Linux wheels, no interpreter |
| `greenwash` | Verification-integrity diff | Fail closed: Python capsule, Git metadata, and fixed execution-time Git are missing |
| `repopass-inspect` | Offline repository inspection | Fail closed: source qualification blocked; no admitted Windows executable; Git dependency unbound |
| `trust-meter` | Advisory structural measure | Fail closed: Python capsule and ambient ancestor config isolation missing |
| `phaseledger` | Caller-observation gate | Fail closed: pin at v0.6.0 (`--version` exists); exact-byte capsule admission exists; OS-enforced no-network/process containment is not implemented |
| `unasked` | Research/authority workflow | Fail closed: runtime/Git closure, non-certifying posture, and proprietary redistribution boundary |
| `normshift` | Standards semantic-change replay | Fail closed: Python capsule and multi-file source bundle missing |
| `smallestlie` | Authorized falsification | Fail closed: runtime, authorization, process-tree, and OS egress containment missing |
| `nullbench` | Preregistered experiment | Fail closed: runtime, directory subject, and capability-separated operations missing |

TomorrowCI is the only ready production adapter and remains qualification-gated. The other eleven fail closed. Readiness requires the complete operation-specific closure plus an exact local qualification record; a launcher hash or manifest flag alone is insufficient.

## Neutral integration boundary

The canonical neutral integration boundary is the `ewb --json` envelope plus
content-addressed exact artifacts and immutable plan/run IDs and digests. An
IDE or other UI may consume those references, but remains optional and gains no
authority. The contract-only `audit-topology/v1` groups claimed exact plan
references in a static acyclic predecessor graph, and `audit-receipt/v1` can
carry a nonempty partial set of claimed exact plan/run references without a
completeness or success claim. These portable objects do not add CLI commands,
workspace registries, scheduling, execution, or workspace-aware verification;
multi-tool composition is therefore not implemented yet. They are contract
groundwork, not a claim that a complete multi-tool carrier has landed.

StateWeaver's completed upstream candidate is recorded separately in a strict `candidate_pin/v1`: source commit `598753d182dda65c73a313e9efbf20b826942f0a`, payload-manifest SHA-256 `8c7c77d59d4cf3abdcadcce3f2d110ca085789da1ec14a2301245f3418b78bc3`, and candidate workflow run `31711437241`. At admission, all 113 listed checksums matched and the payload-manifest OIDC attestation verified. This is an integrity/provenance admission, not native authority.

The adapter remains experimental and cannot accept an arbitrary repository. The candidate itself reports `CANDIDATE_READY_FOR_EXTERNAL_QUALIFICATION` and `release_eligible=false`; it targets Linux x86_64 CPython 3.13 and includes wheels but no Python interpreter. It is therefore not an execution capsule for the current Windows EWB. Python-backed adapters continue to fail closed at planning until EWB can snapshot the complete interpreter, runtime, distribution, and transitive dependency closure. The GitHub Actions artifact expires on 2026-11-11, and EWB does not silently treat that remote artifact as durable or available.

Planning snapshots self-contained native launcher bytes into EWB-owned storage. For a Git subject, planning resolves one canonical Git executable, retains a Windows read-only/no-write-sharing handle while it hashes and invokes that exact path, and verifies the same open file afterward. Git for Windows is not a self-contained `git.exe`, so its staged byte copy is review evidence only and the host installation is explicitly recorded as an unsnapshotted **plan-time** dependency. Planning uses Git to produce both an exact bundle and a deterministic plain-tree artifact; execution uses Rust only to materialize and verify that tree and never resolves Git or PATH. The bundle remains provenance/transport, not the execution source. Artifact subjects execute from a verified private copy. Native execution is currently Windows-only; Unix planning fails closed until descriptor-based exec removes the remaining path-replacement race.

The Git execution tree intentionally contains tracked working-tree files without `.git` metadata, links, or reparse points. Adapters that require repository metadata remain disabled until EWB defines and snapshots that metadata safely.

## Install

Rust 1.85+ is supported. CI tests both the declared Rust 1.85 minimum and the current stable toolchain on Windows and Ubuntu:

```powershell
cargo install --path . --locked
ewb --help
```

Or run [`scripts/install-local.ps1`](scripts/install-local.ps1).

The install script records the checkout's builder-observed Git base and then
verifies the installed executable with:

```powershell
ewb --json build show
```

`build show` is workspace-independent and read-only. It always hashes the
current executable file. VCS fields are either `not_reported` or explicitly
`builder_asserted`; EWB never invokes Git at query time and does not treat the
record as a source attestation. A dirty checkout reports only its HEAD commit
and tree as a builder-recorded base with `dirty: true`, never as the source of
the built bytes. An exact tag is reported only for a clean base with exactly
one tag at HEAD; a clean untagged base keeps commit/tree and reports
`exact_tag: null`. Trusted builders set `EWB_BUILD_VCS_COMMIT`,
`EWB_BUILD_VCS_TREE`, and `EWB_BUILD_VCS_DIRTY` together, with optional
`EWB_BUILD_VCS_TAG`; partial, mixed-object-format, dirty-tagged, or malformed
metadata fails the build. Direct `cargo install --path .` builds intentionally
report `not_reported` unless those variables are supplied by a trusted builder.
CI installs from Cargo's extracted packaged source before checking this
contract, rather than reinstalling from the checkout. On Windows the
executable file is held without write/delete sharing while it is hashed. On
Unix this remains a path-based file observation with an explicit same-user
replacement race; neither platform claims to attest the already-loaded process
image.

## Start

Initialize a directory that will own the evidence registry:

```powershell
ewb --json --workspace C:\evidence-workspace init
ewb --json --workspace C:\evidence-workspace doctor
ewb --json tools list
```

`doctor` is read-only and does not launch native version commands. `tools probe` is also rejected for every `fail_closed` adapter; it may launch a version probe only after a future production adapter has an admitted complete runtime closure. Trusted manifests are compiled into the `ewb` binary; files placed under `.ewb/manifests` cannot grant a new executable, capability, result, or authority claim.

`.ewb/handoffs`, `.ewb/python-qualifications`, and `.ewb/python-admissions` are required workspace
directories. After upgrading an existing workspace, run the same idempotent
`ewb --json --workspace <PATH> init` command once to add either missing
directory. Until then, normal workspace opens and registry commands fail
closed, while `doctor` reports the layout as unhealthy. A missing registry
directory is never treated as an empty registry.

The durable registries have symmetric read-only inspection surfaces:

```powershell
ewb --json --workspace C:\evidence-workspace plans list
ewb --json --workspace C:\evidence-workspace plans show <PLAN_ID>
ewb --json --workspace C:\evidence-workspace artifacts list
ewb --json --workspace C:\evidence-workspace artifacts show <ARTIFACT_ID>
ewb --json --workspace C:\evidence-workspace qualifications list
ewb --json --workspace C:\evidence-workspace python-qualifications list
ewb --json --workspace C:\evidence-workspace python-admissions list
ewb --json --workspace C:\evidence-workspace handoffs list
ewb --json --workspace C:\evidence-workspace handoffs show <HANDOFF_ID>
```

Each command returns the complete stored record only after re-verifying its
record digest and all locally bound bytes. A list is atomic: one malformed,
linked, unexpected, or stale registry entry fails the whole command rather than
returning partial data. A digest read back through `plans show` or
`handoffs show` is inspection data; it must never replace the digest retained
when the plan or handoff was created. Likewise, `handoffs create` requires the
source-run digest retained from the original `runs execute` response; a current
digest reread through `runs show` or `runs list` cannot replace that retained
identity after registry state has been rewritten.

### Runtime capsule registry

An explicit local capsule can be imported only from a closed root whose files
exactly match `runtime-capsule/v1`:

```powershell
$capsule = ewb --json --workspace C:\evidence-workspace capsules admit `
  --descriptor C:\capsules\phaseledger\runtime-capsule.json `
  --root C:\capsules\phaseledger\runtime | ConvertFrom-Json

ewb --json --workspace C:\evidence-workspace capsules verify `
  $capsule.data.capsule_id
```

`capsules snapshot` walks a closed root and writes a `runtime-capsule/v1`
descriptor. It never admits the capsule, never plans, and the descriptor is
always `fail_closed` (`python_capsule_execution_containment_unimplemented`
plus any missing stdlib or qualification). A host copy is not a qualified
embeddable distribution.

```powershell
ewb --json capsules snapshot `
  --root C:\capsules\phaseledger\runtime `
  --out C:\capsules\phaseledger\runtime-capsule.json `
  --tool phaseledger --operation phaseledger_measure
```

`scripts/snapshot-phaseledger-runtime.ps1` copies the host `python.exe`,
sibling interpreter DLLs/zip, and the installed `phaseledger` package into
`artifacts/phaseledger-runtime/runtime/` (gitignored) and runs that command.
The resulting tree is for local admission experiments only.

`admit` never downloads or installs anything. It rejects extra, missing,
linked, reparse, or hash-mismatched files; all qualification evidence must
already exist as exact workspace artifacts. `list`, `show`, and `verify`
revalidate registry records and EWB-owned object bytes. A capsule descriptor's
`readiness` and blocker list are only descriptor claims. `capsules verify`
reports those under `descriptor_claimed_readiness` and
`descriptor_blocker_codes`; its compatibility `readiness` is EWB's fixed
`fail_closed` admission with `python_runtime_qualification_not_connected`.
`execution_admission` remains `not_granted_by_runtime_capsule`. Capsule
admission does not create a native result, trust claim, or authority.

### Incomplete Python runtime qualification registry

`python-qualifications create` binds one re-verified exact-byte,
single-operation Python capsule record to an exact embedded manifest and exact
fail-closed upstream pin, one
existing CPython archive artifact, a capsule-owned `python*._pth` snapshot,
and one or more existing wheel artifacts paired with capsule-owned
`.dist-info/RECORD` snapshots:

```powershell
$qualification = ewb --json --workspace C:\evidence-workspace python-qualifications create `
  --capsule $capsule.data.capsule_id `
  --cpython-archive-artifact $cpythonArchive.data.artifact_id `
  --path-configuration python313._pth `
  --wheel-artifact $phaseledgerWheel.data.artifact_id `
  --installed-record-path site/phaseledger-0.6.0.dist-info/RECORD | ConvertFrom-Json

ewb --json --workspace C:\evidence-workspace python-qualifications verify `
  $qualification.data.qualification_id
```

Repeat `--wheel-artifact` and `--installed-record-path` in corresponding
pairs. EWB canonicalizes the retained pairs by wheel-byte digest and RECORD
path; artifact IDs and RECORD paths must be unique, including Windows ASCII
case folding for paths. Distinct artifact records containing identical wheel
bytes are not collapsed: each exact artifact record remains a separate caller
selection and is paired with its own distinct RECORD path.

This v1 can represent only eight sorted `not_implemented` checks and an
`incomplete` state carrying all eight blocker codes. There is no `verified`,
`ready`, `requirements_met`, success, verdict, or authority-bearing state in
the schema or Rust type. The fixed launch description (`-I -S -B -X utf8`, no
environment inheritance, private runtime/subject/scratch layout, empty PATH)
is a future qualification target, not an implemented launcher. The fixed
embedded wrapper is captured as an exact artifact under
`evidence-workbench-python-runtime-wrapper/v1`; changing its LF-pinned bytes
requires a new wrapper contract ID.

Create validates all caller-selected references before capturing that wrapper,
then atomically creates a unique record and reloads it. `list`, `show`, and
`verify` revalidate the capsule record and CAS, manifest and upstream-pin
digests, recorder identity, wrapper bytes, every artifact record, and every CAS
object; list is all-or-nothing. These commands never spawn Python, inspect a
target, or write `.ewb/plans`, `.ewb/runs`, or `.ewb/executions`. Exit 0 from
create means only that an incomplete record was safely stored. Python planning
still fails with `python_runtime_qualification_not_connected`, regardless of a
capsule descriptor's claimed readiness. The opaque `qualification_<32hex>` ID
is a registry locator, not a trust statement or content digest.

`python-admissions admit` cites one verified incomplete inventory record and
re-proves the five implementable checks from exact CAS bytes without spawning
Python: CPython zip semantics, wheel/RECORD closure, isolated `_pth` grammar,
the fixed launch contract plus embedded wrapper digest, and a disposable
private materialization. Residual containment checks cannot be marked
satisfied. The sibling `python_runtime_execution_admission/v1` stays
`not_granted`. The record may be bound as `python_admission_ref` on a later
plan; it does not set `enabled_by_default` or pin `ready`, and it cannot be
replaced by a `qualification_*` inventory ID.

```powershell
$admission = ewb --json --workspace C:\evidence-workspace python-admissions admit `
  --inventory-qualification $qualification.data.qualification_id | ConvertFrom-Json
ewb --json --workspace C:\evidence-workspace python-admissions verify `
  $admission.data.admission_id
```

An official CPython Windows embed zip can be supplied by the operator and
admitted the same way. EWB does not vendor or download that zip. The stock
`python313._pth` must be replaced with the isolated grammar before admit;
comments and `#import site` fail closed. Five implementable checks may then
be `satisfied` while admission stays `not_granted` and the Trust Meter /
Phaseledger pins stay `fail_closed`. See
[`docs/verification/python-admission-real-embed.md`](docs/verification/python-admission-real-embed.md).

### Untrusted GitHub discovery handoff

`github-radar` discovery remains outside EWB's trusted execution plane. First
capture the exact radar report with its required `github_discovery` role, then
ask the producer to bind that existing EWB artifact record to the observed
commit and tree. Finally import the exact candidate bytes:

```powershell
$source = ewb --json --workspace C:\evidence-workspace artifacts add `
  --file C:\evidence\radar-report.json --role github_discovery `
  --media-type application/json | ConvertFrom-Json

python -m radar ewb-candidate --repo owner/name `
  --source-report C:\evidence\radar-report.json `
  --source-artifact-record (Join-Path C:\evidence-workspace ".ewb\artifacts\$($source.data.artifact_id).json") `
  --output C:\evidence\candidate.json

$candidate = ewb --json --workspace C:\evidence-workspace candidates import `
  --file C:\evidence\candidate.json | ConvertFrom-Json
ewb --json --workspace C:\evidence-workspace candidates verify `
  $candidate.data.candidate_id
```

`candidates import` supports only `subject-candidate/v1`. It strictly parses
the exact supplied bytes, re-hashes the referenced source artifact record and
object already in the same workspace, captures the candidate itself in CAS,
and creates a content-digested registry record. `list`, `show`, and `verify`
repeat all checks. These commands perform no network request, clone, subject
resolution, admission, planning, or execution. The result remains
`trust_state: untrusted_candidate`, requires an independent EWB commit-and-tree
re-resolution before any future admission, and always has
`authority_effect: none`.

### Greenwash future invocation (currently fails closed)

Both revisions must be exact lowercase Git object IDs and the subject checkout must be clean:

```powershell
$base = git -C C:\repo rev-parse HEAD~1
$plan = ewb --json --workspace C:\evidence-workspace runs plan `
  --tool greenwash `
  --subject C:\repo `
  --param "base_revision=$base" | ConvertFrom-Json

ewb --json --workspace C:\evidence-workspace runs execute `
  --plan $plan.data.plan_id `
  --plan-digest $plan.data.record_digest `
  --allow read_subject `
  --allow invoke_fixed_git
```

`runs plan` snapshots the native tool but never launches it, including its version probe. Git-subject planning does invoke the fixed, locked plan-time Git identity to create the bundle and tree artifacts; no Git process is launched by `runs execute`. Keep the returned `record_digest` with the reviewed plan; `runs execute` requires that exact digest and then revalidates the manifest, EWB recorder/adapter implementation, staged native bytes, bundle references, tree artifact, parameters, and full argv before spawning. Each persisted run retains `source_plan_ref` and reload requires the durable plan ID/digest plus every inherited execution input to match. Do not reread a replacement digest from `.ewb/plans`. Original source worktree, native launcher, Git PATH, and Git installation drift after planning do not change the planned execution; staged or stored snapshot drift fails closed.

### TomorrowCI qualified bounded trust audit

```powershell
$qualification = ewb --json --workspace C:\evidence-workspace qualifications admit `
  --descriptor C:\qualification\native-delivery-qualification.json `
  --root C:\qualification | ConvertFrom-Json
$plan = ewb --json --workspace C:\evidence-workspace runs plan `
  --tool tomorrowci-lab `
  --runtime-qualification $qualification.data.qualification_id | ConvertFrom-Json
ewb --json --workspace C:\evidence-workspace runs execute `
  --plan $plan.data.plan_id `
  --plan-digest $plan.data.record_digest `
  --allow inspect_host_tooling
```

The admitted master candidate is statically linked and its built-in PE parser-derived import set is exactly `KERNEL32.DLL`, `NTDLL.DLL`, `BCRYPTPRIMITIVES.DLL`, and the Windows API-set synchronization contract, with no delay imports or `VCRUNTIME140.dll`. EWB binds candidate manifest, checksum ledger, archive, EXE, PE evidence, upstream pin, and local record digest; it materializes a private launcher-only application directory and supplies an exact-empty PATH. `verifier_contract_sha256` hashes the parser contract identifier; it is not presented as an implementation digest. EWB itself re-parses the exact EXE at admission and every reload, while plan/run records bind the EWB implementation. T5 and T8 therefore remain native `BLOCKED` observations. `/overall`, `/probes/4/verdict`, and `/probes/7/verdict` remain separate projections and none supplies authority.

### RepoPassport future local inspect (currently fails closed)

```powershell
ewb --json --workspace C:\evidence-workspace runs plan `
  --tool repopass-inspect --subject C:\repo
```

Planning is disabled until an exact Windows executable is admitted and its optional Git subprocess dependency is eliminated or immutably bound. Even then, `inspect` would not run a scenario or establish a RepoPassport verification verdict; RepoPassport exit `0` would remain command completion only.

### trust-meter and phaseledger vertical slice (currently fail closed)

They remain separate native runs. The Trust Meter adapter's only machine argv is
`<git-root> --json-v1 --no-config --threshold <N> --phase <P>`, which selects
the fixed `builtin-static-v1` collectors and refuses ambient
`.trust-meter.toml`. Observation selectors are `/result/advisory_gate_met`,
`/result/threshold_met`, and `/result/overall_score`. There is no `/passed`
selector. EWB does not copy those projections into a Phaseledger observation or
invent a claim. `tools probe trust-meter` and `tools probe phaseledger` exit `2`
while the pins stay `fail_closed`.

The intended later path is exact transport only:

```text
Trust Meter measure
  -> exact stdout artifact
    -> verified evidence-handoff
  -> caller-authored Phaseledger observation
  -> Phaseledger measure on exact artifact ID
  -> independent native VERDICT
```

```powershell
$measure = ewb --json --workspace C:\evidence-workspace runs plan `
  --tool trust-meter --subject C:\repo `
  --python-admission $admission.data.admission_id `
  --param threshold=75 --param phase=preflight | ConvertFrom-Json
ewb --json --workspace C:\evidence-workspace runs execute `
  --plan $measure.data.plan_id `
  --plan-digest $measure.data.record_digest `
  --allow read_subject

$handoff = ewb --json --workspace C:\evidence-workspace handoffs create `
  --source-run $measure.data.run_id `
  --source-run-digest $measure.data.record_digest `
  --artifact $stdoutArtifactId | ConvertFrom-Json

# Caller, not EWB, writes phaseledger-caller-observation/v1 and maps it
# to Phaseledger 0.6.0 measure JSON. Handoff IDs are not plan inputs.
$artifact = ewb --json --workspace C:\evidence-workspace artifacts add `
  --file C:\evidence\observation.json --role handoff_input `
  --media-type application/json | ConvertFrom-Json
$gate = ewb --json --workspace C:\evidence-workspace runs plan `
  --tool phaseledger `
  --python-admission $phaseledgerAdmission.data.admission_id `
  --input-artifact $artifact.data.artifact_id | ConvertFrom-Json
ewb --json --workspace C:\evidence-workspace runs execute `
  --plan $gate.data.plan_id `
  --plan-digest $gate.data.record_digest `
  --allow read_artifact
```

The caller remains responsible for constructing an honest phaseledger
observation whose claim names the exact artifact ID, digest,
`untrusted_exact_bytes`, and `authority_effect none`. Checks cannot reuse Trust
Meter field names. `--input-artifact` selects one existing verified workspace
artifact by its exact ID; it does not inspect `.ewb/handoffs` or infer a
producer. `--input FILE` remains available for a new byte-for-byte import and
defaults to `application/json`; `--input-media-type` is valid only with that
file-import form. A verified not-granted admission lets planning continue past
the capsule inventory blocker and then still stop on `enabled_by_default: false`
and pin `fail_closed`. Residual containment blockers remain named; empty PATH
or a Job Object is not an OS sandbox.

### StateWeaver candidate admission and future invocation (execution currently fails closed)

Inspect the independently pinned candidate and the separate execution-readiness result:

```powershell
ewb --json tools show stateweaver-foundation
```

The pin records implementation completion and verified-at-admission evidence integrity. It deliberately records `authority_effect: none`; candidate posture never enters `native_result` or `native_authority`.

```powershell
$plan = ewb --json --workspace C:\evidence-workspace runs plan `
  --tool stateweaver-foundation | ConvertFrom-Json
ewb --json --workspace C:\evidence-workspace runs execute `
  --plan $plan.data.plan_id `
  --plan-digest $plan.data.record_digest `
  --allow execute_fixed_synthetic
```

This remains intentionally limited to `stateweaver --json foundation verify`. Planning stays disabled until a platform-matched, content-addressed runtime capsule includes the interpreter, standard library, all first-party packages, and all transitive dependencies. A wheel bundle, lockfile, source checkout, checksum, or attestation alone does not satisfy that execution contract.

## Artifact handoff

```powershell
$artifact = ewb --json --workspace C:\evidence-workspace artifacts add `
  --file C:\evidence\native.json --role handoff_input `
  --media-type application/json | ConvertFrom-Json

ewb --json --workspace C:\evidence-workspace artifacts verify `
  $artifact.data.artifact_id
```

Objects live at `.ewb/objects/sha256/<prefix>/<suffix>`. Records use generated ASCII IDs and content-addressed URIs. Import copies raw bytes while hashing, uses atomic commit, and stores an empty `transforms` list. JSON projections are never substituted for the native artifact.

For an artifact-scoped adapter, `runs plan --input-artifact <ARTIFACT_ID>`
re-verifies that exact artifact registry record and CAS object before any native
snapshot can be written, then records the selected artifact ID, SHA-256, length,
and media type in the existing `Subject::Artifact` v1 shape. Reusing the input
does not create a replacement input artifact, duplicate its CAS bytes, create a
handoff, or create an execution directory during planning. Normal planning may
still create its own native tool-identity snapshots. At execution, EWB derives
`.ewb/executions/<PLAN_ID>/input` internally and streams the CAS object through
one verified source handle into a new private single-link file; it does not use
a hard link, reflink, parse, or reserialization. A pre-existing execution root
is never overwritten, and a failed materialization removes only the root created
for that attempt.

This plan binding deliberately does **not** include the enclosing
`ArtifactRecord`'s `record_digest`, roles, origin, capture mode, transforms, or
producer provenance because `instrument_run/v1` has no fields for them. It also
keeps `source_run_id: null`. Use the independent handoff registry when verified
run-to-plan-to-artifact lineage is required; planning never searches that
registry or promotes it into native authority.

[`evidence-handoff/v1`](contracts/evidence-handoff-v1.schema.json) defines a
closed, reference-only plan/run/artifact descriptor. It fixes the relationship
to `captured_run_artifact`, requires the consumer to treat the referenced
artifact as `untrusted_exact_bytes`, and has `authority_effect: none`. Parsing
that standalone descriptor still proves no lineage. The workspace-aware
[`evidence_handoff_record/v1`](contracts/evidence-handoff-record-v1.schema.json)
registry supplies that separate verification boundary:

```powershell
$handoff = ewb --json --workspace C:\evidence-workspace handoffs create `
  --source-run <RUN_ID> `
  --source-run-digest <RETAINED_RUN_RECORD_DIGEST> `
  --artifact <ARTIFACT_ID> | ConvertFrom-Json

ewb --json --workspace C:\evidence-workspace handoffs verify `
  $handoff.data.handoff.handoff_id `
  --handoff-digest $handoff.data.record_digest
```

Create accepts no plan identity or execution input. It reloads the producer
run using the caller-retained run digest, derives the plan reference from that
run, requires the complete verified artifact descriptor to occur exactly once
in the run, and re-hashes the artifact CAS bytes. Create, list, show, and verify
all repeat the same-workspace lineage checks; verify additionally requires
the caller-retained handoff digest. They return complete records without a
`status`, `verdict`, `passed`, score, command, argument vector, native
interpretation, or authority widening. `ide-handoff/v1` remains a separate
backward-compatible optional projection.

The three referenced `record_digest` values are EWB's compact typed-JSON
digests of `PlanPayload`, `InstrumentRun`, and `ArtifactDescriptor`; the handoff
record digest uses its `EvidenceHandoff` object. They are not hashes of the
enclosing record files. `handoff_id` is an opaque typed ID, not a content digest
or authenticity proof.

## JSON and exit policy

With `--json`, stdout contains exactly one JSON value. Native stdout/stderr are captured as artifacts and never mixed into EWB stdout.

- EWB exit `0`: the workbench command completed. For `runs execute`, the native process exited; its native exit code may be nonzero.
- EWB exit `2`: EWB input, storage, identity, contract, or command failure.
- EWB exit `4`: a run record was committed, but the native process did not exit normally (for example timeout or interrupted output capture).

Never use EWB's process exit as a native verdict. Read `data.run.termination` and the namespaced, source-linked `data.run.native_result`. `native_authority` remains `not_reported` unless a future native-only authority extractor is explicitly implemented.

The machine envelope is:

```json
{"ok":true,"command":"runs.show","data":{}}
```

Its logical contract is `ewb-cli-envelope/v1`. The version is selected out of
band through the contract name; v1 deliberately adds no top-level
`schema_version` field to the established CLI JSON. A success object has exactly
`ok`, `command`, and `data`. A failure object has exactly `ok` and `error`, where
`error` has exactly `code` and `message`. `data` remains the opaque native
payload of the named EWB command and is validated by that command's own
contract. Errors are also one JSON value and never include native output or
credentials.

## Contracts

- [`contracts/instrument-run-v1.schema.json`](contracts/instrument-run-v1.schema.json)
- [`contracts/artifact-descriptor-v1.schema.json`](contracts/artifact-descriptor-v1.schema.json)
- [`contracts/tool-manifest-v1.schema.json`](contracts/tool-manifest-v1.schema.json)
- [`contracts/candidate-pin-v1.schema.json`](contracts/candidate-pin-v1.schema.json)
- [`contracts/upstream-pin-v1.schema.json`](contracts/upstream-pin-v1.schema.json)
- [`contracts/native-delivery-qualification-v1.schema.json`](contracts/native-delivery-qualification-v1.schema.json)
- [`contracts/python-runtime-qualification-v1.schema.json`](contracts/python-runtime-qualification-v1.schema.json)
- [`contracts/python-runtime-qualification-record-v1.schema.json`](contracts/python-runtime-qualification-record-v1.schema.json)
- [`contracts/python-runtime-execution-admission-v1.schema.json`](contracts/python-runtime-execution-admission-v1.schema.json)
- [`contracts/python-runtime-execution-admission-record-v1.schema.json`](contracts/python-runtime-execution-admission-record-v1.schema.json)
- [`contracts/phaseledger-caller-observation-v1.schema.json`](contracts/phaseledger-caller-observation-v1.schema.json)
- [`contracts/build-identity-v1.schema.json`](contracts/build-identity-v1.schema.json)
- [`contracts/ewb-cli-envelope-v1.schema.json`](contracts/ewb-cli-envelope-v1.schema.json)
- [`contracts/evidence-handoff-v1.schema.json`](contracts/evidence-handoff-v1.schema.json)
- [`contracts/evidence-handoff-record-v1.schema.json`](contracts/evidence-handoff-record-v1.schema.json)
- [`contracts/ide-handoff-v1.schema.json`](contracts/ide-handoff-v1.schema.json)
- [`contracts/audit-topology-v1.schema.json`](contracts/audit-topology-v1.schema.json)
- [`contracts/audit-receipt-v1.schema.json`](contracts/audit-receipt-v1.schema.json)

The run schema has no shared `status`, `verdict`, `passed`, `overall_status`, or aggregate result field. A native projection carries its own namespace, value, `projection_only: true`, artifact ID, and exact locator. In `instrument_run/v1`, `native_authority` is schema-constrained to `not_reported`, and artifact `source_run_id` is constrained to `null` rather than asserting unverified lineage; either feature requires a new contract version with native rebinding rather than widening v1 in place.

## Trust and safety boundaries

- Adapters use `Command(executable).args(argv)`, never a shell string. `.cmd` and `.bat` executables are rejected.
- Only embedded manifests are executable; parameters are allowlisted and typed.
- Capability approval is deny-by-default but **is not an OS sandbox**. The native tool still runs as the current user.
- Child environment variables are minimized. This reduces accidental credential inheritance but does not remove the process's filesystem authority.
- On Windows, timeout kills the direct child and then closes a Job Object with `KILL_ON_JOB_CLOSE`. The child is assigned after spawn, so a grandchild can race that assignment. Unix still kills only the direct child. This is not OS network containment.
- Native output capture is bounded at 32 MiB. Exceeding it records an interrupted run with no native result.
- Storage directories reject symlinks and reparse points. Registry records,
  CAS objects, and staged private files must also have exactly one hard-link
  name when read or verified. Full handle-relative, race-free containment
  against a same-user adversary is not yet claimed.
- Reused artifact inputs are copied from the verified CAS handle into a
  plan-scoped `create_new` private file and re-hashed before execution. The
  source object, CAS shard, execution root, and materialized file reject links
  or reparse points; no hardlink or reflink is used for handoff.
- Clean Git commit identity is required. Dirty and untracked working trees fail closed.
- Python-backed planning is disabled until the launcher, interpreter, runtime, distribution, and transitive dependencies can all be snapshotted immutably.
- Each production manifest has one embedded `upstream_pin/v1`. Its source/delivery/posture fields are registry evidence; only its separate `execution_readiness` field controls whether an exact operation has an admitted closure.
- TomorrowCI's qualification-gated trust audit isolates child Git/container-engine lookups to an exact-empty PATH and verifies a private launcher-only application directory before/after execution. The PE import boundary is independently parsed from the exact EXE. Same-user mid-run namespace races remain explicit limitations; this is not OS containment.
- SHA-256 checksums establish byte integrity, not producer authenticity or authority.

## Development verification

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --all-targets
if (Test-Path tests/harness/Cargo.toml) {
  cargo test --manifest-path tests/harness/Cargo.toml
}
```

Internal execution-boundary tests run through an independent harness under `tests/`, which Cargo packages exclude. The production `ewb` target has no harness cfg, test manifest, or test operation in any profile; the fake native executable is compiled by the integration test and admitted by its exact SHA-256 only inside the harness registry. No public feature, test adapter, harness, or fake binary is installable from the packaged crate.
