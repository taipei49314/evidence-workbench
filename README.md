# Evidence Workbench

Evidence Workbench (`ewb`) is a thin execution and artifact shell for Nelson's evidence-first tools. It plans direct invocations, pins immutable subjects and tool identities, captures exact native bytes, and records namespaced native observations.

It is deliberately **not** a verifier, certification service, monorepo, shared runtime, or aggregate scoring engine. The governing rules are in [`docs/SHELL_CHARTER.md`](docs/SHELL_CHARTER.md).

## Current v0.2 scope

The embedded `upstream_pin/v1` registry covers all twelve trusted tool manifests with an exact source commit/tree, delivery evidence, native posture, runtime closure, and a separate execution-readiness decision. `tools list`, `tools show`, `doctor`, and `init` expose those records. Every pin has `authority_effect: none`; a CI result, checksum, release, or attestation cannot make an adapter authoritative.

| Tool ID | Native role | Windows execution readiness |
|---|---|---|
| `walkaround` | Session admission | Fail closed: catalog only; Python capsule, mutable session subject, and capability-separated operations are missing |
| `charterlock` | Exam-charter admission | Fail closed: catalog only; Python capsule, bound multi-artifact inputs, and capability-separated operations are missing |
| `tomorrowci-lab` | Fixed trust-behavior audit | Fail closed: exact EXE is admitted, but app-local-resolvable `VCRUNTIME140.dll` is not bound |
| `stateweaver-foundation` | Fixed synthetic foundation verification | Fail closed: Linux wheels, no interpreter |
| `greenwash` | Verification-integrity diff | Fail closed: Python capsule, Git metadata, and fixed execution-time Git are missing |
| `repopass-inspect` | Offline repository inspection | Fail closed: source qualification blocked; no admitted Windows executable; Git dependency unbound |
| `trust-meter` | Advisory structural measure | Fail closed: Python capsule and ambient ancestor config isolation missing |
| `phaseledger` | Caller-observation gate | Fail closed: Python capsule missing |
| `unasked` | Research/authority workflow | Fail closed: runtime/Git closure, non-certifying posture, and proprietary redistribution boundary |
| `normshift` | Standards semantic-change replay | Fail closed: Python capsule and multi-file source bundle missing |
| `smallestlie` | Authorized falsification | Fail closed: runtime, authorization, process-tree, and OS egress containment missing |
| `nullbench` | Preregistered experiment | Fail closed: runtime, directory subject, and capability-separated operations missing |

No production adapter is currently runnable. This is intentional: a tool becomes ready only when its complete operation-specific runtime closure is admitted, not merely because its launcher is hashed.

StateWeaver's completed upstream candidate is recorded separately in a strict `candidate_pin/v1`: source commit `598753d182dda65c73a313e9efbf20b826942f0a`, payload-manifest SHA-256 `8c7c77d59d4cf3abdcadcce3f2d110ca085789da1ec14a2301245f3418b78bc3`, and candidate workflow run `31711437241`. At admission, all 113 listed checksums matched and the payload-manifest OIDC attestation verified. This is an integrity/provenance admission, not native authority.

The adapter remains experimental and cannot accept an arbitrary repository. The candidate itself reports `CANDIDATE_READY_FOR_EXTERNAL_QUALIFICATION` and `release_eligible=false`; it targets Linux x86_64 CPython 3.13 and includes wheels but no Python interpreter. It is therefore not an execution capsule for the current Windows EWB. Python-backed adapters continue to fail closed at planning until EWB can snapshot the complete interpreter, runtime, distribution, and transitive dependency closure. The GitHub Actions artifact expires on 2026-11-11, and EWB does not silently treat that remote artifact as durable or available.

Planning snapshots self-contained native launcher bytes into EWB-owned storage. For a Git subject, planning resolves one canonical Git executable, retains a Windows read-only/no-write-sharing handle while it hashes and invokes that exact path, and verifies the same open file afterward. Git for Windows is not a self-contained `git.exe`, so its staged byte copy is review evidence only and the host installation is explicitly recorded as an unsnapshotted **plan-time** dependency. Planning uses Git to produce both an exact bundle and a deterministic plain-tree artifact; execution uses Rust only to materialize and verify that tree and never resolves Git or PATH. The bundle remains provenance/transport, not the execution source. Artifact subjects execute from a verified private copy. Native execution is currently Windows-only; Unix planning fails closed until descriptor-based exec removes the remaining path-replacement race.

The Git execution tree intentionally contains tracked working-tree files without `.git` metadata, links, or reparse points. Adapters that require repository metadata remain disabled until EWB defines and snapshots that metadata safely.

## Install

Rust 1.85+ is required (the project currently builds with Rust 1.97.1):

```powershell
cargo install --path . --locked
ewb --help
```

Or run [`scripts/install-local.ps1`](scripts/install-local.ps1).

## Start

Initialize a directory that will own the evidence registry:

```powershell
ewb --json --workspace C:\evidence-workspace init
ewb --json --workspace C:\evidence-workspace doctor
ewb --json tools list
```

`doctor` is read-only and does not launch native version commands. `tools probe` is also rejected for every `fail_closed` adapter; it may launch a version probe only after a future production adapter has an admitted complete runtime closure. Trusted manifests are compiled into the `ewb` binary; files placed under `.ewb/manifests` cannot grant a new executable, capability, result, or authority claim.

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

`runs plan` snapshots the native tool but never launches it, including its version probe. Git-subject planning does invoke the fixed, locked plan-time Git identity to create the bundle and tree artifacts; no Git process is launched by `runs execute`. Keep the returned `record_digest` with the reviewed plan; `runs execute` requires that exact digest and then revalidates the manifest, EWB recorder/adapter implementation, staged native bytes, bundle references, tree artifact, parameters, and full argv before spawning. Do not reread a replacement digest from `.ewb/plans`. Original source worktree, native launcher, Git PATH, and Git installation drift after planning do not change the planned execution; staged or stored snapshot drift fails closed.

### TomorrowCI future bounded trust audit (currently fails closed)

```powershell
$plan = ewb --json --workspace C:\evidence-workspace runs plan `
  --tool tomorrowci-lab | ConvertFrom-Json
ewb --json --workspace C:\evidence-workspace runs execute `
  --plan $plan.data.plan_id `
  --plan-digest $plan.data.record_digest `
  --allow inspect_host_tooling
```

Planning currently rejects this command before writing a plan. EWB admits the exact Windows `tomorrowci.exe` bytes, but the PE imports app-local-resolvable `VCRUNTIME140.dll`; the release contains no copy and the plan does not bind the host DLL. This prevents an honest immutable-runtime claim. Future enablement must admit, snapshot, hash, lock, and reverify the non-platform DLL closure. The implemented adapter also isolates child `PATH` so T5 engine and T8 Git probes would remain explicitly `BLOCKED`, and it preserves `/overall`, `/probes/4/verdict`, and `/probes/7/verdict` separately. None supplies authority or scans a repository.

### RepoPassport future local inspect (currently fails closed)

```powershell
ewb --json --workspace C:\evidence-workspace runs plan `
  --tool repopass-inspect --subject C:\repo
```

Planning is disabled until an exact Windows executable is admitted and its optional Git subprocess dependency is eliminated or immutably bound. Even then, `inspect` would not run a scenario or establish a RepoPassport verification verdict; RepoPassport exit `0` would remain command completion only.

### trust-meter and phaseledger future invocations (currently fail closed)

They remain separate native runs. EWB does not pipe a trust-meter boolean directly into phaseledger or invent a claim:

```powershell
$measure = ewb --json --workspace C:\evidence-workspace runs plan `
  --tool trust-meter --subject C:\repo `
  --param threshold=75 --param phase=preflight | ConvertFrom-Json
ewb --json --workspace C:\evidence-workspace runs execute `
  --plan $measure.data.plan_id `
  --plan-digest $measure.data.record_digest `
  --allow read_subject

$gate = ewb --json --workspace C:\evidence-workspace runs plan `
  --tool phaseledger --input C:\evidence\observation.json | ConvertFrom-Json
ewb --json --workspace C:\evidence-workspace runs execute `
  --plan $gate.data.plan_id `
  --plan-digest $gate.data.record_digest `
  --allow read_artifact
```

The caller remains responsible for constructing an honest phaseledger observation whose claim scope names the exact subject and predicate source.

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

Errors are also one JSON value and never include native output or credentials.

## Contracts

- [`contracts/instrument-run-v1.schema.json`](contracts/instrument-run-v1.schema.json)
- [`contracts/artifact-descriptor-v1.schema.json`](contracts/artifact-descriptor-v1.schema.json)
- [`contracts/tool-manifest-v1.schema.json`](contracts/tool-manifest-v1.schema.json)
- [`contracts/candidate-pin-v1.schema.json`](contracts/candidate-pin-v1.schema.json)
- [`contracts/upstream-pin-v1.schema.json`](contracts/upstream-pin-v1.schema.json)

The run schema has no shared `status`, `verdict`, `passed`, `overall_status`, or aggregate result field. A native projection carries its own namespace, value, `projection_only: true`, artifact ID, and exact locator. In `instrument_run/v1`, `native_authority` is schema-constrained to `not_reported`, and artifact `source_run_id` is constrained to `null` rather than asserting unverified lineage; either feature requires a new contract version with native rebinding rather than widening v1 in place.

## Trust and safety boundaries

- Adapters use `Command(executable).args(argv)`, never a shell string. `.cmd` and `.bat` executables are rejected.
- Only embedded manifests are executable; parameters are allowlisted and typed.
- Capability approval is deny-by-default but **is not an OS sandbox**. The native tool still runs as the current user.
- Child environment variables are minimized. This reduces accidental credential inheritance but does not remove the process's filesystem authority.
- Timeout kills the direct child. This MVP does not claim Windows Job Object or Unix process-group containment.
- Native output capture is bounded at 32 MiB. Exceeding it records an interrupted run with no native result.
- Storage directories and artifact files reject symlinks/reparse points at validation time. Full handle-relative, race-free containment against a same-user adversary is not yet claimed.
- Clean Git commit identity is required. Dirty and untracked working trees fail closed.
- Python-backed planning is disabled until the launcher, interpreter, runtime, distribution, and transitive dependencies can all be snapshotted immutably.
- Each production manifest has one embedded `upstream_pin/v1`. Its source/delivery/posture fields are registry evidence; only its separate `execution_readiness` field controls whether an exact operation has an admitted closure.
- TomorrowCI's future trust-audit path isolates child Git/container-engine lookups to an empty PATH, but PATH isolation does not constrain Windows DLL loading. It remains disabled until `VCRUNTIME140.dll` and the non-platform DLL closure are bound.
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
