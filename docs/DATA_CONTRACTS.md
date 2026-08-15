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

Every object shape is closed with `additionalProperties: false`. Rust parsing
also rejects duplicate JSON keys and applies semantic cross-field validation.

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
