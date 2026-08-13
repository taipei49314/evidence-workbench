# Integration data contracts

These contracts are transport boundaries. They do not create a shared verdict or
authority.

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
  arbitrary argument vector, aggregate verdict, or synthesized pass state.

Every object shape is closed with `additionalProperties: false`. Rust parsing
also rejects duplicate JSON keys and applies semantic cross-field validation.

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
