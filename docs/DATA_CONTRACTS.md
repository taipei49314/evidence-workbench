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
