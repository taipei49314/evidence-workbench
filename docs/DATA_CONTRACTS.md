# Integration data contracts

These contracts are transport boundaries. They do not create a shared verdict or
authority.

- `subject-candidate/v1` carries an untrusted `github-radar` discovery. EWB must
  independently resolve the exact commit and tree before admission.
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

`ewb capsules admit --descriptor <FILE> --root <DIRECTORY>` additionally proves
that the root contains exactly the launcher and inventoried files, rejects links
and reparse points, verifies every length and SHA-256, verifies all qualification
artifact references already held by the workspace, and copies each exact file
into EWB-owned content-addressed storage. The registry record digest binds the
exact descriptor bytes, parsed contract, and every snapshot. Admission and
qualification evidence retain `authority_effect: none`.
