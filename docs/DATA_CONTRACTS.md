# Integration data contracts

These contracts are transport boundaries. They do not create a shared verdict or
authority.

- `subject-candidate/v1` carries an untrusted `github-radar` discovery. EWB must
  independently resolve the exact commit and tree before admission.
- `runtime-capsule/v1` inventories the launcher and its transitive supporting
  files for one platform and operation scope. Incomplete closure, unresolved
  platform assumptions, or missing qualification evidence cannot be `ready`.
- `ide-handoff/v1` gives an IDE immutable plan, run, and artifact references plus
  native namespace and authority-availability metadata. It carries no command,
  arbitrary argument vector, aggregate verdict, or synthesized pass state.

Every object shape is closed with `additionalProperties: false`. Rust parsing
also rejects duplicate JSON keys and applies semantic cross-field validation.
