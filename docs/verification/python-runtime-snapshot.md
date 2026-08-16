# Honest Python runtime snapshot (unimplemented)

This is a binding inventory, not a schema and not an implementation.
`python_runtime_snapshot_unimplemented` stays on the Trust Meter and
Phaseledger pins. Those pins stay `fail_closed`.
`runtime.interpreter_included` stays `false`. Admission stays
`not_granted`. `python_runtime_qualification/v1` stays `incomplete`.

A later snapshot contract may exist only if it binds the bytes below by
artifact ID, SHA-256, and byte length. Writing this file does not create
that contract and does not close the blocker.

## What already exists is not the snapshot

These records cite or prove inventory. None of them is an immutable
runtime snapshot that `runs plan` or `runs execute` may load:

- `python_runtime_qualification/v1` cites a capsule, CPython archive
  artifact, capsule `_pth`, wheel/RECORD pairs, and the embedded wrapper.
  Every check is `not_implemented`. The only state is `incomplete`.
- `python_runtime_execution_admission/v1` proves five implementable
  checks from CAS bytes without spawning Python. Residual containment is
  `failed`. State is `not_granted`.
- `python_runtime_execution_admission/v2` and `/v3` may start the bound
  `python.exe` only to record Job Object and AppContainer observations.
  State is still `not_granted`.
- `runtime-capsule/v1` inventories a sparse root. Official-embed admission
  keeps `python.exe`, a rewritten `_pth`, and unpacked wheel files under
  `site/`. That root is not a CPython install and is not a pin runtime.

`run_validation` still rejects any Python adapter with
"immutable runtime snapshot is not implemented".

## Bytes a snapshot would have to bind

Each row is one exact CAS object, or a capsule-owned file whose bytes are
already a CAS object through the qualification binding. A name, pin field,
or satisfied check is not a substitute.

### 1. Official CPython embed archive

Bind the operator-supplied zip, not extracted members.

For the current Windows embed pin recorded in
[`python-admission-real-embed.md`](python-admission-real-embed.md):

- Filename: `python-3.13.15-embed-amd64.zip`
- SHA-256: `d1f04d990aee1253d8569e8e5104e30fa9f5fa830899f14843448872d936a2cf`
- Size: 11009825 bytes

The snapshot names that archive artifact. It does not name
`python313.dll`, `python313.zip`, `_socket.pyd`, or `select.pyd` as the
interpreter. Those members may be required to start `python.exe`; they
are not a second interpreter identity.

EWB does not vendor this zip and does not download it from an adapter.
A different 3.13 build is a different archive.

Binding this zip does not set pin `runtime.interpreter_included` to
true. That field is a pin-delivery claim. An operator file next to a
workspace is not a pin-included interpreter.

### 2. Isolated `_pth`

Bind the admitted path-configuration artifact. Those are the bytes
`python-admissions admit` already requires:

```text
python313.zip
site
```

or the isolated grammar that also allows `.` and blank lines.

Do not bind the stock archive `python313._pth`. That file still contains
`#import site` or `import site` and fails
`python_path_configuration_isolation`.

### 3. Wheel and installed RECORD

Bind each selected wheel artifact with its capsule-owned
`.dist-info/RECORD` as one pair. Digest mismatch, extra members, or
missing members fail `wheel_record_closure` today and would fail a
snapshot.

Trust Meter 0.2.1 already has a pin-published wheel:

- `trust_meter-0.2.1-py3-none-any.whl`
- SHA-256: `a653b3010896dd8a034dd4bc77b1925ca56680d51a8834cc7aa8ed320f8f7f2d`

Phaseledger 0.6.0 does not. The pin has `release: null` and no wheel
digest. A fixture wheel used by a gated test is not a Phaseledger
runtime snapshot. Do not invent a digest.

### 4. Capsule launcher and wrapper

Also bind, because the launch contract names them:

- capsule `python.exe` bytes, which must match the official zip member
  when the archive is the official embed
- `evidence-workbench-python-runtime-wrapper/v1`
  (`0bb5b8795ad0c97eb8ec94f898d7215eabe19891a70740bccee3d834a98deb9b`,
  261 bytes)

Changing wrapper bytes requires a new wrapper contract ID. That is not a
snapshot implementation.

## EWB prove root does not count

`prove-containment` and `prove-network` write a disposable directory
under `.ewb` tmp. That directory may contain:

- a `create_new` copy of the bound `python.exe`
- the admitted isolated `_pth`
- allowlisted extract of `python313.dll`, `python313.zip`, VCRuntime,
  `_socket.pyd`, and `select.pyd`
- copies of those `.pyd` files under prove-root `site/` so the admitted
  `_pth` can `import socket`

That root is not a runtime snapshot. It is not pin `interpreter_included`.
It is not an execution permit. Deleting it after the prove record is
written does not drop a required binding, because it was never one.

Do not promote prove-root paths, Job Object assignment, an empty PATH,
or an AppContainer SID into snapshot identity.

## What this file does not close

- `python_runtime_snapshot_unimplemented`
- `python_interpreter_not_included`
- Trust Meter `ambient_ancestor_config_not_isolated` (`--no-config` is
  argv, not ancestor isolation)
- pin `ready` / `enabled_by_default: true`
- `admission_state` other than `not_granted`
- `python_runtime_qualification/v1` becoming complete
- WFP, host `python.exe`, and `capsules snapshot` of a host interpreter
