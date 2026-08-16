# Real CPython embed admission (still not granted)

This is an operator procedure. EWB does not vendor the official embed zip,
does not download it from an adapter, and does not spawn `python.exe`.

A satisfied implementable check is not execution admission. Residual
containment is recorded as `failed` because spawnless admit cannot prove
OS containment of `python.exe`; those checks still cannot be `satisfied`.
Trust Meter and Phaseledger stay `fail_closed` and `enabled_by_default: false`.

## Pinned official embed

Recorded from the CPython SPDX SBOM and re-hashed locally on 2026-08-16.
Do not substitute another 3.13 build.

- Filename: `python-3.13.15-embed-amd64.zip`
- URL: `https://www.python.org/ftp/python/3.13.15/python-3.13.15-embed-amd64.zip`
- SHA-256: `d1f04d990aee1253d8569e8e5104e30fa9f5fa830899f14843448872d936a2cf`
- SPDX: `https://www.python.org/ftp/python/3.13.15/python-3.13.15-embed-amd64.zip.spdx.json`
- Size: 11009825 bytes
- Members that matter: `python.exe`, `pythonw.exe`, `python313.zip`, `python313._pth`

If the file bytes do not match that digest, stop. Do not admit the archive.

## Why the stock `_pth` cannot be used

The official `python313._pth` is:

```text
python313.zip
.

# Uncomment to run site.main() automatically
#import site
```

`python-admissions admit` allows only `python3XX.zip`, `site` or `.`, and
blank lines. Comments and `#import site` fail
`python_path_configuration_isolation`. Rewrite the capsule snapshot to:

```text
python313.zip
site
```

That proves the bound `_pth` is isolated. It does not prove the official
default file was already isolated.

## Capsule root is not a full extract

`capsules admit` requires the root to match the descriptor inventory
exactly. Do not extract every embed member into the capsule root.

Minimum inventory for this procedure:

- `python.exe` copied from the official zip member (byte-for-byte)
- rewritten `python313._pth`
- wheel files unpacked under `site/` without pip or `python.exe`
- `site/<dist-info>/RECORD` taken from the wheel's `.dist-info/RECORD`

The official zip itself is the `--cpython-archive-artifact`. The extracted
`python.exe` is only the capsule launcher.

`capsules snapshot` of a host interpreter is not this path. Snapshot records
`host_interpreter_copy` and stays fail-closed.

## Wheel without spawning Python

Supply a Phaseledger 0.6.0 wheel as `EWB_PHASELEDGER_WHEEL`. Unpack it with
a zip tool into `site/`. Keep the wheel's `.dist-info/RECORD`. Digest
mismatch, extra members, or missing members fail `wheel_record_closure`.

Trust Meter uses the same unpack procedure with the already-pinned
`trust_meter-0.2.1-py3-none-any.whl` digest
`a653b3010896dd8a034dd4bc77b1925ca56680d51a8834cc7aa8ed320f8f7f2d`.
This document does not enable Trust Meter execution.

## Commands

```powershell
# 1. Hash the official zip. Stop if it differs.
Get-FileHash -Algorithm SHA256 $env:EWB_CPYTHON_EMBED_ZIP

# 2. Build a sparse capsule root (launcher + isolated _pth + unpacked wheel).
# 3. Write runtime-capsule/v1 naming those exact files, then:

$archive = ewb --json --workspace $ws artifacts add --file $env:EWB_CPYTHON_EMBED_ZIP --role runtime_input
$wheel = ewb --json --workspace $ws artifacts add --file $env:EWB_PHASELEDGER_WHEEL --role runtime_input
$capsule = ewb --json --workspace $ws capsules admit --descriptor $descriptor --root $capsuleRoot
$qualification = ewb --json --workspace $ws python-qualifications create `
  --capsule $capsule.data.capsule_id `
  --cpython-archive-artifact $archive.data.artifact_id `
  --path-configuration python313._pth `
  --wheel-artifact $wheel.data.artifact_id `
  --installed-record-path site/<dist-info>/RECORD
$admission = ewb --json --workspace $ws python-admissions admit `
  --inventory-qualification $qualification.data.qualification_id
```

## Expected admission checks

```text
cpython_archive_semantics           satisfied
wheel_record_closure                satisfied
python_path_configuration_isolation satisfied
python_launch_harness               satisfied
python_private_materialization      satisfied
os_network_egress_denial            failed
python_active_process_limit_one     failed
python_creation_time_job_assignment failed
admission_state                     not_granted
```

`runs plan --tool phaseledger --python-admission <id>` still fails closed
(`disabled` or pin `fail_closed`). `ewb --json tools show trust-meter` and
`phaseledger` stay `fail_closed`.

## Gated test

`python_admission_cli_accepts_official_embed_bytes_but_stays_not_granted`
runs only on Windows when both environment variables are set:

- `EWB_CPYTHON_EMBED_ZIP`
- `EWB_PHASELEDGER_WHEEL`

Unset variables skip the test so Ubuntu CI stays green. A set variable with
the wrong embed digest, a stock `_pth`, or a RECORD that does not close the
wheel fails the test.
