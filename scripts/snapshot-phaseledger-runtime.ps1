# Copy a closed local phaseledger runtime tree and emit a fail-closed
# runtime-capsule/v1 descriptor. This is a snapshot producer, not admission.
# Planning still fail-closes on OS-enforced no-network containment.

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$out = if ($args[0]) { $args[0] } else { Join-Path $projectRoot 'artifacts/phaseledger-runtime' }

if (-not (Get-Command py -ErrorAction SilentlyContinue)) { throw 'py launcher not found' }

$ewb = Join-Path $projectRoot 'target\debug\ewb.exe'
if (-not (Test-Path $ewb)) {
    $found = Get-Command ewb -ErrorAction SilentlyContinue
    if (-not $found) { throw 'ewb not found; build target/debug/ewb.exe first' }
    $ewb = $found.Source
}

$runtime = Join-Path $out 'runtime'
if (Test-Path $runtime) { Remove-Item -Recurse -Force $runtime }
New-Item -ItemType Directory -Force -Path $runtime | Out-Null

$prefix = & py -3.11 -c "import sys; print(sys.base_prefix)"
$pkg = & py -3.11 -c "import phaseledger, pathlib; print(pathlib.Path(phaseledger.__file__).resolve().parent)"
if (-not (Test-Path $prefix)) { throw "python prefix missing: $prefix" }
if (-not (Test-Path $pkg)) { throw "phaseledger package missing: $pkg" }

Write-Output "interpreter prefix: $prefix"
Write-Output "phaseledger package: $pkg"

$exe = Join-Path $prefix 'python.exe'
if (-not (Test-Path $exe)) { $exe = (Get-Command python).Source }
Copy-Item -LiteralPath $exe -Destination (Join-Path $runtime 'python.exe')

Get-ChildItem -LiteralPath $prefix -File | Where-Object {
    $_.Name -match '^(python\d.*|vcruntime.*|api-ms-win.*)\.(dll|zip)$'
} | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $runtime $_.Name)
}

$pkgDest = Join-Path $runtime 'Lib\site-packages\phaseledger'
New-Item -ItemType Directory -Force -Path $pkgDest | Out-Null
Get-ChildItem -LiteralPath $pkg -File -Filter '*.py' | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $pkgDest $_.Name)
}

$descriptor = Join-Path $out 'runtime-capsule.json'
& $ewb --json capsules snapshot `
    --root $runtime `
    --out $descriptor `
    --tool phaseledger `
    --operation phaseledger_measure `
    --launcher python.exe
if ($LASTEXITCODE -ne 0) { throw "ewb capsules snapshot failed: $LASTEXITCODE" }

Write-Output "wrote closed root $runtime"
Write-Output "wrote $descriptor"
Write-Output 'NOT a ready capsule. OS-enforced no-network containment remains unimplemented.'
