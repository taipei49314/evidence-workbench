$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$gate = Join-Path $PSScriptRoot 'check-harness-dependency-sync.ps1'
$rootManifest = Join-Path $repositoryRoot 'Cargo.toml'
$harnessManifest = Join-Path $repositoryRoot 'tests/harness/Cargo.toml'
$rootMetadataPath = [IO.Path]::GetTempFileName()
$harnessMetadataPath = [IO.Path]::GetTempFileName()

try {
    $rootRaw = @(& cargo metadata --locked --format-version 1 --manifest-path $rootManifest)
    if ($LASTEXITCODE -ne 0) { throw 'root cargo metadata failed' }
    $harnessRaw = @(& cargo metadata --locked --format-version 1 --manifest-path $harnessManifest)
    if ($LASTEXITCODE -ne 0) { throw 'harness cargo metadata failed' }

    $rootMetadata = ($rootRaw -join [Environment]::NewLine) | ConvertFrom-Json
    $harnessMetadata = ($harnessRaw -join [Environment]::NewLine) | ConvertFrom-Json
    [IO.File]::WriteAllText(
        $rootMetadataPath,
        ($rootMetadata | ConvertTo-Json -Compress -Depth 100),
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        $harnessMetadataPath,
        ($harnessMetadata | ConvertTo-Json -Compress -Depth 100),
        [Text.UTF8Encoding]::new($false)
    )

    & $gate -RootMetadataPath $rootMetadataPath -HarnessMetadataPath $harnessMetadataPath

    $rootId = [string]$rootMetadata.resolve.root
    $rootPackage = @($rootMetadata.packages | Where-Object { [string]$_.id -eq $rootId })
    if ($rootPackage.Count -ne 1) { throw 'root package lookup failed in regression fixture' }
    $sha2 = @(
        $rootPackage[0].dependencies |
            Where-Object { $_.name -eq 'sha2' -and $null -eq $_.kind }
    )
    if ($sha2.Count -ne 1) { throw 'sha2 dependency lookup failed in regression fixture' }
    $originalRequirement = [string]$sha2[0].req
    $sha2[0].req = '^0.10'
    [IO.File]::WriteAllText(
        $rootMetadataPath,
        ($rootMetadata | ConvertTo-Json -Compress -Depth 100),
        [Text.UTF8Encoding]::new($false)
    )

    $rejected = $false
    try {
        & $gate -RootMetadataPath $rootMetadataPath -HarnessMetadataPath $harnessMetadataPath
    } catch {
        if ($_.Exception.Message -notlike 'Direct normal dependency declarations differ*') {
            throw
        }
        $rejected = $true
    }
    if (-not $rejected) {
        throw 'root-only dependency drift was accepted by the synchronization gate'
    }
    Write-Output 'Regression passed: root-only dependency declaration drift is rejected'

    $sha2[0].req = $originalRequirement
    $resolvedSha2 = @($rootMetadata.packages | Where-Object { $_.name -eq 'sha2' })
    if ($resolvedSha2.Count -ne 1) { throw 'resolved sha2 lookup failed in regression fixture' }
    $oldPackageId = [string]$resolvedSha2[0].id
    $newPackageId = "root-only-drift:$oldPackageId"
    $resolvedSha2[0].id = $newPackageId
    $sha2Node = @($rootMetadata.resolve.nodes | Where-Object { [string]$_.id -eq $oldPackageId })
    if ($sha2Node.Count -ne 1) { throw 'resolved sha2 node lookup failed in regression fixture' }
    $sha2Node[0].id = $newPackageId
    foreach ($node in @($rootMetadata.resolve.nodes)) {
        foreach ($dependency in @($node.deps)) {
            if ([string]$dependency.pkg -eq $oldPackageId) {
                $dependency.pkg = $newPackageId
            }
        }
    }
    [IO.File]::WriteAllText(
        $rootMetadataPath,
        ($rootMetadata | ConvertTo-Json -Compress -Depth 100),
        [Text.UTF8Encoding]::new($false)
    )

    $rejected = $false
    try {
        & $gate -RootMetadataPath $rootMetadataPath -HarnessMetadataPath $harnessMetadataPath
    } catch {
        if ($_.Exception.Message -notlike 'Locked normal dependency packages differ*') {
            throw
        }
        $rejected = $true
    }
    if (-not $rejected) {
        throw 'root-only locked graph drift was accepted by the synchronization gate'
    }
    Write-Output 'Regression passed: root-only locked graph drift is rejected'
} finally {
    Remove-Item -LiteralPath $rootMetadataPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $harnessMetadataPath -Force -ErrorAction SilentlyContinue
}
