$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$commit = (& git -C $projectRoot rev-parse HEAD | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve the builder-recorded Git HEAD' }
$tree = (& git -C $projectRoot rev-parse 'HEAD^{tree}' | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve the builder-recorded Git tree' }
$dirtyLines = @(& git -C $projectRoot status --porcelain=v1 --untracked-files=normal)
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect the builder-recorded Git worktree' }
$dirty = $dirtyLines.Count -ne 0
$rawTags = @(& git -C $projectRoot tag --points-at HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect exact tags at the builder-recorded Git HEAD' }
$tags = @($rawTags | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
$exactTag = if (-not $dirty -and $tags.Count -eq 1) { $tags[0] } else { $null }

$metadataNames = @(
    'EWB_BUILD_VCS_COMMIT',
    'EWB_BUILD_VCS_TREE',
    'EWB_BUILD_VCS_DIRTY',
    'EWB_BUILD_VCS_TAG'
)
$previousEnvironment = @{}
foreach ($name in $metadataNames) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

if (-not [string]::IsNullOrWhiteSpace($env:CARGO_INSTALL_ROOT)) {
    $installRoot = $env:CARGO_INSTALL_ROOT
} elseif (-not [string]::IsNullOrWhiteSpace($env:CARGO_HOME)) {
    $installRoot = $env:CARGO_HOME
} else {
    $userProfile = [Environment]::GetFolderPath('UserProfile')
    if ([string]::IsNullOrWhiteSpace($userProfile)) { throw 'Cannot determine the Cargo install root' }
    $installRoot = Join-Path $userProfile '.cargo'
}
$installRoot = [IO.Path]::GetFullPath($installRoot)

try {
    [Environment]::SetEnvironmentVariable('EWB_BUILD_VCS_COMMIT', $commit, 'Process')
    [Environment]::SetEnvironmentVariable('EWB_BUILD_VCS_TREE', $tree, 'Process')
    [Environment]::SetEnvironmentVariable(
        'EWB_BUILD_VCS_DIRTY',
        $dirty.ToString().ToLowerInvariant(),
        'Process'
    )
    [Environment]::SetEnvironmentVariable('EWB_BUILD_VCS_TAG', $exactTag, 'Process')

    cargo install --path $projectRoot --locked --force --root $installRoot
    if ($LASTEXITCODE -ne 0) { throw "cargo install failed with exit code $LASTEXITCODE" }
} finally {
    foreach ($name in $metadataNames) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
    }
}

$installed = Join-Path (Join-Path $installRoot 'bin') 'ewb'
if (Test-Path -LiteralPath "$installed.exe") { $installed = "$installed.exe" }
if (-not (Test-Path -LiteralPath $installed -PathType Leaf)) {
    throw "Installed ewb binary is absent at $installed"
}
$installed = (Get-Item -LiteralPath $installed).FullName
$buildRaw = & $installed --json build show
if ($LASTEXITCODE -ne 0) { throw "installed ewb build show failed with exit code $LASTEXITCODE" }
$build = $buildRaw | ConvertFrom-Json
if (-not $build.ok -or $build.command -ne 'build.show') { throw 'installed build identity envelope is invalid' }
if ($build.data.schema_version -ne 'build_identity/v1') { throw 'installed build identity schema is invalid' }
if ($build.data.vcs_base.reporting_state -ne 'builder_asserted') { throw 'installed VCS base is not builder-asserted' }
if ($build.data.vcs_base.scope -ne 'builder_recorded_vcs_base') { throw 'installed VCS scope is not builder-recorded' }
if ($build.data.vcs_base.commit -ne $commit -or $build.data.vcs_base.tree -ne $tree) {
    throw 'installed builder-recorded Git base does not match the checkout'
}
if ($build.data.vcs_base.dirty -ne $dirty) { throw 'installed dirty state does not match the checkout' }
if ($null -eq $exactTag) {
    if ($null -ne $build.data.vcs_base.exact_tag) { throw 'installed build guessed an exact tag' }
} elseif ($build.data.vcs_base.exact_tag -ne $exactTag) {
    throw 'installed exact tag does not match the unique clean HEAD tag'
}
$installedSha256 = (Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash.ToLowerInvariant()
if ($build.data.executable.sha256 -ne $installedSha256) {
    throw 'build show did not hash the installed executable file'
}

Write-Output "Installed ewb at $installed"
Write-Output $buildRaw

