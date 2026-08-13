$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
cargo install --path $projectRoot --locked --force

$installed = Get-Command ewb -ErrorAction Stop
Write-Output "Installed ewb at $($installed.Source)"
ewb --version

