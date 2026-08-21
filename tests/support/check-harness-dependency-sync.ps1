[CmdletBinding()]
param(
    [string]$RootManifest,
    [string]$HarnessManifest,
    [string]$RootMetadataPath,
    [string]$HarnessMetadataPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ([string]::IsNullOrWhiteSpace($RootManifest)) {
    $RootManifest = Join-Path $repositoryRoot 'Cargo.toml'
}
if ([string]::IsNullOrWhiteSpace($HarnessManifest)) {
    $HarnessManifest = Join-Path $repositoryRoot 'tests/harness/Cargo.toml'
}

$metadataFilesSupplied = -not [string]::IsNullOrWhiteSpace($RootMetadataPath) -or
    -not [string]::IsNullOrWhiteSpace($HarnessMetadataPath)
if ($metadataFilesSupplied -and
    ([string]::IsNullOrWhiteSpace($RootMetadataPath) -or
     [string]::IsNullOrWhiteSpace($HarnessMetadataPath))) {
    throw 'RootMetadataPath and HarnessMetadataPath must be supplied together'
}

function Read-Metadata {
    param(
        [string]$ManifestPath,
        [string]$MetadataPath
    )

    if (-not [string]::IsNullOrWhiteSpace($MetadataPath)) {
        return Get-Content -LiteralPath $MetadataPath -Raw | ConvertFrom-Json
    }

    $raw = @(& cargo metadata --locked --format-version 1 --manifest-path $ManifestPath)
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed for $ManifestPath with exit code $LASTEXITCODE"
    }
    return ($raw -join [Environment]::NewLine) | ConvertFrom-Json
}

function Get-RootPackage {
    param($Metadata)

    $rootId = [string]$Metadata.resolve.root
    if ([string]::IsNullOrWhiteSpace($rootId)) {
        throw 'cargo metadata did not report a root package'
    }
    $packages = @($Metadata.packages | Where-Object { [string]$_.id -eq $rootId })
    if ($packages.Count -ne 1) {
        throw "cargo metadata root package lookup returned $($packages.Count) matches"
    }
    return $packages[0]
}

function ConvertTo-CanonicalJson {
    param($Value)

    return $Value | ConvertTo-Json -Compress -Depth 20
}

function ConvertTo-OptionalString {
    param($Value)

    if ($null -eq $Value) {
        return $null
    }
    return [string]$Value
}

function Get-OptionalProperty {
    param(
        $Value,
        [string]$Name
    )

    $property = $Value.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Get-DirectNormalDependencies {
    param($Metadata)

    $package = Get-RootPackage $Metadata
    return @(
        $package.dependencies |
            Where-Object { $null -eq $_.kind } |
            ForEach-Object {
                ConvertTo-CanonicalJson ([ordered]@{
                    name = [string]$_.name
                    rename = ConvertTo-OptionalString (Get-OptionalProperty $_ 'rename')
                    requirement = [string]$_.req
                    source = ConvertTo-OptionalString (Get-OptionalProperty $_ 'source')
                    path = ConvertTo-OptionalString (Get-OptionalProperty $_ 'path')
                    registry = ConvertTo-OptionalString (Get-OptionalProperty $_ 'registry')
                    target = ConvertTo-OptionalString (Get-OptionalProperty $_ 'target')
                    optional = [bool]$_.optional
                    default_features = [bool]$_.uses_default_features
                    features = @($_.features | ForEach-Object { [string]$_ } | Sort-Object)
                })
            } |
            Sort-Object
    )
}

function Get-LockedNormalGraph {
    param($Metadata)

    $rootId = [string]$Metadata.resolve.root
    $nodesById = @{}
    foreach ($node in @($Metadata.resolve.nodes)) {
        $nodesById[[string]$node.id] = $node
    }
    if (-not $nodesById.ContainsKey($rootId)) {
        throw 'cargo metadata resolution omitted the root node'
    }

    $visited = @{}
    $queue = [Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($rootId)
    $graphNodes = [Collections.Generic.List[string]]::new()
    $graphEdges = [Collections.Generic.List[string]]::new()

    # The harness intentionally has a different build script and no root dev
    # dependencies. Enter through normal root edges, then retain normal/build
    # edges needed to compile that production dependency closure.
    while ($queue.Count -gt 0) {
        $parentId = $queue.Dequeue()
        if ($visited.ContainsKey($parentId)) {
            continue
        }
        $visited[$parentId] = $true

        $parentNode = $nodesById[$parentId]
        if ($parentId -ne $rootId) {
            # Cargo metadata unifies node features across the full resolution,
            # including root dev dependencies that the harness does not mirror.
            $graphNodes.Add($parentId)
        }

        foreach ($dependency in @($parentNode.deps)) {
            $allowedKinds = @(
                $dependency.dep_kinds |
                    Where-Object {
                        if ($parentId -eq $rootId) {
                            return $null -eq $_.kind
                        }
                        return [string]$_.kind -ne 'dev'
                    } |
                    ForEach-Object {
                        ConvertTo-CanonicalJson ([ordered]@{
                            kind = ConvertTo-OptionalString (Get-OptionalProperty $_ 'kind')
                            target = ConvertTo-OptionalString (Get-OptionalProperty $_ 'target')
                        })
                    } |
                    Sort-Object -Unique
            )
            if ($allowedKinds.Count -eq 0) {
                continue
            }

            $dependencyId = [string]$dependency.pkg
            if (-not $nodesById.ContainsKey($dependencyId)) {
                throw "cargo metadata node lookup failed for $dependencyId"
            }
            $parentKey = if ($parentId -eq $rootId) {
                '<root>'
            } else {
                $parentId
            }
            $graphEdges.Add((ConvertTo-CanonicalJson ([ordered]@{
                parent = $parentKey
                name = [string]$dependency.name
                package = $dependencyId
                kinds = $allowedKinds
            })))
            $queue.Enqueue($dependencyId)
        }
    }

    return [ordered]@{
        nodes = @($graphNodes | Sort-Object -Unique)
        edges = @($graphEdges | Sort-Object -Unique)
    }
}

function Assert-SequenceEqual {
    param(
        [string]$Label,
        [object[]]$RootValues,
        [object[]]$HarnessValues
    )

    $rootText = @($RootValues) -join [Environment]::NewLine
    $harnessText = @($HarnessValues) -join [Environment]::NewLine
    if ($rootText -ne $harnessText) {
        $difference = Compare-Object -ReferenceObject @($RootValues) -DifferenceObject @($HarnessValues)
        $detail = @(
            $difference |
                Select-Object -First 12 |
                ForEach-Object { "$($_.SideIndicator) $($_.InputObject)" }
        ) -join [Environment]::NewLine
        throw "$Label differ between the production crate and execution-boundary harness`n$detail"
    }
}

$rootMetadata = Read-Metadata $RootManifest $RootMetadataPath
$harnessMetadata = Read-Metadata $HarnessManifest $HarnessMetadataPath

$rootDependencies = @(Get-DirectNormalDependencies $rootMetadata)
$harnessDependencies = @(Get-DirectNormalDependencies $harnessMetadata)
Assert-SequenceEqual 'Direct normal dependency declarations' $rootDependencies $harnessDependencies

$rootGraph = Get-LockedNormalGraph $rootMetadata
$harnessGraph = Get-LockedNormalGraph $harnessMetadata
Assert-SequenceEqual 'Locked normal dependency packages' $rootGraph.nodes $harnessGraph.nodes
Assert-SequenceEqual 'Locked normal dependency edges' $rootGraph.edges $harnessGraph.edges

Write-Output (
    "Synchronized Cargo dependency graphs: {0} direct dependencies, {1} locked packages, {2} locked edges" -f
        $rootDependencies.Count,
        $rootGraph.nodes.Count,
        $rootGraph.edges.Count
)
