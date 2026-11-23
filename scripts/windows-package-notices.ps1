#requires -Version 7.0
param([Parameter(Mandatory)][string]$OutputDirectory, [switch]$Offline)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$arguments = @(
    'metadata', '--format-version', '1', '--locked',
    '--filter-platform', 'x86_64-pc-windows-msvc',
    '--manifest-path', (Join-Path $repo 'crates\asl-app\Cargo.toml'),
    '--features', 'desktop-ui'
)
if ($Offline) { $arguments += '--offline' }
$metadata = & cargo @arguments
if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata failed.' }
$details = $metadata -join "`n" | ConvertFrom-Json -AsHashtable

$packages = @{}
$nodes = @{}
foreach ($package in $details.packages) { $packages[$package.id] = $package }
foreach ($node in $details.resolve.nodes) { $nodes[$node.id] = $node }
$application = $details.packages | Where-Object {
    $_.manifest_path -eq (Join-Path $repo 'crates\asl-app\Cargo.toml')
} | Select-Object -First 1
if (-not $application) { throw 'The application is missing from Cargo metadata.' }

$seen = @{}
$pending = [Collections.Generic.Queue[string]]::new()
$pending.Enqueue($application.id)
while ($pending.Count) {
    $id = $pending.Dequeue()
    if ($seen.ContainsKey($id)) { continue }
    $seen[$id] = $true
    foreach ($dep in $nodes[$id].deps) {
        if (@($dep.dep_kinds | Where-Object { $null -eq $_.kind }).Count) {
            $pending.Enqueue($dep.pkg)
        }
    }
}

$utf8 = [Text.UTF8Encoding]::new($false)
$document = Join-Path $OutputDirectory 'THIRD-PARTY.txt'
$components = [Collections.Generic.List[object]]::new()
$sourceArchives = [Collections.Generic.List[string]]::new()
$file = [IO.StreamWriter]::new($document, $false, $utf8)
try {
    $file.WriteLine('ASL Windows runtime dependencies')
    $file.WriteLine('MPL-SOURCES.zip contains the original .crate archives for the MPL-2.0 runtime components.')
    foreach ($package in ($seen.Keys | ForEach-Object { $packages[$_] } | Sort-Object name, version)) {
        if ($package.id -eq $application.id) { continue }
        $file.WriteLine()
        $file.WriteLine(('{0} {1} | {2}' -f $package.name, $package.version, $package.license))
        if ($package.repository) { $file.WriteLine($package.repository) }
        $component = [ordered]@{
            type = 'library'
            name = $package.name
            version = $package.version
        }
        if ($package.license) { $component.licenses = @(@{ expression = $package.license }) }
        if ($package.source -like 'registry+*') {
            $component.purl = 'pkg:cargo/{0}@{1}' -f $package.name, $package.version
        }
        $components.Add($component)

        $directory = [IO.Path]::GetDirectoryName($package.manifest_path)
        foreach ($notice in (Get-ChildItem -LiteralPath $directory -File | Where-Object {
            $_.Name -match '^(LICENSE|LICENCE|COPYING|NOTICE|COPYRIGHT)([-._]|$)'
        } | Sort-Object Name)) {
            if ($notice.Length -gt 262144) { throw "Oversized license notice for $($package.name)." }
            $file.WriteLine($notice.Name)
            $file.WriteLine([IO.File]::ReadAllText($notice.FullName))
        }
        if ($package.source -like 'registry+*' -and $package.license -match '\bMPL-2\.0\b') {
            $archive = '{0}-{1}.crate' -f $package.name, $package.version
            $registry = Split-Path -Leaf (Split-Path -Parent $directory)
            $source = Join-Path $env:CARGO_HOME "registry\cache\$registry\$archive"
            $sourceArchives.Add($source)
        }
    }
    foreach ($name in @('jieba.txt', 'asl-ui-assets.txt')) {
        $file.WriteLine()
        $file.WriteLine([IO.File]::ReadAllText((Join-Path $repo "docs\licenses\$name")))
    }
}
finally { $file.Dispose() }

$sourceZip = [IO.Compression.ZipFile]::Open((Join-Path $OutputDirectory 'MPL-SOURCES.zip'), 'Create')
try {
    foreach ($source in $sourceArchives) {
        [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
            $sourceZip, $source, [IO.Path]::GetFileName($source)
        )
    }
}
finally { $sourceZip.Dispose() }

$sbom = [ordered]@{
    '$schema' = 'http://cyclonedx.org/schema/bom-1.6.schema.json'
    bomFormat = 'CycloneDX'
    specVersion = '1.6'
    version = 1
    metadata = @{ component = @{ type = 'application'; name = 'ASL'; version = $application.version } }
    components = $components.ToArray()
}
[IO.File]::WriteAllText(
    (Join-Path $OutputDirectory 'sbom.cdx.json'),
    ($sbom | ConvertTo-Json -Depth 8),
    $utf8
)
