#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputZip,
    [switch]$Offline,
    [switch]$DebugBuild,
    [string]$NetworkSeeds,
    [string]$NetworkSeedPublicKey,
    [string]$NetworkSeedNetworkId,
    [string]$AuthenticodeThumbprint,
    [string]$SignToolPath,
    [string]$TimestampUrl
)

$ErrorActionPreference = 'Stop'

function Get-ReproducibleZipTimestamp {
    param([Parameter(Mandatory)][string]$Repository)

    $epochText = $env:SOURCE_DATE_EPOCH
    if (-not $epochText) {
        $gitEpoch = & git -C $Repository show -s --format=%ct HEAD
        if ($LASTEXITCODE -ne 0 -or -not $gitEpoch) {
            throw 'Unable to determine the source commit timestamp.'
        }
        $epochText = ([string]$gitEpoch).Trim()
    }
    if ($epochText -cnotmatch '\A[0-9]{1,12}\z') {
        throw 'SOURCE_DATE_EPOCH must be a non-negative Unix timestamp.'
    }
    $value = [long]$epochText
    $sourceDate = [DateTimeOffset]::FromUnixTimeSeconds($value).ToUniversalTime()
    if ($sourceDate.Year -lt 1980 -or $sourceDate.Year -gt 2107) {
        throw 'SOURCE_DATE_EPOCH is outside the ZIP timestamp range.'
    }
    return [DateTimeOffset]::new(
        $sourceDate.Year, $sourceDate.Month, $sourceDate.Day,
        $sourceDate.Hour, $sourceDate.Minute, ($sourceDate.Second - ($sourceDate.Second % 2)),
        [TimeSpan]::Zero
    )
}

function ConvertTo-CanonicalJsonNode {
    param([AllowNull()]$Value)

    if ($Value -is [Collections.IDictionary]) {
        $result = [ordered]@{}
        $keys = [string[]]@($Value.Keys | ForEach-Object { [string]$_ })
        [Array]::Sort($keys, [StringComparer]::Ordinal)
        foreach ($key in $keys) {
            $result[$key] = ConvertTo-CanonicalJsonNode -Value $Value[$key]
        }
        return $result
    }
    if ($Value -is [Collections.IEnumerable] -and $Value -isnot [string]) {
        $items = [Collections.Generic.List[object]]::new()
        foreach ($item in $Value) {
            $items.Add((ConvertTo-CanonicalJsonNode -Value $item))
        }
        return ,$items.ToArray()
    }
    return $Value
}

function Normalize-JsonFile {
    param([Parameter(Mandatory)][string]$Path)

    $parsed = [IO.File]::ReadAllText($Path) | ConvertFrom-Json -AsHashtable
    $layoutProperties = @($parsed.metadata.properties | Where-Object { $_.name -ceq 'asl:package_layout' })
    if ($layoutProperties.Count -ne 1) {
        throw 'The Windows SBOM must contain exactly one package-layout property.'
    }
    $layoutProperties[0].value = Get-PortableLayoutVersion
    $canonical = ConvertTo-CanonicalJsonNode -Value $parsed
    $json = ($canonical | ConvertTo-Json -Depth 32 -Compress) + "`n"
    [IO.File]::WriteAllText($Path, $json, [Text.UTF8Encoding]::new($false))
}

function Normalize-SourceArchive {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][DateTimeOffset]$Timestamp
    )

    $temporary = "$Path.reproducible"
    if (Test-Path -LiteralPath $temporary) { throw "Temporary archive already exists: $temporary" }
    $inputFile = [IO.File]::Open($Path, 'Open', 'Read', 'Read')
    try {
        $inputArchive = [IO.Compression.ZipArchive]::new($inputFile, 'Read', $true)
        try {
            $entries = @($inputArchive.Entries)
            $names = [string[]]@($entries | ForEach-Object FullName)
            [Array]::Sort($names, [StringComparer]::Ordinal)
            $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            $outputFile = [IO.File]::Open($temporary, 'CreateNew', 'Write', 'None')
            try {
                $outputArchive = [IO.Compression.ZipArchive]::new($outputFile, 'Create', $true)
                try {
                    foreach ($name in $names) {
                        if ($name -cnotmatch '\A[A-Za-z0-9_.+-]+\z' -or -not $seen.Add($name)) {
                            throw 'MPL source archive contains an unsafe or repeated entry.'
                        }
                        $sourceEntry = $entries | Where-Object { $_.FullName -ceq $name } | Select-Object -First 1
                        if (-not $sourceEntry -or $sourceEntry.FullName.EndsWith('/')) {
                            throw 'MPL source archive contains a non-file entry.'
                        }
                        $targetEntry = $outputArchive.CreateEntry($name, [IO.Compression.CompressionLevel]::NoCompression)
                        $targetEntry.LastWriteTime = $Timestamp
                        $sourceStream = $sourceEntry.Open()
                        $targetStream = $targetEntry.Open()
                        try { $sourceStream.CopyTo($targetStream) }
                        finally {
                            $targetStream.Dispose()
                            $sourceStream.Dispose()
                        }
                    }
                }
                finally { $outputArchive.Dispose() }
            }
            finally { $outputFile.Dispose() }
        }
        finally { $inputArchive.Dispose() }
    }
    finally { $inputFile.Dispose() }
    [IO.File]::Move($temporary, $Path, $true)
}

function Get-VcRuntimeSource {
    $candidates = [Collections.Generic.List[string]]::new()
    if ($env:VCToolsRedistDir) {
        $candidates.Add((Join-Path $env:VCToolsRedistDir 'x64\Microsoft.VC143.CRT\vcruntime140.dll'))
    }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere -PathType Leaf) {
        $discovered = & $vswhere -latest -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -find 'VC\Redist\MSVC\**\x64\Microsoft.VC143.CRT\vcruntime140.dll'
        foreach ($path in @($discovered)) {
            if ($path) { $candidates.Add($path) }
        }
    }
    foreach ($path in $candidates) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $signature = Get-AuthenticodeSignature -LiteralPath $path
            if ($signature.Status -ne 'Valid') {
                throw "The Visual C++ runtime is not Authenticode-valid: $path"
            }
            return (Resolve-Path -LiteralPath $path).Path
        }
    }
    throw 'VCRUNTIME140.dll was not found. Install the Visual C++ x64 build tools or set VCToolsRedistDir.'
}

function Write-ReproduciblePackageZip {
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string[]]$Members,
        [Parameter(Mandatory)][DateTimeOffset]$Timestamp
    )

    $names = [string[]]@($Members | ForEach-Object { $_.Replace('\', '/') })
    [Array]::Sort($names, [StringComparer]::Ordinal)
    $output = [IO.File]::Open($Destination, 'CreateNew', 'Write', 'None')
    try {
        $archive = [IO.Compression.ZipArchive]::new($output, 'Create', $true)
        try {
            foreach ($name in $names) {
                $source = Join-Path $SourceRoot $name
                if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
                    throw "Package member is missing: $name"
                }
                $entry = $archive.CreateEntry($name, [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = $Timestamp
                $input = [IO.File]::Open($source, 'Open', 'Read', 'Read')
                $target = $entry.Open()
                try { $input.CopyTo($target) }
                finally {
                    $target.Dispose()
                    $input.Dispose()
                }
            }
        }
        finally { $archive.Dispose() }
    }
    finally { $output.Dispose() }
}

. (Join-Path $PSScriptRoot 'move-build-output.ps1')
if ($OutputZip -notmatch '^[A-Za-z]:[\\/]' -or [IO.Path]::GetExtension($OutputZip) -ne '.zip') {
    throw 'Specify an absolute local .zip output path.'
}
$archive = [IO.Path]::GetFullPath($OutputZip)
if (Test-Path -LiteralPath $archive) {
    throw 'Choose a new archive path.'
}

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$zipTimestamp = Get-ReproducibleZipTimestamp -Repository $repo
$hasNetworkSeeds = [bool]$NetworkSeeds
if ($hasNetworkSeeds -ne [bool]$NetworkSeedPublicKey -or
    $hasNetworkSeeds -ne [bool]$NetworkSeedNetworkId) {
    throw 'Pass -NetworkSeeds, -NetworkSeedPublicKey, and -NetworkSeedNetworkId together.'
}
if ($hasNetworkSeeds) {
    $seedPath = (Resolve-Path -LiteralPath $NetworkSeeds).Path
    $seedKeyPath = (Resolve-Path -LiteralPath $NetworkSeedPublicKey).Path
    if (-not (Test-Path -LiteralPath $seedPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $seedKeyPath -PathType Leaf)) {
        throw 'The signed network seed file and public-key file must exist.'
    }
    $repoPrefix = $repo.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    foreach ($path in @($seedPath, $seedKeyPath)) {
        if ($path.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Production network seed inputs must stay outside the repository: $path"
        }
        if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Network seed inputs must not be reparse points: $path"
        }
    }
    $python = Get-Command 'python3.exe' -ErrorAction SilentlyContinue
    if (-not $python) { $python = Get-Command 'python.exe' -ErrorAction SilentlyContinue }
    if (-not $python) { throw 'Python 3 and OpenSSL 3 are required to verify optional signed network seeds.' }
    & $python.Source (Join-Path $PSScriptRoot 'network-seeds.py') verify `
        --seeds $seedPath `
        --public-key-file $seedKeyPath `
        --network-id $NetworkSeedNetworkId | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'The supplied network seed signature or network ID is invalid.' }
}
if (-not $DebugBuild) {
    $changes = git -C $repo status --porcelain --untracked-files=normal
    if ($LASTEXITCODE -ne 0) {
        throw 'Git status failed; official packages require a source-controlled clean tree.'
    }
    if ($changes) {
        throw 'Official packages require a clean worktree. Use -DebugBuild for a development package.'
    }
}
. (Join-Path $repo 'packaging\windows\Portable-Layout.ps1')
$parent = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($archive))
$candidate = [guid]::NewGuid().ToString('N')
$package = Join-Path $parent.FullName "$candidate-asl"
$stagingZip = Join-Path $parent.FullName "$candidate.zip"
$files = Get-PortablePackageMembers -IncludeNetworkSeeds:$hasNetworkSeeds
try {
    & (Join-Path $PSScriptRoot 'prepare-desktop.ps1') -RunDir $package -Release:(-not $DebugBuild) -Offline:$Offline | Out-Null
    [IO.File]::Copy((Get-VcRuntimeSource), (Join-Path $package 'vcruntime140.dll'))
    foreach ($name in @('Start-ASL.ps1', 'Set-ASLLogin.ps1', 'Portable-Layout.ps1', 'Update-ASL.ps1', 'Rollback-ASL.ps1')) {
        [IO.File]::Copy((Join-Path $repo "packaging\windows\$name"), (Join-Path $package $name))
    }
    [IO.File]::Copy((Join-Path $repo 'LICENSE'), (Join-Path $package 'LICENSE'))
    [IO.File]::Copy((Join-Path $repo 'packaging\windows\README.md'), (Join-Path $package 'README.md'))
    if ($hasNetworkSeeds) {
        $assets = [IO.Directory]::CreateDirectory((Join-Path $package 'assets'))
        [IO.File]::Copy($seedPath, (Join-Path $assets.FullName 'network-seeds.json'))
        [IO.File]::Copy($seedKeyPath, (Join-Path $assets.FullName 'network-seeds.public-key.hex'))
    }
    $runtimeVersion = (Get-Item -LiteralPath (Join-Path $package 'vcruntime140.dll')).VersionInfo.FileVersion
    [IO.File]::WriteAllText((Join-Path $package 'active-release.txt'), 'base', [Text.Encoding]::ASCII)
    [IO.File]::WriteAllText((Join-Path $package 'package-layout.txt'), (Get-PortableLayoutVersion), [Text.Encoding]::ASCII)

    if ($AuthenticodeThumbprint) {
        if (-not $TimestampUrl) {
            throw 'Pass an operator-approved -TimestampUrl for an Authenticode release.'
        }
        $timestamp = [Uri]$TimestampUrl
        if (-not $timestamp.IsAbsoluteUri -or $timestamp.Scheme -cne 'https') {
            throw 'Authenticode timestamp service must be an absolute HTTPS URL.'
        }
        if (-not $SignToolPath) {
            $command = Get-Command 'signtool.exe' -ErrorAction SilentlyContinue
            if ($command) { $SignToolPath = $command.Source }
        }
        if (-not $SignToolPath -or -not (Test-Path -LiteralPath $SignToolPath -PathType Leaf)) {
            throw 'Pass -SignToolPath or make signtool.exe available on PATH for an Authenticode release.'
        }
        $SignToolPath = (Resolve-Path -LiteralPath $SignToolPath).Path
        $thumbprint = $AuthenticodeThumbprint.Replace(' ', '').ToUpperInvariant()
        foreach ($executable in @('asl.exe', 'asl-core.exe', 'asl-net.exe', 'asl-worker.exe', 'asl-extractor.exe', 'asl-ui.exe')) {
            $path = Join-Path $package $executable
            & $SignToolPath sign /sha1 $thumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $path
            if ($LASTEXITCODE -ne 0) {
                throw "Authenticode signing failed for $executable."
            }
            $signature = Get-AuthenticodeSignature -LiteralPath $path
            if ($signature.Status -ne 'Valid') {
                throw "Authenticode verification failed for $executable`: $($signature.StatusMessage)"
            }
        }
    }

    & (Join-Path $PSScriptRoot 'windows-package-notices.ps1') `
        -OutputDirectory $package `
        -VcRuntimeVersion $runtimeVersion `
        -Offline:$Offline
    Normalize-JsonFile -Path (Join-Path $package 'sbom.cdx.json')
    Normalize-SourceArchive -Path (Join-Path $package 'MPL-SOURCES.zip') -Timestamp $zipTimestamp
    $hashes = foreach ($name in $files) {
        if ($name -ne 'SHA256SUMS.txt') {
            $digest = Get-FileHash -LiteralPath (Join-Path $package $name) -Algorithm SHA256
            '{0}  {1}' -f $digest.Hash.ToLowerInvariant(), $name
        }
    }
    $hashManifest = (@($hashes) -join "`n") + "`n"
    [IO.File]::WriteAllText(
        (Join-Path $package 'SHA256SUMS.txt'),
        $hashManifest,
        [Text.Encoding]::ASCII
    )
    Write-ReproduciblePackageZip `
        -SourceRoot $package `
        -Destination $stagingZip `
        -Members $files `
        -Timestamp $zipTimestamp
    Move-AslBuildOutput -Source $stagingZip -Destination $archive
}
finally {
    [IO.File]::Delete($stagingZip)
    if ([IO.Directory]::Exists($package)) {
        [IO.File]::Delete((Join-Path $package 'MPL-SOURCES.zip.reproducible'))
        foreach ($name in $files) {
            [IO.File]::Delete((Join-Path $package $name))
        }
        $assets = Join-Path $package 'assets'
        if ([IO.Directory]::Exists($assets)) {
            [IO.Directory]::Delete($assets)
        }
        [IO.Directory]::Delete($package)
    }
}
Write-Output $archive
