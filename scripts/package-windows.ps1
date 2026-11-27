#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputZip,
    [switch]$Offline,
    [switch]$DebugBuild,
    [string]$AuthenticodeThumbprint,
    [string]$SignToolPath,
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'move-build-output.ps1')
if ($OutputZip -notmatch '^[A-Za-z]:[\\/]' -or [IO.Path]::GetExtension($OutputZip) -ne '.zip') {
    throw 'Specify an absolute local .zip output path.'
}
$archive = [IO.Path]::GetFullPath($OutputZip)
if (Test-Path -LiteralPath $archive) {
    throw 'Choose a new archive path.'
}

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
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
$files = Get-PortablePackageMembers
try {
    & (Join-Path $PSScriptRoot 'prepare-desktop.ps1') -RunDir $package -Release:(-not $DebugBuild) -Offline:$Offline | Out-Null
    foreach ($name in @('Start-ASL.ps1', 'Set-ASLLogin.ps1', 'Portable-Layout.ps1', 'Update-ASL.ps1')) {
        [IO.File]::Copy((Join-Path $repo "packaging\windows\$name"), (Join-Path $package $name))
    }
    [IO.File]::Copy((Join-Path $repo 'LICENSE'), (Join-Path $package 'LICENSE'))
    [IO.File]::Copy((Join-Path $repo 'packaging\windows\README.md'), (Join-Path $package 'README.md'))
    [IO.File]::WriteAllText((Join-Path $package 'active-release.txt'), 'base', [Text.Encoding]::ASCII)
    [IO.File]::WriteAllText((Join-Path $package 'package-layout.txt'), (Get-PortableLayoutVersion), [Text.Encoding]::ASCII)

    if ($AuthenticodeThumbprint) {
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

    & (Join-Path $PSScriptRoot 'windows-package-notices.ps1') -OutputDirectory $package -Offline:$Offline
    $hashes = foreach ($name in $files) {
        if ($name -ne 'SHA256SUMS.txt') {
            $digest = Get-FileHash -LiteralPath (Join-Path $package $name) -Algorithm SHA256
            '{0}  {1}' -f $digest.Hash.ToLowerInvariant(), $name
        }
    }
    [IO.File]::WriteAllLines((Join-Path $package 'SHA256SUMS.txt'), $hashes, [Text.Encoding]::ASCII)
    [IO.Compression.ZipFile]::CreateFromDirectory($package, $stagingZip)
    Move-AslBuildOutput -Source $stagingZip -Destination $archive
}
finally {
    [IO.File]::Delete($stagingZip)
    if ([IO.Directory]::Exists($package)) {
        foreach ($name in $files) {
            [IO.File]::Delete((Join-Path $package $name))
        }
        [IO.Directory]::Delete($package)
    }
}
Write-Output $archive
