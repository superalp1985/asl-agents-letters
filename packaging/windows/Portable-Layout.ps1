function Assert-PortablePath {
    param([string]$Path, [switch]$Directory)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -ne [bool]$Directory) {
        throw "Unexpected file type: $Path"
    }
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Reparse points are not supported in the portable layout: $Path"
        }
        $item = if ($item -is [IO.DirectoryInfo]) { $item.Parent } else { $item.Directory }
    }
}

function Get-PortableRelease {
    param([string]$Root)

    Assert-PortablePath $Root -Directory
    $pointer = Join-Path $Root 'active-release.txt'
    Assert-PortablePath $pointer
    if ((Get-Item -LiteralPath $pointer).Length -gt 256) {
        throw 'Invalid release pointer.'
    }
    $record = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($pointer))
    if ($record -ceq 'base') {
        return [PSCustomObject]@{ Directory = $Root; Version = $null }
    }
    if ($record -cnotmatch '\A(release-[0-9a-f]{32})\n([0-9A-Za-z.+-]+)\z') {
        throw 'Invalid release pointer.'
    }
    $directory = Join-Path $Root $Matches[1]
    $version = $Matches[2]
    Assert-PortablePath $directory -Directory
    return [PSCustomObject]@{ Directory = $directory; Version = $version }
}

function Assert-PortableRoot {
    param([string]$Root)

    if ($Root -notmatch '^[A-Za-z]:[\\/]') { throw 'Use a local NTFS installation directory.' }
    $volume = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($Root))
    if ($volume.DriveType -ne [IO.DriveType]::Fixed -or $volume.DriveFormat -ne 'NTFS') {
        throw 'Use a local fixed NTFS installation directory.'
    }
    Assert-PortablePath $Root -Directory
}

function Get-PortablePackageMembers {
    @(
        'asl.exe', 'asl-core.exe', 'asl-net.exe', 'asl-worker.exe', 'asl-extractor.exe', 'asl-ui.exe',
        'Start-ASL.ps1', 'Set-ASLLogin.ps1', 'Update-ASL.ps1', 'Portable-Layout.ps1',
        'LICENSE', 'README.md', 'THIRD-PARTY.txt', 'sbom.cdx.json', 'SHA256SUMS.txt',
        'MPL-SOURCES.zip', 'active-release.txt', 'package-layout.txt'
    )
}

function Get-PortableLayoutVersion { 'asl-windows-layout-v2' }

function Assert-PortableLayoutVersion {
    param([string]$Root)

    $marker = Join-Path $Root 'package-layout.txt'
    Assert-PortablePath $marker
    $version = Get-PortableLayoutVersion
    if ((Get-Item -LiteralPath $marker).Length -ne $version.Length -or
        [IO.File]::ReadAllText($marker) -cne $version) {
        throw 'Incompatible portable package layout.'
    }
}
