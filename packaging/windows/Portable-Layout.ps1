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

function Get-PortablePointerRecord {
    param([string]$Root)

    Assert-PortablePath $Root -Directory
    $pointer = Join-Path $Root 'active-release.txt'
    Assert-PortablePath $pointer
    if ((Get-Item -LiteralPath $pointer).Length -gt 256) {
        throw 'Invalid release pointer.'
    }
    $bytes = [IO.File]::ReadAllBytes($pointer)
    if (@($bytes | Where-Object { $_ -gt 127 }).Count) {
        throw 'Invalid release pointer.'
    }
    $record = [Text.Encoding]::ASCII.GetString($bytes)
    if ($record -cne 'base' -and $record -cnotmatch '\A(release-[0-9a-f]{32})\n([0-9A-Za-z.+-]+)\z') {
        throw 'Invalid release pointer.'
    }
    return $record
}

function Resolve-PortableReleaseRecord {
    param([string]$Root, [string]$Record)

    if ($record -ceq 'base') {
        return [PSCustomObject]@{ Directory = $Root; Version = $null; Record = $Record }
    }
    if ($Record -cnotmatch '\A(release-[0-9a-f]{32})\n([0-9A-Za-z.+-]+)\z') {
        throw 'Invalid release pointer.'
    }
    $directory = Join-Path $Root $Matches[1]
    $version = $Matches[2]
    Assert-PortablePath $directory -Directory
    return [PSCustomObject]@{ Directory = $directory; Version = $version; Record = $Record }
}

function Get-PortableRelease {
    param([string]$Root)

    $record = Get-PortablePointerRecord $Root
    return Resolve-PortableReleaseRecord -Root $Root -Record $record
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
    param([switch]$IncludeNetworkSeeds)

    $members = @(
        'asl.exe', 'asl-core.exe', 'asl-net.exe', 'asl-worker.exe', 'asl-extractor.exe', 'asl-ui.exe',
        'Start-ASL.ps1', 'Set-ASLLogin.ps1', 'Update-ASL.ps1', 'Rollback-ASL.ps1', 'Portable-Layout.ps1',
        'LICENSE', 'README.md', 'THIRD-PARTY.txt', 'sbom.cdx.json', 'SHA256SUMS.txt',
        'MPL-SOURCES.zip', 'active-release.txt', 'package-layout.txt'
    )
    if ($IncludeNetworkSeeds) {
        $members += @(
            'assets/network-seeds.json',
            'assets/network-seeds.public-key.hex'
        )
    }
    return $members
}

function Get-PortableLayoutVersion { 'asl-windows-layout-v3' }

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

function Read-PortableArchiveEntryBytes {
    param(
        [Parameter(Mandatory)]$Entry,
        [Parameter(Mandatory)][long]$MaximumBytes
    )

    if ($Entry.Length -gt $MaximumBytes) {
        throw "Package metadata is oversized: $($Entry.FullName)"
    }
    $stream = $Entry.Open()
    $buffer = [IO.MemoryStream]::new()
    try {
        $stream.CopyTo($buffer)
        return ,$buffer.ToArray()
    }
    finally {
        $buffer.Dispose()
        $stream.Dispose()
    }
}

function Assert-PortablePackageArchive {
    param([Parameter(Mandatory)][IO.Stream]$InputStream)

    if (-not $InputStream.CanRead -or -not $InputStream.CanSeek) {
        throw 'Package verification requires a readable seekable stream.'
    }
    $InputStream.Position = 0
    $archive = [IO.Compression.ZipArchive]::new($InputStream, 'Read', $true)
    try {
        $seedMembers = @('assets/network-seeds.json', 'assets/network-seeds.public-key.hex')
        $archiveNames = @($archive.Entries | ForEach-Object FullName)
        $presentSeedMembers = @($seedMembers | Where-Object { $archiveNames -ccontains $_ })
        if ($presentSeedMembers.Count -ne 0 -and $presentSeedMembers.Count -ne $seedMembers.Count) {
            throw 'The package contains an incomplete network-seed asset set.'
        }
        $files = if ($presentSeedMembers.Count -eq $seedMembers.Count) {
            @(Get-PortablePackageMembers -IncludeNetworkSeeds)
        } else {
            @(Get-PortablePackageMembers)
        }
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $entries = [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::Ordinal
        )
        $directorySeen = $false
        $total = [long]0
        foreach ($entry in $archive.Entries) {
            if ($entry.FullName.EndsWith('/', [StringComparison]::Ordinal)) {
                if ($directorySeen -or $entry.FullName -cne 'assets/' -or
                    $presentSeedMembers.Count -ne $seedMembers.Count) {
                    throw "Unexpected package directory entry: $($entry.FullName)"
                }
                $directorySeen = $true
                continue
            }
            if ($entry.FullName -cnotin $files -or -not $seen.Add($entry.FullName)) {
                throw "Unexpected or repeated package entry: $($entry.FullName)"
            }
            if ($entry.Length -le 0 -or $entry.Length -gt 256MB) {
                throw "Invalid package member size: $($entry.FullName)"
            }
            $total += $entry.Length
            if ($total -gt 1GB) { throw 'The unpacked package is too large.' }
            $entries.Add($entry.FullName, $entry)
        }
        if ($seen.Count -ne $files.Count) { throw 'The package is incomplete.' }

        $manifestBytes = Read-PortableArchiveEntryBytes `
            -Entry $entries['SHA256SUMS.txt'] `
            -MaximumBytes 64KB
        if (@($manifestBytes | Where-Object { $_ -gt 127 }).Count) {
            throw 'The package hash manifest must be ASCII.'
        }
        $manifestText = [Text.Encoding]::ASCII.GetString($manifestBytes)
        if (-not $manifestText.EndsWith("`n", [StringComparison]::Ordinal) -or
            $manifestText.Contains("`r") -or $manifestText.EndsWith("`n`n", [StringComparison]::Ordinal)) {
            throw 'The package hash manifest must use one LF-terminated line per member.'
        }
        $lines = $manifestText.Substring(0, $manifestText.Length - 1).Split("`n")
        $hashedFiles = @($files | Where-Object { $_ -cne 'SHA256SUMS.txt' })
        if ($lines.Count -ne $hashedFiles.Count) {
            throw 'The package hash manifest does not cover every package member.'
        }
        for ($index = 0; $index -lt $hashedFiles.Count; $index++) {
            if ($lines[$index] -cnotmatch '\A([0-9a-f]{64})  ([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?)\z') {
                throw 'The package hash manifest contains a non-canonical entry.'
            }
            $expectedHash = $Matches[1]
            $expectedName = $Matches[2]
            if ($expectedName -cne $hashedFiles[$index]) {
                throw 'The package hash manifest is not in canonical path order.'
            }
            $memberStream = $entries[$expectedName].Open()
            $sha256 = [Security.Cryptography.SHA256]::Create()
            try { $actualBytes = $sha256.ComputeHash($memberStream) }
            finally {
                $sha256.Dispose()
                $memberStream.Dispose()
            }
            $actualHash = [Convert]::ToHexString($actualBytes).ToLowerInvariant()
            if ($actualHash -cne $expectedHash) {
                throw "Package member hash mismatch: $expectedName"
            }
        }

        $layoutBytes = Read-PortableArchiveEntryBytes `
            -Entry $entries['package-layout.txt'] `
            -MaximumBytes 128
        if ([Text.Encoding]::ASCII.GetString($layoutBytes) -cne (Get-PortableLayoutVersion)) {
            throw 'The package layout marker is incompatible.'
        }
        $pointerBytes = Read-PortableArchiveEntryBytes `
            -Entry $entries['active-release.txt'] `
            -MaximumBytes 128
        if ([Text.Encoding]::ASCII.GetString($pointerBytes) -cne 'base') {
            throw 'The package active-release marker must be base.'
        }
        $sbomBytes = Read-PortableArchiveEntryBytes `
            -Entry $entries['sbom.cdx.json'] `
            -MaximumBytes 8MB
        try {
            $sbomText = [Text.UTF8Encoding]::new($false, $true).GetString($sbomBytes)
            $sbom = $sbomText | ConvertFrom-Json -AsHashtable
        }
        catch {
            throw 'The package SBOM is not valid UTF-8 JSON.'
        }
        if ($sbom.bomFormat -cne 'CycloneDX' -or $sbom.specVersion -cne '1.6' -or
            $sbom.metadata.component.name -cne 'ASL' -or
            $sbom.metadata.component.version -cnotmatch '\A[0-9]+\.[0-9]+\.[0-9]+(?:\+[0-9A-Za-z.-]+)?\z') {
            throw 'The package SBOM does not match the Windows release contract.'
        }
        $sbomLayout = @($sbom.metadata.properties | Where-Object {
            $_.name -ceq 'asl:package_layout'
        })
        if ($sbomLayout.Count -ne 1 -or
            $sbomLayout[0].value -cne (Get-PortableLayoutVersion)) {
            throw 'The package SBOM layout property is incompatible.'
        }
        return [PSCustomObject]@{
            Members = $files
            HasNetworkSeeds = ($presentSeedMembers.Count -eq $seedMembers.Count)
        }
    }
    finally {
        $archive.Dispose()
        $InputStream.Position = 0
    }
}

function Assert-PortableAuthenticode {
    param(
        [Parameter(Mandatory)][IO.Stream]$InputStream,
        [Parameter(Mandatory)][string]$ScratchRoot
    )

    $scratch = [IO.Path]::GetFullPath($ScratchRoot)
    [void][IO.Directory]::CreateDirectory($scratch)
    Assert-PortablePath $scratch -Directory
    $working = Join-Path $scratch ('.asl-authenticode-' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($working)
    $executables = @('asl.exe', 'asl-core.exe', 'asl-net.exe', 'asl-worker.exe', 'asl-extractor.exe', 'asl-ui.exe')
    try {
        $InputStream.Position = 0
        $archive = [IO.Compression.ZipArchive]::new($InputStream, 'Read', $true)
        try {
            foreach ($name in $executables) {
                $matches = @($archive.Entries | Where-Object { $_.FullName -ceq $name })
                if ($matches.Count -ne 1) { throw "Authenticode member is missing or repeated: $name" }
                $destination = Join-Path $working $name
                $input = $matches[0].Open()
                $output = [IO.File]::Open($destination, 'CreateNew', 'Write', 'None')
                try { $input.CopyTo($output) }
                finally {
                    $output.Dispose()
                    $input.Dispose()
                }
                $signature = Get-AuthenticodeSignature -LiteralPath $destination
                if ($signature.Status -ne 'Valid') {
                    throw "Authenticode verification failed for $name`: $($signature.StatusMessage)"
                }
            }
        }
        finally { $archive.Dispose() }
    }
    finally {
        $InputStream.Position = 0
        foreach ($name in $executables) {
            [IO.File]::Delete((Join-Path $working $name))
        }
        if ([IO.Directory]::Exists($working)) { [IO.Directory]::Delete($working) }
    }
}

function New-PortableRollbackMetadata {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$PreviousPointer,
        [Parameter(Mandatory)][string]$ActivePointer,
        [Parameter(Mandatory)][string]$PackageSha256,
        [Parameter(Mandatory)][string]$ManifestSha256
    )

    [void](Resolve-PortableReleaseRecord -Root $Root -Record $PreviousPointer)
    [void](Resolve-PortableReleaseRecord -Root $Root -Record $ActivePointer)
    if ($PackageSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or
        $ManifestSha256 -cnotmatch '\A[0-9a-f]{64}\z') {
        throw 'Rollback metadata requires lowercase SHA-256 values.'
    }
    $metadata = [ordered]@{
        format_version = 1
        previous_pointer = $PreviousPointer
        active_pointer = $ActivePointer
        package_sha256 = $PackageSha256
        manifest_sha256 = $ManifestSha256
        recorded_at_utc = [DateTime]::UtcNow.ToString(
            'yyyy-MM-ddTHH:mm:ss.fffffffZ',
            [Globalization.CultureInfo]::InvariantCulture
        )
    }
    return ($metadata | ConvertTo-Json -Compress)
}

function Get-PortableRollbackMetadata {
    param([Parameter(Mandatory)][string]$Root)

    $path = Join-Path $Root 'rollback-release.json'
    Assert-PortablePath $path
    if ((Get-Item -LiteralPath $path).Length -gt 4096) {
        throw 'Rollback metadata is oversized.'
    }
    $metadata = [IO.File]::ReadAllText($path) | ConvertFrom-Json -AsHashtable
    $required = @(
        'format_version', 'previous_pointer', 'active_pointer',
        'package_sha256', 'manifest_sha256', 'recorded_at_utc'
    )
    if ($metadata.Count -ne $required.Count -or
        @($required | Where-Object { -not $metadata.ContainsKey($_) }).Count) {
        throw 'Rollback metadata has an unsupported shape.'
    }
    if ($metadata.format_version -ne 1 -or
        $metadata.package_sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or
        $metadata.manifest_sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or
        $metadata.recorded_at_utc -cnotmatch '\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z\z') {
        throw 'Rollback metadata contains invalid values.'
    }
    [void](Resolve-PortableReleaseRecord -Root $Root -Record $metadata.previous_pointer)
    [void](Resolve-PortableReleaseRecord -Root $Root -Record $metadata.active_pointer)
    return $metadata
}

function Publish-PortableReleaseState {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$PendingPointer,
        [Parameter(Mandatory)][string]$RollbackMetadata
    )

    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $pendingPath = [IO.Path]::GetFullPath($PendingPointer)
    if ([IO.Path]::GetDirectoryName($pendingPath).TrimEnd('\', '/') -cne $rootPath) {
        throw 'Pending release pointer must be inside the portable root.'
    }
    Assert-PortablePath $pendingPath
    $pointer = Join-Path $rootPath 'active-release.txt'
    $rollbackPath = Join-Path $rootPath 'rollback-release.json'
    $pendingRollback = Join-Path $rootPath ('.rollback-' + [guid]::NewGuid().ToString('N'))
    $hadRollback = Test-Path -LiteralPath $rollbackPath -PathType Leaf
    $previousRollback = if ($hadRollback) {
        Assert-PortablePath $rollbackPath
        [IO.File]::ReadAllBytes($rollbackPath)
    } else { $null }
    $rollbackBytes = [Text.UTF8Encoding]::new($false).GetBytes($RollbackMetadata)
    $rollbackFile = [IO.File]::Open($pendingRollback, 'CreateNew', 'Write', 'None')
    try {
        $rollbackFile.Write($rollbackBytes, 0, $rollbackBytes.Length)
        $rollbackFile.Flush($true)
    }
    finally { $rollbackFile.Dispose() }

    $metadataPublished = $false
    try {
        [IO.File]::Move($pendingRollback, $rollbackPath, $true)
        $metadataPublished = $true
        [IO.File]::Move($pendingPath, $pointer, $true)
    }
    catch {
        if ($metadataPublished) {
            if ($hadRollback) {
                $restore = Join-Path $rootPath ('.rollback-restore-' + [guid]::NewGuid().ToString('N'))
                [IO.File]::WriteAllBytes($restore, $previousRollback)
                [IO.File]::Move($restore, $rollbackPath, $true)
            }
            else {
                [IO.File]::Delete($rollbackPath)
            }
        }
        throw
    }
    finally {
        [IO.File]::Delete($pendingRollback)
    }
}
