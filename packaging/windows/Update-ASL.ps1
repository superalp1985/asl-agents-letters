#requires -Version 7.0
[CmdletBinding(DefaultParameterSetName = 'Apply')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Pin')][string]$PinReleaseKey,
    [Parameter(Mandatory, ParameterSetName = 'Apply')][string]$Package,
    [Parameter(Mandatory, ParameterSetName = 'Apply')][string]$Manifest,
    [Parameter(Mandatory, ParameterSetName = 'Apply')][string]$Signature
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Portable-Layout.ps1')
Assert-PortableRoot $PSScriptRoot
Assert-PortableLayoutVersion $PSScriptRoot

$key = Join-Path $PSScriptRoot 'release-key.ed25519'
$lockPath = Join-Path $PSScriptRoot '.update.lock'
if (Test-Path -LiteralPath $lockPath) { Assert-PortablePath $lockPath }
$lock = [IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
try {
    if ($PSCmdlet.ParameterSetName -eq 'Pin') {
        Assert-PortablePath $PinReleaseKey
        if ((Get-Item -LiteralPath $PinReleaseKey).Length -ne 32) {
            throw 'The release key must contain exactly 32 raw bytes.'
        }
        [IO.File]::Copy((Get-Item -LiteralPath $PinReleaseKey).FullName, $key, $false)
        return
    }

    Assert-PortablePath $key
    foreach ($inputFile in @($Package, $Manifest, $Signature)) {
        Assert-PortablePath $inputFile
    }
    $packagePath = (Get-Item -LiteralPath $Package).FullName
    $manifestPath = (Get-Item -LiteralPath $Manifest).FullName
    $signaturePath = (Get-Item -LiteralPath $Signature).FullName
    $installed = Get-PortableRelease $PSScriptRoot
    $verifier = Join-Path $PSScriptRoot 'asl-core.exe'
    Assert-PortablePath $verifier
    $previousHome = $env:ASL_HOME
    $id = [guid]::NewGuid().ToString('N')
    $staging = Join-Path $PSScriptRoot ".staging-$id"
    $pendingPointer = Join-Path $PSScriptRoot ".active-$id"
    $releaseName = "release-$id"
    $release = Join-Path $PSScriptRoot $releaseName
    $pointer = Join-Path $PSScriptRoot 'active-release.txt'
    $files = Get-PortablePackageMembers
    $unpublished = $staging
    # Keep the signed ZIP open for the entire verify/extract sequence.
    $archiveFile = [IO.File]::Open($packagePath, 'Open', 'Read', 'Read')
    try {
        $env:ASL_HOME = $null
        $installedVersion = $installed.Version
        if ($null -eq $installedVersion) {
            $installedVersion = & $verifier --version
            if ($LASTEXITCODE -ne 0 -or $installedVersion -isnot [string]) {
                throw 'The bootstrap Core version could not be determined.'
            }
        }
        $verification = & $verifier --verify-update-receipt $key $manifestPath $signaturePath $packagePath $installedVersion
        if ($LASTEXITCODE -ne 0 -or -not $verification) { throw 'Update signature or version verification failed.' }
        $receipt = $verification | ConvertFrom-Json
        $version = $receipt.version
        $encoded = [Text.Encoding]::ASCII.GetBytes("$releaseName`n$version")
        if ($encoded.Length -gt 256) { throw 'The signed version is too long.' }
        if ((Get-FileHash -InputStream $archiveFile -Algorithm SHA256).Hash -ne $receipt.sha256) {
            throw 'The held archive differs from the verified package.'
        }
        $archiveFile.Position = 0
        $archive = [IO.Compression.ZipArchive]::new($archiveFile, 'Read', $true)
        try {
            $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            $total = [long]0
            foreach ($entry in $archive.Entries) {
                if ($entry.FullName -cnotin $files -or -not $seen.Add($entry.FullName)) {
                    throw "Unexpected or repeated package entry: $($entry.FullName)"
                }
                if ($entry.Length -le 0 -or $entry.Length -gt 256MB) { throw 'Invalid member size.' }
                $total += $entry.Length
                if ($total -gt 1GB) { throw 'The unpacked package is too large.' }
            }
            if ($seen.Count -ne $files.Count) { throw 'The package is incomplete.' }

            [void][IO.Directory]::CreateDirectory($staging)
            foreach ($entry in $archive.Entries) {
                $destination = Join-Path $staging $entry.FullName
                $output = [IO.File]::Open($destination, 'CreateNew', 'Write', 'None')
                try {
                    $inputStream = $entry.Open()
                    try {
                        $bytes = [byte[]]::new(65536)
                        $remaining = $entry.Length
                        while ($remaining -gt 0) {
                            $size = $inputStream.Read($bytes, 0, [int][Math]::Min($remaining, $bytes.Length))
                            if ($size -eq 0) { throw 'Truncated package member.' }
                            $output.Write($bytes, 0, $size)
                            $remaining -= $size
                        }
                        if ($inputStream.ReadByte() -ne -1) { throw 'Package member size mismatch.' }
                        $output.Flush($true)
                    }
                    finally { $inputStream.Dispose() }
                }
                finally { $output.Dispose() }
            }
        }
        finally { $archive.Dispose() }

        Assert-PortableLayoutVersion $staging
        if ([IO.File]::ReadAllText((Join-Path $staging 'active-release.txt')) -cne 'base') {
            throw 'The staged package must have the base release marker.'
        }
        $candidateVersion = & (Join-Path $staging 'asl-core.exe') --version
        if ($LASTEXITCODE -ne 0 -or $candidateVersion -isnot [string] -or $candidateVersion -cne $version) {
            throw 'The staged Core version does not match the signed package.'
        }

        $mapping = [IO.File]::Open($pendingPointer, 'CreateNew', 'Write', 'None')
        try {
            $mapping.Write($encoded, 0, $encoded.Length)
            $mapping.Flush($true)
        }
        finally { $mapping.Dispose() }
        [IO.Directory]::Move($staging, $release)
        $unpublished = $release
        # Publish by renaming within the same directory, without moving the old pointer aside.
        [IO.File]::Move($pendingPointer, $pointer, $true)
        $unpublished = $null
        Write-Output $version
    }
    finally {
        $env:ASL_HOME = $previousHome
        $archiveFile.Dispose()
        [IO.File]::Delete($pendingPointer)
        if ($unpublished -and [IO.Directory]::Exists($unpublished)) {
            foreach ($name in $files) {
                [IO.File]::Delete([IO.Path]::Combine($unpublished, $name))
            }
            [IO.Directory]::Delete($unpublished)
        }
    }
}
finally { $lock.Dispose() }
