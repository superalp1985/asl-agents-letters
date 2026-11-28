#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Tag = 'v1.0.0-rc.2',
    [string]$ReleaseUrl,
    [string]$InstallRoot,
    [string]$DataDirectory,
    [string]$ManifestPath,
    [string]$SignaturePath,
    [string]$AssetDirectory,
    [switch]$NoLaunch,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    Unblock-File -LiteralPath $PSCommandPath -ErrorAction SilentlyContinue
}
catch {
}

$ReleasePublicKeyJson = @'
__RELEASE_PUBLIC_KEY_JSON__
'@
$ReleasePublicKey = $ReleasePublicKeyJson | ConvertFrom-Json
$ManifestName = 'asl-release-manifest.json'
$SignatureName = "$ManifestName.sig"
$RepositoryReleaseUrl = 'https://github.com/superalp1985/asl-agents-letters/releases/download'
$MaxManifestBytes = 1MB
$MaxAssetBytes = 2GB
$MaxExtractedBytes = 4GB
$MaxExtractedMembers = 512

function Fail([string]$Message) {
    throw $Message
}

function Decode-Base64Url([string]$Value) {
    if (-not $Value -or $Value.Length -gt 2048 -or $Value -notmatch '^[A-Za-z0-9_-]+$') {
        Fail 'Release public key contains an invalid base64url value.'
    }
    $normalized = $Value.Replace('-', '+').Replace('_', '/')
    switch ($normalized.Length % 4) {
        2 { $normalized += '==' }
        3 { $normalized += '=' }
        0 { }
        default { Fail 'Release public key contains invalid base64url length.' }
    }
    return [Convert]::FromBase64String($normalized)
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Download-File([string]$Url, [string]$Destination, [long]$MaximumBytes) {
    $request = [Net.HttpWebRequest]::Create($Url)
    $request.UserAgent = 'ASL-Bootstrap/1'
    $request.Accept = 'application/octet-stream'
    $request.Timeout = 60000
    $response = $request.GetResponse()
    try {
        if ($response.ContentLength -gt $MaximumBytes) {
            Fail "Download exceeds size limit: $Url"
        }
        $input = $response.GetResponseStream()
        $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $buffer = [byte[]]::new(1048576)
            $total = [long]0
            while (($read = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $total += $read
                if ($total -gt $MaximumBytes) {
                    Fail "Download exceeds size limit: $Url"
                }
                $output.Write($buffer, 0, $read)
            }
        }
        finally {
            $output.Dispose()
            $input.Dispose()
        }
    }
    finally {
        $response.Dispose()
    }
}

function Read-SignedManifest {
    $temporary = Join-Path ([IO.Path]::GetTempPath()) ('asl-bootstrap-' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($temporary)
    try {
        $manifestFile = $ManifestPath
        $signatureFile = $SignaturePath
        if (-not $manifestFile -and $AssetDirectory) {
            $manifestFile = Join-Path $AssetDirectory $ManifestName
            $signatureFile = Join-Path $AssetDirectory $SignatureName
        }
        if (-not $manifestFile) {
            $base = if ($ReleaseUrl) { $ReleaseUrl.TrimEnd('/') } else { "$RepositoryReleaseUrl/$Tag" }
            $manifestFile = Join-Path $temporary $ManifestName
            $signatureFile = Join-Path $temporary $SignatureName
            Download-File "$base/$ManifestName" $manifestFile $MaxManifestBytes
            Download-File "$base/$SignatureName" $signatureFile 1024
        }
        if (-not $signatureFile) {
            Fail 'SignaturePath is required with ManifestPath.'
        }
        foreach ($path in @($manifestFile, $signatureFile)) {
            if (-not [IO.File]::Exists($path) -or
                (([IO.File]::GetAttributes($path)) -band [IO.FileAttributes]::ReparsePoint)) {
                Fail "Release verification input is missing or unsafe: $path"
            }
        }
        $manifestBytes = [IO.File]::ReadAllBytes($manifestFile)
        $signature = [IO.File]::ReadAllBytes($signatureFile)
        if ($manifestBytes.Length -le 0 -or $manifestBytes.Length -gt $MaxManifestBytes) {
            Fail 'Release manifest size is invalid.'
        }

        $modulus = Decode-Base64Url $ReleasePublicKey.modulus
        $exponent = Decode-Base64Url $ReleasePublicKey.exponent
        $rsa = [Security.Cryptography.RSA]::Create()
        try {
            $parameters = [Security.Cryptography.RSAParameters]::new()
            $parameters.Modulus = $modulus
            $parameters.Exponent = $exponent
            $rsa.KeySize = 4096
            $rsa.ImportParameters($parameters)
            if ($rsa.KeySize -lt 3072 -or $signature.Length -ne ($rsa.KeySize / 8)) {
                Fail 'Release public key or signature size is invalid.'
            }
            $domain = [Text.Encoding]::ASCII.GetBytes("ASL-RELEASE-MANIFEST-v1`0")
            $message = [byte[]]::new($domain.Length + $manifestBytes.Length)
            [Buffer]::BlockCopy($domain, 0, $message, 0, $domain.Length)
            [Buffer]::BlockCopy($manifestBytes, 0, $message, $domain.Length, $manifestBytes.Length)
            $valid = $rsa.VerifyData(
                $message,
                $signature,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            if (-not $valid) {
                Fail 'Release manifest signature verification failed.'
            }
        }
        finally {
            $rsa.Dispose()
        }
        $document = [Text.Encoding]::UTF8.GetString($manifestBytes) | ConvertFrom-Json
        if ($document.format_version -ne 1 -or $document.product -ne 'asl' -or
            $document.tag -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$' -or
            $document.version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$' -or
            $document.commit -notmatch '^[0-9a-f]{40}$') {
            Fail 'Signed release manifest metadata is invalid.'
        }
        if ($Tag -and $document.tag -ne $Tag) {
            Fail 'Signed manifest tag does not match the requested release.'
        }
        return $document
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            [IO.Directory]::Delete($temporary, $true)
        }
    }
}

function Select-Asset($Document, [string]$Kind) {
    $matches = @($Document.assets | Where-Object {
        $_.os -eq 'windows' -and $_.arch -eq 'x86_64' -and $_.kind -eq $Kind
    })
    if ($matches.Count -ne 1) {
        Fail "Expected exactly one Windows x86_64 $Kind asset, found $($matches.Count)."
    }
    return $matches[0]
}

function Verify-Asset([string]$Path, $Asset) {
    if ($Asset.name -notmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$' -or
        $Asset.sha256 -notmatch '^[0-9a-f]{64}$' -or
        $Asset.size -isnot [long] -or $Asset.size -le 0 -or $Asset.size -gt $MaxAssetBytes) {
        Fail 'Signed asset metadata is invalid.'
    }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or $item.Length -ne $Asset.size) {
        Fail "Asset size mismatch: $($Asset.name)"
    }
    if ((Get-Sha256 $Path) -ne $Asset.sha256) {
        Fail "Asset SHA-256 mismatch: $($Asset.name)"
    }
}

function Get-ReleaseAsset($Document) {
    $asset = Select-Asset $Document 'client'
    if ($AssetDirectory) {
        $path = Join-Path $AssetDirectory $asset.name
    }
    else {
        $base = if ($ReleaseUrl) { $ReleaseUrl.TrimEnd('/') } else { "$RepositoryReleaseUrl/$($Document.tag)" }
        $path = Join-Path ([IO.Path]::GetTempPath()) ('asl-asset-' + [guid]::NewGuid().ToString('N') + '.zip')
        Download-File "$base/$([Uri]::EscapeDataString($asset.name))" $path $MaxAssetBytes
    }
    Verify-Asset $path $asset
    return [PSCustomObject]@{ Path = $path; Asset = $asset }
}

function Assert-SafeEntry([string]$Relative) {
    if ([IO.Path]::IsPathRooted($Relative)) {
        Fail "ZIP entry is absolute: $Relative"
    }
    $parts = $Relative -split '[\\/]'
    if ($parts.Count -eq 0 -or @($parts | Where-Object { $_ -in @('', '.', '..') }).Count -gt 0) {
        Fail "ZIP entry has an unsafe path: $Relative"
    }
    return $parts
}

function Expand-ClientZip([string]$Archive, [string]$Destination) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    $root = [IO.Path]::GetFullPath($Destination).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $total = [long]0
    try {
        if ($zip.Entries.Count -lt 1 -or $zip.Entries.Count -gt $MaxExtractedMembers) {
            Fail 'ZIP member count is outside the supported range.'
        }
        foreach ($entry in $zip.Entries) {
            $parts = Assert-SafeEntry $entry.FullName
            $relative = $parts -join [IO.Path]::DirectorySeparatorChar
            if (-not $seen.Add($relative)) {
                Fail "ZIP contains a duplicate path: $relative"
            }
            $mode = ($entry.ExternalAttributes -shr 16) -band 0xF000
            if ($mode -eq 0xA000) {
                Fail "ZIP symlink refused: $relative"
            }
            $target = [IO.Path]::GetFullPath((Join-Path $Destination $relative))
            if (-not $target.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
                Fail "ZIP entry escapes the destination: $relative"
            }
            if ($entry.Name -eq '') {
                [void][IO.Directory]::CreateDirectory($target)
                continue
            }
            $total += $entry.Length
            if ($total -gt $MaxExtractedBytes) {
                Fail 'ZIP expands beyond the size limit.'
            }
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
            $input = $entry.Open()
            $output = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try {
                $input.CopyTo($output)
            }
            finally {
                $output.Dispose()
                $input.Dispose()
            }
        }
    }
    finally {
        $zip.Dispose()
    }
}

function Remove-MarkOfTheWeb([string]$Root) {
    Get-ChildItem -LiteralPath $Root -Recurse -File | Unblock-File -ErrorAction SilentlyContinue
}

$document = Read-SignedManifest
$bootstrapAsset = Select-Asset $document 'bootstrap'
if ($bootstrapAsset.name -ne [IO.Path]::GetFileName($PSCommandPath)) {
    Fail 'Signed manifest bootstrap name does not match this script.'
}
if ((Get-Sha256 $PSCommandPath) -ne $bootstrapAsset.sha256) {
    Fail 'Running PowerShell bootstrap does not match the signed release.'
}

if (-not $InstallRoot) {
    if (-not $env:LOCALAPPDATA) { Fail 'LOCALAPPDATA is not set.' }
    $InstallRoot = Join-Path $env:LOCALAPPDATA 'ASL\client'
}
if (-not $DataDirectory) {
    if (-not $env:LOCALAPPDATA) { Fail 'LOCALAPPDATA is not set.' }
    $DataDirectory = Join-Path $env:LOCALAPPDATA 'ASL\data'
}
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$DataDirectory = [IO.Path]::GetFullPath($DataDirectory)
$clientMetadata = Select-Asset $document 'client'
$releaseName = "$($document.version)-$($clientMetadata.sha256.Substring(0, 12))"
$releasePath = Join-Path $InstallRoot $releaseName

if ($DryRun) {
    [PSCustomObject]@{
        Tag = $document.tag
        Version = $document.version
        Asset = $clientMetadata.name
        InstallRoot = $InstallRoot
        DataDirectory = $DataDirectory
        ReleasePath = $releasePath
    }
    exit 0
}

$client = Get-ReleaseAsset $document
[void][IO.Directory]::CreateDirectory($InstallRoot)
if (-not [IO.Directory]::Exists($releasePath)) {
    $staging = Join-Path $InstallRoot ('.install-' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($staging)
    try {
        Expand-ClientZip $client.Path $staging
        foreach ($required in @('asl.exe', 'asl-core.exe', 'asl-ui.exe', 'Start-ASL.ps1', 'vcruntime140.dll')) {
            if (-not [IO.File]::Exists((Join-Path $staging $required))) {
                Fail "Windows package is missing $required"
            }
        }
        [IO.File]::WriteAllText((Join-Path $staging '.bootstrap-asset-sha256'), $client.Asset.sha256, [Text.Encoding]::ASCII)
        [IO.Directory]::Move($staging, $releasePath)
    }
    finally {
        if (Test-Path -LiteralPath $staging) {
            [IO.Directory]::Delete($staging, $true)
        }
    }
}
else {
    $marker = Join-Path $releasePath '.bootstrap-asset-sha256'
    if (-not [IO.File]::Exists($marker) -or
        [IO.File]::ReadAllText($marker) -ne $client.Asset.sha256) {
        Fail "Existing release directory is not managed by this bootstrap: $releasePath"
    }
}

Remove-MarkOfTheWeb $releasePath
[void][IO.Directory]::CreateDirectory($DataDirectory)
if (-not $NoLaunch) {
    & (Join-Path $releasePath 'Start-ASL.ps1') -DataDirectory $DataDirectory
}
Write-Output "Installed ASL $($document.version)"
Write-Output "Release: $releasePath"
Write-Output "ASL_HOME: $DataDirectory"
