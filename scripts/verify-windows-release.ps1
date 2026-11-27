#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Package,
    [Parameter(Mandatory)][string]$Manifest,
    [Parameter(Mandatory)][string]$Signature,
    [Parameter(Mandatory)][string]$TrustedKeySha256,
    [string]$PublicKeyRaw,
    [string]$VerifierCore,
    [string]$TrustedInstallRoot,
    [string]$PortableLayoutScript,
    [switch]$RequireAuthenticode,
    [string]$ScratchRoot = [IO.Path]::GetTempPath()
)

$ErrorActionPreference = 'Stop'
if ($TrustedKeySha256 -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'TrustedKeySha256 must be the independently authenticated SHA-256 of the raw key.'
}
$sourceLayoutScript = [IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\packaging\windows\Portable-Layout.ps1')
)
$layoutScript = if ($PortableLayoutScript) {
    [IO.Path]::GetFullPath($PortableLayoutScript)
} elseif (Test-Path -LiteralPath $sourceLayoutScript -PathType Leaf) {
    $sourceLayoutScript
} elseif ($TrustedInstallRoot) {
    Join-Path ([IO.Path]::GetFullPath($TrustedInstallRoot)) 'Portable-Layout.ps1'
} else {
    $sourceLayoutScript
}
if (-not (Test-Path -LiteralPath $layoutScript -PathType Leaf) -or
    (Get-Item -LiteralPath $layoutScript -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'A trusted portable-layout verifier script is required.'
}
$layoutItem = Get-Item -LiteralPath $layoutScript -Force
while ($null -ne $layoutItem) {
    if ($layoutItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'The portable-layout verifier path must not traverse a reparse point.'
    }
    $layoutItem = if ($layoutItem -is [IO.DirectoryInfo]) {
        $layoutItem.Parent
    } else {
        $layoutItem.Directory
    }
}
. $layoutScript
if ($TrustedInstallRoot) {
    $trustedRoot = [IO.Path]::GetFullPath($TrustedInstallRoot)
    Assert-PortableRoot $trustedRoot
    Assert-PortableLayoutVersion $trustedRoot
    if (-not $PublicKeyRaw) { $PublicKeyRaw = Join-Path $trustedRoot 'release-key.ed25519' }
    if (-not $VerifierCore) { $VerifierCore = Join-Path $trustedRoot 'asl-core.exe' }
}
if (-not $PublicKeyRaw -or -not $VerifierCore) {
    throw 'Pass -TrustedInstallRoot or both -PublicKeyRaw and -VerifierCore.'
}
foreach ($path in @($Package, $Manifest, $Signature, $PublicKeyRaw, $VerifierCore)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Release input is missing: $path"
    }
    if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Release inputs must not be reparse points: $path"
    }
}
$packageItem = Get-Item -LiteralPath $Package
$manifestItem = Get-Item -LiteralPath $Manifest
$signatureItem = Get-Item -LiteralPath $Signature
if ($packageItem.Length -le 0 -or $packageItem.Length -gt 1GB) {
    throw 'The Windows release package size is outside the supported range.'
}
if ($manifestItem.Length -le 0 -or $manifestItem.Length -gt 4096) {
    throw 'The Windows release manifest size is outside the supported range.'
}
if ($signatureItem.Length -ne 64) {
    throw 'The Windows release signature must contain exactly 64 bytes.'
}
$keyBytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $PublicKeyRaw).Path)
if ($keyBytes.Length -ne 32) {
    throw 'The pinned release public key must be exactly 32 raw Ed25519 bytes.'
}
$actualFingerprint = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData($keyBytes)
).ToLowerInvariant()
if ($actualFingerprint -cne $TrustedKeySha256.ToLowerInvariant()) {
    throw 'Public-key fingerprint mismatch; authenticate the key out of band.'
}

$corePath = (Resolve-Path -LiteralPath $VerifierCore).Path
$packagePath = (Resolve-Path -LiteralPath $Package).Path
$manifestPath = (Resolve-Path -LiteralPath $Manifest).Path
$signaturePath = (Resolve-Path -LiteralPath $Signature).Path
$keyPath = (Resolve-Path -LiteralPath $PublicKeyRaw).Path
$packageStream = [IO.File]::Open($packagePath, 'Open', 'Read', 'Read')
try {
    & $corePath --verify-update $keyPath $manifestPath $signaturePath $packagePath
    if ($LASTEXITCODE -ne 0) {
        throw 'Trusted Core rejected the offline Windows release receipt.'
    }
    $layout = Assert-PortablePackageArchive -InputStream $packageStream
    if ($RequireAuthenticode) {
        Assert-PortableAuthenticode -InputStream $packageStream -ScratchRoot $ScratchRoot
    }
}
finally {
    $packageStream.Dispose()
}

[PSCustomObject]@{
    Result = 'Offline Windows release verification passed.'
    Package = $packagePath
    Members = @($layout.Members).Count
    HasNetworkSeeds = $layout.HasNetworkSeeds
    AuthenticodeRequired = [bool]$RequireAuthenticode
}
