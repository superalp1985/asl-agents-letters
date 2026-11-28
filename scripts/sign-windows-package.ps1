#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Package,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$ReleasePrivateKey,
    [string]$OutputDirectory,
    [string]$OpenSslPath,
    [string]$VerifierCore
)

$ErrorActionPreference = 'Stop'

if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:\+[0-9A-Za-z.-]+)?$') {
    throw 'Use a release SemVer without a prerelease suffix.'
}
if (-not (Test-Path -LiteralPath $Package -PathType Leaf)) {
    throw 'The package ZIP does not exist.'
}
if (-not (Test-Path -LiteralPath $ReleasePrivateKey -PathType Leaf)) {
    throw 'The release private key does not exist.'
}

$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$privateKey = (Resolve-Path -LiteralPath $ReleasePrivateKey).Path
$relativeKey = [IO.Path]::GetRelativePath($repo, $privateKey)
if (-not $relativeKey.StartsWith('..') -and -not [IO.Path]::IsPathRooted($relativeKey)) {
    throw 'Refusing to use a release private key stored inside the repository.'
}
$packagePath = (Resolve-Path -LiteralPath $Package).Path
$output = if ($OutputDirectory) {
    [IO.Path]::GetFullPath($OutputDirectory)
} else {
    [IO.Path]::GetDirectoryName($packagePath)
}
[void][IO.Directory]::CreateDirectory($output)
if (-not $OpenSslPath) {
    $command = Get-Command 'openssl.exe' -ErrorAction SilentlyContinue
    if ($command) { $OpenSslPath = $command.Source }
}
if (-not $OpenSslPath -or -not (Test-Path -LiteralPath $OpenSslPath -PathType Leaf)) {
    throw 'Pass -OpenSslPath or make openssl.exe available on PATH (OpenSSL 3 or newer).'
}
$OpenSslPath = (Resolve-Path -LiteralPath $OpenSslPath).Path

$packageItem = Get-Item -LiteralPath $packagePath
if ($packageItem.Length -le 0 -or $packageItem.Length -gt 1GB) {
    throw 'The package size is outside the supported update range.'
}
$sha256 = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
$manifest = [ordered]@{
    format_version = 1
    version = $Version
    platform = 'windows-x86_64'
    archive_bytes = $packageItem.Length
    sha256 = $sha256
}
$manifestBytes = [Text.Encoding]::UTF8.GetBytes(($manifest | ConvertTo-Json -Compress))
if ($manifestBytes.Length -gt 4096) {
    throw 'The generated release manifest is oversized.'
}

$basename = [IO.Path]::GetFileNameWithoutExtension($packagePath)
$manifestPath = Join-Path $output "$basename.manifest.json"
$signaturePath = Join-Path $output "$basename.manifest.sig"
$publicRawPath = Join-Path $output "$basename.release-key.ed25519"
$publicPemPath = Join-Path $output "$basename.release-key.pem"
$hashPath = Join-Path $output "$basename.sha256"
foreach ($path in @($manifestPath, $signaturePath, $publicRawPath, $publicPemPath, $hashPath)) {
    if (Test-Path -LiteralPath $path) { throw "Release output already exists: $path" }
}

$temporary = Join-Path $output ('.sign-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temporary)
try {
    $temporaryMessage = Join-Path $temporary 'message.bin'
    $temporarySignature = Join-Path $temporary 'signature.bin'
    $temporaryPublicPem = Join-Path $temporary 'release-key.pem'
    $temporaryPublicDer = Join-Path $temporary 'release-key.der'
    $temporaryManifest = Join-Path $temporary 'manifest.json'
    $temporaryRawKey = Join-Path $temporary 'release-key.ed25519'

    [IO.File]::WriteAllBytes($temporaryManifest, $manifestBytes)
    $domain = [Text.Encoding]::ASCII.GetBytes("ASL-WINDOWS-UPDATE-v1`0")
    $message = [byte[]]::new($domain.Length + $manifestBytes.Length)
    [Array]::Copy($domain, 0, $message, 0, $domain.Length)
    [Array]::Copy($manifestBytes, 0, $message, $domain.Length, $manifestBytes.Length)
    [IO.File]::WriteAllBytes($temporaryMessage, $message)

    & $OpenSslPath pkeyutl -sign -rawin -inkey $privateKey -in $temporaryMessage -out $temporarySignature
    if ($LASTEXITCODE -ne 0) { throw 'Ed25519 manifest signing failed.' }
    & $OpenSslPath pkey -in $privateKey -pubout -out $temporaryPublicPem
    if ($LASTEXITCODE -ne 0) { throw 'Release public key derivation failed.' }
    & $OpenSslPath pkey -in $privateKey -pubout -outform DER -out $temporaryPublicDer
    if ($LASTEXITCODE -ne 0) { throw 'Release public key encoding failed.' }
    & $OpenSslPath pkeyutl -verify -pubin -inkey $temporaryPublicPem -rawin `
        -in $temporaryMessage -sigfile $temporarySignature | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Ed25519 manifest signature verification failed.' }

    $der = [IO.File]::ReadAllBytes($temporaryPublicDer)
    if ($der.Length -ne 44) {
        throw 'The release key is not an Ed25519 SubjectPublicKeyInfo key.'
    }
    $rawKey = [byte[]]::new(32)
    [Array]::Copy($der, 12, $rawKey, 0, 32)
    [IO.File]::WriteAllBytes($temporaryRawKey, $rawKey)

    if ($VerifierCore) {
        if (-not (Test-Path -LiteralPath $VerifierCore -PathType Leaf)) {
            throw 'The verifier Core executable does not exist.'
        }
        & (Resolve-Path -LiteralPath $VerifierCore).Path `
            --verify-update $temporaryRawKey $temporaryManifest $temporarySignature $packagePath | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'A previous Core release rejected the generated update receipt.'
        }
    }

    [IO.File]::Move($temporaryManifest, $manifestPath)
    [IO.File]::Move($temporarySignature, $signaturePath)
    [IO.File]::Move($temporaryRawKey, $publicRawPath)
    [IO.File]::Move($temporaryPublicPem, $publicPemPath)
    [IO.File]::WriteAllText($hashPath, "$sha256  $([IO.Path]::GetFileName($packagePath))`n", [Text.Encoding]::ASCII)
}
finally {
    if ([IO.Directory]::Exists($temporary)) {
        Get-ChildItem -LiteralPath $temporary -File | ForEach-Object {
            [IO.File]::Delete($_.FullName)
        }
        [IO.Directory]::Delete($temporary)
    }
}

[PSCustomObject]@{
    Manifest = $manifestPath
    Signature = $signaturePath
    PublicKeyRaw = $publicRawPath
    PublicKeyPem = $publicPemPath
    Sha256 = $hashPath
}
