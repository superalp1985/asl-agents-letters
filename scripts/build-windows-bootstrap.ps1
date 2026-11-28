#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string]$AuthenticodeThumbprint,
    [string]$TimestampUrl
)

$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) {
    throw "Output directory already exists: $output"
}
$templatePath = Join-Path $repo 'bootstrap\asl-bootstrap.ps1'
$keyPath = Join-Path $repo 'packaging\release\release-public-key.json'
$template = [IO.File]::ReadAllText($templatePath)
$key = [IO.File]::ReadAllText($keyPath) | ConvertFrom-Json -AsHashtable
$keyJson = $key | ConvertTo-Json -Depth 8 -Compress
$marker = '__RELEASE_PUBLIC_KEY_JSON__'
$matches = ([regex]::Matches($template, [regex]::Escape($marker))).Count
if ($matches -ne 1) {
    throw 'The Windows bootstrap template must contain exactly one public-key marker.'
}
$rendered = $template.Replace($marker, $keyJson)
[void][IO.Directory]::CreateDirectory($output)
$destination = Join-Path $output 'asl-bootstrap-windows-x86_64.ps1'
[IO.File]::WriteAllText($destination, $rendered, [Text.UTF8Encoding]::new($true))
if ($AuthenticodeThumbprint) {
    if (-not $TimestampUrl) {
        throw 'TimestampUrl is required for Authenticode signing.'
    }
    $certificate = Get-ChildItem Cert:\CurrentUser\My,Cert:\LocalMachine\My |
        Where-Object { $_.Thumbprint -eq $AuthenticodeThumbprint -and $_.HasPrivateKey } |
        Select-Object -First 1
    if (-not $certificate) {
        throw 'The requested Authenticode code-signing certificate is unavailable.'
    }
    $signature = Set-AuthenticodeSignature `
        -LiteralPath $destination `
        -Certificate $certificate `
        -TimestampServer $TimestampUrl `
        -HashAlgorithm SHA256
    if ($signature.Status -ne 'Valid') {
        throw "PowerShell Authenticode verification failed: $($signature.StatusMessage)"
    }
}
Write-Output $destination
