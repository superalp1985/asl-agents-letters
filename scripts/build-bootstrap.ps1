#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string]$Python = 'python',
    [string]$AuthenticodeThumbprint,
    [string]$SignToolPath,
    [string]$TimestampUrl
)

$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) {
    throw "Output directory already exists: $output"
}
[void][IO.Directory]::CreateDirectory($output)
$name = 'asl-bootstrap-windows-x86_64'
$work = Join-Path ([IO.Path]::GetTempPath()) ('asl-bootstrap-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($work)
try {
    & $Python -m PyInstaller `
        --noconfirm `
        --clean `
        --onefile `
        --name $name `
        --distpath $work `
        --workpath (Join-Path $work 'build') `
        --specpath $work `
        --paths $repo `
        (Join-Path $repo 'bootstrap\asl_bootstrap.py')
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller failed' }
    $source = Join-Path $work "$name.exe"
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw 'PyInstaller did not produce the Windows bootstrap executable'
    }
    $destination = Join-Path $output "$name.exe"
    [IO.File]::Copy($source, $destination)
    if ($AuthenticodeThumbprint) {
        if (-not $TimestampUrl) { throw 'TimestampUrl is required for Authenticode signing' }
        if (-not $SignToolPath) {
            $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
            if ($command) { $SignToolPath = $command.Source }
        }
        if (-not $SignToolPath -or -not (Test-Path -LiteralPath $SignToolPath -PathType Leaf)) {
            throw 'SignToolPath is required for Authenticode signing'
        }
        & $SignToolPath sign /sha1 $AuthenticodeThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $destination
        if ($LASTEXITCODE -ne 0) { throw 'Authenticode signing failed' }
        $signature = Get-AuthenticodeSignature -LiteralPath $destination
        if ($signature.Status -ne 'Valid') {
            throw "Authenticode verification failed: $($signature.StatusMessage)"
        }
    }
    Write-Output $destination
}
finally {
    if (Test-Path -LiteralPath $work) {
        [IO.Directory]::Delete($work, $true)
    }
}
