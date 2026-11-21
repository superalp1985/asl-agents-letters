[CmdletBinding()]
param(
    [string]$DevRoot = $env:ASL_DEV_ROOT
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell. Windows only permits LoopbackExempt changes from an administrator session."
}

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
if (-not $DevRoot) {
    for ($current = Get-Item -LiteralPath $repo; $null -ne $current; $current = $current.Parent) {
        if (Test-Path -LiteralPath (Join-Path $current.FullName "dev-cache") -PathType Container) {
            $DevRoot = $current.FullName
            break
        }
    }
}
if (-not $DevRoot) {
    throw "Set ASL_DEV_ROOT or pass -DevRoot with the ASL development root."
}

. (Join-Path $PSScriptRoot "dev-env.ps1") -Root $DevRoot
Push-Location $repo
try {
    & cargo +1.100.0 build -p asl-app --bin asl-net --bin asl-worker --bin asl-extractor --locked --offline
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
    & cargo +1.100.0 test -p asl-app --lib --locked --offline `
        supervisor::groups::process_tests::group_messages_cross_sandboxed_net_processes `
        -- --ignored --exact --nocapture --test-threads=1
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
