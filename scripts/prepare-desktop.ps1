[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RunDir,
    [switch]$Offline,
    [switch]$Release
)

$ErrorActionPreference = "Stop"
if (-not $env:CARGO_TARGET_DIR -or -not $env:CARGO_HOME -or -not $env:RUSTUP_HOME) {
    throw "Run scripts/dev-env.ps1 in this PowerShell session first."
}
if ($RunDir -notmatch '^[A-Za-z]:[\\/]') {
    throw "Pass a new absolute local directory for -RunDir."
}
$destination = [IO.Path]::GetFullPath($RunDir)
if (Test-Path -LiteralPath $destination) {
    throw "The run directory already exists. Reuse its binaries or build into a new directory."
}

$names = @("asl", "asl-core", "asl-net", "asl-worker", "asl-extractor", "asl-ui")
$build = @("build", "-p", "asl-app", "--features", "desktop-ui", "--locked", "--message-format=json-render-diagnostics")
if ($Offline) { $build += "--offline" }
if ($Release) { $build += "--release" }
foreach ($name in $names) { $build += @("--bin", $name) }

$binaries = @{}
Push-Location -LiteralPath (Join-Path $PSScriptRoot "..")
try {
    & cargo @build | ForEach-Object {
        $event = ConvertFrom-Json -InputObject $_
        if ($event.reason -eq "compiler-artifact" -and $event.executable -and $event.target.name -in $names) {
            $binaries[$event.target.name] = $event.executable
        }
    }
    if ($LASTEXITCODE -ne 0 -or $binaries.Count -ne $names.Count) {
        throw "Cargo did not produce the complete Windows runtime."
    }
}
finally { Pop-Location }

# Publish the complete set together. Copies give each helper its own NTFS file.
$parent = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
$staging = $parent.CreateSubdirectory([guid]::NewGuid().ToString("N")).FullName
try {
    foreach ($name in $names) {
        [IO.File]::Copy($binaries[$name], (Join-Path $staging "$name.exe"))
    }
    [IO.Directory]::Move($staging, $destination)
}
finally {
    if ([IO.Directory]::Exists($staging)) {
        foreach ($name in $names) { [IO.File]::Delete((Join-Path $staging "$name.exe")) }
        [IO.Directory]::Delete($staging)
    }
}
Write-Output $destination
