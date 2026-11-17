$ErrorActionPreference = "Stop"

$root = "E:\ASL"
if (-not (Test-Path -LiteralPath "E:\")) {
    throw "E: drive is unavailable; ASL will not move caches to another drive."
}

$directories = @(
    "$root\data",
    "$root\dev-cache\cargo",
    "$root\dev-cache\rustup",
    "$root\dev-cache\target",
    "$root\dev-cache\tools\bin",
    "$root\work\tmp"
)

foreach ($directory in $directories) {
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
}

$env:ASL_HOME = "$root\data"
$env:CARGO_HOME = "$root\dev-cache\cargo"
$env:RUSTUP_HOME = "$root\dev-cache\rustup"
$env:CARGO_TARGET_DIR = "$root\dev-cache\target"
$env:PATH = "$root\dev-cache\tools\bin;$env:CARGO_HOME\bin;$env:PATH"
$env:TEMP = "$root\work\tmp"
$env:TMP = "$root\work\tmp"

Write-Output "ASL development paths are set for this PowerShell process."
