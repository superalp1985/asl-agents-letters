param([string]$Root = $env:ASL_DEV_ROOT)

if ($Root -notmatch '^[A-Za-z]:[\\/]') {
    throw "Set ASL_DEV_ROOT or pass -Root with an absolute local drive path."
}
$Root = [IO.Path]::GetFullPath($Root)
if (-not (Test-Path -LiteralPath ([IO.Path]::GetPathRoot($Root)) -PathType Container)) {
    throw "The configured ASL development drive is unavailable."
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
    [IO.Directory]::CreateDirectory($directory) | Out-Null
}

$env:ASL_HOME = "$root\data"
$env:CARGO_HOME = "$root\dev-cache\cargo"
$env:RUSTUP_HOME = "$root\dev-cache\rustup"
$env:CARGO_TARGET_DIR = "$root\dev-cache\target"
$env:PATH = "$root\dev-cache\tools\bin;$env:CARGO_HOME\bin;$env:PATH"
$env:TEMP = "$root\work\tmp"
$env:TMP = "$root\work\tmp"

Write-Output "ASL development paths are set for this PowerShell process."
