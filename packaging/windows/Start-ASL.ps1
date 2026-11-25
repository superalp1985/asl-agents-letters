[CmdletBinding(DefaultParameterSetName = 'Desktop')]
param(
    [Parameter(Mandatory)][string]$DataDirectory,
    [Parameter(Mandatory, ParameterSetName = 'Background')][switch]$Background,
    [Parameter(Mandatory, ParameterSetName = 'ViewerOnly')][switch]$ViewerOnly
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Portable-Layout.ps1')
if ($DataDirectory -notmatch '^[A-Za-z]:[\\/]') {
    throw 'Specify an absolute local data directory.'
}
$dataRoot = [IO.Path]::GetFullPath($DataDirectory)
$release = (Get-PortableRelease $PSScriptRoot).Directory
$core = Join-Path $release 'asl-core.exe'
$viewer = Join-Path $release 'asl-ui.exe'
if (-not $ViewerOnly) { Assert-PortablePath $core }
if (-not $Background) { Assert-PortablePath $viewer }
$previousRoot = $env:ASL_HOME
try {
    $env:ASL_HOME = $dataRoot
    if ($ViewerOnly) {
        Start-Process -FilePath $viewer
        return
    }
    $process = Start-Process -FilePath $core -WindowStyle Hidden -PassThru
    if (-not $Background) {
        $database = Join-Path $dataRoot 'state\asl.sqlite3'
        for ($attempt = 0; $attempt -lt 60; $attempt++) {
            if ($process.HasExited -or (Test-Path -LiteralPath $database -PathType Leaf)) {
                break
            }
            Start-Sleep -Milliseconds 100
        }
        Start-Process -FilePath $viewer
    }
}
finally {
    $env:ASL_HOME = $previousRoot
}
