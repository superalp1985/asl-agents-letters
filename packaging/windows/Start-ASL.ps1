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
[void][IO.Directory]::CreateDirectory($dataRoot)
$release = (Get-PortableRelease $PSScriptRoot).Directory
$core = Join-Path $release 'asl-core.exe'
$viewer = Join-Path $release 'asl-ui.exe'
$runtime = Join-Path $release 'vcruntime140.dll'
if (-not $ViewerOnly) { Assert-PortablePath $core }
if (-not $Background) { Assert-PortablePath $viewer }
if ((-not $ViewerOnly) -or (-not $Background)) { Assert-PortablePath $runtime }
$previousRoot = $env:ASL_HOME
$viewerArguments = '--home "' + $dataRoot + '"'
try {
    $env:ASL_HOME = $dataRoot
    if ($ViewerOnly) {
        Start-Process -FilePath $viewer -ArgumentList $viewerArguments
        return
    }
    $logRoot = Join-Path $dataRoot 'logs'
    [void][IO.Directory]::CreateDirectory($logRoot)
    $stdout = Join-Path $logRoot 'core-start.stdout.log'
    $stderr = Join-Path $logRoot 'core-start.stderr.log'
    $process = Start-Process -FilePath $core `
        -WindowStyle Hidden `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -PassThru
    if (-not $Background) {
        $database = Join-Path $dataRoot 'state\asl.sqlite3'
        for ($attempt = 0; $attempt -lt 200; $attempt++) {
            if ($process.HasExited -or (Test-Path -LiteralPath $database -PathType Leaf)) {
                break
            }
            Start-Sleep -Milliseconds 100
        }
        if (-not (Test-Path -LiteralPath $database -PathType Leaf)) {
            if (-not $process.HasExited) {
                Stop-Process -Id $process.Id -Force
                Wait-Process -Id $process.Id -ErrorAction SilentlyContinue
            }
            $details = if (Test-Path -LiteralPath $stderr) {
                [IO.File]::ReadAllText($stderr).Trim()
            } else {
                ''
            }
            throw "ASL Core did not initialize $database. $details Logs: $stdout $stderr"
        }
        Start-Process -FilePath $viewer -ArgumentList $viewerArguments
    }
}
finally {
    $env:ASL_HOME = $previousRoot
}
