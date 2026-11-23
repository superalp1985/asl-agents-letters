[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Enable')][switch]$Enable,
    [Parameter(Mandatory, ParameterSetName = 'Enable')][string]$DataDirectory,
    [Parameter(Mandatory, ParameterSetName = 'Disable')][switch]$Disable
)

$ErrorActionPreference = 'Stop'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$name = 'ASL'
if ($Enable) {
    if ($DataDirectory -notmatch '^[A-Za-z]:[\\/]' -or $DataDirectory.Contains('"')) {
        throw 'Specify an absolute local data directory.'
    }
    $launcher = Join-Path $PSScriptRoot 'Start-ASL.ps1'
    if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
        throw 'The ASL launcher is missing.'
    }
    $powershell = Join-Path $PSHOME 'powershell.exe'
    if ($PSVersionTable.PSEdition -eq 'Core') {
        $powershell = Join-Path $PSHOME 'pwsh.exe'
    }
    $dataRoot = [IO.Path]::GetFullPath($DataDirectory).TrimEnd('\', '/')
    if ($dataRoot.EndsWith(':')) {
        $dataRoot += '/'
    }
    $command = '"{0}" -NoProfile -WindowStyle Hidden -File "{1}" -Background -DataDirectory "{2}"' -f `
        $powershell, $launcher, $dataRoot
    New-Item -Path $key -Force | Out-Null
    Set-ItemProperty -LiteralPath $key -Name $name -Value $command
}
elseif ($Disable) {
    if (Get-ItemProperty -LiteralPath $key -Name $name -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -LiteralPath $key -Name $name
    }
}
$enabled = [bool](Get-ItemProperty -LiteralPath $key -Name $name -ErrorAction SilentlyContinue)
[PSCustomObject]@{ Enabled = $enabled }
