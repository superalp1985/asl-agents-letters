#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RpcUrl,
    [Parameter(Mandatory)][string]$Account,
    [string]$Keystore,
    [string]$Broadcast = '--broadcast'
)

$ErrorActionPreference = 'Stop'
if ($RpcUrl -notmatch '^https?://') {
    throw 'RpcUrl must be an explicit HTTP(S) endpoint.'
}
$forge = Get-Command forge -ErrorAction Stop
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\contracts'))
if (-not (Test-Path -LiteralPath (Join-Path $root 'foundry.toml'))) {
    throw 'contracts/foundry.toml was not found.'
}
Push-Location -LiteralPath $root
try {
    $arguments = @(
        'create', 'src/IdentityRegistry.sol:IdentityRegistry',
        '--rpc-url', $RpcUrl,
        '--account', $Account,
        $Broadcast
    )
    if (-not [string]::IsNullOrWhiteSpace($Keystore)) {
        $arguments += @('--keystore', $Keystore)
    }
    & $forge.Source @arguments
    if ($LASTEXITCODE -ne 0) {
        throw 'forge create failed.'
    }
}
finally {
    Pop-Location
}
