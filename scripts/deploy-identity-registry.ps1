#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RpcUrl,
    [Parameter(Mandatory)][string]$Account,
    [string]$Keystore,
    [switch]$Broadcast,
    [long]$ExpectedChainId
)

$ErrorActionPreference = 'Stop'
if ($RpcUrl -notmatch '^https?://') {
    throw 'RpcUrl must be an explicit HTTP(S) endpoint.'
}
$chainArguments = @()
if ($Broadcast) {
    if ($ExpectedChainId -le 0) {
        throw 'Broadcast requires an explicit positive -ExpectedChainId.'
    }
    $cast = Get-Command cast -ErrorAction Stop
    $actualChainIdText = & $cast.Source chain-id --rpc-url $RpcUrl
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to read chain ID from the explicit RPC endpoint; no transaction was sent.'
    }
    $actualChainId = [long]::Parse(
        ($actualChainIdText | Out-String).Trim(),
        [Globalization.CultureInfo]::InvariantCulture
    )
    if ($actualChainId -ne $ExpectedChainId) {
        throw "RPC chain ID mismatch: expected $ExpectedChainId, received $actualChainId. No transaction was sent."
    }
    $chainArguments = @('--chain-id', $ExpectedChainId.ToString([Globalization.CultureInfo]::InvariantCulture), '--broadcast')
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
        '--account', $Account
    )
    $arguments += $chainArguments
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
