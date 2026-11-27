#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RpcUrl,
    [Parameter(Mandatory)][string]$RegistryAddress,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$ExpectedChainId,
    [Parameter(Mandatory)][string]$ExpectedRuntimeCodeHash
)

$ErrorActionPreference = 'Stop'
if ($RpcUrl -notmatch '^https?://') {
    throw 'RpcUrl must be an explicit HTTP(S) endpoint.'
}
if ($RegistryAddress -notmatch '^0x[0-9a-fA-F]{40}$') {
    throw 'Pass the registry address returned by the deployment receipt.'
}
if ($ExpectedRuntimeCodeHash -notmatch '^0x[0-9a-fA-F]{64}$') {
    throw 'ExpectedRuntimeCodeHash must be an explicitly reviewed bytes32 hash.'
}

$cast = Get-Command cast -ErrorAction Stop
$chainIdText = & $cast.Source chain-id --rpc-url $RpcUrl
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to read the chain ID from the explicit RPC endpoint.'
}
$chainId = [long]::Parse(
    ($chainIdText | Out-String).Trim(),
    [Globalization.CultureInfo]::InvariantCulture
)
if ($chainId -ne $ExpectedChainId) {
    throw "Chain ID mismatch: expected $ExpectedChainId, received $chainId."
}

$runtimeCode = & $cast.Source code $RegistryAddress --rpc-url $RpcUrl
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to fetch the registry runtime code.'
}
$runtimeCode = ($runtimeCode | Out-String).Trim()
if ($runtimeCode -notmatch '^0x(?:[0-9a-fA-F]{2})+$') {
    throw 'The supplied registry address has no valid runtime bytecode.'
}
$runtimeHash = & $cast.Source keccak $runtimeCode
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to hash the fetched registry runtime code.'
}
$runtimeHash = ($runtimeHash | Out-String).Trim()
if ($runtimeHash -ine $ExpectedRuntimeCodeHash) {
    throw "Runtime code hash mismatch: expected $ExpectedRuntimeCodeHash, received $runtimeHash."
}

[PSCustomObject]@{
    ChainId = $chainId
    RegistryAddress = $RegistryAddress
    RuntimeCodeHash = $runtimeHash
    Verified = $true
}
