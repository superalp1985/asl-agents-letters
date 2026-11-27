#requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$inputJson = [Console]::In.ReadToEnd()
if ([string]::IsNullOrWhiteSpace($inputJson)) {
    throw 'Expected an ASL self-pay signing request on stdin.'
}
$request = $inputJson | ConvertFrom-Json
if ($request.schema -ne 'asl-self-pay-sign-v1' -or $null -eq $request.request) {
    throw 'Unsupported signing request.'
}

$account = $env:ASL_WALLET_ACCOUNT
$rpcUrl = $env:ASL_SELF_PAY_RPC_URL
if ([string]::IsNullOrWhiteSpace($account) -or [string]::IsNullOrWhiteSpace($rpcUrl)) {
    throw 'Set ASL_WALLET_ACCOUNT and ASL_SELF_PAY_RPC_URL outside the repository.'
}
$cast = Get-Command cast -ErrorAction Stop
$raw = & $cast.Source mktx `
    --rpc-url $rpcUrl `
    --chain $request.request.chain_id `
    --account $account `
    $request.request.registry `
    $request.request.calldata
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($raw -join ''))) {
    throw 'The external wallet did not produce a raw transaction.'
}

[pscustomobject]@{
    raw_transaction = ($raw -join '').Trim()
} | ConvertTo-Json -Compress
