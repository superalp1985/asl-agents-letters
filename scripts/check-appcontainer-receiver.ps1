[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Sid,
    [Parameter(Mandatory)][string]$Report,
    [ValidateSet("Present", "Absent")][string]$Expect = "Present"
)

$ErrorActionPreference = "Stop"
function Test-ReceiverPermit([string]$Path) {
    $xml = [xml]::new()
    $xml.Load($Path)
    if (-not $xml.SelectSingleNode("/wfpdiag/filters")) { throw "Invalid WFP filter report." }
    $rule = $xml.SelectSingleNode("/wfpdiag/filters/item[
        layerKey='FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4' and
        subLayerKey='FWPM_SUBLAYER_MPSSVC_APP_ISOLATION' and action/type='FWP_ACTION_PERMIT' and
        filterCondition/item[fieldKey='FWPM_CONDITION_ALE_PACKAGE_ID' and matchType='FWP_MATCH_EQUAL' and conditionValue/sid='$Sid'] and
        filterCondition/item[fieldKey='FWPM_CONDITION_FLAGS' and matchType='FWP_MATCH_FLAGS_ALL_SET' and conditionValue/uint32='1']
    ]")
    return $null -ne $rule
}

if ($Sid -notmatch '^S-1-15-2-(\d+-){6}\d+$') { throw "Expected an AppContainer SID." }
if ((Test-ReceiverPermit $Report) -eq ($Expect -eq "Present")) { exit 0 }
exit 3
