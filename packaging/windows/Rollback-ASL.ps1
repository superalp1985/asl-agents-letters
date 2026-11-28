#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][switch]$ConfirmDataCompatibility,
    [string]$InstallRoot
)

$ErrorActionPreference = 'Stop'
if (-not $ConfirmDataCompatibility) {
    throw 'Rollback requires explicit confirmation that the existing data is compatible.'
}
. (Join-Path $PSScriptRoot 'Portable-Layout.ps1')
$root = if ($InstallRoot) { [IO.Path]::GetFullPath($InstallRoot) } else { $PSScriptRoot }
Assert-PortableRoot $root
Assert-PortableLayoutVersion $root

$lockPath = Join-Path $root '.update.lock'
if (Test-Path -LiteralPath $lockPath) { Assert-PortablePath $lockPath }
$lock = [IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
try {
    $metadata = Get-PortableRollbackMetadata -Root $root
    $currentPointer = Get-PortablePointerRecord -Root $root
    if ($currentPointer -cne $metadata.active_pointer) {
        throw 'Rollback metadata does not describe the active release.'
    }
    $target = Resolve-PortableReleaseRecord -Root $root -Record $metadata.previous_pointer
    $id = [guid]::NewGuid().ToString('N')
    $pendingPointer = Join-Path $root ".active-$id"
    $pointerBytes = [Text.Encoding]::ASCII.GetBytes($metadata.previous_pointer)
    $mapping = [IO.File]::Open($pendingPointer, 'CreateNew', 'Write', 'None')
    try {
        $mapping.Write($pointerBytes, 0, $pointerBytes.Length)
        $mapping.Flush($true)
    }
    finally { $mapping.Dispose() }
    try {
        $rollbackJson = New-PortableRollbackMetadata `
            -Root $root `
            -PreviousPointer $metadata.active_pointer `
            -ActivePointer $metadata.previous_pointer `
            -PackageSha256 $metadata.package_sha256 `
            -ManifestSha256 $metadata.manifest_sha256
        Publish-PortableReleaseState `
            -Root $root `
            -PendingPointer $pendingPointer `
            -RollbackMetadata $rollbackJson
    }
    finally {
        [IO.File]::Delete($pendingPointer)
    }
    [PSCustomObject]@{
        ActiveDirectory = $target.Directory
        ActiveVersion = $target.Version
        DataRolledBack = $false
    }
}
finally {
    $lock.Dispose()
}
