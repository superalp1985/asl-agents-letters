[CmdletBinding()]
param(
    [string]$DevRoot = $env:ASL_DEV_ROOT,
    [ValidatePattern('^S-1-15-2-(\d+-){6}\d+$')][string]$ReleaseOrphanSid
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell. Windows only permits LoopbackExempt changes from an administrator session."
}

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
if (-not $DevRoot) {
    for ($current = Get-Item -LiteralPath $repo; $null -ne $current; $current = $current.Parent) {
        if (Test-Path -LiteralPath (Join-Path $current.FullName "dev-cache") -PathType Container) {
            $DevRoot = $current.FullName
            break
        }
    }
}
if (-not $DevRoot) {
    throw "Set ASL_DEV_ROOT or pass -DevRoot with the ASL development root."
}

. (Join-Path $PSScriptRoot "dev-env.ps1") -Root $DevRoot
if ($ReleaseOrphanSid) {
    $mapping = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\$ReleaseOrphanSid"
    $name = Get-ItemPropertyValue -LiteralPath $mapping -Name Moniker
    if ($name -notmatch '^asl\.[0-9]+$') { throw "This profile does not belong to an ASL fixture." }
    $utility = Join-Path ([Environment]::SystemDirectory) "CheckNetIsolation.exe"
    $argsPattern = '\s+LoopbackExempt\s+-is\s+"?-p=' + [regex]::Escape($ReleaseOrphanSid) + '"?\s*$'
    $matchesFound = @(Get-CimInstance Win32_Process -Filter "Name='CheckNetIsolation.exe'" | Where-Object {
        $_.ExecutablePath -eq $utility -and $_.CommandLine -match $argsPattern
    })
    if ($matchesFound.Count -gt 1) { throw "Multiple debuggers matched this profile." }
    $process = $null
    $selection = "Profile $name ($ReleaseOrphanSid)"
    if ($matchesFound.Count -eq 1) {
        $helper = $matchesFound[0]
        $owner = Invoke-CimMethod -InputObject $helper -MethodName GetOwnerSid
        if ($owner.ReturnValue -ne 0 -or $owner.Sid -ne $identity.User.Value -or $helper.SessionId -ne (Get-Process -Id $PID).SessionId) {
            throw "Debugger owner or session differs."
        }
        $parent = Get-Process -Id $helper.ParentProcessId -ErrorAction SilentlyContinue
        if ($parent -and $parent.StartTime -le $helper.CreationDate) { throw "The debugger's parent is still running." }
        $process = Get-Process -Id $helper.ProcessId -ErrorAction Stop
        $null = $process.Handle
        if ([Math]::Abs(($process.StartTime - $helper.CreationDate).TotalMilliseconds) -ge 1 -or $process.Path -ne $utility) {
            throw "Debugger process changed during inspection."
        }
        $selection += "`nPID $($process.Id), started $($process.StartTime), command $($helper.CommandLine)"
    }
    $list = & $utility LoopbackExempt -s
    if ($LASTEXITCODE -ne 0) { throw "Could not read the loopback exemption list." }
    $listed = $list -match ('(?<![\d-])' + [regex]::Escape($ReleaseOrphanSid) + '(?![\d-])')
    if ($process -or $listed) {
        Write-Host $selection
        if ((Read-Host "Type Y to retire this previous ASL test session and its exemption") -ne 'Y') {
            throw "Cancelled."
        }
        if ($listed) {
            & $utility LoopbackExempt -d "-p=$ReleaseOrphanSid"
            if ($LASTEXITCODE -ne 0) { throw "Could not remove this profile's exemption ($LASTEXITCODE)." }
        }
        if ($process -and -not $process.HasExited) {
            $process.Kill()
            if (-not $process.WaitForExit(5000)) { throw "The selected debugger did not exit." }
        }
    }
}
Push-Location $repo
try {
    & cargo +1.100.0 build -p asl-app --bin asl-net --bin asl-worker --bin asl-extractor --locked --offline
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
    & cargo +1.100.0 test -p asl-app --lib --locked --offline `
        supervisor::groups::process_tests::group_messages_cross_sandboxed_net_processes `
        -- --ignored --exact --nocapture --test-threads=1
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
