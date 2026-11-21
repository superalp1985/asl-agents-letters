[CmdletBinding(DefaultParameterSetName = 'Listen')]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{32}$')][string]$RunId,
    [Parameter(Mandatory, ParameterSetName = 'Listen')][string]$Program,
    [Parameter(Mandatory, ParameterSetName = 'Listen')][ValidatePattern('^S-1-15-2-(\d+-){6}\d+$')][string]$Sid,
    [Parameter(Mandatory, ParameterSetName = 'Listen')][ValidateRange(1,65535)][int]$Port,
    [Parameter(Mandatory, ParameterSetName = 'Cleanup')][switch]$Cleanup
)

$ErrorActionPreference = 'Stop'
$name = "ASL-GroupLoopback-$RunId"
if ($Cleanup) {
    try {
        $rule = Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop
    } catch {
        if ($_.FullyQualifiedErrorId -like 'CmdletizationQuery_NotFound_InstanceID,*') { return }
        throw
    }
    $rule | Remove-NetFirewallRule -ErrorAction Stop
    return
}

$file = Get-Item -LiteralPath $Program
if ($file.Name -ne 'asl-net.exe' -or $file.PSIsContainer) { throw 'Expected the fixture Net executable.' }
$settings = @{
    Name = $name
    DisplayName = $name
    PolicyStore = 'PersistentStore'
    Direction = 'Inbound'
    Action = 'Allow'
    Program = $file.FullName
    Package = $Sid
    Protocol = 'TCP'
    LocalPort = $Port
    LocalAddress = '127.0.0.1'
    RemoteAddress = '127.0.0.1'
    EdgeTraversalPolicy = 'Block'
}
$owned = New-NetFirewallRule @settings -ErrorAction Stop
try {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        try {
            $effective = Get-NetFirewallRule -PolicyStore ActiveStore -Name $name -ErrorAction Stop
        } catch {
            if ($_.FullyQualifiedErrorId -notlike 'CmdletizationQuery_NotFound_InstanceID,*') { throw }
            $effective = $null
        }
        # MSFT_NetFirewallRule reports enforcement per profile (1 = enforced).
        if ($effective -and $effective.CimInstanceProperties['EnforcementStatus'].Value -contains 1) {
            $app = $effective | Get-NetFirewallApplicationFilter -ErrorAction Stop
            $transport = $effective | Get-NetFirewallPortFilter -ErrorAction Stop
            if ($app.Program -eq $file.FullName -and $app.Package -eq $Sid -and $transport.LocalPort -eq "$Port") { break }
        }
        if ($timer.Elapsed.TotalSeconds -ge 5) {
            throw "Windows did not enforce $name for $Sid on TCP $Port. Status: $($effective.EnforcementStatus -join ', '). Check the active profile's inbound and local-rule policies."
        }
        Start-Sleep -Milliseconds 100
    } while ($true)
    [Console]::Out.WriteLine('READY')
    [Console]::Out.Flush()
    # EOF also releases the rule if the Rust test process exits unexpectedly.
    $null = [Console]::In.ReadLine()
} finally {
    $owned | Remove-NetFirewallRule -ErrorAction Stop
}
