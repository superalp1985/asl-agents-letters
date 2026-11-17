$ErrorActionPreference = "Stop"

$tool = Get-Command cddl -ErrorAction Stop
$version = (& $tool.Source --version).Trim()
if ($version -ne "cddl 0.10.7") {
    throw "Expected cddl 0.10.7, found $version."
}

$root = Split-Path -Parent $PSScriptRoot
$schema = Join-Path $root "schemas\asl-v1.cddl"
$vector = Join-Path $root "schemas\vectors\ack-v1.hex"

& $tool.Source compile-cddl --cddl $schema
if ($LASTEXITCODE -ne 0) {
    throw "CDDL grammar validation failed."
}

$hex = (Get-Content -LiteralPath $vector -Raw) -replace "\s", ""
$bytes = [Convert]::FromHexString($hex)
$startInfo = [System.Diagnostics.ProcessStartInfo]::new(
    $tool.Source,
    "validate --cddl `"$schema`" --stdin"
)
$startInfo.UseShellExecute = $false
$startInfo.RedirectStandardInput = $true
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true

$process = [System.Diagnostics.Process]::Start($startInfo)
$process.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
$process.StandardInput.Close()
$stdout = $process.StandardOutput.ReadToEnd()
$stderr = $process.StandardError.ReadToEnd()
$process.WaitForExit()

if ($stdout) {
    Write-Output $stdout.TrimEnd()
}
if ($stderr) {
    Write-Output $stderr.TrimEnd()
}
if ($process.ExitCode -ne 0) {
    throw "The fixed ACK vector does not conform to the CDDL."
}
