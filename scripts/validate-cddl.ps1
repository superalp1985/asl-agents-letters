#Requires -Version 7.2

$ErrorActionPreference = "Stop"

$tool = Get-Command cddl -ErrorAction Stop
$version = (& $tool.Source --version).Trim()
if ($version -ne "cddl 0.10.7") {
    throw "Expected cddl 0.10.7, found $version."
}

$root = Split-Path -Parent $PSScriptRoot
$schema = Join-Path $root "schemas\asl-v1.cddl"
$contactInviteSchema = Join-Path $root "schemas\contact-invite-v1.cddl"
$vectors = Join-Path $root "schemas\vectors"
$index = Get-Content -LiteralPath (Join-Path $vectors "index.json") -Raw | ConvertFrom-Json
if ($index.version -ne 1 -or $index.vectors.Count -ne 35) {
    throw "Expected schema corpus version 1 with 35 vectors."
}
if (@($index.vectors | Where-Object { $_.accepted -eq $true }).Count -ne 25 -or
    @($index.vectors | Where-Object { $_.accepted -eq $false }).Count -ne 10) {
    throw "Expected 25 accepted and 10 rejected vectors."
}

& $tool.Source compile-cddl --cddl $schema
if ($LASTEXITCODE -ne 0) {
    throw "CDDL grammar validation failed."
}
& $tool.Source compile-cddl --cddl $contactInviteSchema
if ($LASTEXITCODE -ne 0) {
    throw "Contact invite CDDL grammar validation failed."
}

$scratchParent = Join-Path $root "work"
New-Item -ItemType Directory -Force -Path $scratchParent | Out-Null
$scratch = Join-Path $scratchParent ("cddl-validation-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $scratch | Out-Null
$wrapper = Join-Path $scratch "vector.cddl"
$schemaText = Get-Content -LiteralPath $schema -Raw
$seen = [System.Collections.Generic.HashSet[string]]::new()

try {
    foreach ($vector in $index.vectors) {
        if ($vector.name -notmatch '^[a-z][a-z0-9-]*$' -or
            $vector.root -notmatch '^[a-z][a-z0-9-]*$' -or
            $vector.codec -notin @("frame", "group-policy", "record", "value") -or
            $vector.accepted -isnot [bool] -or -not $seen.Add($vector.name)) {
            throw "Invalid or duplicate schema corpus entry."
        }
        # CDDL validates its first rule. Select this vector's exact frozen root
        # without rewriting or widening the application schema.
        Set-Content -LiteralPath $wrapper -Encoding utf8NoBOM -Value (
            "asl-vector-root = " + $vector.root + "`n" + $schemaText
        )
        $hexPath = Join-Path $vectors ($vector.name + ".hex")
        $hex = (Get-Content -LiteralPath $hexPath -Raw) -replace "\s", ""
        $bytes = [Convert]::FromHexString($hex)
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new($tool.Source)
        foreach ($argument in @("--ci", "validate", "--cddl", $wrapper, "--stdin")) {
            $startInfo.ArgumentList.Add($argument)
        }
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardInput = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true

        $process = [System.Diagnostics.Process]::Start($startInfo)
        try {
            $stdoutTask = $process.StandardOutput.ReadToEndAsync()
            $stderrTask = $process.StandardError.ReadToEndAsync()
            $process.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
            $process.StandardInput.Close()
            if (-not $process.WaitForExit(15000)) {
                $process.Kill()
                $process.WaitForExit()
                throw "CDDL validation timed out for $($vector.name)."
            }
            $stdout = $stdoutTask.GetAwaiter().GetResult()
            $stderr = $stderrTask.GetAwaiter().GetResult()
            $accepted = $process.ExitCode -eq 0
            if ($accepted -ne $vector.accepted) {
                throw "Unexpected CDDL result for $($vector.name): $stdout $stderr"
            }
            if ($accepted -and ($stdout + $stderr) -notmatch 'Validation from stdin is successful') {
                throw "CDDL did not confirm conformance for $($vector.name): $stdout $stderr"
            }
            if (-not $accepted -and
                ($stdout + $stderr) -notmatch 'Validation from stdin failed: error validating') {
                throw "CDDL did not report a schema rejection for $($vector.name): $stdout $stderr"
            }
        }
        finally {
            $process.Dispose()
        }
    }
    Write-Output "CDDL corpus: 25 accepted, 10 rejected as expected."
}
finally {
    if (Test-Path -LiteralPath $wrapper) {
        Remove-Item -LiteralPath $wrapper
    }
    Remove-Item -LiteralPath $scratch
}
