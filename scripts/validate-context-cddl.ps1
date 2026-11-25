$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$cddl = (Get-Command cddl -ErrorAction Stop).Source
$cargo = Get-Command cargo -ErrorAction Stop
Push-Location $root
try {
    & $cargo.Source +1.100.0 run -p asl-types --example export_semantic_context_vectors --locked --offline -- --check --validate-cddl $cddl
    if ($LASTEXITCODE -ne 0) {
        throw 'Semantic context vectors or independent CDDL validation failed.'
    }
}
finally {
    Pop-Location
}
