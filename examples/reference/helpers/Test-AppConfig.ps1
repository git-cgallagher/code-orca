<#
.SYNOPSIS
    Reference PowerShell helper (demo-rollout's config_audit): check the rendered host spec.

.DESCRIPTION
    Reads the host spec named by -SpecPath (relative to the project root, the step's working directory) and
    checks it exists and declares the app_api_token as a secret placeholder rather than a value. Writes
    {"ok": true|false, ...} as JSON to $env:CODEORCA_OUTPUT_FILE (the helper contract; stdout is a log).

    code-orca appends -WhatIf under `codeorca run --dry-run` and refuses a script that does not declare
    SupportsShouldProcess. The only change this script makes is an audit marker in the step directory, guarded by
    ShouldProcess; the output file is written with .NET directly so -WhatIf cannot suppress the result.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$SpecPath
)

$ErrorActionPreference = 'Stop'

$exists = Test-Path -LiteralPath $SpecPath -PathType Leaf
$declared = $false
if ($exists) {
    $text = Get-Content -LiteralPath $SpecPath -Raw
    $declared = $text -match '<secret: declared>'
}
$ok = $exists -and $declared
Write-Output "spec ${SpecPath}: exists=$exists secret-declared=$declared"

if ($env:CODEORCA_STEP_DIR) {
    $marker = Join-Path -Path $env:CODEORCA_STEP_DIR -ChildPath 'audit.txt'
    if ($PSCmdlet.ShouldProcess($marker, 'Write the audit marker')) {
        Set-Content -LiteralPath $marker -Value "ok=$ok"
    }
}

if ($env:CODEORCA_OUTPUT_FILE) {
    $result = [ordered]@{
        ok = $ok
        spec = $SpecPath
        dry_run = [bool]$WhatIfPreference
    }
    [System.IO.File]::WriteAllText($env:CODEORCA_OUTPUT_FILE, ($result | ConvertTo-Json -Compress))
}

if (-not $ok) {
    exit 1
}
