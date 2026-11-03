# Fixture helper: reports what it saw into $env:CODEORCA_OUTPUT_FILE; writes a marker only through ShouldProcess.
[CmdletBinding(SupportsShouldProcess)]
param(
    [int]$ExitCode = 0,
    [string]$Word = ''
)

$secret = $env:HELPER_SECRET
if ($secret) {
    Write-Output "stdout sees $secret"
    [Console]::Error.WriteLine("stderr sees $secret")
}
$marker = Join-Path $env:CODEORCA_STEP_DIR 'marker.txt'
if ($PSCmdlet.ShouldProcess($marker, 'Write marker')) {
    Set-Content -LiteralPath $marker -Value 'written'
}
$out = [ordered]@{
    word = $Word
    whatif = [bool]$WhatIfPreference
    dry_run = $env:CODEORCA_DRY_RUN
    secret_echo = $secret
}
$out | ConvertTo-Json -Compress | Set-Content -LiteralPath $env:CODEORCA_OUTPUT_FILE -WhatIf:$false
if ($ExitCode -ne 0) {
    [Console]::Error.WriteLine("failing with $ExitCode")
}
exit $ExitCode
