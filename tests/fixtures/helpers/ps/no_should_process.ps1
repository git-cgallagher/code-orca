# Fixture helper without SupportsShouldProcess: refused under --dry-run.
# A comment that mentions [CmdletBinding(SupportsShouldProcess)] does not count.
[CmdletBinding()]
param()

Set-Content -LiteralPath (Join-Path $env:CODEORCA_STEP_DIR 'marker.txt') -Value 'written'
