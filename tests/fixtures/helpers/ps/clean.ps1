[CmdletBinding()]
param(
    [string]$Name = 'world'
)

$greeting = "Hello, $Name"
Write-Output $greeting
