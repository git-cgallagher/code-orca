function Get-Thing
{
  param($a)
    $x=1;
    if ($a) { Write-Host "thing" } else { gci }
}
