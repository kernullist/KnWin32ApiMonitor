param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

function Assert-True
{
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition)
    {
        throw $Message
    }
}

Assert-True (Test-Path -LiteralPath $HelperPath) "Helper not found: $HelperPath"

$result = & $HelperPath list-targets | ConvertFrom-Json
Assert-True $result.success "list-targets failed: $($result.message)"

$svchostRows = @($result.targets | Where-Object { $_.imageName -eq "svchost.exe" })
Assert-True ($svchostRows.Count -gt 0) "list-targets did not return svchost.exe rows."

$systemRoot = [System.Environment]::GetFolderPath("Windows")
$expected = Join-Path $systemRoot "System32\svchost.exe"
$matched = @($svchostRows | Where-Object { $_.imagePath -ieq $expected })
Assert-True ($matched.Count -gt 0) "svchost.exe path fallback did not resolve to $expected."

$coreNames = @("services.exe", "wininit.exe", "lsass.exe")
foreach ($name in $coreNames)
{
    $rows = @($result.targets | Where-Object { $_.imageName -eq $name })
    if ($rows.Count -eq 0)
    {
        continue
    }

    $withPath = @($rows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.imagePath) })
    Assert-True ($withPath.Count -gt 0) "$name path fallback did not populate an image path."
}

Write-Host "list-targets path fallback smoke passed: svchost=$($svchostRows.Count)"
