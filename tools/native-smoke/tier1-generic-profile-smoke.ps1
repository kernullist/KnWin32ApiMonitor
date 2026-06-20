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

$previousProfile = $env:KNMON_TIER1_PROFILE

try
{
    $env:KNMON_TIER1_PROFILE = "system-safe devices-safe ui-safe network-management-safe graphics-safe"
    $result = & $HelperPath capture-sample | ConvertFrom-Json

    Assert-True $result.success "Tier 1 generic capture failed: $($result.operation): $($result.message)"

    $expected = @(
        @{ Api = "GetSystemTime"; Module = "kernel32.dll"; Profile = "system-safe"; Family = "system"; Arg = "lpSystemTime"; Type = "LPSYSTEMTIME"; PointerOnly = $true },
        @{ Api = "SetupDiClassNameFromGuidW"; Module = "setupapi.dll"; Profile = "devices-safe"; Family = "devices"; Arg = "ClassGuid"; Type = "GUID*"; PointerOnly = $true },
        @{ Api = "GetCursorPos"; Module = "user32.dll"; Profile = "ui-safe"; Family = "ui"; Arg = "lpPoint"; Type = "POINT*"; PointerOnly = $true },
        @{ Api = "GetIpStatistics"; Module = "iphlpapi.dll"; Profile = "network-management-safe"; Family = "network-management"; Arg = "Statistics"; Type = "MIB_IPSTATS*"; PointerOnly = $true },
        @{ Api = "GetStockObject"; Module = "gdi32.dll"; Profile = "graphics-safe"; Family = "graphics"; Arg = "i"; Type = "GET_STOCK_OBJECT_FLAGS"; PointerOnly = $false }
    )

    foreach ($item in $expected)
    {
        $event = @($result.capturedEvents | Where-Object { $_.api -eq $item.Api } | Select-Object -First 1)
        Assert-True ($event.Count -eq 1) "Tier 1 generic smoke did not capture $($item.Api)."
        Assert-True ($event[0].module -eq $item.Module) "$($item.Api) module mismatch: $($event[0].module)"
        Assert-True ($event[0].apiFamily -eq $item.Family) "$($item.Api) family mismatch: $($event[0].apiFamily)"
        Assert-True ($event[0].hookPolicy -eq "tier1_generic_iat") "$($item.Api) hook policy mismatch: $($event[0].hookPolicy)"
        Assert-True ($event[0].coverageStatus -eq "generic_decoded") "$($item.Api) coverage mismatch: $($event[0].coverageStatus)"
        Assert-True ($event[0].tier1Profile -eq $item.Profile) "$($item.Api) profile mismatch: $($event[0].tier1Profile)"
        Assert-True ($event[0].inventoryKey -eq "$($item.Module)!$($item.Api)") "$($item.Api) inventory key mismatch: $($event[0].inventoryKey)"

        $argument = @($event[0].arguments | Where-Object { $_.name -eq $item.Arg } | Select-Object -First 1)
        Assert-True ($argument.Count -eq 1) "$($item.Api) generic argument missing."
        Assert-True ($argument[0].type -eq $item.Type) "$($item.Api) argument type mismatch: $($argument[0].type)"
        Assert-True ($argument[0].decodeStatus -eq "definition_missing") "$($item.Api) generic decode status mismatch: $($argument[0].decodeStatus)"
        if ($item.PointerOnly)
        {
            Assert-True ($argument[0].decodedValue -match "pointer=0x") "$($item.Api) generic pointer evidence missing: $($argument[0].decodedValue)"
        }

        Assert-True ($event[0].bufferPreview -eq "") "$($item.Api) generic event must not carry a buffer preview."
    }

    $payloadText = ($result.capturedEvents | ConvertTo-Json -Depth 10)
    Assert-True ($payloadText -notmatch "wYear|wMonth|wDay|wHour|wMinute|wSecond|pt.x|pt.y|dwForwarding|dwDefaultTTL") "Tier 1 generic smoke leaked structured payload fields."

    Write-Host "Tier 1 generic profile smoke passed: events=$($result.capturedEvents.Count) families=$($expected.Count)"
}
finally
{
    if ($null -eq $previousProfile)
    {
        Remove-Item Env:\KNMON_TIER1_PROFILE -ErrorAction SilentlyContinue
    }
    else
    {
        $env:KNMON_TIER1_PROFILE = $previousProfile
    }
}
