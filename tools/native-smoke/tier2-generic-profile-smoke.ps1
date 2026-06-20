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

$previousProfile = $env:KNMON_TIER2_PROFILE

try
{
    $env:KNMON_TIER2_PROFILE = "api-set-safe missing-metadata-safe"
    $result = & $HelperPath capture-sample | ConvertFrom-Json

    Assert-True $result.success "Tier 2 generic capture failed: $($result.operation): $($result.message)"

    $apiSetEvent = @($result.capturedEvents | Where-Object { $_.api -eq "WindowsGetStringLen" } | Select-Object -First 1)
    Assert-True ($apiSetEvent.Count -eq 1) "Tier 2 API-set smoke did not capture WindowsGetStringLen."
    Assert-True ($apiSetEvent[0].module -eq "api-ms-win-core-winrt-string-l1-1-0.dll") "WindowsGetStringLen module mismatch: $($apiSetEvent[0].module)"
    Assert-True ($apiSetEvent[0].resolvedHostModule -eq "combase.dll") "WindowsGetStringLen resolved host mismatch: $($apiSetEvent[0].resolvedHostModule)"
    Assert-True ($apiSetEvent[0].monitorTier -eq "tier2") "WindowsGetStringLen tier mismatch: $($apiSetEvent[0].monitorTier)"
    Assert-True ($apiSetEvent[0].tier2Profile -eq "api-set-safe") "WindowsGetStringLen profile mismatch: $($apiSetEvent[0].tier2Profile)"
    Assert-True ($apiSetEvent[0].hookPolicy -eq "tier2_api_set_iat") "WindowsGetStringLen hook policy mismatch: $($apiSetEvent[0].hookPolicy)"
    Assert-True ($apiSetEvent[0].coverageStatus -eq "api_set_generic") "WindowsGetStringLen coverage mismatch: $($apiSetEvent[0].coverageStatus)"
    Assert-True ($apiSetEvent[0].inventoryKey -eq "api-ms-win-core-winrt-string-l1-1-0.dll!WindowsGetStringLen") "WindowsGetStringLen inventory key mismatch: $($apiSetEvent[0].inventoryKey)"
    Assert-True ($apiSetEvent[0].returnValue -match "5") "WindowsGetStringLen return value mismatch: $($apiSetEvent[0].returnValue)"

    $apiSetArgument = @($apiSetEvent[0].arguments | Where-Object { $_.name -eq "string" } | Select-Object -First 1)
    Assert-True ($apiSetArgument.Count -eq 1) "WindowsGetStringLen generic argument missing."
    Assert-True ($apiSetArgument[0].type -eq "HSTRING") "WindowsGetStringLen argument type mismatch: $($apiSetArgument[0].type)"
    Assert-True ($apiSetArgument[0].decodedValue -match "pointer=0x") "WindowsGetStringLen pointer evidence missing: $($apiSetArgument[0].decodedValue)"

    $returnOnlyEvent = @($result.capturedEvents | Where-Object { $_.api -eq "RevertToSelf" } | Select-Object -First 1)
    Assert-True ($returnOnlyEvent.Count -eq 1) "Tier 2 missing-metadata smoke did not capture RevertToSelf."
    Assert-True ($returnOnlyEvent[0].module -eq "advapi32.dll") "RevertToSelf module mismatch: $($returnOnlyEvent[0].module)"
    Assert-True ($returnOnlyEvent[0].monitorTier -eq "tier2") "RevertToSelf tier mismatch: $($returnOnlyEvent[0].monitorTier)"
    Assert-True ($returnOnlyEvent[0].tier2Profile -eq "missing-metadata-safe") "RevertToSelf profile mismatch: $($returnOnlyEvent[0].tier2Profile)"
    Assert-True ($returnOnlyEvent[0].hookPolicy -eq "tier2_return_only_iat") "RevertToSelf hook policy mismatch: $($returnOnlyEvent[0].hookPolicy)"
    Assert-True ($returnOnlyEvent[0].coverageStatus -eq "generic_return_only") "RevertToSelf coverage mismatch: $($returnOnlyEvent[0].coverageStatus)"
    Assert-True ($returnOnlyEvent[0].arguments.Count -eq 0) "RevertToSelf return-only event must not carry arguments."
    Assert-True ($returnOnlyEvent[0].returnValue -eq "TRUE") "RevertToSelf return value mismatch: $($returnOnlyEvent[0].returnValue)"

    $getProcEvent = @($result.capturedEvents | Where-Object { $_.api -eq "GetProcAddress" } | Select-Object -First 1)
    $ldrProcEvent = @($result.capturedEvents | Where-Object { $_.api -eq "LdrGetProcedureAddress" } | Select-Object -First 1)
    Assert-True ($getProcEvent.Count -eq 1) "Tier 2 smoke lost GetProcAddress resolver visibility."
    Assert-True ($ldrProcEvent.Count -eq 1) "Tier 2 smoke lost LdrGetProcedureAddress resolver visibility."

    Write-Host "Tier 2 generic profile smoke passed: events=$($result.capturedEvents.Count)"
}
finally
{
    if ($null -eq $previousProfile)
    {
        Remove-Item Env:\KNMON_TIER2_PROFILE -ErrorAction SilentlyContinue
    }
    else
    {
        $env:KNMON_TIER2_PROFILE = $previousProfile
    }
}
