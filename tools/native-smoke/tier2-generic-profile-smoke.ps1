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

function Assert-ReturnOnlyEvent
{
    param(
        [object[]]$Events,
        [string]$Api,
        [string]$Module,
        [string]$InventoryKey,
        [string]$Family
    )

    $event = @($Events | Where-Object { $_.api -eq $Api -and $_.module -eq $Module } | Select-Object -First 1)
    Assert-True ($event.Count -eq 1) "Tier 2 initial return-only batch did not capture $Module!$Api."
    Assert-True ($event[0].monitorTier -eq "tier2") "$Api tier mismatch: $($event[0].monitorTier)"
    Assert-True ($event[0].tier2Profile -eq "tier2-initial-return-only") "$Api profile mismatch: $($event[0].tier2Profile)"
    Assert-True ($event[0].hookPolicy -eq "tier2_return_only_iat") "$Api hook policy mismatch: $($event[0].hookPolicy)"
    Assert-True ($event[0].coverageStatus -eq "generic_return_only") "$Api coverage mismatch: $($event[0].coverageStatus)"
    Assert-True ($event[0].inventoryKey -eq $InventoryKey) "$Api inventory key mismatch: $($event[0].inventoryKey)"
    Assert-True ($event[0].apiFamily -eq $Family) "$Api family mismatch: $($event[0].apiFamily)"
    Assert-True ($event[0].arguments.Count -eq 0) "$Api return-only event must not carry arguments."
}

$previousProfile = $env:KNMON_TIER2_PROFILE

try
{
    $env:KNMON_TIER2_PROFILE = "api-set-safe missing-metadata-safe tier2-initial-return-only"
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

    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "CommDlgExtendedError" -Module "comdlg32.dll" -InventoryKey "comdlg32.dll!CommDlgExtendedError" -Family "ui"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "DwmFlush" -Module "dwmapi.dll" -InventoryKey "dwmapi.dll!DwmFlush" -Family "graphics"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "acmGetVersion" -Module "msacm32.dll" -InventoryKey "msacm32.dll!acmGetVersion" -Family "media"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "auxGetNumDevs" -Module "winmm.dll" -InventoryKey "winmm.dll!auxGetNumDevs" -Family "media"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "joyGetNumDevs" -Module "winmm.dll" -InventoryKey "winmm.dll!joyGetNumDevs" -Family "media"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "midiInGetNumDevs" -Module "winmm.dll" -InventoryKey "winmm.dll!midiInGetNumDevs" -Family "media"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "midiOutGetNumDevs" -Module "winmm.dll" -InventoryKey "winmm.dll!midiOutGetNumDevs" -Family "media"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "mixerGetNumDevs" -Module "winmm.dll" -InventoryKey "winmm.dll!mixerGetNumDevs" -Family "media"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "mmGetCurrentTask" -Module "winmm.dll" -InventoryKey "winmm.dll!mmGetCurrentTask" -Family "media"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "mmTaskYield" -Module "winmm.dll" -InventoryKey "winmm.dll!mmTaskYield" -Family "media"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "timeGetTime" -Module "winmm.dll" -InventoryKey "winmm.dll!timeGetTime" -Family "media"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "waveInGetNumDevs" -Module "winmm.dll" -InventoryKey "winmm.dll!waveInGetNumDevs" -Family "media"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "waveOutGetNumDevs" -Module "winmm.dll" -InventoryKey "winmm.dll!waveOutGetNumDevs" -Family "media"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "BufferedPaintInit" -Module "uxtheme.dll" -InventoryKey "uxtheme.dll!BufferedPaintInit" -Family "ui"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "BufferedPaintUnInit" -Module "uxtheme.dll" -InventoryKey "uxtheme.dll!BufferedPaintUnInit" -Family "ui"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "GetThemeAppProperties" -Module "uxtheme.dll" -InventoryKey "uxtheme.dll!GetThemeAppProperties" -Family "ui"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "IsAppThemed" -Module "uxtheme.dll" -InventoryKey "uxtheme.dll!IsAppThemed" -Family "ui"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "IsCompositionActive" -Module "uxtheme.dll" -InventoryKey "uxtheme.dll!IsCompositionActive" -Family "ui"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "IsThemeActive" -Module "uxtheme.dll" -InventoryKey "uxtheme.dll!IsThemeActive" -Family "ui"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "GetMUILanguage" -Module "comctl32.dll" -InventoryKey "comctl32.dll!GetMUILanguage" -Family "ui"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "ImageList_EndDrag" -Module "comctl32.dll" -InventoryKey "comctl32.dll!ImageList_EndDrag" -Family "ui"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "InitCommonControls" -Module "comctl32.dll" -InventoryKey "comctl32.dll!InitCommonControls" -Family "ui"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "D3DPERF_EndEvent" -Module "d3d9.dll" -InventoryKey "d3d9.dll!D3DPERF_EndEvent" -Family "graphics"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "D3DPERF_GetStatus" -Module "d3d9.dll" -InventoryKey "d3d9.dll!D3DPERF_GetStatus" -Family "graphics"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "D3DPERF_QueryRepeatFrame" -Module "d3d9.dll" -InventoryKey "d3d9.dll!D3DPERF_QueryRepeatFrame" -Family "graphics"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "GetSymLoadError" -Module "dbghelp.dll" -InventoryKey "dbghelp.dll!GetSymLoadError" -Family "system"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "ImagehlpApiVersion" -Module "dbghelp.dll" -InventoryKey "dbghelp.dll!ImagehlpApiVersion" -Family "system"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "RangeMapCreate" -Module "dbghelp.dll" -InventoryKey "dbghelp.dll!RangeMapCreate" -Family "system"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "SymGetOptions" -Module "dbghelp.dll" -InventoryKey "dbghelp.dll!SymGetOptions" -Family "system"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "GdipCreateHalftonePalette" -Module "gdiplus.dll" -InventoryKey "gdiplus.dll!GdipCreateHalftonePalette" -Family "graphics"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "OaBuildVersion" -Module "oleaut32.dll" -InventoryKey "oleaut32.dll!OaBuildVersion" -Family "com"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "OaEnablePerUserTLibRegistration" -Module "oleaut32.dll" -InventoryKey "oleaut32.dll!OaEnablePerUserTLibRegistration" -Family "com"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "DXGIDeclareAdapterRemovalSupport" -Module "dxgi.dll" -InventoryKey "dxgi.dll!DXGIDeclareAdapterRemovalSupport" -Family "graphics"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "DXGIDisableVBlankVirtualization" -Module "dxgi.dll" -InventoryKey "dxgi.dll!DXGIDisableVBlankVirtualization" -Family "graphics"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "MagInitialize" -Module "magnification.dll" -InventoryKey "magnification.dll!MagInitialize" -Family "ui"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "MagUninitialize" -Module "magnification.dll" -InventoryKey "magnification.dll!MagUninitialize" -Family "ui"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "MsiCloseAllHandles" -Module "msi.dll" -InventoryKey "msi.dll!MsiCloseAllHandles" -Family "system"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "MsiGetLastErrorRecord" -Module "msi.dll" -InventoryKey "msi.dll!MsiGetLastErrorRecord" -Family "system"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "ODBCGetTryWaitValue" -Module "odbc32.dll" -InventoryKey "odbc32.dll!ODBCGetTryWaitValue" -Family "system"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "SnmpSvcGetUptime" -Module "snmpapi.dll" -InventoryKey "snmpapi.dll!SnmpSvcGetUptime" -Family "network-management"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "WinHttpCheckPlatform" -Module "winhttp.dll" -InventoryKey "winhttp.dll!WinHttpCheckPlatform" -Family "networking"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "LdapGetLastError" -Module "wldap32.dll" -InventoryKey "wldap32.dll!LdapGetLastError" -Family "networking"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "NeedRebootInit" -Module "advpack.dll" -InventoryKey "advpack.dll!NeedRebootInit" -Family "system"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "DCIOpenProvider" -Module "dciman32.dll" -InventoryKey "dciman32.dll!DCIOpenProvider" -Family "system"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "Dhcpv6CApiCleanup" -Module "dhcpcsvc6.dll" -InventoryKey "dhcpcsvc6.dll!Dhcpv6CApiCleanup" -Family "network-management"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "WSARevertImpersonation" -Module "fwpuclnt.dll" -InventoryKey "fwpuclnt.dll!WSARevertImpersonation" -Family "networking"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "RtlGetReturnAddressHijackTarget" -Module "ntdll.dll" -InventoryKey "ntdll.dll!RtlGetReturnAddressHijackTarget" -Family "system"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "PSRefreshPropertySchema" -Module "propsys.dll" -InventoryKey "propsys.dll!PSRefreshPropertySchema" -Family "ui"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "IEGetUserPrivateNamespaceName" -Module "urlmon.dll" -InventoryKey "urlmon.dll!IEGetUserPrivateNamespaceName" -Family "system"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "CM_Get_Version" -Module "cfgmgr32.dll" -InventoryKey "cfgmgr32.dll!CM_Get_Version" -Family "devices"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "ImmCreateContext" -Module "imm32.dll" -InventoryKey "imm32.dll!ImmCreateContext" -Family "ui"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "UiaClientsAreListening" -Module "uiautomationcore.dll" -InventoryKey "uiautomationcore.dll!UiaClientsAreListening" -Family "ui"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "WscQueryAntiMalwareUri" -Module "wscapi.dll" -InventoryKey "wscapi.dll!WscQueryAntiMalwareUri" -Family "system"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "RatingEnabledQuery" -Module "msrating.dll" -InventoryKey "msrating.dll!RatingEnabledQuery" -Family "web"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "CanSendToFaxRecipient" -Module "fxsutility.dll" -InventoryKey "fxsutility.dll!CanSendToFaxRecipient" -Family "devices"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "DhcpDsCleanup" -Module "dhcpsapi.dll" -InventoryKey "dhcpsapi.dll!DhcpDsCleanup" -Family "network-management"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "DhcpDsInit" -Module "dhcpsapi.dll" -InventoryKey "dhcpsapi.dll!DhcpDsInit" -Family "network-management"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "ImmDisableLegacyIME" -Module "imm32.dll" -InventoryKey "imm32.dll!ImmDisableLegacyIME" -Family "ui"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "RatingInit" -Module "msrating.dll" -InventoryKey "msrating.dll!RatingInit" -Family "web"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "UiaDisconnectAllProviders" -Module "uiautomationcore.dll" -InventoryKey "uiautomationcore.dll!UiaDisconnectAllProviders" -Family "ui"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "WscRegisterForUserNotifications" -Module "wscapi.dll" -InventoryKey "wscapi.dll!WscRegisterForUserNotifications" -Family "system"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "SnmpCleanup" -Module "wsnmp32.dll" -InventoryKey "wsnmp32.dll!SnmpCleanup" -Family "network-management"
    Assert-ReturnOnlyEvent -Events $result.capturedEvents -Api "SnmpCleanupEx" -Module "wsnmp32.dll" -InventoryKey "wsnmp32.dll!SnmpCleanupEx" -Family "network-management"

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
