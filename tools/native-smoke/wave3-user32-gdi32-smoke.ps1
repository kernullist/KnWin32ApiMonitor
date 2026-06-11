param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

function Assert-IntegerValue
{
    param(
        [string]$Value,
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch "^-?[0-9]+$")
    {
        throw "$Name is not a decimal integer: $Value"
    }
}

function Assert-PointerValue
{
    param(
        [string]$Value,
        [string]$Name,
        [bool]$AllowNull = $false
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch "^0x[0-9a-fA-F]+$")
    {
        throw "$Name is not a pointer value: $Value"
    }

    if (-not $AllowNull -and $Value -match "^0x0+$")
    {
        throw "$Name unexpectedly used a null pointer."
    }
}

if (-not (Test-Path -LiteralPath $HelperPath))
{
    throw "Helper not found: $HelperPath"
}

$result = & $HelperPath capture-sample | ConvertFrom-Json

if (-not $result.success)
{
    throw "Wave 3 User32/GDI32 capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Unexpected transport mode: $($result.transportMode)"
}

$droppedEvents = if ($null -ne $result.transportDroppedEvents) { $result.transportDroppedEvents } else { $result.droppedEvents }
if ($droppedEvents -ne 0)
{
    throw "Wave 3 healthy capture dropped transport events: $droppedEvents"
}

$expected = @(
    @{ Api = "GetSystemMetrics"; Module = "user32.dll"; Family = "ui"; Category = "user_system_metric"; Args = @("nIndex") },
    @{ Api = "GetDesktopWindow"; Module = "user32.dll"; Family = "ui"; Category = "window_handle_query"; Args = @() },
    @{ Api = "GetForegroundWindow"; Module = "user32.dll"; Family = "ui"; Category = "window_handle_query"; Args = @() },
    @{ Api = "GetWindowThreadProcessId"; Module = "user32.dll"; Family = "ui"; Category = "window_thread_process_query"; Args = @("hWnd", "lpdwProcessId") },
    @{ Api = "CreateCompatibleDC"; Module = "gdi32.dll"; Family = "gdi"; Category = "gdi_dc_create"; Args = @("hdc") },
    @{ Api = "GetDeviceCaps"; Module = "gdi32.dll"; Family = "gdi"; Category = "gdi_device_cap_query"; Args = @("hdc", "index") },
    @{ Api = "DeleteDC"; Module = "gdi32.dll"; Family = "gdi"; Category = "gdi_dc_delete"; Args = @("hdc") }
)

foreach ($item in $expected)
{
    $event = @($result.capturedEvents | Where-Object { $_.api -eq $item.Api } | Select-Object -First 1)
    if ($event.Count -ne 1)
    {
        throw "Wave 3 smoke did not capture $($item.Api)."
    }

    if ($event[0].module -ne $item.Module)
    {
        throw "$($item.Api) module mismatch: $($event[0].module)"
    }

    if ($event[0].apiFamily -ne $item.Family -or $event[0].apiCategory -ne $item.Category)
    {
        throw "$($item.Api) metadata mismatch: family=$($event[0].apiFamily) category=$($event[0].apiCategory)"
    }

    if ($event[0].hookPolicy -ne "iat" -or $event[0].coverageStatus -ne "smoke_verified")
    {
        throw "$($item.Api) hook metadata mismatch: hook=$($event[0].hookPolicy) coverage=$($event[0].coverageStatus)"
    }

    if (-not [string]::IsNullOrEmpty($event[0].bufferPreview))
    {
        throw "$($item.Api) exposed bufferPreview: $($event[0].bufferPreview)"
    }

    foreach ($argName in $item.Args)
    {
        $argument = @($event[0].arguments | Where-Object { $_.name -eq $argName } | Select-Object -First 1)
        if ($argument.Count -ne 1)
        {
            throw "$($item.Api) argument missing: $argName"
        }

        if ([string]::IsNullOrWhiteSpace($argument[0].decodeAlias))
        {
            throw "$($item.Api) argument decode alias missing: $argName"
        }
    }
}

$systemMetric = @($result.capturedEvents | Where-Object { $_.api -eq "GetSystemMetrics" } | Select-Object -First 1)
Assert-IntegerValue -Value $systemMetric[0].returnValue -Name "GetSystemMetrics returnValue"
$metricIndex = @($systemMetric[0].arguments | Where-Object { $_.name -eq "nIndex" } | Select-Object -First 1)
Assert-IntegerValue -Value $metricIndex[0].decodedValue -Name "GetSystemMetrics nIndex"

$desktopWindow = @($result.capturedEvents | Where-Object { $_.api -eq "GetDesktopWindow" } | Select-Object -First 1)
Assert-PointerValue -Value $desktopWindow[0].returnValue -Name "GetDesktopWindow returnValue"

$foregroundWindow = @($result.capturedEvents | Where-Object { $_.api -eq "GetForegroundWindow" } | Select-Object -First 1)
Assert-PointerValue -Value $foregroundWindow[0].returnValue -Name "GetForegroundWindow returnValue" -AllowNull $true

$threadProcess = @($result.capturedEvents | Where-Object { $_.api -eq "GetWindowThreadProcessId" } | Select-Object -First 1)
Assert-IntegerValue -Value $threadProcess[0].returnValue -Name "GetWindowThreadProcessId returnValue"
$windowArgument = @($threadProcess[0].arguments | Where-Object { $_.name -eq "hWnd" } | Select-Object -First 1)
Assert-PointerValue -Value $windowArgument[0].decodedValue -Name "GetWindowThreadProcessId hWnd"
$processArgument = @($threadProcess[0].arguments | Where-Object { $_.name -eq "lpdwProcessId" } | Select-Object -First 1)
Assert-IntegerValue -Value $processArgument[0].decodedValue -Name "GetWindowThreadProcessId lpdwProcessId"

$createDc = @($result.capturedEvents | Where-Object { $_.api -eq "CreateCompatibleDC" } | Select-Object -First 1)
Assert-PointerValue -Value $createDc[0].returnValue -Name "CreateCompatibleDC returnValue"

$deviceCaps = @($result.capturedEvents | Where-Object { $_.api -eq "GetDeviceCaps" } | Select-Object -First 1)
Assert-IntegerValue -Value $deviceCaps[0].returnValue -Name "GetDeviceCaps returnValue"
$deviceDc = @($deviceCaps[0].arguments | Where-Object { $_.name -eq "hdc" } | Select-Object -First 1)
Assert-PointerValue -Value $deviceDc[0].decodedValue -Name "GetDeviceCaps hdc"
$deviceIndex = @($deviceCaps[0].arguments | Where-Object { $_.name -eq "index" } | Select-Object -First 1)
Assert-IntegerValue -Value $deviceIndex[0].decodedValue -Name "GetDeviceCaps index"

$deleteDc = @($result.capturedEvents | Where-Object { $_.api -eq "DeleteDC" } | Select-Object -First 1)
if ($deleteDc[0].returnValue -ne "1")
{
    throw "DeleteDC did not report a successful handle close: $($deleteDc[0].returnValue)"
}

$uiGdiEvents = @($result.capturedEvents | Where-Object { $_.module -in @("user32.dll", "gdi32.dll") })
$uiGdiPayload = $uiGdiEvents | ConvertTo-Json -Depth 12
if ($uiGdiPayload -cmatch "GetWindowText|WM_GETTEXT|Clipboard|CF_|Screenshot|ScreenCapture|DIB|Bitmap|Keyboard|Mouse|Password|Credential|Authorization|Cookie|BEGIN CERTIFICATE|\b[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7,}\b")
{
    throw "Wave 3 UI/GDI events appear to expose text, pixel, clipboard, input, credential, or byte-preview evidence: $uiGdiPayload"
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Wave 3 smoke did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Hook lifecycle mismatch: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Wave 3 User32/GDI32 smoke passed: events=$($result.capturedEvents.Count) wave3Events=$($uiGdiEvents.Count) restoredHooks=$($shutdown[0].restoredHooks) overheadAvgUs=$($result.hookOverheadAvgUs)"
