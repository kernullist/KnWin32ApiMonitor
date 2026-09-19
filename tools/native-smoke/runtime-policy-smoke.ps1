param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"
$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\generated\runtime-support.json') -Raw | ConvertFrom-Json
$supportText = & $HelperPath runtime-support
if ($LASTEXITCODE -ne 0)
{
    throw 'Runtime support query failed.'
}
$support = $supportText | ConvertFrom-Json
if (!$support.success -or ($support.supportedKeys -join ';') -cne ($manifest.supportedKeys -join ';'))
{
    throw 'Compiled helper policy does not match the generated manifest.'
}

foreach ($selection in @('user32.dll!wsprintfW', 'd2d1.dll!D2D1ConvertColorSpace', 'oleaut32.dll!VarR8FromR4', 'kernel32.dll!ReadFile;user32.dll!wsprintfW'))
{
    $responseText = & $HelperPath capture-sample --api-selection $selection
    $responseCode = $LASTEXITCODE
    $response = $responseText | ConvertFrom-Json
    if ($responseCode -eq 0 -or $response.success -or $response.message -ne 'unsupported_api_selection')
    {
        throw "Unsafe selection was not rejected: $selection"
    }
}
Write-Output 'Runtime policy smoke passed: manifest parity and unsafe selection rejection.'

$selection = ($manifest.supportedKeys | ForEach-Object { ($_.Split('!')[0]) + '!*' } | Sort-Object -Unique) -join ';'
$captureText = & $HelperPath capture-sample --api-selection $selection --timeout-ms 30000
if ($LASTEXITCODE -ne 0)
{
    throw 'Controlled supported-subset capture failed.'
}
$capture = $captureText | ConvertFrom-Json
$fileEvents = @($capture.capturedEvents | Where-Object { $_.api -eq 'CreateFileW' -and $_.module -eq 'kernel32.dll' })
if (!$capture.success -or $fileEvents.Count -eq 0 -or $capture.transportDroppedEvents -ne 0)
{
    throw "Capture metadata or loss regression: $($capture.operation)"
}
Write-Output "Controlled subset capture passed: architecture=$($capture.architecture) events=$(@($capture.capturedEvents).Count)"
