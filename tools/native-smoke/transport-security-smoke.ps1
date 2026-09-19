param(
    [string]$HelperPath = 'build\native-msvc\Debug\knmon-native-helper.exe'
)

$ErrorActionPreference = 'Stop'
$target = Join-Path (Split-Path -Parent $HelperPath) 'knmon-transport-tamper-target.exe'
$responseText = & $HelperPath capture-sample --target $target --api-selection 'kernel32.dll!ReadFile' --timeout-ms 5000
$response = $responseText | ConvertFrom-Json
if ($response.success -or $response.operation -ne 'transport_corrupted' -or $response.sessionState -ne 'failed')
{
    throw "Transport corruption did not fail the capture: $($response.operation) / $($response.message)"
}
if (@($response.auditEvents | Where-Object { $_.eventType -eq 'transport_corrupted' }).Count -ne 1)
{
    throw 'Transport corruption must emit exactly one audit event.'
}
Write-Output "Controlled transport corruption failed closed: architecture=$($response.architecture)"
