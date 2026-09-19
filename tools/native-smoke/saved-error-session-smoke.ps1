param([string]$BuildDir = 'build/native/Debug')
$ErrorActionPreference = 'Stop'
$helper = Join-Path $BuildDir 'knmon-native-helper.exe'
$sessionPath = Join-Path (Get-Location) ('build/saved-error-session-' + [guid]::NewGuid().ToString('N'))
$manifest = Get-Content generated/runtime-support.json -Raw | ConvertFrom-Json
$selection = ($manifest.supportedKeys | ForEach-Object { ($_.Split('!')[0]) + '!*' } | Sort-Object -Unique) -join ';'
$captureText = & $helper capture-sample --api-selection $selection --timeout-ms 30000 --write-session $sessionPath
if ($LASTEXITCODE -ne 0)
{
    throw 'Live capture session write failed.'
}
$capture = $captureText | ConvertFrom-Json
if (!$capture.success)
{
    throw 'Live capture returned failure.'
}
$validationText = & $helper validate-session --session $sessionPath
$validation = $validationText | ConvertFrom-Json
if (!$validation.success)
{
    throw ('Saved live session validation failed: ' + ($validation.validationErrors -join '; '))
}
$replayText = & $helper replay-session --session $sessionPath
$replay = $replayText | ConvertFrom-Json
$errors = @($replay.traceEvents | Where-Object { $null -ne $_.error })
if (!$replay.success -or $errors.Count -eq 0)
{
    throw 'Replay must contain valid non-null error objects.'
}
$captureText | Set-Content -LiteralPath (Join-Path $sessionPath 'capture-result.json')
$replayText | Set-Content -LiteralPath (Join-Path $sessionPath 'replay-result.json')
Write-Output ('Live error session passed: events=' + @($replay.traceEvents).Count + ' errorObjects=' + $errors.Count + ' path=' + $sessionPath)
