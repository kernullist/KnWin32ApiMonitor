param(
    [ValidateSet("desktop", "ui")]
    [string]$Mode = "desktop",

    [switch]$Restart,

    [switch]$NativeBuild,

    [int]$WaitForUiSeconds = 20
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$runDir = Join-Path $repoRoot ".tmp\app-run"
$statePath = Join-Path $runDir "state.json"
$stdoutPath = Join-Path $runDir "app.out.log"
$stderrPath = Join-Path $runDir "app.err.log"
$uiUrl = "http://127.0.0.1:5173"

function Test-ProcessAlive
{
    param(
        [int]$TargetProcessId
    )

    $process = Get-Process -Id $TargetProcessId -ErrorAction SilentlyContinue
    return $null -ne $process
}

function Read-AppState
{
    if (!(Test-Path -LiteralPath $statePath))
    {
        return $null
    }

    try
    {
        return Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    }
    catch
    {
        Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
        return $null
    }
}

function Test-TcpPort
{
    param(
        [string]$HostName,
        [int]$Port
    )

    $client = $null
    $connected = $false

    try
    {
        $client = [System.Net.Sockets.TcpClient]::new()
        $asyncResult = $client.BeginConnect($HostName, $Port, $null, $null)
        $connected = $asyncResult.AsyncWaitHandle.WaitOne(250)

        if ($connected)
        {
            $client.EndConnect($asyncResult)
        }
    }
    catch
    {
        $connected = $false
    }
    finally
    {
        if ($null -ne $client)
        {
            $client.Close()
        }
    }

    return $connected
}

New-Item -ItemType Directory -Path $runDir -Force | Out-Null

$existingState = Read-AppState
if ($null -ne $existingState)
{
    $rootPidProperty = $existingState.PSObject.Properties["rootPid"]

    if ($null -ne $rootPidProperty -and $null -ne $rootPidProperty.Value)
    {
        $existingProcessId = [int]$rootPidProperty.Value

        if (Test-ProcessAlive -TargetProcessId $existingProcessId)
        {
            if (!$Restart)
            {
                Write-Host "KN Win32 API Monitor is already running. PID=$existingProcessId"
                Write-Host "Use .\Stop-App.ps1 or .\Start-App.ps1 -Restart."
                exit 0
            }

            & (Join-Path $repoRoot "Stop-App.ps1") -Quiet
        }
        else
        {
            Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
        }
    }
}

if ($NativeBuild)
{
    Push-Location $repoRoot
    try
    {
        & npm.cmd run native:build

        if ($LASTEXITCODE -ne 0)
        {
            exit $LASTEXITCODE
        }
    }
    finally
    {
        Pop-Location
    }
}

Remove-Item -LiteralPath $stdoutPath -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue

$npmCommand = Get-Command npm.cmd -ErrorAction SilentlyContinue
if ($null -eq $npmCommand)
{
    $npmCommand = Get-Command npm -ErrorAction Stop
}

$npm = $npmCommand.Source
if ($Mode -eq "desktop")
{
    $npmArgs = @("run", "tauri:dev")
}
else
{
    $npmArgs = @("run", "dev")
}

$process = Start-Process `
    -FilePath $npm `
    -ArgumentList $npmArgs `
    -WorkingDirectory $repoRoot `
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdoutPath `
    -RedirectStandardError $stderrPath `
    -PassThru

$state = [ordered]@{
    rootPid = $process.Id
    mode = $Mode
    command = "npm $($npmArgs -join ' ')"
    cwd = $repoRoot
    startedAt = (Get-Date).ToString("o")
    uiUrl = $uiUrl
    stdout = $stdoutPath
    stderr = $stderrPath
}

$state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8

Write-Host "KN Win32 API Monitor started. PID=$($process.Id) mode=$Mode"
Write-Host "Logs: $stdoutPath"

if ($WaitForUiSeconds -gt 0)
{
    $deadline = (Get-Date).AddSeconds($WaitForUiSeconds)
    while ((Get-Date) -lt $deadline)
    {
        if (Test-TcpPort -HostName "127.0.0.1" -Port 5173)
        {
            Write-Host "UI ready: $uiUrl"
            exit 0
        }

        Start-Sleep -Milliseconds 500
    }

    Write-Host "UI was not ready within $WaitForUiSeconds seconds. The app may still be starting."
}
