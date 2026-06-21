param(
    [switch]$Quiet,

    [switch]$KillPort,

    [int]$Port = 5173
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$runDir = Join-Path $repoRoot ".tmp\app-run"
$statePath = Join-Path $runDir "state.json"

function Write-Status
{
    param(
        [string]$Message
    )

    if (!$Quiet)
    {
        Write-Host $Message
    }
}

function Test-ProcessAlive
{
    param(
        [int]$TargetProcessId
    )

    $process = Get-Process -Id $TargetProcessId -ErrorAction SilentlyContinue
    return $null -ne $process
}

function Get-ChildProcessIds
{
    param(
        [int]$TargetProcessId
    )

    $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$TargetProcessId" -ErrorAction SilentlyContinue)
    return @($children | ForEach-Object { [int]$_.ProcessId })
}

function Stop-ProcessTree
{
    param(
        [int]$TargetProcessId
    )

    $children = @(Get-ChildProcessIds -TargetProcessId $TargetProcessId)
    foreach ($childProcessId in $children)
    {
        Stop-ProcessTree -TargetProcessId $childProcessId
    }

    if ($TargetProcessId -ne $PID)
    {
        Stop-Process -Id $TargetProcessId -Force -ErrorAction SilentlyContinue
    }
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
        return $null
    }
}

function Get-ListeningProcessIds
{
    param(
        [int]$TargetPort
    )

    $connections = @(Get-NetTCPConnection -LocalPort $TargetPort -State Listen -ErrorAction SilentlyContinue)
    return @($connections | Select-Object -ExpandProperty OwningProcess -Unique)
}

$stoppedAny = $false
$state = Read-AppState

if ($null -ne $state)
{
    $rootPidProperty = $state.PSObject.Properties["rootPid"]

    if ($null -ne $rootPidProperty -and $null -ne $rootPidProperty.Value)
    {
        $rootProcessId = [int]$rootPidProperty.Value

        if (Test-ProcessAlive -TargetProcessId $rootProcessId)
        {
            Write-Status "Stopping KN Win32 API Monitor. PID=$rootProcessId"
            Stop-ProcessTree -TargetProcessId $rootProcessId
            $stoppedAny = $true

            for ($i = 0; $i -lt 20; $i++)
            {
                if (!(Test-ProcessAlive -TargetProcessId $rootProcessId))
                {
                    break
                }

                Start-Sleep -Milliseconds 250
            }
        }
    }
}

if ($KillPort)
{
    $portProcessIds = @(Get-ListeningProcessIds -TargetPort $Port)
    foreach ($portProcessId in $portProcessIds)
    {
        if ($portProcessId -ne $PID -and (Test-ProcessAlive -TargetProcessId $portProcessId))
        {
            Write-Status "Stopping process listening on port $Port. PID=$portProcessId"
            Stop-ProcessTree -TargetProcessId ([int]$portProcessId)
            $stoppedAny = $true
        }
    }
}

Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue

if ($stoppedAny)
{
    Write-Status "KN Win32 API Monitor stopped."
}
else
{
    Write-Status "KN Win32 API Monitor is not running."
}
