param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe",
    [int]$Capacity = 2,
    [int]$Attempts = 5
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $HelperPath))
{
    throw "Helper not found: $HelperPath"
}

$previousCapacity = $env:KNMON_TRANSPORT_CAPACITY
$env:KNMON_TRANSPORT_CAPACITY = [string]$Capacity

try
{
    $result = $null

    for ($attempt = 1; $attempt -le $Attempts; $attempt++)
    {
        $result = & $HelperPath capture-sample | ConvertFrom-Json

        if (-not $result.success)
        {
            throw "Backpressure capture failed: $($result.operation): $($result.message)"
        }

        if ($result.transportMode -ne "shared-memory")
        {
            throw "Unexpected transport mode under backpressure: $($result.transportMode)"
        }

        if ($result.transportCapacity -ne $Capacity)
        {
            throw "Unexpected transport capacity: expected $Capacity got $($result.transportCapacity)"
        }

        if ($result.transportDroppedEvents -gt 0)
        {
            break
        }

        Start-Sleep -Milliseconds 100
    }
}
finally
{
    if ($null -eq $previousCapacity)
    {
        Remove-Item Env:\KNMON_TRANSPORT_CAPACITY -ErrorAction SilentlyContinue
    }
    else
    {
        $env:KNMON_TRANSPORT_CAPACITY = $previousCapacity
    }
}

if ($result.transportDroppedEvents -le 0)
{
    throw "Backpressure smoke expected dropped transport events after $Attempts attempts. Last produced=$($result.transportRecordsProduced) consumed=$($result.transportRecordsConsumed)"
}

if ($result.droppedEvents -lt $result.transportDroppedEvents)
{
    throw "Result droppedEvents did not include transport drops: result=$($result.droppedEvents) transport=$($result.transportDroppedEvents)"
}

if ($result.transportHighWaterMark -gt $result.transportCapacity)
{
    throw "Transport high-water mark exceeded bounded capacity: highWater=$($result.transportHighWaterMark) capacity=$($result.transportCapacity)"
}

if ($result.capturedEvents.Count -le 0)
{
    throw "Backpressure capture did not retain any events."
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Backpressure capture did not receive agent_shutdown."
}

Write-Host "Shared-memory backpressure smoke passed: capacity=$($result.transportCapacity) consumed=$($result.transportRecordsConsumed) produced=$($result.transportRecordsProduced) dropped=$($result.transportDroppedEvents)"
