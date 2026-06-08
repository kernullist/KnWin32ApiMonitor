param(
    [int]$Capacity = 4,
    [int]$Events = 10,
    [string]$CollectorPath = "build\native\Debug\knmon-collector.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $CollectorPath))
{
    throw "Collector not found: $CollectorPath"
}

$result = & $CollectorPath smoke-backpressure --capacity $Capacity --events $Events | ConvertFrom-Json

if (-not $result.success)
{
    throw "Collector backpressure smoke failed: $($result.message)"
}

$expectedAccepted = [Math]::Min($Capacity, $Events)
$expectedDropped = [Math]::Max(0, $Events - $Capacity)

if ($result.policy -ne "drop-newest")
{
    throw "Unexpected overflow policy: $($result.policy)"
}

if ($result.acceptedEvents -ne $expectedAccepted)
{
    throw "acceptedEvents mismatch: $($result.acceptedEvents)"
}

if ($result.drainedEvents -ne $expectedAccepted)
{
    throw "drainedEvents mismatch: $($result.drainedEvents)"
}

if ($result.droppedEvents -ne $expectedDropped)
{
    throw "droppedEvents mismatch: $($result.droppedEvents)"
}

if ($result.backpressureActivations -ne $expectedDropped)
{
    throw "backpressureActivations mismatch: $($result.backpressureActivations)"
}

if ($result.highWaterMark -ne $expectedAccepted)
{
    throw "highWaterMark mismatch: $($result.highWaterMark)"
}

for ($index = 0; $index -lt $result.retainedSequences.Count; ++$index)
{
    $expectedSequence = $index + 1
    if ($result.retainedSequences[$index] -ne $expectedSequence)
    {
        throw "FIFO sequence mismatch at index $index"
    }
}

Write-Host "Collector smoke passed: capacity=$Capacity events=$Events accepted=$($result.acceptedEvents) dropped=$($result.droppedEvents) retained=$($result.retainedSequences -join ',')"
