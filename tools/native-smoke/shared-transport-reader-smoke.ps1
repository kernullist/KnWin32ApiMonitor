param(
    [string]$CollectorPath = "build\native\Debug\knmon-collector.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $CollectorPath))
{
    throw "Collector not found: $CollectorPath"
}

function Invoke-ReaderSmoke
{
    param(
        [string[]]$Arguments,
        [int]$ExpectedDrained,
        [bool]$ExpectedUnavailable
    )

    $result = & $CollectorPath @Arguments | ConvertFrom-Json

    if (-not $result.success)
    {
        throw "Shared transport reader smoke failed: $($result.message)"
    }

    if (-not $result.headerValid)
    {
        throw "Shared transport reader header was not valid."
    }

    if ($result.recordsDrained -ne $ExpectedDrained)
    {
        throw "recordsDrained mismatch: expected=$ExpectedDrained actual=$($result.recordsDrained)"
    }

    if ($result.recordsConsumed -ne $ExpectedDrained)
    {
        throw "recordsConsumed mismatch: expected=$ExpectedDrained actual=$($result.recordsConsumed)"
    }

    if ([bool]$result.stoppedOnUnavailableRecord -ne $ExpectedUnavailable)
    {
        throw "stoppedOnUnavailableRecord mismatch: expected=$ExpectedUnavailable actual=$($result.stoppedOnUnavailableRecord)"
    }

    if ($result.recordsDropped -ne 0)
    {
        throw "Unexpected reader drops: $($result.recordsDropped)"
    }

    for ($index = 0; $index -lt $result.consumedSequences.Count; ++$index)
    {
        if ($result.consumedSequences[$index] -ne $index)
        {
            throw "Consumed sequence mismatch at index $index"
        }
    }

    return $result
}

$fifo = Invoke-ReaderSmoke `
    -Arguments @("smoke-shared-transport-reader", "--capacity", "4", "--records", "3") `
    -ExpectedDrained 3 `
    -ExpectedUnavailable $false

$partial = Invoke-ReaderSmoke `
    -Arguments @("smoke-shared-transport-reader", "--capacity", "4", "--records", "3", "--partial") `
    -ExpectedDrained 2 `
    -ExpectedUnavailable $true

$bounded = Invoke-ReaderSmoke `
    -Arguments @("smoke-shared-transport-reader", "--capacity", "4", "--records", "4", "--max-drain", "2") `
    -ExpectedDrained 2 `
    -ExpectedUnavailable $false

Write-Host "Shared transport reader smoke passed: fifo=$($fifo.recordsDrained) partial=$($partial.recordsDrained) bounded=$($bounded.recordsDrained)"
