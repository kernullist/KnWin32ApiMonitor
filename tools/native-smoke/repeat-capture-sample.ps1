param(
    [int]$Count = 5,
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

$requiredApis = @(
    "CreateFileW",
    "CreateFileA",
    "ReadFile",
    "WriteFile",
    "CloseHandle"
)

if ($Count -lt 1)
{
    throw "Count must be at least 1."
}

if (-not (Test-Path -LiteralPath $HelperPath))
{
    throw "Helper not found: $HelperPath"
}

for ($index = 1; $index -le $Count; ++$index)
{
    $result = & $HelperPath capture-sample | ConvertFrom-Json

    if (-not $result.success)
    {
        throw "Run $index failed: $($result.operation): $($result.message)"
    }

    if (-not $result.handshake.received)
    {
        throw "Run $index did not receive HELLO."
    }

    if ($result.droppedEvents -ne 0)
    {
        throw "Run $index reported dropped events: $($result.droppedEvents)"
    }

    $apis = @($result.capturedEvents | ForEach-Object { $_.api } | Sort-Object -Unique)
    foreach ($api in $requiredApis)
    {
        if ($apis -notcontains $api)
        {
            throw "Run $index missing API: $api"
        }
    }

    $shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
    if ($shutdown.Count -ne 1)
    {
        throw "Run $index did not receive exactly one agent_shutdown event."
    }

    if ($shutdown[0].installedHooks -ne 5)
    {
        throw "Run $index unexpected installedHooks: $($shutdown[0].installedHooks)"
    }

    if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks)
    {
        throw "Run $index restoredHooks did not match installedHooks."
    }

    if ($shutdown[0].failedHooks -ne 0)
    {
        throw "Run $index reported failedHooks: $($shutdown[0].failedHooks)"
    }

    Write-Host "Run $index passed: events=$($result.capturedEvents.Count), restoredHooks=$($shutdown[0].restoredHooks), apis=$($apis -join ',')"
}

Write-Host "Repeated capture smoke passed: $Count runs."
