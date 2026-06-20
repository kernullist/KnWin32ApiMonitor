param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $HelperPath))
{
    throw "Helper not found: $HelperPath"
}

$result = & $HelperPath capture-sample | ConvertFrom-Json

if (-not $result.success)
{
    throw "Resolver monitoring capture failed: $($result.operation): $($result.message)"
}

if ($result.transportMode -ne "shared-memory")
{
    throw "Resolver monitoring did not use shared-memory transport: $($result.transportMode)"
}

if ($result.droppedEvents -ne 0)
{
    throw "Resolver monitoring reported dropped events: $($result.droppedEvents)"
}

$resolverApis = @(
    "GetProcAddress",
    "LdrGetProcedureAddress"
)

$apis = @($result.capturedEvents | ForEach-Object { $_.api } | Sort-Object -Unique)
foreach ($api in $resolverApis)
{
    if ($apis -notcontains $api)
    {
        throw "Resolver monitoring missing API: $api"
    }
}

$getProc = @($result.capturedEvents | Where-Object { $_.api -eq "GetProcAddress" } | Select-Object -First 1)
if ($getProc.Count -ne 1)
{
    throw "Resolver monitoring did not capture exactly one GetProcAddress sample event."
}

if ($getProc[0].module -ne "kernel32.dll")
{
    throw "GetProcAddress module mismatch: $($getProc[0].module)"
}

if ($getProc[0].tags -notcontains "resolver" -or $getProc[0].tags -notcontains "dynamic_symbol_lookup")
{
    throw "GetProcAddress resolver tags missing: $($getProc[0].tags -join ',')"
}

if ($getProc[0].returnValue -notmatch "^0x[0-9a-fA-F]+$")
{
    throw "GetProcAddress returnValue is not a hex pointer: $($getProc[0].returnValue)"
}

$getProcArgs = ($getProc[0].arguments | ConvertTo-Json -Depth 8)
if ($getProcArgs -notmatch "KnMonDynamicProbe")
{
    throw "GetProcAddress arguments did not include dynamic probe evidence: $getProcArgs"
}

$ldr = @($result.capturedEvents | Where-Object { $_.api -eq "LdrGetProcedureAddress" } | Select-Object -First 1)
if ($ldr.Count -ne 1)
{
    throw "Resolver monitoring did not capture exactly one LdrGetProcedureAddress sample event."
}

if ($ldr[0].module -ne "ntdll.dll")
{
    throw "LdrGetProcedureAddress module mismatch: $($ldr[0].module)"
}

if ($ldr[0].tags -notcontains "resolver" -or $ldr[0].tags -notcontains "dynamic_symbol_lookup_nt")
{
    throw "LdrGetProcedureAddress resolver tags missing: $($ldr[0].tags -join ',')"
}

if ($ldr[0].returnValue -notmatch "^0x[0-9a-fA-F]{8}$")
{
    throw "LdrGetProcedureAddress returnValue is not NTSTATUS hex: $($ldr[0].returnValue)"
}

$ldrArgs = ($ldr[0].arguments | ConvertTo-Json -Depth 8)
if ($ldrArgs -notmatch "KnMonDynamicProbe")
{
    throw "LdrGetProcedureAddress arguments did not include dynamic probe evidence: $ldrArgs"
}

if ($ldrArgs -notmatch "0x[0-9a-fA-F]+")
{
    throw "LdrGetProcedureAddress arguments did not include pointer evidence: $ldrArgs"
}

$resolverPointerCalls = @($result.agentMessages | Where-Object { $_.messageType -eq "resolver_pointer_call" })
if ($resolverPointerCalls.Count -ne 0)
{
    throw "Resolver candidate ledger smoke must not emit resolver_pointer_call events."
}

$ledgerMessages = @($result.agentMessages | Where-Object {
    $_.messageType -eq "resolver_pointer_candidate" -or
    $_.messageType -eq "resolver_pointer_unsupported"
})

if ($ledgerMessages.Count -lt 2)
{
    throw "Resolver pointer ledger evidence missing."
}

$candidateLedgerCount = @($ledgerMessages | Where-Object { $_.messageType -eq "resolver_pointer_candidate" }).Count
$unsupportedLedgerCount = @($ledgerMessages | Where-Object { $_.messageType -eq "resolver_pointer_unsupported" }).Count

if ([uint64]$result.resolverPointerCandidates -ne [uint64]$candidateLedgerCount)
{
    throw "Resolver pointer candidate counter mismatch: result=$($result.resolverPointerCandidates) ledger=$candidateLedgerCount"
}

if ([uint64]$result.resolverPointerUnsupported -ne [uint64]$unsupportedLedgerCount)
{
    throw "Resolver pointer unsupported counter mismatch: result=$($result.resolverPointerUnsupported) ledger=$unsupportedLedgerCount"
}

if ($candidateLedgerCount -lt 1 -or $unsupportedLedgerCount -lt 1)
{
    throw "Resolver pointer counters did not include both candidate and unsupported evidence: candidates=$candidateLedgerCount unsupported=$unsupportedLedgerCount"
}

$candidate = @($ledgerMessages | Where-Object {
    $_.messageType -eq "resolver_pointer_candidate" -and
    $_.definitionName -eq "GetCurrentProcessId" -and
    $_.definitionApiId -eq 141
} | Select-Object -First 1)

if ($candidate.Count -ne 1)
{
    throw "Resolver pointer candidate evidence for GetCurrentProcessId missing."
}

if ($candidate[0].instrumented -ne $false)
{
    throw "Resolver pointer candidate must be explicitly uninstrumented."
}

if ($candidate[0].targetExecutable -ne $true -or [uint64]$candidate[0].targetRva -eq 0)
{
    throw "Resolver pointer candidate did not include executable target RVA evidence."
}

if ($candidate[0].hookPolicy -ne "iat")
{
    throw "Resolver pointer candidate did not map to generated hook policy: $($candidate[0].hookPolicy)"
}

$unsupported = @($ledgerMessages | Where-Object {
    $_.messageType -eq "resolver_pointer_unsupported" -and
    $_.requestedName -eq "KnMonDynamicProbe" -and
    $_.reason -eq "unsupported_definition_missing"
} | Select-Object -First 1)

if ($unsupported.Count -ne 1)
{
    throw "Resolver pointer unsupported evidence for KnMonDynamicProbe missing."
}

$candidateAudit = @($result.auditEvents | Where-Object {
    $_.eventType -eq "resolver_pointer_candidate" -and
    $_.operation -eq "resolver_pointer_classification" -and
    $_.message -match "GetCurrentProcessId" -and
    $_.message -match "instrumented=false"
} | Select-Object -First 1)

if ($candidateAudit.Count -ne 1)
{
    throw "Resolver pointer candidate audit output missing."
}

$unsupportedAudit = @($result.auditEvents | Where-Object {
    $_.eventType -eq "resolver_pointer_unsupported" -and
    $_.operation -eq "resolver_pointer_classification" -and
    $_.message -match "KnMonDynamicProbe" -and
    $_.message -match "unsupported_definition_missing"
} | Select-Object -First 1)

if ($unsupportedAudit.Count -ne 1)
{
    throw "Resolver pointer unsupported audit output missing."
}

$resolverHooks = @($result.agentMessages | Where-Object {
    $_.messageType -eq "hook_installed" -and
    $_.api -in $resolverApis
})

foreach ($api in $resolverApis)
{
    $hook = @($resolverHooks | Where-Object { $_.api -eq $api })
    if ($hook.Count -lt 1)
    {
        throw "Resolver hook installation evidence missing for $api."
    }
}

$shutdown = @($result.agentMessages | Where-Object { $_.messageType -eq "agent_shutdown" } | Select-Object -Last 1)
if ($shutdown.Count -ne 1)
{
    throw "Resolver monitoring did not receive agent_shutdown."
}

if ($shutdown[0].restoredHooks -ne $shutdown[0].installedHooks -or $shutdown[0].failedHooks -ne 0)
{
    throw "Unexpected resolver hook lifecycle counts: installed=$($shutdown[0].installedHooks) restored=$($shutdown[0].restoredHooks) failed=$($shutdown[0].failedHooks)"
}

Write-Host "Resolver monitoring smoke passed: apis=$($resolverApis -join ',') hooks=$($shutdown[0].installedHooks) events=$($result.capturedEvents.Count) resolver=$candidateLedgerCount/$unsupportedLedgerCount ledger=$($ledgerMessages.Count)"
