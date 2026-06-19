param(
    [string]$BuildDir = "build\native\Debug"
)

$ErrorActionPreference = "Stop"

function Assert-True
{
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition)
    {
        throw $Message
    }
}

function Invoke-HelperJson
{
    param(
        [string]$HelperPath,
        [string[]]$Arguments
    )

    $json = & $HelperPath @Arguments
    if ($LASTEXITCODE -ne 0)
    {
        throw "Helper command failed: $($Arguments -join ' ')"
    }

    return $json | ConvertFrom-Json
}

function Copy-Fixture
{
    param(
        [string]$Name,
        [string]$DestinationRoot
    )

    $source = Join-Path "tests\fixtures\session" $Name
    $destination = Join-Path $DestinationRoot $Name
    Copy-Item -Recurse -Force -LiteralPath $source -Destination $destination
    return $destination
}

$helperPath = Join-Path $BuildDir "knmon-native-helper.exe"
Assert-True (Test-Path -LiteralPath $helperPath) "Helper not found: $helperPath"

$tmpDir = Join-Path (Get-Location) ".tmp"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$root = Join-Path $tmpDir "trace-index-smoke-$([Guid]::NewGuid().ToString("N").Substring(0, 12))"
$fixtureRoot = Join-Path $root "fixtures"
$emptyRoot = Join-Path $root "empty"
New-Item -ItemType Directory -Force -Path $fixtureRoot | Out-Null
New-Item -ItemType Directory -Force -Path $emptyRoot | Out-Null

try
{
    $validPath = Copy-Fixture -Name "valid-knapm.knapm" -DestinationRoot $fixtureRoot
    Copy-Fixture -Name "valid-knapm-legacy.knapm" -DestinationRoot $fixtureRoot | Out-Null
    $zstdPath = Copy-Fixture -Name "knapm-zstd-valid.knapm" -DestinationRoot $fixtureRoot
    $invalidPath = Copy-Fixture -Name "knapm-zstd-corrupt-frame.knapm" -DestinationRoot $fixtureRoot

    $emptyDatabase = Join-Path $root "empty-trace-index.db"
    $empty = Invoke-HelperJson -HelperPath $helperPath -Arguments @("trace-index-build", "--root", $emptyRoot, "--database", $emptyDatabase, "--rebuild")
    Assert-True $empty.success "Empty root trace index build failed: $($empty.message)"
    Assert-True ($empty.sessionCount -eq 0) "Empty root trace index should have zero sessions."
    Assert-True ($empty.eventCount -eq 0) "Empty root trace index should have zero events."

    $database = Join-Path $root "trace-index.db"
    $build = Invoke-HelperJson -HelperPath $helperPath -Arguments @("trace-index-build", "--root", $fixtureRoot, "--database", $database, "--rebuild")
    Assert-True $build.success "Trace index build failed: $($build.message)"
    Assert-True (Test-Path -LiteralPath $database) "Trace index database was not created."
    Assert-True ($build.databasePath -eq $database) "Trace index response database path mismatch."
    Assert-True ($build.indexBackend -eq "winsqlite3-fts5") "Trace index backend mismatch."
    Assert-True ($build.indexSchemaVersion -eq 1) "Trace index schema version mismatch."
    Assert-True ($build.sessionCount -ge 4) "Trace index should inspect copied fixture sessions."
    Assert-True ($build.indexedSessionCount -ge 3) "Trace index should include valid fixture sessions."
    Assert-True ($build.invalidSessionCount -ge 1) "Trace index should count invalid fixture sessions."
    Assert-True ($build.eventCount -ge 3) "Trace index should include fixture trace events."

    $textQuery = Invoke-HelperJson -HelperPath $helperPath -Arguments @("trace-index-query", "--database", $database, "--text", "CreateFileW", "--limit", "10")
    Assert-True $textQuery.success "Trace index text query failed: $($textQuery.message)"
    Assert-True (@($textQuery.events).Count -ge 1) "Trace index text query returned no events."
    Assert-True (@($textQuery.events | Where-Object { $_.api -ne "CreateFileW" }).Count -eq 0) "Trace index text query returned unexpected APIs."

    $moduleQuery = Invoke-HelperJson -HelperPath $helperPath -Arguments @("trace-index-query", "--database", $database, "--module", "kernel32.dll", "--limit", "10")
    Assert-True ($moduleQuery.success -and @($moduleQuery.events).Count -ge 1) "Trace index module query returned no events."

    $apiQuery = Invoke-HelperJson -HelperPath $helperPath -Arguments @("trace-index-query", "--database", $database, "--api", "CreateFileW", "--limit", "2")
    Assert-True ($apiQuery.success -and @($apiQuery.events).Count -le 2 -and @($apiQuery.events).Count -ge 1) "Trace index API query limit failed."

    $pidQuery = Invoke-HelperJson -HelperPath $helperPath -Arguments @("trace-index-query", "--database", $database, "--pid", "1234", "--limit", "10")
    Assert-True ($pidQuery.success -and @($pidQuery.events).Count -ge 1) "Trace index PID query returned no fixture events."

    $sessionQuery = Invoke-HelperJson -HelperPath $helperPath -Arguments @("trace-index-query", "--database", $database, "--session", "fixture-knapm-valid", "--limit", "10")
    Assert-True ($sessionQuery.success -and @($sessionQuery.events).Count -ge 1) "Trace index session query returned no fixture events."
    Assert-True (@($sessionQuery.events | Where-Object { $_.sessionId -ne "fixture-knapm-valid" }).Count -eq 0) "Trace index session query returned other sessions."

    $catalogDatabase = Join-Path $root "catalog-index.db"
    $catalogBuild = Invoke-HelperJson -HelperPath $helperPath -Arguments @("catalog-index-build", "--root", $fixtureRoot, "--database", $catalogDatabase, "--rebuild")
    Assert-True $catalogBuild.success "Catalog index setup for format-mismatch smoke failed: $($catalogBuild.message)"
    $formatMismatch = Invoke-HelperJson -HelperPath $helperPath -Arguments @("trace-index-query", "--database", $catalogDatabase, "--text", "CreateFileW")
    Assert-True (-not $formatMismatch.success) "Trace index query should reject catalog index DB."
    Assert-True ($formatMismatch.message -match "not a trace index") "Trace index format mismatch message unexpected: $($formatMismatch.message)"

    $badDatabase = Join-Path $root "not-sqlite.db"
    Set-Content -LiteralPath $badDatabase -Value "not sqlite" -Encoding ASCII
    $badQuery = Invoke-HelperJson -HelperPath $helperPath -Arguments @("trace-index-query", "--database", $badDatabase)
    Assert-True (-not $badQuery.success) "Malformed trace index DB should fail."
    Assert-True (-not [string]::IsNullOrWhiteSpace($badQuery.message)) "Malformed trace index DB should return a typed message."

    Remove-Item -Recurse -Force -LiteralPath $invalidPath
    $dryRun = Invoke-HelperJson -HelperPath $helperPath -Arguments @("trace-index-remove-missing", "--database", $database, "--dry-run")
    Assert-True $dryRun.success "Trace index missing dry-run failed: $($dryRun.message)"
    Assert-True (-not $dryRun.mutationAttempted) "Trace index dry-run should not mutate."
    Assert-True (@($dryRun.missingSessionPaths).Count -eq 0) "Invalid unindexed session should not be tracked as a missing indexed row."
    Assert-True (Test-Path -LiteralPath $validPath) "Trace index dry-run mutated existing .knapm data."

    Remove-Item -Recurse -Force -LiteralPath $zstdPath
    $dryRunIndexed = Invoke-HelperJson -HelperPath $helperPath -Arguments @("trace-index-remove-missing", "--database", $database, "--dry-run")
    Assert-True (@($dryRunIndexed.missingSessionPaths).Count -eq 1) "Trace index dry-run should report one missing indexed row."
    Assert-True (@($dryRunIndexed.missingSessionPaths)[0] -eq $zstdPath) "Trace index dry-run reported the wrong missing row."

    $removed = Invoke-HelperJson -HelperPath $helperPath -Arguments @("trace-index-remove-missing", "--database", $database)
    Assert-True $removed.success "Trace index missing removal failed: $($removed.message)"
    Assert-True $removed.mutationAttempted "Trace index removal should report mutation attempted."
    Assert-True (@($removed.missingSessionPaths).Count -eq 1) "Trace index removal should report one missing indexed row."
    Assert-True (Test-Path -LiteralPath $validPath) "Trace index removal mutated unrelated .knapm data."

    $postRemoveQuery = Invoke-HelperJson -HelperPath $helperPath -Arguments @("trace-index-query", "--database", $database, "--text", "CreateFileW", "--limit", "100")
    Assert-True $postRemoveQuery.success "Trace index query after removal failed: $($postRemoveQuery.message)"
    Assert-True (@($postRemoveQuery.events | Where-Object { $_.sessionPath -in @($removed.missingSessionPaths) }).Count -eq 0) "Removed missing trace index row still appears in query."

    Write-Output "Trace index smoke passed: built=$($build.eventCount) textMatches=$(@($textQuery.events).Count) removed=$($removed.sessionCount)"
}
finally
{
    if (Test-Path -LiteralPath $root)
    {
        Remove-Item -Recurse -Force -LiteralPath $root -ErrorAction SilentlyContinue
    }
}
