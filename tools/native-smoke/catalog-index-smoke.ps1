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

function Set-UnsupportedSchemaVersion
{
    param(
        [string]$DatabasePath
    )

    if (-not ("WinSqliteSmoke" -as [type]))
    {
        Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class WinSqliteSmoke
{
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern int sqlite3_open_v2(string filename, out IntPtr db, int flags, IntPtr zVfs);

    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern int sqlite3_exec(IntPtr db, string sql, IntPtr callback, IntPtr argument, out IntPtr errorMessage);

    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int sqlite3_close(IntPtr db);

    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void sqlite3_free(IntPtr value);
}
"@
    }

    $database = [IntPtr]::Zero
    $SQLITE_OPEN_READWRITE = 0x00000002
    $rc = [WinSqliteSmoke]::sqlite3_open_v2($DatabasePath, [ref]$database, $SQLITE_OPEN_READWRITE, [IntPtr]::Zero)
    Assert-True ($rc -eq 0 -and $database -ne [IntPtr]::Zero) "sqlite3_open_v2 failed for unsupported schema smoke."

    try
    {
        $errorPointer = [IntPtr]::Zero
        $rc = [WinSqliteSmoke]::sqlite3_exec($database, "UPDATE metadata SET value='999' WHERE key='schema_version'; PRAGMA user_version = 999;", [IntPtr]::Zero, [IntPtr]::Zero, [ref]$errorPointer)
        if ($errorPointer -ne [IntPtr]::Zero)
        {
            [WinSqliteSmoke]::sqlite3_free($errorPointer)
        }

        Assert-True ($rc -eq 0) "sqlite3_exec failed while setting unsupported schema version."
    }
    finally
    {
        [void][WinSqliteSmoke]::sqlite3_close($database)
    }
}

$helperPath = Join-Path $BuildDir "knmon-native-helper.exe"
Assert-True (Test-Path -LiteralPath $helperPath) "Helper not found: $helperPath"

$tmpDir = Join-Path (Get-Location) ".tmp"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$root = Join-Path $tmpDir "catalog-index-smoke-$([Guid]::NewGuid().ToString("N").Substring(0, 12))"
$fixtureRoot = Join-Path $root "fixtures"
$emptyRoot = Join-Path $root "empty"
New-Item -ItemType Directory -Force -Path $fixtureRoot | Out-Null
New-Item -ItemType Directory -Force -Path $emptyRoot | Out-Null

try
{
    $validPath = Copy-Fixture -Name "valid-knapm.knapm" -DestinationRoot $fixtureRoot
    Copy-Fixture -Name "valid-knapm-legacy.knapm" -DestinationRoot $fixtureRoot | Out-Null
    Copy-Fixture -Name "knapm-zstd-valid.knapm" -DestinationRoot $fixtureRoot | Out-Null
    $missingCandidate = Copy-Fixture -Name "knapm-zstd-corrupt-frame.knapm" -DestinationRoot $fixtureRoot

    $emptyDatabase = Join-Path $root "empty-catalog-index.db"
    $empty = Invoke-HelperJson -HelperPath $helperPath -Arguments @("catalog-index-build", "--root", $emptyRoot, "--database", $emptyDatabase, "--rebuild")
    Assert-True $empty.success "Empty root catalog index build failed: $($empty.message)"
    Assert-True ($empty.sessionCount -eq 0) "Empty root catalog index should have zero sessions."

    $database = Join-Path $root "catalog-index.db"
    $build = Invoke-HelperJson -HelperPath $helperPath -Arguments @("catalog-index-build", "--root", $fixtureRoot, "--database", $database, "--rebuild")
    Assert-True $build.success "Catalog index build failed: $($build.message)"
    Assert-True (Test-Path -LiteralPath $database) "Catalog index database was not created."
    Assert-True ($build.databasePath -eq $database) "Catalog index response database path mismatch."
    Assert-True ($build.indexBackend -eq "winsqlite3") "Catalog index backend mismatch."
    Assert-True ($build.indexSchemaVersion -eq 1) "Catalog index schema version mismatch."
    Assert-True ($build.sessionCount -ge 4) "Catalog index should include copied fixture sessions."
    Assert-True ($build.validSessionCount -ge 3) "Catalog index should include valid fixture sessions."
    Assert-True ($build.invalidSessionCount -ge 1) "Catalog index should include invalid fixture sessions."

    $validQuery = Invoke-HelperJson -HelperPath $helperPath -Arguments @("catalog-index-query", "--database", $database, "--state", "valid", "--limit", "2")
    Assert-True $validQuery.success "Catalog index valid query failed: $($validQuery.message)"
    Assert-True (@($validQuery.sessions).Count -le 2) "Catalog index limit was not applied."
    Assert-True (@($validQuery.sessions | Where-Object { $_.validationStatus -ne "valid" }).Count -eq 0) "Catalog index valid query returned non-valid rows."

    $invalidQuery = Invoke-HelperJson -HelperPath $helperPath -Arguments @("catalog-index-query", "--database", $database, "--state", "invalid", "--limit", "10")
    Assert-True ($invalidQuery.success -and @($invalidQuery.sessions).Count -ge 1) "Catalog index invalid query did not return invalid rows."

    $finalizedQuery = Invoke-HelperJson -HelperPath $helperPath -Arguments @("catalog-index-query", "--database", $database, "--state", "finalized", "--limit", "10")
    Assert-True ($finalizedQuery.success -and @($finalizedQuery.sessions).Count -ge 1) "Catalog index writer/recovery state query did not return finalized rows."

    $targetPidQuery = Invoke-HelperJson -HelperPath $helperPath -Arguments @("catalog-index-query", "--database", $database, "--target", "1234", "--limit", "10")
    Assert-True ($targetPidQuery.success -and @($targetPidQuery.sessions).Count -ge 1) "Catalog index PID query did not return fixture rows."

    $targetTextQuery = Invoke-HelperJson -HelperPath $helperPath -Arguments @("catalog-index-query", "--database", $database, "--target", "fixture", "--limit", "10")
    Assert-True ($targetTextQuery.success -and @($targetTextQuery.sessions).Count -ge 1) "Catalog index text query did not return fixture rows."

    Remove-Item -Recurse -Force -LiteralPath $missingCandidate
    $dryRun = Invoke-HelperJson -HelperPath $helperPath -Arguments @("catalog-index-remove-missing", "--database", $database, "--dry-run")
    Assert-True $dryRun.success "Catalog index missing dry-run failed: $($dryRun.message)"
    Assert-True (-not $dryRun.mutationAttempted) "Catalog index dry-run should not mutate."
    Assert-True (@($dryRun.missingSessionPaths).Count -eq 1) "Catalog index dry-run should report one missing row."
    Assert-True (Test-Path -LiteralPath $validPath) "Catalog index dry-run mutated existing .knapm data."

    $postDryQuery = Invoke-HelperJson -HelperPath $helperPath -Arguments @("catalog-index-query", "--database", $database, "--limit", "100")
    Assert-True ($postDryQuery.sessionCount -eq $build.sessionCount) "Catalog index dry-run changed DB row count."

    $removed = Invoke-HelperJson -HelperPath $helperPath -Arguments @("catalog-index-remove-missing", "--database", $database)
    Assert-True $removed.success "Catalog index missing removal failed: $($removed.message)"
    Assert-True $removed.mutationAttempted "Catalog index removal should report mutation attempted."
    Assert-True (@($removed.missingSessionPaths).Count -eq 1) "Catalog index removal should report one missing row."
    Assert-True ($removed.sessionCount -eq ($build.sessionCount - 1)) "Catalog index removal should delete only the missing DB row."
    Assert-True (Test-Path -LiteralPath $validPath) "Catalog index removal mutated existing .knapm data."

    $badDatabase = Join-Path $root "not-sqlite.db"
    Set-Content -LiteralPath $badDatabase -Value "not sqlite" -Encoding ASCII
    $badQuery = Invoke-HelperJson -HelperPath $helperPath -Arguments @("catalog-index-query", "--database", $badDatabase)
    Assert-True (-not $badQuery.success) "Malformed catalog index DB should fail."
    Assert-True (-not [string]::IsNullOrWhiteSpace($badQuery.message)) "Malformed catalog index DB should return a typed message."

    $unsupportedDatabase = Join-Path $root "unsupported-schema.db"
    $unsupportedBuild = Invoke-HelperJson -HelperPath $helperPath -Arguments @("catalog-index-build", "--root", $fixtureRoot, "--database", $unsupportedDatabase, "--rebuild")
    Assert-True $unsupportedBuild.success "Unsupported schema setup build failed: $($unsupportedBuild.message)"
    Set-UnsupportedSchemaVersion -DatabasePath $unsupportedDatabase
    $unsupportedQuery = Invoke-HelperJson -HelperPath $helperPath -Arguments @("catalog-index-query", "--database", $unsupportedDatabase)
    Assert-True (-not $unsupportedQuery.success) "Unsupported catalog index schema should fail."
    Assert-True ($unsupportedQuery.message -match "unsupported catalog index schema version") "Unsupported schema error message mismatch: $($unsupportedQuery.message)"

    Write-Output "Catalog index smoke passed: built=$($build.sessionCount) validQuery=$(@($validQuery.sessions).Count) removed=$($removed.sessionCount)"
}
finally
{
    if (Test-Path -LiteralPath $root)
    {
        Remove-Item -Recurse -Force -LiteralPath $root -ErrorAction SilentlyContinue
    }
}
