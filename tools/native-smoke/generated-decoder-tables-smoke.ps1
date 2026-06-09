param(
    [string]$HelperPath = "build\native\Debug\knmon-native-helper.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $HelperPath))
{
    throw "Helper not found: $HelperPath"
}

npm run defs:decoder-tables | Out-Host

$result = & $HelperPath capture-sample | ConvertFrom-Json

if (-not $result.success)
{
    throw "Generated decoder capture failed: $($result.operation): $($result.message)"
}

$createFile = @($result.capturedEvents | Where-Object { $_.api -eq "CreateFileW" } | Select-Object -First 1)
if ($createFile.Count -ne 1)
{
    throw "Generated decoder smoke did not capture CreateFileW."
}

if ($createFile[0].apiFamily -ne "file-io" -or $createFile[0].apiCategory -ne "file_open")
{
    throw "CreateFileW generated API metadata missing: family=$($createFile[0].apiFamily) category=$($createFile[0].apiCategory)"
}

if ($createFile[0].hookPolicy -ne "iat" -or $createFile[0].coverageStatus -ne "smoke_verified")
{
    throw "CreateFileW generated hook metadata mismatch: hook=$($createFile[0].hookPolicy) coverage=$($createFile[0].coverageStatus)"
}

$fileName = @($createFile[0].arguments | Where-Object { $_.name -eq "lpFileName" } | Select-Object -First 1)
if ($fileName.Count -ne 1)
{
    throw "CreateFileW generated parameter name was not rendered."
}

if ($fileName[0].decodeAlias -ne "utf16_string" -or $fileName[0].captureTiming -ne "pre")
{
    throw "CreateFileW generated parameter metadata mismatch: decode=$($fileName[0].decodeAlias) timing=$($fileName[0].captureTiming)"
}

$ntCreate = @($result.capturedEvents | Where-Object { $_.api -eq "NtCreateFile" } | Select-Object -First 1)
if ($ntCreate.Count -ne 1)
{
    throw "Generated decoder smoke did not capture NtCreateFile."
}

$objectAttributes = @($ntCreate[0].arguments | Where-Object { $_.name -eq "ObjectAttributes" } | Select-Object -First 1)
if ($objectAttributes.Count -ne 1)
{
    throw "NtCreateFile generated parameter name was not rendered."
}

if ($objectAttributes[0].decodeAlias -ne "object_attributes")
{
    throw "NtCreateFile ObjectAttributes decode alias mismatch: $($objectAttributes[0].decodeAlias)"
}

$resolver = @($result.capturedEvents | Where-Object { $_.api -eq "GetProcAddress" } | Select-Object -First 1)
if ($resolver.Count -ne 1)
{
    throw "Generated decoder smoke did not capture GetProcAddress."
}

if ($resolver[0].apiFamily -ne "resolver" -or $resolver[0].apiCategory -ne "dynamic_symbol_lookup")
{
    throw "GetProcAddress generated resolver metadata missing: family=$($resolver[0].apiFamily) category=$($resolver[0].apiCategory)"
}

Write-Host "Generated decoder tables smoke passed: events=$($result.capturedEvents.Count) createFileDecode=$($fileName[0].decodeAlias) resolverCategory=$($resolver[0].apiCategory)"
