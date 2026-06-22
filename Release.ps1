param(
    [ValidateSet("Debug", "Release", "RelWithDebInfo", "MinSizeRel")]
    [string]$Configuration = "Release",

    [string]$OutputDir = "dist\release",

    [switch]$IncludeWin32,

    [switch]$NoUi,

    [switch]$Overwrite
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$versionPath = Join-Path $repoRoot "VERSION"

function Get-FullPath
{
    param(
        [string]$Path
    )

    return [System.IO.Path]::GetFullPath($Path)
}

function Assert-PathInsideRepo
{
    param(
        [string]$Path
    )

    $fullPath = Get-FullPath -Path $Path
    $fullRepo = Get-FullPath -Path $repoRoot

    if (!$fullPath.StartsWith($fullRepo, [System.StringComparison]::OrdinalIgnoreCase))
    {
        throw "Refusing to operate outside repository: $fullPath"
    }
}

function Read-KnMonVersionText
{
    if (!(Test-Path -LiteralPath $versionPath))
    {
        throw "VERSION file is missing: $versionPath"
    }

    $text = (Get-Content -LiteralPath $versionPath -Raw).Trim()
    if ($text -notmatch '^\d+\.\d+\.\d+\.\d+$')
    {
        throw "VERSION must use MAJOR.MINOR.PATCH.BUILD numeric format. Current value: $text"
    }

    return $text
}

function Copy-FileSet
{
    param(
        [string]$SourceDir,
        [string]$DestinationDir,
        [string[]]$Extensions
    )

    if (!(Test-Path -LiteralPath $SourceDir))
    {
        throw "Required build output directory is missing: $SourceDir"
    }

    New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null

    $files = @(Get-ChildItem -LiteralPath $SourceDir -File | Where-Object { $Extensions -contains $_.Extension.ToLowerInvariant() })
    if ($files.Count -eq 0)
    {
        throw "No release files found in $SourceDir"
    }

    foreach ($file in $files)
    {
        Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $DestinationDir $file.Name) -Force
    }

    return $files.Count
}

function Copy-DirectoryIfPresent
{
    param(
        [string]$SourceDir,
        [string]$DestinationDir
    )

    if (Test-Path -LiteralPath $SourceDir)
    {
        New-Item -ItemType Directory -Path (Split-Path -Parent $DestinationDir) -Force | Out-Null
        Copy-Item -LiteralPath $SourceDir -Destination $DestinationDir -Recurse -Force
        return $true
    }

    return $false
}

$version = Read-KnMonVersionText
$outputRoot = Join-Path $repoRoot $OutputDir
$packageName = "KnWin32ApiMonitor-$version-$Configuration"
$stageRoot = Join-Path $repoRoot ".tmp\release\$packageName"
$zipPath = Join-Path $outputRoot "$packageName.zip"

Assert-PathInsideRepo -Path $outputRoot
Assert-PathInsideRepo -Path $stageRoot

if (Test-Path -LiteralPath $stageRoot)
{
    Remove-Item -LiteralPath $stageRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null

if (Test-Path -LiteralPath $zipPath)
{
    if (!$Overwrite)
    {
        throw "Release zip already exists: $zipPath. Use -Overwrite to replace it."
    }

    Remove-Item -LiteralPath $zipPath -Force
}

$x64Dir = Join-Path $repoRoot "build\native\$Configuration"
$x64Count = Copy-FileSet -SourceDir $x64Dir -DestinationDir $stageRoot -Extensions @(".exe", ".dll")

$win32Count = 0
if ($IncludeWin32)
{
    $win32Dir = Join-Path $repoRoot "build\native-win32\$Configuration"
    $win32Count = Copy-FileSet -SourceDir $win32Dir -DestinationDir (Join-Path $stageRoot "win32") -Extensions @(".exe", ".dll")
}

$uiCopied = $false
if (!$NoUi)
{
    $uiCopied = Copy-DirectoryIfPresent -SourceDir (Join-Path $repoRoot "apps\knmon-ui\dist") -DestinationDir (Join-Path $stageRoot "ui")
}

$tauriCopied = $false
if (!$NoUi)
{
    $tauriReleaseDir = Join-Path $repoRoot "apps\knmon-ui\src-tauri\target\release"
    if (Test-Path -LiteralPath $tauriReleaseDir)
    {
        $tauriExeFiles = @(Get-ChildItem -LiteralPath $tauriReleaseDir -File -Filter "*.exe")
        if ($tauriExeFiles.Count -gt 0)
        {
            $tauriDestination = $stageRoot
            New-Item -ItemType Directory -Path $tauriDestination -Force | Out-Null

            foreach ($file in $tauriExeFiles)
            {
                Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $tauriDestination $file.Name) -Force
            }

            $tauriCopied = $true
        }

        $bundleCopied = Copy-DirectoryIfPresent -SourceDir (Join-Path $tauriReleaseDir "bundle") -DestinationDir (Join-Path $stageRoot "bundle")
        $tauriCopied = $tauriCopied -or $bundleCopied
    }
}

Copy-Item -LiteralPath (Join-Path $repoRoot "README.md") -Destination (Join-Path $stageRoot "README.md") -Force
Copy-Item -LiteralPath (Join-Path $repoRoot "LICENSE") -Destination (Join-Path $stageRoot "LICENSE") -Force
Copy-Item -LiteralPath $versionPath -Destination (Join-Path $stageRoot "VERSION") -Force

$buildInfo = [ordered]@{
    product = "KN Win32 API Monitor"
    version = $version
    configuration = $Configuration
    createdAt = (Get-Date).ToUniversalTime().ToString("o")
    nativeX64Files = $x64Count
    nativeWin32Files = $win32Count
    layout = "portable-flat"
    entryPoint = "knmon-ui.exe"
    uiIncluded = $uiCopied
    tauriIncluded = $tauriCopied
}

$buildInfo | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stageRoot "BUILD-INFO.json") -Encoding UTF8

Get-ChildItem -LiteralPath $stageRoot | Compress-Archive -DestinationPath $zipPath -Force

Write-Host "Release package created: $zipPath"
