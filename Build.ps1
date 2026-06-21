param(
    [switch]$Release,

    [switch]$SkipUi,

    [switch]$SkipNative,

    [switch]$Win32,

    [switch]$Clean
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

function Read-KnMonVersion
{
    if (!(Test-Path -LiteralPath $versionPath))
    {
        throw "VERSION file is missing: $versionPath"
    }

    $text = (Get-Content -LiteralPath $versionPath -Raw).Trim()
    if ($text -notmatch '^(\d+)\.(\d+)\.(\d+)\.(\d+)$')
    {
        throw "VERSION must use MAJOR.MINOR.PATCH.BUILD numeric format. Current value: $text"
    }

    return [ordered]@{
        Text = $text
        Major = [int]$Matches[1]
        Minor = [int]$Matches[2]
        Patch = [int]$Matches[3]
        Build = [int]$Matches[4]
    }
}

function Write-KnMonVersion
{
    param(
        [string]$Version
    )

    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($versionPath, "$Version`r`n", $utf8NoBom)
}

function Increment-KnMonBuildVersion
{
    $version = Read-KnMonVersion
    $nextBuild = $version.Build + 1
    $nextVersion = "$($version.Major).$($version.Minor).$($version.Patch).$nextBuild"
    Write-KnMonVersion -Version $nextVersion
    return $nextVersion
}

function Invoke-Checked
{
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )

    Write-Host "> $FilePath $($Arguments -join ' ')"
    & $FilePath @Arguments

    if ($LASTEXITCODE -ne 0)
    {
        throw "$FilePath failed with exit code $LASTEXITCODE"
    }
}

$configuration = if ($Release) { "Release" } else { "Debug" }
$versionText = if ($Release) { Increment-KnMonBuildVersion } else { (Read-KnMonVersion).Text }

Write-Host "KN Win32 API Monitor build"
Write-Host "Configuration: $configuration"
Write-Host "Version: $versionText"

$nativeBuildDirName = if ($Win32) { "native-win32" } else { "native" }
$nativeBuildDir = Join-Path $repoRoot "build\$nativeBuildDirName"

if ($Clean)
{
    Assert-PathInsideRepo -Path $nativeBuildDir
    if (Test-Path -LiteralPath $nativeBuildDir)
    {
        Remove-Item -LiteralPath $nativeBuildDir -Recurse -Force
    }
}

Push-Location $repoRoot
try
{
    if (!$SkipNative)
    {
        $configureArgs = @("-S", "native", "-B", $nativeBuildDir)
        if ($Win32)
        {
            $configureArgs += @("-A", "Win32")
        }

        Invoke-Checked -FilePath "cmake" -Arguments $configureArgs
        Invoke-Checked -FilePath "cmake" -Arguments @("--build", $nativeBuildDir, "--config", $configuration)
    }

    if (!$SkipUi)
    {
        Invoke-Checked -FilePath "npm.cmd" -Arguments @("run", "build")
    }
}
finally
{
    Pop-Location
}

Write-Host "Build completed. version=$versionText configuration=$configuration"
