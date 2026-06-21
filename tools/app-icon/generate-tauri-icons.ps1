param(
    [string]$MagickPath = "C:\Program Files\ImageMagick-7.1.1-Q16\magick.exe"
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$iconDir = Join-Path $repoRoot "apps\knmon-ui\src-tauri\icons"
$sourceSvg = Join-Path $iconDir "icon.svg"

if (-not (Test-Path -LiteralPath $MagickPath))
{
    throw "ImageMagick was not found: $MagickPath"
}

if (-not (Test-Path -LiteralPath $sourceSvg))
{
    throw "Icon source SVG was not found: $sourceSvg"
}

$sizes = @(16, 24, 32, 48, 64, 128, 256)
foreach ($size in $sizes)
{
    & $MagickPath -background none -density 384 $sourceSvg -resize "${size}x${size}" (Join-Path $iconDir "${size}x${size}.png")
    if ($LASTEXITCODE -ne 0)
    {
        throw "ImageMagick failed for ${size}x${size}."
    }
}

& $MagickPath -background none -density 384 $sourceSvg -resize "256x256" (Join-Path $iconDir "128x128@2x.png")
if ($LASTEXITCODE -ne 0)
{
    throw "ImageMagick failed for 128x128@2x.png."
}

& $MagickPath -background none -density 384 $sourceSvg -resize "512x512" (Join-Path $iconDir "icon.png")
if ($LASTEXITCODE -ne 0)
{
    throw "ImageMagick failed for icon.png."
}

$icoInputs = $sizes | ForEach-Object { Join-Path $iconDir "${_}x${_}.png" }
& $MagickPath @icoInputs (Join-Path $iconDir "icon.ico")
if ($LASTEXITCODE -ne 0)
{
    throw "ImageMagick failed for icon.ico."
}

Write-Output "Generated KN Win32 API Monitor app icons."
