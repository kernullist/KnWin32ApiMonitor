param(
    [string]$ExerciserPath = "build\native\Debug\knmon-api-exerciser.exe"
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

function Wait-ReadyFile
{
    param(
        [string]$ReadyPath,
        [int]$TimeoutMs = 5000
    )

    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ([DateTime]::UtcNow -lt $deadline)
    {
        if (Test-Path -LiteralPath $ReadyPath)
        {
            $body = Get-Content -LiteralPath $ReadyPath -Raw
            if ($body -match "program=knmon-api-exerciser" -and $body -match "mode=api-exerciser" -and $body -match "pid=\d+")
            {
                return $body
            }
        }

        Start-Sleep -Milliseconds 100
    }

    throw "API exerciser did not write a ready file."
}

Assert-True (Test-Path -LiteralPath $ExerciserPath) "API exerciser not found: $ExerciserPath"

$tmpDir = Join-Path (Get-Location) ".tmp"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null

$onceReady = Join-Path $tmpDir "api-exerciser-once.ready.txt"
Remove-Item -Force -ErrorAction SilentlyContinue $onceReady

$onceOutput = & $ExerciserPath --once --delay-ms 0 --startup-delay-ms 0 --ready-file $onceReady 2>&1
if ($LASTEXITCODE -ne 0)
{
    throw "API exerciser --once failed with exit code $LASTEXITCODE`n$($onceOutput -join "`n")"
}

$onceText = $onceOutput -join "`n"
Assert-True ($onceText -match "knmon-api-exerciser api-exerciser-ready") "API exerciser --once did not report ready."
Assert-True ($onceText -match "knmon-api-exerciser api-exerciser-summary iterations=1 failures=0") "API exerciser --once summary mismatch."
Assert-True ($onceText -match "file roundtrip bytes_written=") "API exerciser --once did not run the file probe."
Assert-True ($onceText -match "expected missing file error=") "API exerciser --once did not run error-path coverage."

$readyBody = Get-Content -LiteralPath $onceReady -Raw
Assert-True ($readyBody -match "program=knmon-api-exerciser") "API exerciser ready file program mismatch."

$loopReady = Join-Path $tmpDir "api-exerciser-loop.ready.txt"
$loopStdout = Join-Path $tmpDir "api-exerciser-loop.stdout.txt"
$loopStderr = Join-Path $tmpDir "api-exerciser-loop.stderr.txt"
Remove-Item -Force -ErrorAction SilentlyContinue $loopReady,$loopStdout,$loopStderr

$loopProcess = Start-Process `
    -FilePath $ExerciserPath `
    -ArgumentList @("--api-exerciser", "--duration-ms", "2500", "--delay-ms", "100", "--ready-file", $loopReady) `
    -RedirectStandardOutput $loopStdout `
    -RedirectStandardError $loopStderr `
    -WindowStyle Hidden `
    -PassThru

try
{
    Wait-ReadyFile -ReadyPath $loopReady | Out-Null
    Start-Sleep -Milliseconds 500
    Assert-True (-not $loopProcess.HasExited) "API exerciser loop exited before an attach window was available."

    $loopProcess.WaitForExit(8000) | Out-Null
    $loopProcess.Refresh()
    if (-not $loopProcess.HasExited)
    {
        throw "API exerciser loop did not exit after duration-ms."
    }

    # Windows PowerShell can leave Start-Process ExitCode empty after redirected runs.
    # The exerciser prints a deterministic summary, which is the stronger signal here.
}
finally
{
    if ($loopProcess -ne $null -and -not $loopProcess.HasExited)
    {
        Stop-Process -Id $loopProcess.Id -Force -ErrorAction SilentlyContinue
    }
}

$loopText = Get-Content -LiteralPath $loopStdout -Raw
Assert-True ($loopText -match "knmon-api-exerciser api-exerciser-ready") "API exerciser loop did not report ready."
Assert-True ($loopText -match "knmon-api-exerciser api-exerciser-summary iterations=\d+ failures=0 stopped=0 code=0") "API exerciser loop summary mismatch."

Write-Host "API exerciser smoke passed."
