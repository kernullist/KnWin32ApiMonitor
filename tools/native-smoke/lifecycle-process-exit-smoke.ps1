param(
    [string]$BuildDir = 'build\native-msvc\Debug'
)

$ErrorActionPreference = 'Stop'
$helper = Join-Path $BuildDir 'knmon-native-helper.exe'
$samplePath = Join-Path $BuildDir 'knmon-sample-fileio.exe'
$evidence = Join-Path (Get-Location) ('build\lifecycle-exit-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $evidence | Out-Null

foreach ($forceExit in @($false, $true))
{
    $tag = if ($forceExit) { 'forced' } else { 'natural' }
    $sampleOut = Join-Path $evidence ($tag + '-sample.txt')
    $captureOut = Join-Path $evidence ($tag + '-capture.json')
    $iterations = if ($forceExit) { 500 } else { 18 }
    $sample = Start-Process -FilePath $samplePath -ArgumentList "--attach-loop --iterations $iterations --delay-ms 80" -WindowStyle Hidden -PassThru -RedirectStandardOutput $sampleOut
    $capture = $null
    try
    {
        $deadline = [DateTime]::UtcNow.AddSeconds(5)
        while ([DateTime]::UtcNow -lt $deadline)
        {
            if ((Test-Path -LiteralPath $sampleOut) -and ((Get-Content -LiteralPath $sampleOut -Raw) -match 'attach-loop-ready'))
            {
                break
            }
            Start-Sleep -Milliseconds 50
        }
        $capture = Start-Process -FilePath $helper -ArgumentList @('attach-capture', '--pid', $sample.Id, '--duration-ms', '6000', '--timeout-ms', '5000', '--api-selection', 'kernel32.dll!ReadFile') -WindowStyle Hidden -PassThru -RedirectStandardOutput $captureOut
        if ($forceExit)
        {
            $loaded = $false
            $deadline = [DateTime]::UtcNow.AddSeconds(5)
            while ([DateTime]::UtcNow -lt $deadline)
            {
                $sample.Refresh()
                if (@($sample.Modules | Where-Object { $_.ModuleName -match '^knmon-agent(32|64)\.dll$' }).Count -ne 0)
                {
                    $loaded = $true
                    break
                }
                Start-Sleep -Milliseconds 50
            }
            if (!$loaded)
            {
                throw 'Agent did not load before forced exit.'
            }
            Start-Sleep -Milliseconds 250
            Stop-Process -Id $sample.Id -Force
        }
        if (!$capture.WaitForExit(15000))
        {
            throw 'Capture did not finish after target exit.'
        }
        $result = Get-Content -LiteralPath $captureOut -Raw | ConvertFrom-Json
        if ($result.operation -ne 'target_exited' -or $result.hookCleanupOutcome -ne 'released_by_process_exit' -or $result.agentCleanupSucceeded)
        {
            throw "Exit cleanup evidence mismatch: $($result.operation) / $($result.message)"
        }
        if (@($result.agentMessages | Where-Object { $_.messageType -eq 'agent_shutdown' }).Count -ne 0)
        {
            throw 'Process exit fabricated agent restoration evidence.'
        }
        if (!$forceExit -and (!$result.success -or $result.sessionState -ne 'stopped' -or $result.targetExitCode -ne 0))
        {
            throw 'Natural target exit was not finalized consistently.'
        }
        if ($forceExit -and ($result.success -or $result.sessionState -ne 'failed' -or $result.targetExitCode -eq 0))
        {
            throw 'Abnormal target exit did not retain its failure code.'
        }
        Write-Output "Lifecycle $tag exit passed: architecture=$($result.architecture) events=$(@($result.capturedEvents).Count) outcome=$($result.hookCleanupOutcome)"
    }
    finally
    {
        if ($capture -ne $null -and !$capture.HasExited)
        {
            Stop-Process -Id $capture.Id -Force -ErrorAction SilentlyContinue
        }
        if (!$sample.HasExited)
        {
            Stop-Process -Id $sample.Id -Force -ErrorAction SilentlyContinue
        }
    }
}
