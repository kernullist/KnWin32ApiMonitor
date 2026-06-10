param(
    [string]$BuildDir = "build\native\Debug"
)

$ErrorActionPreference = "Stop"

function Wait-SampleReady
{
    param(
        [string]$OutputPath,
        [int]$TimeoutMs = 5000
    )

    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ([DateTime]::UtcNow -lt $deadline)
    {
        if ((Test-Path -LiteralPath $OutputPath) -and ((Get-Content -LiteralPath $OutputPath -Raw -ErrorAction SilentlyContinue) -match "attach-loop-ready"))
        {
            return
        }

        Start-Sleep -Milliseconds 100
    }

    throw "Sample target did not report attach-loop-ready."
}

function Copy-KnapmFixture
{
    param(
        [string]$Name,
        [string]$DestinationRoot
    )

    $source = Join-Path (Get-Location) "tests\fixtures\session\valid-knapm.knapm"
    $destination = Join-Path $DestinationRoot "$Name.knapm"
    Copy-Item -Path $source -Destination $destination -Recurse
    return $destination
}

function Read-Manifest
{
    param(
        [string]$SessionPath
    )

    return Get-Content -LiteralPath (Join-Path $SessionPath "manifest.json") -Raw | ConvertFrom-Json
}

function Write-Manifest
{
    param(
        [string]$SessionPath,
        [object]$Manifest
    )

    $json = $Manifest | ConvertTo-Json -Depth 32
    Set-Content -LiteralPath (Join-Path $SessionPath "manifest.json") -Value $json -Encoding UTF8
}

function Set-RunningOwnership
{
    param(
        [object]$Manifest,
        [int]$TargetPid,
        [int]$OwnerPid,
        [string]$LeaseExpiresUtc,
        [string]$RecoveryState,
        [string]$RecoveryReason,
        [string]$RecoveryAction,
        [bool]$OwnerAlive,
        [bool]$TargetAlive,
        [bool]$LeaseExpired,
        [bool]$RestartEligible
    )

    $Manifest.finalized = $false
    $Manifest.finalizedUtc = ""
    $Manifest.writerState = "writing"
    $Manifest.target.pid = $TargetPid
    $Manifest.session.targetProcessId = $TargetPid
    $Manifest.session.sessionState = "running"
    $Manifest.session.stoppedUtc = ""
    $Manifest.session.stopRequested = $false
    $Manifest.session.agentCleanupAttempted = $false
    $Manifest.session.agentCleanupSucceeded = $false
    $Manifest.owner.hostProcessId = $OwnerPid
    $Manifest.owner.helperProcessId = $OwnerPid
    $Manifest.owner.writerProcessId = $OwnerPid
    $Manifest.owner.writerInstanceId = "smoke-writer-$OwnerPid"
    $Manifest.owner.heartbeatUtc = "2026-06-10T00:00:01.000Z"
    $Manifest.owner.leaseExpiresUtc = $LeaseExpiresUtc
    $Manifest.recovery.state = $RecoveryState
    $Manifest.recovery.reason = $RecoveryReason
    $Manifest.recovery.action = $RecoveryAction
    $Manifest.recovery.ownerAlive = $OwnerAlive
    $Manifest.recovery.helperAlive = $OwnerAlive
    $Manifest.recovery.writerAlive = $OwnerAlive
    $Manifest.recovery.targetAlive = $TargetAlive
    $Manifest.recovery.leaseExpired = $LeaseExpired
    $Manifest.recovery.restartEligible = $RestartEligible
}

function Invoke-Validate
{
    param(
        [string]$HelperPath,
        [string]$SessionPath
    )

    return & $HelperPath validate-session --session $SessionPath | ConvertFrom-Json
}

function Assert-Recovery
{
    param(
        [object]$Result,
        [string]$ExpectedState,
        [string]$ExpectedReason,
        [string]$Label
    )

    if (-not $Result.success)
    {
        throw "$Label validation failed: $($Result.validationErrors -join '; ')"
    }

    if ($Result.recoveryState -ne $ExpectedState -or $Result.recoveryReason -ne $ExpectedReason)
    {
        throw "$Label recovery mismatch: state=$($Result.recoveryState) reason=$($Result.recoveryReason)"
    }
}

$helperPath = Join-Path $BuildDir "knmon-native-helper.exe"
$samplePath = Join-Path $BuildDir "knmon-sample-fileio.exe"

if (-not (Test-Path -LiteralPath $helperPath))
{
    throw "Helper not found: $helperPath"
}

if (-not (Test-Path -LiteralPath $samplePath))
{
    throw "Sample target not found: $samplePath"
}

$tmpDir = Join-Path (Get-Location) ".tmp"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$root = Join-Path $tmpDir "knapm-recovery-$([Guid]::NewGuid().ToString("N").Substring(0, 12))"
New-Item -ItemType Directory -Force -Path $root | Out-Null

$sampleStdout = Join-Path $root "sample.stdout.txt"
$sampleStderr = Join-Path $root "sample.stderr.txt"
$sample = Start-Process -FilePath $samplePath -ArgumentList "--attach-loop --iterations 500 --delay-ms 100" -RedirectStandardOutput $sampleStdout -RedirectStandardError $sampleStderr -PassThru -WindowStyle Hidden

$deadProcess = Start-Process -FilePath $env:ComSpec -ArgumentList "/c exit 0" -PassThru -WindowStyle Hidden
$deadProcess.WaitForExit()
$deadPid = $deadProcess.Id

try
{
    Wait-SampleReady -OutputPath $sampleStdout

    $finalizedPath = Copy-KnapmFixture -Name "finalized" -DestinationRoot $root
    $finalized = Invoke-Validate -HelperPath $helperPath -SessionPath $finalizedPath
    Assert-Recovery -Result $finalized -ExpectedState "none" -ExpectedReason "finalized" -Label "finalized"

    $ownedPath = Copy-KnapmFixture -Name "owned" -DestinationRoot $root
    $ownedManifest = Read-Manifest -SessionPath $ownedPath
    Set-RunningOwnership -Manifest $ownedManifest -TargetPid $sample.Id -OwnerPid $PID -LeaseExpiresUtc "2099-01-01T00:00:00.000Z" -RecoveryState "owned" -RecoveryReason "owner_alive" -RecoveryAction "wait" -OwnerAlive $true -TargetAlive $true -LeaseExpired $false -RestartEligible $false
    Write-Manifest -SessionPath $ownedPath -Manifest $ownedManifest
    $owned = Invoke-Validate -HelperPath $helperPath -SessionPath $ownedPath
    Assert-Recovery -Result $owned -ExpectedState "owned" -ExpectedReason "owner_alive" -Label "owned"

    $stalePath = Copy-KnapmFixture -Name "stale" -DestinationRoot $root
    $staleManifest = Read-Manifest -SessionPath $stalePath
    Set-RunningOwnership -Manifest $staleManifest -TargetPid $deadPid -OwnerPid $PID -LeaseExpiresUtc "2099-01-01T00:00:00.000Z" -RecoveryState "stale" -RecoveryReason "target_exited" -RecoveryAction "replay_only" -OwnerAlive $true -TargetAlive $false -LeaseExpired $false -RestartEligible $false
    Write-Manifest -SessionPath $stalePath -Manifest $staleManifest
    $stale = Invoke-Validate -HelperPath $helperPath -SessionPath $stalePath
    Assert-Recovery -Result $stale -ExpectedState "stale" -ExpectedReason "target_exited" -Label "stale"

    $recoveryPath = Copy-KnapmFixture -Name "recovery-required" -DestinationRoot $root
    $recoveryManifest = Read-Manifest -SessionPath $recoveryPath
    Set-RunningOwnership -Manifest $recoveryManifest -TargetPid $sample.Id -OwnerPid $deadPid -LeaseExpiresUtc "2099-01-01T00:00:00.000Z" -RecoveryState "recovery_required" -RecoveryReason "owner_dead_target_alive" -RecoveryAction "recover_writer" -OwnerAlive $false -TargetAlive $true -LeaseExpired $false -RestartEligible $true
    Write-Manifest -SessionPath $recoveryPath -Manifest $recoveryManifest
    $recovery = Invoke-Validate -HelperPath $helperPath -SessionPath $recoveryPath
    Assert-Recovery -Result $recovery -ExpectedState "recovery_required" -ExpectedReason "owner_dead_target_alive" -Label "recovery-required"

    $leasePath = Copy-KnapmFixture -Name "lease-expired" -DestinationRoot $root
    $leaseManifest = Read-Manifest -SessionPath $leasePath
    Set-RunningOwnership -Manifest $leaseManifest -TargetPid $sample.Id -OwnerPid $PID -LeaseExpiresUtc "2000-01-01T00:00:00.000Z" -RecoveryState "recovery_required" -RecoveryReason "lease_expired" -RecoveryAction "recover_writer" -OwnerAlive $true -TargetAlive $true -LeaseExpired $true -RestartEligible $true
    Write-Manifest -SessionPath $leasePath -Manifest $leaseManifest
    $lease = Invoke-Validate -HelperPath $helperPath -SessionPath $leasePath
    Assert-Recovery -Result $lease -ExpectedState "recovery_required" -ExpectedReason "lease_expired" -Label "lease-expired"

    if ($sample.HasExited)
    {
        throw "Validation mutated or terminated the live sample target."
    }

    Write-Output "x64 KNAPM recovery ownership smoke passed: finalized=$($finalized.recoveryState) owned=$($owned.recoveryState) stale=$($stale.recoveryState) recovery=$($recovery.recoveryReason) lease=$($lease.recoveryReason) targetAlive=$(-not $sample.HasExited)"
}
finally
{
    if ($sample -ne $null -and -not $sample.HasExited)
    {
        Stop-Process -Id $sample.Id -Force -ErrorAction SilentlyContinue
    }
}
