[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Package, [switch]$VerifyOnly)
$ErrorActionPreference = 'Stop'
# This script is invoked from the protected installed release, never from the
# incoming package. It accepts local package paths only, never download URLs.
$common = Join-Path $PSScriptRoot 'deployment-common.ps1'
. $common
Assert-Administrator
$deploymentPath = Join-Path $DataRoot 'deployment.json'
$previous = Get-Content -LiteralPath $deploymentPath -Raw | ConvertFrom-Json
$component = if ($previous.PSObject.Properties.Name -contains 'component') { [string]$previous.component } else { 'suite' }
$manifest = Read-Release $Package $previous.publisher_thumbprint (Join-Path $InstallRoot 'publisher.cer') -Component $component
if ([version]$manifest.version -le [version]$previous.version) { throw 'Updates must increase version. A binary downgrade without its matching state snapshot is forbidden.' }
if ([int]$previous.data_schema -lt [int]$manifest.min_data_schema -or [int]$previous.data_schema -gt [int]$manifest.max_data_schema -or [int]$manifest.api -ne [int]$previous.api) { throw 'Incompatible API/state schema; update refused before stopping any service.' }
if ($VerifyOnly) { Write-Output "Verified signed coherent release $($manifest.version); current schema compatible."; exit 0 }
$updateId = [Guid]::NewGuid().ToString('N')
$recoveryRoot = Join-Path $env:ProgramData 'RDPMonitorRecovery'
# Recovery snapshots are outside the mutable tree so they cannot recursively copy
# themselves. They include DB/WAL, configs, secrets, backup state and identity.
Set-ProtectedDirectory $recoveryRoot
$recovery = Join-Path $recoveryRoot $updateId
Set-ProtectedDirectory $recovery
$destination = Join-Path $InstallRoot ('releases\' + $manifest.version)
if (Test-Path -LiteralPath $destination) { throw 'Target release already exists. Refusing to overwrite a prior release.' }
Copy-ProtectedRelease $Package $destination
$manifest = Read-Release $destination $previous.publisher_thumbprint (Join-Path $InstallRoot 'publisher.cer') -Component $component
$agent = Join-Path $destination 'agent\RDPMonitorAgent.exe'
Invoke-Checked $agent @('verify-installation')
$state = [ordered]@{ id=$updateId; state='stopping'; previous_version=$previous.version; target_version=$manifest.version; previous_release=$previous.release; target_release=$destination; snapshot=$recovery; started_utc=[DateTime]::UtcNow.ToString('o') }
function Save-UpdateState { $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $DataRoot 'update-state.json') -Encoding UTF8 }
Save-UpdateState
Stop-AgentServices
$hasSnapshot = $false
try {
    Assert-NoReparse $DataRoot
    Copy-Item -LiteralPath $DataRoot -Destination (Join-Path $recovery 'data') -Recurse
    Invoke-Checked 'icacls.exe' @($recovery,'/setowner','*S-1-5-32-544','/T','/C')
    $snapshotFiles = @()
    foreach ($file in Get-ChildItem -LiteralPath (Join-Path $recovery 'data') -Recurse -File -Force) {
        $snapshotFiles += @{ path=$file.FullName.Substring((Join-Path $recovery 'data').Length).TrimStart('\'); sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash }
    }
    $snapshotFiles | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $recovery 'snapshot.json') -Encoding UTF8
    $hasSnapshot = $true
    $state.state = 'activating'; Save-UpdateState
    $next = $previous | Select-Object *
    $next.version = $manifest.version; $next.release = $destination; $next.data_schema = [int]$manifest.data_schema
    Save-Deployment $next
    Invoke-Checked $agent @('service-register')
    # Keep firewall scope unchanged, but the Program rule must target the new
    # signed immutable executable. No RDP/panic/block rules are modified.
    Set-OwnedGatewayProgram $previous $agent
    Start-AgentServices
    # SCM Running is not application readiness. The local authenticated IPC health
    # command must prove both worker and gateway are serving before committing.
    Wait-AgentReady $agent $next
    $state.state = 'committed'; $state.completed_utc = [DateTime]::UtcNow.ToString('o'); Save-UpdateState
    Write-Output "Updated coherent $component release to $($manifest.version); protected rollback snapshot $recovery"
} catch {
    $failure = $_
    Stop-AgentServices
    if (-not $hasSnapshot) {
        $state.state = 'snapshot-failed'; Save-UpdateState
        Start-AgentServices
        throw $failure
    }
    try {
        foreach ($entry in Get-Content -LiteralPath (Join-Path $recovery 'snapshot.json') -Raw | ConvertFrom-Json) {
            if ((Get-FileHash -LiteralPath (Join-Path (Join-Path $recovery 'data') $entry.path) -Algorithm SHA256).Hash -ne $entry.sha256) { throw 'Rollback snapshot hash mismatch; unsafe binary downgrade refused.' }
        }
        # Preserve failed new-version state separately for diagnostics; restore the
        # WHOLE matching snapshot before any older binary is permitted to run.
        Move-Item -LiteralPath $DataRoot -Destination (Join-Path $recovery 'failed-state')
        Copy-Item -LiteralPath (Join-Path $recovery 'data') -Destination $DataRoot -Recurse
        Set-ProtectedDirectory $DataRoot
        Save-Deployment $previous
        Invoke-Checked (Join-Path $previous.release 'agent\RDPMonitorAgent.exe') @('service-register')
        Set-OwnedGatewayProgram $previous (Join-Path $previous.release 'agent\RDPMonitorAgent.exe')
        Start-AgentServices
        $state.state = 'rolled-back'; Save-UpdateState
    } catch {
        Stop-AgentServices
        # Never start old code on an uncertain/migrated schema.
        throw "Update failed and rollback could not safely complete. Services stopped. Protected recovery: $recovery. Rollback error: $($_.Exception.Message)"
    }
    throw "Update failed; matching code AND state restored. Original error: $($failure.Exception.Message)"
}
