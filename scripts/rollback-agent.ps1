[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$UpdateId, [Parameter(Mandatory=$true)][string]$ConfirmRollback)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'deployment-common.ps1')
Assert-Administrator
if ($UpdateId -notmatch '^[0-9a-f]{32}$' -or $ConfirmRollback -cne 'RESTORE CODE AND STATE') { throw 'Specify the exact update ID and -ConfirmRollback "RESTORE CODE AND STATE". All post-update data, device revocations and config edits will revert.' }
$current = Get-Content -LiteralPath (Join-Path $DataRoot 'deployment.json') -Raw | ConvertFrom-Json
$state = Get-Content -LiteralPath (Join-Path $DataRoot 'update-state.json') -Raw | ConvertFrom-Json
if ($state.id -ne $UpdateId -or $state.state -ne 'committed' -or $state.target_version -ne $current.version) { throw 'Rollback is permitted only for the current committed update and its exact state snapshot.' }
$recovery = Join-Path (Join-Path $env:ProgramData 'RDPMonitorRecovery') $UpdateId
Assert-NoReparse $recovery
$snapshot = Join-Path $recovery 'data'
$previous = Get-Content -LiteralPath (Join-Path $snapshot 'deployment.json') -Raw | ConvertFrom-Json
$release = Read-Release $previous.release $current.publisher_thumbprint (Join-Path $InstallRoot 'publisher.cer')
if ([int]$previous.data_schema -lt [int]$release.min_data_schema -or [int]$previous.data_schema -gt [int]$release.max_data_schema) { throw 'Saved state is incompatible with previous release; binary downgrade refused.' }
foreach ($entry in Get-Content -LiteralPath (Join-Path $recovery 'snapshot.json') -Raw | ConvertFrom-Json) {
    if ($entry.path -match '(^[\\/]|:|(^|[\\/])\.\.([\\/]|$))') { throw 'Unsafe snapshot path.' }
    if ((Get-FileHash -LiteralPath (Join-Path $snapshot $entry.path) -Algorithm SHA256).Hash -ne $entry.sha256) { throw 'Rollback snapshot checksum mismatch.' }
}
Stop-AgentServices
try {
    $failed = Join-Path $recovery ('superseded-state-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
    Move-Item -LiteralPath $DataRoot -Destination $failed
    Copy-Item -LiteralPath $snapshot -Destination $DataRoot -Recurse
    Set-ProtectedDirectory $DataRoot
    Save-Deployment $previous
    $agent = Join-Path $previous.release 'agent\RDPMonitorAgent.exe'
    Invoke-Checked $agent @('service-register')
    if ($previous.scope -eq 'Private') { Set-NetFirewallRule -Name 'RDPMonitor-Gateway-Private' -Program $agent }
    Start-AgentServices
    Invoke-Checked $agent @('status','--data-dir',$DataRoot,'--require-gateway','--host',$previous.host,'--port',([string]$previous.port))
    $state.state = 'manually-rolled-back'
    $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $DataRoot 'update-state.json') -Encoding UTF8
    Write-Output 'Matching code and complete state restored. Review revocations/enrollment and changes since the snapshot. Firewall protection rules were not removed.'
} catch {
    Stop-AgentServices
    throw "Rollback did not complete. Services deliberately stopped; preserve recovery directory $recovery. $($_.Exception.Message)"
}
