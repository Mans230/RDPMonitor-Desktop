param([Parameter(Mandatory=$true)][string]$Source, [Parameter(Mandatory=$true)][string]$Backup)
$ErrorActionPreference = 'Stop'
$Source = [IO.Path]::GetFullPath($Source).TrimEnd('\')
$Needles = @('rdp_suite.py','rdp_monitor.py','autostart.py','RDPWebConsole.py','backup\app\main.py')
function Is-Legacy([string]$Command) {
    if (-not $Command -or $Command.IndexOf($Source, [StringComparison]::OrdinalIgnoreCase) -lt 0) { return $false }
    foreach ($needle in $Needles) {
        if ($Command.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    return $false
}
$Tasks = @()
foreach ($task in Get-ScheduledTask) {
    $matching = $false
    foreach ($action in $task.Actions) {
        if (Is-Legacy ($action.Execute + ' ' + $action.Arguments + ' ' + $action.WorkingDirectory)) { $matching = $true }
    }
    if (-not $matching) { continue }
    $id = [Guid]::NewGuid().ToString('N')
    Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath | Set-Content -LiteralPath (Join-Path $Backup ($id + '.task.xml')) -Encoding Unicode
    $Tasks += @{ name=$task.TaskName; path=$task.TaskPath; snapshot=($id + '.task.xml') }
    Disable-ScheduledTask -InputObject $task | Out-Null
    if ($task.State -eq 'Running') { Stop-ScheduledTask -InputObject $task }
    Unregister-ScheduledTask -InputObject $task -Confirm:$false
}
$Tasks | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $Backup 'legacy-tasks.json') -Encoding UTF8
foreach ($process in Get-CimInstance Win32_Process) {
    if ($process.ProcessId -eq $PID -or -not (Is-Legacy $process.CommandLine)) { continue }
    Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
    Wait-Process -Id $process.ProcessId -Timeout 30 -ErrorAction SilentlyContinue
}
$remaining = @(Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $PID -and (Is-Legacy $_.CommandLine) })
if ($remaining.Count) { throw 'Legacy execution is still active; migration stopped without changing firewall policy.' }
# Only matching legacy Run entries are removed, and their values are backed up.
$Run = @()
foreach ($key in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run')) {
    if (-not (Test-Path $key)) { continue }
    $values = Get-ItemProperty -LiteralPath $key
    foreach ($property in $values.PSObject.Properties) {
        if ($property.Name -like 'PS*' -or -not ($property.Value -is [string])) { continue }
        if (Is-Legacy $property.Value) {
            $Run += @{ key=$key; name=$property.Name; value=$property.Value }
            Remove-ItemProperty -LiteralPath $key -Name $property.Name
        }
    }
}
$Run | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $Backup 'legacy-run.json') -Encoding UTF8
Write-Output 'Legacy execution stopped and saved; firewall policy was not modified.'
