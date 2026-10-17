[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Check','Configure','Remove')][string]$Action,
    [Parameter(Mandatory=$true)][ValidateRange(1024,65535)][int]$Port,
    [Parameter(Mandatory=$true)][string]$Source,
    [string]$Program,
    [switch]$Existing
)
$ErrorActionPreference = 'Stop'
# Exactly one literal source. Never broaden scope to repair connectivity.
$ip = $null
if (-not [Net.IPAddress]::TryParse($Source,[ref]$ip) -or $ip.ToString() -cne $Source -or $Source -in @('0.0.0.0','::') -or $Source.Contains('%')) { throw 'A single canonical source IP is required.' }
$bytes = $ip.GetAddressBytes()
if (($bytes.Length -eq 4 -and $bytes[0] -ge 224) -or ($bytes.Length -eq 16 -and $bytes[0] -eq 255)) { throw 'Multicast sources are forbidden.' }
Import-Module NetSecurity -ErrorAction Stop
$service = Get-Service -Name MpsSvc
if ($service.Status -ne 'Running') { throw 'Windows Defender Firewall must be running.' }
if ($Action -ne 'Remove') {
    # Use effective COM values: NetSecurity can report NotConfigured even when
    # the effective default is Block. Never change unrelated profile policy.
    $policy = New-Object -ComObject HNetCfg.FwPolicy2
    try {
        foreach ($profileType in @(1,2,4)) {
            if (-not $policy.FirewallEnabled($profileType) -or [int]$policy.DefaultInboundAction($profileType) -ne 0) {
                throw 'Direct monitoring requires enabled firewall profiles with effective default inbound Block.'
            }
            if ($policy.BlockAllInboundTraffic($profileType)) {
                throw 'An effective block-all-inbound policy prevents the approved direct rule.'
            }
        }
    } finally {
        if ([Runtime.InteropServices.Marshal]::IsComObject($policy)) {
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($policy)
        }
    }
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    if ($profiles.Count -ne 3) { throw 'Cannot verify all effective firewall profiles.' }
    foreach ($profile in $profiles) {
        if ([string]$profile.AllowInboundRules -eq 'False' -or [string]$profile.AllowLocalFirewallRules -eq 'False') {
            throw 'Effective policy does not permit the local direct firewall rule.'
        }
    }
}
$name = 'RDPMonitor-Gateway-Direct'
$rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { $_.Name -eq $name })
if ($rules.Count -gt 1 -or ($rules.Count -and -not $Existing)) { throw 'An existing direct rule requires explicit retained-deployment maintenance.' }
if ($rules.Count) {
    $rule = $rules[0]
    $ports = @($rule | Get-NetFirewallPortFilter)
    $addresses = @($rule | Get-NetFirewallAddressFilter)
    $apps = @($rule | Get-NetFirewallApplicationFilter)
    $interfaces = @($rule | Get-NetFirewallInterfaceFilter)
    if ($rule.Group -cne 'RDPMonitor Direct' -or [string]$rule.Direction -ne 'Inbound' -or [string]$rule.Action -ne 'Allow' -or
        [string]$rule.Profile -ne 'Any' -or [string]$rule.Enabled -ne 'True' -or $ports.Count -ne 1 -or
        [string]$ports[0].Protocol -notin @('TCP','6') -or @($ports[0].LocalPort).Count -ne 1 -or [string]$ports[0].LocalPort -ne [string]$Port -or
        $addresses.Count -ne 1 -or @($addresses[0].RemoteAddress).Count -ne 1 -or [string]$addresses[0].RemoteAddress -cne $Source -or
        @($addresses[0].LocalAddress).Count -ne 1 -or [string]$addresses[0].LocalAddress -ne 'Any' -or
        $interfaces.Count -ne 1 -or [string]$interfaces[0].InterfaceAlias -ne 'Any' -or $apps.Count -ne 1 -or
        -not $apps[0].Program -or [string]$apps[0].Program -eq 'Any') { throw 'The retained direct firewall rule does not match its owned single-source scope.' }
}
if ($Action -eq 'Check') { return }
if ($Action -eq 'Remove') {
    if (-not $Existing) { throw 'Removal requires an installed deployment.' }
    if ($rules.Count) { $rules[0] | Remove-NetFirewallRule }
    return
}
if (-not $Program -or -not [IO.Path]::IsPathRooted($Program) -or -not (Test-Path -LiteralPath $Program -PathType Leaf)) { throw 'An installed executable is required.' }
if ($rules.Count) {
    # Repair/update changes only the executable, never remote addresses or profiles.
    $rules[0] | Set-NetFirewallRule -Program $Program | Out-Null
} else {
    # All local profiles deliberately includes a VM classified Public; source is still one IP.
    New-NetFirewallRule -Name $name -DisplayName 'RDPMonitor direct monitoring (one approved desktop)' -Group 'RDPMonitor Direct' -PolicyStore PersistentStore -Direction Inbound -Action Allow -Enabled True -Protocol TCP -LocalPort $Port -RemoteAddress $Source -Profile Any -Program $Program -EdgeTraversalPolicy Block | Out-Null
}
