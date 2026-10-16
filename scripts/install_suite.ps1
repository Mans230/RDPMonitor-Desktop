[CmdletBinding()]
param(
    [string]$Package = (Split-Path -Parent $PSScriptRoot),
    [string]$PublisherThumbprint,
    [ValidateSet('Local','Private')][string]$Scope = 'Local',
    [string]$ListenAddress = '127.0.0.1',
    [int]$Port = 8443,
    [string[]]$RemoteAddress,
    [string[]]$InterfaceAlias,
    [string]$MigrateFrom,
    [string]$OriginalAccount,
    [switch]$Repair,
    [switch]$Remove,
    [switch]$DeleteData,
    [string]$ConfirmDataDeletion
)
$ErrorActionPreference = 'Stop'
$knownDeployment = Join-Path $env:ProgramData 'RDPMonitor\deployment.json'
if (-not $PublisherThumbprint -and (Test-Path -LiteralPath $knownDeployment)) {
    $PublisherThumbprint = (Get-Content -LiteralPath $knownDeployment -Raw | ConvertFrom-Json).publisher_thumbprint
}
if (-not $PublisherThumbprint) { throw 'Supply -PublisherThumbprint from an independently authenticated release publisher certificate.' }
$common = Join-Path $PSScriptRoot 'deployment-common.ps1'
$signature = Get-AuthenticodeSignature -LiteralPath $common
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $PublisherThumbprint.Replace(' ','').ToUpperInvariant()) { throw 'Deployment helpers must have a valid Authenticode signature from the trusted publisher. Build/sign the release first.' }
. $common
Assert-Administrator
if (Test-Path -LiteralPath $InstallRoot) { Assert-NoReparse $InstallRoot }
if (Test-Path -LiteralPath $DataRoot) { Assert-NoReparse $DataRoot }
if ($Remove) {
    Stop-AgentServices
    foreach ($name in @('RDPMonitorGateway','RDPMonitorWorker')) {
        if (Get-Service $name -ErrorAction SilentlyContinue) { Invoke-Checked 'sc.exe' @('delete',$name) }
    }
    $shortcut = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\RDPMonitor.lnk'
    Remove-ItemProperty -LiteralPath 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'RDPMonitorSessionHelper' -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $shortcut -Force -ErrorAction SilentlyContinue
    # Retain a protected deployment record and publisher key for recovery. Firewall
    # rules (including RDP protection) and all backup repositories remain untouched.
    if ($DeleteData) {
        if ($ConfirmDataDeletion -cne 'DELETE RDPMonitor DATA') { throw 'Explicit -ConfirmDataDeletion "DELETE RDPMonitor DATA" is required.' }
        Remove-Item -LiteralPath $DataRoot -Recurse -Force
    }
    if (Test-Path (Join-Path $InstallRoot 'releases')) {
        try { Remove-Item -LiteralPath (Join-Path $InstallRoot 'releases') -Recurse -Force }
        catch {
            # An installed management executable may still be open. Schedule its
            # exact remaining files/directories for removal, never arbitrary paths.
            Add-Type -Namespace RDPMonitor -Name NativeDelete -MemberDefinition '[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet=System.Runtime.InteropServices.CharSet.Unicode, SetLastError=true)] public static extern bool MoveFileEx(string existing, string replacement, int flags);'
            $remaining = @(Get-ChildItem -LiteralPath (Join-Path $InstallRoot 'releases') -Force -Recurse | Sort-Object { $_.FullName.Length } -Descending)
            $remaining += Get-Item -LiteralPath (Join-Path $InstallRoot 'releases')
            foreach ($item in $remaining) { if (-not [RDPMonitor.NativeDelete]::MoveFileEx($item.FullName,$null,4)) { throw 'Unable to schedule locked release removal; close the client and rerun remove.' } }
            Write-Output 'Locked release files scheduled for deletion on reboot.'
        }
    }
    Write-Output 'Services/client removed. Firewall unchanged; data preserved unless explicitly deleted. Protected publisher/recovery files retained.'
    exit 0
}
if ($Repair) {
    if (-not (Test-Path -LiteralPath $knownDeployment)) { throw 'No installed deployment to repair.' }
    $deployment = Get-Content -LiteralPath $knownDeployment -Raw | ConvertFrom-Json
    $Package = $deployment.release
    $release = Read-Release $Package $deployment.publisher_thumbprint (Join-Path $InstallRoot 'publisher.cer')
    Stop-AgentServices
    Set-ProtectedDirectory $InstallRoot -Code
    Set-ProtectedDirectory $DataRoot
    Invoke-Checked (Join-Path $Package 'agent\RDPMonitorAgent.exe') @('service-register')
    Save-Deployment $deployment
    Start-AgentServices
    Wait-AgentReady (Join-Path $Package 'agent\RDPMonitorAgent.exe') $deployment
    Write-Output 'Verified release and repaired native service registration. Data/schedules/firewall settings preserved.'
    exit 0
}
if (Test-Path -LiteralPath $knownDeployment) { throw 'Use update-agent.ps1 for an installed deployment, or -Repair; install never overwrites live state.' }
if ($Port -lt 1024 -or $Port -gt 65535) { throw 'Choose an explicit administration port from 1024 through 65535.' }
if ($Scope -eq 'Local') {
    if ($ListenAddress -notin @('127.0.0.1','::1')) { throw 'Local scope only permits a loopback listener.' }
    if ($RemoteAddress -or $InterfaceAlias) { throw 'Remote firewall settings require explicit -Scope Private.' }
} else {
    if (-not $RemoteAddress -or -not $InterfaceAlias) { throw 'Private scope requires explicit -RemoteAddress CIDRs/IPs AND -InterfaceAlias VPN/private interfaces.' }
    if ($ListenAddress -in @('0.0.0.0','::','127.0.0.1','::1')) { throw 'Bind the gateway to a specific private/VPN interface address.' }
    $local = @(Get-NetIPAddress -IPAddress $ListenAddress -ErrorAction Stop)
    if (-not ($local | Where-Object { $_.InterfaceAlias -in $InterfaceAlias })) { throw 'Listener does not belong to a selected interface.' }
    foreach ($alias in $InterfaceAlias) {
        $profiles = @(Get-NetConnectionProfile -InterfaceAlias $alias -ErrorAction Stop)
        if (-not $profiles -or ($profiles | Where-Object { $_.NetworkCategory -eq 'Public' })) { throw 'Public or unclassified interfaces cannot expose administration.' }
    }
    foreach ($address in $RemoteAddress) {
        $pieces = $address.Split('/')
        $ip = $null
        if (-not [Net.IPAddress]::TryParse($pieces[0],[ref]$ip) -or $pieces.Count -gt 2) { throw 'Remote scope must contain literal private/VPN IP addresses or CIDRs, not Any/Internet/DNS names.' }
        $bytes = $ip.GetAddressBytes()
        $private = if ($bytes.Length -eq 4) { $bytes[0] -eq 10 -or ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) } else { ($bytes[0] -band 254) -eq 252 }
        $minimumPrefix = if ($bytes.Length -eq 4) { if ($bytes[0] -eq 10) { 8 } elseif ($bytes[0] -eq 172) { 12 } elseif ($bytes[0] -eq 192) { 16 } else { 10 } } else { 7 }
        if (-not $private -or ($pieces.Count -eq 2 -and ($pieces[1] -notmatch '^\d+$' -or [int]$pieces[1] -lt $minimumPrefix -or [int]$pieces[1] -gt ($bytes.Length*8)))) { throw 'Scope must stay inside an RFC1918, CGNAT VPN, or IPv6 ULA private network.' }
    }
}
if ($MigrateFrom -and -not $OriginalAccount) { throw 'Migration requires -OriginalAccount DOMAIN\user; run elevated as that same account.' }
$release = Read-Release $Package $PublisherThumbprint ''
Set-ProtectedDirectory $InstallRoot -Code
Set-ProtectedDirectory $DataRoot
$destination = Join-Path $InstallRoot ('releases\' + $release.version)
if (Test-Path $destination) { throw 'Release directory already exists; repair/remove the incomplete installation explicitly.' }
Copy-ProtectedRelease $Package $destination
# Validate the protected COPY, not just the user-writable source package.
$release = Read-Release $destination $PublisherThumbprint ''
Copy-Item -LiteralPath (Join-Path $destination 'publisher.cer') -Destination (Join-Path $InstallRoot 'publisher.cer') -Force
$agent = Join-Path $destination 'agent\RDPMonitorAgent.exe'
Invoke-Checked $agent @('verify-installation')
if ($MigrateFrom) { Invoke-Checked $agent @('migrate','--source',$MigrateFrom,'--data-dir',$DataRoot,'--original-account',$OriginalAccount) }
Set-ProtectedDirectory $DataRoot
$deployment = [ordered]@{ version=$release.version; release=$destination; publisher_thumbprint=$PublisherThumbprint.Replace(' ','').ToUpperInvariant(); data_schema=[int]$release.data_schema; api=1; host=$ListenAddress; port=$Port; scope=$Scope; remote_addresses=@($RemoteAddress); interfaces=@($InterfaceAlias); installed_utc=[DateTime]::UtcNow.ToString('o') }
Save-Deployment $deployment
Invoke-Checked $agent @('service-register')
if ($Scope -eq 'Private') {
    New-NetFirewallRule -Name 'RDPMonitor-Gateway-Private' -DisplayName 'RDPMonitor enrolled administration (explicit private/VPN scope)' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -LocalAddress $ListenAddress -RemoteAddress $RemoteAddress -InterfaceAlias $InterfaceAlias -Profile Private,Domain -Program $agent | Out-Null
}
try { Start-AgentServices; Wait-AgentReady $agent $deployment }
catch { Stop-AgentServices; throw }
Write-Output "Installed signed RDPMonitor $($release.version). Client startup is independent of boot-time agent/schedules. Enroll using: `"$agent`" pair --data-dir `"$DataRoot`""
