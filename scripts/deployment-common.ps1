$ErrorActionPreference = 'Stop'
$InstallRoot = Join-Path $env:ProgramFiles 'RDPMonitor'
$DataRoot = Join-Path $env:ProgramData 'RDPMonitor'
$serviceHash = [Security.Cryptography.SHA1]::Create().ComputeHash([Text.Encoding]::Unicode.GetBytes('RDPMONITORGATEWAY'))
$GatewaySid = 'S-1-5-80-' + ((0..4 | ForEach-Object { [BitConverter]::ToUInt32($serviceHash, $_ * 4).ToString() }) -join '-')
function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'An elevated Administrator terminal is required.'
    }
}
function Invoke-Checked([string]$File, [string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$File failed with exit code $LASTEXITCODE" }
}
function Set-ProtectedDirectory([string]$Path, [switch]$Code) {
    if (Test-Path -LiteralPath $Path) { Assert-NoReparse $Path }
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    if ($Code) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    } else {
        # Traverse/read the root descriptor only; no inherited access to worker state.
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($GatewaySid)), [Security.AccessControl.FileSystemRights]0x000200A0, 'None', 'None', 'Allow')))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
    Invoke-Checked 'icacls.exe' @($Path,'/setowner','*S-1-5-32-544','/T','/C')
}
function Assert-NoReparse([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point forbidden: $Path" }
    foreach ($parent in @($item.Parent)) {
        while ($parent) {
            if ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Protected path has a reparse-point ancestor.' }
            $parent = $parent.Parent
        }
    }
    foreach ($child in Get-ChildItem -LiteralPath $Path -Force -Recurse) {
        if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point forbidden: $($child.FullName)" }
    }
}
function Read-Release([string]$Package, [string]$PublisherThumbprint, [string]$PinnedCertificate, [ValidateSet('suite','guest')][string]$Component = 'suite') {
    $Package = [IO.Path]::GetFullPath($Package)
    Assert-NoReparse $Package
    $certificatePath = Join-Path $Package 'publisher.cer'
    $certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2($certificatePath)
    $expected = $PublisherThumbprint.Replace(' ','').ToUpperInvariant()
    if (-not $expected -or $certificate.Thumbprint -ne $expected) { throw 'Release publisher does not match the explicitly trusted certificate.' }
    if ($PinnedCertificate) {
        $pinned = New-Object Security.Cryptography.X509Certificates.X509Certificate2($PinnedCertificate)
        if ([Convert]::ToBase64String($pinned.GetPublicKey()) -ne [Convert]::ToBase64String($certificate.GetPublicKey())) { throw 'Publisher key changed; an explicit local trust rotation is required.' }
    }
    if ($certificate.NotBefore -gt (Get-Date) -or $certificate.NotAfter -lt (Get-Date)) { throw 'Publisher certificate is not currently valid.' }
    $eku = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
    if (-not $eku -or -not (@($eku[0].EnhancedKeyUsages | ForEach-Object { $_.Value }) -contains '1.3.6.1.5.5.7.3.3')) { throw 'A real code-signing certificate is required.' }
    $manifestPath = Join-Path $Package 'release.json'
    $bytes = [IO.File]::ReadAllBytes($manifestPath)
    $signature = [Convert]::FromBase64String([IO.File]::ReadAllText((Join-Path $Package 'release.sig')).Trim())
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate)
    try {
        if (-not $rsa.VerifyData($bytes,$signature,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)) { throw 'Invalid signed release manifest.' }
    } finally { $rsa.Dispose() }
    $manifest = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
    if ($manifest.format -ne 1 -or $manifest.api -ne 1 -or $manifest.platform -ne 'windows-x64' -or -not $manifest.files) { throw 'Incompatible release manifest.' }
    if ($manifest.version -notmatch '^\d+\.\d+\.\d+$') { throw 'Release version must be numeric major.minor.patch.' }
    $declaredComponent = if ($manifest.PSObject.Properties.Name -contains 'component') { [string]$manifest.component } else { 'suite' }
    if ($declaredComponent -ne $Component) { throw "Release component mismatch; expected $Component." }
    if ($Component -eq 'guest' -and (Test-Path -LiteralPath (Join-Path $Package 'client'))) { throw 'Guest release must not contain a desktop client.' }
    $expectedFiles = @{}
    foreach ($entry in $manifest.files) {
        if ($entry.path -match '(^[\\/]|:|(^|[\\/])\.\.([\\/]|$))') { throw 'Unsafe release manifest path.' }
        $relative = $entry.path.Replace('/','\')
        if ($expectedFiles.ContainsKey($relative)) { throw 'Duplicate release manifest path.' }
        $expectedFiles[$relative] = $true
        $file = Join-Path $Package $relative
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing release file: $relative" }
        if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $entry.sha256 -or (Get-Item -LiteralPath $file).Length -ne $entry.size) { throw "Release checksum mismatch: $relative" }
        if ([IO.Path]::GetExtension($file) -in @('.exe','.dll','.pyd','.ps1')) {
            $auth = Get-AuthenticodeSignature -LiteralPath $file
            if ($auth.Status -ne 'Valid' -or $auth.SignerCertificate.Thumbprint -ne $expected) { throw "Invalid Authenticode publisher: $relative ($($auth.Status))" }
        }
    }
    foreach ($file in Get-ChildItem -LiteralPath $Package -Recurse -File -Force) {
        $relative = $file.FullName.Substring($Package.Length).TrimStart('\')
        if ($relative -in @('release.json','release.sig','publisher.cer')) { continue }
        if (-not $expectedFiles.ContainsKey($relative)) { throw "Unmanifested release file: $relative" }
    }
    $requiredFiles = @('agent\RDPMonitorAgent.exe','scripts\install_suite.ps1','scripts\update-agent.ps1','scripts\deployment-common.ps1')
    if ($Component -eq 'suite') { $requiredFiles += 'client\rdpmonitor.exe' }
    foreach ($required in $requiredFiles) {
        if (-not $expectedFiles.ContainsKey($required)) { throw "Incomplete coherent $Component release: $required" }
    }
    return $manifest
}
function Stop-AgentServices {
    foreach ($name in @('RDPMonitorGateway','RDPMonitorWorker')) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne 'Stopped') {
            Stop-Service -InputObject $service -Force
            $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(90))
        }
    }
}
function Start-AgentServices {
    Start-Service RDPMonitorWorker
    (Get-Service RDPMonitorWorker).WaitForStatus('Running',[TimeSpan]::FromSeconds(90))
    Start-Service RDPMonitorGateway
    (Get-Service RDPMonitorGateway).WaitForStatus('Running',[TimeSpan]::FromSeconds(90))
}
function Wait-AgentReady([string]$Agent, $Deployment) {
    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        & $Agent status --data-dir $DataRoot --require-gateway --host $Deployment.host --port ([string]$Deployment.port)
        if ($LASTEXITCODE -eq 0) { return }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Worker/gateway did not reach authenticated local health readiness.'
}
function Save-Deployment($Value) {
    $temporary = Join-Path $DataRoot 'deployment.json.new'
    $Value | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination (Join-Path $DataRoot 'deployment.json') -Force
    $acl = Get-Acl (Join-Path $DataRoot 'deployment.json')
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($GatewaySid)),'ReadAndExecute','Allow')))
    Set-Acl (Join-Path $DataRoot 'deployment.json') $acl
    # Refresh user entrypoints on every activation, including update rollback.
    $runKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
    $launcher = Join-Path $Value.release 'scripts\start-session-helper.ps1'
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    New-Item -Path $runKey -Force | Out-Null
    New-ItemProperty -LiteralPath $runKey -Name 'RDPMonitorSessionHelper' -PropertyType String -Force -Value ('"' + $powershell + '" -NoProfile -WindowStyle Hidden -File "' + $launcher + '"') | Out-Null
    if ($Value.component -ne 'guest') {
        $shortcutPath = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\RDPMonitor.lnk'
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = Join-Path $Value.release 'client\rdpmonitor.exe'
        $shortcut.WorkingDirectory = Join-Path $Value.release 'client'
        $shortcut.Save()
    }
}
function Copy-ProtectedRelease([string]$Package, [string]$Destination) {
    Set-ProtectedDirectory $Destination -Code
    Copy-Item -Path (Join-Path $Package '*') -Destination $Destination -Recurse -Force
    Assert-NoReparse $Destination
    Invoke-Checked 'icacls.exe' @($Destination,'/setowner','*S-1-5-32-544','/T','/C')
    # Re-inherit from the protected release root; never preserve package ACLs.
    foreach ($item in Get-ChildItem -LiteralPath $Destination -Force) {
        Invoke-Checked 'icacls.exe' @($item.FullName,'/reset','/T','/C')
    }
}
function Set-OwnedGatewayProgram($Deployment, [string]$Program) {
    if ($Deployment.scope -eq 'Private') {
        Set-NetFirewallRule -Name 'RDPMonitor-Gateway-Private' -Program $Program
    } elseif ($Deployment.scope -eq 'Direct') {
        if ($Deployment.read_only -ne $true -or $Deployment.component -ne 'guest' -or
            @($Deployment.remote_addresses).Count -ne 1 -or @($Deployment.interfaces).Count -ne 0) {
            throw 'Invalid retained direct deployment; scope was not broadened.'
        }
        & (Join-Path $PSScriptRoot 'direct-network.ps1') -Action Configure -Port ([int]$Deployment.port) -Source ([string]$Deployment.remote_addresses[0]) -Program $Program -Existing
    } elseif ($Deployment.scope -ne 'Local') {
        throw 'Unknown gateway scope; firewall was not modified.'
    }
}
