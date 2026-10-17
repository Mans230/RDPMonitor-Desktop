[CmdletBinding(DefaultParameterSetName='Production')]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [Parameter(Mandatory=$true,ParameterSetName='Production')][string]$CertificateThumbprint,
    [Parameter(Mandatory=$true,ParameterSetName='Production')][string]$TimestampUrl,
    [Parameter(Mandatory=$true,ParameterSetName='Preview')][switch]$UnsignedPreview,
    [switch]$GuestOnly,
    [Parameter(Mandatory=$true)][string]$VCRuntimeDirectory,
    [Parameter(Mandatory=$true)][string]$VCRedistributionNoticeFile,
    [string]$Python = 'python.exe',
    [string]$Flutter = 'flutter.bat',
    [string]$SignTool = 'signtool.exe',
    [int]$BuildNumber = 5,
    [int]$DataSchema = 1,
    [int]$MinimumDataSchema = 1,
    [int]$MaximumDataSchema = 1,
    [string]$GuestSetupUrl,
    [string]$GuestSetupSha256,
    [string]$GuestSetupMode,
    [string]$GuestPublisherThumbprint,
    [ValidateSet(1,2)][int]$GuestSetupProtocol = 1,
    [string]$Output
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
if (-not $Output) { $Output = Join-Path $Root 'dist' }
function Run([string]$Program,[string[]]$Arguments) { & $Program @Arguments; if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" } }
if (-not $UnsignedPreview -and -not $GuestOnly -and $GuestSetupMode -ne 'production') { throw 'Production desktop builds require an explicit pinned production guest installer; preview guest defaults are not production trust.' }
if ($GuestOnly -and ($GuestSetupUrl -or $GuestSetupSha256 -or $GuestSetupMode -or $GuestPublisherThumbprint -or $PSBoundParameters.ContainsKey('GuestSetupProtocol'))) { throw 'Guest bootstrap overrides apply only to desktop builds.' }
if ($PSBoundParameters.ContainsKey('GuestSetupProtocol') -and -not ($GuestSetupUrl -or $GuestSetupSha256 -or $GuestSetupMode -or $GuestPublisherThumbprint)) { throw 'Guest setup protocol requires explicit guest installer trust overrides.' }
$thumbprint = ''
$certificate = $null
Get-Command $Python -ErrorAction Stop | Out-Null
if (-not $GuestOnly) { Get-Command $Flutter -ErrorAction Stop | Out-Null }
if (-not $UnsignedPreview) {
    if ($TimestampUrl -notmatch '^https://') { throw 'A real HTTPS RFC3161 Authenticode timestamp service is required.' }
    $thumbprint = $CertificateThumbprint.Replace(' ','').ToUpperInvariant()
    $certificate = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $thumbprint) -ErrorAction Stop
    if (-not $certificate.HasPrivateKey -or $certificate.NotAfter -lt (Get-Date) -or $certificate.NotBefore -gt (Get-Date)) { throw 'A valid provided code-signing certificate WITH private key is required; no self-signed substitute is generated.' }
    $eku = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
    if (-not $eku -or -not (@($eku[0].EnhancedKeyUsages | ForEach-Object { $_.Value }) -contains '1.3.6.1.5.5.7.3.3')) { throw 'Certificate must have the code-signing EKU.' }
    Get-Command $SignTool -ErrorAction Stop | Out-Null
}
foreach ($name in @('msvcp140.dll','vcruntime140.dll','vcruntime140_1.dll')) {
    if (-not (Test-Path -LiteralPath (Join-Path $VCRuntimeDirectory $name) -PathType Leaf)) { throw "Missing x64 Visual C++ redistributable: $name" }
}
if (-not (Test-Path -LiteralPath $VCRedistributionNoticeFile -PathType Leaf)) { throw 'Supply the official Microsoft runtime redistribution notice from the licensed toolchain.' }
if ($MinimumDataSchema -gt $DataSchema -or $MaximumDataSchema -lt $DataSchema) { throw 'Invalid state schema compatibility range.' }
$suffix = if ($UnsignedPreview) { '-UNSIGNED-PREVIEW' } else { '' }
$product = if ($GuestOnly) { 'RDPMonitorGuest-' } else { 'RDPMonitor-' }
$stage = Join-Path $Output ($product + $Version + '-windows-x64' + $suffix)
if (Test-Path -LiteralPath $stage) { throw 'Output release already exists; use a fresh output directory/version.' }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
# Dependency/toolchain installation is a separate explicit prerequisite. No pip
# downloads or mutable Python installation is performed by the production installer.
Run $Python @('-m','PyInstaller','--noconfirm','--clean','--distpath',(Join-Path $Output 'frozen'),'--workpath',(Join-Path $Output 'pyinstaller-work'),(Join-Path $PSScriptRoot 'agent.spec'))
if (-not $GuestOnly) {
    Push-Location (Join-Path $Root 'clients\app')
    try {
        Run $Flutter @('pub','get','--enforce-lockfile')
        $flutterArguments = @('build','windows','--release','--build-name',$Version,'--build-number',([string]$BuildNumber))
        $guestInputs = @($GuestSetupUrl,$GuestSetupSha256,$GuestSetupMode,$GuestPublisherThumbprint) | Where-Object { $_ }
        if ($guestInputs) {
            if ($GuestSetupUrl -notmatch '^https://' -or $GuestSetupSha256 -notmatch '^[0-9a-fA-F]{64}$' -or $GuestSetupMode -notin @('unsigned-preview','production')) { throw 'Guest bootstrap override requires an HTTPS URL, complete SHA256 and explicit unsigned-preview/production mode.' }
            if ($GuestSetupMode -eq 'production' -and $GuestPublisherThumbprint -notmatch '^[0-9a-fA-F]{40}$') { throw 'Production guest bootstrap requires its independently trusted publisher thumbprint.' }
            $flutterArguments += @("--dart-define=RDP_GUEST_URL=$GuestSetupUrl","--dart-define=RDP_GUEST_SHA256=$($GuestSetupSha256.ToLowerInvariant())","--dart-define=RDP_GUEST_MODE=$GuestSetupMode","--dart-define=RDP_GUEST_PUBLISHER=$GuestPublisherThumbprint","--dart-define=RDP_GUEST_SETUP_PROTOCOL=$GuestSetupProtocol")
        }
        Run $Flutter $flutterArguments
    } finally { Pop-Location }
}
Copy-Item -LiteralPath (Join-Path $Output 'frozen\RDPMonitorAgent') -Destination (Join-Path $stage 'agent') -Recurse
if (-not $GuestOnly) {
    Copy-Item -LiteralPath (Join-Path $Root 'clients\app\build\windows\x64\runner\Release') -Destination (Join-Path $stage 'client') -Recurse
    # The desktop has app-local release CRT DLLs; the frozen agent owns its runtime.
    Copy-Item -Path (Join-Path $VCRuntimeDirectory '*.dll') -Destination (Join-Path $stage 'client')
}
Copy-Item -LiteralPath $VCRedistributionNoticeFile -Destination (Join-Path $stage 'MICROSOFT-VC-REDISTRIBUTION.txt')
Copy-Item -LiteralPath $PSScriptRoot -Destination (Join-Path $stage 'scripts') -Recurse
New-Item -ItemType Directory -Path (Join-Path $stage 'docs') | Out-Null
Copy-Item -Path (Join-Path $Root 'docs\*') -Destination (Join-Path $stage 'docs') -Recurse
Copy-Item -LiteralPath (Join-Path $Root 'LICENSE'),(Join-Path $Root 'README.md'),(Join-Path $Root 'SECURITY.md'),(Join-Path $Root 'CHANGELOG-FIXED.md') -Destination $stage
if (-not $GuestOnly) { Copy-Item -LiteralPath (Join-Path $Root 'clients\app\assets\fonts\OFL.txt') -Destination (Join-Path $stage 'GEIST-OFL.txt') }
if (-not $UnsignedPreview -and -not $GuestOnly) { Copy-Item -LiteralPath (Join-Path $Root 'install.bat'),(Join-Path $Root 'uninstall.bat') -Destination $stage }
Run $Python @((Join-Path $PSScriptRoot 'collect-licenses.py'),'--output',(Join-Path $stage 'PYTHON-THIRD-PARTY-NOTICES.txt'))
$freeze = & $Python -m pip freeze --all
if ($LASTEXITCODE -ne 0) { throw 'Failed to capture installed dependency versions.' }
$freeze | Set-Content -LiteralPath (Join-Path $stage 'runtime-dependencies.txt') -Encoding ASCII
if (-not $UnsignedPreview) {
[IO.File]::WriteAllBytes((Join-Path $stage 'publisher.cer'),$certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
# Sign every PE/native plugin and PowerShell entrypoint, including bundled runtime
# dependencies. A failed signing/chain verification aborts artifact production.
foreach ($file in Get-ChildItem -LiteralPath $stage -Recurse -File) {
    if ($file.Extension -in @('.exe','.dll','.pyd','.ps1')) {
        Run $SignTool @('sign','/sha1',$thumbprint,'/fd','SHA256','/tr',$TimestampUrl,'/td','SHA256',$file.FullName)
        Run $SignTool @('verify','/pa','/all',$file.FullName)
    }
}
}
$files = @()
foreach ($file in Get-ChildItem -LiteralPath $stage -Recurse -File | Sort-Object FullName) {
    if ($file.Name -eq 'publisher.cer' -and $file.DirectoryName -eq $stage) { continue }
    $files += [ordered]@{ path=$file.FullName.Substring($stage.Length).TrimStart('\').Replace('\','/'); size=$file.Length; sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
}
$manifest = [ordered]@{ format=1; version=$Version; platform='windows-x64'; api=1; data_schema=$DataSchema; min_data_schema=$MinimumDataSchema; max_data_schema=$MaximumDataSchema; publisher_thumbprint=$thumbprint; created_utc=[DateTime]::UtcNow.ToString('o'); files=$files }
$manifest['build_number'] = $BuildNumber
$manifest['component'] = if ($GuestOnly) { 'guest' } else { 'suite' }
if ($UnsignedPreview) { $manifest['unsigned_preview'] = $true; $manifest['read_only'] = $true }
$manifestBytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($manifest | ConvertTo-Json -Depth 12))
[IO.File]::WriteAllBytes((Join-Path $stage 'release.json'),$manifestBytes)
if (-not $UnsignedPreview) {
$rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
if (-not $rsa) { throw 'RSA code-signing key required for detached update manifest signing.' }
try { $signed = $rsa.SignData($manifestBytes,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1) } finally { $rsa.Dispose() }
[IO.File]::WriteAllText((Join-Path $stage 'release.sig'),[Convert]::ToBase64String($signed),(New-Object Text.UTF8Encoding($false)))
}
$archive = $stage + '.zip'
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -CompressionLevel Optimal
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText(($archive + '.sha256'),($hash + '  ' + [IO.Path]::GetFileName($archive) + "`n"))
if ($UnsignedPreview) {
    Write-Output "UNSIGNED monitoring-only evaluation package: $archive"
    Write-Output 'No publisher authentication is claimed. Build the explicit preview setup with scripts/build-installer.ps1 -UnsignedPreview.'
} else {
    Write-Output "Signed coherent release: $archive"
    Write-Output "Publisher thumbprint (authenticate independently): $thumbprint"
}
Write-Output "SHA256: $hash"
