[CmdletBinding()]
param(
    [string]$Package,
    [string]$ISCC,
    [switch]$AcquireCompiler,
    [switch]$UnsignedPreview,
    [switch]$GuestOnly,
    [string]$CertificateThumbprint,
    [string]$TimestampUrl,
    [string]$SignTool = 'signtool.exe',
    [string]$Output
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
if (-not $Output) { $Output = Join-Path $Root 'dist\installers' }
$Output = [IO.Path]::GetFullPath($Output)
function Run([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}
# Official immutable release asset and SHA256 from:
# https://api.github.com/repos/jrsoftware/issrc/releases/tags/is-7_1_0
# Both the release digest AND Windows Authenticode chain/publisher are required.
# Official current Authenticode publisher: https://jrsoftware.org/isdl-verify.php
if ($AcquireCompiler) {
    $tools = Join-Path $env:LOCALAPPDATA 'RDPMonitor-BuildTools'
    New-Item -ItemType Directory -Path $tools -Force | Out-Null
    $download = Join-Path $tools 'innosetup-7.1.0-x64.exe'
    $url = 'https://github.com/jrsoftware/issrc/releases/download/is-7_1_0/innosetup-7.1.0-x64.exe'
    $sha = '0362a383ed217d4c4239b5933866dd96d3eb2102737da92f80f6057a4b40df2f'
    if (-not (Test-Path -LiteralPath $download)) { Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $download }
    if ((Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash.ToLowerInvariant() -ne $sha) { throw 'Official compiler digest mismatch; refusing to execute download.' }
    $auth = Get-AuthenticodeSignature -LiteralPath $download
    if ($auth.Status -ne 'Valid' -or $auth.SignerCertificate.Subject -notmatch '(^|, )CN=Pyrsys B\.V\.(,|$)') { throw 'Official compiler Authenticode chain/publisher verification failed.' }
    $compilerRoot = Join-Path $tools 'InnoSetup-7.1.0'
    $process = Start-Process -FilePath $download -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/CURRENTUSER',('/DIR="' + $compilerRoot + '"')) -Wait -PassThru
    if ($process.ExitCode -ne 0) { throw "Compiler tool installation failed: $($process.ExitCode)" }
    $ISCC = Join-Path $compilerRoot 'ISCC.exe'
    Write-Output "Compiler provenance: $url SHA256=$sha Authenticode=$($auth.SignerCertificate.Subject)"
    Write-Output "Compiler: $ISCC"
    if (-not $Package) { return }
}
if (-not $Package) { throw 'Supply -Package containing the complete packaged agent/client runtime, or -AcquireCompiler alone to acquire only the build tool.' }
$Package = (Resolve-Path -LiteralPath $Package).Path.TrimEnd('\')
if (-not $ISCC) {
    $localCompiler = Join-Path $env:LOCALAPPDATA 'RDPMonitor-BuildTools\InnoSetup-7.1.0\ISCC.exe'
    if (Test-Path -LiteralPath $localCompiler) { $ISCC = $localCompiler }
    else { $ISCC = (Get-Command 'ISCC.exe' -ErrorAction Stop).Source }
}
Get-Command $ISCC -ErrorAction Stop | Out-Null
$requiredFiles = @('agent\RDPMonitorAgent.exe','scripts\deployment-common.ps1','scripts\install_suite.ps1','scripts\update-agent.ps1','scripts\start-session-helper.ps1')
if (-not $GuestOnly) { $requiredFiles += 'client\rdpmonitor.exe' }
if ($GuestOnly -and (Test-Path -LiteralPath (Join-Path $Package 'client'))) { throw 'Guest input must not contain a client payload.' }
foreach ($required in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $Package $required) -PathType Leaf)) { throw "Incomplete packaged runtime: $required" }
}
# The complete one-directory Python and Flutter runtimes must already be present.
# This build never pip-installs and never falls back from production to preview.
if (-not (Test-Path -LiteralPath (Join-Path $Package 'agent\runtime') -PathType Container)) { throw 'Frozen agent runtime directory is missing.' }
foreach ($item in @(Get-Item -LiteralPath $Package) + @(Get-ChildItem -LiteralPath $Package -Recurse -Force)) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse points cannot be packaged.' }
}
$manifestPath = Join-Path $Package 'release.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'Packaged release.json is required.' }
$metadata = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$component = 'suite'
if ($metadata.PSObject.Properties.Name -contains 'component') { $component = [string]$metadata.component }
$expectedComponent = if ($GuestOnly) { 'guest' } else { 'suite' }
if ($component -cne $expectedComponent) { throw 'Package component does not match the explicit installer build mode.' }
$stage = $Package
$thumbprint = ''
if ($UnsignedPreview) {
    if ($CertificateThumbprint -or $TimestampUrl) { throw 'Preview is deliberately unsigned; do not mix production signing inputs.' }
    $manifestPath = Join-Path $Package 'release.json'
    if (-not (Test-Path -LiteralPath $manifestPath)) { throw 'Preview input requires release.json with numeric version and data_schema from its packaged runtime.' }
    $metadata = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $version = [string]$metadata.version
    if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'Preview version must be numeric major.minor.patch.' }
    $previewStageName = if ($GuestOnly) { 'preview-guest-payload-' + $version } else { 'preview-payload-' + $version }
    $stage = Join-Path $Output $previewStageName
    if (Test-Path -LiteralPath $stage) { throw 'Preview staging directory already exists; use a fresh output directory.' }
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    Copy-Item -Path (Join-Path $Package '*') -Destination $stage -Recurse -Force
    # Signature metadata is not a claim of production authentication in a preview.
    foreach ($name in @('release.sig','publisher.cer','preview.json')) { Remove-Item -LiteralPath (Join-Path $stage $name) -Force -ErrorAction SilentlyContinue }
    $files = @()
    foreach ($file in Get-ChildItem -LiteralPath $stage -Recurse -File -Force | Sort-Object FullName) {
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse points cannot be packaged.' }
        $files += [ordered]@{ path=$file.FullName.Substring($stage.Length).TrimStart('\').Replace('\','/'); size=$file.Length; sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
    }
    $preview = [ordered]@{ format=1; version=$version; component=$component; platform='windows-x64'; api=1; data_schema=[int]$metadata.data_schema; unsigned_preview=$true; read_only=$true; files=$files }
    [IO.File]::WriteAllText((Join-Path $stage 'preview.json'),($preview | ConvertTo-Json -Depth 12),(New-Object Text.UTF8Encoding($false)))
} else {
    if (-not $CertificateThumbprint -or $TimestampUrl -notmatch '^https://') { throw 'Production requires the real publisher thumbprint/private key and HTTPS RFC3161 timestamp service. Use -UnsignedPreview only for an explicitly labeled monitoring-only preview.' }
    $thumbprint = $CertificateThumbprint.Replace(' ','').ToUpperInvariant()
    $certificate = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $thumbprint) -ErrorAction Stop
    if (-not $certificate.HasPrivateKey -or $certificate.NotBefore -gt (Get-Date) -or $certificate.NotAfter -lt (Get-Date)) { throw 'A real current publisher signing credential with private key is required.' }
    Get-Command $SignTool -ErrorAction Stop | Out-Null
    $helper = Join-Path $Package 'scripts\deployment-common.ps1'
    $signature = Get-AuthenticodeSignature -LiteralPath $helper
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $thumbprint) { throw 'Production lifecycle helper is not authenticated by the selected publisher.' }
    . $helper
    $metadata = Read-Release $Package $thumbprint '' -Component $expectedComponent
    $version = $metadata.version
}
New-Item -ItemType Directory -Path $Output -Force | Out-Null
$arguments = @("/DPackageDir=$stage", "/DReleaseVersion=$version", "/DOutputDir=$Output", "/DPublisherThumbprint=$thumbprint")
if ($GuestOnly) { $arguments += '/DGuestOnly' }
$artifactPrefix = if ($GuestOnly) { 'RDPMonitorGuest-' } else { 'RDPMonitor-' }
if ($UnsignedPreview) {
    $arguments += '/DUnsignedPreview'
    $artifact = Join-Path $Output ($artifactPrefix + $version + '-windows-x64-UNSIGNED-PREVIEW-setup.exe')
} else {
    # ISCC signs the embedded uninstaller as well as the outer setup. Credentials
    # stay in the Windows certificate provider; no PFX password enters argv.
    $signCommand = '"' + $SignTool + '" sign /sha1 ' + $thumbprint + ' /fd SHA256 /tr "' + $TimestampUrl + '" /td SHA256 $f'
    $arguments += @('/DProductionSigned', ('/Spublisher=' + $signCommand))
    $artifact = Join-Path $Output ($artifactPrefix + $version + '-windows-x64-setup.exe')
}
$arguments += Join-Path $Root 'installer\RDPMonitor.iss'
Run $ISCC $arguments
if (-not $UnsignedPreview) {
    Run $SignTool @('verify','/pa','/all',$artifact)
    $signature = Get-AuthenticodeSignature -LiteralPath $artifact
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $thumbprint) { throw 'Installer publisher verification failed.' }
}
$hash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText(($artifact + '.sha256'),$hash + '  ' + [IO.Path]::GetFileName($artifact) + "`n")
Write-Output "Installer: $artifact"
Write-Output "SHA256: $hash"
if ($UnsignedPreview) { Write-Output 'UNSIGNED PREVIEW ONLY: explicit consent and forced read_only; not a signed production release.' }
