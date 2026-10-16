@echo off
setlocal
cd /d "%~dp0"
if "%~1"=="" (
  echo Usage: install.bat TRUSTED_PUBLISHER_THUMBPRINT [additional installer parameters]
  echo Obtain the publisher fingerprint through an independently trusted channel.
  echo Production installation requires an authenticated signed release package.
  exit /b 2
)
set "PUBLISHER=%~1"
powershell.exe -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; $path=Join-Path (Get-Location) 'scripts\install_suite.ps1'; $s=Get-AuthenticodeSignature -LiteralPath $path; if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -ne $env:PUBLISHER.Replace(' ','').ToUpperInvariant()) { throw 'Installer signature does not match the trusted publisher' }; & $path -Package (Get-Location).Path -PublisherThumbprint $env:PUBLISHER; if (-not $?) { exit 1 }"
exit /b %errorlevel%
