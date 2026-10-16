@echo off
setlocal
rem Removal preserves monitoring policies, backups, recovery state and credentials.
powershell.exe -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; $record=Join-Path $env:ProgramData 'RDPMonitor\deployment.json'; if (-not (Test-Path -LiteralPath $record)) { throw 'No installed RDPMonitor deployment was found' }; $d=Get-Content -LiteralPath $record -Raw | ConvertFrom-Json; $path=Join-Path $d.release 'scripts\install_suite.ps1'; $s=Get-AuthenticodeSignature -LiteralPath $path; if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -ne $d.publisher_thumbprint) { throw 'Untrusted installed removal script' }; & $path -Remove -PublisherThumbprint $d.publisher_thumbprint; if (-not $?) { exit 1 }"
exit /b %errorlevel%
