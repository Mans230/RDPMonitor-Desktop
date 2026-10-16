$ErrorActionPreference = 'Stop'
# The signed launcher lives in the protected release tree. Run in the signed-in
# user's session, without elevation or a console window; never in session zero.
$agent = Join-Path (Split-Path -Parent $PSScriptRoot) 'agent\RDPMonitorAgent.exe'
Start-Process -FilePath $agent -ArgumentList @('session-helper') -WindowStyle Hidden
