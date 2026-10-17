$ErrorActionPreference='Stop';$env:RDP_MONITOR_BOOTSTRAP=$null;$c=1;$d=$null;$r=$null;$f=$null;$m='Open Command Prompt as Administrator, then paste again.'
try{
if(!(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(544)){throw 'Open Command Prompt as Administrator, then paste again.'}
$m='Guest bootstrap failed. Verify network, pinned release and protected cache policy.'
$u=[uri]$env:RDP_MONITOR_INSTALLER_URL;$h=$env:RDP_MONITOR_INSTALLER_SHA256;$p=$env:RDP_MONITOR_PUBLISHER;$a='/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CMDBOOTSTRAP'
if($h-notmatch'\A[0-9a-fA-F]{64}\z'-or !$env:RDP_MONITOR_SETUP){throw 'Invalid bootstrap input.'}
if($env:RDP_MONITOR_INSTALLER_MODE-eq'preview'){if($env:RDP_MONITOR_PREVIEW_ACCEPT-ne'I_ACCEPT_UNSIGNED_MONITORING_ONLY'){throw 'Unsigned monitoring-only consent required.'};$a+=' /ACCEPTUNSIGNEDMONITORINGONLY'}elseif($env:RDP_MONITOR_INSTALLER_MODE-ne'production'-or $p-notmatch'\A[0-9a-fA-F]{40}\z'){throw 'Invalid publisher policy.'}
$b=[Environment]::GetFolderPath('CommonApplicationData');$t=Get-Item -LiteralPath $b -Force
while($t){
if($t.Attributes-band 1024){throw 'Unsafe cache parent.'}
$v=Get-Acl -LiteralPath $t.FullName
if($null-eq[Security.AccessControl.RawSecurityDescriptor]::new($v.GetSecurityDescriptorBinaryForm(),0).DiscretionaryAcl){throw 'Unsafe cache parent permissions.'}
$ok=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
if($v.GetOwner([Security.Principal.SecurityIdentifier]).Value-notin$ok){throw 'Unsafe cache owner.'}
foreach($rule in $v.Access){if($rule.AccessControlType-eq'Allow'-and !($rule.PropagationFlags-band 2)-and ($rule.FileSystemRights-band 0x500D0040)-and $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value-notin$ok){throw 'Unsafe cache parent permissions.'}}
$t=$t.Parent
}
$y=Join-Path $b ('RDPMonitor-'+[guid]::NewGuid().ToString('N'));$s=New-Object Security.AccessControl.DirectorySecurity;$s.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)');[IO.Directory]::CreateDirectory($y,$s)|Out-Null
$t=Get-Item -LiteralPath $y -Force;$v=Get-Acl -LiteralPath $y
if(($t.Attributes-band 1024)-or $v.Sddl-ne$s.Sddl){throw 'Unsafe cache permissions.'}
$d=$y;$x=Join-Path $d 'guest.exe'
for($i=0;$i-le 5;$i++){
if($u.Scheme-ne'https'-or $u.UserInfo-or $u.Fragment){throw 'HTTPS download required.'}
$q=[Net.HttpWebRequest]::Create($u);$q.AllowAutoRedirect=$false;$q.Timeout=60000;$q.ReadWriteTimeout=60000;$r=$q.GetResponse();$n=[int]$r.StatusCode
if($n-ge 300-and $n-lt 400){$l=$r.Headers['Location'];$r.Close();$r=$null;$u=New-Object uri($u,$l);continue}
if($n-ne 200-or $r.ContentLength-gt 536870912){throw 'Installer download rejected.'};break
}
if(!$r-or $n-ne 200){throw 'Too many download redirects.'}
$f=[IO.File]::Open($x,1,2,0);$z=New-Object byte[] 65536;$k=0;$w=$r.GetResponseStream();while(($j=$w.Read($z,0,$z.Length))-gt 0){$k+=$j;if($k-gt 536870912){throw 'Installer too large.'};$f.Write($z,0,$j)};$f.Close();$f=$null;$r.Close();$r=$null
if((Get-FileHash -LiteralPath $x -Algorithm SHA256).Hash-ne$h){throw 'Installer SHA256 mismatch.'}
if($env:RDP_MONITOR_INSTALLER_MODE-eq'production'){$g=Get-AuthenticodeSignature -LiteralPath $x;if($g.Status-ne'Valid'-or $g.SignerCertificate.Thumbprint-ne$p){throw 'Installer publisher verification failed.'}}
$c=(Start-Process -FilePath $x -ArgumentList $a -NoNewWindow -Wait -PassThru).ExitCode
if($c-ne 0){Write-Host ('Guest installation failed (exit '+$c+').')}
}catch{Write-Host $m}finally{
$env:RDP_MONITOR_SETUP=$null;if($f){$f.Close()};if($r){$r.Close()};if($d){try{Remove-Item -LiteralPath $d -Recurse -Force}catch{Write-Host 'Warning: protected installer cache cleanup failed.'}}
}
exit $c
