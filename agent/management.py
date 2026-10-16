"""Local administrative CLI. Client startup never controls monitoring/schedules."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def _deployment():
    from agent.service import data_directory
    path = data_directory() / 'deployment.json'
    if not path.is_file():
        raise RuntimeError('No installed agent. Install an authenticated signed release package first.')
    return json.loads(path.read_text(encoding='utf-8-sig'))


def _powershell(script: Path, args: list[str], publisher: str):
    if os.name != 'nt':
        raise RuntimeError('Product lifecycle management requires Windows')
    environment = dict(os.environ, RDPM_SCRIPT=str(script), RDPM_PUBLISHER=publisher.replace(' ', '').upper())
    validation = "$s=Get-AuthenticodeSignature -LiteralPath $env:RDPM_SCRIPT; if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -ne $env:RDPM_PUBLISHER) { throw 'Untrusted deployment script' }"
    subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', validation], env=environment, check=True)
    # Never ExecutionPolicy Bypass and never a downloaded command string.
    return subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script), *args], check=False).returncode


def client_startup(action: str, client: Path | None = None):
    """Unelevated HKCU Run value only, no privileged scheduled task/scheduler."""
    import winreg
    key_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
    name = 'RDPMonitorDesktop'
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
        if action == 'disable':
            try:
                winreg.DeleteValue(key, name)
            except FileNotFoundError:
                pass
        elif action == 'enable':
            from agent.service import verify_protected_tree
            explicit_client = client is not None
            client = client or Path(_deployment()['release']) / 'client' / 'rdpmonitor.exe'
            if not client.is_file():
                raise FileNotFoundError(client)
            verify_protected_tree(client.parent)
            shortcut = Path(os.environ['PROGRAMDATA']) / 'Microsoft/Windows/Start Menu/Programs/RDPMonitor.lnk'
            command = [str(client)]
            if not explicit_client and shortcut.is_file():
                command = [str(Path(os.environ['SystemRoot']) / 'explorer.exe'), str(shortcut)]
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, subprocess.list2cmdline(command))
        try:
            value, _ = winreg.QueryValueEx(key, name)
        except FileNotFoundError:
            value = None
    print(json.dumps({'client_startup': value, 'agent_services': 'unchanged', 'backup_schedules': 'unchanged'}))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    install = commands.add_parser('install')
    install.add_argument('--package', type=Path, required=True)
    install.add_argument('--publisher-thumbprint', required=True)
    install.add_argument('--scope', choices=['Local', 'Private'], default='Local')
    install.add_argument('--listen-address', default='127.0.0.1')
    install.add_argument('--port', type=int, default=8443)
    install.add_argument('--remote-address', action='append', default=[])
    install.add_argument('--interface-alias', action='append', default=[])
    install.add_argument('--migrate-from', type=Path)
    install.add_argument('--original-account')
    commands.add_parser('repair')
    remove = commands.add_parser('remove')
    remove.add_argument('--delete-data', action='store_true')
    remove.add_argument('--confirm-data-deletion')
    update = commands.add_parser('update')
    update.add_argument('--package', type=Path, required=True)
    update.add_argument('--verify-only', action='store_true')
    rollback = commands.add_parser('rollback')
    rollback.add_argument('--update-id', required=True)
    rollback.add_argument('--confirm-rollback', required=True)
    startup = commands.add_parser('client-startup')
    startup.add_argument('action', choices=['enable','disable','status'])
    startup.add_argument('--client', type=Path)
    commands.add_parser('client')
    args = parser.parse_args(argv)
    if args.command == 'client-startup':
        return client_startup(args.action, args.client)
    if args.command == 'client':
        client = Path(_deployment()['release']) / 'client' / 'rdpmonitor.exe'
        subprocess.Popen([str(client)], cwd=str(client.parent))
        return 0
    if args.command == 'install':
        script = args.package / 'scripts' / 'install_suite.ps1'
        switches = ['-Package', str(args.package), '-PublisherThumbprint', args.publisher_thumbprint,
                    '-Scope', args.scope, '-ListenAddress', args.listen_address, '-Port', str(args.port)]
        # PowerShell -File does not reliably bind array arguments from native argv;
        # use one address/interface per CLI invocation or call the PS installer
        # directly for multiple scoped CIDRs/interfaces.
        if len(args.remote_address) > 1 or len(args.interface_alias) > 1:
            parser.error('For multiple scopes use the signed PowerShell installer with native array parameters')
        if args.remote_address:
            switches += ['-RemoteAddress', args.remote_address[0]]
        if args.interface_alias:
            switches += ['-InterfaceAlias', args.interface_alias[0]]
        if args.migrate_from:
            switches += ['-MigrateFrom', str(args.migrate_from)]
        if args.original_account:
            switches += ['-OriginalAccount', args.original_account]
    else:
        deployment = _deployment()
        scripts = Path(deployment['release']) / 'scripts'
        if args.command == 'update':
            script, switches = scripts / 'update-agent.ps1', ['-Package', str(args.package)]
            if args.verify_only:
                switches += ['-VerifyOnly']
        elif args.command == 'rollback':
            script, switches = scripts / 'rollback-agent.ps1', ['-UpdateId', args.update_id, '-ConfirmRollback', args.confirm_rollback]
        else:
            script, switches = scripts / 'install_suite.ps1', ['-Repair' if args.command == 'repair' else '-Remove']
            if args.command == 'remove' and args.delete_data:
                switches += ['-DeleteData', '-ConfirmDataDeletion', args.confirm_data_deletion or '']
    publisher = args.publisher_thumbprint if args.command == 'install' else deployment['publisher_thumbprint']
    return _powershell(script, switches, publisher)


if __name__ == '__main__':
    raise SystemExit(main())
