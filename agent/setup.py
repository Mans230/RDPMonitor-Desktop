"""Elevated native-setup helper. Secret exchange is confined to protected files.

The native wizard invokes this module through the frozen agent. No command accepts
an invitation, route credential or connection code on its command line.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

from .ipc import current_identity, protect_path, WorkerProxy
from .service import (data_directory, verify_protected_tree, register_services,
                      WORKER, GATEWAY, GATEWAY_METADATA_RIGHTS, gateway_sid)


def install_directory() -> Path:
    return Path(os.environ.get('ProgramFiles', r'C:\Program Files')) / 'RDPMonitor'




def _normalize_owner(path: Path, *, recursive=False) -> None:
    """Normalize files copied by this elevated wizard inside its protected root."""
    import stat
    import win32security
    paths = [path]
    if recursive:
        for directory, directories, files in os.walk(path, followlinks=False):
            paths.extend(Path(directory) / name for name in directories + files)
    owner = win32security.ConvertStringSidToSid('S-1-5-32-544')
    for item in paths:
        if item.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise PermissionError('Reparse points are forbidden in setup payload/exchange')
        win32security.SetNamedSecurityInfo(str(item), win32security.SE_FILE_OBJECT,
                                          win32security.OWNER_SECURITY_INFORMATION, owner, None, None, None)


def _protected_directory(path: Path, *, code=False, gateway_traverse=False) -> None:
    """Create with an atomic protected descriptor; never repair an unsafe tree."""
    import pywintypes
    import win32file
    import win32security
    sddl = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    if code:
        sddl += '(A;OICI;GRGX;;;BU)'
    if gateway_traverse:
        sddl += f'(A;;0x{GATEWAY_METADATA_RIGHTS:08x};;;{gateway_sid()})'
    if path.exists():
        verify_protected_tree(path)
        return
    verify_protected_tree(path.parent, recursive=False, parent_only=True)
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1)
    win32file.CreateDirectory(str(path), attributes)
    verify_protected_tree(path)


def _session(session: str, *, create=False) -> Path:
    if not re.fullmatch(r'[0-9a-f]{32}', session):
        raise ValueError('Invalid setup session identifier')
    root = data_directory()
    if create:
        _protected_directory(root, gateway_traverse=True)
        _protected_directory(root / 'setup')
        path = root / 'setup' / session
        if path.exists():
            raise FileExistsError('Setup session already exists')
        _protected_directory(path)
    else:
        path = root / 'setup' / session
        verify_protected_tree(path, recursive=False)
        invitation = path / 'invitation.txt'
        if invitation.exists():
            # Inno inherits the protected DACL, but initially uses the elevated
            # human administrator as file owner.
            _normalize_owner(invitation)
        verify_protected_tree(path)
    return path


def _write(path: Path, value: str) -> None:
    # Parent is already protected before the first byte (or temporary file) exists.
    verify_protected_tree(path.parent, recursive=False)
    temporary = path.with_suffix(path.suffix + '.new')
    with temporary.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(value)
    protect_path(temporary)
    os.replace(temporary, path)


def _deployment() -> dict | None:
    path = data_directory() / 'deployment.json'
    if not path.exists():
        return None
    verify_protected_tree(path, recursive=False)
    result = json.loads(path.read_text(encoding='utf-8-sig'))
    release = Path(result['release']).absolute()
    if release.parent != install_directory() / 'releases' or not re.fullmatch(r'\d+\.\d+\.\d+', release.name):
        raise ValueError('Installed release path is invalid')
    if result.get('host') != '127.0.0.1' or result.get('scope') != 'Local':
        raise ValueError('This relay wizard cannot modify a private/direct deployment; use its signed lifecycle tools')
    if result.get('unsigned_preview') and result.get('read_only') is not True:
        raise PermissionError('Unsafe preview deployment')
    return result


def prepare(session: str) -> None:
    root = data_directory()
    exchange = root / 'setup'
    if exchange.exists():
        # Recover only wizard exchange ownership after an interrupted native
        # write. Never alter worker state, identity or protection policy.
        verify_protected_tree(root, recursive=False)
        verify_protected_tree(exchange, recursive=False)
        _normalize_owner(exchange, recursive=True)
    path = _session(session, create=True)
    _protected_directory(install_directory(), code=True)
    _protected_directory(install_directory() / 'releases', code=True)
    deployment = _deployment()
    _write(path / 'release.txt', deployment['release'] if deployment else '')
    _write(path / 'registered.txt', '1' if (data_directory() / 'gateway' / 'relay.json').exists() else '0')
    _write(path / 'readonly.txt', '1' if deployment and deployment.get('read_only') else '0')
    _write(path / 'ready.txt', '1')


def _service_action(action: str) -> None:
    import win32service
    import win32serviceutil
    names = (GATEWAY, WORKER) if action in ('stop', 'remove') else (WORKER, GATEWAY)
    for name in names:
        try:
            state = win32serviceutil.QueryServiceStatus(name)[1]
        except Exception as exc:
            if getattr(exc, 'winerror', None) == 1060:
                continue
            raise
        if action in ('stop', 'remove'):
            if state != win32service.SERVICE_STOPPED:
                win32serviceutil.StopService(name)
                win32serviceutil.WaitForServiceStatus(name, win32service.SERVICE_STOPPED, 90)
            if action == 'remove':
                win32serviceutil.RemoveService(name)
        else:
            if state != win32service.SERVICE_RUNNING:
                win32serviceutil.StartService(name)
                win32serviceutil.WaitForServiceStatus(name, win32service.SERVICE_RUNNING, 90)


def stage(session: str, version: str, unsigned_preview: bool) -> None:
    _session(session)
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Invalid release version')
    deployment = _deployment()
    if deployment:
        if deployment['version'] != version or bool(deployment.get('unsigned_preview')) != unsigned_preview:
            raise ValueError('Use the signed update lifecycle for version/trust changes; this wizard repairs only the same release')
        _service_action('stop')
    _protected_directory(install_directory() / 'releases' / version, code=True)


def _verify_package(package: Path, thumbprint: str, preview: bool) -> dict:
    verify_protected_tree(package)
    if preview:
        manifest = json.loads((package / 'preview.json').read_text(encoding='utf-8-sig'))
        if manifest.get('format') != 1 or manifest.get('unsigned_preview') is not True or manifest.get('read_only') is not True:
            raise ValueError('Not an explicitly monitoring-only preview package')
        expected = set()
        for item in manifest['files']:
            relative = item['path']
            if not isinstance(relative, str) or '\\' in relative or ':' in relative or any(p in ('', '.', '..') for p in relative.split('/')):
                raise ValueError('Unsafe preview manifest path')
            if relative.casefold() in expected:
                raise ValueError('Duplicate preview file')
            expected.add(relative.casefold())
            file = package / relative
            with file.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            if file.stat().st_size != item['size'] or digest != item['sha256']:
                raise ValueError('Preview payload checksum mismatch')
        actual = {p.relative_to(package).as_posix().casefold() for p in package.rglob('*') if p.is_file() and p != package / 'preview.json'}
        if actual != expected:
            raise ValueError('Preview payload inventory mismatch')
        return manifest
    normalized = thumbprint.replace(' ', '').upper()
    if not re.fullmatch(r'[0-9A-F]{40}', normalized):
        raise ValueError('An independently authenticated publisher certificate is required')
    helper = package / 'scripts' / 'deployment-common.ps1'
    # Authenticate before dot-sourcing. Read-Release retains all production manifest,
    # native-file signature, certificate validity/EKU and pinned-key checks.
    script = r'''
$ErrorActionPreference='Stop'
$helper=$env:RDP_SETUP_HELPER
$package=$env:RDP_SETUP_PACKAGE
$thumbprint=$env:RDP_SETUP_THUMBPRINT
$pinned=$env:RDP_SETUP_PINNED
$s=Get-AuthenticodeSignature -LiteralPath $helper
if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -ne $thumbprint) { throw 'Untrusted deployment helper' }
. $helper
Read-Release $package $thumbprint $pinned | Out-Null
'''
    import base64
    pinned = install_directory() / 'publisher.cer'
    environment = dict(os.environ, RDP_SETUP_HELPER=str(helper), RDP_SETUP_PACKAGE=str(package),
                       RDP_SETUP_THUMBPRINT=normalized, RDP_SETUP_PINNED=str(pinned) if pinned.exists() else '')
    command = [str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'),
               '-NoProfile', '-NonInteractive', '-EncodedCommand', base64.b64encode(script.encode('utf-16-le')).decode('ascii')]
    result = subprocess.run(command, capture_output=True, check=False, env=environment,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        raise PermissionError('Signed production package authentication failed')
    return json.loads((package / 'release.json').read_text(encoding='utf-8-sig'))


def _save_deployment(value: dict) -> None:
    _write(data_directory() / 'deployment.json', json.dumps(value, indent=2))
    protect_path(data_directory() / 'deployment.json', gateway_sid())


def _entrypoint(release: Path, *, remove=False) -> None:
    import winreg
    key_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE) as key:
        if remove:
            try:
                winreg.DeleteValue(key, 'RDPMonitorSessionHelper')
            except FileNotFoundError:
                pass
        else:
            executable = release / 'agent' / 'RDPMonitorAgent.exe'
            winreg.SetValueEx(key, 'RDPMonitorSessionHelper', 0, winreg.REG_SZ, f'"{executable}" session-helper')


def _ready(deployment: dict) -> None:
    from .__main__ import _gateway_status
    deadline = time.monotonic() + 90
    while True:
        try:
            proxy = WorkerProxy()
            state = proxy.rpc('local.status')
            if _gateway_status(proxy, deployment['host'], deployment['port'])['agent_id'] != state['agent_id']:
                raise ValueError('Gateway identity mismatch')
            return
        except Exception:
            if time.monotonic() >= deadline:
                raise RuntimeError('Worker/gateway did not reach authenticated local readiness') from None
            time.sleep(1)


def _installation_input(path: Path) -> tuple[str | None, bytes | None]:
    """Read the wizard's protected exchange, never an argv or network setup URI."""
    from relay.protocol import parse_invitation, parse_setup_invitation
    from .relay import relay_settings_path
    invitation_file = path / 'invitation.txt'
    if relay_settings_path(data_directory()).exists():
        if invitation_file.exists():
            raise ValueError('Already registered; use the explicit pair-installed flow')
        return None, None
    try:
        verify_protected_tree(invitation_file, recursive=False)
        if invitation_file.stat().st_size > 8192:
            raise ValueError('Invitation exceeds limit')
        invitation = invitation_file.read_text(encoding='utf-8-sig').strip()
        if invitation.startswith('rdpmonitor://setup?'):
            setup = parse_setup_invitation(invitation)
            return setup.installation_code, setup.pairing_secret
        parse_invitation(invitation, kind='install')
        return invitation, None
    finally:
        invitation_file.unlink(missing_ok=True)


def pair(session: str) -> None:
    path = _session(session)
    deployment = _deployment()
    if not deployment:
        raise ValueError('No installed deployment')
    verify_protected_tree(Path(deployment['release']))
    _ready(deployment)
    from .relay import publish_connection_code
    from relay.protocol import decode_secret
    key_file = path / 'pairing-key.txt'
    secret = None
    if key_file.exists():
        verify_protected_tree(key_file, recursive=False)
        if key_file.stat().st_size != 43:
            raise ValueError('Invalid protected pairing key')
        secret = decode_secret(key_file.read_text(encoding='ascii'))
    result = publish_connection_code(data_directory(), role='viewer' if deployment.get('read_only') else 'owner',
                                     ttl=300, secret=secret)
    _write(path / 'connection.txt', result['code'])
    _write(path / 'expires.txt', str(result['expires']))
    _write(path / 'automatic.txt', '1' if secret is not None else '0')
    _write(path / 'status.txt', 'Ready for automatic desktop enrollment. Return to Add machine on your desktop; no second code is needed.'
           if secret is not None else 'Connection code published. Private; expires after five minutes. Enrollment is single-use.')
    # Broker lookups are immutable. A later explicit refresh is a new manual
    # recovery code, never an attempt to overwrite the desktop's setup envelope.
    key_file.unlink(missing_ok=True)


def install(args) -> None:
    path = _session(args.session)
    invitation, pairing_secret = _installation_input(path)
    package = args.package.absolute()
    if package.parent != install_directory() / 'releases':
        raise ValueError('Payload must be installed in the protected versioned Program Files directory')
    if args.unsigned_preview and not args.preview_consent:
        raise PermissionError('Unsigned preview requires explicit affirmative monitoring-only consent')
    verify_protected_tree(package, recursive=False)
    _normalize_owner(package, recursive=True)
    manifest = _verify_package(package, args.publisher_thumbprint or '', args.unsigned_preview)
    if manifest['version'] != package.name:
        raise ValueError('Manifest version differs from protected release directory')
    deployment = _deployment()
    if deployment and (deployment['release'] != str(package) or bool(deployment.get('unsigned_preview')) != args.unsigned_preview):
        raise ValueError('Installed identity/trust cannot be replaced by the repair wizard')
    if deployment is None:
        deployment = {'version': manifest['version'], 'release': str(package), 'data_schema': int(manifest.get('data_schema', 1)),
                      'api': 1, 'host': '127.0.0.1', 'port': 8443, 'scope': 'Local',
                      'remote_addresses': [], 'interfaces': [], 'installed_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                      'unsigned_preview': args.unsigned_preview, 'read_only': bool(args.unsigned_preview or args.read_only),
                      'publisher_thumbprint': '' if args.unsigned_preview else args.publisher_thumbprint.replace(' ', '').upper()}
    if args.unsigned_preview:
        deployment['read_only'] = True
    _save_deployment(deployment)
    if not args.unsigned_preview:
        pinned = install_directory() / 'publisher.cer'
        if not pinned.exists():
            shutil.copyfile(package / 'publisher.cer', pinned)
            protect_path(pinned)
    register_services(package / 'agent' / 'RDPMonitorAgent.exe')
    from .relay import register_installation
    if invitation is not None:
        register_installation(invitation, data_directory())
        if pairing_secret is not None:
            from relay.protocol import encode_secret
            _write(path / 'pairing-key.txt', encode_secret(pairing_secret))
    _entrypoint(package)
    _service_action('start')
    _ready(deployment)
    pair(args.session)


def remove(package: Path) -> None:
    deployment = _deployment()
    if not deployment or Path(deployment['release']) != package.absolute():
        raise ValueError('Uninstaller does not match the active release')
    _verify_package(package, deployment.get('publisher_thumbprint', ''), bool(deployment.get('unsigned_preview')))
    _service_action('remove')
    _entrypoint(package, remove=True)
    # Retain identities, enrolled devices, publisher trust, deployment recovery
    # record, firewall policy and backup repositories. Inno removes only its files.


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog='rdpmonitor-agent setup')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('surface', help='Describe setup surface without filesystem or SCM mutation')
    for name in ('prepare', 'pair', 'cleanup'):
        command = commands.add_parser(name)
        command.add_argument('--session', required=True)
    command = commands.add_parser('stage')
    command.add_argument('--session', required=True)
    command.add_argument('--version', required=True)
    command.add_argument('--unsigned-preview', action='store_true')
    command = commands.add_parser('install')
    command.add_argument('--session', required=True)
    command.add_argument('--package', type=Path, required=True)
    command.add_argument('--publisher-thumbprint')
    command.add_argument('--unsigned-preview', action='store_true')
    command.add_argument('--preview-consent', action='store_true')
    command.add_argument('--read-only', action='store_true')
    command = commands.add_parser('remove')
    command.add_argument('--package', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == 'surface':
        print(json.dumps({'protocol': 1, 'commands': ['prepare', 'stage', 'install', 'pair', 'cleanup', 'remove'],
                          'secret_exchange': 'protected ProgramData setup session files', 'preview': 'forced read_only'}))
        return 0
    path = None
    try:
        if not current_identity()['admin']:
            raise PermissionError('Setup requires an elevated local administrator')
        if args.command == 'prepare':
            prepare(args.session)
        elif args.command == 'stage':
            stage(args.session, args.version, args.unsigned_preview)
        elif args.command == 'install':
            install(args)
        elif args.command == 'pair':
            pair(args.session)
        elif args.command == 'cleanup':
            shutil.rmtree(_session(args.session))
        elif args.command == 'remove':
            remove(args.package)
        return 0
    except Exception as exc:
        # Never stringify an exception from a network/crypto/file operation: it
        # may embed invitation fragments, response data or credentials.
        print(f'RDPMonitor setup failed [{type(exc).__name__}]. No secret details were logged.', file=sys.stderr)
        if hasattr(args, 'session'):
            try:
                path = _session(args.session)
                _write(path / 'status.txt', f'Setup failed ({type(exc).__name__}). Registration/data were preserved. Repair or generate a fresh code after resolving connectivity/signature/service prerequisites.')
            except Exception:
                pass
        return 1
