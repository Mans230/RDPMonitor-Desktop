"""Elevated native-setup helper. Secret exchange is confined to protected files.

The native wizard invokes this module through the frozen agent. No command accepts
an invitation, route credential or connection code on its command line.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from urllib.parse import urlsplit

from .contracts import OperationError

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
    if result.get('scope') == 'Direct':
        _direct_network_values(result)
        if result.get('read_only') is not True or result.get('component') != 'guest':
            raise PermissionError('Direct deployments require the monitoring-only guest component')
    elif result.get('host') != '127.0.0.1' or result.get('scope') != 'Local':
        raise ValueError('This wizard supports relay loopback and direct guest deployments only')
    if result.get('unsigned_preview') and result.get('read_only') is not True:
        raise PermissionError('Unsafe preview deployment')
    return result


def _require_fresh() -> None:
    """Command provisioning never repairs or replaces a retained machine identity."""
    root = data_directory()
    for relative in ('deployment.json', 'identity.json', 'tls', 'direct-bootstrap.json',
                     'state.sqlite3', 'state.sqlite3-wal', 'state.sqlite3-shm',
                     'state.sqlite3-journal', 'gateway/relay.json'):
        if (root / relative).exists():
            raise ValueError('Command setup requires a fresh machine; use interactive maintenance')
    import win32serviceutil
    for name in (WORKER, GATEWAY):
        try:
            win32serviceutil.QueryServiceStatus(name)
        except Exception as exc:
            if getattr(exc, 'winerror', None) == 1060:
                continue
            raise
        raise ValueError('Command setup cannot replace existing services')


def _direct_metadata(spec: dict) -> dict:
    endpoint = urlsplit(spec['endpoint'])
    return {'scope': 'Direct', 'endpoint': spec['endpoint'],
            'host': '::' if ':' in endpoint.hostname else '0.0.0.0',
            'port': endpoint.port, 'remote_addresses': [spec['source']], 'interfaces': []}


def _direct_network_values(deployment: dict) -> tuple[int, str]:
    """Fail closed before passing retained metadata to Windows networking."""
    try:
        endpoint = urlsplit(deployment['endpoint'])
        addresses = deployment['remote_addresses']
        port = deployment['port']
        if (deployment['scope'] != 'Direct' or type(port) is not int or not 1024 <= port <= 65535
                or endpoint.scheme != 'https' or not endpoint.hostname or endpoint.port != port
                or endpoint.username is not None or endpoint.password is not None
                or endpoint.path or endpoint.query or endpoint.fragment
                or deployment['host'] != ('::' if ':' in endpoint.hostname else '0.0.0.0')
                or deployment.get('interfaces') != [] or not isinstance(addresses, list) or len(addresses) != 1):
            raise ValueError
        source = ipaddress.ip_address(addresses[0])
        if str(source) != addresses[0] or source.is_unspecified or source.is_multicast:
            raise ValueError
        if source.is_loopback:
            if not ipaddress.ip_address(endpoint.hostname).is_loopback:
                raise ValueError
        if (source.version == 6) != (deployment['host'] == '::'):
            raise ValueError
        return port, str(source)
    except (ValueError, TypeError, KeyError):
        raise OperationError('direct_network_invalid',
                             'Direct access requires one literal desktop source IP matching the listener address family.', 400) from None


def _direct_network(action: str, deployment: dict, program: Path | None = None, *, existing=False) -> None:
    port, source = _direct_network_values(deployment)
    root = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent.parent))
    script = root / 'scripts' / 'direct-network.ps1'
    powershell = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    arguments = [str(powershell), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                 '-File', str(script), '-Action', action, '-Port', str(port), '-Source', source]
    if program is not None:
        arguments.extend(['-Program', str(program)])
    if existing:
        arguments.append('-Existing')
    result = subprocess.run(arguments, capture_output=True, check=False, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        raise OperationError('direct_firewall_required',
                             'Direct firewall prerequisites failed. Check Windows Defender Firewall and the owned RDPMonitor direct rule; provider/router rules must be configured separately.', 503)


def _check_direct_network(deployment: dict, *, existing=False) -> None:
    import psutil
    port, _ = _direct_network_values(deployment)
    try:
        occupied = any(connection.status == psutil.CONN_LISTEN and connection.laddr.port == port
                       for connection in psutil.net_connections(kind='tcp'))
    except (OSError, psutil.Error):
        raise OperationError('direct_network_unavailable', 'Cannot inspect TCP listeners. Run elevated and check networking prerequisites.', 503) from None
    if occupied:
        raise OperationError('direct_port_in_use', 'The direct HTTPS port is already listening. Stop the conflicting service or prepare a command using another port.', 409)
    _direct_network('Check', deployment, existing=existing)


def _direct_input(path: Path) -> dict:
    from .direct import parse_direct_setup_uri, resolve_desktop_source
    invitation_file = path / 'invitation.txt'
    verify_protected_tree(invitation_file, recursive=False)
    if invitation_file.stat().st_size > 4096:
        raise OperationError('direct_setup_invalid', 'Direct command exceeds the supported limit.')
    spec = parse_direct_setup_uri(invitation_file.read_text(encoding='utf-8'))
    source_file = path / 'direct-source.txt'
    verify_protected_tree(source_file, recursive=False)
    if source_file.stat().st_size > 45:
        raise OperationError('direct_source_required', 'Prepare a new command with an explicit desktop source IP.')
    spec['source'] = source_file.read_text(encoding='ascii')
    spec['source'] = resolve_desktop_source(spec)
    return spec


def _decode_command(value: str | None) -> str:
    """Decode the bounded canonical transport without including it in errors."""
    from relay.protocol import parse_setup_invitation
    from .direct import parse_direct_setup_uri
    if not isinstance(value, str) or not 1 <= len(value) <= 5462 or not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        raise ValueError('Invalid command setup capability')
    try:
        raw = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
        if len(raw) > 4096 or base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=') != value:
            raise ValueError
        invitation = raw.decode('utf-8', errors='strict')
        if invitation != invitation.strip():
            raise ValueError
        if invitation.startswith('rdpmonitor://direct?'):
            parse_direct_setup_uri(invitation)
        else:
            parse_setup_invitation(invitation)
        return invitation
    except (ValueError, UnicodeError):
        raise ValueError('Invalid command setup capability') from None


def import_command(session: str, value: str | None, *, unsigned_preview=False, preview_consent=False) -> None:
    # Validate before creating directories, reading SCM, or touching machine state.
    invitation = _decode_command(value)
    direct = None
    if invitation.startswith('rdpmonitor://direct?'):
        from .direct import parse_direct_setup_uri, resolve_desktop_source
        direct = parse_direct_setup_uri(invitation)
        direct['source'] = resolve_desktop_source(direct)
        _check_direct_network(_direct_metadata(direct))
    if unsigned_preview and not preview_consent:
        raise PermissionError('Unsigned command setup requires explicit monitoring-only consent')
    if not re.fullmatch(r'[0-9a-f]{32}', session):
        raise ValueError('Invalid setup session identifier')
    _require_fresh()
    path = _session(session, create=True)
    try:
        _write(path / 'invitation.txt', invitation)
        if direct is not None:
            _write(path / 'direct-source.txt', direct['source'])
        _write(path / 'command.txt', '1')
        _write(path / 'registered.txt', '0')
    except Exception:
        shutil.rmtree(path)
        raise


def _command_session(path: Path) -> None:
    if (path / 'command.txt').read_text(encoding='ascii') != '1':
        raise ValueError('Missing validated command setup session')
    _require_fresh()


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
    _write(path / 'registered.txt', '1' if deployment or (data_directory() / 'gateway' / 'relay.json').exists() else '0')
    _write(path / 'direct.txt', '1' if deployment and deployment.get('scope') == 'Direct' else '0')
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


def stage(session: str, version: str, unsigned_preview: bool, *, cmd_bootstrap=False, guest_only=False) -> None:
    path = _session(session)
    if cmd_bootstrap and not guest_only:
        raise ValueError('Command staging requires the explicit guest component')
    if cmd_bootstrap:
        _command_session(path)
        invitation = (path / 'invitation.txt').read_text(encoding='utf-8')
        _decode_command(base64.urlsafe_b64encode(invitation.encode('utf-8')).decode('ascii').rstrip('='))
        if invitation.startswith('rdpmonitor://direct?'):
            direct = _direct_input(path)
            _check_direct_network(_direct_metadata(direct))
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Invalid release version')
    deployment = _deployment()
    if deployment:
        component = 'guest' if guest_only else 'suite'
        if (deployment['version'] != version or bool(deployment.get('unsigned_preview')) != unsigned_preview
                or deployment.get('component', 'suite') != component):
            raise ValueError('Use the signed update lifecycle for version/trust changes; this wizard repairs only the same release')
        _service_action('stop')
    _protected_directory(install_directory(), code=True)
    _protected_directory(install_directory() / 'releases', code=True)
    _protected_directory(install_directory() / 'releases' / version, code=True)


def _verify_package(package: Path, thumbprint: str, preview: bool, *, component='suite') -> dict:
    verify_protected_tree(package)
    if component not in ('guest', 'suite'):
        raise ValueError('Invalid package component')
    if component == 'guest' and (package / 'client').exists():
        raise ValueError('Guest package contains a desktop client')
    if preview:
        manifest = json.loads((package / 'preview.json').read_text(encoding='utf-8-sig'))
        if manifest.get('format') != 1 or manifest.get('unsigned_preview') is not True or manifest.get('read_only') is not True:
            raise ValueError('Not an explicitly monitoring-only preview package')
        release = json.loads((package / 'release.json').read_text(encoding='utf-8-sig'))
        if (manifest.get('component', 'suite') != component or release.get('component', 'suite') != component
                or manifest.get('version') != release.get('version')):
            raise ValueError('Preview release component/version mismatch')
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
Read-Release $package $thumbprint $pinned -Component $env:RDP_SETUP_COMPONENT | Out-Null
'''
    pinned = install_directory() / 'publisher.cer'
    environment = dict(os.environ, RDP_SETUP_HELPER=str(helper), RDP_SETUP_PACKAGE=str(package),
                       RDP_SETUP_THUMBPRINT=normalized, RDP_SETUP_PINNED=str(pinned) if pinned.exists() else '',
                       RDP_SETUP_COMPONENT=component)
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
    try:
        if relay_settings_path(data_directory()).exists():
            if invitation_file.exists():
                raise ValueError('Already registered; use the explicit pair-installed flow')
            return None, None
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
    if deployment.get('scope') == 'Direct':
        result = WorkerProxy().rpc('pairing.begin', {'ttl_seconds': 300, 'role': 'viewer'})
        _write(path / 'connection.txt', f"HTTPS address: {deployment['endpoint']}\nSHA256 fingerprint: {result['fingerprint']}\nOne-use pairing code: {result['code']}")
        _write(path / 'expires.txt', str(result['expires']))
        _write(path / 'automatic.txt', '0')
        _write(path / 'direct.txt', '1')
        _write(path / 'status.txt', 'Manual direct approval created. Use Advanced direct HTTPS on the desktop and verify this fingerprint. Viewer only; private, single-use, expires in five minutes. The existing desktop source firewall restriction remains unchanged.')
        return
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
    command = bool(getattr(args, 'cmd_bootstrap', False))
    expected_component = 'guest' if getattr(args, 'guest_only', False) else 'suite'
    if command and expected_component != 'guest':
        raise ValueError('Command setup requires the explicit guest component')
    if command:
        _command_session(path)
        if not args.read_only:
            raise PermissionError('Command setup is monitoring-only')
    if args.unsigned_preview and not args.preview_consent:
        raise PermissionError('Unsigned preview requires explicit affirmative monitoring-only consent')
    deployment = _deployment()
    direct = None
    if (path / 'direct-source.txt').exists():
        if not command:
            raise ValueError('Direct provisioning requires the fresh guest command path')
        direct = _direct_input(path)
        _check_direct_network(_direct_metadata(direct))
        invitation, pairing_secret = None, None
    elif deployment and deployment.get('scope') == 'Direct':
        if (path / 'invitation.txt').exists():
            raise ValueError('Repair cannot replace the installed direct identity')
        invitation, pairing_secret = None, None
        _check_direct_network(deployment, existing=True)
    else:
        invitation, pairing_secret = _installation_input(path)
    if command and direct is None and (invitation is None or pairing_secret is None):
        raise ValueError('Command setup requires an automatic HTTPS setup invitation')
    package = args.package.absolute()
    if package.parent != install_directory() / 'releases':
        raise ValueError('Payload must be installed in the protected versioned Program Files directory')
    verify_protected_tree(package, recursive=False)
    _normalize_owner(package, recursive=True)
    manifest = _verify_package(package, args.publisher_thumbprint or '', args.unsigned_preview, component=expected_component)
    component = manifest.get('component', 'suite')
    if component != expected_component or (command and component != 'guest'):
        raise ValueError('Package component does not permit command provisioning')
    if component == 'guest' and (package / 'client').exists():
        raise ValueError('Guest package contains a desktop client')
    if manifest['version'] != package.name:
        raise ValueError('Manifest version differs from protected release directory')
    if deployment and (deployment['release'] != str(package) or bool(deployment.get('unsigned_preview')) != args.unsigned_preview
                       or deployment.get('component', 'suite') != component):
        raise ValueError('Installed identity/trust cannot be replaced by the repair wizard')
    if deployment is None:
        deployment = {'version': manifest['version'], 'release': str(package), 'component': component,
                      'data_schema': int(manifest.get('data_schema', 1)),
                      'api': 1, 'host': '127.0.0.1', 'port': 8443, 'scope': 'Local',
                      'remote_addresses': [], 'interfaces': [], 'installed_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                      'unsigned_preview': args.unsigned_preview, 'read_only': bool(args.unsigned_preview or args.read_only),
                      'publisher_thumbprint': '' if args.unsigned_preview else args.publisher_thumbprint.replace(' ', '').upper()}
    if direct is not None:
        # Recheck freshness after package authentication, immediately before local
        # identity creation. Provisioning itself also refuses retained state.
        _require_fresh()
        from .direct import provision_direct_bootstrap
        deployment.update(provision_direct_bootstrap(data_directory(), direct))
        deployment['read_only'] = True
        (path / 'invitation.txt').unlink(missing_ok=True)
        (path / 'direct-source.txt').unlink(missing_ok=True)
    if args.unsigned_preview or command:
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
    if deployment.get('scope') == 'Direct':
        _direct_network('Configure', deployment, package / 'agent' / 'RDPMonitorAgent.exe', existing=direct is None)
    _entrypoint(package)
    _service_action('start')
    _ready(deployment)
    if deployment.get('scope') == 'Direct':
        _write(path / 'direct.txt', '1')
        _write(path / 'automatic.txt', '1')
        _write(path / 'connection.txt', '')
        _write(path / 'expires.txt', '')
        _write(path / 'status.txt', 'Direct guest installed and locally ready. Return to Add machine on the originating desktop to complete authentication. This is not confirmation of a desktop connection. If unreachable, allow this HTTPS port in your provider/router firewall for the same desktop source IP; no provider rules were changed.')
    else:
        pair(args.session)


def remove(package: Path) -> None:
    deployment = _deployment()
    if not deployment or Path(deployment['release']) != package.absolute():
        raise ValueError('Uninstaller does not match the active release')
    _verify_package(package, deployment.get('publisher_thumbprint', ''), bool(deployment.get('unsigned_preview')),
                    component=deployment.get('component', 'suite'))
    _service_action('remove')
    _entrypoint(package, remove=True)
    if deployment.get('scope') == 'Direct':
        _direct_network('Remove', deployment, existing=True)
    # Retain identities, enrolled devices, publisher trust, deployment recovery
    # record, unrelated firewall policy and backup repositories.


_SAFE_DIRECT_ERRORS = {
    'direct_setup_invalid': 'Invalid direct command. Prepare and copy a new command from the originating desktop.',
    'direct_setup_expired': 'Direct command expired. Prepare a fresh command and check both clocks.',
    'direct_source_required': 'No unique active RDP TCP peer was found. Set the advanced desktop source IP explicitly and prepare a new command.',
    'direct_state_exists': 'This VM retains an identity. Use same-release maintenance; command setup never overwrites it.',
    'direct_network_invalid': 'Use one literal desktop source IP with the same address family as the endpoint. DNS endpoints bind IPv4; IPv6 requires an explicit IPv6 endpoint and reachable source.',
    'direct_network_unavailable': 'Cannot inspect listeners. Run elevated and check Windows networking prerequisites.',
    'direct_port_in_use': 'The HTTPS port is already listening. Stop the conflicting service or prepare a command using another port.',
    'direct_firewall_required': 'Check Windows Defender Firewall and the owned single-source direct rule. Configure provider/router reachability separately.',
}
_DIRECT_EXIT_CODES = {code: 70 + index for index, code in enumerate(_SAFE_DIRECT_ERRORS)}


def main(argv=None) -> int:
    # Consume immediately, including malformed argv, authorization and parse failures.
    value = os.environ.pop('RDP_MONITOR_SETUP', None)
    preview_accept = os.environ.pop('RDP_MONITOR_PREVIEW_ACCEPT', None)
    parser = argparse.ArgumentParser(prog='rdpmonitor-agent setup')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('surface', help='Describe setup surface without filesystem or SCM mutation')
    for name in ('prepare', 'pair', 'cleanup', 'import-command'):
        command = commands.add_parser(name)
        command.add_argument('--session', required=True)
        if name == 'import-command':
            command.add_argument('--unsigned-preview', action='store_true')
            command.add_argument('--preview-consent', action='store_true')
    command = commands.add_parser('stage')
    command.add_argument('--session', required=True)
    command.add_argument('--version', required=True)
    command.add_argument('--unsigned-preview', action='store_true')
    command.add_argument('--cmd-bootstrap', action='store_true')
    command.add_argument('--guest-only', action='store_true')
    command = commands.add_parser('install')
    command.add_argument('--session', required=True)
    command.add_argument('--package', type=Path, required=True)
    command.add_argument('--publisher-thumbprint')
    command.add_argument('--unsigned-preview', action='store_true')
    command.add_argument('--preview-consent', action='store_true')
    command.add_argument('--read-only', action='store_true')
    command.add_argument('--cmd-bootstrap', action='store_true')
    command.add_argument('--guest-only', action='store_true')
    command = commands.add_parser('remove')
    command.add_argument('--package', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == 'surface':
        print(json.dumps({'protocol': 2, 'commands': ['prepare', 'import-command', 'stage', 'install', 'pair', 'cleanup', 'remove'],
                          'secret_exchange': 'protected ProgramData setup session files', 'preview': 'forced read_only',
                          'command_setup': 'fresh guest component only; forced viewer'}))
        return 0
    path = None
    try:
        if not current_identity()['admin']:
            raise PermissionError('Setup requires an elevated local administrator')
        if args.command == 'import-command':
            import_command(args.session, value, unsigned_preview=args.unsigned_preview,
                           preview_consent=args.preview_consent and preview_accept == 'I_ACCEPT_UNSIGNED_MONITORING_ONLY')
        elif args.command == 'prepare':
            prepare(args.session)
        elif args.command == 'stage':
            stage(args.session, args.version, args.unsigned_preview, cmd_bootstrap=args.cmd_bootstrap,
                  guest_only=args.guest_only)
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
        code = exc.code if isinstance(exc, OperationError) and exc.code in _SAFE_DIRECT_ERRORS else type(exc).__name__
        detail = _SAFE_DIRECT_ERRORS.get(code, 'Resolve connectivity, signature, service or protected-state prerequisites before same-release maintenance.')
        print(f'RDPMonitor setup failed [{code}]. {detail} No secret details were logged.', file=sys.stderr)
        if hasattr(args, 'session') and args.command != 'import-command':
            try:
                path = _session(args.session)
                _write(path / 'status.txt', f'Setup failed [{code}]. {detail} Retained identities/data were not replaced. Do not treat this as a completed desktop connection.')
            except Exception:
                pass
        return _DIRECT_EXIT_CODES.get(code, 1)
