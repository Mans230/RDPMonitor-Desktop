"""Direct native setup boundaries; never install services or firewall rules."""
from __future__ import annotations

from argparse import Namespace
import base64
from contextlib import ExitStack, redirect_stderr
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock
import zlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from agent import setup
from agent.contracts import OperationError


def direct_command(source='198.51.100.20'):
    server = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Desktop')])).sign(client, hashes.SHA256())
    spec = {'v': 1, 'endpoint': 'https://203.0.113.10:8443',
            'server_key': server.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
            'csr': csr.public_bytes(serialization.Encoding.PEM).decode(),
            'nonce': base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='),
            'expires': int(time.time()) + 1800, 'source': source}
    compressor = zlib.compressobj(wbits=-15)
    compressed = compressor.compress(json.dumps(spec, separators=(',', ':')).encode()) + compressor.flush()
    uri = 'rdpmonitor://direct?v=1#' + base64.urlsafe_b64encode(compressed).decode().rstrip('=')
    return uri, base64.urlsafe_b64encode(uri.encode()).decode().rstrip('=')


class DirectSetupTests(unittest.TestCase):
    def test_source_resolution_failure_does_not_create_machine_or_session_state(self):
        _, command = direct_command('auto')
        with mock.patch('agent.direct.resolve_desktop_source', side_effect=OperationError('direct_source_required', 'safe')), \
                mock.patch.object(setup, '_session') as session, \
                mock.patch.object(setup, '_require_fresh') as fresh, \
                mock.patch.object(setup, '_direct_network') as network:
            with self.assertRaises(OperationError) as caught:
                setup.import_command('a' * 32, command)
            self.assertEqual(caught.exception.code, 'direct_source_required')
            session.assert_not_called()
            fresh.assert_not_called()
            network.assert_not_called()

    def test_command_import_retains_resolved_source_only_in_protected_session(self):
        uri, command = direct_command('auto')
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch('agent.direct.resolve_desktop_source', return_value='198.51.100.20'), \
                mock.patch.object(setup, '_session', return_value=Path(temporary)), \
                mock.patch.object(setup, '_require_fresh'), \
                mock.patch.object(setup, '_check_direct_network'), \
                mock.patch.object(setup, 'verify_protected_tree'), \
                mock.patch.object(setup, 'protect_path'):
            setup.import_command('a' * 32, command)
            self.assertEqual((Path(temporary) / 'invitation.txt').read_text(), uri)
            self.assertEqual((Path(temporary) / 'direct-source.txt').read_text(), '198.51.100.20')
            self.assertEqual(set(Path(temporary).iterdir()), {Path(temporary) / name for name in
                ('invitation.txt', 'direct-source.txt', 'command.txt', 'registered.txt')})

    def test_retained_partial_identity_is_never_overwritten_by_command_setup(self):
        for relative in ('tls', 'direct-bootstrap.json', 'state.sqlite3', 'state.sqlite3-wal'):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / relative
                path.write_bytes(b'recoverable-state')
                with mock.patch.object(setup, 'data_directory', return_value=Path(temporary)):
                    with self.assertRaises(ValueError):
                        setup._require_fresh()
                self.assertEqual(path.read_bytes(), b'recoverable-state')

    def test_direct_network_rejects_broad_ambiguous_or_mismatched_sources(self):
        base = setup._direct_metadata({'endpoint': 'https://203.0.113.10:8443', 'source': '198.51.100.20'})
        self.assertEqual(setup._direct_network_values(base), (8443, '198.51.100.20'))
        for sources in ([], ['Any'], ['0.0.0.0'], ['198.51.100.0/24'], ['198.51.100.20', '198.51.100.21'], ['::1'], ['127.0.0.1']):
            with self.subTest(sources=sources), self.assertRaises(OperationError):
                setup._direct_network_values({**base, 'remote_addresses': sources})

    def test_port_conflict_is_reported_before_firewall_is_opened(self):
        import psutil
        deployment = setup._direct_metadata({'endpoint': 'https://203.0.113.10:8443', 'source': '198.51.100.20'})
        connection = Namespace(status=psutil.CONN_LISTEN, laddr=Namespace(port=8443))
        with mock.patch.object(psutil, 'net_connections', return_value=[connection]), \
                mock.patch.object(setup, '_direct_network') as firewall:
            with self.assertRaises(OperationError) as caught:
                setup._check_direct_network(deployment)
            self.assertEqual(caught.exception.code, 'direct_port_in_use')
            firewall.assert_not_called()

    def test_signed_direct_command_installs_guest_viewer_without_public_pairing(self):
        uri, _ = direct_command()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / 'releases' / '1.0.1'
            package.mkdir(parents=True)
            (root / 'publisher.cer').write_bytes(b'test-pinned-publisher')
            (root / 'invitation.txt').write_text(uri)
            (root / 'direct-source.txt').write_text('198.51.100.20')
            (root / 'command.txt').write_text('1')
            metadata = setup._direct_metadata({'endpoint': 'https://203.0.113.10:8443', 'source': '198.51.100.20'})
            args = Namespace(session='a' * 32, package=package, guest_only=True, cmd_bootstrap=True,
                read_only=True, unsigned_preview=False, preview_consent=False, publisher_thumbprint='AB' * 20)
            with ExitStack() as stack:
                for name in ('verify_protected_tree', '_normalize_owner', 'register_services', '_entrypoint',
                             '_service_action', '_ready', 'protect_path', '_check_direct_network', '_require_fresh'):
                    stack.enter_context(mock.patch.object(setup, name))
                stack.enter_context(mock.patch.object(setup, '_session', return_value=root))
                stack.enter_context(mock.patch.object(setup, 'data_directory', return_value=root))
                stack.enter_context(mock.patch.object(setup, 'install_directory', return_value=root))
                stack.enter_context(mock.patch.object(setup, '_deployment', return_value=None))
                stack.enter_context(mock.patch.object(setup, '_verify_package', return_value={'version': '1.0.1', 'component': 'guest'}))
                save = stack.enter_context(mock.patch.object(setup, '_save_deployment'))
                stack.enter_context(mock.patch.object(setup, '_direct_network'))
                stack.enter_context(mock.patch('agent.direct.provision_direct_bootstrap', return_value=metadata))
                pairing = stack.enter_context(mock.patch.object(setup, 'WorkerProxy'))
                relay = stack.enter_context(mock.patch('agent.relay.register_installation'))
                setup.install(args)
                stored = save.call_args.args[0]
                self.assertEqual(stored['scope'], 'Direct')
                self.assertEqual(stored['endpoint'], metadata['endpoint'])
                self.assertEqual(stored['remote_addresses'], ['198.51.100.20'])
                self.assertEqual(stored['component'], 'guest')
                self.assertIs(stored['read_only'], True)
                self.assertIs(stored['unsigned_preview'], False)
                pairing.assert_not_called()
                relay.assert_not_called()
                self.assertFalse((root / 'invitation.txt').exists())
                self.assertFalse((root / 'direct-source.txt').exists())
                self.assertEqual((root / 'automatic.txt').read_text(), '1')

    def test_direct_repair_preserves_identity_endpoint_and_source_without_public_pairing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / 'releases' / '1.0.1'
            package.mkdir(parents=True)
            identity = root / 'identity.json'
            identity.write_bytes(b'retained-private-identity')
            (root / 'publisher.cer').write_bytes(b'test-pinned-publisher')
            deployment = {'version': '1.0.1', 'release': str(package), 'component': 'guest',
                'unsigned_preview': False, 'read_only': True,
                **setup._direct_metadata({'endpoint': 'https://203.0.113.10:8443', 'source': '198.51.100.20'})}
            args = Namespace(session='a' * 32, package=package, guest_only=True, cmd_bootstrap=False,
                read_only=True, unsigned_preview=False, preview_consent=False, publisher_thumbprint='AB' * 20)
            with ExitStack() as stack:
                for name in ('verify_protected_tree', '_normalize_owner', 'register_services', '_entrypoint',
                             '_service_action', '_ready', 'protect_path', '_check_direct_network'):
                    stack.enter_context(mock.patch.object(setup, name))
                stack.enter_context(mock.patch.object(setup, '_session', return_value=root))
                stack.enter_context(mock.patch.object(setup, 'data_directory', return_value=root))
                stack.enter_context(mock.patch.object(setup, 'install_directory', return_value=root))
                stack.enter_context(mock.patch.object(setup, '_deployment', return_value=deployment))
                stack.enter_context(mock.patch.object(setup, '_verify_package', return_value={'version': '1.0.1', 'component': 'guest'}))
                save = stack.enter_context(mock.patch.object(setup, '_save_deployment'))
                firewall = stack.enter_context(mock.patch.object(setup, '_direct_network'))
                provision = stack.enter_context(mock.patch('agent.direct.provision_direct_bootstrap'))
                pairing = stack.enter_context(mock.patch.object(setup, 'WorkerProxy'))
                setup.install(args)
                provision.assert_not_called()
                pairing.assert_not_called()
                self.assertEqual(save.call_args.args[0], deployment)
                self.assertEqual(firewall.call_args.args, ('Configure', deployment, package / 'agent' / 'RDPMonitorAgent.exe'))
                self.assertTrue(firewall.call_args.kwargs['existing'])
                self.assertEqual(identity.read_bytes(), b'retained-private-identity')
                self.assertEqual((root / 'connection.txt').read_text(), '')
                self.assertIn('not confirmation', (root / 'status.txt').read_text())

    def test_explicit_direct_manual_pairing_returns_actual_details_without_relay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            deployment = {'release': str(root), 'scope': 'Direct', 'endpoint': 'https://203.0.113.10:8443', 'read_only': True}
            result = {'fingerprint': 'ab' * 32, 'code': 'one-use-private-code', 'expires': '2026-10-17T14:00:00Z'}
            with mock.patch.object(setup, '_session', return_value=root), \
                    mock.patch.object(setup, '_deployment', return_value=deployment), \
                    mock.patch.object(setup, 'verify_protected_tree'), \
                    mock.patch.object(setup, 'protect_path'), \
                    mock.patch.object(setup, '_ready'), \
                    mock.patch.object(setup, 'WorkerProxy') as worker, \
                    mock.patch('agent.relay.publish_connection_code') as relay:
                worker.return_value.rpc.return_value = result
                setup.pair('a' * 32)
                worker.return_value.rpc.assert_called_once_with('pairing.begin', {'ttl_seconds': 300, 'role': 'viewer'})
                relay.assert_not_called()
                details = (root / 'connection.txt').read_text()
                self.assertIn(deployment['endpoint'], details)
                self.assertIn(result['fingerprint'], details)
                self.assertIn(result['code'], details)
                self.assertEqual((root / 'expires.txt').read_text(), result['expires'])

    def test_failure_diagnostics_never_include_payload_or_exception_text(self):
        with mock.patch.dict(os.environ, {'RDP_MONITOR_SETUP': 'private-payload'}), \
                mock.patch.object(setup, 'current_identity', return_value={'admin': True}), \
                mock.patch.object(setup, 'import_command', side_effect=OperationError('direct_source_required', 'SECRET')), \
                redirect_stderr(io.StringIO()) as diagnostics:
            self.assertEqual(setup.main(['import-command', '--session', 'a' * 32]), setup._DIRECT_EXIT_CODES['direct_source_required'])
            self.assertIn('direct_source_required', diagnostics.getvalue())
            self.assertNotIn('SECRET', diagnostics.getvalue())
            self.assertNotIn('private-payload', diagnostics.getvalue())
            self.assertNotIn('RDP_MONITOR_SETUP', os.environ)


class DirectFirewallPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.powershell = shutil.which('powershell.exe') or shutil.which('pwsh')
        if not cls.powershell:
            raise unittest.SkipTest('PowerShell is required for isolated firewall-policy behavior tests')

    def invoke(self, source, *, existing=False, action='Configure', rule_source='198.51.100.20',
               disabled_profile=0, permissive_profile=0, local_rules=True):
        script = Path(__file__).resolve().parents[1] / 'scripts' / 'direct-network.ps1'
        with tempfile.TemporaryDirectory() as temporary:
            program = Path(temporary) / 'RDPMonitorAgent.exe'
            program.write_bytes(b'not-executed')
            # All Windows networking commands are replaced in-process; no host policy is queried or changed.
            harness = r"""
$ErrorActionPreference = 'Stop'
function Import-Module {}
function Get-Service { [pscustomobject]@{Status='Running'} }
function New-Object {
    param($ComObject)
    if ($ComObject -ne 'HNetCfg.FwPolicy2') { throw 'Unexpected COM activation' }
    $policy = [pscustomobject]@{}
    $policy | Add-Member -MemberType ScriptMethod -Name FirewallEnabled -Value { param($profile) return $profile -ne DISABLED_PROFILE }
    $policy | Add-Member -MemberType ScriptMethod -Name DefaultInboundAction -Value { param($profile) if ($profile -eq PERMISSIVE_PROFILE) { return 1 }; return 0 }
    $policy | Add-Member -MemberType ScriptMethod -Name BlockAllInboundTraffic -Value { param($profile) return $false }
    return $policy
}
function Get-NetFirewallProfile {
    foreach ($profile in @(1,2,4)) { [pscustomobject]@{AllowInboundRules='True';AllowLocalFirewallRules='LOCAL_RULES'} }
}
function Get-NetFirewallRule {
    if ('EXISTING' -eq 'True') { [pscustomobject]@{Name='RDPMonitor-Gateway-Direct';Group='RDPMonitor Direct';Direction='Inbound';Action='Allow';Profile='Any';Enabled='True'} }
}
function Get-NetFirewallPortFilter { [pscustomobject]@{Protocol='TCP';LocalPort='8443'} }
function Get-NetFirewallAddressFilter { [pscustomobject]@{LocalAddress='Any';RemoteAddress='RULESOURCE'} }
function Get-NetFirewallApplicationFilter { [pscustomobject]@{Program='C:\\Program Files\\RDPMonitor\\old\\RDPMonitorAgent.exe'} }
function Get-NetFirewallInterfaceFilter { [pscustomobject]@{InterfaceAlias='Any'} }
function Set-NetFirewallRule {
    param([Parameter(ValueFromPipeline=$true)]$InputObject,$Program)
    [Console]::WriteLine('unexpected firewall mutation')
}
function Remove-NetFirewallRule {
    param([Parameter(ValueFromPipeline=$true)]$InputObject)
    [Console]::WriteLine('unexpected firewall mutation')
}
function New-NetFirewallRule { param($Name,$DisplayName,$Group,$PolicyStore,$Direction,$Action,$Enabled,$Protocol,$LocalPort,$RemoteAddress,$Profile,$Program,$EdgeTraversalPolicy)
    [Console]::WriteLine('unexpected firewall mutation')
}
& 'SCRIPT' -Action ACTION -Port 8443 -Source 'SOURCE' -Program 'PROGRAM' SWITCH
""".replace('SCRIPT', str(script).replace("'", "''")).replace('RULESOURCE', rule_source.replace("'", "''")).replace('SOURCE', source.replace("'", "''")).replace('PROGRAM', str(program).replace("'", "''")).replace('EXISTING', str(existing)).replace('ACTION', action).replace('SWITCH', '-Existing' if existing else '').replace('DISABLED_PROFILE', str(disabled_profile)).replace('PERMISSIVE_PROFILE', str(permissive_profile)).replace('LOCAL_RULES', str(local_rules))
            encoded = base64.b64encode(harness.encode('utf-16-le')).decode()
            return subprocess.run([self.powershell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded], capture_output=True, text=True)

    def test_invalid_source_never_creates_a_rule(self):
        for source in ('Any', 'Internet', '198.51.100.0/24', '0.0.0.0', '::', '224.0.0.1'):
            with self.subTest(source=source):
                result = self.invoke(source)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout.strip(), '')

    def test_maintenance_never_adopts_or_broadens_an_unexpected_rule(self):
        result = self.invoke('198.51.100.20', existing=True, rule_source='Any')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), '')

    def test_ineffective_filtering_is_rejected_before_rule_creation(self):
        for policy in ({'disabled_profile': 4}, {'permissive_profile': 2}, {'local_rules': False}):
            with self.subTest(policy=policy):
                result = self.invoke('198.51.100.20', **policy)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout.strip(), '')
