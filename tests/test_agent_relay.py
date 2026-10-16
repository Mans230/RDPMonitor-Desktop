"""Actual broker/WebSocket/TLS sockets; no service, account or firewall changes."""
from __future__ import annotations

import asyncio
import json
import secrets
import socket
import ssl
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from uuid import uuid4

import httpx
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from websockets.asyncio.client import connect

from agent import relay, setup
from agent.contracts import OperationError
from relay.protocol import (decode_secret, decrypt_pairing, encode_secret, make_invitation,
                            make_setup_invitation, new_token, parse_invitation, parse_setup_invitation)
from relay.server import create_app
from relay.websocket import RelayWebSocketProtocol


class RelayBoundaryTests(unittest.TestCase):
    def test_absent_configuration_leaves_direct_gateway_untouched(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            relay.run_connector(directory, "0.0.0.0", 9443, threading.Event())
            self.assertFalse(relay.relay_settings_path(directory).exists())
            self.assertFalse((directory / "identity.json").exists())
            self.assertFalse((directory / "gateway").exists())

    def test_only_numeric_loopback_gateway_targets_are_accepted(self):
        for host in ("127.0.0.1", "127.255.255.254", "::1"):
            self.assertEqual(relay._loopback_target(host, 9443), (host, 9443))
        for host in ("localhost", "0.0.0.0", "192.0.2.1", "::", "::1%1", "127.0.0.1.example", None):
            with self.subTest(host=host), self.assertRaises(OperationError) as error:
                relay._loopback_target(host, 9443)
            self.assertEqual(error.exception.code, "relay_gateway_target")
        for port in (0, 65536, True, "9443", None):
            with self.subTest(port=port), self.assertRaises(OperationError):
                relay._loopback_target("127.0.0.1", port)

    def test_existing_unusable_settings_surface_without_secret_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = relay.relay_settings_path(directory)
            path.parent.mkdir()
            secret = new_token()
            path.write_text(json.dumps({"agent_token": secret}), encoding="utf-8")
            with self.assertRaises(OperationError) as error:
                relay.run_connector(directory, "127.0.0.1", 9443, threading.Event())
            self.assertEqual(error.exception.code, "relay_configuration")
            self.assertNotIn(secret, str(error.exception))
            self.assertNotIn(secret, error.exception.message)

    def test_supplied_desktop_key_requires_local_consent_and_never_enters_broker_payload(self):
        now = int(time.time())
        key = bytes(range(32))
        settings = relay._Settings("https://relay.example", str(uuid4()), str(uuid4()), "Local VM", new_token())
        approval = {"code": "test_local_approval_capability", "expires": datetime.fromtimestamp(now + 300, timezone.utc).isoformat(),
                    "agent_id": settings.agent_id, "fingerprint": "ab" * 32}
        grant_token = new_token()
        calls = []

        def request(origin, path, payload, *, token=None):
            calls.append((origin, path, payload, token))
            if path.endswith("/grants"):
                return {"grant_id": str(uuid4()), "route_token": grant_token}
            return {"published": True}

        with mock.patch.object(relay, "_require_local_admin") as consent, \
                mock.patch.object(relay, "_load_settings", return_value=settings), \
                mock.patch.object(relay, "WorkerProxy") as worker, \
                mock.patch.object(relay, "_request", side_effect=request):
            worker.return_value.rpc.return_value = approval
            result = relay.publish_connection_code(Path("unused"), role="viewer", ttl=300, secret=key)
            consent.assert_called_once_with()
            worker.return_value.rpc.assert_called_once_with("pairing.begin", {"ttl_seconds": 300, "role": "viewer"})
        invitation = parse_invitation(result["code"], kind="pair")
        self.assertEqual(invitation.secret, key)
        published = calls[1][2]
        self.assertEqual(set(published), {"lookup_id", "ciphertext", "expires"})
        self.assertEqual(published["lookup_id"], invitation.lookup_id)
        self.assertNotIn(encode_secret(key), json.dumps(calls))
        self.assertNotIn(approval["code"], json.dumps(calls))
        payload = decrypt_pairing(settings.relay_origin, key, published["ciphertext"])
        self.assertEqual(payload["route_token"], grant_token)
        self.assertEqual(payload["pairing_code"], approval["code"])
        self.assertEqual(payload["fingerprint"], approval["fingerprint"])
        with self.assertRaises(ValueError):
            decrypt_pairing(settings.relay_origin, decode_secret(settings.agent_token), published["ciphertext"])

    def test_bad_desktop_key_or_worker_identity_never_allocates_a_broker_grant(self):
        settings = relay._Settings("https://relay.example", str(uuid4()), str(uuid4()), "Local VM", new_token())
        with mock.patch.object(relay, "_require_local_admin"), \
                mock.patch.object(relay, "_load_settings", return_value=settings), \
                mock.patch.object(relay, "WorkerProxy") as worker, \
                mock.patch.object(relay, "_request") as request:
            for secret in (b"short", "A" * 32, bytearray(32)):
                with self.subTest(secret_type=type(secret)), self.assertRaises(OperationError):
                    relay.publish_connection_code(Path("unused"), secret=secret)
            worker.assert_not_called()
            worker.return_value.rpc.return_value = {"agent_id": str(uuid4()), "code": "test_local_approval_capability",
                "expires": datetime.now(timezone.utc).isoformat(), "fingerprint": "ab" * 32}
            with self.assertRaises(OperationError):
                relay.publish_connection_code(Path("unused"), secret=bytes(range(32)))
            request.assert_not_called()

    def test_desktop_setup_key_never_bypasses_local_administrator_approval(self):
        with mock.patch.object(relay, "current_identity", return_value={"admin": False}), \
                mock.patch.object(relay, "WorkerProxy") as worker, \
                mock.patch.object(relay, "_request") as request:
            with self.assertRaises(OperationError) as error:
                relay.publish_connection_code(Path("unused"), secret=bytes(range(32)), role="viewer")
            self.assertEqual(error.exception.code, "local_admin_required")
            worker.assert_not_called()
            request.assert_not_called()


class NativeSetupCodeTests(unittest.TestCase):
    def test_native_exchange_strips_pairing_key_before_registration_and_keeps_legacy_input(self):
        key = bytes(range(32))
        install_token = encode_secret(bytes(range(32, 64)))
        new_code = make_setup_invitation("https://relay.example", install_token, key)
        legacy = make_invitation("install", "https://relay.example", install_token)
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(setup, "data_directory", return_value=Path(temporary)), \
                mock.patch.object(setup, "verify_protected_tree"):
            path = Path(temporary)
            for code, expected_key in ((new_code, key), (legacy, None)):
                invitation = path / "invitation.txt"
                invitation.write_text(code, encoding="utf-8")
                registration_code, supplied_key = setup._installation_input(path)
                self.assertEqual(parse_invitation(registration_code, kind="install").token, install_token)
                self.assertEqual(supplied_key, expected_key)
                self.assertNotIn(encode_secret(key), registration_code)
                self.assertFalse(invitation.exists())
            invitation.write_text(new_code + "=", encoding="utf-8")
            with self.assertRaises(ValueError):
                setup._installation_input(path)
            self.assertFalse(invitation.exists())
            settings_file = relay.relay_settings_path(path)
            settings_file.parent.mkdir()
            settings_file.write_text("existing identity", encoding="utf-8")
            self.assertEqual(setup._installation_input(path), (None, None))
            invitation.write_text(new_code, encoding="utf-8")
            with self.assertRaises(ValueError):
                setup._installation_input(path)
            self.assertEqual(settings_file.read_text(), "existing identity")

    def test_native_pairing_uses_protected_setup_key_and_forced_viewer_then_legacy_random_key(self):
        key = bytes(range(32))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            deployment = {"release": str(path), "read_only": True, "unsigned_preview": True}
            (path / "pairing-key.txt").write_text(encode_secret(key), encoding="ascii")
            published = {"code": "private_manual_recovery_code", "expires": int(time.time()) + 300}
            with mock.patch.object(setup, "_session", return_value=path), \
                    mock.patch.object(setup, "_deployment", return_value=deployment), \
                    mock.patch.object(setup, "verify_protected_tree"), \
                    mock.patch.object(setup, "_ready") as ready, \
                    mock.patch.object(setup, "_write", side_effect=lambda file, value: file.write_text(value, encoding="utf-8")), \
                    mock.patch.object(relay, "publish_connection_code", return_value=published) as publish:
                setup.pair("unused")
                ready.assert_called_once_with(deployment)
                self.assertEqual(publish.call_args.kwargs, {"role": "viewer", "ttl": 300, "secret": key})
                self.assertEqual((path / "automatic.txt").read_text(), "1")
                self.assertIn("no second code", (path / "status.txt").read_text())
                self.assertFalse((path / "pairing-key.txt").exists())
                setup.pair("unused")
                self.assertEqual(publish.call_args.kwargs, {"role": "viewer", "ttl": 300, "secret": None})
                self.assertEqual((path / "automatic.txt").read_text(), "0")



class RelaySocketTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.admin_key = new_token()
        self.connector = None
        self.connector_stop = threading.Event()
        self.desktop_tasks = set()
        self.gateway_tasks = set()
        self.gateway_bytes = bytearray()
        self.wire_chunks = []
        self.broker = self.broker_task = None
        self.port = 0
        await self._start_broker()
        self.http = httpx.AsyncClient(base_url=self.origin, trust_env=False, timeout=5)
        self.admin_headers = {"Authorization": "Bearer " + self.admin_key}
        response = await self.http.post("/api/v1/installations", headers=self.admin_headers, json={"ttl_seconds": 300})
        self.assertEqual(response.status_code, 200)
        invitation = parse_invitation(response.json()["invitation"], kind="install", allow_loopback=True)
        self.agent_id = str(uuid4())
        response = await self.http.post("/api/v1/agents/register", json={
            "invitation_token": invitation.token, "agent_id": self.agent_id, "name": "Isolated TLS agent"})
        self.assertEqual(response.status_code, 200)
        registered = response.json()
        self.settings = relay._Settings(self.origin, self.agent_id, registered["route_id"],
                                        "Isolated TLS agent", registered["agent_token"])
        response = await self.http.post(f"/api/v1/agents/{self.settings.route_id}/grants",
                                        headers={"Authorization": "Bearer " + self.settings.agent_token}, json={})
        self.assertEqual(response.status_code, 200)
        self.route_token = response.json()["route_token"]
        self._tls_contexts()
        self.gateway = await asyncio.start_server(self._gateway, "127.0.0.1", 0, ssl=self.server_tls)
        self.gateway_port = self.gateway.sockets[0].getsockname()[1]
        self.desktop = await asyncio.start_server(self._desktop_bridge, "127.0.0.1", 0)
        self.desktop_port = self.desktop.sockets[0].getsockname()[1]
        self.connector = asyncio.create_task(relay._run_connector(
            connect, self.settings, "127.0.0.1", self.gateway_port, self.connector_stop))
        await self._wait_online()

    async def _start_broker(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", self.port))
        listener.listen(128)
        listener.setblocking(False)
        self.port = listener.getsockname()[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        app = create_app(self.directory / "relay.sqlite3", public_origin=self.origin,
                         admin_key=self.admin_key, allow_loopback_http=True)
        self.broker = uvicorn.Server(uvicorn.Config(
            app, host="127.0.0.1", port=self.port, log_config=None, access_log=False,
            log_level="warning", ws=RelayWebSocketProtocol, ws_max_size=65536,
            ws_per_message_deflate=False, timeout_graceful_shutdown=1))
        self.broker_task = asyncio.create_task(self.broker.serve(sockets=[listener]))
        deadline = time.monotonic() + 5
        while not self.broker.started:
            if self.broker_task.done():
                self.broker_task.result()
                self.fail("Isolated broker did not start")
            if time.monotonic() >= deadline:
                self.fail("Isolated broker startup deadline exceeded")
            await asyncio.sleep(0.01)

    async def _stop_broker(self):
        if self.broker_task is not None:
            self.broker.should_exit = True
            await asyncio.wait_for(self.broker_task, 5)
            self.broker_task = None

    async def _wait_online(self):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            response = await self.http.get("/api/v1/agents", headers=self.admin_headers)
            self.assertEqual(response.status_code, 200)
            if any(item["route_id"] == self.settings.route_id and item["online"]
                   for item in response.json()["agents"]):
                return
            await asyncio.sleep(0.05)
        self.fail("Actual connector did not become online")

    async def test_one_setup_code_registers_then_resolves_only_desktop_key_at_real_broker(self):
        response = await self.http.post("/api/v1/installations", headers=self.admin_headers, json={"ttl_seconds": 900})
        installation = parse_invitation(response.json()["invitation"], kind="install", allow_loopback=True)
        key = bytes(range(32))
        code = make_setup_invitation(self.origin, installation.token, key, allow_loopback=True)
        setup_code = parse_setup_invitation(code, allow_loopback=True)
        pairing = parse_invitation(setup_code.connection_code, kind="pair", allow_loopback=True)
        self.assertEqual((await self.http.get(f"/api/v1/pairings/{pairing.lookup_id}")).status_code, 404)
        agent_id = str(uuid4())
        registration_payload = {"invitation_token": parse_invitation(setup_code.installation_code,
            kind="install", allow_loopback=True).token, "agent_id": agent_id, "name": "One-code VM"}
        self.assertNotIn(encode_secret(key), json.dumps(registration_payload))
        registered = await self.http.post("/api/v1/agents/register", json=registration_payload)
        self.assertEqual(registered.status_code, 200)
        credentials = registered.json()
        settings = relay._Settings(self.origin, agent_id, credentials["route_id"], "One-code VM", credentials["agent_token"])
        approval = {"agent_id": agent_id, "code": "one_use_local_approval_capability",
            "fingerprint": "ab" * 32, "expires": datetime.fromtimestamp(int(time.time()) + 300, timezone.utc).isoformat()}
        with mock.patch.object(relay, "_require_local_admin"), \
                mock.patch.object(relay, "_load_settings", return_value=settings), \
                mock.patch.object(relay, "WorkerProxy") as worker:
            worker.return_value.rpc.return_value = approval
            published = await asyncio.to_thread(relay.publish_connection_code, Path("unused"),
                role="viewer", ttl=300, secret=setup_code.pairing_secret, allow_loopback=True)
        self.assertEqual(published["code"], setup_code.connection_code)
        envelope = await self.http.get(f"/api/v1/pairings/{pairing.lookup_id}")
        self.assertEqual(envelope.status_code, 200)
        payload = decrypt_pairing(self.origin, key, envelope.json()["ciphertext"], allow_loopback=True)
        self.assertEqual(payload["agent_id"], agent_id)
        self.assertEqual(payload["pairing_code"], approval["code"])
        with self.assertRaises(ValueError):
            decrypt_pairing(self.origin, setup_code.install_secret, envelope.json()["ciphertext"], allow_loopback=True)
        self.assertEqual((await self.http.post("/api/v1/agents/register", json=registration_payload)).status_code, 401)
        self.assertEqual((await self.http.get(f"/api/v1/pairings/{installation.lookup_id}")).status_code, 404)
        database = (self.directory / "relay.sqlite3").read_bytes()
        self.assertNotIn(encode_secret(key).encode("ascii"), database)
        self.assertNotIn(approval["code"].encode("ascii"), database)

    def _tls_contexts(self):
        key = ec.generate_private_key(ec.SECP256R1())
        ca_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gateway.test")])
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Isolated relay test CA")])
        now = datetime.now(timezone.utc)
        ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
              .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
              .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
              .sign(ca_key, hashes.SHA256()))
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(ca_name)
                       .public_key(key.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
                       .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                       .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
                       .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                       .add_extension(x509.SubjectAlternativeName([x509.DNSName("gateway.test")]), critical=False)
                       .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                       .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                       .sign(ca_key, hashes.SHA256()))
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
        certificate_path, key_path = self.directory / "test.pem", self.directory / "test-key.pem"
        certificate_path.write_bytes(certificate_pem)
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        self.server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_tls.load_cert_chain(certificate_path, key_path)
        self.client_tls = ssl.create_default_context(cadata=ca.public_bytes(serialization.Encoding.PEM).decode("ascii"))

    async def _gateway(self, reader, writer):
        task = asyncio.current_task()
        self.gateway_tasks.add(task)
        try:
            while data := await reader.read(65536):
                self.gateway_bytes.extend(data)
                writer.write(data)
                await writer.drain()
        except (OSError, ssl.SSLError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass
            self.gateway_tasks.discard(task)

    async def _desktop_bridge(self, reader, writer):
        task = asyncio.current_task()
        self.desktop_tasks.add(task)
        pumps = []
        websocket = None
        try:
            websocket = await connect(
                f"ws://127.0.0.1:{self.port}/api/v1/connect/{self.settings.route_id}",
                additional_headers={"Authorization": "Bearer " + self.route_token},
                proxy=None, compression=None, max_size=65536, max_queue=4,
                open_timeout=5, close_timeout=1, logger=relay._WIRE_LOG)

            async def outgoing():
                while data := await reader.read(65536):
                    self.wire_chunks.append(data)
                    await websocket.send(data)

            async def incoming():
                async for data in websocket:
                    self.assertIsInstance(data, bytes)
                    self.assertLessEqual(len(data), 65536)
                    writer.write(data)
                    await writer.drain()

            pumps = [asyncio.create_task(outgoing()), asyncio.create_task(incoming())]
            await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
        except Exception:
            # These fixture connections are deliberately interrupted by tests.
            pass
        finally:
            for pump in pumps:
                pump.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            await relay._close_websocket(websocket)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            self.desktop_tasks.discard(task)

    async def _tls_client(self):
        return await asyncio.wait_for(asyncio.open_connection(
            "127.0.0.1", self.desktop_port, ssl=self.client_tls, server_hostname="gateway.test"), 8)

    async def _assert_closed(self, reader):
        try:
            data = await asyncio.wait_for(reader.read(1), 5)
        except (OSError, ssl.SSLError):
            return
        self.assertEqual(data, b"")

    async def test_outer_https_and_websocket_never_accept_untrusted_certificate(self):
        token = new_token()
        origin = f"https://127.0.0.1:{self.gateway_port}"
        with self.assertRaises(OperationError) as error:
            await asyncio.to_thread(relay._request, origin, "/api/v1/agents/register", {}, token=token)
        self.assertEqual(error.exception.code, "relay_unavailable")
        self.assertNotIn(token, error.exception.message)
        settings = relay._Settings(origin, self.agent_id, self.settings.route_id, "Machine", token)
        with self.assertRaises(ssl.SSLCertVerificationError):
            await relay._connect_websocket(connect, settings, "/api/v1/control")
        self.assertEqual(self.gateway_bytes, b"")

    async def test_full_tls_bytes_and_backpressure_cross_actual_broker(self):
        reader, writer = await self._tls_client()
        payload = b"private-application-payload:" + secrets.token_bytes(400000)
        writer.write(payload)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(len(payload)), 8), payload)
        self.assertEqual(self.gateway_bytes, payload)
        self.assertTrue(self.wire_chunks)
        self.assertTrue(all(0 < len(chunk) <= relay.MAX_MESSAGE for chunk in self.wire_chunks))
        self.assertNotIn(payload[:64], b"".join(self.wire_chunks))
        writer.close()
        await writer.wait_closed()

    async def test_control_restart_closes_old_tls_and_reconnects_without_replay(self):
        reader, writer = await self._tls_client()
        first = b"first request, exactly once"
        writer.write(first)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(len(first)), 5), first)
        await self._stop_broker()
        await self._assert_closed(reader)
        writer.close()
        await self._start_broker()
        await self._wait_online()
        reader, writer = await self._tls_client()
        second = b"new connection after durable broker restart"
        writer.write(second)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(len(second)), 5), second)
        self.assertEqual(self.gateway_bytes, first + second)
        writer.close()
        await writer.wait_closed()

    async def test_stop_closes_attached_stream_and_all_connector_pumps(self):
        reader, writer = await self._tls_client()
        self.connector_stop.set()
        await asyncio.wait_for(self.connector, 5)
        await self._assert_closed(reader)
        self.assertFalse([task for task in asyncio.all_tasks() if not task.done()
                          and task.get_coro().__qualname__.startswith("_RelayStream.")])
        writer.close()

    async def asyncTearDown(self):
        self.connector_stop.set()
        if self.connector is not None:
            await asyncio.wait_for(self.connector, 5)
        self.desktop.close()
        await self.desktop.wait_closed()
        self.gateway.close()
        await self.gateway.wait_closed()
        for task in [*self.desktop_tasks, *self.gateway_tasks]:
            task.cancel()
        await asyncio.gather(*self.desktop_tasks, *self.gateway_tasks, return_exceptions=True)
        await self._stop_broker()
        await self.http.aclose()
        self.temporary.cleanup()


class RelayHandshakeStopTests(unittest.IsolatedAsyncioTestCase):
    async def test_stop_cancels_incomplete_control_handshake_and_late_socket(self):
        accepted = asyncio.Event()
        closed = asyncio.Event()
        handlers = set()

        async def incomplete_handshake(reader, writer):
            task = asyncio.current_task()
            handlers.add(task)
            accepted.set()
            try:
                await reader.read()
            finally:
                writer.close()
                await writer.wait_closed()
                handlers.discard(task)
                closed.set()

        server = await asyncio.start_server(incomplete_handshake, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        settings = relay._Settings(f"http://127.0.0.1:{port}", str(uuid4()), str(uuid4()), "Machine", new_token())
        stop = threading.Event()
        connector = asyncio.create_task(relay._run_connector(connect, settings, "127.0.0.1", 9443, stop))
        try:
            await asyncio.wait_for(accepted.wait(), 3)
            stop.set()
            await asyncio.wait_for(connector, 3)
            await asyncio.wait_for(closed.wait(), 3)
            self.assertFalse(handlers)
        finally:
            stop.set()
            await asyncio.wait_for(connector, 3)
            server.close()
            await server.wait_closed()
            for task in handlers:
                task.cancel()
            await asyncio.gather(*handlers, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()
