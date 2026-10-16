"""Consumer-visible relay security regressions over real loopback TCP sockets.

No SCM/firewall changes, fake WebSockets, source assertions or public relay are
used. Persisted expiry fixtures are aged only while the broker is stopped.
"""
from __future__ import annotations

import asyncio
import base64
import json
import socket
import sqlite3
import sys
import tempfile
import time
import unittest
from contextlib import AsyncExitStack, closing
from pathlib import Path
from uuid import uuid4

import httpx
import uvicorn
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from relay.protocol import ProtocolError, new_token, parse_invitation
from relay.server import create_app
from relay.store import Limits
from relay.websocket import RelayWebSocketProtocol


def authorization(token):
    return {"Authorization": "Bearer " + token}


class RelaySecurityTests(unittest.IsolatedAsyncioTestCase):
    # Exercise the selector socket transport used by the Linux relay container,
    # including on Windows where the default proactor closes buffered I/O differently.
    loop_factory = asyncio.SelectorEventLoop

    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "relay.sqlite3"
        self.admin_key = new_token()
        self.limits = Limits()
        self.server_task = None
        self.http = None
        await self.start()

    async def start(self, *, production=False):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        listener.setblocking(False)
        self.port = listener.getsockname()[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        self.ws_origin = f"ws://127.0.0.1:{self.port}"
        app = create_app(self.database, public_origin=self.origin.replace("http:", "https:") if production else self.origin,
                         admin_key=self.admin_key, allow_loopback_http=not production, limits=self.limits)
        self.server = uvicorn.Server(uvicorn.Config(
            app, host="127.0.0.1", port=self.port, ws=RelayWebSocketProtocol, ws_max_size=65536,
            ws_per_message_deflate=False, proxy_headers=False,
            access_log=False, log_level="warning", timeout_graceful_shutdown=2,
            lifespan="on"))
        self.server_task = asyncio.create_task(self.server.serve(sockets=[listener]))
        deadline = asyncio.get_running_loop().time() + 5
        while not self.server.started:
            if self.server_task.done():
                await self.server_task
                self.fail("Broker failed to start")
            if asyncio.get_running_loop().time() > deadline:
                self.fail("Broker startup exceeded its deadline")
            await asyncio.sleep(0.01)
        self.http = httpx.AsyncClient(base_url=self.origin, trust_env=False, timeout=5)

    async def stop(self):
        if self.http is not None:
            await self.http.aclose()
            self.http = None
        if self.server_task is not None:
            self.server.should_exit = True
            try:
                await asyncio.wait_for(self.server_task, 6)
            finally:
                self.server_task = None

    async def asyncTearDown(self):
        try:
            await self.stop()
        finally:
            self.temporary.cleanup()

    async def invitation(self, ttl=900):
        result = await self.http.post("/api/v1/installations", json={"ttl_seconds": ttl},
                                      headers=authorization(self.admin_key))
        self.assertEqual(result.status_code, 200, result.text)
        return parse_invitation(result.json()["invitation"], kind="install", allow_loopback=True).token

    async def register(self, *, token=None, agent_id=None):
        token = token or await self.invitation()
        agent_id = agent_id or str(uuid4())
        result = await self.http.post("/api/v1/agents/register", json={
            "invitation_token": token, "agent_id": agent_id, "name": "Isolated test VM"})
        self.assertEqual(result.status_code, 200, result.text)
        return {**result.json(), "agent_id": agent_id}

    async def grant(self, agent):
        result = await self.http.post(f"/api/v1/agents/{agent['route_id']}/grants", json={},
                                      headers=authorization(agent["agent_token"]))
        self.assertEqual(result.status_code, 200, result.text)
        return result.json()

    def websocket(self, path, token):
        return connect(self.ws_origin + path, additional_headers=authorization(token), proxy=None,
                       compression=None, max_size=65536, max_queue=4, open_timeout=3, close_timeout=1)

    def control(self, agent):
        return self.websocket(f"/api/v1/agents/{agent['route_id']}/control", agent["agent_token"])

    def client(self, agent, grant):
        return self.websocket(f"/api/v1/connect/{agent['route_id']}", grant["route_token"])

    async def rejected(self, connection, status):
        with self.assertRaises(InvalidStatus) as error:
            async with connection:
                self.fail("Expected WebSocket admission rejection")
        self.assertEqual(error.exception.response.status_code, status)

    async def joined(self, stack, agent, grant, control):
        client = await stack.enter_async_context(self.client(agent, grant))
        notice = json.loads(await asyncio.wait_for(control.recv(), 3))
        self.assertEqual(set(notice), {"type", "stream_id"})
        self.assertEqual(notice["type"], "open")
        agent_socket = await stack.enter_async_context(self.websocket(
            f"/api/v1/agents/{agent['route_id']}/streams/{notice['stream_id']}", agent["agent_token"]))
        return client, agent_socket, notice["stream_id"]

    async def test_invitation_redemption_is_one_atomic_use(self):
        token = await self.invitation()
        async def redeem():
            return await self.http.post("/api/v1/agents/register", json={
                "invitation_token": token, "agent_id": str(uuid4()), "name": "VM"})
        responses = await asyncio.gather(redeem(), redeem())
        self.assertEqual(sorted(response.status_code for response in responses), [200, 401])
        listing = await self.http.get("/api/v1/agents", headers=authorization(self.admin_key))
        self.assertEqual(len(listing.json()["agents"]), 1)

    async def test_failed_registration_does_not_consume_invitation_or_replace_identity(self):
        agent = await self.register()
        token = await self.invitation()
        response = await self.http.post("/api/v1/agents/register", json={
            "invitation_token": token, "agent_id": agent["agent_id"], "name": "Replacement"})
        self.assertEqual(response.status_code, 409)
        other = await self.register(token=token)
        self.assertNotEqual(other["route_id"], agent["route_id"])
        self.assertEqual((await self.http.delete(f"/api/v1/agents/{agent['route_id']}",
                         headers=authorization(self.admin_key))).status_code, 200)
        token = await self.invitation()
        response = await self.http.post("/api/v1/agents/register", json={
            "invitation_token": token, "agent_id": agent["agent_id"], "name": "Tombstone takeover"})
        self.assertEqual(response.status_code, 409)

    async def test_expired_installation_and_pairing_are_not_usable(self):
        token = await self.invitation(ttl=2)
        agent = await self.register()
        lookup_id = "1" * 64
        ciphertext = base64.urlsafe_b64encode(b"opaque ciphertext" * 3).decode().rstrip("=")
        response = await self.http.post(f"/api/v1/agents/{agent['route_id']}/pairings", json={
            "lookup_id": lookup_id, "ciphertext": ciphertext, "expires": int(time.time()) + 2},
            headers=authorization(agent["agent_token"]))
        self.assertEqual(response.status_code, 200)
        for _ in range(2):
            response = await self.http.get(f"/api/v1/pairings/{lookup_id}")
            self.assertEqual(response.json(), {"ciphertext": ciphertext})
        await asyncio.sleep(2.05)
        response = await self.http.post("/api/v1/agents/register", json={
            "invitation_token": token, "agent_id": str(uuid4()), "name": "Expired"})
        self.assertEqual(response.status_code, 401)
        self.assertEqual((await self.http.get(f"/api/v1/pairings/{lookup_id}")).status_code, 404)

    async def test_ciphertext_cannot_be_overwritten_or_published_for_another_route(self):
        first, second = await self.register(), await self.register()
        value = {"lookup_id": "2" * 64,
                 "ciphertext": base64.urlsafe_b64encode(b"\0" * 40).decode().rstrip("="),
                 "expires": int(time.time()) + 300}
        path = f"/api/v1/agents/{first['route_id']}/pairings"
        self.assertEqual((await self.http.post(path, json=value,
                          headers=authorization(second["agent_token"]))).status_code, 401)
        self.assertEqual((await self.http.post(path, json=value,
                          headers=authorization(first["agent_token"]))).status_code, 200)
        self.assertEqual((await self.http.post(path, json=value,
                          headers=authorization(first["agent_token"]))).status_code, 409)

    async def test_real_binary_data_and_duplicate_control_stream_protection(self):
        first, second = await self.register(), await self.register()
        grant = await self.grant(first)
        async with AsyncExitStack() as stack:
            control = await stack.enter_async_context(self.control(first))
            await self.rejected(self.control(first), 409)
            client, agent_socket, stream_id = await self.joined(stack, first, grant, control)
            await self.rejected(self.websocket(
                f"/api/v1/agents/{second['route_id']}/streams/{stream_id}", second["agent_token"]), 404)
            await self.rejected(self.websocket(
                f"/api/v1/agents/{first['route_id']}/streams/{stream_id}", first["agent_token"]), 409)
            await self.rejected(self.websocket(
                f"/api/v1/agents/{first['route_id']}/streams/{uuid4()}", first["agent_token"]), 404)
            payload = bytes(range(256)) * 256
            await client.send(payload)
            self.assertEqual(await asyncio.wait_for(agent_socket.recv(), 3), payload)
            await agent_socket.send(payload[::-1])
            self.assertEqual(await asyncio.wait_for(client.recv(), 3), payload[::-1])
            await client.send("text is not TLS bytes")
            with self.assertRaises(ConnectionClosed):
                await asyncio.wait_for(agent_socket.recv(), 3)

    async def test_offline_and_cross_route_grants_cannot_open_streams(self):
        first, second = await self.register(), await self.register()
        grant = await self.grant(first)
        await self.rejected(self.client(first, grant), 503)
        async with self.control(second):
            await self.rejected(self.client(second, grant), 401)

    async def test_grant_revocation_closes_both_live_sockets(self):
        agent = await self.register()
        grant = await self.grant(agent)
        async with AsyncExitStack() as stack:
            control = await stack.enter_async_context(self.control(agent))
            client, data, _ = await self.joined(stack, agent, grant, control)
            response = await self.http.delete(
                f"/api/v1/agents/{agent['route_id']}/grants/{grant['grant_id']}",
                headers=authorization(self.admin_key))
            self.assertEqual(response.json(), {"revoked": True})
            for ws in (client, data):
                with self.assertRaises(ConnectionClosed):
                    await asyncio.wait_for(ws.recv(), 3)
            await self.rejected(self.client(agent, grant), 401)
            listing = await self.http.get(f"/api/v1/agents/{agent['route_id']}/grants",
                                          headers=authorization(self.admin_key))
            self.assertEqual(listing.json()["grants"][0]["revoked"], True)

    async def test_agent_revocation_closes_control_and_all_streams_persistently(self):
        agent = await self.register()
        grant = await self.grant(agent)
        async with AsyncExitStack() as stack:
            control = await stack.enter_async_context(self.control(agent))
            client, data, _ = await self.joined(stack, agent, grant, control)
            response = await self.http.delete(f"/api/v1/agents/{agent['route_id']}",
                                               headers=authorization(self.admin_key))
            self.assertEqual(response.status_code, 200)
            for ws in (control, client, data):
                with self.assertRaises(ConnectionClosed):
                    await asyncio.wait_for(ws.recv(), 3)
            await self.rejected(self.control(agent), 401)
        await self.stop()
        await self.start()
        await self.rejected(self.control(agent), 401)
        listing = await self.http.get("/api/v1/agents", headers=authorization(self.admin_key))
        self.assertTrue(listing.json()["agents"][0]["revoked"])

    async def test_control_disconnect_terminates_existing_and_pending_streams(self):
        agent = await self.register()
        grant = await self.grant(agent)
        async with AsyncExitStack() as stack:
            control = await stack.enter_async_context(self.control(agent))
            client, data, _ = await self.joined(stack, agent, grant, control)
            pending = await stack.enter_async_context(self.client(agent, grant))
            await asyncio.wait_for(control.recv(), 3)
            await control.close()
            for ws in (client, data, pending):
                with self.assertRaises(ConnectionClosed):
                    await asyncio.wait_for(ws.recv(), 3)
        async with self.control(agent):
            pass

    async def test_unattached_stream_has_finite_deadline(self):
        agent = await self.register()
        grant = await self.grant(agent)
        async with self.control(agent) as control, self.client(agent, grant) as client:
            notice = json.loads(await asyncio.wait_for(control.recv(), 3))
            with self.assertRaises(ConnectionClosed):
                await asyncio.wait_for(client.recv(), 12)
            await self.rejected(self.websocket(
                f"/api/v1/agents/{agent['route_id']}/streams/{notice['stream_id']}", agent["agent_token"]), 404)

    async def test_oversized_websocket_message_closes_the_entire_stream(self):
        agent = await self.register()
        grant = await self.grant(agent)
        async with AsyncExitStack() as stack:
            control = await stack.enter_async_context(self.control(agent))
            client, data, _ = await self.joined(stack, agent, grant, control)
            await client.send(b"x" * 65537)
            for ws in (client, data):
                with self.assertRaises(ConnectionClosed):
                    await asyncio.wait_for(ws.recv(), 3)

    async def test_slow_reader_revocation_retains_quota_until_native_socket_is_aborted(self):
        await self.stop()
        self.limits = Limits(streams=1, streams_per_route=1)
        await self.start()
        agent = await self.register()
        grant, replacement = await self.grant(agent), await self.grant(agent)
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        raw.setblocking(False)
        producer = None
        try:
            await asyncio.get_running_loop().sock_connect(raw, ("127.0.0.1", self.port))
            async with AsyncExitStack() as stack:
                control = await stack.enter_async_context(self.control(agent))
                slow = await stack.enter_async_context(connect(
                    self.ws_origin + f"/api/v1/connect/{agent['route_id']}", sock=raw,
                    additional_headers=authorization(grant["route_token"]), proxy=None,
                    compression=None, max_size=65536, max_queue=1, close_timeout=1))
                slow.transport.pause_reading()
                notice = json.loads(await asyncio.wait_for(control.recv(), 3))
                data = await stack.enter_async_context(self.websocket(
                    f"/api/v1/agents/{agent['route_id']}/streams/{notice['stream_id']}", agent["agent_token"]))
                runtime = self.server.config.app.state.relay
                stream = runtime.streams[notice["stream_id"]]
                protocol = next(connection for connection in self.server.server_state.connections
                                if isinstance(connection, RelayWebSocketProtocol)
                                and connection.scope.get("path") == f"/api/v1/connect/{agent['route_id']}")

                async def fill():
                    block = b"x" * 65536
                    for _ in range(1024):
                        await data.send(block)

                producer = asyncio.create_task(fill())
                deadline = asyncio.get_running_loop().time() + 3
                while protocol.writable.is_set():
                    if asyncio.get_running_loop().time() > deadline:
                        self.fail("The real slow reader did not apply TCP backpressure")
                    await asyncio.sleep(0.01)
                revoke = asyncio.create_task(self.http.delete(
                    f"/api/v1/agents/{agent['route_id']}/grants/{grant['grant_id']}",
                    headers=authorization(self.admin_key)))
                await asyncio.wait_for(stream.done.wait(), 1)
                await self.rejected(self.client(agent, replacement), 429)
                self.assertEqual((await asyncio.wait_for(revoke, 3)).status_code, 200)
                self.assertNotIn(protocol, self.server.server_state.connections)
                self.assertNotIn(notice["stream_id"], runtime.streams)
                slow.transport.resume_reading()
                new_client, new_data, _ = await self.joined(stack, agent, replacement, control)
                await new_client.send(b"quota released after native teardown")
                self.assertEqual(await asyncio.wait_for(new_data.recv(), 3), b"quota released after native teardown")
        finally:
            if producer is not None:
                producer.cancel()
                await asyncio.gather(producer, return_exceptions=True)
            raw.close()

    async def test_restart_preserves_active_grant_but_expires_pending_grant(self):
        agent = await self.register()
        active, pending = await self.grant(agent), await self.grant(agent)
        async with AsyncExitStack() as stack:
            control = await stack.enter_async_context(self.control(agent))
            await self.joined(stack, agent, active, control)
        invitation = await self.invitation()
        await self.stop()
        # Simulate elapsed wall-clock time while the broker was offline. These
        # are genuine persisted credentials, not a mocked authentication layer.
        with closing(sqlite3.connect(self.database)) as db:
            db.execute("UPDATE grants SET expires=?", (int(time.time()) - 1,))
            db.commit()
        await self.start()
        await self.register(token=invitation)
        async with AsyncExitStack() as stack:
            control = await stack.enter_async_context(self.control(agent))
            await self.rejected(self.client(agent, pending), 401)
            client, data, _ = await self.joined(stack, agent, active, control)
            await client.send(b"still authorized after restart")
            self.assertEqual(await asyncio.wait_for(data.recv(), 3), b"still authorized after restart")
        listing = await self.http.get(f"/api/v1/agents/{agent['route_id']}/grants",
                                      headers=authorization(self.admin_key))
        self.assertEqual(set(listing.json()["grants"][0]), {"grant_id", "created_at", "activated_at", "revoked"})

    async def test_quotas_bound_invitations_agents_grants_pairings_and_streams(self):
        await self.stop()
        self.limits = Limits(agents=1, invitations=1, grants_per_route=1, pairings_per_route=1,
                             streams_per_route=1, streams=1, pending_control=1)
        await self.start()
        token = await self.invitation()
        response = await self.http.post("/api/v1/installations", json={}, headers=authorization(self.admin_key))
        self.assertEqual(response.status_code, 429)
        agent = await self.register(token=token)
        another = await self.invitation()
        response = await self.http.post("/api/v1/agents/register", json={
            "invitation_token": another, "agent_id": str(uuid4()), "name": "Over capacity"})
        self.assertEqual(response.status_code, 429)
        grant = await self.grant(agent)
        response = await self.http.post(f"/api/v1/agents/{agent['route_id']}/grants", json={},
                                        headers=authorization(agent["agent_token"]))
        self.assertEqual(response.status_code, 429)
        value = {"lookup_id": "3" * 64,
                 "ciphertext": base64.urlsafe_b64encode(b"x" * 40).decode().rstrip("="),
                 "expires": int(time.time()) + 300}
        path = f"/api/v1/agents/{agent['route_id']}/pairings"
        self.assertEqual((await self.http.post(path, json=value,
                          headers=authorization(agent["agent_token"]))).status_code, 200)
        value["lookup_id"] = "4" * 64
        self.assertEqual((await self.http.post(path, json=value,
                          headers=authorization(agent["agent_token"]))).status_code, 429)
        async with AsyncExitStack() as stack:
            control = await stack.enter_async_context(self.control(agent))
            client, data, _ = await self.joined(stack, agent, grant, control)
            await self.rejected(self.client(agent, grant), 429)
            await client.close()
            with self.assertRaises(ConnectionClosed):
                await asyncio.wait_for(data.recv(), 3)
            await self.joined(stack, agent, grant, control)

    async def test_request_bounds_and_credential_errors_do_not_echo_secrets(self):
        token = new_token()
        response = await self.http.post("/api/v1/installations", json={}, headers=authorization(token))
        self.assertEqual(response.status_code, 401)
        self.assertNotIn(token, response.text)
        response = await self.http.post("/api/v1/agents/register", content=b"x" * 16385)
        self.assertEqual(response.status_code, 413)
        response = await self.http.get("/api/v1/agents?token=" + token)
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(token, response.text)
        self.assertEqual((await self.http.get("/health", headers={"Host": "remote.example"})).status_code, 400)

    async def test_http_requires_explicit_numeric_loopback_development_mode(self):
        for origin in ("http://192.0.2.1", "http://localhost", "http://example.com"):
            with self.subTest(origin=origin), self.assertRaises(ProtocolError):
                create_app(self.database, public_origin=origin, admin_key=self.admin_key,
                           allow_loopback_http=True)
        await self.stop()
        await self.start(production=True)
        response = await self.http.get("/health", headers={"X-Forwarded-Proto": "https"})
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
