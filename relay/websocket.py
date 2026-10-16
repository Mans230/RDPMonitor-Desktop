"""Pinned Uvicorn transport with observable, hard-bounded socket teardown.

ASGI close completion means a close frame was submitted, not that its TCP socket
was released. Keep the transport's actual connection-lost future in the scope so
relay quotas include closing sockets. Abort discards stalled output after two
seconds; normal asyncio transport.close() alone may wait forever for a reader.
"""
from __future__ import annotations

import asyncio

from uvicorn.protocols.websockets.websockets_sansio_impl import WebSocketsSansIOProtocol

EXTENSION = "rdpmonitor.transport"
CLOSE_DEADLINE = 2


class RelayWebSocketProtocol(WebSocketsSansIOProtocol):
    def __init__(self, config, server_state, app_state, _loop=None):
        super().__init__(config, server_state, app_state, _loop)
        self._transport_closed = self.loop.create_future()
        self._abort_timer = None

    def begin_close(self):
        if not self._transport_closed.done() and self._abort_timer is None:
            self._abort_timer = self.loop.call_later(CLOSE_DEADLINE, self.transport.abort)

    def connection_lost(self, exc):
        try:
            super().connection_lost(exc)
        finally:
            if self._abort_timer is not None:
                self._abort_timer.cancel()
                self._abort_timer = None
            if not self._transport_closed.done():
                self._transport_closed.set_result(None)

    def handle_connect(self, event):
        super().handle_connect(event)
        # The base schedules, but cannot run, the ASGI task before this
        # synchronous callback returns. Install ownership before application I/O.
        if hasattr(self, "scope"):
            self.scope.setdefault("extensions", {})[EXTENSION] = {
                "closed": self._transport_closed,
                "begin_close": self.begin_close,
            }
        if self.close_sent:
            self.begin_close()

    async def send(self, message):
        terminal_http = message["type"] == "websocket.http.response.body" and not message.get("more_body", False)
        if message["type"] == "websocket.close" or terminal_http:
            # Arm before the base waits on a blocked writable buffer.
            self.begin_close()
        await super().send(message)
        if terminal_http:
            # Uvicorn 0.54 leaves rejected HTTP handshakes incomplete until
            # connection_lost, incorrectly logging a successful ASGI denial.
            self.handshake_complete = True

    def handle_close(self, event):
        self.begin_close()
        super().handle_close(event)

    def handle_parser_exception(self):
        self.begin_close()
        super().handle_parser_exception()

    def shutdown(self):
        self.begin_close()
        super().shutdown()


async def close_connection(websocket, code):
    ownership = websocket.scope.get("extensions", {}).get(EXTENSION)
    if ownership is None:
        raise RuntimeError("Relay sockets require RelayWebSocketProtocol")
    closed = ownership["closed"]
    if closed.done():
        return
    ownership["begin_close"]()
    try:
        await asyncio.wait_for(websocket.close(code=code), CLOSE_DEADLINE)
    except (Exception, asyncio.CancelledError):
        # The native abort deadline is independently armed. This task remains
        # accounted for until actual connection_lost, even if ASGI close failed.
        pass
    await asyncio.shield(closed)
