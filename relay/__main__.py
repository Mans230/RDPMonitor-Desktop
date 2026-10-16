"""Run one relay worker; secrets come only from the environment."""
from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path

import uvicorn

from .protocol import ProtocolError, normalize_origin, token_hash
from .server import create_app
from .websocket import RelayWebSocketProtocol


def main(argv=None):
    parser = argparse.ArgumentParser(description="Self-hosted RDPMonitor outbound relay (one worker only).")
    parser.add_argument("--host", default="127.0.0.1", help="Listener address; put Caddy in front for public TLS.")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--database", type=Path,
                        default=Path(os.environ.get("RDP_RELAY_DATABASE", "relay-data/relay.sqlite3")))
    parser.add_argument("--public-origin", default=os.environ.get("RDP_RELAY_PUBLIC_ORIGIN"),
                        help="Required external HTTPS origin, also accepted through RDP_RELAY_PUBLIC_ORIGIN.")
    parser.add_argument("--allow-loopback-http", action="store_true",
                        help="Development only: numeric-loopback HTTP origin and listener, never remote HTTP.")
    parser.add_argument("--trusted-proxy", default="127.0.0.1",
                        help="Comma-separated numeric proxy IPs; never '*'. Set to Caddy's private address.")
    parser.add_argument("--tls-cert", type=Path, help="Optional direct TLS certificate chain.")
    parser.add_argument("--tls-key", type=Path, help="Optional direct TLS private key file.")
    options = parser.parse_args(argv)
    admin_key = os.environ.get("RDP_RELAY_ADMIN_KEY")
    try:
        if not options.public_origin or not admin_key:
            parser.error("RDP_RELAY_ADMIN_KEY and a public origin are required; no defaults are provided.")
        origin = normalize_origin(options.public_origin, allow_loopback=options.allow_loopback_http)
        token_hash(admin_key)
    except ProtocolError:
        parser.error("The admin key must be a canonical 256-bit token and the public origin must be valid.")
    if not 1 <= options.port <= 65535:
        parser.error("Port must be between 1 and 65535.")
    if bool(options.tls_cert) != bool(options.tls_key):
        parser.error("Direct TLS requires both --tls-cert and --tls-key.")
    try:
        proxies = [str(ipaddress.ip_address(value.strip())) for value in options.trusted_proxy.split(",")]
    except ValueError:
        parser.error("Trusted proxies must be explicit numeric IP addresses, not wildcard networks.")
    if options.allow_loopback_http:
        try:
            loopback = ipaddress.ip_address(options.host).is_loopback
        except ValueError:
            loopback = False
        if not loopback or not origin.startswith("http://") or options.tls_cert:
            parser.error("Loopback HTTP development mode requires a numeric loopback listener and HTTP origin.")
    app = create_app(options.database, public_origin=origin, admin_key=admin_key,
                     allow_loopback_http=options.allow_loopback_http)
    # Warning-only logging also disables uvicorn's informational WS path logs.
    # Never enable access logs: pairing lookup identifiers and bearer responses
    # are intentionally absent from all broker diagnostics.
    # The pinned native protocol applies the SDK's preassembly message limit
    # and read-batch backpressure, plus a hard abort deadline for stalled closes.
    uvicorn.run(app, host=options.host, port=options.port, workers=1,
                ws=RelayWebSocketProtocol, ws_max_size=65536,
                ws_per_message_deflate=False, ws_ping_interval=20, ws_ping_timeout=20,
                access_log=False, log_level="warning", proxy_headers=True,
                forwarded_allow_ips=",".join(proxies), timeout_keep_alive=5,
                timeout_graceful_shutdown=5,
                ssl_certfile=str(options.tls_cert) if options.tls_cert else None,
                ssl_keyfile=str(options.tls_key) if options.tls_key else None)


if __name__ == "__main__":
    main()
