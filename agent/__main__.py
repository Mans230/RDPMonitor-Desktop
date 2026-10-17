"""Windows agent CLI and service lifecycle functions."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shutil
import signal
import ssl
import sys
import threading
import time
from pathlib import Path

from .contracts import OperationError
from .ipc import (DEFAULT_PIPE, GATEWAY_ACCOUNT, IntegratedProxy, PipeServer,
                  WorkerDispatcher, WorkerProxy, account_sid, current_identity, protect_path)


def _paths(root, data_dir):
    return Path(root).resolve(), Path(data_dir).resolve()


def _gateway_tls(runtime, gateway_sid):
    identity = runtime.ca.ensure()
    directory = runtime.data_dir / "gateway"
    directory.mkdir(parents=True, exist_ok=True)
    protect_path(directory, gateway_sid, directory=True)
    result = {}
    for field, filename in (("certificate_path", "server.pem"), ("key_path", "server-key.pem"),
                            ("ca_path", "ca.pem")):
        destination = directory / filename
        # Directory already has a protected ACL before a private-key copy is created.
        shutil.copyfile(identity[field], destination)
        protect_path(destination, gateway_sid)
        result[field] = str(destination)
    return result


def _ensure_listener_san(authority, host):
    # Wildcard bind addresses are not endpoint identities. In particular, adding
    # them must not reissue the pre-pinned transport certificate on first boot.
    if host in ("0.0.0.0", "::"):
        return
    from cryptography import x509
    info = authority.ensure()
    certificate = x509.load_pem_x509_certificate(Path(info["certificate_path"]).read_bytes())
    names = {str(name.value) for name in certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value}
    if host not in names:
        authority.ensure(configured_hosts=sorted(names | {host}))


def run_worker(root: Path, data_dir: Path, stop_event: threading.Event,
               pipe_name=DEFAULT_PIPE, read_only=False):
    from .runtime import AgentRuntime
    if not current_identity()["admin"]:
        raise OperationError("elevation_required", "Worker requires an elevated administrator or SYSTEM.", 403)
    root, data_dir = _paths(root, data_dir)
    runtime = AgentRuntime(root, data_dir, read_only=read_only)
    deployment = data_dir / "deployment.json"
    if deployment.is_file():
        host = json.loads(deployment.read_text(encoding="utf-8-sig"))["host"]
        _ensure_listener_san(runtime.ca, host)
    try:
        try:
            gateway_sid = account_sid(GATEWAY_ACCOUNT)
        except Exception:
            # Integrated development may precede SCM registration; only admins can connect then.
            gateway_sid = None
        paths = _gateway_tls(runtime, gateway_sid)
        server = PipeServer(pipe_name, WorkerDispatcher(runtime, paths, gateway_sid),
                            [gateway_sid] if gateway_sid else [])
        runtime.start()
        print("RDPMonitor worker ready " + pipe_name, flush=True)
        server.serve(stop_event)
    finally:
        runtime.stop()


def _run_https(proxy, paths, host, port, stop_event, on_started=None):
    import uvicorn
    from .api import CertificateH11Protocol, create_app

    class Server(uvicorn.Server):
        async def startup(self, sockets=None):
            await super().startup(sockets)
            if self.started:
                display_host = f"[{host}]" if ":" in host else host
                print(f"RDPMonitor agent listening https://{display_host}:{port}", flush=True)
                if on_started is not None:
                    on_started()

    config = uvicorn.Config(create_app(proxy), host=host, port=port,
        http=CertificateH11Protocol, ws="none", ssl_keyfile=paths["key_path"],
        ssl_certfile=paths["certificate_path"], ssl_ca_certs=paths["ca_path"],
        ssl_cert_reqs=ssl.CERT_OPTIONAL, ssl_version=ssl.PROTOCOL_TLS_SERVER,
        ssl_ciphers="ECDHE+AESGCM:ECDHE+CHACHA20", access_log=False,
        # Exceed the desktop's 20s idle pool lifetime: a 5s server close races
        # its 5s telemetry timer and can tear down a reused request socket.
        limit_concurrency=None, backlog=64, timeout_keep_alive=30, proxy_headers=False,
        timeout_graceful_shutdown=20, h11_max_incomplete_event_size=16384,
        server_header=False, date_header=True)
    server = Server(config)
    finished = threading.Event()

    def watch_stop():
        while not finished.is_set():
            if stop_event.wait(0.25):
                server.should_exit = True
                return

    watcher = threading.Thread(target=watch_stop, daemon=True)
    watcher.start()
    try:
        server.run()
    finally:
        finished.set()
        watcher.join(timeout=1)

def _serve_transport(proxy, paths, data_dir, host, port, stop_event, *, allow_loopback_relay=False):
    """Own HTTPS and the optional outbound connector as one gateway lifetime."""
    from .relay import relay_settings_path, run_connector
    if not os.path.lexists(relay_settings_path(data_dir)):
        _run_https(proxy, paths, host, port, stop_event)
        return
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        raise OperationError("relay_listener", "Relay mode requires a numeric loopback HTTPS listener.")
    errors = []

    def connect():
        try:
            run_connector(data_dir, host, port, stop_event, allow_loopback=allow_loopback_relay)
            if not stop_event.is_set():
                raise RuntimeError("Relay connector stopped unexpectedly")
        except Exception as exc:
            errors.append(type(exc).__name__)
            stop_event.set()

    connector = threading.Thread(target=connect, name="rdpmonitor-relay", daemon=True)
    try:
        _run_https(proxy, paths, host, port, stop_event, on_started=connector.start)
    finally:
        stop_event.set()
        if connector.ident is not None:
            connector.join(timeout=20)
        if connector.is_alive():
            raise OperationError("relay_shutdown", "Outbound relay connector did not stop within its deadline.", 503)
    if errors:
        raise OperationError("relay_connector", f"Outbound relay connector failed ({errors[0]}); check protected relay settings.", 503)



def run_gateway(root: Path, data_dir: Path, host: str, port: int,
                stop_event: threading.Event, pipe_name=DEFAULT_PIPE, *, allow_loopback_relay=False):
    proxy = WorkerProxy(pipe_name)
    deadline = time.monotonic() + 30
    while True:
        try:
            paths = proxy.rpc("transport.tls")
            break
        except OperationError as exc:
            if exc.code != "worker_unavailable" or time.monotonic() >= deadline:
                raise
            if stop_event.wait(0.5):
                return
    _serve_transport(proxy, paths, data_dir, host, port, stop_event,
                     allow_loopback_relay=allow_loopback_relay)


def run_serve(root, data_dir, host, port, stop_event, read_only=False, *, allow_loopback_relay=False):
    from .runtime import AgentRuntime
    root, data_dir = _paths(root, data_dir)
    runtime = AgentRuntime(root, data_dir, read_only=read_only)
    try:
        runtime.start()
        identity = runtime.ca.ensure()
        print("RDPMonitor TLS SHA256 " + identity["fingerprint"], flush=True)
        _serve_transport(IntegratedProxy(runtime), identity, data_dir, host, port, stop_event,
                         allow_loopback_relay=allow_loopback_relay)
    finally:
        runtime.stop()


def _gateway_status(proxy, host, port):
    import urllib.request
    paths = proxy.rpc("transport.tls")
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=paths["ca_path"])
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    connect_host = "127.0.0.1" if host == "0.0.0.0" else "::1" if host == "::" else host
    display_host = f"[{connect_host}]" if ":" in connect_host else connect_host
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        urllib.request.HTTPSHandler(context=context))
    try:
        with opener.open(f"https://{display_host}:{port}/api/v1/health", timeout=5) as response:
            payload = response.read(65537)
            if len(payload) > 65536:
                raise ValueError("health response exceeds limit")
            value = json.loads(payload)
            if not isinstance(value, dict) or not value.get("agent_id"):
                raise ValueError("invalid health identity")
            return value
    except Exception:
        raise OperationError("gateway_unavailable", "Gateway HTTPS health or certificate verification failed.", 503)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "setup":
        from .setup import main as setup
        return setup(argv[1:])
    parser = argparse.ArgumentParser(prog="rdpmonitor-agent", description="RDPMonitor Windows agent")
    subparsers = parser.add_subparsers(dest="mode", required=True)
    default_root = Path(__file__).resolve().parent.parent
    default_data = Path(os.environ.get("PROGRAMDATA", str(Path.home()))) / "RDPMonitor"
    for mode in ("worker", "gateway", "serve", "pair", "status", "session-helper", "certificate-hosts"):
        command = subparsers.add_parser(mode)
        command.add_argument("--root", type=Path, default=default_root)
        command.add_argument("--data-dir", type=Path, default=default_data)
        command.add_argument("--pipe-name", default=DEFAULT_PIPE)
        if mode in ("gateway", "serve", "status"):
            command.add_argument("--host", default="127.0.0.1")
            command.add_argument("--port", type=int, default=8443)
        if mode in ("gateway", "serve"):
            command.add_argument("--allow-loopback-relay", action="store_true",
                                 help="Development only: allow relay HTTP on a numeric loopback IP; never skip TLS checks")
        if mode in ("worker", "serve"):
            command.add_argument("--read-only", action="store_true",
                                 help="Collect real telemetry; disable mutations, protection and schedules")
        if mode == "pair":
            command.add_argument("--role", choices=("owner", "operator", "viewer"), default="owner")
            command.add_argument("--ttl", type=int, default=300)
        if mode == "status":
            command.add_argument("--require-gateway", action="store_true",
                                 help="Also require verified HTTPS gateway health")
        if mode == "session-helper":
            command.add_argument("--session-id", type=int)
        if mode == "certificate-hosts":
            command.add_argument("--host", action="append", required=True,
                                 help="Complete locally approved DNS/IP SAN list; repeat for each endpoint")
    args = parser.parse_args(argv)
    stop_event = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop_event.set())
    try:
        if args.mode == "worker":
            run_worker(args.root, args.data_dir, stop_event, args.pipe_name, args.read_only)
        elif args.mode == "gateway":
            if not 1 <= args.port <= 65535:
                raise OperationError("port", "Port must be between 1 and 65535.")
            run_gateway(args.root, args.data_dir, args.host, args.port, stop_event, args.pipe_name,
                        allow_loopback_relay=args.allow_loopback_relay)
        elif args.mode == "serve":
            if not 1 <= args.port <= 65535:
                raise OperationError("port", "Port must be between 1 and 65535.")
            run_serve(args.root, args.data_dir, args.host, args.port, stop_event, args.read_only,
                      allow_loopback_relay=args.allow_loopback_relay)
        elif args.mode == "session-helper":
            from .session_helper import run_session_helper
            run_session_helper(stop_event, args.session_id)
        elif args.mode == "status":
            proxy = WorkerProxy(args.pipe_name)
            result = proxy.rpc("local.status")
            if args.require_gateway:
                result["gateway"] = _gateway_status(proxy, args.host, args.port)
                if result["gateway"].get("agent_id") != result.get("agent_id"):
                    raise OperationError("gateway_identity", "Gateway and worker agent identities differ.", 503)
            print(json.dumps(result, ensure_ascii=True))
        elif args.mode == "certificate-hosts":
            if not current_identity()["admin"]:
                raise OperationError("elevation_required", "Certificate host changes require local administrator approval.", 403)
            from .certificates import CertificateAuthority
            identity = CertificateAuthority(args.data_dir.resolve()).ensure(configured_hosts=args.host)
            print(json.dumps({"agent_id": identity["agent_id"], "fingerprint": identity["fingerprint"],
                              "hosts": args.host, "restart_worker_and_gateway": True}), flush=True)
        elif args.mode == "pair":
            if not current_identity()["admin"]:
                raise OperationError("elevation_required", "Local pairing requires an elevated administrator.", 403)
            if not 30 <= args.ttl <= 600:
                raise OperationError("ttl", "Pairing lifetime must be between 30 and 600 seconds.")
            params = {"ttl_seconds": args.ttl, "role": args.role}
            try:
                result = WorkerProxy(args.pipe_name).rpc("pairing.begin", params)
            except OperationError as exc:
                if exc.code != "worker_unavailable":
                    raise
                # Offline local enrollment approval never starts a second backend or scheduler.
                from .store import Store
                from .certificates import CertificateAuthority
                from .security import Security
                store = Store(args.data_dir.resolve())
                try:
                    authority = CertificateAuthority(args.data_dir.resolve())
                    authority.ensure()
                    result = Security(store, authority).begin_pairing(**params)
                finally:
                    store.close()
            print(json.dumps(result, ensure_ascii=True), flush=True)
        return 0
    except KeyboardInterrupt:
        stop_event.set()
        return 0
    except OperationError as exc:
        print(f"RDPMonitor error [{exc.code}]: {exc.message}", file=sys.stderr, flush=True)
        return 1
    except Exception as exc:
        # Exception payloads may contain credentials; operator gets a safe failure class only.
        print(f"RDPMonitor error [startup_failed]: {type(exc).__name__}; inspect protected agent diagnostics.",
              file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
