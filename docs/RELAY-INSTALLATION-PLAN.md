# Outbound relay installation and code pairing

## Goal and scope

Install the Windows agent on a VM without opening an inbound management port or configuring a VPN. The operator configures a self-hosted relay once, chooses Add machine with a name/group, then pastes one private command into an existing Administrator CMD window on the VM. The background agent installs without a VM wizard or desktop app; the operator desktop finishes encrypted enrollment automatically, without a return code. The installed agent reconnects outward and runs independently of the desktop window or RDP session.

The relay is a real deployable service, not GitHub Releases, a discovery mock, or a publicly hosted service supplied by this repository. Public hosting, a domain, HTTPS certificates and production publisher-signing credentials are operator prerequisites. Development verification must not be represented as a deployed internet service or signed installer acceptance.

Existing direct HTTPS connections remain supported. Windows remains the implemented agent platform. This work does not add Linux agents, hypervisor power control, mobile push or a commercial account system.

## Operator experience

1. Deploy the relay using the supplied container configuration and an HTTPS domain. Keep the bootstrap administration key private.
2. In the desktop app, configure the relay address and administration key once. These are protected client credentials, not source-code settings.
3. Choose **Add machine**, enter the name and optional group, create the command, approve the explicit unsigned monitoring-only evaluation notice when applicable, then choose **Copy CMD command**.
4. Open Command Prompt as Administrator on a fresh Windows VM, paste the line and press Enter. The bundled public bootstrap downloads only the native guest installer over validated HTTPS, verifies the app-pinned SHA256 and production publisher when applicable, and runs it silently. The command path always forces monitoring-only/viewer, including signed builds. Protected services use a loopback-only listener and outward relay connections.
5. The VM publishes its approved encrypted envelope under the desktop-selected pairing lookup. The waiting desktop authenticates the identity, enrolls a client certificate and probes ordinary mTLS automatically.
6. Pending intent and issued credentials are recoverable from OS-protected storage. Interrupted one-use issuance is not blindly replayed; advanced manual codes remain available for installed-agent recovery.

The copied CMD line is a private capability, not an ordinary public download link or globally resolvable six-digit PIN. Its setup URI is base64url-encoded into the caller environment; encoding does not hide it from clipboard/CMD history. Never share it or pass the whole line as `cmd /c` process arguments. The public bootstrap code contains no secret, executes no downloaded script, and clears generated environment values on both success and failure.

The existing version-one setup fragment contains an installation token and an independent desktop-generated pairing key, separated by a dot. Only the first capability is submitted during registration. No new broker endpoint or trusted web bootstrap is required: native setup imports the protected invitation before staging any install, publishes the existing origin-bound AES-GCM envelope with the second key, and desktop polling sends only its SHA256 identifier. Polling remains serialized every three seconds and bounded by the invitation lifetime plus a five-minute completion window.


## Trust boundaries

- The privileged Windows worker remains the authority for roles, confirmations, job admission, revocation and configuration. No relay credential authorizes a Windows operation.
- The constrained gateway retains TLS termination and existing local worker IPC. An outbound connector forwards bytes only to its fixed local gateway; it cannot be instructed to dial an arbitrary host or port.
- Desktop-to-agent HTTPS and mutual TLS run inside the relay tunnel. The broker forwards opaque TLS bytes and routing metadata. It never receives client private keys, the agent CA key, enrollment secrets in plaintext or decrypted administration traffic.
- Broker administration can register/revoke relay routes and consume resources. It is not equivalent to the Windows agent's owner role.
- Installation invitations are single-use and expiring. Agent enrollment remains atomically single-use under the existing local pairing transaction.
- Client and agent routing tokens are random transport capabilities, stored hashed at the relay and protected in Windows/desktop storage. They are not substitutes for enrolled client certificates. Revoking a device at the worker must still deny new API requests over an already established relay route.
- A malicious relay may observe metadata, drop, delay or misroute traffic. Misrouting must fail the agent certificate check before the desktop sends the enrollment secret. Availability cannot be guaranteed against the network intermediary.

## Connection-code confidentiality

A relay that can replace an agent fingerprint during code lookup could otherwise substitute a machine. Do not trust a fingerprint supplied in cleartext by the broker.

The VM creates a random 256-bit connection secret and a short-lived encrypted pairing envelope. The lookup identifier is SHA256(secret); the envelope is AES-256-GCM encrypted under that secret, with a fresh nonce and the normalized relay origin bound as associated data. Its plaintext contains the agent ID, agent TLS fingerprint, locally approved enrollment code, route capability and expiry. The broker stores only the lookup identifier and ciphertext.

The copied connection URI carries the relay origin and the secret in its fragment. The native app parses it locally: the secret must never appear in HTTP requests, browser navigation, query strings or broker logs. The desktop fetches ciphertext by lookup identifier, decrypts/authenticates it locally, validates expiry and origin binding, then uses the existing pinned enrollment flow inside the tunnel. A lookup fetch alone does not consume agent enrollment; successful enrollment does.

## Transport design

Use one outbound agent control WebSocket and a separate binary WebSocket pair for each desktop TCP connection. The control channel announces a fresh stream identifier; the agent opens the matching outbound data connection and connects it only to the local HTTPS gateway. The relay joins the two WebSockets without terminating the inner TLS session.

There is no new RPC interpreter in the relay and no replay of application requests. All existing HTTP routes, artifact downloads, chunked uploads, confirmations, request IDs and job results stay on the established encrypted agent API.

The desktop tunnel adapts WebSocket streams to a local loopback TCP socket used by `HttpClient.connectionFactory`. A custom direct factory replaces Dart's normal TLS connector: it **must return `SecureSocket.secure(localSocket, host: originalUri.host, context: originalSecurityContext)`**, not the plain socket. Enrollment must explicitly pass its exact-fingerprint callback into that handshake; ordinary connections have no permissive callback. The requested HTTPS host remains the agent's stable certificate name. Socket ownership, cancellation, queued bytes and shutdown must be bounded.

Agent control reconnects do not replay jobs. A disconnected data stream is closed, not silently reattached to another stream. Fresh connections use new stream identifiers; expired notifications and orphan stream records are removed. Both sides apply bounded connection counts, frame sizes, connection/attach deadlines and backpressure.

The broker uses the pinned Uvicorn sans-IO implementation for preassembly message limits/read-batch backpressure plus a native protocol adapter. Its connection-lost future, not submission of an ASGI close frame, ends quota accounting. A two-second hard transport-abort deadline releases stalled socket output; independently owned cleanup tasks survive endpoint cancellation. Deploy through the supplied single-process launcher.

## Broker service

Implement a self-hosted Python ASGI service, using SQLite for durable hashed registrations/invitations and a single process for live stream rendezvous. Do not imply that multiple independent workers share in-memory sockets. Container deployment includes a TLS reverse proxy and persistent storage, with no privileged host mounts.

Required operations:

- Administrator-authenticated creation of expiring installation invitations and route/grant revocation.
- Atomic invitation redemption into a unique agent route and protected agent credential; no replacement of an existing route by a supplied agent ID.
- Agent-authenticated outbound control/data channels, routing grants and encrypted pairing-envelope publication.
- Client-grant-authenticated binary connection channels and bounded encrypted-envelope lookup.
- Minimal public health, explicit offline/expired/invalid responses, bounded resource accounting and cleanup. No secret values or pairing envelopes in request logs.

Remote origins require HTTPS/WSS and ordinary certificate validation. Any loopback-only development transport exception must be explicit and must not become a general certificate-verification bypass in a release UI.

## Windows integration

Reuse existing worker/gateway service identities, Program Files ownership checks, protected ProgramData, machine-bound secret protection and session helper isolation. Add a stable per-agent certificate hostname for tunneled HTTPS without removing locally approved direct endpoint names.

The outbound connector belongs to the constrained network side. It must not receive worker database/CA access. Gateway-readable relay settings contain only the minimum connection credential; local administrative setup owns enrollment approval and durable configuration.

The installer must contain the complete runtime and operate on a protected payload, never pip-install into an arbitrary user environment. Existing signed deployment/update verification must remain intact. An unsigned preview installer must identify itself as such and must never be represented as a trusted signed production release. Publisher signing is an external credential requirement, not something to simulate.

Never pass installation secrets or connection codes in command-line arguments. Setup request/result files must be created under administrator/SYSTEM-owned protected directories before writing secrets. Repair must preserve machine identity, enrolled devices, data and firewall protection; removal must not relax unrelated protection policy or delete backup repositories.

Data-root hardening must preserve a noninheriting gateway grant for READ_CONTROL, FILE_READ_ATTRIBUTES and FILE_TRAVERSE only. Private child files/directories do not inherit it. Native setup, signed scripts and worker identity/CA/store initialization use the same rights; a runtime ACL reset must not make the constrained gateway unable to verify its protected ancestors.

Inno's post-install event does not roll back a committed runtime when its helper fails. Setup records that failure, shows explicit recovery instructions and returns custom exit code `42`; it must not show a successful connection or remove the runtime needed for same-release repair.

## Implementation work packages

1. Freeze the broker/code formats, storage limits and desktop transport contract against the actual SDK and existing lifecycle code.
2. Implement the real broker, encrypted envelope protocol and outbound connector; retain existing worker authorization and direct mode.
3. Implement protected relay preferences, installation-invitation creation, connection-code enrollment, durable relay profiles and ordinary API/file transfer through the tunnel in the desktop app.
4. Implement native Windows installation/setup, local code generation, protected service wiring, runtime packaging and reproducible installer builds.
5. Exercise the complete flow through real sockets: invitation -> registration -> outbound tunnel -> code decryption -> pinned enrollment -> mutual-TLS telemetry -> authorized job -> reconnect -> revocation. Build and run the affected applications.
6. Publish source, deployment instructions and only accurately verified/labeled release artifacts. Public relay deployment and signed clean-VM installer acceptance require their real prerequisites.

## Required observable acceptance

- No VM inbound management firewall rule or public management listener is needed for relay mode.
- Expired/reused installation invitations fail; an existing route cannot be stolen by reusing its identifier.
- Wrong envelope secret, tampered ciphertext/origin, expired pairing, wrong agent fingerprint and misrouted TLS fail before exposing the enrollment secret.
- The relay cannot issue Windows owner certificates or learn the plaintext agent request/response stream.
- Enrolled viewer/owner policies and device revocation remain effective through the relay, including requests on existing connections.
- Concurrent desktop resource requests, large upload/download streams, missing agents, network loss, reconnect and shutdown remain bounded and produce truthful results. Accepted jobs are not automatically resubmitted.
- Agent/server restarts preserve durable registrations and identity; duplicate active agent connections cannot silently take over an existing session.
- Desktop credentials and setup files do not expose tokens through plaintext preferences, arguments, logs, source control or release archives.
- The Windows setup surface is exercised and the produced application/installer binaries are built. Actual installed SCM identities, reboot/logoff behavior and signed update/rollback are validated only on a disposable Windows VM with console recovery, never by altering a production host as a smoke test.

## Observed implementation verification

The implementation passed 195 backend and 30 client tests, including actual existing-CMD success/failure cleanup; analyzer checks were clean and the native Windows debug client built and ran. Earlier packaged-agent verification and real selector sockets covered bounded hard-abort teardown and quota retention. Real Windows ACL/DPAPI fixtures covered gateway root-only metadata access without private-file reads.

The actual broker CLI and bundled worker/gateway were exercised through native desktop invitation creation, encrypted-code enrollment, live mTLS telemetry, view-job completion and duplicate request identity, read-only/viewer denial, SHA256-verified report download, revocation on an unchanged live TLS socket, certificate renewal, broker loss/reconnect without job replay, and desktop process exit/relaunch from protected credentials while resident sampling continued.

The simplified flow was exercised with native name/group entry, actual setup creation, close/reopen recovery, a real broker and Windows worker/gateway, encrypted automatic enrollment, authenticated disk telemetry and contract editing. Real certificate renewal preserved exact expiry/renewal dates and cost. Native two/three-column Backups layouts, sidebar toggling and a narrow pointer-operated drawer were inspected. A deliberately rejected final mTLS probe retained issued credentials across dialog close/reopen; restored connectivity saved the same identity with an unchanged device count. A pinned TLS response stalled beyond 58 seconds before the fix and hit the new 30-second body deadline afterward.

Preview 4 replaced normal installer-link/setup-code steps with one private Administrator CMD command and a distinct guest-only native artifact. The actual native preparation/consent/copy controls produced a 4,359-character command; close/reopen restored the same protected setup. A real strict HTTPS/WSS broker and frozen read-only worker/gateway completed encrypted automatic viewer enrollment and live disk telemetry with the requested name/group. Wide and narrow rendered dialogs were inspected. Guest packaging succeeded without Flutter; frozen protected import/cleanup succeeded with only OS tools on PATH. Real native silent entry rejected missing command mode/preview consent, malformed transport and retained identity before service installation. Actual HTTPS binary downloads reached SHA256 and Authenticode/publisher rejection with protected cache cleanup and no signature-to-preview fallback.


Earlier observations used explicit numeric-loopback development HTTP; Preview 4 used a strict fixture HTTPS CA trusted per-process without changing the Windows root store. Protected local fixtures used a native-verified virtual-service SID but no installed SCM service. They are not public Caddy/HTTPS hosting, constrained-token/reboot proof, signed publisher acceptance or a clean-VM installed setup test. Those external gates remain required before production deployment.
