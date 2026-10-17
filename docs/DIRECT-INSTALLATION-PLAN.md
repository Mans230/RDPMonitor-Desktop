# Direct VM installation

## Intended operator flow

1. In the desktop, choose **Add machine**, enter a name/group and the Windows VM's IP or hostname. HTTPS defaults to port 8443.
2. Prepare and copy one private installation command. The app retains the same pending identity in OS-protected storage when closed/reopened.
3. Paste into Administrator Command Prompt inside the VM. The guest-only installer configures the background agent; no VM desktop app, relay account or return code is required.
4. The desktop verifies the VM's preapproved transport identity, retrieves its already-issued public client certificate and verifies ordinary mutual TLS before saving the machine.

The source address defaults to the unique established TCP RDP peer on the VM. An explicit desktop source IP is available under advanced settings. If no unique peer can be determined, setup fails before installation rather than opening the firewall to everyone. RDP gateways, provider consoles and multiple concurrent RDP peers may require the override.

## Trust and ownership

An IP address is a locator, not an authority. Before command generation the desktop creates its client key/CSR and a separate initial VM transport key. The desktop private key never enters the command or leaves the PC. Locally approved guest setup creates its own private CA and preissues a monitoring-only viewer certificate to the exact CSR supplied in the command. There is no public direct-setup registration that can substitute another desktop key.

Bootstrap HTTPS is pinned to the expected server RSA public key, including host, port and validity checks; it does not accept arbitrary certificates. Once the public certificate bundle is validated, the desktop uses the agent's CA, hostname verification and its private client key for normal mTLS. The VM CA private key remains on the VM. Public bootstrap lookup cannot issue credentials, and completion requires the bound client's mTLS identity.

Issued credentials are checkpointed before the final probe. A failed probe or secure-storage write must resume the same identity, not issue another certificate. Completion after saving cannot remove or duplicate the saved machine. Expiry, wrong keys, revoked devices and retained installations are rejected. Local discard never revokes remote devices or resets a VM.

## Installation boundary

The existing trusted bundled bootstrap downloads the guest installer over HTTPS and verifies its pinned SHA256 and production publisher when applicable. Native setup consumes the private environment payload through a protected exchange; private values do not enter helper arguments or download URLs. The copied command and clipboard/history remain sensitive.

Direct CMD setup is fresh-machine-only and monitoring-only/viewer, whether signed or unsigned. It must refuse retained identity/services instead of taking over an installed machine. Existing relay setup remains an advanced alternative; direct installation never requires relay settings.

The Windows inbound rule is restricted to the guest executable, chosen TCP port and one literal desktop source address. RDP policy is unchanged. Provider security groups and routers remain outside the installer's control. Dynamic desktop public-IP changes require an explicitly authorized source-rule update; the agent must not silently broaden access. DNS endpoints use IPv4 by default; an IPv6 literal selects IPv6 binding.

## Protocol and recovery

The private `rdpmonitor://direct?v=1#...` capability contains bounded raw-DEFLATE JSON in canonical base64url. Its exact fields are version, HTTPS endpoint, initial server transport key, desktop CSR, random nonce, expiry and source selection. It contains neither the desktop private key nor a VM CA private key. Parsing rejects unknown/duplicate fields, malformed keys, unsafe origins, trailing streams and oversized/decompression-bomb input.

The guest publishes only the bound device's public certificate/CA and identity through an expiring bootstrap lookup. Installed identity is never replaced on retry. Same-release repair preserves identity and direct network scope. Expired installed-machine recovery requires explicit local approval through the advanced direct pairing path.

## Verification gates

- Wrong IP/server key, wrong CSR/private key, expired nonce and revoked device must not produce usable access.
- Knowing the IP, nonce or public certificate must not authenticate another desktop.
- Fresh-state, source-address and command-size checks must fail before installation side effects.
- Reopen, failed final probe, storage failure and completion retries must preserve one issued identity.
- Exercise real direct HTTPS/mTLS through the native desktop and packaged foreground worker/gateway, without installing services/firewall rules on the development workstation.
- Installed SCM/reboot, real provider routing/firewall behavior and production signing require a disposable Windows VM and the corresponding deployment credentials. A local smoke run is not a claim that those external gates passed.
