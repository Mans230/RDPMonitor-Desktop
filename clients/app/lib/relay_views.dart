import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'api.dart';
import 'design.dart';
import 'relay.dart';

const _releasesUrl = 'https://github.com/Mans230/RDPMonitor-Desktop/releases';

Future<void> showRelaySettingsDialog(BuildContext context) => showDialog<void>(
  context: context, barrierDismissible: false,
  builder: (_) => const _RelaySettingsDialog(),
);

Future<void> showPrepareInstallationDialog(BuildContext context) => showDialog<void>(
  context: context, barrierDismissible: false,
  builder: (_) => const _PrepareInstallationDialog(),
);

Future<void> showConnectCodeDialog(BuildContext context, {
  required Future<void> Function(MachineProfile) onEnrolled,
}) => showDialog<void>(
  context: context, barrierDismissible: false,
  builder: (_) => _ConnectCodeDialog(onEnrolled: onEnrolled),
);

String _relayError(Object error) {
  if (error is ApiException || error is RelayException) {
    // Even unexpected upstream diagnostics must not echo a pasted capability.
    return error.toString()
      .replaceAll(RegExp(r'rdpmonitor://[^\s]+'), '[private code]')
      .replaceAll(RegExp(r'[A-Za-z0-9_-]{43,}'), '[private value]');
  }
  if (error is SocketException) return 'Could not reach the relay. Check its address, network connection and deployment, then retry.';
  if (error is HandshakeException) return 'The HTTPS certificate could not be verified. Check the relay domain and certificate; certificate verification cannot be bypassed.';
  if (error is TimeoutException) return 'The request timed out. Check relay and agent connectivity before retrying.';
  return 'The operation could not be completed. Check the relay configuration and OS credential storage, then retry.';
}

Widget _notice(BuildContext context, String text) => Container(
  padding: const EdgeInsets.all(16),
  decoration: BoxDecoration(
    color: Theme.of(context).colorScheme.surfaceContainerLow,
    borderRadius: BorderRadius.circular(8),
  ),
  child: Text(text),
);

Widget _error(BuildContext context, String text) => Padding(
  padding: const EdgeInsets.only(top: 14),
  child: SelectableText(text, style: TextStyle(color: Theme.of(context).colorScheme.error)),
);

Future<bool> _confirmDestructive(BuildContext context, String title, String text) async =>
  await showDialog<bool>(context: context, builder: (dialog) => AlertDialog(
    icon: const Icon(Icons.warning_amber_outlined), title: Text(title),
    content: SizedBox(width: 460, child: SingleChildScrollView(child: Text(text))),
    actions: [
      TextButton(onPressed: () => Navigator.pop(dialog, false), child: const Text('Cancel')),
      FilledButton(
        style: FilledButton.styleFrom(backgroundColor: Theme.of(dialog).colorScheme.error),
        onPressed: () => Navigator.pop(dialog, true), child: const Text('Revoke'),
      ),
    ],
  )) ?? false;

class _RelaySettingsDialog extends StatefulWidget {
  const _RelaySettingsDialog();
  @override
  State<_RelaySettingsDialog> createState() => _RelaySettingsDialogState();
}

class _RelaySettingsDialogState extends State<_RelaySettingsDialog> {
  final _form = GlobalKey<FormState>();
  final _origin = TextEditingController();
  final _adminKey = TextEditingController();
  RelayPreferences? _saved;
  RelayAdminClient? _client;
  List<Map<String, dynamic>>? _agents;
  bool _busy = false;
  bool _loaded = false;
  String? _errorText;
  String? _status;

  @override
  void initState() { super.initState(); unawaited(_load()); }

  @override
  void dispose() {
    _client?.close();
    _origin.dispose(); _adminKey.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    setState(() { _busy = true; _errorText = null; });
    try {
      final prefs = await RelayPreferences.load();
      if (!mounted) return;
      _saved = prefs;
      _origin.text = prefs?.origin ?? '';
      _adminKey.text = prefs?.adminKey ?? '';
      _loaded = true;
      if (prefs != null) await _fetchAgents(prefs);
    } catch (e) {
      if (mounted) setState(() => _errorText = _relayError(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _fetchAgents(RelayPreferences prefs) async {
    final client = RelayAdminClient(origin: prefs.origin, adminKey: prefs.adminKey);
    _client = client;
    try {
      final agents = await client.agents();
      if (mounted) setState(() => _agents = agents);
    } finally {
      client.close();
      if (identical(_client, client)) _client = null;
    }
  }

  Future<void> _save() async {
    if (_busy || !_form.currentState!.validate()) return;
    setState(() { _busy = true; _errorText = null; _status = null; _agents = null; });
    try {
      final prefs = RelayPreferences(origin: _origin.text.trim(), adminKey: _adminKey.text.trim());
      await prefs.save();
      if (!mounted) return;
      _saved = prefs;
      _status = 'Saved in OS-protected credential storage.';
      await _fetchAgents(prefs);
    } catch (e) {
      if (mounted) setState(() => _errorText = _relayError(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _refresh() async {
    final prefs = _saved;
    if (_busy || prefs == null) return;
    setState(() { _busy = true; _errorText = null; _agents = null; });
    try { await _fetchAgents(prefs); }
    catch (e) { if (mounted) setState(() => _errorText = _relayError(e)); }
    finally { if (mounted) setState(() => _busy = false); }
  }

  Future<void> _revoke(Map<String, dynamic> agent) async {
    if (_busy || _saved == null) return;
    final approved = await _confirmDestructive(context, 'Revoke relay route?',
      'Revoke ${agent['name']} (${agent['route_id']})? This disconnects its active tunnels and permanently revokes its relay credentials and grants. It does not uninstall the Windows agent or delete its data.');
    if (!approved || !mounted) return;
    setState(() { _busy = true; _errorText = null; _status = null; });
    final prefs = _saved!;
    RelayAdminClient? client;
    try {
      client = RelayAdminClient(origin: prefs.origin, adminKey: prefs.adminKey);
      _client = client;
      await client.revokeAgent(agent['route_id'] as String);
      if (!mounted) return;
      setState(() { _status = 'Relay route revoked.'; _agents = null; });
      client.close();
      if (identical(_client, client)) _client = null;
      await _fetchAgents(prefs);
    } catch (e) {
      if (mounted) setState(() => _errorText = _relayError(e));
    } finally {
      client?.close();
      if (identical(_client, client)) _client = null;
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _clear() async {
    if (_busy) return;
    setState(() { _busy = true; _errorText = null; _status = null; });
    try {
      await RelayPreferences.clear();
      if (!mounted) return;
      setState(() {
        _saved = null; _agents = null; _origin.clear(); _adminKey.clear();
        _status = 'Local relay settings removed. Existing enrolled profiles and relay routes are unchanged.';
      });
    } catch (e) {
      if (mounted) setState(() => _errorText = _relayError(e));
    } finally { if (mounted) setState(() => _busy = false); }
  }

  @override
  Widget build(BuildContext context) => PopScope(canPop: !_busy, child: AlertDialog(
    icon: const Icon(Icons.hub_outlined), title: const Text('Self-hosted relay settings'),
    content: SizedBox(width: 560, child: SingleChildScrollView(child: Form(key: _form, child: Column(
      mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _notice(context, 'An operator must deploy and maintain the relay with an HTTPS domain and certificate. RDPMonitor does not supply a hosted relay. The administration key controls relay registration and revocation, not Windows agent permissions.'),
        const SizedBox(height: 20),
        TextFormField(controller: _origin, enabled: !_busy, autocorrect: false, enableSuggestions: false,
          decoration: const InputDecoration(labelText: 'Relay HTTPS origin', hintText: 'https://relay.example.com'),
          validator: (v) => v == null || v.trim().isEmpty ? 'Enter your self-hosted relay HTTPS origin.' : null),
        const SizedBox(height: 14),
        TextFormField(controller: _adminKey, enabled: !_busy, obscureText: true, autocorrect: false, enableSuggestions: false,
          decoration: const InputDecoration(labelText: 'Relay administration key', helperText: 'Stored in OS-protected credential storage on this device.'),
          validator: (v) => v == null || v.trim().isEmpty ? 'Enter the administration key configured by the operator.' : null),
        const SizedBox(height: 14),
        Wrap(spacing: 8, runSpacing: 8, children: [
          FilledButton(onPressed: _busy ? null : _save, child: const Text('Save & load routes')),
          TextButton(onPressed: _busy || _saved == null ? null : _clear, child: const Text('Remove local settings')),
        ]),
        if (_status != null) ...[const SizedBox(height: 14), Text(_status!)],
        const Divider(height: 32),
        SectionHeader(title: 'Registered relay routes', subtitle: 'Status is a snapshot from the saved relay configuration.',
          action: IconButton(tooltip: 'Refresh registered routes', onPressed: _busy || _saved == null ? null : _refresh, icon: const Icon(Icons.refresh))),
        const SizedBox(height: 12),
        if (_loaded && _saved == null) const Text('Save a relay origin and administration key to load registered routes.'),
        if (_agents != null && _agents!.isEmpty) const Text('No agents are registered with this relay.'),
        for (final agent in _agents ?? <Map<String, dynamic>>[]) Padding(
          padding: const EdgeInsets.only(bottom: 16),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(agent['name'] as String, style: Theme.of(context).textTheme.titleSmall),
            const SizedBox(height: 4),
            SelectableText('Route: ${agent['route_id']}\nAgent: ${agent['agent_id']}'),
            const SizedBox(height: 8),
            Wrap(spacing: 8, runSpacing: 8, crossAxisAlignment: WrapCrossAlignment.center, children: [
              StatusPill(label: agent['revoked'] == true ? 'Revoked' : agent['online'] == true ? 'Online' : 'Offline',
                tone: agent['revoked'] == true ? MonitorTone.danger : agent['online'] == true ? MonitorTone.success : MonitorTone.neutral),
              if (agent['revoked'] != true) TextButton.icon(
                onPressed: _busy ? null : () => _revoke(agent),
                icon: const Icon(Icons.link_off), label: const Text('Revoke route'),
                style: TextButton.styleFrom(foregroundColor: Theme.of(context).colorScheme.error)),
            ]),
          ]),
        ),
        if (_errorText != null) _error(context, _errorText!),
        if (!_loaded && !_busy) TextButton(onPressed: _load, child: const Text('Retry loading settings')),
        if (_busy) const Padding(padding: EdgeInsets.only(top: 14), child: LinearProgressIndicator()),
      ],
    )))),
    actions: [TextButton(onPressed: _busy ? null : () => Navigator.pop(context), child: const Text('Close'))],
  ));
}

class _PrepareInstallationDialog extends StatefulWidget {
  const _PrepareInstallationDialog();
  @override
  State<_PrepareInstallationDialog> createState() => _PrepareInstallationDialogState();
}

class _PrepareInstallationDialogState extends State<_PrepareInstallationDialog> {
  RelayPreferences? _prefs;
  RelayAdminClient? _client;
  RelayInstallationInvitation? _invitation;
  final _invitationText = TextEditingController();
  Timer? _clock;
  bool _busy = false;
  bool _loaded = false;
  bool _copied = false;
  String? _errorText;

  @override
  void initState() { super.initState(); unawaited(_load()); }
  @override
  void dispose() { _clock?.cancel(); _client?.close(); _invitationText.dispose(); super.dispose(); }
  bool get _expired => _invitation != null && !DateTime.now().toUtc().isBefore(_invitation!.expires);

  Future<void> _load() async {
    setState(() { _busy = true; _errorText = null; });
    try {
      final prefs = await RelayPreferences.load();
      if (mounted) setState(() { _prefs = prefs; _loaded = true; });
    } catch (e) { if (mounted) setState(() => _errorText = _relayError(e)); }
    finally { if (mounted) setState(() => _busy = false); }
  }

  Future<void> _settings() async {
    await showRelaySettingsDialog(context);
    if (mounted) await _load();
  }

  Future<void> _create() async {
    if (_busy || _prefs == null) return;
    _clock?.cancel();
    setState(() { _busy = true; _errorText = null; _invitation = null; _invitationText.clear(); _copied = false; });
    RelayAdminClient? client;
    try {
      client = RelayAdminClient(origin: _prefs!.origin, adminKey: _prefs!.adminKey);
      _client = client;
      final invitation = await client.createInstallationInvitation(ttlSeconds: 900);
      if (!mounted) return;
      setState(() { _invitation = invitation; _invitationText.text = invitation.invitation; });
      _clock = Timer.periodic(const Duration(seconds: 1), (timer) {
        if (!mounted) { timer.cancel(); return; }
        if (_expired) { timer.cancel(); setState(() {}); }
      });
    } catch (e) { if (mounted) setState(() => _errorText = _relayError(e)); }
    finally {
      client?.close();
      if (identical(_client, client)) _client = null;
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _copy() async {
    if (_invitation == null || _expired || _busy) return;
    try {
      await Clipboard.setData(ClipboardData(text: _invitation!.invitation));
      if (mounted) setState(() { _copied = true; _errorText = null; });
    } catch (_) { if (mounted) setState(() => _errorText = 'Could not copy the invitation. Check clipboard access and retry.'); }
  }

  @override
  Widget build(BuildContext context) => PopScope(canPop: !_busy, child: AlertDialog(
    icon: const Icon(Icons.install_desktop_outlined), title: const Text('Prepare agent installation'),
    content: SizedBox(width: 560, child: SingleChildScrollView(child: Column(
      mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _notice(context, 'Windows agents connect outward to your self-hosted relay. The operator must deploy it first. This creates a private, one-use installation invitation, not a connection code or Windows authorization.'),
        const SizedBox(height: 18),
        if (_prefs != null) Text('Relay: ${_prefs!.origin}'),
        if (_loaded && _prefs == null) ...[
          const Text('No relay is configured on this device. Configure your relay address and administration key first.'),
          const SizedBox(height: 10),
          Align(alignment: Alignment.centerLeft, child: OutlinedButton(onPressed: _busy ? null : _settings, child: const Text('Configure relay'))),
        ],
        const SizedBox(height: 18),
        Text('Windows installer availability', style: Theme.of(context).textTheme.titleSmall),
        const SizedBox(height: 6),
        const Text('Check the project releases for available artifacts and their labels. A signed production installer is not supplied by this dialog. Unsigned preview packages are evaluation builds, not trusted signed production installers.'),
        const SizedBox(height: 8),
        const SelectableText(_releasesUrl),
        const SizedBox(height: 18),
        const Text('1. Obtain the appropriate Windows package and verify its release instructions.\n2. Run setup on the VM, approve administrator elevation, and paste the installation invitation.\n3. Copy the private connection code shown by setup into Connect with code in this app.'),
        const SizedBox(height: 18),
        Align(alignment: Alignment.centerLeft, child: FilledButton.icon(
          onPressed: _busy || _prefs == null ? null : _create,
          icon: const Icon(Icons.key_outlined), label: Text(_invitation == null ? 'Create installation invitation' : 'Create another invitation'))),
        if (_invitation != null) ...[
          const SizedBox(height: 16),
          TextFormField(controller: _invitationText, readOnly: true, obscureText: true, enableInteractiveSelection: false,
            decoration: const InputDecoration(labelText: 'Private installation invitation')),
          const SizedBox(height: 10),
          Text('Expires: ${_invitation!.expires.toLocal()} (local time). One use only.'),
          if (_expired) _error(context, 'This invitation has expired. Create another invitation before installing.'),
          const SizedBox(height: 10),
          const Text('Copy only to the intended VM. Clipboard history or other applications may retain copied secrets. Successful use is enforced by the relay; this dialog does not track redemption.'),
          const SizedBox(height: 10),
          Align(alignment: Alignment.centerLeft, child: OutlinedButton.icon(
            onPressed: _busy || _expired ? null : _copy, icon: const Icon(Icons.copy_outlined), label: const Text('Copy private invitation'))),
          if (_copied) const Text('Invitation copied to the clipboard.'),
        ],
        if (_errorText != null) _error(context, _errorText!),
        if (!_loaded && !_busy) TextButton(onPressed: _load, child: const Text('Retry loading configuration')),
        if (_busy) const Padding(padding: EdgeInsets.only(top: 14), child: LinearProgressIndicator()),
      ],
    ))),
    actions: [TextButton(onPressed: _busy ? null : () => Navigator.pop(context), child: const Text('Close'))],
  ));
}

class _ConnectCodeDialog extends StatefulWidget {
  final Future<void> Function(MachineProfile) onEnrolled;
  const _ConnectCodeDialog({required this.onEnrolled});
  @override
  State<_ConnectCodeDialog> createState() => _ConnectCodeDialogState();
}

class _ConnectCodeDialogState extends State<_ConnectCodeDialog> {
  final _form = GlobalKey<FormState>();
  final _code = TextEditingController();
  final _name = TextEditingController();
  final _group = TextEditingController();
  final _device = TextEditingController(text: '${Platform.operatingSystem} operator');
  bool _busy = false;
  MachineProfile? _enrolled;
  String? _errorText;

  @override
  void dispose() { _code.dispose(); _name.dispose(); _group.dispose(); _device.dispose(); super.dispose(); }

  Future<void> _submit() async {
    if (_busy || !_form.currentState!.validate()) return;
    setState(() { _busy = true; _errorText = null; });
    try {
      // Preserve the successfully issued identity if local profile persistence fails.
      // Retrying that callback must not consume the one-use agent code again.
      final profile = _enrolled ?? await AgentApi.enrollRelay(
        connectionCode: _code.text.trim(), name: _name.text.trim(),
        group: _group.text.trim(), deviceName: _device.text.trim(),
      );
      _enrolled = profile;
      if (!mounted) return;
      await widget.onEnrolled(profile);
      if (mounted) Navigator.pop(context);
    } catch (e) {
      if (mounted) {
        setState(() => _errorText = _enrolled == null
          ? '${_relayError(e)}\nCheck that this is the full connection code from the intended VM, not an installation invitation. If expired or already used, generate a fresh connection code on that VM.'
          : 'The agent enrolled, but saving the profile failed. Keep this dialog open and choose Retry saving profile. ${_relayError(e)}');
      }
    } finally { if (mounted) setState(() => _busy = false); }
  }

  @override
  Widget build(BuildContext context) => PopScope(canPop: !_busy, child: AlertDialog(
    icon: const Icon(Icons.fingerprint_outlined), title: const Text('Connect with code'),
    content: SizedBox(width: 560, child: SingleChildScrollView(child: Form(key: _form, child: Column(
      mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _notice(context, 'Paste the private connection code obtained directly from the intended Windows VM. The app decrypts it locally and verifies the agent identity before enrollment. Never paste it into a browser or share it publicly.'),
        const SizedBox(height: 20),
        TextFormField(controller: _code, enabled: !_busy && _enrolled == null, obscureText: true, autocorrect: false, enableSuggestions: false,
          decoration: const InputDecoration(labelText: 'Private connection code', helperText: 'Paste the complete rdpmonitor://pair… code. It is short-lived and one-use.'),
          validator: (v) => v == null || v.trim().isEmpty ? 'Paste the connection code from the VM.' : null),
        const SizedBox(height: 14),
        TextFormField(controller: _name, enabled: !_busy && _enrolled == null,
          decoration: const InputDecoration(labelText: 'Machine display name (optional)', helperText: 'Leave blank to use the authenticated agent name.')),
        const SizedBox(height: 14),
        TextFormField(controller: _group, enabled: !_busy && _enrolled == null, decoration: const InputDecoration(labelText: 'Group (optional)')),
        const SizedBox(height: 14),
        TextFormField(controller: _device, enabled: !_busy && _enrolled == null, decoration: const InputDecoration(labelText: 'This device name'),
          validator: (v) => v == null || v.trim().isEmpty ? 'Enter a name identifying this client device.' : null),
        const SizedBox(height: 14),
        const Text('Enrollment uses the permissions approved locally on the agent. Closing this app later does not stop the agent or its running jobs.'),
        if (_errorText != null) _error(context, _errorText!),
        if (_busy) const Padding(padding: EdgeInsets.only(top: 14), child: LinearProgressIndicator()),
      ],
    )))),
    actions: [
      TextButton(onPressed: _busy ? null : () => Navigator.pop(context), child: const Text('Cancel')),
      FilledButton(onPressed: _busy ? null : _submit, child: Text(_enrolled == null ? 'Verify & enroll' : 'Retry saving profile')),
    ],
  ));
}
