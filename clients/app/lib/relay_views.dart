import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'api.dart';
import 'design.dart';
import 'guest_installation.dart';
import 'guest_release.dart';
import 'relay.dart';


Future<void> showRelaySettingsDialog(BuildContext context) => showDialog<void>(
  context: context, barrierDismissible: false,
  builder: (_) => const _RelaySettingsDialog(),
);

Future<void> showAddMachineDialog(BuildContext context, {
  required Future<void> Function(MachineProfile) onEnrolled,
}) => showDialog<void>(
  context: context, barrierDismissible: false,
  builder: (_) => _AddMachineDialog(onEnrolled: onEnrolled),
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

Future<bool> _confirmDestructive(BuildContext context, String title, String text, {String action = 'Revoke'}) async =>
  await showDialog<bool>(context: context, builder: (dialog) => AlertDialog(
    icon: const Icon(Icons.warning_amber_outlined), title: Text(title),
    content: SizedBox(width: 460, child: SingleChildScrollView(child: Text(text))),
    actions: [
      TextButton(onPressed: () => Navigator.pop(dialog, false), child: const Text('Cancel')),
      FilledButton(
        style: FilledButton.styleFrom(backgroundColor: Theme.of(dialog).colorScheme.error),
        onPressed: () => Navigator.pop(dialog, true), child: Text(action),
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

class _AddMachineDialog extends StatefulWidget {
  final Future<void> Function(MachineProfile) onEnrolled;
  const _AddMachineDialog({required this.onEnrolled});
  @override
  State<_AddMachineDialog> createState() => _AddMachineDialogState();
}

class _AddMachineDialogState extends State<_AddMachineDialog> {
  final _form = GlobalKey<FormState>();
  final _name = TextEditingController();
  final _group = TextEditingController();
  RelayPreferences? _prefs;
  RelayAdminClient? _admin;
  RelayPairingLookup? _lookup;
  PendingRelaySetup? _pending;
  MachineProfile? _issued;
  Timer? _pollTimer;
  int _generation = 0;
  bool _loaded = false;
  bool _busy = false;
  bool _waiting = false;
  bool _pendingStored = true;
  bool _copied = false;
  bool _previewAccepted = false;
  bool _copying = false;
  GuestInstallerRelease? _release;
  String? _errorText;
  bool get _mustKeepOpen => _issued != null && !_pendingStored;

  @override
  void initState() { super.initState(); unawaited(_load()); }
  @override
  void dispose() {
    _stopWaiting(); _admin?.close();
    _name.dispose(); _group.dispose();
    super.dispose();
  }

  void _stopWaiting() {
    _generation++; _pollTimer?.cancel(); _pollTimer = null;
    _lookup?.close(); _lookup = null; _waiting = false;
  }

  Future<void> _load() async {
    setState(() { _busy = true; _errorText = null; });
    try {
      final pending = await PendingRelaySetup.load();
      if (!mounted) return;
      _pending = pending;
      _pendingStored = true;
      if (pending != null) {
        _name.text = pending.name; _group.text = pending.group;
        if (pending.profile != null) _issued = MachineProfile.fromJson(pending.profile!);
      }
      _prefs = await RelayPreferences.load();
      if (!mounted) return;
      try { _release = guestInstallerRelease(); }
      catch (_) { _release = null; }
      setState(() => _loaded = true);
    } catch (error) {
      if (mounted) setState(() => _errorText = _relayError(error));
    } finally { if (mounted) setState(() => _busy = false); }
    if (mounted && _loaded && _pending?.stage == RelaySetupStage.waiting) _startWaiting();
  }

  Future<void> _settings() async {
    await showRelaySettingsDialog(context);
    if (mounted) await _load();
  }

  Future<void> _create() async {
    if (_busy || _prefs == null || _pending != null || !_form.currentState!.validate()) return;
    setState(() { _busy = true; _errorText = null; });
    RelayAdminClient? client;
    try {
      client = RelayAdminClient(origin: _prefs!.origin, adminKey: _prefs!.adminKey);
      _admin = client;
      final invitation = await client.createInstallationInvitation(ttlSeconds: 900);
      if (!mounted) return;
      final pending = PendingRelaySetup(setup: RelaySetupCode.create(invitation.invitation),
        name: _name.text.trim(), group: _group.text.trim(), expires: invitation.expires);
      // Do not expose a usable code until its decryption key is durably recoverable.
      _pending = pending; _pendingStored = false;
      await pending.save();
      _pendingStored = true;
    } catch (error) { if (mounted) setState(() => _errorText = _relayError(error)); }
    finally {
      client?.close(); if (identical(_admin, client)) _admin = null;
      if (mounted) setState(() => _busy = false);
    }
    if (mounted && _pending != null && _pendingStored) _startWaiting();
  }

  void _startWaiting() {
    if (_busy || _pending == null || !_pendingStored || _pending!.stage != RelaySetupStage.waiting) return;
    _stopWaiting();
    setState(() { _errorText = null; _waiting = true; });
    _lookup = RelayPairingLookup(_pending!.setup.connectionCode);
    unawaited(_poll(_generation));
  }

  Future<void> _poll(int generation) async {
    try {
      if (!_pending!.canWait()) throw const RelayException('Setup wait expired. If the VM was installed, use its fresh manual connection code in advanced Connect with code. Otherwise discard this setup and create another.');
      final pairing = await _lookup!.poll();
      if (!mounted || generation != _generation) return;
      if (pairing == null) {
        // Serialized 3-second polling stays below the broker's 60/source/minute limit.
        _pollTimer = Timer(const Duration(seconds: 3), () { if (mounted && generation == _generation) unawaited(_poll(generation)); });
        setState(() {});
        return;
      }
      _stopWaiting();
      await _enroll(pairing);
    } catch (error) {
      if (!mounted || generation != _generation) return;
      _stopWaiting();
      setState(() => _errorText = _relayError(error));
    }
  }

  Future<void> _enroll(RelayPairing pairing) async {
    setState(() { _busy = true; _errorText = null; });
    try {
      final existing = await ProfileVault().load();
      if (existing.any((profile) => profile.id == pairing.agentId)) {
        throw ApiException('This agent is already enrolled on this desktop. Its saved identity was not changed. Discard this pending setup and open the existing machine.');
      }
      final profile = await AgentApi.enrollRelay(
        connectionCode: _pending!.setup.connectionCode, name: _pending!.name, group: _pending!.group,
        deviceName: '${Platform.operatingSystem} operator',
        onEnrolling: () async {
          // Before POST, durably distinguish ambiguous issuance from safe waiting.
          final pending = _pending!.withEnrollment();
          await pending.save(); _pending = pending;
        },
        onIssued: (profile) async {
          _issued = profile; _pending = _pending!.withEnrollment(profile: profile.toJson()); _pendingStored = false;
          await _pending!.save(); _pendingStored = true;
        },
      );
      _issued = profile;
      await _finishProfile(probe: false);
    } catch (error) {
      if (mounted) {
        setState(() => _errorText = _issued != null
          ? 'The agent issued a device identity. Do not enroll again. Retry verifying and saving this identity. ${_relayError(error)}'
          : _pending!.stage == RelaySetupStage.enrolling
            ? 'Enrollment did not finish and may already have consumed the VM approval. It will not be replayed automatically. Generate a fresh code on the VM and use advanced Connect with code. ${_relayError(error)}'
            : _relayError(error));
      }
    } finally { if (mounted) setState(() => _busy = false); }
  }

  Future<void> _finishProfile({bool probe = true}) async {
    final profile = _issued!;
    if (!_pendingStored) { await _pending!.save(); _pendingStored = true; }
    if (probe) {
      final api = AgentApi(profile);
      try {
        final health = await api.call('GET', '/health');
        if (health['agent_id'] != profile.id) throw ApiException('Authenticated agent identity mismatch.');
      } finally { api.close(); }
    }
    final profiles = await ProfileVault().load();
    final matches = profiles.where((saved) => saved.id == profile.id);
    if (matches.isEmpty) {
      await widget.onEnrolled(profile);
    } else if (matches.single.deviceId != profile.deviceId || matches.single.certificate != profile.certificate) {
      throw ApiException('This agent already has a different saved device identity. The existing profile was not replaced. Resolve the duplicate in Machines before retrying.');
    }
    await PendingRelaySetup.clear();
    if (mounted) Navigator.pop(context);
  }

  Future<void> _retrySaving() async {
    if (_busy) return;
    setState(() { _busy = true; _errorText = null; });
    try {
      if (_issued != null) {
        await _finishProfile();
      } else {
        await _pending!.save(); _pendingStored = true;
      }
    } catch (error) { if (mounted) setState(() => _errorText = _relayError(error)); }
    finally { if (mounted) setState(() => _busy = false); }
    if (mounted && _issued == null && _pendingStored) _startWaiting();
  }

  Future<void> _discard() async {
    if (_busy || _mustKeepOpen) return;
    // Freeze/cancel polling before opening confirmation: it must not begin a
    // one-use enrollment underneath a dialog that could erase its checkpoint.
    _stopWaiting();
    setState(() {});
    if (!await _confirmDestructive(context, 'Discard pending setup?',
      'This removes only this desktop’s pending setup and private key. It does not revoke an installation invitation, installed agent, or an issued device certificate. Use relay settings or the VM to revoke those separately.', action: 'Discard')) {
      return;
    }
    if (!mounted || _busy || _mustKeepOpen) return;
    setState(() { _busy = true; _errorText = null; });
    try {
      await PendingRelaySetup.clear();
      if (mounted) setState(() { _pending = null; _issued = null; _copied = false; _previewAccepted = false; _pendingStored = true; });
    } catch (error) { if (mounted) setState(() => _errorText = _relayError(error)); }
    finally { if (mounted) setState(() => _busy = false); }
  }

  Future<void> _copy() async {
    final pending = _pending;
    final release = _release;
    if (_busy || _copying || pending == null || release == null || !_pendingStored ||
        !pending.canInstall() || pending.stage != RelaySetupStage.waiting ||
        (release.unsignedPreview && !_previewAccepted)) { return; }
    final generation = _generation;
    setState(() { _copying = true; _errorText = null; });
    try {
      final command = await buildGuestInstallCommand(setupUri: pending.setup.code,
        release: release, acceptUnsignedPreview: _previewAccepted);
      // Asset loading must not copy a cancelled, expired or consumed invitation.
      if (!mounted || generation != _generation || !identical(_pending, pending) ||
          !pending.canInstall() || _pending!.stage != RelaySetupStage.waiting) { return; }
      await Clipboard.setData(ClipboardData(text: command));
      if (mounted && generation == _generation && identical(_pending, pending)) setState(() => _copied = true);
    } catch (error) {
      if (mounted && generation == _generation) {
        setState(() => _errorText = error is FormatException
          ? error.message.toString()
          : 'Could not prepare or copy the CMD command. Check the bundled guest bootstrap and clipboard access, then retry.');
      }
    } finally { if (mounted) setState(() => _copying = false); }
  }

  void _close() {
    if (_busy || _mustKeepOpen) return;
    _stopWaiting();
    Navigator.pop(context);
  }

  String? _validateLabel(String? value, {bool isRequired = false}) {
    final text = value?.trim() ?? '';
    if (isRequired && text.isEmpty) return 'Enter a machine name.';
    if (text.length > 128 || RegExp(r'[\x00-\x1f]').hasMatch(text)) return 'Use up to 128 characters without control characters.';
    return null;
  }

  @override
  Widget build(BuildContext context) {
    final pending = _pending;
    return PopScope(canPop: !_busy && !_mustKeepOpen,
      onPopInvokedWithResult: (didPop, _) { if (didPop) _stopWaiting(); },
      child: AlertDialog(
      icon: const Icon(Icons.add_to_queue_outlined), title: const Text('Add machine'),
      content: SizedBox(width: 600, child: SingleChildScrollView(child: Form(key: _form, child: Column(
        mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (pending == null) ...[
            const Text('Name the Windows VM, then paste one private command into an Administrator Command Prompt on that VM. The background guest agent installs silently and this desktop connects automatically.'),
            const SizedBox(height: 18),
            TextFormField(controller: _name, enabled: !_busy, decoration: const InputDecoration(labelText: 'Machine name'),
              validator: (value) => _validateLabel(value, isRequired: true)),
            const SizedBox(height: 14),
            TextFormField(controller: _group, enabled: !_busy, decoration: const InputDecoration(labelText: 'Group (optional)'),
              validator: _validateLabel),
            if (_loaded && _prefs == null) ...[
              const SizedBox(height: 16),
              const Text('One-time prerequisite: configure your own certificate-valid HTTPS relay. No public relay is supplied.'),
              Align(alignment: Alignment.centerLeft, child: OutlinedButton(onPressed: _busy ? null : _settings, child: const Text('Configure relay'))),
            ],
            if (_prefs != null) Padding(padding: const EdgeInsets.only(top: 14), child: Text('Relay: ${_prefs!.origin}')),
          ] else ...[
            Text(pending.group.isEmpty ? pending.name : '${pending.name} · ${pending.group}', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 12),
            if (_issued != null) ...[
              _notice(context, _pendingStored
                ? 'The VM issued this desktop’s identity. It is retained in protected pending storage for authenticated verification and saving; no second enrollment is needed.'
                : 'The VM issued this desktop’s identity, but OS credential storage has not confirmed its recovery copy. It is still held in this dialog; keep it open and retry saving.'),
              if (_mustKeepOpen) _error(context, 'Secure storage has not confirmed the issued identity. Keep this dialog open and retry saving; closing now could lose access.'),
            ] else if (pending.stage == RelaySetupStage.enrolling) ...[
              _notice(context, 'Enrollment was interrupted after the one-use request could have begun. It cannot safely be replayed automatically. On the VM, generate a new manual connection code and use advanced Connect with code.'),
            ] else if (pending.stage == RelaySetupStage.enrolled) ...[
              _notice(context, 'The protected issued identity could not be loaded. Restore OS credential storage before trying enrollment again.'),
            ] else if (!_pendingStored) ...[
              _notice(context, 'The private command is unavailable until OS credential storage confirms its recovery key. Retry secure storage before installing.'),
            ] else ...[
              const Text('On the Windows VM, open Command Prompt as Administrator. Paste the copied line into that existing CMD window and press Enter. Keep this desktop open or reopen Add machine to connect automatically.'),
              const SizedBox(height: 12),
              _notice(context, 'Private capability: anyone with this command can use this one-VM invitation. Clipboard history, CMD history and transcription may retain it. Encoding is not encryption. Do not share it or pass it as a cmd /c argument.'),
              const SizedBox(height: 12),
              if (_release?.unsignedPreview ?? true)
                CheckboxListTile(
                  contentPadding: EdgeInsets.zero, controlAffinity: ListTileControlAffinity.leading,
                  value: _previewAccepted,
                  onChanged: _busy || _copying ? null : (value) => setState(() => _previewAccepted = value ?? false),
                  title: const Text('I accept the unsigned monitoring-only preview.'),
                  subtitle: const Text('Only continue if you trust this release source. The guest remains read-only; no administration, RDP, firewall or account changes are enabled.'),
                )
              else
                const Text('Publisher-verified Windows x64 guest agent · monitoring-only.'),
              const SizedBox(height: 10),
              Align(alignment: Alignment.centerLeft, child: OutlinedButton.icon(
                onPressed: _busy || _copying || !pending.canInstall() || _release == null ||
                  (_release!.unsignedPreview && !_previewAccepted) ? null : _copy,
                icon: const Icon(Icons.copy_outlined),
                label: Text(_copying ? 'Preparing command…' : _copied ? 'CMD command copied' : 'Copy CMD command'))),
              Text('Run before ${pending.expires.toLocal().toString().split('.').first}. One VM only.'),
              const SizedBox(height: 14),
              Text(_waiting ? 'Waiting for the VM. Connects automatically — no code to bring back.' : 'Waiting paused. Resume when the VM is ready.'),
              if (!pending.canInstall()) const Text('The installation invitation expired. A VM registered before expiry may still finish within the bounded five-minute enrollment window.'),
              if (!pending.canWait()) _error(context, 'The setup window ended. Use a fresh manual connection code on an installed VM, or discard and create a new setup for a VM not installed yet.'),
            ],
            const SizedBox(height: 14),
            const Text('Close and reopen Add machine to resume this setup. Its private key stays in OS-protected storage.'),
          ],
          if (_loaded && _release == null)
            _error(context, 'The trusted guest installer release configuration is unavailable. Existing pending enrollment can still resume; new installation commands cannot be copied.'),
          if (_errorText != null) _error(context, _errorText!),
          if (!_loaded && !_busy) TextButton(onPressed: _load, child: const Text('Retry loading protected settings')),
          if (_busy || _waiting) const Padding(padding: EdgeInsets.only(top: 14), child: LinearProgressIndicator()),
        ],
      )))),
      actions: [
        if (pending != null) TextButton(onPressed: _busy || _mustKeepOpen ? null : _discard, child: const Text('Discard setup')),
        TextButton(onPressed: _busy || _mustKeepOpen ? null : _close,
          child: Text(pending == null ? 'Cancel' : 'Close')),
        if (pending == null)
          FilledButton(onPressed: _busy || !_loaded || _prefs == null || _release == null ? null : _create, child: const Text('Prepare CMD command'))
        else if (_issued != null || !_pendingStored)
          FilledButton(onPressed: _busy ? null : _retrySaving, child: Text(_issued != null ? 'Verify & save identity' : 'Retry secure storage'))
        else if (pending.stage == RelaySetupStage.waiting && !_waiting && pending.canWait())
          FilledButton(onPressed: _busy ? null : _startWaiting, child: const Text('Resume waiting')),
      ],
    ));
  }
}

class _ConnectCodeDialog extends StatefulWidget {
  final Future<void> Function(MachineProfile) onEnrolled;
  const _ConnectCodeDialog({required this.onEnrolled});
  @override
  State<_ConnectCodeDialog> createState() => _ConnectCodeDialogState();
}

class _ConnectCodeDialogState extends State<_ConnectCodeDialog> {
  static const _checkpoint = 'rdpmonitor.pending-manual-enrollment.v1';
  final _vault = ProfileVault();
  final _form = GlobalKey<FormState>();
  final _code = TextEditingController();
  final _name = TextEditingController();
  final _group = TextEditingController();
  final _device = TextEditingController(text: '${Platform.operatingSystem} operator');
  bool _busy = false;
  bool _ready = false;
  bool _stored = false;
  bool _admitted = false;
  MachineProfile? _enrolled;
  String? _errorText;
  bool get _mustKeepOpen => _enrolled != null && !_stored;

  @override
  void initState() { super.initState(); unawaited(_loadIssued()); }
  @override
  void dispose() { _code.dispose(); _name.dispose(); _group.dispose(); _device.dispose(); super.dispose(); }

  Future<void> _loadIssued() async {
    setState(() { _busy = true; _errorText = null; });
    try {
      final raw = await _vault.storage.read(key: _checkpoint);
      if (!mounted) return;
      if (raw != null) {
        if (raw.length > 262144) throw const RelayException('The protected recovery record exceeds its safety limit.');
        final profile = MachineProfile.fromJson(Map<String, dynamic>.from(jsonDecode(raw)));
        final validation = AgentApi(profile); validation.close();
        _enrolled = profile; _stored = true;
        _name.text = profile.name; _group.text = profile.group;
      }
      _ready = true;
    } catch (error) {
      if (mounted) _errorText = 'Could not load the protected enrollment checkpoint. Do not enroll again until it is restored. ${_relayError(error)}';
    } finally { if (mounted) setState(() => _busy = false); }
  }

  Future<void> _storeIssued(MachineProfile profile) async {
    _enrolled = profile; _stored = false;
    final raw = jsonEncode(profile.toJson());
    await _vault.storage.write(key: _checkpoint, value: raw);
    if (await _vault.storage.read(key: _checkpoint) != raw) {
      throw const RelayException('The issued identity could not be verified in OS-protected storage.');
    }
    _stored = true;
  }

  Future<void> _clearIssued() async {
    await _vault.storage.delete(key: _checkpoint);
    if (await _vault.storage.read(key: _checkpoint) != null) {
      throw const RelayException('The enrollment recovery record could not be removed.');
    }
  }

  Future<void> _submit() async {
    if (_busy || !_ready || (_enrolled == null && !_form.currentState!.validate())) return;
    setState(() { _busy = true; _errorText = null; });
    try {
      if (!_admitted) {
        if (_enrolled == null) {
          await AgentApi.enrollRelay(connectionCode: _code.text.trim(), name: _name.text.trim(),
            group: _group.text.trim(), deviceName: _device.text.trim(), onIssued: _storeIssued);
        } else {
          if (!_stored) await _storeIssued(_enrolled!);
          final probe = AgentApi(_enrolled!);
          try { await probe.call('GET', '/health'); } finally { probe.close(); }
        }
        await widget.onEnrolled(_enrolled!);
        _admitted = true;
      }
      await _clearIssued();
      if (mounted) Navigator.pop(context);
    } catch (error) {
      if (mounted) {
        setState(() => _errorText = _enrolled == null
          ? '${_relayError(error)}\nUse the full connection code from the intended VM. If expired or consumed, generate a fresh code there.'
          : _admitted
            ? 'The machine was saved. Retry removing its temporary recovery record; enrollment will not be repeated. ${_relayError(error)}'
            : 'The agent issued an identity. Verify and save it instead of enrolling again. ${_relayError(error)}');
      }
    } finally { if (mounted) setState(() => _busy = false); }
  }

  Future<void> _discard() async {
    if (_busy || !_ready) return;
    if (!await _confirmDestructive(context, 'Discard local recovery identity?',
      'This erases only the temporary enrollment checkpoint, not any saved machine profile or remote certificate. If this identity was never saved, generate a fresh approval on the VM before connecting again. Revoke the unused certificate there if access must end.', action: 'Discard')) {
      return;
    }
    if (!mounted) return;
    setState(() { _busy = true; _errorText = null; });
    try { await _clearIssued(); if (mounted) Navigator.pop(context); }
    catch (error) { if (mounted) setState(() => _errorText = _relayError(error)); }
    finally { if (mounted) setState(() => _busy = false); }
  }

  @override
  Widget build(BuildContext context) => PopScope(canPop: !_busy && !_mustKeepOpen, child: AlertDialog(
    icon: const Icon(Icons.fingerprint_outlined), title: const Text('Connect with code'),
    content: SizedBox(width: 560, child: SingleChildScrollView(child: Form(key: _form, child: Column(
      mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _notice(context, _enrolled == null
          ? 'Paste the private connection code obtained directly from the intended Windows VM. The app decrypts it locally and verifies the agent identity before enrollment. Never paste it into a browser or share it publicly.'
          : 'An issued device identity is held in OS-protected recovery storage. Verify its authenticated connection and save it; the one-use enrollment will not be repeated.'),
        const SizedBox(height: 20),
        if (_enrolled == null) ...[
          TextFormField(controller: _code, enabled: _ready && !_busy, obscureText: true, autocorrect: false, enableSuggestions: false,
            decoration: const InputDecoration(labelText: 'Private connection code', helperText: 'Paste the complete rdpmonitor://pair… code. It is short-lived and one-use.'),
            validator: (v) => v == null || v.trim().isEmpty ? 'Paste the connection code from the VM.' : null),
          const SizedBox(height: 14),
          TextFormField(controller: _name, enabled: _ready && !_busy,
            decoration: const InputDecoration(labelText: 'Machine display name (optional)', helperText: 'Leave blank to use the authenticated agent name.')),
          const SizedBox(height: 14),
          TextFormField(controller: _group, enabled: _ready && !_busy, decoration: const InputDecoration(labelText: 'Group (optional)')),
          const SizedBox(height: 14),
          TextFormField(controller: _device, enabled: _ready && !_busy, decoration: const InputDecoration(labelText: 'This device name'),
            validator: (v) => v == null || v.trim().isEmpty ? 'Enter a name identifying this client device.' : null),
        ] else ...[
          Text(_enrolled!.name, style: Theme.of(context).textTheme.titleMedium),
          Text('Group: ${_enrolled!.group.isEmpty ? 'Ungrouped' : _enrolled!.group}'),
        ],
        const SizedBox(height: 14),
        const Text('Enrollment uses permissions approved locally on the agent. Closing this app later does not stop the agent or its jobs.'),
        if (_errorText != null) _error(context, _errorText!),
        if (_busy) const Padding(padding: EdgeInsets.only(top: 14), child: LinearProgressIndicator()),
      ],
    )))),
    actions: [
      if (_enrolled != null) TextButton(onPressed: _busy ? null : _discard, child: const Text('Discard recovery record')),
      TextButton(onPressed: _busy || _mustKeepOpen ? null : () => Navigator.pop(context), child: const Text('Close')),
      FilledButton(onPressed: _busy ? null : _ready ? _submit : _loadIssued,
        child: Text(!_ready ? 'Retry loading identity' : _admitted ? 'Finish cleanup' : _enrolled == null ? 'Verify & enroll' : 'Verify & save identity')),
    ],
  ));
}
