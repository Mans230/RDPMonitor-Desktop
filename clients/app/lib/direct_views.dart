import 'dart:async';
import 'dart:io';
import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'api.dart';
import 'design.dart';
import 'direct_installation.dart';
import 'guest_installation.dart';
import 'guest_release.dart';

Future<void> showDirectInstallDialog(BuildContext context, {
  required Future<void> Function(MachineProfile) onEnrolled,
}) => showDialog<void>(
  context: context, barrierDismissible: false,
  builder: (_) => _DirectInstallDialog(onEnrolled: onEnrolled),
);

String _directError(Object error) {
  if (error is FormatException) return error.message.toString();
  if (error is ApiException) {
    return error.toString().replaceAll(RegExp(r'rdpmonitor://[^\s]+'), '[private setup]')
      .replaceAll(RegExp(r'-----BEGIN[^-]+-----[\s\S]*?-----END[^-]+-----'), '[private material]')
      .replaceAll(RegExp(r'[A-Za-z0-9_-]{43,}'), '[private value]');
  }
  if (error is HandshakeException) return 'The VM HTTPS identity does not match the prepared key, hostname or certificate lifetime. Do not bypass verification or reinstall over an existing VM. Check the address and both clocks.';
  if (error is SocketException || error is TimeoutException) return 'The VM is not reachable yet. Finish the installer, check the VM address and TCP port, and allow this desktop source in the provider/router firewall. No relay is required.';
  return 'Direct setup could not finish. Keep the pending identity, check OS credential storage and VM connectivity, then retry. Private keys were not replaced.';
}

class _DirectInstallDialog extends StatefulWidget {
  final Future<void> Function(MachineProfile) onEnrolled;
  const _DirectInstallDialog({required this.onEnrolled});
  @override
  State<_DirectInstallDialog> createState() => _DirectInstallDialogState();
}

class _DirectInstallDialogState extends State<_DirectInstallDialog> {
  final _form = GlobalKey<FormState>();
  final _name = TextEditingController();
  final _group = TextEditingController();
  final _endpoint = TextEditingController();
  final _source = TextEditingController();
  PendingDirectSetup? _pending;
  GuestInstallerRelease? _release;
  Timer? _timer;
  Future<void>? _pollTask;
  int _generation = 0;
  bool _loaded = false;
  bool _busy = false;
  bool _copying = false;
  bool _waiting = false;
  bool _stored = true;
  bool _consent = false;
  bool _copied = false;
  String? _error;
  String? _status;
  bool get _mustKeepOpen => _pending != null && !_stored;
  bool get _working => _busy || _copying;

  @override
  void initState() { super.initState(); unawaited(_load()); }
  @override
  void dispose() {
    _stopWaiting();
    _name.dispose(); _group.dispose(); _endpoint.dispose(); _source.dispose();
    super.dispose();
  }
  void _stopWaiting() { _generation++; _timer?.cancel(); _timer = null; _waiting = false; }

  Future<void> _load() async {
    setState(() { _busy = true; _error = null; });
    try {
      final pending = await PendingDirectSetup.load();
      if (!mounted) return;
      _pending = pending; _stored = true;
      if (pending != null) {
        _name.text = pending.name; _group.text = pending.group;
        _endpoint.text = pending.endpoint; _source.text = pending.source == 'auto' ? '' : pending.source;
      }
      try {
        final release = guestInstallerRelease();
        _release = release.setupProtocol >= 2 ? release : null;
      } catch (_) { _release = null; }
      _loaded = true;
    } catch (error) { if (mounted) _error = _directError(error); }
    finally { if (mounted) setState(() => _busy = false); }
    if (mounted && _loaded && _pending != null) {
      if (_pending!.stage == DirectSetupStage.waiting) {
        if (_pending!.canInstall) _startWaiting();
      } else { await _finish(); }
    }
  }

  Future<void> _prepare() async {
    if (_working || !_loaded || _pending != null || !_form.currentState!.validate()) return;
    setState(() { _busy = true; _error = null; _status = 'Creating two separate RSA identities on this desktop…'; });
    try {
      final pending = await PendingDirectSetup.create(name: _name.text, group: _group.text,
        endpoint: _endpoint.text, source: _source.text);
      _pending = pending; _stored = false;
      await pending.save(); _stored = true;
      _status = 'Prepared and protected on this desktop. Copy the command, then run it once in Administrator CMD on the VM.';
    } catch (error) { if (mounted) _error = _directError(error); }
    finally { if (mounted) setState(() => _busy = false); }
    if (mounted && _pending != null && _stored) _startWaiting();
  }

  void _startWaiting() {
    if (_working || _pending?.canInstall != true || !_stored) return;
    _stopWaiting();
    setState(() { _waiting = true; _error = null; _status = 'Waiting for the approved VM installation…'; });
    _pollTask = _poll(_generation);
    unawaited(_pollTask!);
  }
  Future<void> _poll(int generation) async {
    try {
      final issued = await _pending!.pollBootstrap();
      if (!mounted || generation != _generation) return;
      _stopWaiting();
      setState(() { _pending = issued; _stored = false; });
      await _retryStorage();
    } catch (error) {
      if (!mounted || generation != _generation) return;
      if ((error is SocketException || error is TimeoutException) && _pending!.canInstall) {
        setState(() => _status = 'Waiting for the VM. Check installation progress and provider TCP reachability if this continues.');
        _timer = Timer(const Duration(seconds: 3), () {
          if (mounted && generation == _generation) { _pollTask = _poll(generation); unawaited(_pollTask!); }
        });
      } else {
        _stopWaiting();
        setState(() => _error = _directError(error));
      }
    }
  }

  Future<void> _finish() async {
    if (_working || _pending?.profile == null) return;
    _stopWaiting();
    setState(() {
      _busy = true; _error = null;
      _status = _pending!.stage == DirectSetupStage.saved
        ? 'The profile is saved. Retrying only the protected completion acknowledgement…'
        : 'Verifying the issued viewer identity over normal mutual TLS, then saving…';
    });
    try {
      await _pending!.finish(onEnrolled: widget.onEnrolled);
      if (mounted) Navigator.pop(context);
    } catch (error) {
      // finish may already have committed the profile and erased the transport
      // key. Resume its checkpoint and idempotent live-fleet admission.
      try {
        final checkpoint = await PendingDirectSetup.load();
        if (checkpoint != null) { _pending = checkpoint; _stored = true; }
      } catch (_) { /* Retain the in-memory identity if vault reading fails. */ }
      if (mounted) {
        setState(() {
          _status = _pending!.stage == DirectSetupStage.saved
            ? 'The machine is saved and usable in Machines. Completion is still pending; retry does not add it again.'
            : 'The VM identity is retained. Retry verification and saving; do not reinstall or enroll another key.';
          _error = _directError(error);
        });
      }
    } finally { if (mounted) setState(() => _busy = false); }
  }

  Future<void> _retryStorage() async {
    if (_working || _pending == null) return;
    setState(() { _busy = true; _error = null; });
    try { await _pending!.save(); _stored = true; }
    catch (error) { if (mounted) _error = _directError(error); }
    finally { if (mounted) setState(() => _busy = false); }
    if (mounted && _stored) {
      if (_pending!.stage == DirectSetupStage.waiting) { _startWaiting(); }
      else { await _finish(); }
    }
  }

  Future<void> _copy() async {
    final pending = _pending;
    final release = _release;
    if (_working || pending == null || release == null || !_stored || !pending.canInstall ||
        (release.unsignedPreview && !_consent)) {
      return;
    }
    setState(() { _copying = true; _error = null; });
    try {
      final command = await buildGuestInstallCommand(setupUri: pending.setupUri, release: release, acceptUnsignedPreview: _consent);
      if (!mounted || !identical(_pending, pending) || !pending.canInstall) return;
      await Clipboard.setData(ClipboardData(text: command));
      if (mounted) setState(() { _copied = true; _status = 'Command copied. Paste into Administrator CMD on the VM. Leave this desktop open, or reopen Add machine to resume.'; });
    } catch (error) { if (mounted) setState(() => _error = _directError(error)); }
    finally { if (mounted) setState(() => _copying = false); }
    // A bootstrap bundle can arrive during asset/clipboard work. Resume its
    // checkpoint once copying releases the serialized action gate.
    if (mounted && _pending?.profile != null && !_busy) await _finish();
  }

  Future<void> _discard() async {
    if (_working || _mustKeepOpen) return;
    _stopWaiting();
    setState(() => _busy = true);
    // A poll may still be checkpointing its public response. Drain it before
    // deleting the vault entry, so it cannot resurrect a discarded intent.
    await _pollTask;
    if (!mounted) return;
    final approved = await showDialog<bool>(context: context, builder: (dialog) => AlertDialog(
      title: const Text('Discard local pending setup?'),
      content: const SizedBox(width: 460, child: SingleChildScrollView(child: Text(
        'This deletes only the pending identity on this desktop. It does not uninstall the VM, revoke its issued certificate, remove a saved profile or replace any VM identity. If already installed, keep this identity or approve recovery locally on the VM using Pair installed agent. A fresh command cannot take over an existing VM.'))),
      actions: [monitorDialogActions(dialog, [
        TextButton(onPressed: () => Navigator.pop(dialog, false), child: const Text('Keep identity')),
        FilledButton(onPressed: () => Navigator.pop(dialog, true), child: const Text('Discard pending setup')),
      ])],
    )) ?? false;
    if (!mounted) return;
    try {
      if (approved) {
        await PendingDirectSetup.clear();
        if (mounted) setState(() { _pending = null; _stored = true; _copied = false; _consent = false; _error = null; _status = null; });
      }
    } catch (error) { if (mounted) setState(() => _error = _directError(error)); }
    finally { if (mounted) setState(() => _busy = false); }
    if (mounted && !approved && _pending?.canInstall == true) _startWaiting();
  }

  void _close() {
    if (_working || _mustKeepOpen) return;
    _stopWaiting(); Navigator.pop(context);
  }
  String? _label(String? input, {bool isRequired = false}) {
    final value = input?.trim() ?? '';
    if (isRequired && value.isEmpty) return 'Enter a machine name.';
    if (value.length > 128 || RegExp(r'[\x00-\x1f\x7f]').hasMatch(value)) return 'Use up to 128 characters without control characters.';
    return null;
  }

  @override
  Widget build(BuildContext context) {
    final pending = _pending;
    final phone = MediaQuery.sizeOf(context).width < 560;
    final waiting = pending?.stage == DirectSetupStage.waiting;
    final body = SafeArea(child: Padding(padding: EdgeInsets.all(phone ? 16 : 24), child: Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        SectionHeader(title: 'Add machine', subtitle: 'Direct Windows VM installation · viewer access only',
          action: StatusPill(label: pending == null ? 'Direct' : pending.stage == DirectSetupStage.saved ? 'Saved · acknowledgement pending' : pending.stage == DirectSetupStage.issued ? 'Identity retained' : _waiting ? 'Waiting for VM' : 'Prepared')),
        const SizedBox(height: 8),
        Expanded(child: SingleChildScrollView(child: Form(key: _form, child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            const MonitorPanel(child: Text('Copy one command and run it in Administrator CMD on a fresh Windows VM. This desktop’s private client key stays on this PC. Knowing the VM IP or copied public certificate cannot claim the VM. No return code, account or relay is required.')),
            const SizedBox(height: 16),
            TextFormField(controller: _name, enabled: !_working && pending == null,
              decoration: const InputDecoration(labelText: 'Machine name'), validator: (value) => _label(value, isRequired: true)),
            const SizedBox(height: 12),
            TextFormField(controller: _group, enabled: !_working && pending == null,
              decoration: const InputDecoration(labelText: 'Group (optional)'), validator: _label),
            const SizedBox(height: 12),
            TextFormField(controller: _endpoint, enabled: !_working && pending == null,
              autocorrect: false, enableSuggestions: false,
              decoration: const InputDecoration(labelText: 'VM IP or hostname', hintText: '203.0.113.10 or vm.example.com:8443', helperText: 'HTTPS TCP 8443 by default. Use an address reachable from this desktop.'),
              validator: (value) { try { normalizeDirectEndpoint(value ?? ''); return null; } catch (error) { return _directError(error); } }),
            const SizedBox(height: 12),
            ExpansionTile(tilePadding: EdgeInsets.zero, title: const Text('Advanced: desktop source IP'),
              childrenPadding: const EdgeInsets.only(bottom: 12), children: [
                TextFormField(controller: _source, enabled: !_working && pending == null,
                  autocorrect: false, enableSuggestions: false,
                  decoration: const InputDecoration(labelText: 'Desktop source IP (optional)', hintText: 'Auto: unique active RDP TCP peer'),
                  validator: (value) { try { normalizeDirectSource((value ?? '').trim(), normalizeDirectEndpoint(_endpoint.text)); return null; } catch (error) { return _directError(error); } }),
                const SizedBox(height: 8),
                const Text('Auto detection runs on the VM and requires exactly one non-loopback established TCP peer on its configured RDP listener. No active RDP peer, multiple peers, or an RDP gateway/NAT mismatch requires your explicit desktop source IP. It never guesses from adapters or opens access to everyone. For an IPv6-only VM, enter an IPv6 literal endpoint; DNS uses an IPv4 listener.'),
              ]),
            const SizedBox(height: 8),
            const MonitorPanel(child: Text('Network requirement: the VM HTTPS port must be reachable from this desktop. The installer restricts its Windows TCP firewall rule to the detected or explicit desktop source. You must also permit that source/port in any provider firewall, security group or router; this command cannot configure your provider. If source detection fails, set the correct literal source here and prepare a fresh command before installing.')),
            const SizedBox(height: 16),
            if (!_loaded && !_busy) TextButton(onPressed: _load, child: const Text('Retry loading protected setup')),
            if (_release == null && _loaded) const Text('Command copying is unavailable: a verified guest release with secure direct setup protocol 2 is required. Existing pending identities remain recoverable.'),
            if (_release?.unsignedPreview == true && (pending == null || waiting)) ...[
              CheckboxListTile(contentPadding: EdgeInsets.zero, controlAffinity: ListTileControlAffinity.leading,
                value: _consent, onChanged: _working ? null : (value) => setState(() => _consent = value == true),
                title: const Text('I explicitly accept this unsigned monitoring-only preview.'),
                subtitle: const Text('Windows may warn or block it. Download hash verification is required and does not replace publisher signing. Monitoring-only/viewer access cannot perform agent write operations.')),
            ],
            if (pending != null) ...[
              const SizedBox(height: 8),
              MonitorPanel(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text('${pending.name} · ${pending.endpoint}', style: Theme.of(context).textTheme.titleMedium),
                const SizedBox(height: 8),
                Text(pending.stage == DirectSetupStage.saved
                  ? 'Saved profile retained. Only completion acknowledgement is pending; retries never add another profile.'
                  : pending.stage == DirectSetupStage.issued
                    ? 'The approved viewer certificate is protected locally. Verification retries reuse the same private key and certificate.'
                    : pending.canInstall
                      ? 'Install before ${pending.expires.toLocal()}. Closing this dialog preserves the same keys and command in OS credential storage.'
                      : 'The installation window expired. If the VM is installed, do not rerun setup: use locally approved Pair installed agent recovery on the VM. If it was never installed, discard this local intent before preparing a new command.'),
                const SizedBox(height: 8),
                const Text('Treat the command, clipboard and CMD history as private: the command includes this VM’s initial transport key, but never the desktop client private key or the VM CA private key.'),
              ])),
            ],
            if (_status != null) Padding(padding: const EdgeInsets.only(top: 14), child: Text(_status!)),
            if (_error != null) Padding(padding: const EdgeInsets.only(top: 14), child: SelectableText(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error))),
          ],
        )))),
        if (_working) const Padding(padding: EdgeInsets.only(top: 12), child: LinearProgressIndicator()),
        const SizedBox(height: 16),
        monitorDialogActions(context, [
          TextButton(onPressed: _working || _mustKeepOpen ? null : _close, child: Text(pending == null ? 'Cancel' : 'Close · keep setup')),
          if (pending != null) TextButton(onPressed: _working || _mustKeepOpen ? null : _discard, child: const Text('Discard local setup')),
          if (_mustKeepOpen) FilledButton(onPressed: _working ? null : _retryStorage, child: const Text('Retry protecting identity')),
          if (pending == null) FilledButton(onPressed: _working || !_loaded || _release == null ? null : _prepare, child: const Text('Prepare command')),
          if (pending != null && waiting && _stored) ...[
            if (!_waiting && pending.canInstall) OutlinedButton(onPressed: _working ? null : _startWaiting, child: const Text('Retry waiting')),
            FilledButton(onPressed: _working || !pending.canInstall || _release == null || (_release!.unsignedPreview && !_consent) ? null : _copy,
              child: Text(_copied ? 'Copy CMD again' : 'Copy CMD command')),
          ],
          if (pending?.profile != null && _stored) FilledButton(onPressed: _working ? null : _finish,
            child: Text(pending!.stage == DirectSetupStage.saved ? 'Retry acknowledgement' : 'Verify & save identity')),
        ]),
      ],
    )));
    return PopScope(canPop: !_working && !_mustKeepOpen,
      child: phone ? Dialog.fullscreen(child: body) : Dialog(child: SizedBox(width: 620,
        height: math.max(300, math.min(820, MediaQuery.sizeOf(context).height - 48)), child: body)));
  }
}
