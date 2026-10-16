import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'design.dart';

const _desktopChannel = MethodChannel('rdpmonitor/desktop');

String _desktopError(Object error) => error is PlatformException
    ? '${error.message ?? 'Windows could not complete the request'} (${error.code})'
    : error.toString();

Future<void> showDesktopSettings(BuildContext context) => showDialog<void>(
  context: context,
  builder: (_) => const _DesktopSettingsDialog(),
);

Future<void> _desktopAction(BuildContext context, String method) async {
  try {
    await _desktopChannel.invokeMethod<void>(method);
  } catch (error) {
    if (!context.mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text('Could not ${method == 'hide' ? 'hide' : 'exit'} the desktop client: ${_desktopError(error)}'),
    ));
  }
}

class DesktopMenu extends StatelessWidget {
  const DesktopMenu({super.key});

  @override
  Widget build(BuildContext context) => PopupMenuButton<String>(
    tooltip: 'Desktop client settings and actions',
    icon: const Icon(Icons.desktop_windows_outlined),
    onSelected: (action) {
      if (action == 'settings') {
        unawaited(showDesktopSettings(context));
      } else {
        unawaited(_desktopAction(context, action));
      }
    },
    itemBuilder: (_) => const [
      PopupMenuItem(value: 'settings', child: Text('Desktop settings')),
      PopupMenuItem(value: 'hide', child: Text('Hide to notification area')),
      PopupMenuItem(value: 'quit', child: Text('Exit desktop client')),
    ],
  );
}

class DesktopSettingsLauncher extends StatelessWidget {
  const DesktopSettingsLauncher({super.key});

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 18),
    child: MonitorPanel(padding: EdgeInsets.zero, child: ListTile(
      contentPadding: const EdgeInsets.symmetric(horizontal: 22, vertical: 12),
      leading: const Icon(Icons.desktop_windows_outlined),
      title: const Text('This desktop client'),
      subtitle: const Text('Windows sign-in, notification area and exit behavior. Agent jobs keep running.'),
      trailing: const Icon(Icons.chevron_right_outlined),
      onTap: () => showDesktopSettings(context),
    )),
  );
}

class _DesktopSettingsDialog extends StatefulWidget {
  const _DesktopSettingsDialog();

  @override
  State<_DesktopSettingsDialog> createState() => _DesktopSettingsDialogState();
}

class _DesktopSettingsDialogState extends State<_DesktopSettingsDialog> {
  bool _loaded = false;
  bool _busy = false;
  bool _startAtLogin = false;
  bool _closeToTray = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    unawaited(_loadState('getState'));
  }

  Future<void> _loadState(String method, [bool? value]) async {
    if (_busy) return;
    setState(() { _busy = true; _error = null; });
    try {
      final state = await _desktopChannel.invokeMapMethod<String, dynamic>(method, value);
      if (state == null || state['startAtLogin'] is! bool || state['closeToTray'] is! bool) {
        throw PlatformException(code: 'invalid_state', message: 'Windows returned an invalid desktop settings response.');
      }
      if (!mounted) return;
      setState(() {
        _startAtLogin = state['startAtLogin'] as bool;
        _closeToTray = state['closeToTray'] as bool;
        _loaded = true;
      });
    } catch (error) {
      if (mounted) setState(() => _error = 'Could not ${method == 'getState' ? 'load' : 'save'} desktop settings: ${_desktopError(error)}');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _act(String method) async {
    if (_busy) return;
    setState(() { _busy = true; _error = null; });
    try {
      await _desktopChannel.invokeMethod<void>(method);
      if (mounted) Navigator.of(context).pop();
    } catch (error) {
      if (mounted) setState(() => _error = 'Could not ${method == 'hide' ? 'hide' : 'exit'} the desktop client: ${_desktopError(error)}');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    icon: const Icon(Icons.desktop_windows_outlined),
    title: const Text('Desktop preferences'),
    content: SizedBox(width: 520, child: SingleChildScrollView(child: Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(color: Theme.of(context).colorScheme.surfaceContainerLow, borderRadius: BorderRadius.circular(8)),
          child: const Text('Only this client changes. The Windows agent, running jobs, schedules and backups continue when you hide or exit.'),
        ),
        const SizedBox(height: 24),
        Text('Startup & window behavior', style: Theme.of(context).textTheme.titleSmall),
        const SizedBox(height: 8),
        if (_busy) const LinearProgressIndicator(),
        if (_loaded) ...[
          SwitchListTile(
            contentPadding: EdgeInsets.zero,
            title: const Text('Start RDPMonitor at Windows sign-in'),
            subtitle: const Text('Open the desktop client automatically for your Windows account.'),
            value: _startAtLogin,
            onChanged: _busy ? null : (value) => _loadState('setStartAtLogin', value),
          ),
          const Divider(height: 20),
          SwitchListTile(
            contentPadding: EdgeInsets.zero,
            title: const Text('Close to notification area'),
            subtitle: const Text('Off by default. When enabled, the window Close button hides the client instead of exiting. Use Open RDPMonitor on the notification icon to return.'),
            value: _closeToTray,
            onChanged: _busy ? null : (value) => _loadState('setCloseToTray', value),
          ),
        ],
        if (_error != null) ...[
          const SizedBox(height: 12),
          SelectableText(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
          Align(alignment: Alignment.centerLeft, child: TextButton.icon(
            onPressed: _busy ? null : () => _loadState('getState'),
            icon: const Icon(Icons.refresh), label: const Text('Reload settings'),
          )),
        ],
        const SizedBox(height: 24),
        Text('Client session', style: Theme.of(context).textTheme.titleSmall),
        const SizedBox(height: 8),
        const Text('Hide keeps the client available from its notification icon. Exit closes only the desktop client, even when close to notification area is enabled.'),
        const SizedBox(height: 16),
        Wrap(spacing: 8, runSpacing: 8, children: [
          OutlinedButton.icon(onPressed: _busy ? null : () => _act('hide'), icon: const Icon(Icons.visibility_off_outlined), label: const Text('Hide to notification area')),
          OutlinedButton.icon(onPressed: _busy ? null : () => _act('quit'), icon: const Icon(Icons.exit_to_app_outlined), label: const Text('Exit desktop client')),
        ]),
      ],
    ))),
    actions: [TextButton(onPressed: () => Navigator.of(context).pop(), child: const Text('Done'))],
  );
}
