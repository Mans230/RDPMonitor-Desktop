import 'dart:async';
import 'dart:io';
import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';
import 'api.dart';
import 'state.dart';
import 'views.dart';
import 'transfers.dart';
import 'desktop.dart';
import 'design.dart';
import 'relay_views.dart';
import 'direct_views.dart';
import 'fleet_views.dart';
import 'operation_layout.dart';

void main() { WidgetsFlutterBinding.ensureInitialized(); runApp(const MonitorApp()); }
class MonitorApp extends StatelessWidget {
  const MonitorApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'RDPMonitor', debugShowCheckedModeBanner: false, themeMode: ThemeMode.system,
    theme: buildMonitorTheme(Brightness.light), darkTheme: buildMonitorTheme(Brightness.dark), home: const Workspace(),
    builder: (context, child) {
      final media = MediaQuery.of(context);
      final theme = Theme.of(context);
      final height = (media.size.height - media.viewInsets.bottom - media.padding.vertical).clamp(0.0, double.infinity);
      if (media.size.width >= 560) {
        // Material controls animate their local themes across window resizes.
        // Both sides need finite dialog bounds for ThemeData interpolation.
        return Theme(data: theme.copyWith(dialogTheme: theme.dialogTheme.copyWith(
          constraints: BoxConstraints(maxWidth: 600, maxHeight: height),
        )), child: child!);
      }
      return Theme(data: theme.copyWith(
        visualDensity: VisualDensity.standard,
        materialTapTargetSize: MaterialTapTargetSize.padded,
        filledButtonTheme: FilledButtonThemeData(style: theme.filledButtonTheme.style?.copyWith(minimumSize: const WidgetStatePropertyAll(Size(44, 40)))),
        outlinedButtonTheme: OutlinedButtonThemeData(style: theme.outlinedButtonTheme.style?.copyWith(minimumSize: const WidgetStatePropertyAll(Size(44, 40)))),
        textButtonTheme: TextButtonThemeData(style: theme.textButtonTheme.style?.copyWith(minimumSize: const WidgetStatePropertyAll(Size(44, 40)))),
        iconButtonTheme: IconButtonThemeData(style: theme.iconButtonTheme.style?.copyWith(minimumSize: const WidgetStatePropertyAll(Size(40, 40)))),
        dialogTheme: theme.dialogTheme.copyWith(
          insetPadding: EdgeInsets.zero,
          constraints: BoxConstraints(minWidth: media.size.width, maxWidth: media.size.width, minHeight: height, maxHeight: height),
          shape: const RoundedRectangleBorder(),
        ),
      ), child: child!);
    },
  );
}

const destinations = <String, IconData>{
  'Machines': Icons.computer_outlined, 'Overview': Icons.dashboard_outlined,
  'Monitoring': Icons.monitor_heart_outlined, 'Security': Icons.shield_outlined,
  'Accounts': Icons.people_outline, 'Processes': Icons.memory_outlined,
  'Services': Icons.miscellaneous_services_outlined,
  'Backups': Icons.backup_outlined, 'Recovery': Icons.restore_outlined,
  'Files': Icons.folder_outlined,
  'Diagnostics': Icons.troubleshoot, 'Imaging': Icons.disc_full_outlined,
  'Automation': Icons.schedule_outlined, 'Activity': Icons.history,
  'Settings': Icons.settings_outlined, 'Devices & access': Icons.key_outlined,
  'Maintenance & help': Icons.help_outline, 'Setup': Icons.add_circle_outline,
};

// Grouped in working order: pick a machine, watch it, protect it, change it,
// then manage the agent itself. Diagnostics sits with observation because it
// answers "what is happening"; imaging sits with management because it changes
// the operating system rather than recovering data.
const navigationGroups = <String, List<String>>{
  'Fleet': ['Machines'],
  'Observe': ['Overview', 'Monitoring', 'Diagnostics', 'Activity'],
  'Protect & recover': ['Security', 'Backups'],
  'Manage': ['Accounts', 'Processes', 'Files', 'Automation', 'Imaging'],
  'Workspace': ['Settings', 'Devices & access', 'Setup', 'Maintenance & help'],
};

class Workspace extends StatefulWidget {
  const Workspace({super.key});
  @override
  State<Workspace> createState() => _WorkspaceState();
}
class _WorkspaceState extends State<Workspace> {
  final Fleet fleet = Fleet();
  final scaffold = GlobalKey<ScaffoldState>();
  String page = 'Machines';
  String search = '';
  bool sidebarVisible = true;
  String? error;
  @override
  void initState() { super.initState(); fleet.addListener(changed); unawaited(fleet.initialize()); }
  void changed() { if (mounted) setState(() {}); }
  @override
  void dispose() { fleet.removeListener(changed); fleet.dispose(); super.dispose(); }
  Future<T?> attempt<T>(Future<T> Function() action) async {
    try { final value = await action(); if (mounted) setState(() => error = null); return value; }
    catch (e) { if (mounted) setState(() => error = e.toString()); return null; }
  }
  void message(String text) { if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(text))); }
  Future<void> enroll() => showDirectInstallDialog(context, onEnrolled: fleet.add);
  Future<void> enrollDirect() async {
    await showDialog<void>(context: context, barrierDismissible: false, builder: (_) => EnrollmentDialog(onEnrolled: fleet.add));
  }
  Future<void> connectionAction(String action) async {
    switch (action) {
      case 'connect': await showConnectCodeDialog(context, onEnrolled: fleet.add);
      case 'relay': if (mounted) await showRelaySettingsDialog(context);
      case 'install-relay': await showRelayInstallDialog(context, onEnrolled: fleet.add);
      case 'direct': await enrollDirect();
    }
  }
  Future<void> operate(Map<String, dynamic> operation, {MachineState? target}) async {
    final machine = target ?? fleet.current;
    if (machine == null) return;
    await showDialog<void>(context: context, barrierDismissible: false,
      builder: (_) => OperationDialog(machine: machine, operation: operation, onSubmitted: (job) {
        message('Job ${job['id']} submitted to ${machine.profile.name}. Closing this application does not stop it.');
        setState(() => page = 'Activity'); unawaited(fleet.refresh(full: true));
      }));
  }
  Future<void> jobDetail(MachineState machine, Map<String, dynamic> job) async {
    await showDialog<void>(context: context, builder: (_) => JobDialog(machine: machine, initial: job, onChanged: () => fleet.refresh(full: true), onDownload: (artifact) => download(machine, artifact)));
  }
  Future<void> download(MachineState machine, Map<String, dynamic> artifact) async {
    await attempt(() async {
      final name = (artifact['name']?.toString() ?? 'artifact-${artifact['id']}').replaceAll(RegExp(r'[\\/:*?"<>|]'), '_');
      String? path;
      if (Platform.isAndroid || Platform.isIOS) {
        final directory = await getApplicationDocumentsDirectory(); path = '${directory.path}/$name';
      } else {
        path = (await getSaveLocation(suggestedName: name))?.path;
      }
      if (path == null) return;
      final target = File(path);
      if (await target.exists() && mounted) {
        final allowed = await confirm(context, title: 'Replace local file?', message: 'The existing file at $path will be replaced after the authenticated download completes.', danger: true);
        if (!allowed) return;
      }
      await machine.api.download(artifact['id'].toString(), target, expectedHash: artifact['sha256']?.toString());
      message('Artifact saved: $path${artifact['sha256'] == null ? '' : ' • SHA256 verified'}');
    });
  }
  @override
  Widget build(BuildContext context) {
    final width = MediaQuery.sizeOf(context).width;
    final phone = width < 560;
    final expanded = width >= 1100;
    final visible = !phone && sidebarVisible;
    final current = fleet.current;
    final fleetPage = page == 'Machines' || page == 'Setup';
    final body = !fleet.ready ? const Center(child: CircularProgressIndicator()) : content(current);
    return Scaffold(
      key: scaffold,
      drawer: phone ? Drawer(width: 280, shape: const RoundedRectangleBorder(), child: SafeArea(child: navigation(expanded: true, drawer: true))) : null,
      body: SafeArea(child: Row(children: [
        if (visible) SizedBox(width: expanded ? 240 : 52, child: navigation(expanded: expanded)),
        if (visible) const VerticalDivider(width: 1),
        Expanded(child: Column(children: [
          if (!fleetPage || !visible) workspaceBar(current, phone: phone, fleetPage: fleetPage),
          if (fleet.startupError != null) errorBanner(fleet.startupError!),
          if (error != null) errorBanner(error!, onClose: () => setState(() => error = null)),
          Expanded(child: body),
        ])),
      ])),
    );
  }
  String navigationDestination(String value) => switch (value) {
    'Recovery' => 'Backups', 'Services' => 'Processes', _ => value,
  };
  String navigationLabel(String value) => switch (value) {
    'Backups' => 'Backups & recovery', 'Processes' => 'Processes & services', _ => value,
  };
  void navigate(String name, {bool drawer = false}) {
    setState(() { page = name; search = ''; });
    if (drawer) Navigator.pop(context);
  }
  Widget connectionMenu() => PopupMenuButton<String>(
    tooltip: 'Connection options', icon: const Icon(Icons.more_horiz, size: 18),
    onSelected: (action) => unawaited(connectionAction(action)),
    itemBuilder: (_) => const [
      PopupMenuItem(value: 'direct', child: Text('Pair installed agent (direct HTTPS)')),
      PopupMenuDivider(),
      PopupMenuItem(value: 'install-relay', child: Text('Install through relay (advanced)')),
      PopupMenuItem(value: 'connect', child: Text('Connect with relay code (advanced)')),
      PopupMenuItem(value: 'relay', child: Text('Relay settings')),
    ],
  );
  Widget workspaceBar(MachineState? machine, {required bool phone, required bool fleetPage}) {
    final colors = Theme.of(context).colorScheme;
    final controls = <Widget>[
      if (phone || !sidebarVisible) IconButton(
        tooltip: phone ? 'Open navigation' : 'Show sidebar',
        onPressed: () { if (phone) { scaffold.currentState?.openDrawer(); } else { setState(() => sidebarVisible = true); } },
        icon: const Icon(Icons.menu_outlined)),
      if (fleetPage || machine == null) Text(navigationLabel(navigationDestination(page)), style: Theme.of(context).textTheme.titleMedium),
      if (!fleetPage && machine != null) ConstrainedBox(
        constraints: BoxConstraints(maxWidth: phone ? 230 : 300),
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
          decoration: BoxDecoration(border: Border.all(color: colors.outline), borderRadius: monitorRadius),
          child: DropdownButtonHideUnderline(child: DropdownButton<String>(
            value: fleet.selected, isExpanded: true, isDense: true,
            icon: const Icon(Icons.unfold_more_outlined, size: 16),
            items: fleet.machines.values.map((m) => DropdownMenuItem(
              value: m.profile.id,
              child: Row(children: [const Icon(Icons.dns_outlined, size: 15), const SizedBox(width: 8),
                Expanded(child: Text(m.profile.name, overflow: TextOverflow.ellipsis, style: const TextStyle(fontSize: 12)))]),
            )).toList(),
            onChanged: (id) { if (id != null) fleet.select(id); },
          )),
        ),
      ),
      if (!fleetPage && machine != null) StatusPill(
        label: fleet.pollingPaused ? (phone ? 'Paused' : '${machine.freshness} · refresh paused') : machine.freshness,
        tone: fleet.pollingPaused ? MonitorTone.warning : machine.freshness == 'Live' ? MonitorTone.success : machine.freshness == 'Offline' ? MonitorTone.danger : MonitorTone.warning,
        icon: fleet.pollingPaused ? Icons.pause : Icons.circle),
      if (!fleetPage && machine != null && object(machine.snapshot['network']).isNotEmpty)
        StatusPill(label: switch (object(machine.snapshot['network'])['state']) { 'up' => 'Network up', 'down' => 'Network down', _ => 'Network unknown' },
          tone: networkStateTone(object(machine.snapshot['network'])['state']), icon: networkStateIcon(object(machine.snapshot['network'])['state'])),
      if (!fleetPage && machine != null && !phone)
        StatusPill(label: '${machine.profile.role} access', icon: Icons.key_outlined),
    ];
    final actions = <Widget>[
      if (!fleetPage && machine != null && phone) IconButton.outlined(
        onPressed: () => fleet.setPollingPaused(!fleet.pollingPaused),
        tooltip: fleet.pollingPaused ? 'Resume telemetry' : 'Pause telemetry',
        icon: Icon(fleet.pollingPaused ? Icons.play_arrow_outlined : Icons.pause_outlined, size: 16))
      else if (!fleetPage && machine != null) OutlinedButton.icon(
        onPressed: () => fleet.setPollingPaused(!fleet.pollingPaused),
        icon: Icon(fleet.pollingPaused ? Icons.play_arrow_outlined : Icons.pause_outlined, size: 15),
        label: Text(fleet.pollingPaused ? 'Resume telemetry' : 'Pause telemetry')),
      if (!fleetPage && machine != null) FilledButton(
        onPressed: machine.catalog.isEmpty ? null : () => pickOperation(machine), child: const Text('Run operation')),
      if (!phone) IconButton(onPressed: () => attempt(() => fleet.refresh(full: true)), tooltip: 'Refresh agent data', icon: const Icon(Icons.refresh_outlined)),
      if (!phone && !sidebarVisible) ...[if (Platform.isWindows) const DesktopMenu(), connectionMenu()],
    ];
    return Container(
      width: double.infinity, padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(border: Border(bottom: BorderSide(color: colors.outlineVariant))),
      child: LayoutBuilder(builder: (context, bounds) => bounds.maxWidth < 900
        ? Wrap(spacing: 8, runSpacing: 8, crossAxisAlignment: WrapCrossAlignment.center, children: [...controls, ...actions])
        : Row(children: [Expanded(child: Wrap(spacing: 8, runSpacing: 6, crossAxisAlignment: WrapCrossAlignment.center, children: controls)),
            const SizedBox(width: 12), for (var i = 0; i < actions.length; i++) ...[if (i > 0) const SizedBox(width: 8), actions[i]]])),
    );
  }
  Future<void> pickOperation(MachineState machine) async {
    var query = '';
    final operation = await showDialog<Map<String, dynamic>>(context: context, builder: (dialog) => StatefulBuilder(
      builder: (context, update) {
        final matches = machine.catalog.where((op) => op['hidden'] != true &&
          '${op['title']} ${op['description']} ${op['id']} ${op['capability']}'.toLowerCase().contains(query.toLowerCase())).toList();
        return AlertDialog(title: const Text('Run operation'),
          content: SizedBox(width: 520, height: MediaQuery.sizeOf(context).height * .6, child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            Text('Target: ${machine.profile.name}', style: Theme.of(context).textTheme.bodySmall),
            const SizedBox(height: 8),
            TextField(autofocus: true, decoration: const InputDecoration(hintText: 'Search action, description or capability', prefixIcon: Icon(Icons.search_outlined)),
              onChanged: (value) => update(() => query = value)),
            const SizedBox(height: 8),
            Expanded(child: matches.isEmpty ? const Center(child: Text('No matching operations.')) : ListView.separated(
              itemCount: matches.length, separatorBuilder: (_, _) => const Divider(),
              itemBuilder: (context, index) {
                final op = matches[index];
                return ListTile(title: Text(op['title']?.toString() ?? op['id'].toString()),
                  subtitle: Text('${operationDestination(op)} · ${op['capability']} capability'),
                  leading: Icon(op['destructive'] == true ? Icons.warning_amber_outlined : Icons.play_circle_outline,
                    color: op['destructive'] == true ? Theme.of(context).colorScheme.error : null),
                  trailing: const Icon(Icons.chevron_right, size: 16), onTap: () => Navigator.pop(dialog, op));
              })),
          ])),
          actions: [monitorDialogActions(context, [TextButton(onPressed: () => Navigator.pop(dialog), child: const Text('Cancel'))])]);
      }));
    if (operation != null && mounted) await operate(operation, target: machine);
  }
  Widget errorBanner(String text, {VoidCallback? onClose}) {
    final colors = Theme.of(context).colorScheme;
    return Material(color: colors.errorContainer, child: Padding(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
      child: Row(children: [
        Icon(Icons.error_outline, color: colors.onErrorContainer), const SizedBox(width: 12),
        Expanded(child: SelectableText(text, style: TextStyle(color: colors.onErrorContainer))),
        if (onClose != null) IconButton(onPressed: onClose, tooltip: 'Dismiss error', icon: const Icon(Icons.close_outlined)),
      ]),
    ));
  }
  Widget navigation({required bool expanded, bool drawer = false}) {
    final colors = Theme.of(context).colorScheme;
    return Material(color: colors.surface, child: Column(children: [
      SizedBox(height: 56, child: Padding(padding: EdgeInsets.symmetric(horizontal: expanded ? 12 : 8), child: Row(children: [
        if (expanded) ...[
          const MonitorMark(size: 26), const SizedBox(width: 10),
          Expanded(child: Column(mainAxisAlignment: MainAxisAlignment.center, crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('RDPMonitor', style: Theme.of(context).textTheme.titleMedium),
            Text('Console', style: Theme.of(context).textTheme.bodySmall?.copyWith(fontSize: 10)),
          ])),
        ],
        IconButton(
          tooltip: drawer ? 'Close navigation' : 'Hide sidebar',
          onPressed: () { if (drawer) { Navigator.pop(context); } else { setState(() => sidebarVisible = false); } },
          icon: expanded ? const Icon(Icons.menu_open_outlined, size: 18) : const MonitorMark(size: 24)),
      ]))),
      const Divider(),
      Expanded(child: ListView(padding: EdgeInsets.symmetric(horizontal: expanded ? 6 : 4, vertical: 6), children: [
        for (final group in navigationGroups.entries) ...[
          if (expanded) Padding(padding: const EdgeInsets.fromLTRB(7, 10, 7, 3),
            child: Text(group.key.toUpperCase(), style: Theme.of(context).textTheme.labelSmall?.copyWith(color: colors.onSurfaceVariant, letterSpacing: .7)))
          else if (group.key != 'Fleet') const Padding(padding: EdgeInsets.symmetric(horizontal: 7, vertical: 7), child: Divider()),
          for (final name in group.value) Tooltip(message: expanded ? '' : navigationLabel(name), child: Semantics(
            selected: navigationDestination(page) == name,
            child: Material(
              color: navigationDestination(page) == name ? colors.surfaceContainer : colors.surface,
              shape: const RoundedRectangleBorder(borderRadius: monitorRadius),
              child: InkWell(
                borderRadius: monitorRadius, onTap: () => navigate(name, drawer: drawer),
                child: Container(
                  constraints: BoxConstraints(minHeight: drawer ? 44 : 30),
                  padding: EdgeInsets.symmetric(horizontal: expanded ? 7 : 9, vertical: 5),
                  decoration: BoxDecoration(border: Border(left: BorderSide(width: 2, color: navigationDestination(page) == name ? colors.onSurface : Colors.transparent))),
                  child: Row(children: [
                    Icon(destinations[name], size: 16, semanticLabel: expanded ? null : navigationLabel(name)),
                    if (expanded) ...[const SizedBox(width: 9), Expanded(child: Text(navigationLabel(name), style: const TextStyle(fontSize: 12))),
                      if (name == 'Machines') Text('${fleet.machines.length}', style: Theme.of(context).textTheme.bodySmall)],
                  ]),
                ),
              ),
            ),
          )),
        ],
      ])),
      const Divider(),
      Padding(padding: EdgeInsets.all(expanded ? 8 : 4), child: expanded
        ? Row(children: [
            const Icon(Icons.lock_outline, size: 16), const SizedBox(width: 8),
            Expanded(child: Text(fleet.startupError != null ? 'Vault unavailable' : 'Local secure vault', style: Theme.of(context).textTheme.bodySmall)),
            if (drawer) IconButton(onPressed: () => attempt(() => fleet.refresh(full: true)), tooltip: 'Refresh agent data', icon: const Icon(Icons.refresh_outlined)),
            if (Platform.isWindows) const DesktopMenu(), connectionMenu(),
          ])
        : Column(children: [if (Platform.isWindows) const DesktopMenu(), connectionMenu()])),
    ]));
  }
  Widget content(MachineState? machine) {
    if (page == 'Machines') return MachineFleetView(fleet: fleet, onAdd: enroll, onOpen: openMachine);
    if (page == 'Setup') return emptySetup();
    if (page == 'Settings' && machine == null) {
      return ListView(padding: const EdgeInsets.all(20), children: [
        relaySettingsLauncher(), const SizedBox(height: 16),
        if (Platform.isWindows) const DesktopSettingsLauncher(),
      ]);
    }
    if (machine == null) return emptySetup();
    final children = <Widget>[
      if (machine.errors.isNotEmpty) Padding(padding: const EdgeInsets.only(bottom: 16), child: Material(color: Theme.of(context).colorScheme.errorContainer, borderRadius: BorderRadius.circular(10), child: ExpansionTile(leading: const Icon(Icons.warning_amber_outlined), title: Text('${machine.errors.length} data source(s) unavailable'), subtitle: const Text('Retained data may be stale. Expand to inspect source errors.'), children: machine.errors.entries.map((e) => Padding(padding: const EdgeInsets.all(16), child: SelectableText('${e.key}: ${e.value}'))).toList()))),
      if (page == 'Overview' || page == 'Monitoring') Overview(machine: machine, expanded: page == 'Monitoring'),
      if (page == 'Activity') ActivityView(machine: machine, onJob: (job) => jobDetail(machine, job), onError: (e) => setState(() => error = e), onRefresh: () => fleet.refresh(full: true)),
      if (page == 'Settings') relaySettingsLauncher(),
      if (page == 'Settings' && Platform.isWindows) const DesktopSettingsLauncher(),
      if (page == 'Settings') SettingsView(machine: machine, fleet: fleet, onError: (e) => setState(() => error = e)),
      if (page == 'Devices & access') DevicesView(machine: machine, onError: (e) => setState(() => error = e)),
      if (page == 'Files') UploadView(key: ValueKey(machine.profile.id), machine: machine, onJob: (job) { setState(() => page = 'Activity'); unawaited(fleet.refresh(full: true)); unawaited(jobDetail(machine, job)); }),
      if (page == 'Maintenance & help') help(machine),
    ];
    if (operationSections.containsValue(page)) children.add(operations(machine));
    return LayoutBuilder(builder: (context, bounds) => Align(alignment: Alignment.topCenter,
      child: ConstrainedBox(constraints: const BoxConstraints(maxWidth: 1440),
        child: ListView(key: ValueKey('workspace-${machine.profile.id}-$page'), padding: EdgeInsets.all(bounds.maxWidth < 560 ? 10 : 12), children: children))));
  }
  Widget relaySettingsLauncher() => MonitorPanel(child: ListTile(
    contentPadding: EdgeInsets.zero, leading: const Icon(Icons.hub_outlined),
    title: const Text('Optional relay settings'),
    subtitle: const Text('Advanced routing for VMs that cannot be reached directly. Normal direct setup does not need a relay.'),
    trailing: const Icon(Icons.chevron_right_outlined),
    onTap: () => showRelaySettingsDialog(context),
  ));
  Widget emptySetup() => ListView(padding: const EdgeInsets.all(12), children: [
    SectionHeader(title: fleet.machines.isEmpty ? 'Your fleet starts here' : 'Set up a machine',
      subtitle: 'One CMD command on the VM. Automatic connection to this desktop.',
      action: FilledButton.icon(onPressed: fleet.ready && fleet.startupError == null ? enroll : null,
        icon: const Icon(Icons.add, size: 16), label: const Text('Add machine'))),
    MonitorPanel(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      const Text('Each Windows VM hosts its own background agent/API. This desktop connects directly using certificate-authenticated HTTPS; knowing the VM address does not grant access. No relay account or administration key is required.'),
      const SizedBox(height: 12),
      for (final step in const <(String, String)>[
        ('1', 'Choose Add machine and enter the VM address, a display name and optional group.'),
        ('2', 'Prepare and copy its private CMD command, then paste it into Administrator Command Prompt inside that fresh Windows VM.'),
        ('3', 'Keep the desktop waiting. It verifies the VM identity and connects automatically; no return code or VM desktop app is needed.'),
      ]) Padding(padding: const EdgeInsets.only(bottom: 12), child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Container(width: 22, height: 22, alignment: Alignment.center,
          decoration: BoxDecoration(shape: BoxShape.circle, border: Border.all(color: Theme.of(context).colorScheme.outline)),
          child: Text(step.$1, style: Theme.of(context).textTheme.bodySmall)),
        const SizedBox(width: 8), Expanded(child: Text(step.$2)),
      ])),
      Container(padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(color: Theme.of(context).colorScheme.secondaryContainer,
          border: Border.all(color: Theme.of(context).colorScheme.onSecondaryContainer), borderRadius: monitorRadius),
        child: Text('The HTTPS port (8443 by default) must be reachable from this PC. Windows access is restricted to your desktop source IP; provider/router firewalls may need a matching rule. Unsigned previews require explicit consent and are monitoring-only. Keep copied commands private, including clipboard and CMD history.',
          style: TextStyle(color: Theme.of(context).colorScheme.onSecondaryContainer, fontSize: 12))),
      const SizedBox(height: 12),
      Align(alignment: Alignment.centerLeft, child: OutlinedButton.icon(
        onPressed: () => showRelayInstallDialog(context, onEnrolled: fleet.add), icon: const Icon(Icons.hub_outlined, size: 16), label: const Text('Advanced: install through relay'))),
    ])),
  ]);
  void openMachine(MachineState machine) {
    fleet.select(machine.profile.id);
    setState(() { page = 'Overview'; search = ''; });
  }
  Widget operations(MachineState machine) {
    final matching = machine.catalog.where((op) => op['hidden'] != true && operationDestination(op) == page).toList();
    final list = matching.where((op) => '${op['title']} ${op['description']} ${op['id']} ${op['capability']}'.toLowerCase().contains(search.toLowerCase())).toList();
    final groups = <String, List<Map<String, dynamic>>>{};
    for (final operation in list) {
      final subcategory = operationSubcategory(operation);
      groups.putIfAbsent(subcategory, () => []).add(operation);
    }
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      const SizedBox(height: 12),
      SectionHeader(title: navigationLabel(navigationDestination(page)), subtitle: '${matching.length} catalog actions · permissions are enforced by the agent',
        action: StatusPill(label: machine.health['read_only'] == true ? 'Read-only on' : 'Read-only ${machine.health.isEmpty ? 'unknown' : 'off'}', icon: Icons.lock_outlined,
          tone: machine.health['read_only'] == true ? MonitorTone.warning : MonitorTone.neutral)),
      if (page == 'Backups' || page == 'Recovery' || page == 'Processes' || page == 'Services') ...[
        Wrap(spacing: 8, runSpacing: 8, children: [
          for (final tab in (page == 'Backups' || page == 'Recovery' ? ['Backups', 'Recovery'] : ['Processes', 'Services']))
            ChoiceChip(label: Text(tab), selected: page == tab,
              labelStyle: TextStyle(color: page == tab ? Theme.of(context).colorScheme.onPrimary : Theme.of(context).colorScheme.onSurface),
              onSelected: (_) => navigate(tab)),
        ]),
        const SizedBox(height: 12),
      ],
      TextField(key: ValueKey('operations-$page'), decoration: const InputDecoration(hintText: 'Search action, description or capability', prefixIcon: Icon(Icons.search_outlined)), onChanged: (value) => setState(() => search = value)),
      const SizedBox(height: 16),
      if (machine.catalog.isEmpty) const MonitorPanel(child: Text('Operation catalog is unavailable. Reconnect to retrieve the agent capabilities.')),
      if (machine.catalog.isNotEmpty && list.isEmpty) const MonitorPanel(child: Text('No matching operations in this section. The agent catalog is authoritative.')),
      if (machine.freshness == 'Offline' || machine.freshness == 'Connecting')
        Padding(padding: const EdgeInsets.symmetric(vertical: 8), child: Text('Agent contact is unavailable. Retained capabilities may be out of date; submission requires a connection.',
          style: Theme.of(context).textTheme.bodySmall)),
      for (final group in groups.entries) ...[
        Padding(padding: const EdgeInsets.only(top: 16, bottom: 8), child: Text('${group.key.toUpperCase()} · ${group.value.length}',
          style: Theme.of(context).textTheme.titleSmall)),
        MonitorPanel(padding: EdgeInsets.zero, child: Column(children: [
          for (var i = 0; i < group.value.length; i++) ...[
            if (i > 0) const Padding(padding: EdgeInsets.symmetric(horizontal: 12), child: Divider()),
            operationCard(machine, group.value[i]),
          ],
        ])),
      ],
    ]);
  }
  Widget operationCard(MachineState machine, Map<String, dynamic> operation) {
    final colors = Theme.of(context).colorScheme;
    final danger = operation['destructive'] == true;
    final readOnly = machine.health['read_only'] == true && operation['capability'] != 'view';
    final unavailable = operation['allowed'] == false || readOnly;
    final title = operation['title']?.toString() ?? operation['id'].toString();
    final description = operation['description']?.toString().trim() ?? '';
    return InkWell(
      borderRadius: monitorRadius,
      hoverColor: colors.onSurface.withValues(alpha: .035),
      focusColor: colors.onSurface.withValues(alpha: .08),
      onTap: () => operate(operation, target: machine),
      child: Padding(padding: const EdgeInsets.all(12), child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Padding(padding: const EdgeInsets.only(top: 2), child: Icon(danger ? Icons.warning_amber_outlined : Icons.play_circle_outline, size: 16, color: danger ? colors.error : colors.onSurfaceVariant)),
        const SizedBox(width: 12),
        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(title, style: Theme.of(context).textTheme.bodyMedium),
          if (description.isNotEmpty && description != title) ...[
            const SizedBox(height: 4), Text(description, style: Theme.of(context).textTheme.bodySmall),
          ],
          const SizedBox(height: 8),
          Wrap(spacing: 6, runSpacing: 6, children: [
            operationBadge('${operation['capability']} capability', icon: Icons.key_outlined),
            if (danger) operationBadge('Explicit confirmation', icon: Icons.warning_amber_outlined, danger: true),
            if (unavailable) operationBadge(readOnly ? 'Read-only mode' : 'Permission required', icon: Icons.lock_outlined, warning: true),
          ]),
        ])),
        const SizedBox(width: 8), Icon(Icons.chevron_right_outlined, size: 16, color: colors.onSurfaceVariant),
      ])),
    );
  }
  Widget operationBadge(String text, {required IconData icon, bool danger = false, bool warning = false, MonitorTone tone = MonitorTone.neutral}) {
    return StatusPill(label: text, icon: icon, tone: danger ? MonitorTone.danger : warning ? MonitorTone.warning : tone);
  }
  Widget help(MachineState machine) => Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    Text('Agent maintenance', style: Theme.of(context).textTheme.headlineMedium), const SizedBox(height: 12),
    const Text('The worker owns monitoring, protection, schedules, and jobs independently of this app. Pausing telemetry stops automatic desktop refresh only; active requests and agent jobs keep running. Cancel means a request to stop remaining work, never rollback. Interrupted jobs are not replayed automatically.\n\nDirect setup binds an approved desktop key to the VM. An IP address is only a locator; another desktop cannot gain access by entering it. Normal CMD setup is monitoring-only/viewer and never sends this desktop private key to the VM. The VM keeps its own CA private key. Keep installation commands private.\n\nDirect HTTPS must be reachable from this PC. Automatic source selection uses the unique established RDP TCP peer; an RDP gateway, provider console or multiple peers may require the advanced desktop-source override. Router/provider firewall changes are not automatic. A changed desktop public IP requires an explicitly authorized source-rule update.\n\nRemote session actions require an available interactive user-session helper. Powered-off machines cannot report their own outage. An external observer is needed for reliable machine-down alerts.\n\nOptional relay connections retain end-to-end agent HTTPS and mutual TLS. The relay can route traffic, not authorize Windows operations.\n\nIf a fresh command expires before installation, discard that local intent and prepare another. If the agent is already installed, use the matching installer repair/pair-installed flow and Advanced direct HTTPS rather than rerunning fresh provisioning. Failed final verification must reuse the checkpointed identity. Never disable certificate checks. Removal preserves policy/data unless explicitly requested otherwise.'),
    const SizedBox(height: 14), DataTree(value: machine.health),
  ]);
}


Future<bool> confirm(BuildContext context, {required String title, required String message, bool danger = false}) async => await showDialog<bool>(context: context, builder: (dialog) => AlertDialog(
  icon: Icon(danger ? Icons.warning_amber : Icons.info_outline), title: Text(title), content: SizedBox(width: 520, child: SingleChildScrollView(child: Text(message))),
  actions: [monitorDialogActions(context, [TextButton(onPressed: () => Navigator.pop(dialog, false), child: const Text('Cancel')), FilledButton(onPressed: () => Navigator.pop(dialog, true), style: danger ? FilledButton.styleFrom(backgroundColor: Theme.of(context).colorScheme.error) : null, child: const Text('Confirm'))])],
)) ?? false;

class EnrollmentDialog extends StatefulWidget {
  final Future<void> Function(MachineProfile) onEnrolled;
  const EnrollmentDialog({super.key, required this.onEnrolled});
  @override
  State<EnrollmentDialog> createState() => _EnrollmentDialogState();
}
class _EnrollmentDialogState extends State<EnrollmentDialog> {
  final form = GlobalKey<FormState>();
  final controllers = {for (final key in ['name','group','endpoint','fingerprint','code','device']) key: TextEditingController()};
  bool busy = false;
  bool verified = false;
  String? error;
  @override
  void initState() { super.initState(); controllers['device']!.text = '${Platform.operatingSystem} operator'; }
  @override
  void dispose() { for (final c in controllers.values) { c.dispose(); } super.dispose(); }
  Future<void> submit() async {
    if (!form.currentState!.validate() || !verified || busy) return;
    setState(() { busy = true; error = null; });
    try {
      final profile = await AgentApi.enroll(endpoint: controllers['endpoint']!.text, fingerprint: controllers['fingerprint']!.text,
        code: controllers['code']!.text, name: controllers['name']!.text, group: controllers['group']!.text, deviceName: controllers['device']!.text);
      await widget.onEnrolled(profile);
      if (mounted) Navigator.pop(context);
    } catch (e) { if (mounted) setState(() => error = e.toString()); }
    finally { if (mounted) setState(() => busy = false); }
  }
  @override
  Widget build(BuildContext context) => PopScope(canPop: !busy, child: AlertDialog(
    icon: const Icon(Icons.fingerprint_outlined),
    title: const Text('Enroll a Windows machine'), content: SizedBox(width: 560, child: SingleChildScrollView(child: Form(key: form, child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(color: Theme.of(context).colorScheme.surfaceContainerLow, borderRadius: BorderRadius.circular(8)),
        child: const Text('Run python -m agent pair --data-dir <agent-data-directory> --role owner locally on the agent. Pairing codes are short-lived and one-use. Compare the certificate fingerprint through a trusted channel.'),
      ),
      const SizedBox(height: 20),
      for (final entry in <String,String>{'name':'Machine display name','group':'Group (optional)','endpoint':'HTTPS address, e.g. https://server:9443','device':'This device name','fingerprint':'Agent server SHA256 fingerprint','code':'One-use pairing code'}.entries) Padding(padding: const EdgeInsets.only(bottom: 14), child: TextFormField(
        controller: controllers[entry.key], enabled: !busy, obscureText: entry.key == 'code', autocorrect: false, enableSuggestions: false,
        decoration: InputDecoration(labelText: entry.value), validator: (v) => entry.key != 'group' && (v == null || v.trim().isEmpty) ? 'Required' : null,
      )),
      CheckboxListTile(contentPadding: EdgeInsets.zero, value: verified, onChanged: busy ? null : (v) => setState(() => verified = v ?? false), title: const Text('I verified this fingerprint on the actual agent or another trusted channel.')),
      if (error != null) Padding(padding: const EdgeInsets.all(8), child: SelectableText(error!, style: TextStyle(color: Theme.of(context).colorScheme.error))),
      if (busy) const LinearProgressIndicator(),
    ])))), actions: [monitorDialogActions(context, [TextButton(onPressed: busy ? null : () => Navigator.pop(context), child: const Text('Cancel')), FilledButton(onPressed: busy || !verified ? null : submit, child: const Text('Verify & enroll'))])],
  ));
}
