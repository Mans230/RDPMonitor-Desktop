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
import 'fleet_views.dart';
import 'operation_layout.dart';

void main() { WidgetsFlutterBinding.ensureInitialized(); runApp(const MonitorApp()); }
class MonitorApp extends StatelessWidget {
  const MonitorApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'RDPMonitor', debugShowCheckedModeBanner: false, themeMode: ThemeMode.system,
    theme: buildMonitorTheme(Brightness.light), darkTheme: buildMonitorTheme(Brightness.dark), home: const Workspace(),
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
  'Maintenance & help': Icons.help_outline,
};

// Grouped in working order: pick a machine, watch it, protect it, change it,
// then manage the agent itself. Diagnostics sits with observation because it
// answers "what is happening"; imaging sits with management because it changes
// the operating system rather than recovering data.
const navigationGroups = <String, List<String>>{
  'Fleet': ['Machines'],
  'Observe': ['Overview', 'Monitoring', 'Diagnostics', 'Activity'],
  'Protect & recover': ['Security', 'Backups', 'Recovery'],
  'Manage': ['Accounts', 'Processes', 'Services', 'Files', 'Automation', 'Imaging'],
  'Workspace': ['Settings', 'Devices & access', 'Maintenance & help'],
};

class Workspace extends StatefulWidget {
  const Workspace({super.key});
  @override
  State<Workspace> createState() => _WorkspaceState();
}
class _WorkspaceState extends State<Workspace> {
  final Fleet fleet = Fleet();
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
  Future<void> enroll() => showAddMachineDialog(context, onEnrolled: fleet.add);
  Future<void> enrollDirect() async {
    await showDialog<void>(context: context, barrierDismissible: false, builder: (_) => EnrollmentDialog(onEnrolled: fleet.add));
  }
  Future<void> connectionAction(String action) async {
    switch (action) {
      case 'connect': await showConnectCodeDialog(context, onEnrolled: fleet.add);
      case 'relay': if (mounted) await showRelaySettingsDialog(context);
      case 'direct': await enrollDirect();
    }
  }
  Future<void> operate(Map<String, dynamic> operation) async {
    final machine = fleet.current;
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
    final windowWidth = MediaQuery.sizeOf(context).width;
    final wide = windowWidth >= 1120;
    final showSidebar = wide && sidebarVisible;
    final textScale = MediaQuery.textScalerOf(context).scale(14) / 14;
    final inlineAdd = windowWidth >= 600 * textScale.clamp(1, 2);
    final current = fleet.current;
    final body = !fleet.ready ? const Center(child: CircularProgressIndicator()) : content(current);
    return Scaffold(
      appBar: AppBar(
        leading: wide ? IconButton(
          onPressed: () => setState(() => sidebarVisible = !sidebarVisible),
          tooltip: sidebarVisible ? 'Hide sidebar' : 'Show sidebar',
          icon: Icon(sidebarVisible ? Icons.menu_open_outlined : Icons.menu_outlined),
        ) : null,
        title: Row(children: [
          if (!showSidebar && windowWidth >= 600) ...[const MonitorMark(size: 28), const SizedBox(width: 10)],
          Flexible(child: Text(page, overflow: TextOverflow.ellipsis)),
        ]),
        actions: [
          if (inlineAdd) Padding(
            padding: const EdgeInsets.only(right: 8),
            child: FilledButton.icon(onPressed: fleet.ready && fleet.startupError == null ? enroll : null, icon: const Icon(Icons.add), label: const Text('Add machine')),
          ),
          if (current != null) IconButton(onPressed: () => attempt(() => fleet.refresh(full: true)), tooltip: 'Refresh agent data', icon: const Icon(Icons.refresh_outlined)),
          if (Platform.isWindows) const DesktopMenu(),
          PopupMenuButton<String>(
            tooltip: 'Advanced connection options', icon: const Icon(Icons.more_vert),
            onSelected: (action) => unawaited(connectionAction(action)),
            itemBuilder: (_) => const [
              PopupMenuItem(value: 'connect', child: Text('Connect with code')),
              PopupMenuItem(value: 'relay', child: Text('Relay settings')),
              PopupMenuDivider(),
              PopupMenuItem(value: 'direct', child: Text('Advanced: direct HTTPS')),
            ],
          ),
          const SizedBox(width: 12),
        ],
      ),
      drawer: wide ? null : Drawer(child: SafeArea(child: navigation(false))),
      body: Row(children: [
        if (showSidebar) SizedBox(width: 258, child: navigation(true)),
        if (showSidebar) const VerticalDivider(width: 1),
        Expanded(child: Column(children: [
          if (!inlineAdd) Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
            child: Align(alignment: Alignment.centerLeft, child: FilledButton.icon(
              onPressed: fleet.ready && fleet.startupError == null ? enroll : null, icon: const Icon(Icons.add), label: const Text('Add machine'),
            )),
          ),
          if (fleet.startupError != null) errorBanner(fleet.startupError!),
          if (error != null) errorBanner(error!, onClose: () => setState(() => error = null)),
          Expanded(child: body),
        ])),
      ]),
    );
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
  Widget navigation(bool wide) {
    final colors = Theme.of(context).colorScheme;
    return Material(color: colors.surfaceContainerLow, child: ListView(padding: const EdgeInsets.only(bottom: 16), children: [
      Padding(padding: const EdgeInsets.fromLTRB(20, 24, 20, 22), child: Row(children: [
        const MonitorMark(size: 34), const SizedBox(width: 12),
        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('RDPMonitor', style: Theme.of(context).textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w700)),
          Text('Machine command center', style: Theme.of(context).textTheme.bodySmall),
        ])),
      ])),
      if (fleet.machines.isNotEmpty) Padding(padding: const EdgeInsets.fromLTRB(14, 0, 14, 12), child: DropdownButtonFormField<String>(
        key: ValueKey('target-${fleet.selected}'), initialValue: fleet.selected, isExpanded: true,
        decoration: const InputDecoration(labelText: 'Target machine', prefixIcon: Icon(Icons.computer_outlined)),
        items: fleet.machines.values.map((m) => DropdownMenuItem(value: m.profile.id, child: Text(m.profile.name, overflow: TextOverflow.ellipsis))).toList(),
        onChanged: (id) { if (id != null) fleet.select(id); },
      )),
      Padding(padding: const EdgeInsets.symmetric(horizontal: 10), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        for (final group in navigationGroups.entries) ...[
          Padding(padding: const EdgeInsets.fromLTRB(14, 15, 14, 7), child: Text(group.key, style: Theme.of(context).textTheme.labelSmall?.copyWith(color: colors.onSurfaceVariant, fontWeight: FontWeight.w600))),
          for (final name in group.value) Padding(padding: const EdgeInsets.symmetric(vertical: 2), child: ListTile(
            dense: true, shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
            selected: page == name, selectedTileColor: colors.primaryContainer, selectedColor: colors.onPrimaryContainer,
            hoverColor: colors.onSurface.withValues(alpha: .06), focusColor: colors.primary.withValues(alpha: .14),
            leading: Icon(destinations[name], size: 20), title: Text(name),
            trailing: page == name ? Icon(Icons.chevron_right_outlined, size: 17, color: colors.primary) : null,
            onTap: () { setState(() { page = name; search = ''; }); if (!wide) Navigator.pop(context); },
          )),
        ],
      ])),
      const Divider(height: 1),
      Padding(padding: const EdgeInsets.all(18), child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Icon(Icons.dns_outlined, size: 17, color: colors.onSurfaceVariant), const SizedBox(width: 9),
        Expanded(child: Text('Native client · 1.0.0\nAgent jobs continue after exit.', style: Theme.of(context).textTheme.bodySmall)),
      ])),
    ]));
  }
  Widget machineBar(MachineState machine) {
    final colors = Theme.of(context).colorScheme;
    final reach = object(machine.snapshot['network']);
    return Container(
      width: double.infinity, padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
      decoration: BoxDecoration(color: colors.surfaceContainerLowest, border: Border(bottom: BorderSide(color: colors.outlineVariant))),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Wrap(spacing: 12, runSpacing: 8, crossAxisAlignment: WrapCrossAlignment.center, children: [
          Text(machine.profile.name, style: Theme.of(context).textTheme.titleSmall?.copyWith(fontWeight: FontWeight.w700)),
          operationBadge(machine.freshness, icon: machine.freshness == 'Live' ? Icons.sensors_outlined : Icons.history_outlined, tone: machine.freshness == 'Live' ? MonitorTone.success : MonitorTone.warning),
          if (reach.isNotEmpty) operationBadge(networkStateLabel(reach['state']), icon: networkStateIcon(reach['state']), tone: networkStateTone(reach['state'])),
          operationBadge('${machine.profile.role} access', icon: Icons.key_outlined),
          if (machine.health['read_only'] == true) operationBadge('Read-only safety mode', icon: Icons.lock_outlined, warning: true),
          if (machine.busy) const SizedBox(width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2)),
        ]),
        const SizedBox(height: 6),
        Text('${_connectionLabel(machine.profile)}  ·  Last contact: ${timestamp(machine.lastContact?.toIso8601String())}', style: Theme.of(context).textTheme.bodySmall?.copyWith(fontFeatures: monitorFigures)),
        if (machine.freshness == 'Offline' || machine.freshness == 'Stale') Padding(
          padding: const EdgeInsets.only(top: 7),
          child: Text(machine.freshness == 'Offline' ? 'Agent contact is unavailable. Retained data is not current; operations require a connection.' : 'Telemetry is stale or incomplete. Review source warnings before acting.', style: TextStyle(color: colors.error, fontSize: 12)),
        ),
      ]),
    );
  }
  Widget content(MachineState? machine) {
    if (page == 'Machines') return MachineFleetView(fleet: fleet, onAdd: enroll, onOpen: openMachine);
    if (page == 'Settings' && machine == null) {
      return ListView(padding: const EdgeInsets.all(20), children: [
        relaySettingsLauncher(), const SizedBox(height: 16),
        if (Platform.isWindows) const DesktopSettingsLauncher(),
      ]);
    }
    if (machine == null) return emptySetup();
    final children = <Widget>[
      machineBar(machine),
      const SizedBox(height: 20),
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
        child: ListView(padding: EdgeInsets.all(bounds.maxWidth < 600 ? 16 : 28), children: children))));
  }
  Widget relaySettingsLauncher() => MonitorPanel(child: ListTile(
    contentPadding: EdgeInsets.zero, leading: const Icon(Icons.hub_outlined),
    title: const Text('Relay settings'),
    subtitle: const Text('Configure your self-hosted relay and manage its connection routes.'),
    trailing: const Icon(Icons.chevron_right_outlined),
    onTap: () => showRelaySettingsDialog(context),
  ));
  Widget emptySetup() => Center(child: SingleChildScrollView(padding: const EdgeInsets.all(28), child: ConstrainedBox(constraints: const BoxConstraints(maxWidth: 720), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    const MonitorMark(size: 48), const SizedBox(height: 22),
    Text('Your fleet starts here', style: Theme.of(context).textTheme.headlineLarge),
    const SizedBox(height: 12), Text('One CMD command. Automatic connection.', style: Theme.of(context).textTheme.titleLarge),
    const SizedBox(height: 12), const Text('Connect Windows VMs across networks without opening inbound management ports or configuring a VPN. Agent traffic remains end-to-end certificate-authenticated HTTPS inside the relay tunnel.'),
    const SizedBox(height: 20), const Text('Choose Add machine, give it a name and group, then copy its private CMD command. Paste the line into Command Prompt as Administrator inside the VM. Only the background agent installs; no VM wizard or return code. This desktop connects automatically. Configure your self-hosted HTTPS relay once if prompted.'),
    const SizedBox(height: 16), const Text('This project does not supply a publicly hosted relay. Unsigned guest previews require explicit consent and are monitoring-only, not production-signed installations. Invitations are single-use. Private client keys stay in OS-protected storage; the copied command remains private clipboard/CMD history.'),
    const SizedBox(height: 22), Wrap(spacing: 12, runSpacing: 12, children: [
      FilledButton.icon(onPressed: enroll, icon: const Icon(Icons.add), label: const Text('Add machine')),
      TextButton(onPressed: () => showRelaySettingsDialog(context), child: const Text('Relay settings')),
    ]),
  ]))));
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
      const SizedBox(height: 24),
      SectionHeader(title: '$page commands', subtitle: '${matching.length} catalog actions. Permissions and confirmations are enforced by the agent.'),
      const SizedBox(height: 16),
      TextField(key: ValueKey('operations-$page'), decoration: const InputDecoration(labelText: 'Find an operation', hintText: 'Search action, description or capability', prefixIcon: Icon(Icons.search_outlined)), onChanged: (value) => setState(() => search = value)),
      const SizedBox(height: 16),
      if (machine.catalog.isEmpty) const MonitorPanel(child: Text('Operation catalog is unavailable. Reconnect to retrieve the agent capabilities.')),
      if (machine.catalog.isNotEmpty && list.isEmpty) const MonitorPanel(child: Text('No matching operations in this section. The agent catalog is authoritative.')),
      for (final group in groups.entries) ...[
        Padding(padding: const EdgeInsets.only(top: 16, bottom: 12), child: SectionHeader(title: group.key, subtitle: '${group.value.length} related commands')),
        OperationCardGrid(children: [
          for (final operation in group.value) operationCard(machine, operation),
        ]),
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
    return MonitorPanel(padding: EdgeInsets.zero, child: InkWell(
      borderRadius: monitorRadius,
      hoverColor: colors.primary.withValues(alpha: .06),
      focusColor: colors.primary.withValues(alpha: .14),
      onTap: () => operate(operation),
      child: Padding(padding: const EdgeInsets.all(18), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Icon(danger ? Icons.warning_amber_outlined : Icons.play_circle_outline, size: 22, color: danger ? colors.error : colors.primary),
          const SizedBox(width: 12),
          Expanded(child: Text(title, style: Theme.of(context).textTheme.titleMedium)),
          const SizedBox(width: 8), Icon(Icons.chevron_right_outlined, size: 20, color: colors.onSurfaceVariant),
        ]),
        if (description.isNotEmpty && description != title) ...[
          const SizedBox(height: 12),
          Text(description, style: Theme.of(context).textTheme.bodySmall),
        ],
        const SizedBox(height: 14),
        Wrap(spacing: 8, runSpacing: 8, children: [
          operationBadge('${operation['capability']} capability', icon: Icons.key_outlined),
          if (danger) operationBadge('Explicit confirmation', icon: Icons.warning_amber_outlined, danger: true),
          if (unavailable) operationBadge(readOnly ? 'Read-only mode' : 'Permission required', icon: Icons.lock_outlined, warning: true),
        ]),
        if (machine.freshness == 'Offline' || machine.freshness == 'Connecting') Padding(
          padding: const EdgeInsets.only(top: 10),
          child: Text('Submission requires an agent connection. Retained capabilities may be out of date.', style: Theme.of(context).textTheme.bodySmall),
        ),
      ])),
    ));
  }
  Widget operationBadge(String text, {required IconData icon, bool danger = false, bool warning = false, MonitorTone tone = MonitorTone.neutral}) {
    final colors = Theme.of(context).colorScheme;
    final foreground = danger || tone == MonitorTone.danger ? colors.error
      : warning || tone == MonitorTone.warning ? colors.onSecondaryContainer
      : tone == MonitorTone.success ? colors.primary : colors.onSurfaceVariant;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
      decoration: BoxDecoration(color: foreground.withValues(alpha: .08), borderRadius: BorderRadius.circular(6)),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Icon(icon, size: 14, color: foreground), const SizedBox(width: 5),
        Flexible(child: Text(text, style: Theme.of(context).textTheme.bodySmall?.copyWith(color: foreground, fontWeight: FontWeight.w600))),
      ]),
    );
  }
  Widget help(MachineState machine) => Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    Text('Agent maintenance', style: Theme.of(context).textTheme.headlineMedium), const SizedBox(height: 12),
    const Text('The worker owns monitoring, protection, schedules, and jobs independently of this app. Cancel means a request to stop remaining work, never rollback. Interrupted jobs are not replayed automatically.\n\nRemote session actions require an available interactive user-session helper. Powered-off machines cannot report their own outage. An external observer is needed for reliable machine-down alerts.\n\nRelay connections retain end-to-end agent HTTPS and mutual TLS. The relay can route or disconnect traffic, not authorize Windows operations. Revoking a device at the agent remains effective through an existing relay connection.\n\nIf a connection code expires, reopen the agent installer on the VM to generate a fresh code. Never disable certificate checks. Install, repair, update and remove using the matching release installer or signed deployment scripts. Unsigned previews are monitoring-only. Removal preserves policy/data unless explicitly requested otherwise.'),
    const SizedBox(height: 14), DataTree(value: machine.health),
  ]);
}

String _connectionLabel(MachineProfile profile) => profile.relay == null ? profile.endpoint : 'Relay · ${profile.relay!.origin}';

Future<bool> confirm(BuildContext context, {required String title, required String message, bool danger = false}) async => await showDialog<bool>(context: context, builder: (dialog) => AlertDialog(
  icon: Icon(danger ? Icons.warning_amber : Icons.info_outline), title: Text(title), content: SizedBox(width: 520, child: SingleChildScrollView(child: Text(message))),
  actions: [TextButton(onPressed: () => Navigator.pop(dialog, false), child: const Text('Cancel')), FilledButton(onPressed: () => Navigator.pop(dialog, true), style: danger ? FilledButton.styleFrom(backgroundColor: Theme.of(context).colorScheme.error) : null, child: const Text('Confirm'))],
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
    ])))), actions: [TextButton(onPressed: busy ? null : () => Navigator.pop(context), child: const Text('Cancel')), FilledButton(onPressed: busy || !verified ? null : submit, child: const Text('Verify & enroll'))],
  ));
}
