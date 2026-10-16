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
  'Accounts': Icons.people_outline, 'Processes & services': Icons.memory_outlined,
  'Backups & recovery': Icons.backup_outlined, 'Files': Icons.folder_outlined,
  'Diagnostics': Icons.troubleshoot, 'Imaging': Icons.disc_full_outlined,
  'Automation': Icons.schedule_outlined, 'Activity': Icons.history,
  'Settings': Icons.settings_outlined, 'Devices & access': Icons.key_outlined,
  'Maintenance & help': Icons.help_outline,
};
const sectionMap = <String, List<String>>{
  'Overview': ['overview'], 'Monitoring': ['monitoring'], 'Security': ['security'],
  'Accounts': ['accounts'], 'Processes & services': ['processes', 'services'],
  'Backups & recovery': ['backups', 'backup', 'recovery'], 'Files': ['files'],
  'Diagnostics': ['diagnostics'], 'Imaging': ['imaging'], 'Automation': ['automation'],
  'Settings': ['settings'], 'Maintenance & help': ['maintenance'], 'Activity': ['activity'],
};

const navigationGroups = <String, List<String>>{
  'Fleet': ['Machines'],
  'Observe': ['Overview', 'Monitoring', 'Activity'],
  'Protect & recover': ['Security', 'Backups & recovery', 'Imaging'],
  'Manage': ['Accounts', 'Processes & services', 'Files', 'Diagnostics', 'Automation'],
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
  String fleetSearch = '';
  String fleetFilter = 'All';
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
  Future<void> enroll() async {
    await showDialog<void>(context: context, barrierDismissible: false, builder: (_) => EnrollmentDialog(onEnrolled: fleet.add));
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
    final wide = MediaQuery.sizeOf(context).width >= 1120;
    final current = fleet.current;
    final body = !fleet.ready ? const Center(child: CircularProgressIndicator()) : content(current);
    return Scaffold(
      appBar: AppBar(
        title: Row(children: [
          if (!wide) ...[const MonitorMark(size: 28), const SizedBox(width: 10)],
          Flexible(child: Text(page, overflow: TextOverflow.ellipsis)),
        ]),
        actions: [
          if (current != null) IconButton(onPressed: () => attempt(() => fleet.refresh(full: true)), tooltip: 'Refresh agent data', icon: const Icon(Icons.refresh_outlined)),
          if (Platform.isWindows) const DesktopMenu(),
          IconButton(onPressed: enroll, tooltip: 'Enroll machine', icon: const Icon(Icons.add_link_outlined)),
          const SizedBox(width: 12),
        ],
      ),
      drawer: wide ? null : Drawer(child: SafeArea(child: navigation(false))),
      body: Row(children: [
        if (wide) SizedBox(width: 258, child: navigation(true)),
        if (wide) const VerticalDivider(width: 1),
        Expanded(child: Column(children: [
          if (fleet.startupError != null) errorBanner(fleet.startupError!),
          if (error != null) errorBanner(error!, onClose: () => setState(() => error = null)),
          if (current != null) machineBar(current),
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
    return Material(color: colors.surfaceContainerLow, child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
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
      Expanded(child: ListView(padding: const EdgeInsets.fromLTRB(10, 0, 10, 16), children: [
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
    return Container(
      width: double.infinity, padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
      decoration: BoxDecoration(color: colors.surfaceContainerLowest, border: Border(bottom: BorderSide(color: colors.outlineVariant))),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Wrap(spacing: 12, runSpacing: 8, crossAxisAlignment: WrapCrossAlignment.center, children: [
          Text(machine.profile.name, style: Theme.of(context).textTheme.titleSmall?.copyWith(fontWeight: FontWeight.w700)),
          statusChip(machine.freshness),
          StatusPill(label: '${machine.profile.role} access', icon: Icons.key_outlined),
          if (machine.health['read_only'] == true) const StatusPill(label: 'Read-only safety mode', tone: MonitorTone.warning, icon: Icons.lock_outlined),
          if (machine.busy) const SizedBox(width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2)),
        ]),
        const SizedBox(height: 6),
        Text('${machine.profile.endpoint}  ·  Last contact: ${timestamp(machine.lastContact?.toIso8601String())}', style: Theme.of(context).textTheme.bodySmall?.copyWith(fontFeatures: monitorFigures)),
        if (machine.freshness == 'Offline' || machine.freshness == 'Stale') Padding(
          padding: const EdgeInsets.only(top: 7),
          child: Text(machine.freshness == 'Offline' ? 'Agent contact is unavailable. Retained data is not current; operations require a connection.' : 'Telemetry is stale or incomplete. Review source warnings before acting.', style: TextStyle(color: colors.error, fontSize: 12)),
        ),
      ]),
    );
  }
  Widget content(MachineState? machine) {
    if (page == 'Machines') return machines();
    if (page == 'Settings' && machine == null && Platform.isWindows) {
      return ListView(padding: const EdgeInsets.all(20), children: const [DesktopSettingsLauncher()]);
    }
    if (machine == null) return emptySetup();
    final children = <Widget>[
      if (machine.errors.isNotEmpty) Padding(padding: const EdgeInsets.only(bottom: 16), child: Material(color: Theme.of(context).colorScheme.errorContainer, borderRadius: BorderRadius.circular(10), child: ExpansionTile(leading: const Icon(Icons.warning_amber_outlined), title: Text('${machine.errors.length} data source(s) unavailable'), subtitle: const Text('Retained data may be stale. Expand to inspect source errors.'), children: machine.errors.entries.map((e) => Padding(padding: const EdgeInsets.all(16), child: SelectableText('${e.key}: ${e.value}'))).toList()))),
      if (page == 'Overview' || page == 'Monitoring') Overview(machine: machine, expanded: page == 'Monitoring'),
      if (page == 'Activity') ActivityView(machine: machine, onJob: (job) => jobDetail(machine, job), onError: (e) => setState(() => error = e), onRefresh: () => fleet.refresh(full: true)),
      if (page == 'Settings' && Platform.isWindows) const DesktopSettingsLauncher(),
      if (page == 'Settings') SettingsView(machine: machine, fleet: fleet, onError: (e) => setState(() => error = e)),
      if (page == 'Devices & access') DevicesView(machine: machine, onError: (e) => setState(() => error = e)),
      if (page == 'Files') UploadView(key: ValueKey(machine.profile.id), machine: machine, onJob: (job) { setState(() => page = 'Activity'); unawaited(fleet.refresh(full: true)); unawaited(jobDetail(machine, job)); }),
      if (page == 'Maintenance & help') help(machine),
    ];
    if (sectionMap.containsKey(page)) children.add(operations(machine));
    return Align(alignment: Alignment.topCenter, child: ConstrainedBox(constraints: const BoxConstraints(maxWidth: 1440), child: ListView(padding: EdgeInsets.all(MediaQuery.sizeOf(context).width < 600 ? 16 : 28), children: children)));
  }
  Widget emptySetup() => Center(child: SingleChildScrollView(padding: const EdgeInsets.all(28), child: ConstrainedBox(constraints: const BoxConstraints(maxWidth: 720), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    const MonitorMark(size: 48), const SizedBox(height: 22),
    Text('Your fleet starts here', style: Theme.of(context).textTheme.headlineLarge),
    const SizedBox(height: 12), Text('Enroll your first Windows machine', style: Theme.of(context).textTheme.titleLarge),
    const SizedBox(height: 12), const Text('No machines are enrolled on this device. Connect directly to a Windows agent over certificate-authenticated HTTPS. No browser panel, shared password, or Telegram credentials are required.'),
    const SizedBox(height: 20), const Text('1. Install the agent using the signed agent installer on the machine you administer. For a source checkout, install agent/requirements.txt and use the commands below in an elevated terminal. Configure the server certificate hosts for your remote hostname before pairing.\n\n2. Start the agent and create a short-lived pairing challenge locally on that machine.\n\n3. Copy its HTTPS address, exact server SHA256 fingerprint, and pairing code into Enroll machine. Verify the fingerprint over a trusted channel, never from the same untrusted connection.'),
    const SizedBox(height: 16), const SelectableText('python -m agent serve --data-dir C:\\ProgramData\\RDPMonitor --port 9443\npython -m agent pair --data-dir C:\\ProgramData\\RDPMonitor --role owner', style: TextStyle(fontFamily: 'monospace')),
    const SizedBox(height: 16), const Text('For read-only local evaluation add --read-only to serve. Do not open inbound access to untrusted networks without the deployment firewall policy. Enrollment codes expire and can be used once. Private keys are generated on this device and stored in OS-protected storage.'),
    const SizedBox(height: 22), FilledButton.icon(onPressed: enroll, icon: const Icon(Icons.add_link), label: const Text('Enroll machine')),
  ]))));
  Widget machines() {
    if (fleet.machines.isEmpty) return emptySetup();
    final all = fleet.machines.values.toList();
    final live = all.where((m) => m.freshness == 'Live').length;
    final contacts = all.map((m) => m.lastContact).whereType<DateTime>().toList()..sort();
    final query = fleetSearch.trim().toLowerCase();
    final visible = all.where((m) =>
      (fleetFilter == 'All' || m.freshness == fleetFilter) &&
      '${m.profile.name} ${m.profile.group} ${m.profile.endpoint} ${m.profile.role}'.toLowerCase().contains(query)).toList();
    final groups = <String, List<MachineState>>{};
    for (final machine in visible) {
      groups.putIfAbsent(machine.profile.group.isEmpty ? 'Ungrouped' : machine.profile.group, () => []).add(machine);
    }
    return LayoutBuilder(builder: (context, constraints) {
      final table = constraints.maxWidth >= 950;
      return Align(alignment: Alignment.topCenter, child: ConstrainedBox(constraints: const BoxConstraints(maxWidth: 1440), child: ListView(
        padding: EdgeInsets.all(constraints.maxWidth < 600 ? 16 : 28),
        children: [
          SectionHeader(title: 'Machines', subtitle: 'Every action targets one enrolled machine. No destructive bulk operations.', action: FilledButton.icon(onPressed: enroll, icon: const Icon(Icons.add_link_outlined), label: const Text('Enroll machine'))),
          const SizedBox(height: 22),
          MonitorPanel(child: Wrap(spacing: 40, runSpacing: 18, children: [
            fleetMetric('Enrolled', '${all.length}'),
            fleetMetric('Live telemetry', '$live'),
            fleetMetric('Not live', '${all.length - live}'),
            fleetMetric('Latest fleet contact', contacts.isEmpty ? 'Not reported' : timestamp(contacts.last.toIso8601String())),
          ])),
          const SizedBox(height: 22),
          TextFormField(initialValue: fleetSearch,
            decoration: const InputDecoration(labelText: 'Find a machine', hintText: 'Name, group, address or role', prefixIcon: Icon(Icons.search_outlined)),
            onChanged: (value) => setState(() => fleetSearch = value),
          ),
          const SizedBox(height: 12),
          Wrap(spacing: 8, runSpacing: 8, children: [
            for (final filter in ['All', 'Live', 'Stale', 'Offline', 'Connecting']) ChoiceChip(
              label: Text('$filter · ${filter == 'All' ? all.length : all.where((m) => m.freshness == filter).length}'),
              selected: fleetFilter == filter, onSelected: (_) => setState(() => fleetFilter = filter),
            ),
          ]),
          const SizedBox(height: 8),
          if (visible.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 36), child: Text('No machines match this search and connection filter. Change the search or select All.')),
          for (final group in groups.entries) ...[
            Padding(padding: const EdgeInsets.only(top: 24, bottom: 12), child: Row(children: [
              Text(group.key, style: Theme.of(context).textTheme.titleMedium),
              const SizedBox(width: 10), Text('${group.value.length}', style: Theme.of(context).textTheme.bodySmall?.copyWith(fontFeatures: monitorFigures)),
            ])),
            MonitorPanel(padding: EdgeInsets.zero, child: table ? SizedBox(width: double.infinity, child: DataTable(
              headingRowHeight: 42, dataRowMinHeight: 72, dataRowMaxHeight: 82,
              horizontalMargin: 18, columnSpacing: 22, showCheckboxColumn: false,
              columns: const [
                DataColumn(label: Text('Machine / endpoint')), DataColumn(label: Text('Connection')),
                DataColumn(label: Text('Role')), DataColumn(label: Text('Last contact')), DataColumn(label: Text('Profile')),
              ],
              rows: group.value.map((machine) => DataRow(
                selected: fleet.selected == machine.profile.id,
                onSelectChanged: (_) => openMachine(machine),
                cells: [
                  DataCell(ConstrainedBox(constraints: const BoxConstraints(maxWidth: 310), child: Column(mainAxisAlignment: MainAxisAlignment.center, crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text(machine.profile.name, maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(fontWeight: FontWeight.w600)),
                    const SizedBox(height: 4), Text(machine.profile.endpoint, maxLines: 1, overflow: TextOverflow.ellipsis, style: Theme.of(context).textTheme.bodySmall),
                  ]))),
                  DataCell(statusChip(machine.freshness)), DataCell(Text(machine.profile.role)),
                  DataCell(Text(timestamp(machine.lastContact?.toIso8601String()), style: TextStyle(fontFeatures: monitorFigures))),
                  DataCell(IconButton(onPressed: () => editProfile(machine), tooltip: 'Edit connection and grouping', icon: const Icon(Icons.edit_outlined))),
                ],
              )).toList(),
            )) : Column(children: [
              for (var i = 0; i < group.value.length; i++) ...[
                if (i > 0) const Divider(height: 1),
                machineRow(group.value[i]),
              ],
            ])),
          ],
        ],
      )));
    });
  }
  Widget fleetMetric(String label, String value) => Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    Text(label, style: Theme.of(context).textTheme.bodySmall), const SizedBox(height: 6),
    Text(value, style: Theme.of(context).textTheme.titleLarge?.copyWith(fontFeatures: monitorFigures)),
  ]);
  void openMachine(MachineState machine) {
    fleet.select(machine.profile.id);
    setState(() { page = 'Overview'; search = ''; });
  }
  Widget machineRow(MachineState machine) => Material(type: MaterialType.transparency, child: InkWell(
    onTap: () => openMachine(machine),
    child: Padding(padding: const EdgeInsets.all(18), child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
      const Padding(padding: EdgeInsets.only(top: 2), child: Icon(Icons.computer_outlined, size: 22)),
      const SizedBox(width: 12),
      Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(machine.profile.name, style: Theme.of(context).textTheme.titleSmall),
        const SizedBox(height: 6), Text(machine.profile.endpoint, style: Theme.of(context).textTheme.bodySmall),
        const SizedBox(height: 9),
        Wrap(spacing: 8, runSpacing: 6, crossAxisAlignment: WrapCrossAlignment.center, children: [
          statusChip(machine.freshness), Text('${machine.profile.role} access', style: Theme.of(context).textTheme.bodySmall),
        ]),
        const SizedBox(height: 8),
        Text('Last contact: ${timestamp(machine.lastContact?.toIso8601String())}', style: Theme.of(context).textTheme.bodySmall?.copyWith(fontFeatures: monitorFigures)),
      ])),
      IconButton(onPressed: () => editProfile(machine), tooltip: 'Edit connection and grouping', icon: const Icon(Icons.more_horiz_outlined)),
    ])),
  ));
  Future<void> editProfile(MachineState machine) async {
    final name = TextEditingController(text: machine.profile.name), group = TextEditingController(text: machine.profile.group), endpoint = TextEditingController(text: machine.profile.endpoint);
    await showDialog<void>(context: context, builder: (dialog) => AlertDialog(title: const Text('Machine profile'), content: SizedBox(width: 480, child: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, children: [
      TextField(controller: name, decoration: const InputDecoration(labelText: 'Display name')), const SizedBox(height: 14),
      TextField(controller: group, decoration: const InputDecoration(labelText: 'Group')), const SizedBox(height: 14),
      TextField(controller: endpoint, decoration: const InputDecoration(labelText: 'HTTPS origin')), const SizedBox(height: 10),
      const Text('Moving addresses does not change the enrolled identity. The new hostname must be covered by the agent certificate. Removing a local profile does not revoke the remote device certificate.'),
    ]))), actions: [
      TextButton(onPressed: () async { final ok = await confirm(dialog, title: 'Remove local profile?', message: 'Secure credentials for ${machine.profile.name} will be erased from this app. Revoke the device on the agent first if it must no longer have access.', danger: true); if (ok) { final done = await attempt(() async { await fleet.remove(machine.profile.id); return true; }); if (done == true && dialog.mounted) Navigator.pop(dialog); } }, child: const Text('Remove')),
      TextButton(onPressed: () => Navigator.pop(dialog), child: const Text('Cancel')),
      FilledButton(onPressed: () async {
        final done = await attempt(() async { serverUri(endpoint.text); if (name.text.trim().isEmpty) throw ApiException('A display name is required.');
          final oldName = machine.profile.name, oldGroup = machine.profile.group, oldEndpoint = machine.profile.endpoint;
          machine.profile.name = name.text.trim(); machine.profile.group = group.text.trim(); machine.profile.endpoint = endpoint.text.trim();
          try { await fleet.save(); } catch (_) { machine.profile.name = oldName; machine.profile.group = oldGroup; machine.profile.endpoint = oldEndpoint; rethrow; }
          machine.reconnect(); return true;
        }); if (done == true && dialog.mounted) Navigator.pop(dialog);
      }, child: const Text('Save')),
    ]));
    name.dispose(); group.dispose(); endpoint.dispose();
  }
  Widget operations(MachineState machine) {
    final sections = sectionMap[page]!;
    final matching = machine.catalog.where((op) => op['hidden'] != true && op['id'] != 'files.upload').where((op) => sections.contains(op['section']) || (page == 'Maintenance & help' && !sectionMap.values.expand((s) => s).contains(op['section']) && op['section'] != 'activity')).toList();
    final list = matching.where((op) => '${op['title']} ${op['description']} ${op['id']} ${op['capability']}'.toLowerCase().contains(search.toLowerCase())).toList();
    final groups = <String, List<Map<String, dynamic>>>{};
    for (final operation in list) {
      final section = operation['section']?.toString() ?? 'Other';
      groups.putIfAbsent(section, () => []).add(operation);
    }
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      const SizedBox(height: 24),
      SectionHeader(title: 'Agent operations', subtitle: '${matching.length} catalog actions in ${page.toLowerCase()}. Permissions are enforced by the agent.'),
      const SizedBox(height: 16),
      TextField(key: ValueKey('operations-$page'), decoration: const InputDecoration(labelText: 'Find an operation', hintText: 'Search action, description or capability', prefixIcon: Icon(Icons.search_outlined)), onChanged: (value) => setState(() => search = value)),
      const SizedBox(height: 16),
      if (machine.catalog.isEmpty) const MonitorPanel(child: Text('Operation catalog is unavailable. Reconnect to retrieve the agent capabilities.')),
      if (machine.catalog.isNotEmpty && list.isEmpty) const MonitorPanel(child: Text('No matching operations in this section. The agent catalog is authoritative.')),
      for (final group in groups.entries) ...[
        Padding(padding: const EdgeInsets.only(top: 12, bottom: 10), child: Text('${group.key.replaceAll('_', ' ')} · ${group.value.length}', style: Theme.of(context).textTheme.labelLarge)),
        MonitorPanel(padding: EdgeInsets.zero, child: Column(children: [
          for (var i = 0; i < group.value.length; i++) ...[
            if (i > 0) const Divider(height: 1),
            operationRow(machine, group.value[i]),
          ],
        ])),
      ],
    ]);
  }
  Widget operationRow(MachineState machine, Map<String, dynamic> operation) {
    final colors = Theme.of(context).colorScheme;
    final danger = operation['destructive'] == true;
    final readOnly = machine.health['read_only'] == true && operation['capability'] != 'view';
    final unavailable = operation['allowed'] == false || readOnly;
    return Material(type: MaterialType.transparency, child: InkWell(
      onTap: () => operate(operation),
      child: Padding(padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 16), child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Padding(padding: const EdgeInsets.only(top: 2), child: Icon(danger ? Icons.warning_amber_outlined : Icons.play_circle_outline, size: 22, color: danger ? colors.error : colors.onSurfaceVariant)),
        const SizedBox(width: 14),
        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(operation['title']?.toString() ?? operation['id'].toString(), style: Theme.of(context).textTheme.titleSmall),
          const SizedBox(height: 5),
          Text(operation['description']?.toString() ?? '', style: Theme.of(context).textTheme.bodySmall),
          const SizedBox(height: 10),
          Wrap(spacing: 8, runSpacing: 6, children: [
            StatusPill(label: '${operation['capability']} capability', icon: Icons.key_outlined),
            if (danger) const StatusPill(label: 'Explicit confirmation', tone: MonitorTone.danger, icon: Icons.warning_amber_outlined),
            if (unavailable) StatusPill(label: readOnly ? 'Read-only mode' : 'Permission required', tone: MonitorTone.warning, icon: Icons.lock_outlined),
          ]),
          if (machine.freshness == 'Offline' || machine.freshness == 'Connecting') Padding(padding: const EdgeInsets.only(top: 8), child: Text('Submission requires an agent connection. Retained capabilities may be out of date.', style: TextStyle(color: colors.onSurfaceVariant, fontSize: 12))),
        ])),
        const SizedBox(width: 10), Icon(Icons.chevron_right_outlined, size: 20, color: colors.onSurfaceVariant),
      ])),
    ));
  }
  Widget help(MachineState machine) => Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    Text('Agent maintenance', style: Theme.of(context).textTheme.headlineMedium), const SizedBox(height: 12),
    const Text('The worker owns monitoring, protection, schedules, and jobs independently of this app. Cancel means a request to stop remaining work, never rollback. Interrupted jobs are not replayed automatically.\n\nRemote session actions require an available interactive user-session helper. Powered-off machines cannot report their own outage. An external observer is needed for reliable machine-down alerts.\n\nCertificate renewal or server identity replacement requires trusted local pairing. Never disable certificate checking. If access was revoked, ask an owner to issue a new pairing challenge.\n\nInstall, repair, update, and remove the agent using the supplied signed deployment scripts and release instructions on that Windows machine. Agent removal preserves policy/data unless explicitly requested otherwise.'),
    const SizedBox(height: 14), DataTree(value: machine.health),
  ]);
}

Future<bool> confirm(BuildContext context, {required String title, required String message, bool danger = false}) async => await showDialog<bool>(context: context, builder: (dialog) => AlertDialog(
  icon: Icon(danger ? Icons.warning_amber : Icons.info_outline), title: Text(title), content: SizedBox(width: 520, child: SingleChildScrollView(child: Text(message))),
  actions: [TextButton(onPressed: () => Navigator.pop(dialog, false), child: const Text('Cancel')), FilledButton(onPressed: () => Navigator.pop(dialog, true), style: danger ? FilledButton.styleFrom(backgroundColor: Theme.of(context).colorScheme.error) : null, child: const Text('Confirm'))],
)) ?? false;

Widget statusChip(String status) => StatusPill(
  label: status,
  tone: status == 'Live' ? MonitorTone.success : status == 'Stale' || status == 'Offline' ? MonitorTone.warning : MonitorTone.neutral,
  icon: status == 'Live' ? Icons.sensors_outlined : status == 'Stale' ? Icons.history_outlined : status == 'Connecting' ? Icons.sync_outlined : Icons.cloud_off_outlined,
);

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
