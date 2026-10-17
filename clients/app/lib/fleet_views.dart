import 'package:flutter/material.dart';
import 'api.dart';
import 'design.dart';
import 'state.dart';
import 'views.dart' show bytes;

class MachineFleetView extends StatefulWidget {
  final Fleet fleet;
  final VoidCallback onAdd;
  final ValueChanged<MachineState> onOpen;
  const MachineFleetView({super.key, required this.fleet, required this.onAdd, required this.onOpen});
  @override
  State<MachineFleetView> createState() => _MachineFleetViewState();
}

class _MachineFleetViewState extends State<MachineFleetView> {
  String search = '';
  String filter = 'All';

  bool matches(MachineState machine) {
    final p = machine.profile;
    if (!'${p.name} ${p.group} ${p.endpoint} ${p.role}'.toLowerCase().contains(search.toLowerCase().trim())) return false;
    final today = DateUtils.dateOnly(DateTime.now());
    return switch (filter) {
      'Live' => machine.freshness == 'Live',
      'Stale' => machine.freshness == 'Stale',
      'Offline' => machine.freshness == 'Offline',
      'Connecting' => machine.freshness == 'Connecting',
      'Needs attention' => machine.freshness != 'Live',
      'Expiry due' => p.expiresOn != null && !p.expiresOn!.isAfter(today),
      'Renewal due' => p.renewOn != null && !p.renewOn!.isAfter(today),
      _ => true,
    };
  }

  Future<void> edit(MachineState machine, {bool datesOnly = false}) async {
    await showDialog<void>(context: context, barrierDismissible: false, builder: (_) =>
      _ProfileEditor(fleet: widget.fleet, machine: machine, datesOnly: datesOnly));
    if (mounted) setState(() {});
  }

  @override
  Widget build(BuildContext context) => AnimatedBuilder(animation: widget.fleet, builder: (context, _) {
    final all = widget.fleet.machines.values.toList();
    final groups = <String, List<MachineState>>{};
    for (final machine in all.where(matches)) {
      groups.putIfAbsent(machine.profile.group.trim(), () => []).add(machine);
    }
    final keys = groups.keys.toList()..sort((a, b) => a.toLowerCase().compareTo(b.toLowerCase()));
    for (final list in groups.values) {
      list.sort((a, b) => a.profile.name.toLowerCase().compareTo(b.profile.name.toLowerCase()));
    }
    final live = all.where((m) => m.freshness == 'Live').length;
    DateTime? latestContact;
    for (final machine in all) {
      final contact = machine.lastContact;
      if (contact != null && (latestContact == null || contact.isAfter(latestContact))) latestContact = contact;
    }
    final available = widget.fleet.ready && widget.fleet.startupError == null;
    return ListView(padding: const EdgeInsets.all(12), children: [
      SectionHeader(title: 'Machines', subtitle: widget.fleet.pollingPaused
          ? 'Automatic refresh paused · showing retained contact and disk values.'
          : 'Every action targets one enrolled machine.',
        action: Wrap(spacing: 8, runSpacing: 8, children: [
          if (widget.fleet.pollingPaused) OutlinedButton.icon(onPressed: () => widget.fleet.setPollingPaused(false),
            icon: const Icon(Icons.play_arrow_outlined, size: 16), label: const Text('Resume refresh')),
          FilledButton.icon(onPressed: available ? widget.onAdd : null,
            icon: const Icon(Icons.add, size: 16), label: const Text('Add machine')),
        ])),
      const SizedBox(height: 12),
      if (widget.fleet.startupError != null) ...[
        MonitorPanel(child: Text('${widget.fleet.startupError}\nProfiles are unavailable, not an empty fleet. Restore secure storage before making changes.',
          style: TextStyle(color: Theme.of(context).colorScheme.error))),
        const SizedBox(height: 16),
      ],
      if (!widget.fleet.ready) const LinearProgressIndicator(),
      if (available) ...[
        MonitorPanel(child: LayoutBuilder(builder: (context, bounds) {
          final contact = latestContact;
          final narrow = bounds.maxWidth < 560 * MediaQuery.textScalerOf(context).scale(13) / 13;
          final metrics = <(String, String)>[
            ('Enrolled', '${all.length}'), ('Live telemetry', '$live'),
            ('Not live', '${all.length - live}'),
            ('Latest fleet contact', contact == null ? 'No contact yet' : timestamp(contact.toIso8601String())),
          ];
          return Wrap(spacing: 12, runSpacing: 12, children: [
            for (final metric in metrics)
              SizedBox(width: (bounds.maxWidth - (narrow ? 12 : 36)) / (narrow ? 2 : 4),
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(metric.$1, style: Theme.of(context).textTheme.bodySmall),
                  const SizedBox(height: 4),
                  Text(metric.$2, style: TextStyle(fontFamily: 'Consolas', fontSize: 20, fontFeatures: monitorFigures)),
                ])),
          ]);
        })),
        const SizedBox(height: 8),
      ],
      TextField(onChanged: (value) => setState(() => search = value),
        decoration: const InputDecoration(hintText: 'Name, group, address or role',
          prefixIcon: Icon(Icons.search, size: 18), isDense: true)),
      const SizedBox(height: 8),
      Wrap(spacing: 6, runSpacing: 6, children: [
        for (final value in ['All', 'Live', 'Stale', 'Offline', 'Connecting', 'Needs attention', 'Expiry due', 'Renewal due'])
          ChoiceChip(label: Text(value == 'All' ? 'All · ${all.length}' :
            ['Live', 'Stale', 'Offline', 'Connecting'].contains(value)
              ? '$value · ${all.where((m) => m.freshness == value).length}' : value),
            selected: filter == value, onSelected: (_) => setState(() => filter = value),
            visualDensity: VisualDensity.compact, showCheckmark: false),
      ]),
      const SizedBox(height: 12),
      if (groups.isEmpty && widget.fleet.ready && widget.fleet.startupError == null)
        MonitorPanel(child: Text(all.isEmpty ? 'No machines yet. Add a machine to get started.' : 'No machines match these filters.')),
      for (final key in keys) ...[
        Padding(padding: const EdgeInsets.symmetric(vertical: 10), child: Text('${key.isEmpty ? 'UNGROUPED' : key.toUpperCase()} · ${groups[key]!.length}',
          style: Theme.of(context).textTheme.labelMedium)),
        MonitorPanel(padding: EdgeInsets.zero, child: _FleetTable(machines: groups[key]!, onOpen: widget.onOpen,
          onEdit: (m) => edit(m), onDates: (m) => edit(m, datesOnly: true))),
        const SizedBox(height: 14),
      ],
      const SizedBox(height: 8),
      const Text('Expiry and renewal are optional contract dates, separate from device certificates. Costs are manually entered estimates; no payments or provider changes are performed.'),
    ]);
  });
}

class _FleetTable extends StatefulWidget {
  final List<MachineState> machines;
  final ValueChanged<MachineState> onOpen, onEdit, onDates;
  const _FleetTable({required this.machines, required this.onOpen, required this.onEdit, required this.onDates});
  @override
  State<_FleetTable> createState() => _FleetTableState();
}

class _FleetTableState extends State<_FleetTable> {
  final scroll = ScrollController();
  @override
  void dispose() { scroll.dispose(); super.dispose(); }

  Widget disk(MachineState machine) {
    final disks = records(machine.snapshot['disks']);
    if (disks.isEmpty) return const Text('Not reported');
    final stale = machine.freshness != 'Live';
    final lines = disks.map((d) {
      final mount = d['mount']?.toString() ?? d['device']?.toString() ?? 'Disk';
      return '$mount  ${bytes(d['used'])} used / ${bytes(d['total'])} total\n${bytes(d['free'])} free';
    }).toList();
    return Tooltip(message: '${stale ? 'Stale / retained snapshot\n' : ''}${lines.join('\n\n')}\nMeasured: ${timestamp(machine.snapshot['ts'])}',
      child: SizedBox(width: 250 * (MediaQuery.textScalerOf(context).scale(14) / 14).clamp(1, double.infinity).toDouble(), child: Column(mainAxisAlignment: MainAxisAlignment.center, crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text('${disks.first['mount'] ?? disks.first['device'] ?? 'Disk'} · ${bytes(disks.first['used'])} / ${bytes(disks.first['total'])}', maxLines: 1, overflow: TextOverflow.ellipsis),
        Text('${bytes(disks.first['free'])} free', maxLines: 1, overflow: TextOverflow.ellipsis),
        if (disks.length > 1 || stale) Text('${disks.length > 1 ? '+${disks.length - 1} more disks · ' : ''}${stale ? 'Stale values' : 'Live snapshot'}',
          style: Theme.of(context).textTheme.bodySmall),
      ])));
  }

  Widget date(DateTime? value) {
    if (value == null) return const Text('Not set');
    final due = !value.isAfter(DateUtils.dateOnly(DateTime.now()));
    return Text('${calendarDate(value)}${due ? '\nDue / expired' : ''}',
      style: due ? TextStyle(color: Theme.of(context).colorScheme.error) : null);
  }

  Widget status(MachineState machine) => StatusPill(label: machine.freshness,
    tone: machine.freshness == 'Live' ? MonitorTone.success :
      machine.freshness == 'Offline' ? MonitorTone.danger : MonitorTone.warning);

  Widget contact(MachineState machine) => Text(machine.lastContact == null ? 'No contact yet' :
    timestamp(machine.lastContact!.toIso8601String()), style: Theme.of(context).textTheme.bodySmall);

  Widget cost(MachineState machine) {
    final p = machine.profile;
    return Text(p.costMinor == null ? 'Not set' : '${p.currency} ${costDecimal(p.costMinor!)} · ${p.billingPeriod}');
  }

  Widget actions(MachineState machine, {bool labelled = false}) => Wrap(spacing: 4, runSpacing: 4, children: [
    if (labelled) OutlinedButton.icon(onPressed: () => widget.onOpen(machine),
      icon: const Icon(Icons.open_in_new, size: 16), label: const Text('Open'))
    else IconButton(tooltip: 'Open machine', onPressed: () => widget.onOpen(machine),
      icon: const Icon(Icons.open_in_new, size: 16), visualDensity: VisualDensity.compact),
    if (labelled) OutlinedButton.icon(onPressed: () => widget.onEdit(machine),
      icon: const Icon(Icons.edit_outlined, size: 16), label: const Text('Edit profile'))
    else IconButton(tooltip: 'Edit profile and contract', onPressed: () => widget.onEdit(machine),
      icon: const Icon(Icons.edit_outlined, size: 16), visualDensity: VisualDensity.compact),
    if (labelled) OutlinedButton.icon(onPressed: () => widget.onDates(machine),
      icon: const Icon(Icons.event_repeat_outlined, size: 16), label: const Text('Renewal dates'))
    else IconButton(tooltip: 'Edit renewal dates', onPressed: () => widget.onDates(machine),
      icon: const Icon(Icons.event_repeat_outlined, size: 16), visualDensity: VisualDensity.compact),
  ]);

  Widget field(String label, Widget value) => Padding(
    padding: const EdgeInsets.only(top: 8),
    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text(label.toUpperCase(), style: Theme.of(context).textTheme.labelSmall),
      const SizedBox(height: 3), value,
    ]));

  Widget record(MachineState machine) => Container(
    padding: const EdgeInsets.all(10),
    decoration: BoxDecoration(border: Border(bottom: BorderSide(color: Theme.of(context).dividerColor))),
    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      field('Machine', Text(machine.profile.name, style: Theme.of(context).textTheme.titleSmall)),
      field('Endpoint', SelectableText(machine.profile.endpoint)),
      field('Connection', status(machine)),
      field('Role', Text(machine.profile.role)),
      field('Last contact', contact(machine)),
      field('Disk space', disk(machine)),
      field('Contract expiry', date(machine.profile.expiresOn)),
      field('Renewal date', date(machine.profile.renewOn)),
      field('Cost estimate', cost(machine)),
      const SizedBox(height: 10),
      actions(machine, labelled: true),
    ]));

  @override
  Widget build(BuildContext context) {
    final scale = (MediaQuery.textScalerOf(context).scale(14) / 14).clamp(1, double.infinity).toDouble();
    return LayoutBuilder(builder: (context, bounds) {
      if (bounds.maxWidth < 560 * scale) {
        return Column(crossAxisAlignment: CrossAxisAlignment.stretch,
          children: widget.machines.map(record).toList());
      }
      return Scrollbar(
        controller: scroll, thumbVisibility: true, notificationPredicate: (notice) => notice.depth == 0,
        child: SingleChildScrollView(controller: scroll, scrollDirection: Axis.horizontal,
          padding: const EdgeInsets.only(bottom: 10),
          child: ConstrainedBox(constraints: BoxConstraints(minWidth: bounds.maxWidth),
            child: DataTable(horizontalMargin: 12, columnSpacing: 16,
              headingRowHeight: 28 * scale, dataRowMinHeight: 64 * scale, dataRowMaxHeight: 64 * scale,
              columns: const [
                DataColumn(label: Text('MACHINE / ENDPOINT')), DataColumn(label: Text('CONNECTION')),
                DataColumn(label: Text('ROLE')), DataColumn(label: Text('LAST CONTACT')),
                DataColumn(label: Text('DISK SPACE')), DataColumn(label: Text('CONTRACT EXPIRY')),
                DataColumn(label: Text('RENEWAL DATE')), DataColumn(label: Text('COST ESTIMATE')),
                DataColumn(label: Text('PROFILE')),
              ],
              rows: widget.machines.map((machine) {
                final p = machine.profile;
                return DataRow(cells: [
                  DataCell(SizedBox(width: 190 * scale, child: Column(
                    mainAxisAlignment: MainAxisAlignment.center, crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(p.name, maxLines: 1, overflow: TextOverflow.ellipsis,
                        style: const TextStyle(fontWeight: FontWeight.w600)),
                      Text(p.endpoint, maxLines: 1, overflow: TextOverflow.ellipsis,
                        style: Theme.of(context).textTheme.bodySmall),
                    ])), onTap: () => widget.onOpen(machine)),
                  DataCell(status(machine)), DataCell(Text(p.role)), DataCell(contact(machine)),
                  DataCell(disk(machine)), DataCell(date(p.expiresOn)),
                  DataCell(date(p.renewOn), onTap: () => widget.onDates(machine)),
                  DataCell(cost(machine)), DataCell(actions(machine)),
                ]);
              }).toList()),
          )),
      );
    });
  }
}

class _ProfileEditor extends StatefulWidget {
  final Fleet fleet;
  final MachineState machine;
  final bool datesOnly;
  const _ProfileEditor({required this.fleet, required this.machine, required this.datesOnly});
  @override
  State<_ProfileEditor> createState() => _ProfileEditorState();
}

class _ProfileEditorState extends State<_ProfileEditor> {
  final form = GlobalKey<FormState>();
  late final TextEditingController name, group, amount, currency, endpoint;
  DateTime? expiresOn, renewOn;
  late String period;
  bool saving = false;
  String? error;
  @override
  void initState() {
    super.initState();
    final p = widget.machine.profile;
    name = TextEditingController(text: p.name); group = TextEditingController(text: p.group);
    endpoint = TextEditingController(text: p.endpoint);
    amount = TextEditingController(text: p.costMinor == null ? '' : costDecimal(p.costMinor!));
    currency = TextEditingController(text: p.currency); period = p.billingPeriod;
    expiresOn = p.expiresOn; renewOn = p.renewOn;
  }
  @override
  void dispose() { name.dispose(); group.dispose(); amount.dispose(); currency.dispose(); endpoint.dispose(); super.dispose(); }

  Future<void> pickDate(bool renewal) async {
    final current = renewal ? renewOn : expiresOn;
    final picked = await showDatePicker(context: context, initialDate: current ?? DateTime.now(),
      firstDate: DateTime(1), lastDate: DateTime(9999, 12, 31), helpText: renewal ? 'Contract renewal date' : 'Contract expiry date');
    if (picked != null && mounted) setState(() { if (renewal) { renewOn = DateUtils.dateOnly(picked); } else { expiresOn = DateUtils.dateOnly(picked); } });
  }

  Widget dateField(String label, DateTime? value, bool renewal) => Padding(
    padding: const EdgeInsets.only(bottom: 12), child: InputDecorator(decoration: InputDecoration(labelText: label),
      child: Wrap(crossAxisAlignment: WrapCrossAlignment.center, spacing: 8, children: [
        Text(value == null ? 'Not set' : calendarDate(value)),
        TextButton.icon(onPressed: saving ? null : () => pickDate(renewal), icon: const Icon(Icons.calendar_today_outlined, size: 18), label: const Text('Choose date')),
        if (value != null) TextButton(onPressed: saving ? null : () => setState(() { if (renewal) { renewOn = null; } else { expiresOn = null; } }), child: const Text('Clear')),
      ])));

  Future<void> save() async {
    if (!form.currentState!.validate()) return;
    if (widget.fleet.startupError != null) { setState(() => error = 'Secure storage is unavailable. No changes were saved.'); return; }
    final p = widget.machine.profile;
    if (!identical(widget.fleet.machines[p.id], widget.machine)) {
      setState(() => error = 'This profile changed while the editor was open. Close and reopen the editor.'); return;
    }
    final oldName = p.name, oldGroup = p.group, oldCurrency = p.currency, oldPeriod = p.billingPeriod, oldEndpoint = p.endpoint;
    final oldExpiry = p.expiresOn, oldRenewal = p.renewOn;
    final oldCost = p.costMinor;
    setState(() { saving = true; error = null; });
    if (!widget.datesOnly) {
      p.name = name.text.trim(); p.group = group.text.trim(); p.costMinor = parseCostMinor(amount.text);
      p.currency = currency.text.trim().toUpperCase(); p.billingPeriod = period;
      p.endpoint = endpoint.text.trim();
    }
    p.expiresOn = expiresOn; p.renewOn = renewOn;
    try {
      await widget.fleet.save();
    } catch (failure) {
      p.name = oldName; p.group = oldGroup; p.currency = oldCurrency; p.billingPeriod = oldPeriod;
      p.endpoint = oldEndpoint;
      p.expiresOn = oldExpiry; p.renewOn = oldRenewal; p.costMinor = oldCost;
      if (mounted) setState(() { saving = false; error = 'Could not save to secure storage. Changes were rolled back: $failure'; });
      return;
    }
    if (p.endpoint != oldEndpoint) widget.machine.reconnect();
    if (mounted) Navigator.pop(context);
  }

  Future<void> remove() async {
    final confirmed = await showDialog<bool>(context: context, builder: (context) => AlertDialog(
      title: const Text('Remove local profile?'), content: const Text('This removes credentials from this app only. Revoke the device on the agent first if access must end.'),
      actions: [monitorDialogActions(context, [
        TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
        FilledButton(onPressed: () => Navigator.pop(context, true), child: const Text('Remove')),
      ])]));
    if (confirmed != true || !mounted) return;
    setState(() { saving = true; error = null; });
    try { await widget.fleet.remove(widget.machine.profile.id); if (mounted) Navigator.pop(context); }
    catch (failure) { if (mounted) setState(() { saving = false; error = 'Could not remove profile: $failure'; }); }
  }

  @override
  Widget build(BuildContext context) => PopScope(canPop: !saving, child: AlertDialog(
    title: Text(widget.datesOnly ? 'Edit contract renewal dates' : 'Machine profile and contract'),
    content: SizedBox(width: 520, child: SingleChildScrollView(child: Form(key: form, child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text(widget.machine.profile.name, style: Theme.of(context).textTheme.titleMedium),
      const SizedBox(height: 10),
      const Text('Local reminders only. These dates do not renew a device certificate, change a provider contract or make a payment.'),
      const SizedBox(height: 20),
      if (!widget.datesOnly) ...[
        TextFormField(controller: name, enabled: !saving, decoration: const InputDecoration(labelText: 'Display name'),
          validator: (value) => value == null || value.trim().isEmpty ? 'A display name is required.' : null),
        const SizedBox(height: 12),
        TextFormField(controller: group, enabled: !saving, decoration: const InputDecoration(labelText: 'Group (optional)')),
        const SizedBox(height: 16),
      ],
      dateField('Contract expiry', expiresOn, false), dateField('Renewal date', renewOn, true),
      if (!widget.datesOnly) ...[
        TextFormField(controller: amount, enabled: !saving, keyboardType: const TextInputType.numberWithOptions(decimal: true),
          decoration: const InputDecoration(labelText: 'Cost estimate (optional)', helperText: 'Two decimal places; blank means not set. No currency conversion.'),
          validator: (value) { try { parseCostMinor(value ?? ''); return null; } on FormatException catch (e) { return e.message; } }),
        const SizedBox(height: 12),
        TextFormField(controller: currency, enabled: !saving, textCapitalization: TextCapitalization.characters,
          decoration: const InputDecoration(labelText: 'Currency code', helperText: 'Three letters, for example USD or EUR.'),
          validator: (value) => RegExp(r'^[A-Z]{3}$').hasMatch((value ?? '').trim().toUpperCase()) ? null : 'Use three ASCII letters.'),
        const SizedBox(height: 12),
        DropdownButtonFormField<String>(initialValue: period, isExpanded: true, decoration: const InputDecoration(labelText: 'Billing period'),
          items: ['monthly', 'yearly', 'one-time'].map((p) => DropdownMenuItem(value: p, child: Text(p))).toList(),
          onChanged: saving ? null : (value) => setState(() => period = value!)),
        const SizedBox(height: 16),
        ExpansionTile(tilePadding: EdgeInsets.zero, title: const Text('Connection'),
          children: [
            TextFormField(controller: endpoint, enabled: !saving, readOnly: widget.machine.profile.relay != null,
              decoration: InputDecoration(labelText: widget.machine.profile.relay == null ? 'HTTPS origin' : 'Agent TLS identity (read-only)'),
              validator: (value) { try { serverUri(value ?? ''); return null; } on ApiException catch (e) { return e.message; } }),
            const SizedBox(height: 12),
            const Text('Changing a direct address keeps the enrolled identity; the hostname must match its certificate. Relay changes require a new code from the VM.'),
          ]),
        const SizedBox(height: 12),
        const Text('Use Devices & access for device certificate renewal. Contract dates do not change agent access.'),
      ],
      if (error != null) ...[const SizedBox(height: 16), Text(error!, style: TextStyle(color: Theme.of(context).colorScheme.error))],
    ])))),
    actions: [monitorDialogActions(context, [
      if (!widget.datesOnly) TextButton(onPressed: saving || widget.fleet.startupError != null ? null : remove, child: const Text('Remove local profile')),
      TextButton(onPressed: saving ? null : () => Navigator.pop(context), child: const Text('Cancel')),
      FilledButton(onPressed: saving ? null : save, child: Text(saving ? 'Saving…' : 'Save')),
    ])],
  ));
}
