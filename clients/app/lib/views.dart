import 'dart:async';
import 'dart:convert';
import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'api.dart';
import 'state.dart';
import 'main.dart' show confirm;
import 'design.dart';

String label(String key) => key.replaceAll(RegExp(r'[_\-.]'), ' ').split(' ').map((v) => v.isEmpty ? v : '${v[0].toUpperCase()}${v.substring(1)}').join(' ');
String unit(dynamic value, [String suffix = '']) => value is num && value.isFinite ? '${value.toStringAsFixed(1)}$suffix' : 'Not reported';
String bytes(dynamic value) {
  if (value is! num || !value.isFinite) return 'Not reported';
  var n = value.toDouble(); var index = 0;
  while (n.abs() >= 1024 && index < 4) { n /= 1024; index++; }
  return '${n.toStringAsFixed(index == 0 ? 0 : 1)} ${['B','KiB','MiB','GiB','TiB'][index]}';
}

MonitorTone _tone(dynamic value) => switch (value?.toString().toLowerCase()) {
  'live' || 'succeeded' || 'success' || 'running' => MonitorTone.success,
  'failed' || 'interrupted' || 'critical' || 'error' || 'offline' => MonitorTone.danger,
  'stale' || 'warning' || 'queued' || 'cancelling' || 'partial' => MonitorTone.warning,
  _ => MonitorTone.neutral,
};

String networkStateLabel(dynamic state) => switch (state?.toString()) {
  'up' => 'Network reachable',
  'down' => 'Network unreachable',
  _ => 'Checking reachability',
};
MonitorTone networkStateTone(dynamic state) => switch (state?.toString()) {
  'up' => MonitorTone.success,
  'down' => MonitorTone.danger,
  _ => MonitorTone.neutral,
};
IconData networkStateIcon(dynamic state) => switch (state?.toString()) {
  'up' => Icons.cloud_done_outlined,
  'down' => Icons.cloud_off_outlined,
  _ => Icons.sync_outlined,
};

class DataTree extends StatelessWidget {
  final dynamic value;
  final String? name;
  const DataTree({super.key, this.value, this.name});
  @override
  Widget build(BuildContext context) {
    if (value is Map) {
      final entries = (value as Map).entries;
      if (entries.isEmpty) return const Padding(padding: EdgeInsets.all(12), child: Text('No fields reported.'));
      return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: entries.map((e) => item(context, e.key.toString(), e.value)).toList());
    }
    if (value is List) {
      final list = value as List;
      if (list.isEmpty) return const Padding(padding: EdgeInsets.all(12), child: Text('No records returned.'));
      return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: List.generate(list.length, (i) => item(context, '${name ?? 'Record'} ${i + 1}', list[i])));
    }
    return SelectableText(value?.toString() ?? 'Not reported', style: const TextStyle(fontFeatures: monitorFigures));
  }
  Widget item(BuildContext context, String key, dynamic data) {
    final scheme = Theme.of(context).colorScheme;
    if (data is Map || data is List) {
      return ExpansionTile(
        key: PageStorageKey('data-$key'),
        tilePadding: const EdgeInsets.symmetric(horizontal: 12),
        title: Text(label(key), style: Theme.of(context).textTheme.titleSmall),
        subtitle: Text(data is List ? '${data.length} records' : '${(data as Map).length} fields', style: Theme.of(context).textTheme.bodySmall),
        childrenPadding: const EdgeInsets.only(left: 12, right: 12, bottom: 12),
        children: [DataTree(value: data, name: key)],
      );
    }
    final heading = Text(label(key), style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 13));
    final content = SelectableText(data?.toString() ?? 'Not reported', style: const TextStyle(fontFeatures: monitorFigures));
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 12),
      decoration: BoxDecoration(border: Border(bottom: BorderSide(color: scheme.outlineVariant.withValues(alpha: .5)))),
      child: LayoutBuilder(builder: (context, bounds) => bounds.maxWidth < 360
        ? Column(crossAxisAlignment: CrossAxisAlignment.start, children: [heading, const SizedBox(height: 4), content])
        : Row(crossAxisAlignment: CrossAxisAlignment.start, children: [Expanded(flex: 2, child: heading), const SizedBox(width: 18), Expanded(flex: 3, child: content)])),
    );
  }
}

class Overview extends StatefulWidget {
  final MachineState machine;
  final bool expanded;
  const Overview({super.key, required this.machine, this.expanded = false});
  @override
  State<Overview> createState() => _OverviewState();
}

class _OverviewState extends State<Overview> {
  int? rangeMinutes;
  @override
  void didUpdateWidget(Overview old) {
    super.didUpdateWidget(old);
    if (old.machine != widget.machine) rangeMinutes = null;
  }
  @override
  Widget build(BuildContext context) {
    final machine = widget.machine;
    final snapshot = machine.snapshot;
    final cpu = object(snapshot['cpu']), ram = object(snapshot['ram']);
    final reach = object(snapshot['network']);
    final theme = Theme.of(context);
    final valid = machine.history.where((row) => instant(row['ts']) != null).toList()
      ..sort((a, b) => instant(a['ts'])!.compareTo(instant(b['ts'])!));
    final span = valid.length > 1 ? instant(valid.last['ts'])!.difference(instant(valid.first['ts'])!).inMinutes : 0;
    final ranges = [5, 15, 60].where((minutes) => span > minutes).toList();
    final selected = ranges.contains(rangeMinutes) ? rangeMinutes : null;
    final cutoff = valid.isEmpty || selected == null ? null : instant(valid.last['ts'])!.subtract(Duration(minutes: selected));
    final visible = cutoff == null ? valid : valid.where((row) => !instant(row['ts'])!.isBefore(cutoff)).toList();
    final resources = MonitorPanel(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      const SectionHeader(title: 'Resource load', subtitle: 'Latest agent measurement'),
      const SizedBox(height: 16),
      LayoutBuilder(builder: (context, bounds) {
        final processor = _resource(context, 'CPU utilization', unit(cpu['pct'], '%'), '${cpu['cores'] ?? 'Unreported'} logical cores', cpu['pct'], prominent: true);
        final memory = _resource(context, 'Memory', unit(ram['pct'], '%'), '${bytes(ram['used'])} used of ${bytes(ram['total'])}', ram['pct']);
        return bounds.maxWidth < 460
          ? Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [processor, const SizedBox(height: 26), memory])
          : Row(crossAxisAlignment: CrossAxisAlignment.start, children: [Expanded(flex: 3, child: processor), const SizedBox(width: 32), Expanded(flex: 2, child: memory)]);
      }),
      const SizedBox(height: 18),
      MetricChart(history: visible, series: const ['cpu', 'ram'], title: 'Utilization history', percent: true),
    ]));
    final facts = MonitorPanel(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      const SectionHeader(title: 'Machine facts', subtitle: 'Reported by this agent'),
      const SizedBox(height: 14),
      DataTree(value: {
        'uptime': _uptime(snapshot['uptime']),
        'sessions': snapshot['sessions'] is List ? (snapshot['sessions'] as List).length : null,
        'monitor_service': object(snapshot['services'])['monitor'],
        'read_only_mode': snapshot['read_only'] ?? machine.health['read_only'],
      }),
      if (object(snapshot['protection']).isNotEmpty) ...[
        const SizedBox(height: 14),
        Text('Protection signals', style: theme.textTheme.titleSmall),
        DataTree(value: snapshot['protection']),
      ],
      if (snapshot['errors'] is List && (snapshot['errors'] as List).isNotEmpty) ...[
        const SizedBox(height: 12),
        const StatusPill(label: 'Component data unavailable', tone: MonitorTone.warning, icon: Icons.info_outline),
        DataTree(value: snapshot['errors']),
      ],
    ]));
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      SectionHeader(
        title: widget.expanded ? 'Monitoring' : 'Machine overview',
        subtitle: machine.profile.name,
        action: StatusPill(label: machine.freshness, tone: _tone(machine.freshness), icon: machine.freshness == 'Live' ? Icons.sensors_outlined : Icons.schedule_outlined),
      ),
      const SizedBox(height: 18),
      Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
        decoration: BoxDecoration(color: theme.colorScheme.surfaceContainer, borderRadius: BorderRadius.circular(8)),
        child: Wrap(spacing: 14, runSpacing: 6, crossAxisAlignment: WrapCrossAlignment.center, children: [
          Text('Snapshot measured', style: theme.textTheme.labelMedium?.copyWith(color: theme.colorScheme.onSurfaceVariant)),
          SelectableText(timestamp(snapshot['ts']), style: theme.textTheme.titleSmall?.copyWith(fontFeatures: monitorFigures)),
          if (machine.freshness != 'Live') Text('${machine.freshness}: retained sample, not a current health guarantee.', style: theme.textTheme.bodySmall),
        ]),
      ),
      const SizedBox(height: 16),
      Wrap(spacing: 8, runSpacing: 8, crossAxisAlignment: WrapCrossAlignment.center, children: [
        Text('Loaded history', style: theme.textTheme.titleSmall),
        ChoiceChip(label: const Text('All loaded'), selected: selected == null, onSelected: (_) => setState(() => rangeMinutes = null)),
        for (final minutes in ranges) ChoiceChip(label: Text(minutes == 60 ? 'Last hour' : 'Last $minutes min'), selected: selected == minutes, onSelected: (_) => setState(() => rangeMinutes = minutes)),
      ]),
      const SizedBox(height: 8),
      Tooltip(message: 'These ranges filter loaded measurements only; earlier history is not fetched.', child: Text(valid.isEmpty ? 'No timestamped history loaded.' : '${visible.length} of ${valid.length} loaded samples · ${timestamp(valid.first['ts'])} — ${timestamp(valid.last['ts'])}', style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant))),
      if (machine.errors['history'] != null) Padding(padding: const EdgeInsets.only(top: 8), child: Text('History refresh unavailable. Showing retained measurements.', style: TextStyle(color: theme.colorScheme.error))),
      const SizedBox(height: 16),
      LayoutBuilder(builder: (context, bounds) => bounds.maxWidth < 800
        ? Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [resources, const SizedBox(height: 16), facts])
        : Row(crossAxisAlignment: CrossAxisAlignment.start, children: [Expanded(flex: 7, child: resources), const SizedBox(width: 18), Expanded(flex: 4, child: facts)])),
      const SizedBox(height: 18),
      MonitorPanel(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        SectionHeader(
          title: 'Network',
          subtitle: 'Reachability, transfer rates and interface state',
          action: reach.isEmpty ? null : StatusPill(label: networkStateLabel(reach['state']), tone: networkStateTone(reach['state']), icon: networkStateIcon(reach['state'])),
        ),
        const SizedBox(height: 16),
        if (reach.isEmpty)
          const Text('Reachability monitoring has not reported yet. The agent probes the configured target about once a minute while net_watch is enabled.')
        else
          DataTree(value: {
            'target': reach['target'],
            'last_checked': timestamp(reach['checked_at']),
            'state_since': timestamp(reach['since']),
            if (reach['state'] == 'down') 'outage_started': timestamp(reach['down_since']),
            if (reach['state'] == 'up' && (reach['seconds_down'] is num) && (reach['seconds_down'] as num) > 0) 'last_outage_seconds': reach['seconds_down'],
          }),
        const SizedBox(height: 18),
        Wrap(spacing: 38, runSpacing: 16, children: [
          _networkValue(context, 'Receive', snapshot['down_bps'], Icons.south_outlined),
          _networkValue(context, 'Send', snapshot['up_bps'], Icons.north_outlined),
        ]),
        const SizedBox(height: 20),
        MetricChart(history: visible, series: const ['down_bps', 'up_bps'], title: 'Throughput history'),
        const SizedBox(height: 10),
        DataTree(value: {'total_received': bytes(snapshot['bytes_received']), 'total_sent': bytes(snapshot['bytes_sent']), 'interfaces': snapshot['nics']}),
      ])),
      const SizedBox(height: 18),
      LayoutBuilder(builder: (context, bounds) {
        final disks = MonitorPanel(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          const SectionHeader(title: 'Storage', subtitle: 'Reported volumes'),
          const SizedBox(height: 12),
          if (snapshot['disks'] is! List || (snapshot['disks'] as List).isEmpty) const Text('No volume measurements reported.'),
          for (final disk in records(snapshot['disks'])) Padding(padding: const EdgeInsets.symmetric(vertical: 12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            Text('${disk['mount'] ?? disk['device'] ?? 'Volume'}', style: theme.textTheme.titleMedium),
            const SizedBox(height: 5),
            Text('${unit(disk['pct'], '%')} used · ${bytes(disk['free'])} free', style: const TextStyle(fontFeatures: monitorFigures)),
            const SizedBox(height: 8),
            if (_number(disk['pct']) != null) LinearProgressIndicator(value: (_number(disk['pct'])! / 100).clamp(0.0, 1.0).toDouble()),
          ])),
        ]));
        final recent = _recent(context, machine);
        return bounds.maxWidth < 850
          ? Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [disks, const SizedBox(height: 18), recent])
          : Row(crossAxisAlignment: CrossAxisAlignment.start, children: [Expanded(flex: 4, child: disks), const SizedBox(width: 18), Expanded(flex: 6, child: recent)]);
      }),
      const SizedBox(height: 18),
      MonitorPanel(padding: EdgeInsets.zero, child: ExpansionTile(
        title: const Text('Raw agent snapshot'),
        subtitle: const Text('Inspect all reported fields and component errors'),
        childrenPadding: const EdgeInsets.all(12),
        children: [DataTree(value: snapshot)],
      )),
    ]);
  }
  Widget _resource(BuildContext context, String title, String value, String detail, dynamic percent, {bool prominent = false}) => Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    Text(title, style: Theme.of(context).textTheme.labelLarge?.copyWith(color: Theme.of(context).colorScheme.onSurfaceVariant)),
    const SizedBox(height: 10),
    Text(value, style: Theme.of(context).textTheme.headlineLarge?.copyWith(fontSize: value == 'Not reported' ? 24 : prominent ? 56 : 38, letterSpacing: -1.8, fontFeatures: monitorFigures)),
    const SizedBox(height: 9),
    Text(detail, style: Theme.of(context).textTheme.bodySmall),
    const SizedBox(height: 14),
    if (_number(percent) != null) LinearProgressIndicator(value: (_number(percent)! / 100).clamp(0.0, 1.0).toDouble(), minHeight: 4),
  ]);
  Widget _networkValue(BuildContext context, String title, dynamic value, IconData icon) => Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    Row(mainAxisSize: MainAxisSize.min, children: [Icon(icon, size: 16, color: Theme.of(context).colorScheme.primary), const SizedBox(width: 5), Text(title)]),
    const SizedBox(height: 5),
    Text(value is num && value.isFinite ? '${bytes(value)}/s' : 'Not reported', style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontFeatures: monitorFigures)),
  ]);
  Widget _recent(BuildContext context, MachineState machine) {
    final recent = [
      for (final job in machine.jobs) {'type': 'Job', 'data': job},
      for (final event in machine.events) {'type': 'Event', 'data': event},
    ]..sort((a, b) => (instant((b['data'] as Map)['created']) ?? DateTime(1970)).compareTo(instant((a['data'] as Map)['created']) ?? DateTime(1970)));
    return MonitorPanel(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      const SectionHeader(title: 'Recent activity', subtitle: 'Latest loaded jobs and events · full controls in Activity'),
      const SizedBox(height: 14),
      if (machine.errors.containsKey('jobs') || machine.errors.containsKey('events')) const Padding(padding: EdgeInsets.only(bottom: 12), child: Text('Activity refresh unavailable; retained records may be stale.')),
      if (recent.isEmpty) const Text('No jobs or events returned by this agent.'),
      for (final item in recent.take(5)) Builder(builder: (context) {
        final row = item['data'] as Map;
        final status = row['state'] ?? row['severity'];
        return Padding(padding: const EdgeInsets.symmetric(vertical: 10), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Wrap(spacing: 8, runSpacing: 6, crossAxisAlignment: WrapCrossAlignment.center, children: [
            Text(item['type'] as String, style: Theme.of(context).textTheme.labelMedium),
            if (status != null) StatusPill(label: label(status.toString()), tone: _tone(status)),
            Text(timestamp(row['created']), style: Theme.of(context).textTheme.bodySmall?.copyWith(fontFeatures: monitorFigures)),
          ]),
          const SizedBox(height: 6),
          Text('${row['message'] ?? row['operation'] ?? row['kind'] ?? 'Record'}'),
        ]));
      }),
    ]));
  }
}

double? _number(dynamic value) {
  final number = value is num ? value.toDouble() : value is Map && value['pct'] is num ? (value['pct'] as num).toDouble() : null;
  return number != null && number.isFinite ? number : null;
}
String _uptime(dynamic value) {
  if (value is! num || !value.isFinite) return 'Not reported';
  final duration = Duration(seconds: value.toInt());
  return '${duration.inDays}d ${duration.inHours.remainder(24)}h ${duration.inMinutes.remainder(60)}m';
}
String _seriesLabel(String key) => switch (key) {'cpu' => 'CPU', 'ram' => 'Memory', 'up_bps' => 'Send', 'down_bps' => 'Receive', _ => label(key)};

class MetricChart extends StatelessWidget {
  final List<Map<String, dynamic>> history;
  final List<String> series;
  final String title;
  final bool percent;
  const MetricChart({super.key, required this.history, required this.series, required this.title, this.percent = false});
  @override
  Widget build(BuildContext context) {
    final valid = history.where((row) => instant(row['ts']) != null).toList()..sort((a, b) => instant(a['ts'])!.compareTo(instant(b['ts'])!));
    final scheme = Theme.of(context).colorScheme;
    final colors = [scheme.primary, scheme.onSurfaceVariant];
    final values = [for (final row in valid) for (final key in series) if (_number(row[key]) != null) _number(row[key])!];
    final maximum = percent ? 100.0 : values.isEmpty ? 1.0 : math.max(1.0, values.reduce(math.max) * 1.1);
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Text(title, style: Theme.of(context).textTheme.titleSmall),
      const SizedBox(height: 10),
      Wrap(spacing: 20, runSpacing: 8, children: List.generate(series.length, (i) => Row(mainAxisSize: MainAxisSize.min, children: [
        Icon(i == 0 ? Icons.show_chart_outlined : Icons.more_horiz_outlined, size: 18, color: colors[i % colors.length]),
        const SizedBox(width: 5), Text(_seriesLabel(series[i]), style: Theme.of(context).textTheme.bodySmall),
      ]))),
      const SizedBox(height: 14),
      if (valid.length < 2 || values.isEmpty)
        SizedBox(height: 160, child: Center(child: Text(values.isEmpty ? 'No numeric measurements reported for this range.' : 'Waiting for two timestamped measurements.')))
      else Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        SizedBox(width: percent ? 46 : 84, height: 164, child: Column(mainAxisAlignment: MainAxisAlignment.spaceBetween, crossAxisAlignment: CrossAxisAlignment.start, children: [
          for (final factor in [1.0, .5, 0.0]) Text(percent ? '${(maximum * factor).toStringAsFixed(0)}%' : '${bytes(maximum * factor)}/s', style: Theme.of(context).textTheme.bodySmall?.copyWith(fontSize: 11, color: scheme.onSurfaceVariant, fontFeatures: monitorFigures)),
        ])),
        Expanded(child: Semantics(label: '$title. ${valid.length} loaded samples. Axis from zero to ${percent ? '$maximum percent' : '${bytes(maximum)} per second'}. Gaps indicate unavailable measurements.', child: SizedBox(height: 164, child: CustomPaint(painter: HistoryPainter(valid, series, colors, percent, scheme.outlineVariant, maximum: maximum))))),
      ]),
      if (valid.isNotEmpty) Padding(padding: const EdgeInsets.only(top: 8), child: Wrap(alignment: WrapAlignment.spaceBetween, spacing: 14, runSpacing: 4, children: [
        Text(timestamp(valid.first['ts']), style: Theme.of(context).textTheme.bodySmall?.copyWith(fontFeatures: monitorFigures)),
        Text(timestamp(valid.last['ts']), style: Theme.of(context).textTheme.bodySmall?.copyWith(fontFeatures: monitorFigures)),
      ])),
      if (valid.isNotEmpty) ExpansionTile(
        tilePadding: EdgeInsets.zero,
        title: const Text('Inspect measurements', style: TextStyle(fontSize: 12)),
        subtitle: const Text('Missing samples are gaps, not zero.', style: TextStyle(fontSize: 11)),
        children: [DataTree(value: valid.map((row) => {'measured': timestamp(row['ts']), for (final key in series) _seriesLabel(key): percent ? unit(_number(row[key]), '%') : _number(row[key]) == null ? 'Not reported' : '${bytes(_number(row[key]))}/s'}).toList())],
      ),
    ]);
  }
}

class HistoryPainter extends CustomPainter {
  final List<Map<String, dynamic>> rows;
  final List<String> keys;
  final List<Color> colors;
  final bool percent;
  final Color grid;
  final double? maximum;
  HistoryPainter(this.rows, this.keys, this.colors, this.percent, this.grid, {this.maximum});
  double? number(dynamic value) => _number(value);
  @override
  void paint(Canvas canvas, Size size) {
    if (rows.isEmpty) return;
    final start = instant(rows.first['ts'])!.millisecondsSinceEpoch;
    final end = instant(rows.last['ts'])!.millisecondsSinceEpoch;
    final span = math.max(1, end - start);
    var ceiling = maximum ?? (percent ? 100.0 : 1.0);
    if (maximum == null && !percent) {
      for (final row in rows) { for (final key in keys) { final value = number(row[key]); if (value != null) ceiling = math.max(ceiling, value); } }
    }
    for (var i = 0; i <= 4; i++) {
      final y = 4 + (size.height - 8) * i / 4;
      canvas.drawLine(Offset(0, y), Offset(size.width, y), Paint()..color = grid.withValues(alpha: .6)..strokeWidth = 1);
    }
    for (var k = 0; k < keys.length; k++) {
      final paint = Paint()..color = colors[k % colors.length]..strokeWidth = 2..style = PaintingStyle.stroke;
      final path = Path(); var started = false; int? previous;
      for (final row in rows) {
        final value = number(row[keys[k]]); final ts = instant(row['ts'])!.millisecondsSinceEpoch;
        if (value == null) { started = false; previous = null; continue; }
        final x = (ts - start) / span * size.width;
        final y = 4 + (size.height - 8) * (1 - (value / ceiling).clamp(0.0, 1.0));
        if (!started || (previous != null && ts - previous > 45000)) { path.moveTo(x, y); } else { path.lineTo(x, y); }
        canvas.drawCircle(Offset(x, y), 1.8, Paint()..color = colors[k % colors.length]);
        started = true; previous = ts;
      }
      canvas.drawPath(path, paint);
    }
  }
  @override
  bool shouldRepaint(HistoryPainter old) => true;
}

class OperationDialog extends StatefulWidget {
  final MachineState machine;
  final Map<String, dynamic> operation;
  final void Function(Map<String, dynamic>) onSubmitted;
  const OperationDialog({super.key, required this.machine, required this.operation, required this.onSubmitted});
  @override
  State<OperationDialog> createState() => _OperationDialogState();
}
class _OperationDialogState extends State<OperationDialog> {
  final form = GlobalKey<FormState>();
  final Map<String, TextEditingController> controllers = {};
  final Map<String, dynamic> values = {};
  final phrase = TextEditingController();
  bool busy = false;
  String? error;
  String? previousArgs;
  String id = requestId();
  List<Map<String, dynamic>> get fields => records(widget.operation['fields']);
  bool get danger => widget.operation['destructive'] == true;
  bool get unavailable => widget.operation['allowed'] == false;
  @override
  void initState() {
    super.initState();
    for (final field in fields) {
      final key = field['name'].toString();
      if (field['type'] == 'boolean') { values[key] = field['default'] ?? false; }
      else if (field['type'] == 'choice') { values[key] = field['default']; }
      else { controllers[key] = TextEditingController(text: field['default']?.toString() ?? ''); }
    }
  }
  @override
  void dispose() { phrase.dispose(); for (final c in controllers.values) { c.dispose(); } super.dispose(); }
  Map<String, dynamic> arguments() {
    final args = <String, dynamic>{};
    for (final field in fields) {
      final key = field['name'].toString(), type = field['type'];
      if (type == 'boolean') { args[key] = values[key]; continue; }
      if (type == 'choice') { if (values[key] != null) args[key] = values[key]; continue; }
      final text = controllers[key]!.text;
      if (text.isEmpty && field['required'] != true && !field.containsKey('default')) continue;
      args[key] = type == 'integer' ? int.parse(text) : type == 'number' ? double.parse(text) : text;
    }
    return args;
  }
  Future<void> submit() async {
    if (busy || unavailable || !form.currentState!.validate()) return;
    if (danger && phrase.text != widget.machine.profile.name) { setState(() => error = 'Type the exact target machine name to authorize this operation.'); return; }
    setState(() { busy = true; error = null; });
    try {
      final args = arguments(); final serialized = jsonEncode(args);
      if (previousArgs != null && previousArgs != serialized) id = requestId();
      previousArgs = serialized;
      String? nonce;
      if (danger) {
        final approved = await confirm(context, title: 'Confirm ${widget.operation['title']}', message: 'Target: ${widget.machine.profile.name}\nAddress: ${widget.machine.profile.endpoint}\n\n${widget.operation['description']}\n\nThis may modify accounts, files, protection or availability. Cancellation is not rollback. The agent will authorize these exact parameters.', danger: true);
        if (!approved) return;
        final challenge = await widget.machine.api.call('POST', '/confirmations', body: {'operation': widget.operation['id'], 'args': args});
        nonce = challenge['nonce'];
      }
      final response = await widget.machine.api.call('POST', '/jobs', body: {'operation': widget.operation['id'], 'args': args, 'request_id': id, 'nonce': ?nonce});
      widget.onSubmitted(object(response['job']));
      if (mounted) Navigator.pop(context);
    } catch (e) { if (mounted) setState(() => error = '$e\nNo automatic retry was performed. If the connection ended during submission, inspect Activity before explicitly submitting again. Request identifier: $id'); }
    finally { if (mounted) setState(() => busy = false); }
  }
  @override
  Widget build(BuildContext context) => PopScope(canPop: !busy, child: AlertDialog(
    title: Text(widget.operation['title']?.toString() ?? widget.operation['id']), content: SizedBox(width: 600, child: SingleChildScrollView(child: Form(key: form, child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, mainAxisSize: MainAxisSize.min, children: [
      MonitorPanel(padding: const EdgeInsets.all(16), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text('Target machine', style: Theme.of(context).textTheme.labelMedium),
        const SizedBox(height: 5),
        Text(widget.machine.profile.name, style: Theme.of(context).textTheme.titleLarge),
        SelectableText(widget.machine.profile.endpoint, style: Theme.of(context).textTheme.bodySmall),
        const SizedBox(height: 10),
        Wrap(spacing: 8, runSpacing: 8, children: [
          StatusPill(label: widget.machine.freshness, tone: _tone(widget.machine.freshness)),
          StatusPill(label: '${label(widget.operation['capability']?.toString() ?? 'Agent')} capability', icon: Icons.key_outlined),
        ]),
      ])),
      const SizedBox(height: 18),
      Text(widget.operation['description']?.toString() ?? ''), const SizedBox(height: 20),
      if (widget.machine.health['read_only'] == true) const Padding(padding: EdgeInsets.only(bottom: 14), child: Text('Read-only safety mode: the agent refuses mutations. View operations remain available.')),
      if (unavailable) const Padding(padding: EdgeInsets.only(bottom: 18), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        StatusPill(label: 'Operation unavailable', tone: MonitorTone.warning, icon: Icons.lock_outline),
        SizedBox(height: 6),
        Text('This device’s capability or the agent’s current mode does not permit submission. You can still review the parameters.'),
      ])),
      for (final field in fields) Padding(padding: const EdgeInsets.only(bottom: 20), child: fieldWidget(field)),
      if (danger) ...[
        Container(padding: const EdgeInsets.all(16), decoration: BoxDecoration(color: Theme.of(context).colorScheme.error.withValues(alpha: .07), borderRadius: BorderRadius.circular(8)), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Destructive operation', style: TextStyle(color: Theme.of(context).colorScheme.error, fontWeight: FontWeight.w600)),
          const SizedBox(height: 6),
          const Text('Review this target and every parameter. Committed effects may be irreversible; cancellation is not rollback.'),
        ])),
        const SizedBox(height: 16),
        TextFormField(controller: phrase, enabled: !busy, autocorrect: false, decoration: InputDecoration(labelText: 'Type ${widget.machine.profile.name} to confirm', helperText: 'The machine name must match exactly.'), validator: (v) => v == widget.machine.profile.name ? null : 'Machine name must match exactly'),
      ],
      if (error != null) Padding(padding: const EdgeInsets.symmetric(vertical: 14), child: SelectableText(error!, style: TextStyle(color: Theme.of(context).colorScheme.error))),
      if (busy) ...[const SizedBox(height: 14), const LinearProgressIndicator(), const SizedBox(height: 8), const Text('Submitting to the agent. Keep this dialog open.')],
    ])))), actions: [TextButton(onPressed: busy ? null : () => Navigator.pop(context), child: const Text('Cancel')), FilledButton.icon(onPressed: busy || unavailable ? null : submit, style: danger ? FilledButton.styleFrom(backgroundColor: Theme.of(context).colorScheme.error, foregroundColor: Theme.of(context).colorScheme.onError) : null, icon: Icon(danger ? Icons.warning_amber_outlined : Icons.play_arrow_outlined), label: Text(danger ? 'Review & authorize' : 'Run on agent'))],
  ));
  Widget fieldWidget(Map<String, dynamic> field) {
    final key = field['name'].toString(), type = field['type']; final title = '${field['label'] ?? label(key)}${field['required'] == true ? ' *' : ''}';
    if (type == 'boolean') return SwitchListTile(contentPadding: EdgeInsets.zero, title: Text(title), subtitle: field['help'] == null ? null : Text(field['help'].toString()), value: values[key] == true, onChanged: busy ? null : (v) => setState(() => values[key] = v));
    if (type == 'choice') {
      return DropdownButtonFormField<String>(initialValue: values[key]?.toString(), isExpanded: true, decoration: InputDecoration(labelText: title, helperText: field['help']?.toString(), helperMaxLines: 4),
        items: (field['choices'] as List? ?? []).map((v) => DropdownMenuItem(value: v.toString(), child: Text(v.toString()))).toList(), onChanged: busy ? null : (v) => setState(() => values[key] = v), validator: (v) => field['required'] == true && v == null ? 'Required' : null);
    }
    return TextFormField(controller: controllers[key], enabled: !busy, obscureText: type == 'secret', autocorrect: false, enableSuggestions: type != 'secret', maxLines: type == 'secret' ? 1 : (field['multiline'] == true ? 4 : 1),
      keyboardType: type == 'integer' || type == 'number' ? const TextInputType.numberWithOptions(decimal: true, signed: true) : TextInputType.text,
      decoration: InputDecoration(labelText: title, helperText: field['help']?.toString(), helperMaxLines: 5), validator: (v) {
        if (v == null || v.isEmpty) return field['required'] == true ? 'Required' : null;
        if (type == 'integer' && int.tryParse(v) == null) return 'Enter a whole number';
        if (type == 'number' && (double.tryParse(v) == null || !double.parse(v).isFinite)) return 'Enter a finite number';
        return null;
      });
  }
}

class JobDialog extends StatefulWidget {
  final MachineState machine;
  final Map<String, dynamic> initial;
  final Future<void> Function() onChanged;
  final Future<void> Function(Map<String, dynamic>) onDownload;
  const JobDialog({super.key, required this.machine, required this.initial, required this.onChanged, required this.onDownload});
  @override
  State<JobDialog> createState() => _JobDialogState();
}
class _JobDialogState extends State<JobDialog> {
  late Map<String, dynamic> job = widget.initial;
  String? error;
  Timer? timer;
  bool busy = false;
  bool get active => ['queued','running','cancelling'].contains(job['state']);
  @override
  void initState() { super.initState(); timer = Timer.periodic(const Duration(seconds: 3), (_) { if (active && !busy) unawaited(refresh()); }); unawaited(refresh()); }
  @override
  void dispose() { timer?.cancel(); super.dispose(); }
  Future<void> refresh() async {
    busy = true;
    try { final result = await widget.machine.api.call('GET', '/jobs/${Uri.encodeComponent(job['id'].toString())}'); if (mounted) setState(() { job = object(result['job']); error = null; }); }
    catch (e) { if (mounted) setState(() => error = e.toString()); }
    finally { busy = false; }
  }
  Future<void> cancel() async {
    if (!await confirm(context, title: 'Request cancellation?', message: 'Target: ${widget.machine.profile.name}\nJob: ${job['id']}\n\nThe agent will stop remaining work where supported. Committed effects are not rolled back.', danger: true)) return;
    try { final result = await widget.machine.api.call('POST', '/jobs/${Uri.encodeComponent(job['id'].toString())}/cancel', body: {}); if (mounted) setState(() => job = object(result['job'])); await widget.onChanged(); }
    catch (e) { if (mounted) setState(() => error = e.toString()); }
  }
  @override
  Widget build(BuildContext context) {
    final result = object(job['result']);
    final artifacts = [...records(result['artifacts']), ...records(object(result['data'])['artifacts'])];
    return AlertDialog(title: const Text('Job details'), content: SizedBox(width: 720, child: SingleChildScrollView(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, mainAxisSize: MainAxisSize.min, children: [
      Text(widget.machine.profile.name, style: Theme.of(context).textTheme.titleLarge),
      const SizedBox(height: 4),
      Text('${job['operation'] ?? 'Operation not reported'}', style: Theme.of(context).textTheme.titleMedium),
      const SizedBox(height: 12),
      Wrap(spacing: 12, runSpacing: 8, crossAxisAlignment: WrapCrossAlignment.center, children: [
        StatusPill(label: label(job['state']?.toString() ?? 'Not reported'), tone: _tone(job['state'])),
        SelectableText('ID ${job['id']}', style: const TextStyle(fontFeatures: monitorFigures)),
      ]),
      const SizedBox(height: 12),
      Text('${job['message'] ?? 'No execution message reported.'}'),
      if (active) ...[
        Padding(padding: const EdgeInsets.symmetric(vertical: 12), child: LinearProgressIndicator(value: _number(job['progress']) == null ? null : (_number(job['progress'])! / 100).clamp(0.0, 1.0).toDouble())),
        Text(_number(job['progress']) == null ? 'Agent-owned execution · progress not reported' : '${unit(job['progress'], '%')} · agent-owned execution', style: Theme.of(context).textTheme.bodySmall),
      ],
      const SizedBox(height: 14),
      DataTree(value: {'created': timestamp(job['created']), 'started': timestamp(job['started']), 'finished': timestamp(job['finished'])}),
      if (artifacts.isNotEmpty) ...[
        const SizedBox(height: 20),
        const SectionHeader(title: 'Artifacts', subtitle: 'Authenticated downloads from this agent'),
        for (final artifact in artifacts) ListTile(
          leading: const Icon(Icons.download_outlined),
          title: Text(artifact['name']?.toString() ?? artifact['id'].toString()),
          subtitle: Text(bytes(artifact['size']), style: const TextStyle(fontFeatures: monitorFigures)),
          trailing: const Icon(Icons.chevron_right_outlined),
          onTap: () async { try { await widget.onDownload(artifact); } catch (e) { if (mounted) setState(() => error = e.toString()); } },
        ),
      ],
      const SizedBox(height: 14),
      ExpansionTile(tilePadding: EdgeInsets.zero, title: const Text('Execution record'), subtitle: const Text('Parameters, results and agent-reported errors'), children: [DataTree(value: job)]),
      if (error != null) Padding(padding: const EdgeInsets.only(top: 14), child: SelectableText(error!, style: TextStyle(color: Theme.of(context).colorScheme.error))),
    ]))), actions: [
      if (active) TextButton.icon(onPressed: job['state'] == 'cancelling' ? null : cancel, icon: const Icon(Icons.stop_circle_outlined), label: const Text('Request cancellation')),
      TextButton.icon(onPressed: refresh, icon: const Icon(Icons.refresh_outlined), label: const Text('Refresh')),
      FilledButton(onPressed: () => Navigator.pop(context), child: const Text('Close')),
    ]);
  }
}

class ActivityView extends StatefulWidget {
  final MachineState machine;
  final void Function(Map<String, dynamic>) onJob;
  final void Function(String) onError;
  final Future<void> Function() onRefresh;
  const ActivityView({super.key, required this.machine, required this.onJob, required this.onError, required this.onRefresh});
  @override
  State<ActivityView> createState() => _ActivityViewState();
}
class _ActivityViewState extends State<ActivityView> {
  String tab = 'Jobs';
  List<Map<String, dynamic>> audit = [];
  bool loading = false;
  @override
  void didUpdateWidget(ActivityView old) { super.didUpdateWidget(old); if (old.machine != widget.machine) { audit = []; if (tab == 'Audit') unawaited(loadAudit()); } }
  Future<void> loadAudit() async {
    setState(() => loading = true);
    try { final result = await widget.machine.api.call('GET','/audit'); if (mounted) setState(() => audit = records(result['items'])); }
    catch (e) { widget.onError(e.toString()); } finally { if (mounted) setState(() => loading = false); }
  }
  @override
  Widget build(BuildContext context) {
    final data = List<Map<String, dynamic>>.of(tab == 'Jobs' ? widget.machine.jobs : tab == 'Events' ? widget.machine.events : audit)
      ..sort((a, b) => (instant(b['created']) ?? DateTime(1970)).compareTo(instant(a['created']) ?? DateTime(1970)));
    final operations = widget.machine.catalog.where((op) => op['section'] == 'activity');
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      SectionHeader(title: 'Activity', subtitle: '${widget.machine.profile.name} · durable agent records', action: OutlinedButton.icon(
        onPressed: loading ? null : () => tab == 'Audit' ? loadAudit() : widget.onRefresh(),
        icon: const Icon(Icons.refresh_outlined), label: const Text('Refresh'),
      )),
      const SizedBox(height: 20),
      Wrap(spacing: 8, runSpacing: 8, children: [
        for (final name in ['Jobs', 'Events', 'Audit']) ChoiceChip(label: Text(name), selected: tab == name, onSelected: (_) { setState(() => tab = name); if (name == 'Audit') unawaited(loadAudit()); }),
      ]),
      const SizedBox(height: 16),
      if (loading) const Padding(padding: EdgeInsets.only(bottom: 12), child: LinearProgressIndicator()),
      if (tab != 'Audit' && widget.machine.errors.containsKey(tab.toLowerCase())) const Padding(padding: EdgeInsets.only(bottom: 12), child: Text('Refresh unavailable. Showing retained records, which may be stale.')),
      MonitorPanel(padding: EdgeInsets.zero, child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        if (data.isEmpty) Padding(padding: const EdgeInsets.all(24), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Icon(tab == 'Jobs' ? Icons.work_outline : Icons.receipt_long_outlined, color: Theme.of(context).colorScheme.onSurfaceVariant),
          const SizedBox(height: 12),
          Text(loading ? 'Loading agent records…' : 'No ${tab.toLowerCase()} returned by the agent.', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 5),
          const Text('This view shows only records the selected agent has supplied.'),
        ])),
        for (var index = 0; index < data.length; index++) ...[
          if (index > 0) const Divider(height: 1),
          _entry(context, data[index]),
        ],
      ])),
      if (operations.isNotEmpty) ...[
        const SizedBox(height: 24),
        const SectionHeader(title: 'Activity operations', subtitle: 'Review the target and parameters before running'),
        const SizedBox(height: 12),
        MonitorPanel(padding: EdgeInsets.zero, child: Column(children: [
          for (final operation in operations) ListTile(
            leading: const Icon(Icons.play_circle_outline),
            title: Text(operation['title']?.toString() ?? operation['id'].toString()),
            subtitle: Text('${operation['description'] ?? ''}${operation['allowed'] == false ? '\nUnavailable for this device or agent mode.' : ''}'),
            trailing: const Icon(Icons.chevron_right_outlined),
            onTap: () => showDialog<void>(context: context, builder: (_) => OperationDialog(machine: widget.machine, operation: operation, onSubmitted: (_) => widget.onRefresh())),
          ),
        ])),
      ],
    ]);
  }
  Widget _entry(BuildContext context, Map<String, dynamic> entry) {
    final status = entry['state'] ?? entry['severity'] ?? entry['outcome'];
    final summary = Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Wrap(spacing: 10, runSpacing: 6, crossAxisAlignment: WrapCrossAlignment.center, children: [
        StatusPill(label: label(status?.toString() ?? 'Not reported'), tone: _tone(status)),
        Text(timestamp(entry['created']), style: Theme.of(context).textTheme.bodySmall?.copyWith(fontFeatures: monitorFigures)),
      ]),
      if (tab == 'Jobs' && entry['message'] != null) ...[const SizedBox(height: 8), Text(entry['message'].toString())],
    ]);
    if (tab == 'Jobs') {
      return InkWell(onTap: () => widget.onJob(entry), child: Padding(padding: const EdgeInsets.all(18), child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Padding(padding: const EdgeInsets.only(top: 3), child: Icon(['failed', 'interrupted'].contains(entry['state']) ? Icons.error_outline : entry['state'] == 'succeeded' ? Icons.task_alt_outlined : Icons.schedule_outlined, size: 20, color: Theme.of(context).colorScheme.onSurfaceVariant)),
        const SizedBox(width: 14),
        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(entry['operation']?.toString() ?? 'Operation not reported', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8), summary,
        ])),
        const SizedBox(width: 8), const Icon(Icons.chevron_right_outlined),
      ])));
    }
    return ExpansionTile(
      tilePadding: const EdgeInsets.symmetric(horizontal: 18, vertical: 8),
      leading: Icon(tab == 'Events' ? Icons.notifications_outlined : Icons.policy_outlined, size: 20),
      title: Text(entry['message']?.toString() ?? entry['operation']?.toString() ?? entry['kind']?.toString() ?? 'Record', style: Theme.of(context).textTheme.titleMedium),
      subtitle: Padding(padding: const EdgeInsets.only(top: 8), child: summary),
      childrenPadding: const EdgeInsets.fromLTRB(18, 0, 18, 14),
      children: [
        DataTree(value: entry),
        if (tab == 'Events') Align(alignment: Alignment.centerRight, child: TextButton.icon(
          onPressed: () async { try { await widget.machine.api.call('POST', '/events/${entry['id']}/ack', body: {}); await widget.onRefresh(); } catch (e) { widget.onError(e.toString()); } },
          icon: const Icon(Icons.done_outlined), label: const Text('Acknowledge'),
        )),
      ],
    );
  }
}

class DevicesView extends StatefulWidget {
  final MachineState machine;
  final void Function(String) onError;
  const DevicesView({super.key, required this.machine, required this.onError});
  @override
  State<DevicesView> createState() => _DevicesViewState();
}
class _DevicesViewState extends State<DevicesView> {
  List<Map<String, dynamic>> devices = [];
  bool loading = false;
  @override
  void initState() { super.initState(); unawaited(load()); }
  @override
  void didUpdateWidget(DevicesView old) { super.didUpdateWidget(old); if (old.machine != widget.machine) { devices = []; unawaited(load()); } }
  Future<void> load() async {
    setState(() => loading = true);
    try { final response = await widget.machine.api.call('GET','/devices'); if (mounted) setState(() => devices = records(response['items'])); }
    catch (e) { widget.onError(e.toString()); } finally { if (mounted) setState(() => loading = false); }
  }
  Future<void> revoke(Map<String, dynamic> device) async {
    final self = device['id'] == widget.machine.profile.deviceId;
    if (!await confirm(context, title: 'Revoke enrolled device?', message: 'Machine: ${widget.machine.profile.name}\nDevice: ${device['name']}\n\nThis certificate will lose access immediately.${self ? '\nThis is your current device. You will need local pairing to regain access.' : ''}', danger: true)) return;
    try { await widget.machine.api.call('DELETE','/devices/${Uri.encodeComponent(device['id'].toString())}'); await load(); }
    catch (e) { widget.onError(e.toString()); }
  }
  @override
  Widget build(BuildContext context) => Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
    SectionHeader(title: 'Devices & access', subtitle: widget.machine.profile.name, action: OutlinedButton.icon(onPressed: loading ? null : load, icon: const Icon(Icons.refresh_outlined), label: const Text('Refresh'))),
    const SizedBox(height: 16),
    const Text('Roles are approved locally during pairing. This client cannot elevate its own role. Revocation takes effect immediately on the agent.'),
    const SizedBox(height: 20),
    if (loading) const Padding(padding: EdgeInsets.only(bottom: 14), child: LinearProgressIndicator()),
    MonitorPanel(padding: EdgeInsets.zero, child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      if (!loading && devices.isEmpty) const Padding(padding: EdgeInsets.all(24), child: Text('No enrolled devices returned or access is unavailable. Refresh to request the agent’s current device list.')),
      for (var index = 0; index < devices.length; index++) ...[
        if (index > 0) const Divider(height: 1),
        ExpansionTile(
          leading: const Icon(Icons.devices_outlined, size: 20),
          tilePadding: const EdgeInsets.symmetric(horizontal: 18, vertical: 8),
          title: Text(devices[index]['name']?.toString() ?? 'Name not reported', style: Theme.of(context).textTheme.titleMedium),
          subtitle: Padding(padding: const EdgeInsets.only(top: 8), child: Wrap(spacing: 8, runSpacing: 6, children: [
            StatusPill(label: label(devices[index]['role']?.toString() ?? 'Role not reported')),
            StatusPill(label: devices[index]['revoked'] == true ? 'Revoked' : devices[index]['revoked'] == false ? 'Enrolled' : 'Status not reported', tone: devices[index]['revoked'] == true ? MonitorTone.danger : MonitorTone.neutral),
            if (devices[index]['id'] == widget.machine.profile.deviceId) const StatusPill(label: 'This device', icon: Icons.computer_outlined),
          ])),
          childrenPadding: const EdgeInsets.fromLTRB(18, 0, 18, 14),
          children: [
            DataTree(value: devices[index]),
            Align(alignment: Alignment.centerRight, child: TextButton.icon(
              style: TextButton.styleFrom(foregroundColor: Theme.of(context).colorScheme.error),
              onPressed: devices[index]['revoked'] == true ? null : () => revoke(devices[index]),
              icon: const Icon(Icons.block_outlined), label: const Text('Revoke access'),
            )),
          ],
        ),
      ],
    ])),
  ]);
}

class SettingsView extends StatefulWidget {
  final MachineState machine;
  final Fleet fleet;
  final void Function(String) onError;
  const SettingsView({super.key, required this.machine, required this.fleet, required this.onError});
  @override
  State<SettingsView> createState() => _SettingsViewState();
}
class _SettingsViewState extends State<SettingsView> {
  final configurationForm = GlobalKey<FormState>();
  String domain = 'monitor';
  Map<String, dynamic>? configuration;
  dynamic edited;
  String? error;
  bool loading = false;
  int generation = 0;
  @override
  void initState() { super.initState(); unawaited(load()); }
  @override
  void didUpdateWidget(SettingsView old) { super.didUpdateWidget(old); if (old.machine != widget.machine) { configuration = null; unawaited(load()); } }
  Future<void> load() async {
    if (loading) return;
    final machine = widget.machine;
    setState(() { loading = true; error = null; });
    try {
      final result = await machine.api.call('GET', '/config/${Uri.encodeComponent(domain)}');
      if (mounted && widget.machine == machine) setState(() { configuration = result; edited = jsonDecode(jsonEncode(result['value'])); generation++; });
    } catch (e) { if (mounted) setState(() => error = e.toString()); }
    finally { if (mounted) setState(() => loading = false); }
  }
  Future<void> save() async {
    if (!(configurationForm.currentState?.validate() ?? false)) return;
    if (configuration == null || edited is! Map) return;
    if (!await confirm(context, title: 'Apply configuration revision?', message: 'Machine: ${widget.machine.profile.name}\nDomain: $domain\nExpected revision: ${configuration!['revision']}\n\nThe agent validates the whole revision and retains last-known-good configuration on failure. Unchanged masked secrets are preserved. New settings may change protection, schedules, or restart behavior.', danger: true)) return;
    setState(() { loading = true; error = null; });
    try {
      final args = {'domain': domain, 'revision': configuration!['revision'], 'value': edited};
      final challenge = await widget.machine.api.call('POST','/confirmations', body: {'operation': 'configuration.update', 'args': args});
      final updated = await widget.machine.api.call('PUT','/config/${Uri.encodeComponent(domain)}', body: {'revision': configuration!['revision'], 'value': edited, 'nonce': challenge['nonce']});
      if (mounted) setState(() { configuration = updated; edited = jsonDecode(jsonEncode(updated['value'])); generation++; });
    } catch (e) { if (mounted) setState(() => error = '$e\nYour edits remain here. Reload before resolving a revision conflict; no automatic retry was attempted.'); }
    finally { if (mounted) setState(() => loading = false); }
  }
  @override
  Widget build(BuildContext context) {
    final domains = (widget.machine.health['config_domains'] as List? ?? ['monitor','backup']).map((v) => v.toString()).toSet().toList();
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      SectionHeader(title: 'Settings', subtitle: '${widget.machine.profile.name} · client preferences and agent configuration'),
      const SizedBox(height: 20),
      MonitorPanel(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        const SectionHeader(title: 'This client', subtitle: 'Local preferences do not change agent execution'),
        const SizedBox(height: 12),
        SwitchListTile(contentPadding: EdgeInsets.zero, title: const Text('Local alert notifications'), subtitle: const Text('Opt-in while this client is running. Agent events remain durable when the app is closed. Mobile background push requires separately configured APNs/FCM credentials and a trusted server sender; it is not enabled by this switch.'), value: widget.fleet.notificationsEnabled, onChanged: (value) async { try { await widget.fleet.enableNotifications(value); } catch (e) { widget.onError(e.toString()); } }),
        const Divider(height: 28),
        Text('Device certificate', style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 6),
        const Text('Renewal replaces this device’s key and revokes its previous certificate. Keep the client open until secure storage is updated.'),
        const SizedBox(height: 12),
        Align(alignment: Alignment.centerLeft, child: OutlinedButton.icon(onPressed: loading ? null : () async {
        if (!await confirm(context, title: 'Renew this device certificate?', message: 'Target: ${widget.machine.profile.name}\nA new private key is generated locally. The current certificate is revoked immediately when the agent issues its replacement. Keep this application open until secure storage is updated. If interrupted, local pairing may be required.', danger: true)) return;
        setState(() { loading = true; error = null; });
        try { await widget.fleet.renew(widget.machine); } catch (e) { if (mounted) setState(() => error = 'Certificate renewal failed: $e. If the old certificate is no longer accepted, obtain a new local pairing challenge.'); }
        finally { if (mounted) setState(() => loading = false); }
        }, icon: const Icon(Icons.autorenew_outlined), label: const Text('Renew this device certificate'))),
      ])),
      const SizedBox(height: 20),
      MonitorPanel(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        const SectionHeader(title: 'Agent configuration', subtitle: 'Revision-controlled changes, validated by the agent'),
        const SizedBox(height: 14),
        const Text('Secrets remain masked. Leave a protected secret unchanged to preserve it, or explicitly replace or clear it. Edit advanced domain keys with the typed controls below.'),
        if (widget.machine.health['read_only'] == true) const Padding(padding: EdgeInsets.only(top: 12), child: StatusPill(label: 'Read-only safety mode', tone: MonitorTone.warning, icon: Icons.lock_outline)),
        const SizedBox(height: 20),
        LayoutBuilder(builder: (context, bounds) => Wrap(spacing: 14, runSpacing: 12, crossAxisAlignment: WrapCrossAlignment.center, children: [
          SizedBox(width: math.min(260.0, bounds.maxWidth), child: DropdownButtonFormField<String>(
            initialValue: domain, isExpanded: true,
            decoration: const InputDecoration(labelText: 'Configuration domain'),
            items: domains.map((d) => DropdownMenuItem(value: d, child: Text(label(d)))).toList(),
            onChanged: loading ? null : (v) async { if (v != null && v != domain) { setState(() { domain = v; configuration = null; }); await load(); } },
          )),
          StatusPill(label: 'Revision ${configuration?['revision'] ?? 'not loaded'}'),
          OutlinedButton.icon(onPressed: loading ? null : load, icon: const Icon(Icons.refresh_outlined), label: const Text('Reload / discard edits')),
        ])),
        if (loading) const Padding(padding: EdgeInsets.symmetric(vertical: 18), child: LinearProgressIndicator()),
        if (error != null) Padding(padding: const EdgeInsets.symmetric(vertical: 14), child: SelectableText(error!, style: TextStyle(color: Theme.of(context).colorScheme.error))),
        if (configuration != null) ...[
          const SizedBox(height: 20),
          Form(key: configurationForm, child: IgnorePointer(ignoring: loading, child: ConfigEditor(key: ValueKey('${widget.machine.profile.id}-$domain-$generation'), value: edited, name: domain, onChanged: (value) => edited = value))),
          const SizedBox(height: 20),
          Align(alignment: Alignment.centerRight, child: FilledButton.icon(onPressed: loading ? null : save, icon: const Icon(Icons.save_outlined), label: const Text('Review & apply revision'))),
        ],
      ])),
    ]);
  }
}

class ConfigEditor extends StatefulWidget {
  final dynamic value;
  final String name;
  final ValueChanged<dynamic> onChanged;
  const ConfigEditor({super.key, required this.value, required this.name, required this.onChanged});
  @override
  State<ConfigEditor> createState() => _ConfigEditorState();
}
class _ConfigEditorState extends State<ConfigEditor> {
  late dynamic value = widget.value;
  bool replacingSecret = false;
  late final TextEditingController controller = TextEditingController(text: widget.value == '***' ? '' : widget.value?.toString() ?? '');
  bool get secret => widget.value == '***' || RegExp(r'password|secret|token|api_key|private_key|credential', caseSensitive: false).hasMatch(widget.name);
  @override
  void dispose() { controller.dispose(); super.dispose(); }
  void update(dynamic next) { value = next; widget.onChanged(next); }
  Future<void> add({required bool map}) async {
    final key = TextEditingController(); final text = TextEditingController(); var type = 'text'; String? validation;
    final result = await showDialog<Map<String,dynamic>>(context: context, builder: (context) => StatefulBuilder(builder: (context, set) => AlertDialog(title: Text(map ? 'Add setting' : 'Add list item'), content: SizedBox(width: 440, child: SingleChildScrollView(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, mainAxisSize: MainAxisSize.min, children: [
      if (map) ...[TextField(controller: key, decoration: const InputDecoration(labelText: 'Setting name')), const SizedBox(height: 14)],
      DropdownButtonFormField<String>(initialValue: type, decoration: const InputDecoration(labelText: 'Value type'), items: ['text','number','boolean','object','list'].map((t) => DropdownMenuItem(value: t, child: Text(label(t)))).toList(), onChanged: (v) => set(() => type = v!)), const SizedBox(height: 14),
      if (type == 'text' || type == 'number') TextField(controller: text, keyboardType: type == 'number' ? const TextInputType.numberWithOptions(decimal: true, signed: true) : TextInputType.text, decoration: const InputDecoration(labelText: 'Value')),
      if (type == 'boolean') const Text('New boolean starts disabled; toggle it after adding.'),
      if (validation != null) Padding(padding: const EdgeInsets.only(top: 12), child: Text(validation!, style: TextStyle(color: Theme.of(context).colorScheme.error))),
    ]))), actions: [TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')), FilledButton(onPressed: () {
      if (map && (key.text.trim().isEmpty || (value as Map).containsKey(key.text.trim()))) { set(() => validation = 'Enter a new unique setting name.'); return; }
      if (type == 'number' && (num.tryParse(text.text) == null || !num.parse(text.text).isFinite)) { set(() => validation = 'Enter a finite number.'); return; }
      final dynamic item = switch(type) {'number' => num.parse(text.text), 'boolean' => false, 'object' => <String,dynamic>{}, 'list' => <dynamic>[], _ => text.text};
      Navigator.pop(context, {'key': key.text.trim(), 'value': item});
    }, child: const Text('Add'))],)));
    key.dispose(); text.dispose();
    if (result != null) setState(() { if (map) { value[result['key']] = result['value']; } else { value.add(result['value']); } widget.onChanged(value); });
  }
  @override
  Widget build(BuildContext context) {
    if (value is Map) {
      final map = value as Map;
      return MonitorPanel(padding: EdgeInsets.zero, child: ExpansionTile(
        initiallyExpanded: widget.name == 'monitor' || widget.name == 'backup',
        tilePadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
        title: Text(label(widget.name), style: Theme.of(context).textTheme.titleMedium),
        subtitle: Text('${map.length} typed settings', style: Theme.of(context).textTheme.bodySmall),
        childrenPadding: const EdgeInsets.fromLTRB(12, 12, 12, 16),
        children: [
          for (final key in map.keys.toList()) Padding(padding: const EdgeInsets.only(bottom: 20), child: ConfigEditor(key: ValueKey(key), value: map[key], name: key.toString(), onChanged: (next) { map[key] = next; widget.onChanged(map); })),
          Align(alignment: Alignment.centerLeft, child: TextButton.icon(onPressed: () => add(map: true), icon: const Icon(Icons.add_outlined), label: const Text('Add named setting'))),
        ],
      ));
    }
    if (value is List) {
      final list = value as List;
      return MonitorPanel(padding: EdgeInsets.zero, child: ExpansionTile(
        tilePadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
        title: Text(label(widget.name), style: Theme.of(context).textTheme.titleMedium),
        subtitle: Text('${list.length} items', style: Theme.of(context).textTheme.bodySmall),
        childrenPadding: const EdgeInsets.fromLTRB(12, 12, 12, 16),
        children: [
          for (var i = 0; i < list.length; i++) Padding(padding: const EdgeInsets.only(bottom: 16), child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [Expanded(child: ConfigEditor(key: ObjectKey(list[i]), value: list[i], name: 'Item ${i+1}', onChanged: (next) { list[i] = next; widget.onChanged(list); })), IconButton(tooltip: 'Remove list item', onPressed: () => setState(() { list.removeAt(i); widget.onChanged(list); }), icon: const Icon(Icons.remove_circle_outline))])),
          Align(alignment: Alignment.centerLeft, child: TextButton.icon(onPressed: () => add(map: false), icon: const Icon(Icons.add_outlined), label: const Text('Add item'))),
        ],
      ));
    }
    if (value is bool) return SwitchListTile(contentPadding: EdgeInsets.zero, title: Text(label(widget.name)), value: value, onChanged: (v) => setState(() => update(v)));
    if (secret && !replacingSecret) {
      final information = Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [const Icon(Icons.lock_outline, size: 18), const SizedBox(width: 8), Expanded(child: Text(label(widget.name), style: Theme.of(context).textTheme.titleSmall))]),
        const SizedBox(height: 6),
        Text(widget.value == '***' ? 'Protected secret configured. Leave unchanged to preserve it.' : 'Secret hidden. Replace only when intentionally changing credentials.', style: Theme.of(context).textTheme.bodySmall),
      ]);
      final action = TextButton(onPressed: () => setState(() { replacingSecret = true; controller.clear(); update(''); }), child: const Text('Replace / clear'));
      return Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(color: Theme.of(context).colorScheme.surfaceContainerLow, borderRadius: BorderRadius.circular(8)),
        child: LayoutBuilder(builder: (context, bounds) => bounds.maxWidth < 420
          ? Column(crossAxisAlignment: CrossAxisAlignment.start, children: [information, const SizedBox(height: 8), action])
          : Row(children: [Expanded(child: information), const SizedBox(width: 14), action])),
      );
    }
    return TextFormField(controller: controller, obscureText: secret, autocorrect: false, enableSuggestions: !secret,
      keyboardType: value is num ? const TextInputType.numberWithOptions(decimal: true, signed: true) : TextInputType.multiline, maxLines: secret || value is num ? 1 : null,
      decoration: InputDecoration(labelText: label(widget.name), helperMaxLines: 4, helperText: secret ? 'Empty explicitly clears this secret; unchanged secrets remain protected.' : value == null ? 'Unset value; enter text to configure.' : value is num ? 'Numeric value' : null),
      onChanged: (text) { if (value is num) { final parsed = num.tryParse(text); if (parsed != null && parsed.isFinite) update(parsed); } else { update(text); } },
      autovalidateMode: AutovalidateMode.onUserInteraction, validator: (text) => value is num && (num.tryParse(text ?? '') == null || !num.parse(text!).isFinite) ? 'Enter a finite number' : null,
    );
  }
}
