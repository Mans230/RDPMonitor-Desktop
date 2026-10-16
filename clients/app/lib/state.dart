import 'dart:async';
import 'dart:io';
import 'package:flutter/widgets.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'api.dart';

DateTime? instant(dynamic value) {
  if (value is num) return DateTime.fromMillisecondsSinceEpoch((value * 1000).round(), isUtc: true);
  return DateTime.tryParse(value?.toString() ?? '');
}
String timestamp(dynamic value) => instant(value)?.toLocal().toString().split('.').first ?? 'Not reported';

class MachineState {
  final MachineProfile profile;
  late AgentApi api;
  Map<String, dynamic> health = {}, snapshot = {};
  List<Map<String, dynamic>> catalog = [], history = [], jobs = [], events = [];
  Map<String, String> errors = {};
  DateTime? lastContact;
  bool busy = false;
  bool loaded = false;
  MachineState(this.profile) { api = AgentApi(profile); }
  String get freshness {
    if (lastContact == null) return errors.isEmpty ? 'Connecting' : 'Offline';
    if (DateTime.now().difference(lastContact!) > const Duration(seconds: 45)) return 'Offline';
    final measured = instant(snapshot['ts']);
    if (errors.containsKey('snapshot') || measured == null || DateTime.now().difference(measured) > const Duration(seconds: 20)) return 'Stale';
    return 'Live';
  }
  void reconnect() { api.close(); api = AgentApi(profile); }
}

class Fleet extends ChangeNotifier with WidgetsBindingObserver {
  final ProfileVault vault = ProfileVault();
  final Map<String, MachineState> machines = {};
  final FlutterLocalNotificationsPlugin notifications = FlutterLocalNotificationsPlugin();
  String? selected;
  String? startupError;
  bool ready = false;
  bool notificationsEnabled = false;
  bool _polling = false;
  bool _active = true;
  int _tick = 0;
  Timer? _timer;
  final Set<String> _notified = {};
  MachineState? get current => machines[selected];
  Future<void> initialize() async {
    WidgetsBinding.instance.addObserver(this);
    try {
      for (final profile in await vault.load()) { machines[profile.id] = MachineState(profile); }
      selected = machines.keys.firstOrNull;
    } catch (error) { startupError = 'Secure profile storage could not be opened: $error'; }
    ready = true; notifyListeners();
    await refresh();
    _timer = Timer.periodic(const Duration(seconds: 5), (_) { if (_active) unawaited(refresh()); });
  }
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // A running Windows client still polls and notifies when unfocused or hidden.
    if (Platform.isWindows) return;
    _active = state == AppLifecycleState.resumed;
    if (_active) { for (final machine in machines.values) { machine.reconnect(); } unawaited(refresh(full: true)); }
  }
  Future<void> enableNotifications(bool enabled) async {
    if (!enabled) { notificationsEnabled = false; notifyListeners(); return; }
    const settings = InitializationSettings(
      android: AndroidInitializationSettings('@mipmap/ic_launcher'),
      iOS: DarwinInitializationSettings(requestAlertPermission: true, requestBadgePermission: true, requestSoundPermission: true),
      windows: WindowsInitializationSettings(appName: 'RDPMonitor', appUserModelId: 'RDPMonitor.Desktop', guid: '5cf9290e-f292-4c2b-9a33-55f770442c11'),
    );
    await notifications.initialize(settings);
    if (Platform.isAndroid) {
      final granted = await notifications.resolvePlatformSpecificImplementation<AndroidFlutterLocalNotificationsPlugin>()?.requestNotificationsPermission();
      if (granted == false) throw ApiException('Notification permission was denied by Android.');
    }
    notificationsEnabled = true;
    for (final machine in machines.values) { for (final event in machine.events) { _notified.add('${machine.profile.id}:${event['id']}'); } }
    notifyListeners();
  }
  Future<void> _alerts(MachineState machine, List<Map<String, dynamic>> events, bool wasLoaded) async {
    for (final event in events) {
      final key = '${machine.profile.id}:${event['id']}';
      if (!_notified.add(key) || !wasLoaded || !notificationsEnabled || !['warning', 'error', 'critical'].contains(event['severity'])) continue;
      await notifications.show(key.hashCode & 0x7fffffff, '${machine.profile.name}: ${event['severity']}',
        event['message']?.toString() ?? event['kind']?.toString(), const NotificationDetails(
          android: AndroidNotificationDetails('agent_alerts', 'Agent alerts', channelDescription: 'Warnings and critical agent events', importance: Importance.high),
          iOS: DarwinNotificationDetails(),
        ));
    }
  }
  Future<void> refresh({bool full = false}) async {
    if (_polling) return;
    _polling = true;
    try {
      _tick++;
      for (final machine in List<MachineState>.from(machines.values)) {
        if (machine.profile.id != selected && !full && machine.loaded && _tick % 6 != 0) continue;
        await refreshMachine(machine, full: full || !machine.loaded);
      }
    } finally { _polling = false; notifyListeners(); }
  }
  Future<void> refreshMachine(MachineState machine, {bool full = false}) async {
    if (machine.busy) return;
    machine.busy = true;
    final wasLoaded = machine.loaded;
    Future<void> resource(String key, String path, void Function(Map<String, dynamic>) apply) async {
      try {
        final lastEvent = machine.events.isEmpty ? 0 : machine.events.map((e) => int.tryParse(e['id'].toString()) ?? 0).reduce((a,b) => a > b ? a : b);
        final value = await machine.api.call('GET', path, query: key == 'events' ? {'after': '$lastEvent', 'limit': '500'} : null);
        if (machines[machine.profile.id] != machine) return;
        apply(value); machine.errors.remove(key); machine.lastContact = DateTime.now();
      } catch (error) { machine.errors[key] = error.toString(); }
    }
    try {
      await Future.wait([
        resource('health', '/health', (v) => machine.health = v),
        resource('snapshot', '/snapshot', (v) => machine.snapshot = v),
        resource('history', '/history', (v) => machine.history = records(v['items'])),
        resource('jobs', '/jobs', (v) => machine.jobs = records(v['items'])),
        resource('events', '/events', (v) {
          final combined = {for (final event in machine.events) event['id'].toString(): event};
          for (final event in records(v['items'])) { combined[event['id'].toString()] = event; }
          machine.events = combined.values.toList();
        }),
        if (full || machine.catalog.isEmpty) resource('catalog', '/catalog', (v) => machine.catalog = records(v['operations'])),
      ]);
      await _alerts(machine, machine.events, wasLoaded);
      machine.loaded = true;
    } catch (error) { machine.errors['notifications'] = error.toString(); }
    finally { machine.busy = false; notifyListeners(); }
  }
  void select(String id) { selected = id; notifyListeners(); unawaited(refresh(full: true)); }
  void _requireWritable() {
    if (!ready || startupError != null) {
      throw ApiException('Secure profiles are unavailable. Restore secure storage and reopen the app before changing the fleet.');
    }
  }
  Future<void> add(MachineProfile profile) async {
    _requireWritable();
    if (machines.containsKey(profile.id)) throw ApiException('This agent is already enrolled. Remove its local profile before enrolling a replacement device certificate.');
    final profiles = [...machines.values.map((m) => m.profile), profile];
    await vault.save(profiles);
    machines[profile.id] = MachineState(profile); selected = profile.id;
    notifyListeners(); await refresh(full: true);
  }
  Future<void> save() async { _requireWritable(); await vault.save(machines.values.map((m) => m.profile).toList()); notifyListeners(); }
  Future<void> renew(MachineState machine) async {
    _requireWritable();
    final replacement = await machine.api.renew();
    // Write the complete replacement atomically in OS storage before dropping the old in-memory profile.
    await vault.save(machines.values.map((m) => m == machine ? replacement : m.profile).toList());
    machines[replacement.id] = MachineState(replacement);
    machine.api.close();
    notifyListeners();
    await refresh(full: true);
  }
  Future<void> remove(String id) async {
    _requireWritable();
    final remaining = machines.values.where((m) => m.profile.id != id).map((m) => m.profile).toList();
    await vault.save(remaining); machines.remove(id)?.api.close();
    if (selected == id) selected = machines.keys.firstOrNull;
    notifyListeners();
  }
  @override
  void dispose() { _timer?.cancel(); WidgetsBinding.instance.removeObserver(this); for (final machine in machines.values) { machine.api.close(); } super.dispose(); }
}
