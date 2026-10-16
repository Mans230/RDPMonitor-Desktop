import 'package:flutter_test/flutter_test.dart';
import 'package:rdpmonitor/api.dart';
import 'package:rdpmonitor/state.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test('Unloaded or unreadable secure profiles cannot be replaced by fleet mutations', () async {
    for (final initialized in [false, true]) {
      final fleet = Fleet()..ready = initialized;
      if (initialized) fleet.startupError = 'Fixture secure storage is unavailable';
      final profile = MachineProfile(id: 'fixture-agent', name: 'Fixture VM', group: '',
        endpoint: 'https://vm.example', certificate: 'fixture certificate', privateKey: 'fixture key',
        ca: 'fixture CA', fingerprint: 'fixture fingerprint', deviceId: 'fixture device', role: 'viewer');
      try {
        await expectLater(fleet.add(profile), throwsA(isA<ApiException>()));
        await expectLater(fleet.save(), throwsA(isA<ApiException>()));
        await expectLater(fleet.remove(profile.id), throwsA(isA<ApiException>()));
        expect(fleet.machines, isEmpty);
      } finally {
        fleet.dispose();
      }
    }
  });
}
