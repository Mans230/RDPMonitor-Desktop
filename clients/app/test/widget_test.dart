import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:rdpmonitor/main.dart' show MonitorApp;
import 'package:rdpmonitor/api.dart';
import 'package:rdpmonitor/state.dart';
import 'package:rdpmonitor/views.dart';

void main() {
  test('Agent addresses require HTTPS origins without embedded credentials', () {
    expect(serverUri('https://server.example:9443').host, 'server.example');
    for (final address in ['http://server', 'https://user:password@server', 'https://server/api', 'https://server?key=secret', 'not a URL']) {
      expect(() => serverUri(address), throwsA(isA<ApiException>()));
    }
  });
  test('Idempotency identifiers are UUID v4 values and differ', () {
    final first = requestId();
    expect(first, matches(RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')));
    expect(requestId(), isNot(first));
  });
  test('Unknown telemetry stays unknown rather than becoming zero', () {
    expect(unit(null, '%'), 'Not reported');
    expect(bytes(null), 'Not reported');
    expect(instant(1700000000)!.millisecondsSinceEpoch, 1700000000000);
    expect(timestamp(null), 'Not reported');
  });
  testWidgets('Protected config secrets remain unchanged until explicit replacement', (tester) async {
    dynamic changed;
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: ConfigEditor(value: '***', name: 'api_token', onChanged: (v) => changed = v))));
    expect(find.byType(TextFormField), findsNothing);
    expect(changed, isNull);
    await tester.tap(find.text('Replace / clear'));
    await tester.pump();
    expect(changed, '');
    await tester.enterText(find.byType(TextFormField), 'replacement');
    expect(changed, 'replacement');
    final input = tester.widget<TextField>(find.byType(TextField));
    expect(input.obscureText, isTrue);
  });
  testWidgets('Config booleans retain their real type', (tester) async {
    dynamic changed;
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: ConfigEditor(value: false, name: 'enabled', onChanged: (v) => changed = v))));
    await tester.tap(find.byType(Switch));
    await tester.pump();
    expect(changed, isTrue);
  });
  test('Reachability toggle edits only net_watch and never mutates its input', () {
    final original = <String, dynamic>{'net_watch': false, 'ping_target': '9.9.9.9', 'cpu_alert_pct': 80};
    final enabled = withNetworkWatch(original, true);
    expect(enabled['net_watch'], isTrue);
    expect(enabled['ping_target'], '9.9.9.9');
    expect(enabled['cpu_alert_pct'], 80);
    expect(enabled, isNot(same(original)));
    expect(original['net_watch'], isFalse, reason: 'the live configuration map must not be mutated');
    expect(withNetworkWatch(original, false)['net_watch'], isFalse);
  });
  testWidgets('Open settings remain usable across the rail and drawer breakpoint', (tester) async {
    FlutterSecureStorage.setMockInitialValues({});
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(900, 900);
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(const MonitorApp());
    await tester.pumpAndSettle();
    await tester.tap(find.byTooltip('Connection options'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Relay settings').last);
    await tester.pumpAndSettle();
    expect(find.byType(AlertDialog), findsOneWidget);
    for (final size in const [Size(390, 844), Size(900, 900), Size(390, 844)]) {
      tester.view.physicalSize = size;
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 50));
      expect(tester.takeException(), isNull);
      await tester.pumpAndSettle();
      final dialog = tester.getRect(find.byType(Dialog));
      expect(dialog.left, greaterThanOrEqualTo(0));
      expect(dialog.top, greaterThanOrEqualTo(0));
      expect(dialog.right, lessThanOrEqualTo(size.width));
      expect(dialog.bottom, lessThanOrEqualTo(size.height));
    }
    await tester.tap(find.text('Close').last);
    await tester.pumpAndSettle();
    expect(find.byType(AlertDialog), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
  });
}
