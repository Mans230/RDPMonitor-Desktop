import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
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
}
