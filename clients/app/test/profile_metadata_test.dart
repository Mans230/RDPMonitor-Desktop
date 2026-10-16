import 'package:flutter_test/flutter_test.dart';
import 'package:rdpmonitor/api.dart';

Map<String, dynamic> legacyProfile() => {
  'id': 'agent-id', 'name': 'Work VM', 'group': 'Production',
  'endpoint': 'https://vm.example:9443', 'certificate': 'certificate',
  'privateKey': 'private-key', 'ca': 'ca', 'fingerprint': 'fingerprint',
  'deviceId': 'device-id', 'role': 'viewer',
};

void main() {
  test('Existing profiles do not acquire invented contract dates or costs', () {
    final legacy = legacyProfile();
    final profile = MachineProfile.fromJson(legacy);
    expect(profile.expiresOn, isNull);
    expect(profile.renewOn, isNull);
    expect(profile.costMinor, isNull);
  });

  test('Contract dates are strict calendar dates without timezone conversions', () {
    expect(calendarDate(parseCalendarDate('2028-02-29')!), '2028-02-29');
    expect(calendarDate(parseCalendarDate('2026-10-16')!), '2026-10-16');
    expect(parseCalendarDate(null), isNull);
    for (final invalid in ['2026-02-29', '2026-04-31', '2026-00-10', '0000-01-01', '2026-1-01', '2026-10-16T00:00:00Z', '']) {
      expect(() => parseCalendarDate(invalid), throwsFormatException, reason: invalid);
    }
  });

  test('Cost parsing never rounds through binary floating point', () {
    expect(parseCostMinor(''), isNull);
    expect(parseCostMinor('0'), 0);
    expect(parseCostMinor('0.01'), 1);
    expect(parseCostMinor('12.3'), 1230);
    expect(parseCostMinor('19.99'), 1999);
    expect(parseCostMinor('90071992547409.93'), 9007199254740993);
    expect(parseCostMinor('92233720368547758.07'), 9223372036854775807);
    expect(costDecimal(9007199254740993), '90071992547409.93');
    for (final invalid in ['-1', '1.001', '1e3', 'NaN', '1,000.00', '92233720368547758.08']) {
      expect(() => parseCostMinor(invalid), throwsFormatException, reason: invalid);
    }
  });


  test('Invalid stored metadata fails honestly instead of displaying a fake zero', () {
    for (final invalid in [
      {'costMinor': -1}, {'costMinor': 1.2}, {'currency': 'US'},
      {'billingPeriod': 'weekly'}, {'expiresOn': '2026-02-30'},
    ]) {
      expect(() => MachineProfile.fromJson({...legacyProfile(), ...invalid}), throwsFormatException);
    }
  });
}
