import 'package:flutter/material.dart';

const monitorAccent = Color(0xff0f7566);
const monitorRadius = BorderRadius.all(Radius.circular(12));
const monitorFigures = <FontFeature>[FontFeature.tabularFigures()];

ThemeData buildMonitorTheme(Brightness brightness) {
  final dark = brightness == Brightness.dark;
  final scheme = ColorScheme.fromSeed(
    seedColor: monitorAccent,
    brightness: brightness,
  ).copyWith(
    primary: dark ? const Color(0xff5dd7bb) : monitorAccent,
    onPrimary: dark ? const Color(0xff082d25) : Colors.white,
    primaryContainer: dark ? const Color(0xff173f36) : const Color(0xffddefea),
    onPrimaryContainer: dark ? const Color(0xffb9f2df) : const Color(0xff124e43),
    secondary: dark ? const Color(0xffa8c1cc) : const Color(0xff526875),
    surface: dark ? const Color(0xff182126) : Colors.white,
    surfaceContainerLowest: dark ? const Color(0xff101619) : const Color(0xfff3f5f7),
    surfaceContainerLow: dark ? const Color(0xff151d22) : const Color(0xfff9fafb),
    surfaceContainer: dark ? const Color(0xff1d292f) : const Color(0xffedf1f4),
    surfaceContainerHigh: dark ? const Color(0xff223039) : const Color(0xffe8edf1),
    surfaceContainerHighest: dark ? const Color(0xff293b44) : const Color(0xffe1e8ed),
    onSurface: dark ? const Color(0xffe9f0f2) : const Color(0xff17222b),
    onSurfaceVariant: dark ? const Color(0xffa2b2bc) : const Color(0xff5a6874),
    outline: dark ? const Color(0xff58707d) : const Color(0xff879aa7),
    outlineVariant: dark ? const Color(0xff33454f) : const Color(0xffd8e1e6),
    error: dark ? const Color(0xffff938d) : const Color(0xffb93535),
  );
  final base = ThemeData(
    useMaterial3: true,
    brightness: brightness,
    colorScheme: scheme,
    fontFamily: 'Geist',
  );
  final type = base.textTheme;
  return base.copyWith(
    scaffoldBackgroundColor: scheme.surfaceContainerLowest,
    visualDensity: VisualDensity.standard,
    textTheme: type.copyWith(
      headlineLarge: type.headlineLarge?.copyWith(fontSize: 34, fontWeight: FontWeight.w600, letterSpacing: -1.1, fontFeatures: monitorFigures),
      headlineMedium: type.headlineMedium?.copyWith(fontSize: 28, fontWeight: FontWeight.w600, letterSpacing: -.8, height: 1.18),
      headlineSmall: type.headlineSmall?.copyWith(fontSize: 24, fontWeight: FontWeight.w600, letterSpacing: -.5),
      titleLarge: type.titleLarge?.copyWith(fontSize: 19, fontWeight: FontWeight.w600, letterSpacing: -.3),
      titleMedium: type.titleMedium?.copyWith(fontSize: 15, fontWeight: FontWeight.w600),
      titleSmall: type.titleSmall?.copyWith(fontSize: 13, fontWeight: FontWeight.w600),
      bodyLarge: type.bodyLarge?.copyWith(fontSize: 15, height: 1.5),
      bodyMedium: type.bodyMedium?.copyWith(fontSize: 14, height: 1.45),
      bodySmall: type.bodySmall?.copyWith(fontSize: 12, height: 1.45),
      labelLarge: type.labelLarge?.copyWith(fontSize: 13, fontWeight: FontWeight.w600),
      labelMedium: type.labelMedium?.copyWith(fontSize: 12, fontWeight: FontWeight.w500),
    ),
    appBarTheme: AppBarTheme(
      backgroundColor: scheme.surfaceContainerLowest,
      foregroundColor: scheme.onSurface,
      elevation: 0,
      scrolledUnderElevation: 0,
      centerTitle: false,
      toolbarHeight: 76,
    ),
    cardTheme: CardThemeData(
      color: scheme.surface,
      elevation: 0,
      surfaceTintColor: Colors.transparent,
      margin: const EdgeInsets.symmetric(vertical: 6),
      shape: const RoundedRectangleBorder(borderRadius: monitorRadius),
    ),
    dialogTheme: DialogThemeData(
      backgroundColor: scheme.surface,
      surfaceTintColor: Colors.transparent,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      titleTextStyle: type.titleLarge?.copyWith(fontFamily: 'Geist', fontWeight: FontWeight.w600, color: scheme.onSurface),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: scheme.surfaceContainerLow,
      contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 15),
      labelStyle: TextStyle(color: scheme.onSurfaceVariant, fontSize: 14),
      helperStyle: TextStyle(color: scheme.onSurfaceVariant, fontSize: 12, height: 1.4),
      border: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: BorderSide(color: scheme.outlineVariant)),
      enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: BorderSide(color: scheme.outlineVariant)),
      focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: BorderSide(color: scheme.primary, width: 2)),
      alignLabelWithHint: true,
    ),
    filledButtonTheme: FilledButtonThemeData(style: FilledButton.styleFrom(
      minimumSize: const Size(44, 44),
      padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
      elevation: 0,
    )),
    outlinedButtonTheme: OutlinedButtonThemeData(style: OutlinedButton.styleFrom(
      minimumSize: const Size(44, 44),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 13),
      side: BorderSide(color: scheme.outlineVariant),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
    )),
    textButtonTheme: TextButtonThemeData(style: TextButton.styleFrom(
      minimumSize: const Size(44, 44),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
    )),
    iconButtonTheme: IconButtonThemeData(style: IconButton.styleFrom(
      minimumSize: const Size(44, 44),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
    )),
    listTileTheme: ListTileThemeData(
      minLeadingWidth: 22,
      iconColor: scheme.onSurfaceVariant,
      selectedColor: scheme.primary,
      selectedTileColor: scheme.primaryContainer,
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 5),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
    ),
    chipTheme: ChipThemeData(
      backgroundColor: scheme.surfaceContainer,
      selectedColor: scheme.primaryContainer,
      labelStyle: TextStyle(fontFamily: 'Geist', fontSize: 12, color: scheme.onSurface),
      side: BorderSide.none,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
    ),
    dataTableTheme: DataTableThemeData(
      headingRowColor: WidgetStatePropertyAll(scheme.surfaceContainerLow),
      headingTextStyle: TextStyle(fontFamily: 'Geist', fontSize: 12, fontWeight: FontWeight.w600, color: scheme.onSurfaceVariant),
      dataTextStyle: TextStyle(fontFamily: 'Geist', fontSize: 13, color: scheme.onSurface, fontFeatures: monitorFigures),
      dataRowMinHeight: 58,
      dataRowMaxHeight: 76,
      headingRowHeight: 44,
      horizontalMargin: 18,
      columnSpacing: 24,
    ),
    dividerTheme: DividerThemeData(color: scheme.outlineVariant, thickness: 1),
    progressIndicatorTheme: ProgressIndicatorThemeData(color: scheme.primary, linearTrackColor: scheme.surfaceContainerHighest),
    tooltipTheme: TooltipThemeData(decoration: BoxDecoration(color: scheme.inverseSurface, borderRadius: BorderRadius.circular(6))),
  );
}

class MonitorPanel extends StatelessWidget {
  final Widget child;
  final EdgeInsetsGeometry padding;
  const MonitorPanel({super.key, required this.child, this.padding = const EdgeInsets.all(22)});
  @override
  Widget build(BuildContext context) => Material(
    color: Theme.of(context).colorScheme.surface,
    borderRadius: monitorRadius,
    child: Padding(padding: padding, child: child),
  );
}

class SectionHeader extends StatelessWidget {
  final String title;
  final String? subtitle;
  final Widget? action;
  const SectionHeader({super.key, required this.title, this.subtitle, this.action});
  @override
  Widget build(BuildContext context) {
    final heading = Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text(title, style: Theme.of(context).textTheme.titleLarge),
      if (subtitle != null) ...[const SizedBox(height: 5), Text(subtitle!, style: TextStyle(color: Theme.of(context).colorScheme.onSurfaceVariant))],
    ]);
    return LayoutBuilder(builder: (context, bounds) => bounds.maxWidth < 540
      ? Column(crossAxisAlignment: CrossAxisAlignment.start, children: [heading, if (action != null) ...[const SizedBox(height: 12), action!]])
      : Row(crossAxisAlignment: CrossAxisAlignment.start, children: [Expanded(child: heading), if (action != null) ...[const SizedBox(width: 16), action!]]));
  }
}

enum MonitorTone { neutral, success, warning, danger }

class StatusPill extends StatelessWidget {
  final String label;
  final MonitorTone tone;
  final IconData? icon;
  const StatusPill({super.key, required this.label, this.tone = MonitorTone.neutral, this.icon});
  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final dark = scheme.brightness == Brightness.dark;
    final color = switch (tone) {
      MonitorTone.success => dark ? const Color(0xff7ce1bf) : const Color(0xff15634d),
      MonitorTone.warning => dark ? const Color(0xfff1c27b) : const Color(0xff845211),
      MonitorTone.danger => scheme.error,
      MonitorTone.neutral => scheme.onSurfaceVariant,
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
      decoration: BoxDecoration(color: color.withValues(alpha: dark ? .13 : .08), borderRadius: BorderRadius.circular(6)),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        if (icon != null) ...[Icon(icon, size: 14, color: color), const SizedBox(width: 5)],
        Text(label, style: TextStyle(color: color, fontSize: 12, fontWeight: FontWeight.w600)),
      ]),
    );
  }
}

class MonitorMark extends StatelessWidget {
  final double size;
  const MonitorMark({super.key, this.size = 32});
  @override
  Widget build(BuildContext context) => SizedBox.square(
    dimension: size,
    child: const CustomPaint(painter: _MonitorMarkPainter()),
  );
}

class _MonitorMarkPainter extends CustomPainter {
  const _MonitorMarkPainter();
  static final _background = Paint()..color = monitorAccent;
  static final _line = Paint()
    ..color = const Color(0xfff5fffb)
    ..style = PaintingStyle.stroke
    ..strokeWidth = 1.6
    ..strokeCap = StrokeCap.round
    ..strokeJoin = StrokeJoin.round;
  static final _pulse = Path()
    ..moveTo(8.5, 14)
    ..lineTo(12, 14)
    ..lineTo(14, 11)
    ..lineTo(16.7, 17)
    ..lineTo(18.5, 14)
    ..lineTo(23.5, 14);
  static final _stand = Path()
    ..moveTo(16, 21.5)
    ..lineTo(16, 25)
    ..moveTo(11, 25)
    ..lineTo(21, 25);
  static final _tile = RRect.fromRectAndRadius(const Rect.fromLTWH(0, 0, 32, 32), const Radius.circular(7));
  static final _screen = RRect.fromRectAndRadius(const Rect.fromLTWH(6, 7, 20, 14), const Radius.circular(2));
  @override
  void paint(Canvas canvas, Size size) {
    canvas.save();
    canvas.scale(size.width / 32, size.height / 32);
    canvas.drawRRect(_tile, _background);
    canvas.drawRRect(_screen, _line);
    canvas.drawPath(_pulse, _line);
    canvas.drawPath(_stand, _line);
    canvas.restore();
  }
  @override
  bool shouldRepaint(covariant _MonitorMarkPainter oldDelegate) => false;
}
