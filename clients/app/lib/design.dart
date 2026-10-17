import 'package:flutter/material.dart';

const monitorAccent = Color(0xff111111);
const monitorRadius = BorderRadius.all(Radius.circular(4));
const monitorFigures = <FontFeature>[FontFeature.tabularFigures()];

ThemeData buildMonitorTheme(Brightness brightness) {
  final dark = brightness == Brightness.dark;
  final ink = dark ? const Color(0xfff4f4f4) : monitorAccent;
  final panel = dark ? const Color(0xff171717) : Colors.white;
  final well = dark ? const Color(0xff242424) : const Color(0xfff2f2f2);
  final line = dark ? const Color(0xff414141) : const Color(0xffdcdcdc);
  final scheme = ColorScheme.fromSeed(seedColor: monitorAccent, brightness: brightness).copyWith(
    primary: ink, onPrimary: dark ? monitorAccent : Colors.white,
    primaryContainer: well, onPrimaryContainer: ink,
    secondary: ink, onSecondary: panel,
    secondaryContainer: dark ? const Color(0xff463821) : const Color(0xfff6ead2),
    onSecondaryContainer: dark ? const Color(0xffefc581) : const Color(0xff7a4a00),
    surface: panel, surfaceContainerLowest: panel, surfaceContainerLow: panel,
    surfaceContainer: well, surfaceContainerHigh: well,
    surfaceContainerHighest: dark ? const Color(0xff333333) : const Color(0xffe6e6e6),
    onSurface: ink, onSurfaceVariant: dark ? const Color(0xffbdbdbd) : const Color(0xff525252),
    outline: dark ? const Color(0xff969696) : const Color(0xff8a8a8a),
    outlineVariant: line,
    error: dark ? const Color(0xffffa6a6) : const Color(0xff8a1c1c),
    errorContainer: dark ? const Color(0xff431e1e) : const Color(0xfff6dcdc),
    onErrorContainer: dark ? const Color(0xffffcaca) : const Color(0xff8a1c1c),
  );
  final base = ThemeData(useMaterial3: true, brightness: brightness, colorScheme: scheme, fontFamily: 'Segoe UI');
  final type = base.textTheme;
  const shape = RoundedRectangleBorder(borderRadius: monitorRadius);
  return base.copyWith(
    scaffoldBackgroundColor: panel,
    visualDensity: VisualDensity.compact,
    materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
    iconTheme: IconThemeData(size: 18, color: ink),
    textTheme: type.copyWith(
      headlineLarge: type.headlineLarge?.copyWith(fontSize: 26, fontWeight: FontWeight.w600, height: 1.2, fontFeatures: monitorFigures),
      headlineMedium: type.headlineMedium?.copyWith(fontSize: 20, fontWeight: FontWeight.w600, height: 1.2),
      headlineSmall: type.headlineSmall?.copyWith(fontSize: 20, fontWeight: FontWeight.w600, height: 1.2),
      titleLarge: type.titleLarge?.copyWith(fontSize: 20, fontWeight: FontWeight.w600, height: 1.25),
      titleMedium: type.titleMedium?.copyWith(fontSize: 13, fontWeight: FontWeight.w600, height: 1.3),
      titleSmall: type.titleSmall?.copyWith(fontSize: 12, fontWeight: FontWeight.w600, height: 1.3, letterSpacing: .4),
      bodyLarge: type.bodyLarge?.copyWith(fontSize: 13, height: 1.4),
      bodyMedium: type.bodyMedium?.copyWith(fontSize: 13, height: 1.4),
      bodySmall: type.bodySmall?.copyWith(fontSize: 12, height: 1.4, color: scheme.onSurfaceVariant),
      labelLarge: type.labelLarge?.copyWith(fontSize: 12, fontWeight: FontWeight.w500),
      labelMedium: type.labelMedium?.copyWith(fontSize: 12, fontWeight: FontWeight.w500),
      labelSmall: type.labelSmall?.copyWith(fontSize: 11, fontWeight: FontWeight.w600),
    ),
    appBarTheme: AppBarTheme(backgroundColor: panel, foregroundColor: ink, elevation: 0, scrolledUnderElevation: 0, centerTitle: false, toolbarHeight: 56),
    cardTheme: CardThemeData(color: panel, elevation: 0, surfaceTintColor: Colors.transparent, margin: EdgeInsets.zero,
      shape: RoundedRectangleBorder(borderRadius: monitorRadius, side: BorderSide(color: line))),
    dialogTheme: DialogThemeData(
      backgroundColor: panel, surfaceTintColor: Colors.transparent,
      shape: RoundedRectangleBorder(borderRadius: monitorRadius, side: BorderSide(color: line)),
      insetPadding: const EdgeInsets.all(24),
      constraints: const BoxConstraints(maxWidth: 600),
      titleTextStyle: TextStyle(fontFamily: 'Segoe UI', fontSize: 18, fontWeight: FontWeight.w600, color: ink),
    ),
    inputDecorationTheme: InputDecorationTheme(
      isDense: true, filled: true, fillColor: panel,
      contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 11),
      labelStyle: TextStyle(color: scheme.onSurfaceVariant, fontSize: 12),
      hintStyle: TextStyle(color: scheme.onSurfaceVariant, fontSize: 12),
      helperStyle: TextStyle(color: scheme.onSurfaceVariant, fontSize: 12, height: 1.4),
      prefixIconConstraints: const BoxConstraints(minWidth: 36, minHeight: 36),
      border: OutlineInputBorder(borderRadius: monitorRadius, borderSide: BorderSide(color: scheme.outline)),
      enabledBorder: OutlineInputBorder(borderRadius: monitorRadius, borderSide: BorderSide(color: scheme.outline)),
      focusedBorder: OutlineInputBorder(borderRadius: monitorRadius, borderSide: BorderSide(color: ink, width: 2)),
      alignLabelWithHint: true,
    ),
    filledButtonTheme: FilledButtonThemeData(style: FilledButton.styleFrom(
      minimumSize: const Size(34, 34), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      shape: shape, elevation: 0, tapTargetSize: MaterialTapTargetSize.shrinkWrap)),
    outlinedButtonTheme: OutlinedButtonThemeData(style: OutlinedButton.styleFrom(
      minimumSize: const Size(34, 34), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      side: BorderSide(color: scheme.outline), shape: shape, tapTargetSize: MaterialTapTargetSize.shrinkWrap)),
    textButtonTheme: TextButtonThemeData(style: TextButton.styleFrom(
      minimumSize: const Size(34, 34), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      shape: shape, tapTargetSize: MaterialTapTargetSize.shrinkWrap)),
    iconButtonTheme: IconButtonThemeData(style: IconButton.styleFrom(
      minimumSize: const Size(32, 32), padding: const EdgeInsets.all(6), iconSize: 18,
      shape: shape, tapTargetSize: MaterialTapTargetSize.shrinkWrap)),
    listTileTheme: ListTileThemeData(
      minLeadingWidth: 18, minTileHeight: 36, dense: true,
      iconColor: scheme.onSurfaceVariant, selectedColor: ink, selectedTileColor: well,
      contentPadding: const EdgeInsets.symmetric(horizontal: 12), shape: shape,
    ),
    chipTheme: ChipThemeData(
      backgroundColor: panel, selectedColor: ink, showCheckmark: false,
      labelStyle: TextStyle(fontFamily: 'Segoe UI', fontSize: 12, color: ink),
      secondaryLabelStyle: TextStyle(fontFamily: 'Segoe UI', fontSize: 12, color: scheme.onPrimary),
      side: BorderSide(color: scheme.outline), shape: const StadiumBorder(),
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
    ),
    dataTableTheme: DataTableThemeData(
      headingRowColor: WidgetStatePropertyAll(panel),
      headingTextStyle: TextStyle(fontFamily: 'Segoe UI', fontSize: 11, fontWeight: FontWeight.w600, color: scheme.onSurfaceVariant, letterSpacing: .5),
      dataTextStyle: TextStyle(fontFamily: 'Segoe UI', fontSize: 12, color: ink, fontFeatures: monitorFigures),
      dataRowMinHeight: 36, dataRowMaxHeight: 64, headingRowHeight: 28, horizontalMargin: 12, columnSpacing: 16,
    ),
    dividerTheme: DividerThemeData(color: line, thickness: 1, space: 1),
    progressIndicatorTheme: ProgressIndicatorThemeData(color: ink, linearTrackColor: scheme.surfaceContainerHighest),
    tooltipTheme: TooltipThemeData(decoration: BoxDecoration(color: scheme.inverseSurface, borderRadius: monitorRadius)),
  );
}

Widget monitorDialogActions(BuildContext context, List<Widget> actions) {
  if (MediaQuery.sizeOf(context).width < 560) {
    return SizedBox(width: double.infinity, child: Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      mainAxisSize: MainAxisSize.min,
      children: [
        for (var index = 0; index < actions.length; index++) ...[
          if (index > 0) const SizedBox(height: 8),
          ConstrainedBox(constraints: const BoxConstraints(minHeight: 40), child: actions[index]),
        ],
      ],
    ));
  }
  return Wrap(spacing: 8, runSpacing: 8, alignment: WrapAlignment.end, children: actions);
}

class MonitorPanel extends StatelessWidget {
  final Widget child;
  final EdgeInsetsGeometry padding;
  const MonitorPanel({super.key, required this.child, this.padding = const EdgeInsets.all(12)});
  @override
  Widget build(BuildContext context) => Material(
    color: Theme.of(context).colorScheme.surface,
    shape: RoundedRectangleBorder(borderRadius: monitorRadius, side: BorderSide(color: Theme.of(context).colorScheme.outlineVariant)),
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
      if (subtitle != null) ...[const SizedBox(height: 4), Text(subtitle!, style: Theme.of(context).textTheme.bodySmall)],
    ]);
    return Padding(padding: const EdgeInsets.only(bottom: 8), child: DecoratedBox(
      decoration: BoxDecoration(border: Border(bottom: BorderSide(color: Theme.of(context).colorScheme.outlineVariant))),
      child: Padding(padding: const EdgeInsets.only(bottom: 8), child: LayoutBuilder(builder: (context, bounds) => bounds.maxWidth < 540
        ? Column(crossAxisAlignment: CrossAxisAlignment.start, children: [heading, if (action != null) ...[const SizedBox(height: 8), action!]])
        : Row(crossAxisAlignment: CrossAxisAlignment.start, children: [Expanded(child: heading), if (action != null) ...[const SizedBox(width: 12), action!]])))));
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
      MonitorTone.success => dark ? const Color(0xff9cdbb6) : const Color(0xff1a5c38),
      MonitorTone.warning => dark ? const Color(0xffefc581) : const Color(0xff7a4a00),
      MonitorTone.danger => scheme.error,
      MonitorTone.neutral => scheme.onSurface,
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(color: tone == MonitorTone.neutral ? scheme.surfaceContainer : color.withValues(alpha: dark ? .15 : .10),
        border: Border.all(color: tone == MonitorTone.neutral ? scheme.outline : color), borderRadius: BorderRadius.circular(12)),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        if (icon != null) ...[Icon(icon, size: 12, color: color), const SizedBox(width: 4)],
        Flexible(child: Text(label, style: TextStyle(color: color, fontSize: 11, fontWeight: FontWeight.w500))),
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
    ..color = Colors.white
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
  static final _tile = RRect.fromRectAndRadius(const Rect.fromLTWH(0, 0, 32, 32), const Radius.circular(4));
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
