import 'dart:async';
import 'dart:math' as math;
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';
import 'api.dart';
import 'state.dart';
import 'main.dart' show confirm;
import 'views.dart' show bytes;
import 'design.dart';

class UploadView extends StatefulWidget {
  final MachineState machine;
  final void Function(Map<String, dynamic>) onJob;
  const UploadView({super.key, required this.machine, required this.onJob});
  @override
  State<UploadView> createState() => _UploadViewState();
}
class _UploadViewState extends State<UploadView> {
  XFile? file;
  Map<String, dynamic>? upload;
  String? checksum;
  String? error;
  bool busy = false;
  bool stop = false;
  String submitId = requestId();
  Future<void> choose() async {
    final selected = await openFile(confirmButtonText: 'Select upload');
    if (selected != null && mounted) setState(() { file = selected; upload = null; checksum = null; error = null; submitId = requestId(); });
  }
  Future<void> send() async {
    final source = file;
    if (source == null || busy) return;
    if (!await confirm(context, title: 'Upload file to agent?', message: 'Target: ${widget.machine.profile.name}\nFile: ${source.name}\n\nThe agent writes only into its approved upload directory and verifies the declared size/hash. An existing file is not silently replaced.', danger: true)) return;
    setState(() { busy = true; stop = false; error = null; });
    try {
      final size = await source.length();
      checksum ??= (await sha256.bind(source.openRead()).first).toString();
      if (upload == null) {
        final response = await widget.machine.api.call('POST','/uploads', body: {'name': source.name, 'size': size, 'sha256': checksum});
        upload = object(response['upload']);
      } else {
        upload = object((await widget.machine.api.call('GET','/uploads/${upload!['id']}'))['upload']);
      }
      var offset = (upload!['offset'] as num).toInt();
      final id = upload!['id'].toString();
      if (mounted) setState(() {});
      // Read at most one protocol-sized block at a time; never buffer the whole file.
      while (offset < size && !stop) {
        final length = math.min(262144, size - offset);
        final builder = BytesBuilder(copy: false);
        await for (final chunk in source.openRead(offset, offset + length)) { builder.add(chunk); }
        final chunk = builder.takeBytes();
        if (chunk.length != length) throw ApiException('The source file changed during upload. Select it again.');
        final next = await widget.machine.api.uploadChunk(id, offset, chunk);
        final accepted = (next['offset'] as num).toInt();
        if (accepted <= offset || accepted > size) throw ApiException('Agent returned an invalid upload offset.');
        upload = next; offset = accepted;
        if (mounted) setState(() {});
      }
      if (stop) return;
      final response = await widget.machine.api.call('POST','/uploads/$id/complete', body: {'request_id': submitId});
      widget.onJob(object(response['job']));
      if (mounted) setState(() { file = null; upload = null; checksum = null; });
    } catch (e) { if (mounted) setState(() => error = '$e\nTransfer was not retried automatically. Resume checks the agent offset before sending more data. If completion was interrupted, check Activity first.'); }
    finally { if (mounted) setState(() => busy = false); }
  }
  @override
  Widget build(BuildContext context) {
    final total = upload?['size'] as num?;
    final offset = upload?['offset'] as num?;
    final colors = Theme.of(context).colorScheme;
    final progress = total != null && total > 0 && offset != null ? offset / total : null;
    return Padding(padding: const EdgeInsets.only(bottom: 8), child: MonitorPanel(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      const SectionHeader(title: 'Upload a file', subtitle: 'Stage a local file in the agent’s approved upload directory.'),
      const SizedBox(height: 12),
      Text('Target: ${widget.machine.profile.name}', style: Theme.of(context).textTheme.titleSmall),
      const SizedBox(height: 10),
      Wrap(spacing: 8, runSpacing: 8, children: [
        const StatusPill(label: 'SHA256 integrity check', icon: Icons.fact_check_outlined),
        if (widget.machine.health['read_only'] == true) const StatusPill(label: 'Read-only mode', tone: MonitorTone.warning, icon: Icons.lock_outlined),
      ]),
      const SizedBox(height: 8),
      Text('The Windows worker must have uploads enabled and an approved directory. Existing files are not silently replaced. Downloads are available as authenticated artifacts on job results.', style: TextStyle(color: colors.onSurfaceVariant)),
      const SizedBox(height: 12),
      Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(color: colors.surfaceContainerLow, border: Border.all(color: colors.outlineVariant), borderRadius: BorderRadius.circular(4)),
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Row(children: [
            Icon(file == null ? Icons.upload_file_outlined : Icons.insert_drive_file_outlined, color: colors.onSurfaceVariant),
            const SizedBox(width: 12),
            Expanded(child: Text(file?.name ?? 'No local file selected', style: Theme.of(context).textTheme.titleSmall)),
          ]),
          const SizedBox(height: 12),
          Wrap(spacing: 8, runSpacing: 8, crossAxisAlignment: WrapCrossAlignment.center, children: [
            OutlinedButton.icon(onPressed: busy ? null : choose, icon: const Icon(Icons.attach_file_outlined), label: Text(file == null ? 'Choose local file' : 'Change file')),
            if (file != null) FilledButton.icon(onPressed: busy ? null : send, icon: const Icon(Icons.upload_outlined), label: Text(upload == null ? 'Review & upload' : 'Resume / complete')),
            if (busy) TextButton.icon(onPressed: stop ? null : () => setState(() => stop = true), icon: const Icon(Icons.pause_circle_outline), label: Text(stop ? 'Pause requested' : 'Pause after current chunk')),
          ]),
          if (busy || upload != null) ...[
            const SizedBox(height: 12),
            LinearProgressIndicator(value: progress, minHeight: 4, semanticsLabel: 'File upload progress'),
            const SizedBox(height: 10),
            Text(upload == null ? 'Preparing the file and transfer integrity check…' : '${bytes(offset)} / ${bytes(total)}${progress == null ? '' : ' · ${(progress * 100).toStringAsFixed(1)}%'}', style: TextStyle(fontFeatures: monitorFigures, color: colors.onSurfaceVariant)),
            if (stop && busy) const Padding(padding: EdgeInsets.only(top: 6), child: Text('The current protocol chunk finishes before the transfer pauses.')),
          ],
          if (upload != null) ...[
            const SizedBox(height: 8),
            Text('Staged until ${timestamp(upload!['expires'])}. Resume checks the agent’s accepted offset.', style: Theme.of(context).textTheme.bodySmall),
          ],
          if (checksum != null) ...[
            const SizedBox(height: 14),
            Text('Source SHA256', style: Theme.of(context).textTheme.labelSmall),
            const SizedBox(height: 4),
            SelectableText(checksum!, style: Theme.of(context).textTheme.bodySmall?.copyWith(fontFeatures: monitorFigures)),
          ],
        ]),
      ),
      if (error != null) Padding(padding: const EdgeInsets.only(top: 12), child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(color: colors.errorContainer, border: Border.all(color: colors.error), borderRadius: BorderRadius.circular(4)),
        child: SelectableText(error!, style: TextStyle(color: colors.onErrorContainer)),
      )),
    ])));
  }
}
