const operationSections = <String, String>{
  'overview': 'Overview', 'monitoring': 'Monitoring', 'security': 'Security',
  'accounts': 'Accounts', 'processes': 'Processes', 'services': 'Services',
  'backups': 'Backups', 'backup': 'Backups', 'recovery': 'Recovery',
  'files': 'Files', 'diagnostics': 'Diagnostics', 'imaging': 'Imaging',
  'automation': 'Automation', 'activity': 'Activity', 'settings': 'Settings',
  'maintenance': 'Maintenance & help',
};

String operationDestination(Map<String, dynamic> operation) {
  final id = operation['id']?.toString() ?? '';
  // These IDs share broader producer sections, but represent distinct tasks.
  if (id.startsWith('services.')) return 'Services';
  if (id == 'backup.restore' || id == 'backup.drill' ||
      id.startsWith('backup.recovery.') || id == 'backup.restore_drill.set' ||
      id == 'settings.recovery_export' || id == 'imaging.recovery') {
    return 'Recovery';
  }
  return operationSections[operation['section']] ?? 'Maintenance & help';
}

String operationSubcategory(Map<String, dynamic> operation) {
  final id = operation['id']?.toString() ?? '';
  final destination = operationDestination(operation);
  if (id.startsWith('backup.recovery.') || id == 'settings.recovery_export') return 'Encrypted recovery configuration';
  if (id == 'imaging.recovery') return 'System image recovery';
  if (destination == 'Recovery') return 'Restore copies and recovery drills';
  if (destination == 'Backups') {
    if (id.startsWith('backup.cloud.')) return 'Cloud destinations and access';
    if (id.startsWith('backup.repository.') || id == 'backup.restic.set') return 'Repository integrity and retention';
    if (id.startsWith('backup.tools.')) return 'Backup tools';
    if (id.startsWith('backup.archive') || id == 'backup.archives') return 'Archives and snapshots';
    if (id.endsWith('.set') || id == 'backup.config' || id == 'backup.secrets.update') return 'Backup settings and schedules';
    return 'Run and monitor backups';
  }
  if (destination == 'Security') {
    if (id.startsWith('security.trap')) return 'Trap account protection';
    if (id.startsWith('security.hardening')) return 'RDP hardening';
    if (id == 'rdp.sessions' || id == 'rdp.logins') return 'Sessions and sign-in history';
    if (id.startsWith('rdp.')) return 'RDP access and emergency controls';
    return 'Firewall and trusted addresses';
  }
  if (destination == 'Monitoring') {
    if (id.contains('network') || id == 'monitoring.traffic') return 'Network reachability and traffic';
    if (id == 'monitoring.top' || id == 'monitoring.temperature') return 'Live resources';
    return 'History, reports and thresholds';
  }
  if (destination == 'Processes') return id.startsWith('session.') ? 'Interactive session actions' : 'Process inspection and control';
  if (destination == 'Services') return 'Windows service inspection and control';
  if (destination == 'Accounts') return id == 'accounts.list' ? 'Account inventory' : 'Account changes and credentials';
  if (destination == 'Diagnostics') {
    if (id.contains('dump')) return 'Crash dumps and sensitive exports';
    if (id.contains('event') || id.contains('logs') || id == 'diagnostics.boot') return 'Windows events and failure diagnosis';
    if (id == 'diagnostics.connections' || id == 'diagnostics.network_test' || id == 'diagnostics.speed_test') return 'Connectivity and bandwidth tests';
    return 'Windows system inventory';
  }
  if (destination == 'Automation') {
    if (id.startsWith('automation.svcwatch.')) return 'Service watchdog policies';
    if (id.startsWith('automation.keepalive.')) return 'Application keepalive policies';
    if (id.startsWith('automation.watch.')) return 'Resource watchdog policies';
    return 'Automation policies';
  }
  if (destination == 'Imaging') return id == 'imaging.upload' || id == 'imaging.link' || id == 'imaging.chart' ? 'Image upload and sharing' : 'System image creation and verification';
  if (destination == 'Maintenance & help') {
    if (id.startsWith('power.')) return 'Host power controls';
    if (id.startsWith('maintenance.cleanup')) return 'Temporary file cleanup';
    if (id == 'maintenance.logs' || id == 'maintenance.export_log') return 'Agent diagnostics';
    if (id == 'maintenance.update') return 'Signed agent updates';
    if (id == 'advanced.shell') return 'Privileged execution';
    if (id == 'help.operations') return 'Command reference';
    return 'Additional agent operations';
  }
  if (destination == 'Settings') return id == 'settings.status' || id == 'settings.export' || id == 'settings.import' ? 'Configuration review and transfer' : 'Monitor behavior and permissions';
  if (destination == 'Activity') return id == 'activity.audit' ? 'Privileged operation audit' : 'Alerts and notifications';
  if (destination == 'Overview') return 'Machine and session inspection';
  if (destination == 'Files') return 'Approved files and exports';
  return 'Additional agent operations';
}
