"""Explicit, original-account migration; no engine imports or firewall cleanup."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

MONITOR_FILES = ('config.json', 'config.json.bak', 'history.json', 'blocked.json',
                 'traffic.json', 'audit.json', 'alert_queue.json', 'file_queue.json',
                 'image_state.json', 'rdp_monitor.log')
BACKUP_EXCLUDE = {'app', 'scripts', '__pycache__', 'app.lock', 'app.pid'}
EXECUTABLE_SUFFIXES = {'.exe', '.dll', '.pyd', '.py', '.pyw', '.ps1', '.bat', '.cmd'}
BACKUP_ENTROPY = b'VPSBackupTool/secrets/v1'


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def atomic_json(path: Path, value) -> None:
    temporary = path.with_suffix(path.suffix + '.new')
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding='utf-8')
    os.replace(temporary, path)


def protect_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(['icacls.exe', str(path), '/inheritance:r', '/grant:r',
                    '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F',
                    '/setowner', '*S-1-5-32-544', '/T', '/C'], check=True, capture_output=True)
    from agent.service import verify_protected_tree
    verify_protected_tree(path)


def _copy(source: Path, target: Path, records: list, original: Path) -> None:
    if source.is_symlink() or source.stat().st_file_attributes & 0x400:
        raise ValueError(f'Migration refuses reparse point: {source}')
    if source.is_dir():
        target.mkdir(parents=True, exist_ok=True)
        for child in source.iterdir():
            _copy(child, target / child.name, records, original)
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    checksum = digest(source)
    if digest(target) != checksum:
        raise IOError(f'Migration copy checksum mismatch: {source}')
    records.append({'source': str(source), 'destination': str(target.relative_to(original)),
                    'sha256': checksum, 'size': target.stat().st_size})


def _reprotect(value, entropy=None):
    import win32crypt
    raw = win32crypt.CryptUnprotectData(base64.b64decode(value, validate=True), entropy, None, None, 1)[1]
    return base64.b64encode(win32crypt.CryptProtectData(raw, 'RDPMonitor migrated secret', entropy, None, None, 5)).decode('ascii')


def _convert_secrets(value):
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            if key == 'telegram_token_enc' and child:
                result[key] = _reprotect(child)
            else:
                result[key] = _convert_secrets(child)
        return result
    if isinstance(value, list):
        return [_convert_secrets(item) for item in value]
    if isinstance(value, str) and value.startswith('dpapi:'):
        return 'dpapi:' + _reprotect(value[6:], BACKUP_ENTROPY)
    return value


def _remap(value, old: Path, new: Path):
    if isinstance(value, dict):
        return {key: _remap(child, old, new) for key, child in value.items()}
    if isinstance(value, list):
        return [_remap(child, old, new) for child in value]
    if isinstance(value, str):
        try:
            candidate = Path(os.path.expandvars(value)).expanduser()
            if candidate.is_absolute() and candidate.is_relative_to(old):
                return str(new / candidate.relative_to(old))
        except (ValueError, OSError):
            pass
    return value


def migrate(source: Path, data_dir: Path, *, expected_account: str) -> dict:
    if os.name != 'nt':
        raise RuntimeError('Migration requires the original Windows account and machine')
    import win32api
    import win32con
    account = win32api.GetUserNameEx(win32con.NameSamCompatible)
    if account.casefold() != expected_account.casefold():
        raise PermissionError('Run migration elevated as the ORIGINAL account; do not use another administrator')
    source, data_dir = source.resolve(), data_dir.absolute()
    if not (source / 'rdp_monitor.py').is_file():
        raise ValueError('Source must be the original suite root containing rdp_monitor.py')
    if data_dir.is_relative_to(source) or source.is_relative_to(data_dir):
        raise ValueError('Source and migration data directory must not contain one another')
    if (data_dir / 'migration.json').exists() or (data_dir / 'state.sqlite3').exists():
        raise FileExistsError('Destination has agent state; migrate before starting the new worker')
    for path in (data_dir / 'legacy' / 'monitor', data_dir / 'backup'):
        if path.exists() and any(path.iterdir()):
            raise FileExistsError(f'Migration destination is not empty: {path}')
    protect_directory(data_dir)
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    recovery = data_dir / 'migration-backups' / stamp
    protect_directory(recovery)
    manifest = {'version': 1, 'source': str(source), 'account': account, 'created': stamp,
                'state': 'stopping-legacy', 'files': [], 'firewall': 'unchanged',
                'external_repositories': 'preserved at original configured locations'}
    atomic_json(recovery / 'manifest.json', manifest)
    # The signed packaged script only targets original source command lines. It
    # snapshots task XML before stopping/unregistering; it never touches firewall.
    script = Path(__file__).resolve().parent.parent / 'scripts' / 'stop-legacy.ps1'
    subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script),
                    '-Source', str(source), '-Backup', str(recovery)], check=True)
    try:
        backup_records = []
        raw_monitor = recovery / 'original' / 'monitor'
        raw_backup = recovery / 'original' / 'backup'
        for name in MONITOR_FILES:
            if (source / name).is_file():
                _copy(source / name, raw_monitor / name, backup_records, recovery)
        old_backup = source / 'backup'
        if old_backup.is_dir():
            for item in old_backup.iterdir():
                if item.name.casefold() not in BACKUP_EXCLUDE:
                    # Preserve original assets, including installed tool binaries,
                    # in the recovery copy. Untrusted executable code is not activated.
                    _copy(item, raw_backup / item.name, backup_records, recovery)
        manifest['backups'] = backup_records
        monitor = data_dir / 'legacy' / 'monitor'
        target_backup = data_dir / 'backup'
        for raw, target in ((raw_monitor, monitor), (raw_backup, target_backup)):
            if raw.exists():
                for directory, dirs, files in os.walk(raw):
                    for name in files:
                        item = Path(directory) / name
                        if item.suffix.casefold() in EXECUTABLE_SUFFIXES:
                            continue
                        _copy(item, target / item.relative_to(raw), manifest['files'], data_dir)
        # Config secret decryption is deliberately in this process/account. A DPAPI
        # failure is fatal and the untouched ciphertext remains in recovery storage.
        for config in (monitor / 'config.json', target_backup / 'config.json'):
            if not config.exists():
                continue
            value = _convert_secrets(json.loads(config.read_text(encoding='utf-8-sig')))
            value = _remap(value, old_backup, target_backup)
            if config.parent == target_backup:
                rclone = value.get('cloud', {}).get('rclone_config', '')
                if rclone and Path(rclone).is_file() and not Path(rclone).is_relative_to(target_backup):
                    destination = target_backup / 'rclone' / 'rclone.conf'
                    _copy(Path(rclone), destination, manifest['files'], data_dir)
                    value['cloud']['rclone_config'] = str(destination)
                value.setdefault('general', {})['autostart'] = False
            atomic_json(config, value)
        # Include the original account's rclone configuration when legacy config
        # relied on profile discovery rather than an explicit configuration path.
        profile_rclone = Path(os.environ.get('APPDATA', '')) / 'rclone' / 'rclone.conf'
        rclone_target = target_backup / 'rclone' / 'rclone.conf'
        if profile_rclone.is_file() and not rclone_target.exists():
            _copy(profile_rclone, rclone_target, manifest['files'], data_dir)
        protect_directory(data_dir)
        for record in manifest['files']:
            destination = data_dir / record['destination']
            record['migrated_sha256'] = digest(destination)
        manifest['state'] = 'complete'
        atomic_json(recovery / 'manifest.json', manifest)
        atomic_json(data_dir / 'migration.json', manifest)
        return manifest
    except Exception as exc:
        manifest['state'] = 'failed'
        manifest['error_type'] = type(exc).__name__
        atomic_json(recovery / 'manifest.json', manifest)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--data-dir', type=Path, required=True)
    parser.add_argument('--original-account', required=True)
    args = parser.parse_args(argv)
    result = migrate(args.source, args.data_dir, expected_account=args.original_account)
    print(json.dumps({'state': result['state'], 'files': len(result['files']), 'firewall': 'unchanged'}))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
