"""Native SCM service host. Never execute privileged code from a writable tree."""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import sys
import threading

WORKER = 'RDPMonitorWorker'
GATEWAY = 'RDPMonitorGateway'
PIPE = r'\\.\pipe\RDPMonitor.Worker.v1'
SYSTEM_SID = 'S-1-5-18'
ADMIN_SID = 'S-1-5-32-544'
GATEWAY_METADATA_RIGHTS = 0x000200A0  # READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE; not inherited.


def gateway_sid() -> str:
    """Derive the fixed virtual-service SID before SCM registration exists."""
    digest = hashlib.sha1(GATEWAY.upper().encode('utf-16-le')).digest()
    return 'S-1-5-80-' + '-'.join(str(int.from_bytes(digest[i:i + 4], 'little')) for i in range(0, 20, 4))


def data_directory() -> Path:
    return Path(os.environ.get('ProgramData', r'C:\ProgramData')) / 'RDPMonitor'


def code_directory() -> Path:
    return Path(sys.executable).resolve().parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent.parent


def verify_protected_tree(path: Path, *, recursive: bool = True, ancestors: bool = True, parent_only: bool = False) -> None:
    """Conservative DACL verification, including ownership and reparse points.

    Reject ANY non-administrative write allow ACE, including inherited/group ACEs,
    rather than assuming a particular user's current group membership is sufficient.
    Deny ACEs cannot make an otherwise unsafe tree acceptable. Fail closed on NULL
    DACL, unknown/object-specific ACEs, unreadable security descriptors or junctions.
    """
    if os.name != 'nt':
        raise RuntimeError('Protected service execution requires Windows')
    import win32security
    import win32con
    path = path.absolute()
    trusted = {SYSTEM_SID, ADMIN_SID}
    trusted.add(win32security.ConvertSidToStringSid(win32security.LookupAccountName(None, 'NT SERVICE\\TrustedInstaller')[0]))
    # FILE_GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE/ALL.
    write_mask = 0x40000000 | 0x10000000 | 0x000D0156
    if parent_only:
        write_mask = 0x500D0040  # replacement/delete-child/owner/DACL rights
    paths = [path]
    if recursive and path.is_dir():
        for directory, dirs, files in os.walk(path, followlinks=False):
            paths.extend(Path(directory) / name for name in dirs + files)
    for item in paths:
        attrs = item.lstat().st_file_attributes
        if attrs & win32con.FILE_ATTRIBUTE_REPARSE_POINT:
            raise PermissionError(f'Reparse points are forbidden in protected trees: {item}')
        sd = win32security.GetFileSecurity(str(item), win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
        owner = win32security.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner())
        if owner not in trusted:
            raise PermissionError(f'Untrusted protected-path owner: {item}')
        acl = sd.GetSecurityDescriptorDacl()
        if acl is None:
            raise PermissionError(f'Unrestricted DACL: {item}')
        for index in range(acl.GetAceCount()):
            ace = acl.GetAce(index)
            kind, flags = ace[0]
            if flags & 0x08:  # INHERIT_ONLY does not apply to this object.
                continue
            if kind == win32security.ACCESS_DENIED_ACE_TYPE:
                continue
            if kind != win32security.ACCESS_ALLOWED_ACE_TYPE:
                raise PermissionError(f'Unsupported ACL entry on protected path: {item}')
            sid = win32security.ConvertSidToStringSid(ace[2])
            if sid not in trusted and ace[1] & write_mask:
                raise PermissionError(f'Non-administrator can modify protected path: {item}')
    # An attacker must not be able to replace the protected root through its parent.
    if ancestors:
        parent = path.parent
        while parent != parent.parent:
            verify_protected_tree(parent, recursive=False, ancestors=False, parent_only=True)
            parent = parent.parent


def verify_installation(root: Path | None = None, data_dir: Path | None = None) -> None:
    root, data_dir = root or code_directory(), data_dir or data_directory()
    program_files = Path(os.environ.get('ProgramFiles', r'C:\Program Files')).resolve()
    if not root.resolve().is_relative_to(program_files):
        raise PermissionError('Services must run from protected Program Files')
    verify_protected_tree(root)
    # Mutable content is privileged input, not an alternative executable directory.
    verify_protected_tree(data_dir)
    verify_protected_tree(Path(sys.executable))


def dispatch(kind: str) -> None:
    if os.name != 'nt' or kind not in ('worker', 'gateway'):
        raise RuntimeError('Expected Windows service-dispatch worker|gateway')
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    class NativeService(win32serviceutil.ServiceFramework):
        _svc_name_ = WORKER if kind == 'worker' else GATEWAY
        _svc_display_name_ = 'RDPMonitor privileged worker' if kind == 'worker' else 'RDPMonitor constrained API gateway'

        def __init__(self, args):
            super().__init__(args)
            self.stop_event = threading.Event()
            self.completed = win32event.CreateEvent(None, True, False, None)

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING, waitHint=60000)
            self.stop_event.set()

        def SvcDoRun(self):
            try:
                root, data = code_directory(), data_directory()
                if kind == 'worker':
                    verify_installation(root, data)
                else:
                    # Gateway cannot read worker state; only executable code and its
                    # own read-only deployment/TLS inputs are accessible to its SID.
                    verify_protected_tree(root)
                    verify_protected_tree(data / 'deployment.json', recursive=False)
                    verify_protected_tree(data / 'gateway')
                config = json.loads((data / 'deployment.json').read_text(encoding='utf-8-sig'))
                from agent.__main__ import run_worker, run_gateway
                resources = Path(getattr(sys, '_MEIPASS', root))
                os.chdir(resources)
                if kind == 'worker':
                    read_only = config.get('read_only', False)
                    if type(read_only) is not bool:
                        raise RuntimeError('Deployment read_only must be a Boolean')
                    if config.get('unsigned_preview') is True and not read_only:
                        raise RuntimeError('Unsigned preview deployments must be monitoring-only')
                    run_worker(resources, data, self.stop_event, pipe_name=config.get('pipe_name', PIPE),
                               read_only=read_only)
                else:
                    run_gateway(resources, data, config['host'], int(config['port']), self.stop_event,
                                pipe_name=config.get('pipe_name', PIPE))
            except Exception:
                servicemanager.LogErrorMsg(f'{self._svc_name_} failed; see Windows Application event log')
                import traceback
                servicemanager.LogErrorMsg(traceback.format_exc())
                raise
            finally:
                win32event.SetEvent(self.completed)

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(NativeService)
    servicemanager.StartServiceCtrlDispatcher()


def register_services(executable: Path) -> None:
    """Register only an already protected, fully installed frozen bundle."""
    import win32service
    import win32serviceutil
    verify_installation(executable.parent)
    scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
    try:
        for name, mode, account, dependencies in (
            (WORKER, 'worker', 'LocalSystem', []),
            (GATEWAY, 'gateway', f'NT SERVICE\\{GATEWAY}', [WORKER]),
        ):
            command = f'"{executable}" service-dispatch {mode}'
            try:
                handle = win32service.OpenService(scm, name, win32service.SERVICE_ALL_ACCESS)
                win32service.ChangeServiceConfig(handle, win32service.SERVICE_WIN32_OWN_PROCESS,
                    win32service.SERVICE_AUTO_START, win32service.SERVICE_ERROR_NORMAL, command,
                    None, 0, dependencies, account, '', None)
            except win32service.error as exc:
                if exc.winerror != 1060:
                    raise
                handle = win32service.CreateService(scm, name, f'RDPMonitor {mode}',
                    win32service.SERVICE_ALL_ACCESS, win32service.SERVICE_WIN32_OWN_PROCESS,
                    win32service.SERVICE_AUTO_START, win32service.SERVICE_ERROR_NORMAL,
                    command, None, 0, dependencies, account, '')
            try:
                win32service.ChangeServiceConfig2(handle, win32service.SERVICE_CONFIG_SERVICE_SID_INFO,
                                                win32service.SERVICE_SID_TYPE_UNRESTRICTED)
                win32service.ChangeServiceConfig2(handle, win32service.SERVICE_CONFIG_FAILURE_ACTIONS,
                    {'ResetPeriod': 86400, 'RebootMsg': '', 'Command': '',
                     'Actions': [(win32service.SC_ACTION_RESTART, 15000),
                                 (win32service.SC_ACTION_RESTART, 60000)]})
            finally:
                win32service.CloseServiceHandle(handle)
    finally:
        win32service.CloseServiceHandle(scm)
