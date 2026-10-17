"""Real SCM account transitions; isolated, never-started service fixtures only."""
import ctypes
import os
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch
import uuid


@unittest.skipUnless(os.name == 'nt' and ctypes.windll.shell32.IsUserAnAdmin(),
                     'Requires elevated Windows SCM and protected Program Files fixtures')
class NativeServiceRegistrationTests(unittest.TestCase):
    def test_fresh_registration_and_repair_restore_the_gateway_virtual_account(self):
        import win32service
        from agent import service, setup

        identifier = 'RDPMonitorSvcTest' + uuid.uuid4().hex
        worker, gateway = identifier + 'Worker', identifier + 'Gateway'
        code = Path(os.environ['ProgramFiles']) / identifier
        data = Path(os.environ['ProgramData']) / identifier
        executable = code / 'RDPMonitorAgent.exe'
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)

        def configuration(name):
            handle = win32service.OpenService(scm, name, win32service.SERVICE_QUERY_CONFIG)
            try:
                return win32service.QueryServiceConfig(handle)
            finally:
                win32service.CloseServiceHandle(handle)

        try:
            # The product's display names are fixed. Never collide with an
            # installed deployment even though fixture service keys are unique.
            for _, display, _ in win32service.EnumServicesStatus(scm):
                if display in ('RDPMonitor worker', 'RDPMonitor gateway'):
                    self.skipTest('An installed RDPMonitor service owns the fixed display name')
            setup._protected_directory(code, code=True)
            setup._protected_directory(data)
            # A protected executable fixture, never launched. The real code/data
            # ACL verifier stays enabled; only the frozen-process identity and
            # service/data names are isolated from any installed deployment.
            shutil.copyfile(Path(os.environ['SystemRoot']) / 'System32' / 'cmd.exe', executable)
            setup._normalize_owner(code, recursive=True)
            with patch.object(service, 'WORKER', worker), patch.object(service, 'GATEWAY', gateway), \
                    patch.object(service, 'data_directory', return_value=data), \
                    patch.object(sys, 'executable', str(executable)):
                service.register_services(executable)
                fresh = configuration(gateway)
                self.assertEqual(fresh[7], 'NT SERVICE\\' + gateway)
                self.assertEqual(fresh[6], [worker])
                self.assertEqual(fresh[1], win32service.SERVICE_AUTO_START)

                # Exercise the existing-service branch with an actual account
                # transition, not a mock echo of the registration arguments.
                handle = win32service.OpenService(scm, gateway, win32service.SERVICE_CHANGE_CONFIG)
                try:
                    win32service.ChangeServiceConfig(handle, win32service.SERVICE_NO_CHANGE,
                        win32service.SERVICE_NO_CHANGE, win32service.SERVICE_NO_CHANGE,
                        None, None, 0, None, 'LocalSystem', '', None)
                finally:
                    win32service.CloseServiceHandle(handle)
                self.assertEqual(configuration(gateway)[7], 'LocalSystem')
                service.register_services(executable)
                repaired = configuration(gateway)
                self.assertEqual(repaired[7], 'NT SERVICE\\' + gateway)
                self.assertEqual(repaired[6], [worker])
        finally:
            try:
                for name in (gateway, worker):
                    try:
                        handle = win32service.OpenService(scm, name, win32service.SERVICE_ALL_ACCESS)
                    except win32service.error as error:
                        if error.winerror == 1060:
                            continue
                        raise
                    try:
                        # Neither fixture is started, so removal cannot stop a
                        # real process, interrupt jobs or touch installed data.
                        win32service.DeleteService(handle)
                    finally:
                        win32service.CloseServiceHandle(handle)
            finally:
                win32service.CloseServiceHandle(scm)
                for directory in (code, data):
                    if directory.exists():
                        shutil.rmtree(directory)


if __name__ == '__main__':
    unittest.main()
