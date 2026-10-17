import os
import tempfile
import threading
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from agent.ipc import PipeServer, current_identity, pipe_call, protect_path


@unittest.skipUnless(os.name == 'nt', 'Windows named pipes are required')
class PipeIdentityTests(unittest.TestCase):
    def setUp(self):
        import pywintypes
        import win32pipe

        self.identity = current_identity()
        self.name = r'\\.\pipe\RDPMonitor.IdentityTest.' + uuid.uuid4().hex
        stop = threading.Event()
        failures = []

        def handler(request, peer):
            return {'sid': peer['sid'], 'admin': peer['admin']}

        server = PipeServer(self.name, handler, allowed_sids=[self.identity['sid']])

        def serve():
            try:
                server.serve(stop)
            except Exception as error:
                failures.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

        def cleanup():
            stop.set()
            thread.join(timeout=17)
            self.assertFalse(thread.is_alive(), 'The isolated pipe server did not stop')
            if failures:
                raise failures[0]

        self.addCleanup(cleanup)
        deadline = time.monotonic() + 5
        while True:
            try:
                win32pipe.WaitNamedPipe(self.name, 100)
                break
            except pywintypes.error:
                if failures:
                    raise failures[0]
                if time.monotonic() >= deadline:
                    self.fail('The isolated pipe server did not become ready')
                time.sleep(0.01)

    def test_peer_identity_comes_from_windows_not_request_claims(self):
        response = pipe_call(self.name, {'sid': 'S-1-0-0', 'admin': not self.identity['admin']},
                             expected_sid=self.identity['sid'])
        self.assertEqual(response['sid'], self.identity['sid'])
        self.assertNotEqual(response['sid'], 'S-1-0-0')
        self.assertEqual(response['admin'], self.identity['admin'])

    def test_simultaneous_clients_do_not_stall_the_accept_loop(self):
        def request(index):
            return pipe_call(self.name, {'request': index}, expected_sid=self.identity['sid'])

        with ThreadPoolExecutor(max_workers=6) as pool:
            responses = list(pool.map(request, range(24)))
        for response in responses:
            self.assertEqual(response['sid'], self.identity['sid'])
        after_contention = request(24)
        self.assertEqual(after_contention['sid'], self.identity['sid'])
        self.assertEqual(after_contention['admin'], self.identity['admin'])


@unittest.skipUnless(os.name == 'nt', 'Windows named pipes are required')
class PipeConnectionTests(unittest.TestCase):
    def test_instance_gap_after_contention_connects_without_replaying_rpc(self):
        import pywintypes
        import win32con
        import win32file
        import win32pipe

        identity = current_identity()
        name = r'\\.\pipe\RDPMonitor.InstanceGap.' + uuid.uuid4().hex
        old_server = win32pipe.CreateNamedPipe(name, win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
            1, 65536, 65536, 5000, None)
        old_client = win32file.CreateFile(name, win32con.GENERIC_READ | win32con.GENERIC_WRITE,
            0, None, win32con.OPEN_EXISTING, 0, None)
        stop = threading.Event()
        calls, errors, native_errors = [], [], []

        def handler(request, peer):
            calls.append(peer['sid'])
            return {'sid': peer['sid']}

        server = PipeServer(name, handler, allowed_sids=[identity['sid']])

        def serve():
            try:
                server.serve(stop)
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        original_wait = win32pipe.WaitNamedPipe
        switched = False
        started = False

        def transition(pipe, timeout):
            nonlocal switched, started
            if not switched:
                switched = True
                old_client.Close()
                old_server.Close()
                try:
                    return original_wait(pipe, timeout)
                except pywintypes.error as error:
                    # This is a real Windows no-instance result, not a fake
                    # transport response. Recreate the real server afterward.
                    native_errors.append(error.winerror)
                    self.assertEqual(error.winerror, 2)
                    thread.start()
                    started = True
                    raise
            return original_wait(pipe, timeout)

        try:
            with mock.patch.object(win32pipe, 'WaitNamedPipe', side_effect=transition):
                result = pipe_call(name, {'observe': True}, expected_sid=identity['sid'])
            self.assertEqual(result['sid'], identity['sid'])
            self.assertEqual(native_errors, [2])
            self.assertEqual(calls, [identity['sid']])
        finally:
            stop.set()
            if started:
                thread.join(timeout=17)
                self.assertFalse(thread.is_alive(), 'The replacement pipe server did not stop')
            if not switched:
                old_client.Close()
                old_server.Close()
            self.assertEqual(errors, [])


@unittest.skipUnless(os.name == 'nt', 'Windows ACLs are required')
class PathProtectionTests(unittest.TestCase):
    def test_worker_files_have_protected_admin_and_system_only_dacl(self):
        import win32security
        if not current_identity()['admin']:
            self.skipTest('Worker file protection requires elevation')
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'worker-state'
            path.write_bytes(b'isolated test state')
            protect_path(path)
            descriptor = win32security.GetNamedSecurityInfo(
                str(path), win32security.SE_FILE_OBJECT,
                win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION)
            control, _ = descriptor.GetSecurityDescriptorControl()
            self.assertTrue(control & win32security.SE_DACL_PROTECTED)
            acl = descriptor.GetSecurityDescriptorDacl()
            sids = {win32security.ConvertSidToStringSid(acl.GetAce(index)[2])
                    for index in range(acl.GetAceCount())}
            self.assertEqual(sids, {'S-1-5-18', 'S-1-5-32-544'})
            self.assertEqual(win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()), 'S-1-5-32-544')
            from agent.service import verify_protected_tree
            verify_protected_tree(path, recursive=False, ancestors=False)


if __name__ == '__main__':
    unittest.main()
