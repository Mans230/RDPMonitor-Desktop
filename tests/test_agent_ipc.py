import os
import tempfile
import threading
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

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
