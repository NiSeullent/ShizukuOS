"""review-b12: actual guardian failure diagnostics and target policy-FD identity.

Host unit/boundary controls only (no QEMU, no VM, no COM2 evidence):
* record_actual_failure stores the FIRST real error (type, bounded detail,
  bounded traceback tail, stage/op marker, scalar post-grant facts) and a later
  cleanup error never overwrites it;
* assert_child_policy_fd stats the gated CHILD's own FD number against the
  sealed memfd identity: a correct inheritance passes, a different file at the
  same number and a missing FD both refuse.
"""
import fcntl
import os
from pathlib import Path
import subprocess
import sys
import types
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_original_epoch_generated_manifest as generated  # noqa: E402

g = generated.guardian
SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE


def bare_owner():
    owner = object.__new__(g.Owner)
    owner.record = {'VM_executed': False}
    owner.attempted = owner.target_released = False
    owner.process = owner.pidfd = None
    return owner


class ActualFailureRecord(unittest.TestCase):
    def raised(self, message):
        try:
            raise ValueError(message)
        except ValueError as error:
            return error

    def test_first_error_bounded_and_not_overwritten(self):
        owner = bare_owner(); owner.attempted = owner.target_released = True; owner.record['VM_executed'] = True
        server = types.SimpleNamespace(in_flight='epoch-monitor', sequence=7)
        nonce_hex = bytes(range(0x40, 0x60)).hex()
        grant = types.SimpleNamespace(grant_bytes_written=0, transport_calls=3, nonce=b'N' * 32,
                                      transport_failure={'schema': 'x', 'phase': 'READY', 'kind': 'surplus', 'frame_bytes_transferred': 48,
                                                         'frame_head_hex': '57444531010004003000000000000000' + nonce_hex,
                                                         'last_chunk_head_hex': nonce_hex, 'raw': b'x', 'segment_lengths': [16, 16, 'x'],
                                                         'pre_ready_console': {'bytes': 3, 'sha256': 'ab', 'head_hex': '1b5b30'}})
        owner.epoch_context = {'grant': grant}
        g.record_actual_failure(owner, self.raised('COM2 closed/surplus frame' + 'x' * 20000), 'controller-observation', server)
        r = owner.record
        self.assertEqual(r['error'], 'ValueError')
        self.assertTrue(r['error_detail'].startswith('COM2 closed/surplus frame'))
        self.assertLessEqual(len(r['error_detail'].encode()), g.FAILURE_DETAIL_BYTES)
        self.assertLessEqual(len(r['error_traceback'].encode()), g.FAILURE_TRACEBACK_BYTES)
        self.assertIn('ValueError', r['error_traceback'])
        self.assertEqual(r['error_stage']['stage'], 'controller-observation')
        self.assertEqual(r['error_stage']['rpc_op_in_flight'], 'epoch-monitor')
        self.assertTrue(r['error_stage']['VM_executed'])
        facts = r['epoch_exchange_failure']
        self.assertEqual(facts['transport_calls'], 3); self.assertNotIn('nonce', facts)
        tf = facts['transport_failure']
        self.assertEqual((tf['phase'], tf['kind'], tf['frame_bytes_transferred']), ('READY', 'surplus', 48))
        self.assertEqual(tf['frame_head_hex'], '57444531010004003000000000000000')
        self.assertNotIn('last_chunk_head_hex', tf); self.assertNotIn('raw', tf)
        self.assertNotIn(nonce_hex[:8], repr(r)); self.assertEqual(tf['segment_lengths'], [16, 16])
        self.assertEqual(tf['pre_ready_console'], {'bytes': 3, 'sha256': 'ab', 'head_hex': '1b5b30'})
        g.record_actual_failure(owner, RuntimeError('later cleanup'), 'cleanup', None)
        self.assertEqual(r['error'], 'ValueError'); self.assertTrue(r['error_detail'].startswith('COM2'))

    def test_no_grant_no_exchange_facts_and_no_vm_claim(self):
        owner = bare_owner()
        g.record_actual_failure(owner, self.raised('pre-launch refusal'), 'controller-preparation', None)
        self.assertNotIn('epoch_exchange_failure', owner.record)

    def test_error_attached_diagnostics_without_grant(self):
        owner = bare_owner(); error = self.raised('COM2 EOF before current READY (0 bytes received)')
        error.transport_diagnostics = {'phase': 'READY', 'kind': 'eof', 'frame_bytes_transferred': 0}
        g.record_actual_failure(owner, error, 'controller-observation', None)
        self.assertEqual(owner.record['epoch_exchange_failure'], {'transport_failure': {'phase': 'READY', 'kind': 'eof', 'frame_bytes_transferred': 0}})

    def test_no_grant_record_unchanged(self):
        owner = bare_owner()
        g.record_actual_failure(owner, self.raised('pre-launch refusal'), 'controller-preparation', None)
        self.assertNotIn('epoch_exchange_failure', owner.record)
        self.assertFalse(owner.record['error_stage']['VM_executed'])
        self.assertIsNone(owner.record['error_stage']['rpc_op_in_flight'])


class ChildPolicyFD(unittest.TestCase):
    def setUp(self):
        self.fd = os.memfd_create('shz-test-policy', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        os.write(self.fd, b'P' * 256); fcntl.fcntl(self.fd, fcntl.F_ADD_SEALS, SEALS)
        info = os.fstat(self.fd)
        self.attempt = types.SimpleNamespace(policy_fd=self.fd, policy_identity=(info.st_dev, info.st_ino, info.st_size), check=lambda: None)
        self.other = os.open(__file__, os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(os.close, self.fd); self.addCleanup(os.close, self.other)

    def child(self, pass_fds, preexec=None):
        process = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(30)'], pass_fds=pass_fds, preexec_fn=preexec)
        def clean():
            process.kill(); process.wait(5)
        self.addCleanup(clean)
        owner = bare_owner(); owner.process = process; owner.pidfd = os.pidfd_open(process.pid, 0)
        self.addCleanup(os.close, owner.pidfd)
        return owner

    def test_actual_inherited_sealed_memfd_passes(self):
        owner = self.child((self.fd,))
        owner.assert_child_policy_fd(self.attempt)
        self.assertTrue(owner.record['target_policy_fd_identity_verified_before_exec'])

    def test_different_file_at_same_number_refused(self):
        fd, other = self.fd, self.other
        owner = self.child((fd,), preexec=lambda: os.dup2(other, fd))
        with self.assertRaisesRegex(ValueError, 'inherited policy FD differs'):
            owner.assert_child_policy_fd(self.attempt)
        self.assertNotIn('target_policy_fd_identity_verified_before_exec', owner.record)

    def test_fd_not_inherited_refused(self):
        owner = self.child(())
        with self.assertRaises(FileNotFoundError):
            owner.assert_child_policy_fd(self.attempt)


if __name__ == '__main__':
    unittest.main()
