# SPDX-License-Identifier: GPL-2.0-only
"""Failure evidence regressions; only the external guest/QMP boundary is fake."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


user_boot = load_module('dos10_user_boot', HERE / 'test_user_boot.py')
qemu_tools = load_module('dos10_qemu_tools', HERE.parent / 'tools/qemu.py')


class GuestProcess:
    """Owned QEMU process boundary: snapshot operations require a live guest."""
    def __init__(self):
        self.alive = True
        self.returncode = None

    def poll(self):
        return self.returncode

    def wait(self, timeout):
        if self.alive:
            raise subprocess.TimeoutExpired('owned-qemu', timeout)
        return self.returncode

    def terminate(self):
        self.alive = False
        self.returncode = -15

    def kill(self):
        self.alive = False
        self.returncode = -9


class GuestQMP:
    def __init__(self, proc, memory, registers, failures=()):
        self.proc = proc
        self.memory = memory
        self.registers = registers
        self.failures = failures
        self.stopped = False

    def call(self, command, arguments=None):
        if not self.proc.alive:
            raise RuntimeError('Guest was already torn down')
        if command == 'stop':
            if 'stop' in self.failures:
                raise RuntimeError('Guest stop unavailable')
            self.stopped = True
            return {}
        if command == 'pmemsave':
            if not self.stopped:
                raise RuntimeError('Failure guest was not frozen before reading memory')
            address, size = arguments['val'], arguments['size']
            if address == 0 and 'memory' in self.failures:
                raise RuntimeError('Low memory capture unavailable')
            Path(arguments['filename']).write_bytes(self.memory[address:address + size])
            return {}
        if command == 'human-monitor-command':
            if not self.stopped:
                raise RuntimeError('Failure guest was not frozen before reading registers')
            if 'registers' in self.failures:
                raise RuntimeError('Register capture unavailable')
            if arguments['command-line'] != 'info registers':
                raise RuntimeError('Unexpected monitor command')
            return self.registers
        raise RuntimeError('Unexpected QMP command: ' + command)

    def hmp(self, command):
        return self.call('human-monitor-command', {'command-line': command})

    def close(self):
        if 'close' in self.failures:
            raise RuntimeError('QMP close failed')


class FailureEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='dos10-failure-test-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.output = self.directory / 'run'
        self.disk = self.directory / 'owned.img'
        self.disk.write_bytes(b'owned guest image')
        self.args = SimpleNamespace(qemu='fake-qemu', accel='tcg', firmware='bios',
                                    timeout=0.001, png=False)
        self.proc = GuestProcess()
        self.registers = 'EIP=00000102 EFL=00000202\nCS =1234 SS =2345 ESP=00008ffe\n'
        memory = bytearray(1 << 20)
        memory[0x18:0x1c] = b'\x02\x01\x34\x12'  # Hand-set interrupt 6 vector.
        memory[0x8ffe:0x9004] = b'\x02\x01\x34\x12\x02\x02'  # IP, CS, FLAGS.
        text = b'Invalid Opcode'
        memory[0xB8000:0xB8000 + len(text) * 2] = b''.join(bytes((c, 7)) for c in text)
        self.memory = bytes(memory)
        self.qmp = GuestQMP(self.proc, self.memory, self.registers)
        self.tools = SimpleNamespace(QMP=lambda *a, **k: self.qmp,
                                     read_guest_memory=qemu_tools.read_guest_memory,
                                     decode_text_page=qemu_tools.decode_text_page,
                                     cpu_state=qemu_tools.cpu_state)

    def launch(self, command, **kwargs):
        serial_arg = command[command.index('-serial') + 1]
        Path(serial_arg.removeprefix('file:')).write_bytes(b'SHZ-DOS10: STARTUP\r\nInvalid Opcode\r\n')
        return self.proc

    def run_startup_failure(self):
        with patch.object(user_boot.subprocess, 'Popen', self.launch):
            with self.assertRaises(ValueError) as raised:
                user_boot.boot(self.args, self.tools, self.disk, self.output, 'normal')
        self.assertEqual(str(raised.exception),
                         'Guest startup/input marker was not reached within the bounded timeout')
        self.assertFalse(self.proc.alive, 'The owned guest must still be cleaned up')
        result_path = self.output / 'result.json'
        self.assertTrue(result_path.is_file(), 'The failing run must retain its own result')
        result = json.loads(result_path.read_text())
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['error'], str(raised.exception))
        self.assertEqual(result['serial_text'], 'SHZ-DOS10: STARTUP\r\nInvalid Opcode\r\n')
        return result

    def test_startup_failure_saves_live_registers_vga_and_bounded_low_memory(self):
        result = self.run_startup_failure()
        self.assertEqual((self.output / 'failure-registers.txt').read_text(), self.registers)
        self.assertEqual((self.output / 'failure-screen.bin').read_bytes(), self.memory[0xB8000:0xB8000 + 4000])
        self.assertEqual((self.output / 'failure-screen.txt').read_text().splitlines()[0], 'Invalid Opcode')
        memory = (self.output / 'failure-memory-000000-0fffff.bin').read_bytes()
        self.assertEqual(len(memory), 1 << 20)
        self.assertEqual(memory[0x18:0x1c], b'\x02\x01\x34\x12')
        self.assertEqual(memory[0x8ffe:0x9004], b'\x02\x01\x34\x12\x02\x02')
        self.assertTrue(result['failure_snapshot']['qmp_available'])
        self.assertTrue(result['failure_snapshot']['guest_stopped'])
        self.assertEqual(result['failure_snapshot']['errors'], {})

    def test_partial_snapshot_still_saves_vga_and_preserves_startup_error(self):
        self.qmp.failures = {'registers', 'memory'}
        result = self.run_startup_failure()
        self.assertEqual((self.output / 'failure-screen.txt').read_text().splitlines()[0], 'Invalid Opcode')
        errors = result['failure_snapshot']['errors']
        self.assertIn('Register capture unavailable', errors['cpu_registers'])
        self.assertIn('Low memory capture unavailable', errors['low_memory'])

    def test_unavailable_qmp_retains_serial_and_original_connection_exception(self):
        original = RuntimeError('QMP socket never appeared: refused')
        def unavailable(*args, **kwargs):
            raise original
        self.tools.QMP = unavailable
        with patch.object(user_boot.subprocess, 'Popen', self.launch):
            with self.assertRaises(RuntimeError) as raised:
                user_boot.boot(self.args, self.tools, self.disk, self.output, 'normal')
        self.assertIs(raised.exception, original)
        self.assertFalse(self.proc.alive)
        result_path = self.output / 'result.json'
        self.assertTrue(result_path.is_file(), 'QMP connection failures must be recorded')
        result = json.loads(result_path.read_text())
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['error'], str(original))
        self.assertEqual(result['serial_text'], 'SHZ-DOS10: STARTUP\r\nInvalid Opcode\r\n')
        self.assertFalse(result['failure_snapshot']['qmp_available'])
        self.assertIn('unavailable', result['failure_snapshot']['errors']['qmp'].lower())

    def test_qmp_close_failure_does_not_mask_startup_error_or_skip_owned_cleanup(self):
        self.qmp.failures = {'close'}
        result = self.run_startup_failure()
        self.assertIn('QMP close failed', result['failure_snapshot']['errors']['cleanup'])


if __name__ == '__main__':
    unittest.main()
