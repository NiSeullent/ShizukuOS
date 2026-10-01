#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only: host-only injected guard boundaries.
import copy
import ast
from dataclasses import replace
import importlib.util
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

PATH = Path(__file__).resolve().parents[1] / 'tools/run_native_w64_negative_guarded.py'
SPEC = importlib.util.spec_from_file_location('native_guard_contract', PATH)
guard = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = guard
SPEC.loader.exec_module(guard)


def who(pid=101, start=200, ppid=1, session=101, argv=('python3',), state='S'):
    return guard.Identity(pid, start, ppid, session, state, argv, 4, 50)


def qemu_argv():
    qmp = 'unix:/tmp/shz-win98-uefi-fixture1/qmp.sock,server=on,wait=off'
    return [str(guard.QEMU), '-name', 'shz-disposable-win98-uefi', '-machine', 'q35,hpet=off', '-accel', 'kvm',
        '-cpu', 'qemu64', '-smp', '2', '-m', '128', '-nodefaults', '-nic', 'none', '-display', 'none',
        '-device', 'VGA', '-drive', f'if=pflash,unit=0,format=raw,readonly=on,file={guard.CODE}',
        '-drive', f'if=pflash,unit=1,format=raw,file={guard.RUN / "OVMF_VARS.fd"}',
        '-drive', f'file={guard.RUN / "windows-uefi.raw"},format=raw,if=none,id=win98',
        '-device', 'ide-hd,drive=win98,bus=ide.0,bootindex=1', '-serial', f'file:{guard.RUN / "serial.log"}',
        '-qmp', qmp, '-no-reboot']


def actual_capture_fixture(run, number=2, fallback=False):
    """Execute the pinned real capture() body with injected host-only QMP.

    Its filename, sidecar writes, screenshot fallback and returned digest are
    production behavior. RAM/register/QMP results are explicit host fixtures;
    no guest or repository runner main entry point is executed.
    """
    from PIL import Image
    source = Path(guard.EXPECTED_ARGV[2]).read_bytes()
    proposal = json.loads(guard.DEFAULT_PROPOSAL.read_text())
    if guard.hashlib.sha256(source).hexdigest() != proposal['held_source_pins'][guard.EXPECTED_ARGV[2]]:
        raise AssertionError('actual capture producer source pin drift')
    (run / 'runner-source.py').write_bytes(source)
    node = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'capture')
    namespace = {'struct': struct, 'sha256_file': guard.digest_file,
                 'capture_gop_handover': lambda *args: {'scope': 'injected host fixture'},
                 'capture_cpu0_code': lambda *args: None,
                 'capture_proxy_diagnostics': lambda *args: {'scope': 'injected host fixture'}}
    def read_memory(qmp, address, count, path):
        raw = b'\0' * count; path.write_bytes(raw); return raw
    namespace['qemu'] = SimpleNamespace(read_guest_memory=read_memory,
        decode_text_page=lambda raw: ['host fixture only'], cpu_state=lambda qmp: 'CPU#0\nEIP=0000106c EFL=00000202\n')
    calls = []
    class InjectedQmp:
        def call(self, command, arguments):
            if command != 'screendump': raise AssertionError(command)
            calls.append((command, arguments))
            if fallback and arguments.get('format') == 'png': raise RuntimeError('injected unsupported PNG')
            image = Image.new('RGB', (2, 1), (30, 31, 34))
            image.save(arguments['filename'], format='PNG' if arguments.get('format') == 'png' else 'PPM')
    exec(compile(ast.Module(body=[node], type_ignores=[]), guard.EXPECTED_ARGV[2], 'exec'), namespace)
    frame = namespace['capture'](InjectedQmp(), run, number, firmware_gop=True)
    return frame, calls


class GuardContracts(unittest.TestCase):
    def test_preserved_v8_profile_only_changes_fresh_run_and_bounded_times(self):
        old_path = guard.DEFAULT_PROPOSAL.with_name('native-launch-proposal-v7.json')
        old = json.loads(old_path.read_text())
        v8_path = guard.DEFAULT_PROPOSAL.with_name('native-launch-proposal-v8.json')
        proposal = json.loads(v8_path.read_text())
        self.assertEqual(guard.digest_file(old_path), '73124c8295bd3ddda730b19af1dd16179b0ad1da122c940963167f4bfaa85f0a')
        self.assertEqual(guard.digest_file(v8_path), '92bc97b2beadff899971300f69b9dff2bae6c57df2cc115c7e451663b9170847')
        self.assertEqual(old['guards']['wall_bound_seconds'], 1800)
        self.assertEqual(old['argv_for_root_guarded_launcher'][old['argv_for_root_guarded_launcher'].index('--timeout')+1], '900')
        permitted = copy.deepcopy(old)
        permitted['run'] = proposal['run']
        permitted['argv_for_root_guarded_launcher'][-1] = proposal['argv_for_root_guarded_launcher'][-1]
        permitted['argv_for_root_guarded_launcher'][permitted['argv_for_root_guarded_launcher'].index('--timeout')+1] = '1500'
        permitted['guards']['wall_bound_seconds'] = 2400
        self.assertEqual(proposal, permitted)  # pins, floors, no-NIC and controls stay exact
        with self.assertRaises(guard.GuardError): guard.validate_proposal(proposal)
        with self.assertRaises(guard.GuardError): guard.validate_proposal(old)

    def test_v9_profile_exact_derivation_and_unchanged_controls(self):
        old_path = guard.DEFAULT_PROPOSAL.with_name('native-launch-proposal-v8.json')
        old = json.loads(old_path.read_text())
        proposal = json.loads(guard.DEFAULT_PROPOSAL.read_text())
        self.assertEqual(guard.digest_file(old_path), '92bc97b2beadff899971300f69b9dff2bae6c57df2cc115c7e451663b9170847')
        self.assertEqual(guard.digest_file(guard.DEFAULT_PROPOSAL), guard.DEFAULT_PROPOSAL_SHA)
        permitted = copy.deepcopy(old)
        permitted['run'] = str(guard.RUN)
        permitted['argv_for_root_guarded_launcher'][2] = str(guard.RUNNER_ADAPTER)
        permitted['argv_for_root_guarded_launcher'][-1] = guard.RUN_NAME
        permitted['held_source_pins'][str(guard.RUNNER_ADAPTER)] = guard.RUNNER_ADAPTER_SHA
        self.assertEqual(proposal, permitted)
        original = guard.RUNNER_ORIGINAL.read_bytes()
        adapter = guard.RUNNER_ADAPTER.read_bytes()
        self.assertEqual(guard.hashlib.sha256(original).hexdigest(), guard.RUNNER_ORIGINAL_SHA)
        self.assertEqual(guard.hashlib.sha256(adapter).hexdigest(), guard.RUNNER_ADAPTER_SHA)
        self.assertEqual(adapter, guard.runner_adapter_bytes(original))
        self.assertIn(b'sha256_file(Path(__file__))', adapter)
        self.assertIn(b'shutil.copyfile(Path(__file__), source_copy)', adapter)
        self.assertIn(b'str(Path("/root/Win98-Modern-boot/shizukudos/tools"))', adapter)
        self.assertIn(b'str(Path("/root/Win98-Modern-boot/tools"))', adapter)
        self.assertIn(b'Path("/root/Win98-Modern-boot"))', adapter)
        self.assertIs(guard.validate_proposal(proposal), proposal)
        for seconds in ['900', '1499', '1501', 'unbounded']:
            broken = copy.deepcopy(proposal)
            broken['argv_for_root_guarded_launcher'][broken['argv_for_root_guarded_launcher'].index('--timeout')+1] = seconds
            with self.assertRaises(guard.GuardError): guard.validate_proposal(broken)
        for seconds in [1800, 2399, 2401, float('inf')]:
            broken = copy.deepcopy(proposal)
            broken['guards']['wall_bound_seconds'] = seconds
            with self.assertRaises(guard.GuardError): guard.validate_proposal(broken)
        with self.assertRaises(guard.GuardError): guard.validate_proposal(old)
        for path in (guard.RUNNER_ORIGINAL, guard.RUNNER_ADAPTER):
            broken = copy.deepcopy(proposal)
            broken['held_source_pins'][str(path)] = '0' * 64
            with self.assertRaises(guard.GuardError): guard.validate_proposal(broken)

    def test_actual_producer_cli_boundaries_and_old_900_failure(self):
        original = guard.RUNNER_ORIGINAL.read_bytes()
        adapter = guard.RUNNER_ADAPTER.read_bytes()
        argv = guard.EXPECTED_ARGV[3:]
        with self.assertRaisesRegex(guard.GuardError, '10..900 seconds'):
            guard.runner_cli_capability(original, argv)
        for seconds in ('10', '900', '1500'):
            candidate = list(argv); candidate[candidate.index('--timeout') + 1] = seconds
            result = guard.runner_cli_capability(adapter, candidate)
            self.assertEqual(result['timeout_seconds'], int(seconds))
            self.assertEqual(result['maximum_timeout_seconds'], 1500)
            self.assertFalse(result['producer_main_executed'])
            if seconds != '1500':
                self.assertEqual(guard.runner_cli_capability(original, candidate)['maximum_timeout_seconds'], 900)
        for option, value in (('--timeout', '9'), ('--timeout', '1501'), ('--timeout', 'inf'),
                              ('--smp', '1'), ('--smp', '9'), ('--memory', '63'), ('--memory', '513')):
            candidate = list(argv); candidate[candidate.index(option) + 1] = value
            with self.assertRaises(guard.GuardError): guard.runner_cli_capability(adapter, candidate)
        for source in (adapter.replace(b'parser.add_argument("--timeout", type=int', b'parser.add_argument("--timeout", type=float'),
                       adapter.replace(b'    args = parser.parse_args()', b'    subprocess.Popen(["must-never-run"])\n    args = parser.parse_args()'),
                       adapter.replace(b'not 10 <= args.timeout <= 1500:', b'not 10 <= args.timeout <= 999999:')):
            with mock.patch.object(guard.subprocess, 'Popen') as spawn:
                with self.assertRaises(guard.GuardError): guard.runner_cli_capability(source, argv)
                spawn.assert_not_called()

    def test_actual_cli_preflight_rejection_persists_before_any_spawn(self):
        proposal = json.loads(guard.DEFAULT_PROPOSAL.read_text())
        proposal['argv_for_root_guarded_launcher'][proposal['argv_for_root_guarded_launcher'].index('--timeout') + 1] = '1501'
        values = {str(guard.RUNNER_ORIGINAL): guard.RUNNER_ORIGINAL_SHA, str(guard.RUNNER_ADAPTER): guard.RUNNER_ADAPTER_SHA}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / 'receipt'; output.mkdir(); (output / 'requests').mkdir()
            with mock.patch.object(guard, 'capture_sources', return_value=values), mock.patch.object(guard, 'RUN', root / 'uncreated-run'):
                trial = guard.GuardedRun(proposal, guard.DEFAULT_PROPOSAL, guard.DEFAULT_PROPOSAL_SHA, output, True)
                with mock.patch.object(trial, 'check'), mock.patch.object(trial, 'own_run_lock') as runlock, \
                        mock.patch.object(trial, 'stop'), mock.patch.object(guard.subprocess, 'Popen') as spawn:
                    self.assertEqual(trial.run(), 1)
                spawn.assert_not_called(); runlock.assert_not_called()
                receipt = json.loads((output / 'guard-receipt.json').read_text())
                self.assertEqual(receipt['status'], 'FAIL')
                self.assertIn('10..1500 seconds', receipt['error'])
                self.assertTrue(all(v['matches'] for v in receipt['source_after'].values()))
                self.assertFalse(receipt['native_executed'])

    def test_source_drift_after_accepted_cli_is_rejected_before_spawn(self):
        proposal = json.loads(guard.DEFAULT_PROPOSAL.read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); adapter = root / 'runner.py'; adapter.write_bytes(guard.RUNNER_ADAPTER.read_bytes())
            output = root / 'receipt'; output.mkdir(); (output / 'requests').mkdir()
            proposal['argv_for_root_guarded_launcher'][2] = str(adapter)
            values = {str(guard.RUNNER_ORIGINAL): guard.RUNNER_ORIGINAL_SHA, str(adapter): guard.RUNNER_ADAPTER_SHA}
            with mock.patch.object(guard, 'capture_sources', return_value=values), mock.patch.object(guard, 'RUNNER_ADAPTER', adapter), \
                    mock.patch.object(guard, 'RUN', root / 'uncreated-run'):
                trial = guard.GuardedRun(proposal, guard.DEFAULT_PROPOSAL, guard.DEFAULT_PROPOSAL_SHA, output, True)
                def drift():
                    adapter.write_bytes(adapter.read_bytes().replace(b'not 10 <= args.timeout <= 1500:', b'not 10 <= args.timeout <= 900:'))
                with mock.patch.object(trial, 'check'), mock.patch.object(trial, 'own_run_lock', side_effect=drift), \
                        mock.patch.object(trial, 'stop'), mock.patch.object(guard.subprocess, 'Popen') as spawn:
                    self.assertEqual(trial.run(), 1)
                spawn.assert_not_called()
                receipt = json.loads((output / 'guard-receipt.json').read_text())
                self.assertEqual(receipt['status'], 'FAIL')
                self.assertEqual(receipt['runner_cli_capability']['status'], 'PINNED_PRODUCER_CLI_ACCEPTED_NOT_EXECUTED')
                self.assertNotIn('runner_cli_capability_before_exec', receipt)
                self.assertTrue(receipt['after_pin_failure'])
                self.assertFalse(receipt['source_after'][str(adapter)]['matches'])
                self.assertFalse(receipt['native_executed'])

    def test_actual_run_loop_stops_after_2400_not_prior_1800(self):
        proposal = json.loads(guard.DEFAULT_PROPOSAL.read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pin = root / 'immutable'
            pin.write_bytes(b'preserved-source')
            output = root / 'receipt'; output.mkdir(); (output / 'requests').mkdir()
            values = {str(pin): guard.digest_file(pin)}
            with mock.patch.object(guard, 'capture_sources', return_value=values), \
                    mock.patch.object(guard, 'RUN', root / 'uncreated-run'):
                trial = guard.GuardedRun(proposal, guard.DEFAULT_PROPOSAL, guard.DEFAULT_PROPOSAL_SHA, output, True)
                trial.started = 10
                # Real retained test-owned descriptor; no runner/QEMU is spawned.
                descriptor = os.open(os.devnull, os.O_RDONLY)
                runner = guard.OwnedProcess(who(), descriptor, 'runner')
                child = mock.Mock(); child.poll.return_value = None
                def stopped():
                    saved = json.loads((output / 'guard-receipt.json').read_text())
                    self.assertEqual(saved['status'], 'FAIL')
                    self.assertEqual(saved['error'], 'Frozen 2400-second wall bound expired')
                with mock.patch.object(trial, 'check'), mock.patch.object(trial, 'own_run_lock'), \
                        mock.patch.object(guard, 'validate_runner_capability', return_value={'scope': 'host wall-loop fixture'}), \
                        mock.patch.object(trial, 'discover_qemu'), mock.patch.object(trial, 'controls') as controls, \
                        mock.patch.object(trial, 'stop', side_effect=stopped) as stop, \
                        mock.patch.object(guard.subprocess, 'Popen', return_value=child) as spawn, \
                        mock.patch.object(guard, 'capture_spawn_candidate', return_value=runner), \
                        mock.patch.object(guard, 'await_spawn_identity', return_value=runner), \
                        mock.patch.object(guard, 'identity', return_value=runner.who), \
                        mock.patch.object(guard.time, 'monotonic', side_effect=[1811, 2410, 2410.001]), \
                        mock.patch.object(guard.time, 'sleep'):
                    self.assertEqual(trial.run(), 1)
                self.assertEqual(controls.call_count, 2)  # 1801s and exactly2400s both remain bounded live polls
                stop.assert_called_once()
                child.wait.assert_not_called()
                argv = spawn.call_args.args[0]
                self.assertEqual(argv[argv.index('--timeout') + 1], '1500')
                receipt = json.loads((output / 'guard-receipt.json').read_text())
                self.assertTrue(receipt['source_after'][str(pin)]['matches'])
                self.assertFalse(receipt['native_executed'])
                with self.assertRaises(OSError): os.fstat(descriptor)

    def test_proposal_exact_and_mutations(self):
        proposal = json.loads(guard.DEFAULT_PROPOSAL.read_text())
        self.assertIs(guard.validate_proposal(proposal), proposal)
        for index in range(len(guard.EXPECTED_ARGV)):
            broken = copy.deepcopy(proposal)
            broken['argv_for_root_guarded_launcher'][index] += '-foreign'
            with self.assertRaises(guard.GuardError):
                guard.validate_proposal(broken)
        for key in ['disk_floor_bytes', 'minimum_before_clone_bytes', 'minimum_host_mem_available_bytes',
                    'wall_bound_seconds', 'poll_seconds', 'actual_guest_memory_mib']:
            broken = copy.deepcopy(proposal)
            broken['guards'][key] -= 1
            with self.assertRaises(guard.GuardError):
                guard.validate_proposal(broken)
        for key in ['native_executed', 'application_executed']:
            broken = copy.deepcopy(proposal)
            broken[key] = True
            with self.assertRaises(guard.GuardError):
                guard.validate_proposal(broken)
        for index in range(5):
            broken = copy.deepcopy(proposal)
            broken['gui_control_proposal'][index]['foreign'] = True
            with self.assertRaises(guard.GuardError):
                guard.validate_proposal(broken)

    def test_actual_qemu_argv_exact_and_mutations(self):
        argv = qemu_argv()
        self.assertTrue(guard.validate_qemu_argv(argv))
        self.assertTrue(guard.exact_owned_disk(argv))
        for index in range(len(argv)):
            bad = argv.copy()
            bad[index] += '-foreign'
            with self.assertRaises(guard.GuardError):
                guard.validate_qemu_argv(bad)
        for extra in ['-snapshot', '-net', '-cdrom']:
            with self.assertRaises(guard.GuardError):
                guard.validate_qemu_argv(argv + [extra])
        bad = argv.copy()
        bad[25] = 'file=' + str(guard.SOURCE_RUN / 'windows-uefi.raw') + ',format=raw,if=none,id=win98'
        self.assertFalse(guard.exact_owned_disk(bad))

    def test_pid_identity_reuse_and_exit_races(self):
        original = who()
        process = guard.OwnedProcess(original, 77, 'runner')
        sender = mock.Mock()
        self.assertEqual(guard.signal_owned(process, signal.SIGTERM, lambda _: original, sender), 'sent')
        sender.assert_called_once_with(77, signal.SIGTERM, None, 0)
        for altered in [replace(original, start=201), replace(original, exe_inode=51), replace(original, argv=('foreign',)),
                        replace(original, session=88)]:
            sender.reset_mock()
            with self.assertRaises(guard.GuardError):
                guard.signal_owned(process, signal.SIGTERM, lambda _: altered, sender)
            sender.assert_not_called()
        sender.reset_mock()
        self.assertEqual(guard.signal_owned(process, signal.SIGTERM, lambda _: None, sender), 'already-gone')
        self.assertEqual(guard.signal_owned(process, signal.SIGTERM, lambda _: replace(original, state='Z'), sender), 'already-gone')
        sender.assert_not_called()
        sender.side_effect = ProcessLookupError()
        self.assertEqual(guard.signal_owned(process, signal.SIGTERM, lambda _: original, sender), 'already-gone')
        # Legitimate orphan keeps retained ownership, while PID reuse never does.
        sender.side_effect = None
        self.assertEqual(guard.signal_owned(process, signal.SIGTERM, lambda _: replace(original, ppid=1), sender), 'sent')

    def test_qemu_stop_requires_owned_raw(self):
        original = who(argv=tuple(qemu_argv()))
        sender = mock.Mock()
        self.assertEqual(guard.signal_owned(guard.OwnedProcess(original, 88, 'qemu'), signal.SIGTERM, lambda _: original, sender), 'sent')
        argv = qemu_argv()
        argv[25] = 'file=/foreign.raw,format=raw,if=none,id=win98'
        foreign = replace(original, argv=tuple(argv))
        sender.reset_mock()
        with self.assertRaises(guard.GuardError):
            guard.signal_owned(guard.OwnedProcess(foreign, 88, 'qemu'), signal.SIGTERM, lambda _: foreign, sender)
        sender.assert_not_called()

    def test_descendant_requires_exact_parent_start_and_session(self):
        parent = who(101, 200, 99, 101)
        child = who(102, 201, 101, 101)
        grandchild = who(103, 202, 102, 101)
        table = {101: parent, 102: child, 103: grandchild}
        self.assertTrue(guard.descendant(103, parent, table.get))
        table[101] = replace(parent, start=999)
        self.assertFalse(guard.descendant(103, parent, table.get))
        table[101] = parent
        table[102] = replace(child, session=102)
        self.assertFalse(guard.descendant(103, parent, table.get))

    def test_proc_stat_parentheses_and_start_field(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            entry = proc / '123'
            entry.mkdir()
            (entry / 'stat').write_text('123 (name with ) close) ' + ' '.join(['S', '9', '123', '123'] + ['0'] * 15 + ['4321'] + ['0'] * 8))
            (entry / 'exe').symlink_to(sys.executable)
            (entry / 'cmdline').write_bytes(b'python3\0-u\0fixture\0')
            actual = guard.identity(123, proc)
            self.assertEqual((actual.pid, actual.ppid, actual.session, actual.start), (123, 9, 123, 4321))
            self.assertEqual(actual.argv, ('python3', '-u', 'fixture'))
            self.assertIsNone(guard.identity(124, proc))

    def test_shared_pin_hash_inode_drift_and_exclusive_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'pin'
            path.write_bytes(b'original')
            pins = guard.Pins({str(path): guard.digest_file(path)})
            self.assertEqual(pins.open(), [])
            self.assertTrue(pins.snapshot()[str(path)]['matches'])
            path.write_bytes(b'mutated!')
            self.assertFalse(pins.snapshot()[str(path)]['matches'])
            with self.assertRaises(guard.GuardError):
                pins.unchanged_metadata()
            pins.close()
            pins = guard.Pins({str(path): guard.digest_file(path)})
            fd = os.open(path, os.O_RDONLY)
            guard.fcntl.flock(fd, guard.fcntl.LOCK_EX | guard.fcntl.LOCK_NB)
            self.assertEqual(len(pins.open()), 1)
            self.assertEqual(pins.held, {})
            os.close(fd)
            path.unlink()
            path.symlink_to(sys.executable)
            self.assertEqual(len(pins.open()), 1)

    def test_source_holder_foreign_inode_and_owned_descendant(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.write_bytes(b'fixture')
            info = source.stat()
            wrapper, runner, foreign = who(101), who(102, 201, 101, 102), who(103, 202, 1, 103)
            child = who(104, 203, 102, 102)
            table = {101: wrapper, 102: runner, 103: foreign, 104: child}
            for pid in table:
                (root / str(pid) / 'fd').mkdir(parents=True)
                (root / str(pid) / 'fd' / '8').symlink_to(source)
                (root / str(pid) / 'fdinfo').mkdir()
                flags = os.O_RDWR if pid == foreign.pid else os.O_RDONLY
                (root / str(pid) / 'fdinfo' / '8').write_text(f'flags:\t{flags:o}\nmnt_id:\t1\nino:\t{info.st_ino}\n')
            holders = guard.source_foreign_holders(info.st_dev, info.st_ino, wrapper, runner, root, table.get)
            self.assertEqual([p['pid'] for p in holders], [103])
            holders = guard.source_foreign_holders(info.st_dev, info.st_ino, wrapper, None, root, table.get)
            self.assertEqual([p['pid'] for p in holders], [103])

    def test_foreign_readonly_fdinfo_allowed_but_vm_and_writers_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'; source.write_bytes(b'cold source fixture')
            info = source.stat(); wrapper = who(101); foreign = who(102,201,1,102)
            entry = root / '102'; (entry/'fd').mkdir(parents=True); (entry/'fdinfo').mkdir()
            (entry/'fd'/'7').symlink_to(source)
            fdinfo = entry/'fdinfo'/'7'
            def write_flags(flags):
                fdinfo.write_text(f'pos:\t0\nflags:\t{flags:o}\nmnt_id:\t1\nino:\t{info.st_ino}\n')
            for flags in [os.O_RDONLY, os.O_RDONLY | os.O_CLOEXEC | os.O_LARGEFILE]:
                write_flags(flags); audit=[]
                self.assertEqual(guard.source_foreign_holders(info.st_dev,info.st_ino,wrapper,None,root,
                                 lambda pid: foreign,audit=audit),[])
                self.assertTrue(audit[0]['stable_double_read'])
                self.assertTrue(audit[0]['read_only'])
                self.assertEqual(audit[0]['flags'],flags)
                self.assertNotIn('argv',audit[0])
            for flags in [os.O_WRONLY,os.O_RDWR,os.O_ACCMODE,getattr(os,'O_PATH',0)]:
                write_flags(flags)
                rejected=guard.source_foreign_holders(info.st_dev,info.st_ino,wrapper,None,root,lambda pid: foreign)
                self.assertEqual(len(rejected),1)
                self.assertFalse(rejected[0]['allowed'])
            write_flags(os.O_RDONLY)
            for name in ['/usr/libexec/qemu-kvm','qemu-system-x86_64','VBoxHeadless','vmware-vmx']:
                vm=replace(foreign,argv=(name,'-drive','immutable-source'))
                rejected=guard.source_foreign_holders(info.st_dev,info.st_ino,wrapper,None,root,lambda pid: vm)
                self.assertTrue(rejected[0]['live_vm'])
                # Being a descendant cannot permit a VM to open the base inode.
                rejected=guard.source_foreign_holders(info.st_dev,info.st_ino,wrapper,vm,root,lambda pid: vm)
                self.assertTrue(rejected[0]['live_vm'])
            executable=guard.QEMU.stat()
            vm=replace(foreign,argv=('hidden-alias',),exe_device=executable.st_dev,exe_inode=executable.st_ino)
            rejected=guard.source_foreign_holders(info.st_dev,info.st_ino,wrapper,None,root,lambda pid: vm)
            self.assertTrue(rejected[0]['live_vm'])

    def test_source_fdinfo_missing_invalid_or_changed_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'source';source.write_bytes(b'fixture');info=source.stat()
            entry=root/'102';(entry/'fd').mkdir(parents=True);(entry/'fdinfo').mkdir()
            (entry/'fd'/'7').symlink_to(source);fdinfo=entry/'fdinfo'/'7'
            wrapper=who(101);foreign=who(102,201,1,102)
            invalid=['',f'flags: 9\nmnt_id: 1\nino: {info.st_ino}\n',
                     f'flags: 0\nflags: 0\nmnt_id: 1\nino: {info.st_ino}\n',
                     f'flags: 0\nmnt_id: 1\nino: {info.st_ino+1}\n',f'flags: 0\nino: {info.st_ino}\n']
            for text in invalid:
                fdinfo.write_text(text)
                rejected=guard.source_foreign_holders(info.st_dev,info.st_ino,wrapper,None,root,lambda pid: foreign)
                self.assertEqual(len(rejected),1);self.assertFalse(rejected[0]['allowed'])
            fdinfo.unlink()
            self.assertEqual(len(guard.source_foreign_holders(info.st_dev,info.st_ino,wrapper,None,root,lambda pid: foreign)),1)
            fdinfo.write_text(f'flags: 0\nmnt_id: 1\nino: {info.st_ino}\n')
            original=guard.source_fd_observation(entry/'fd'/'7',fdinfo)
            for changed in [original|{'inode':info.st_ino+1},original|{'flags':os.O_RDWR},
                            original|{'mtime_ns':original['mtime_ns']+1}]:
                with mock.patch.object(guard,'source_fd_observation',side_effect=[original,changed]):
                    rejected=guard.source_foreign_holders(info.st_dev,info.st_ino,wrapper,None,root,lambda pid: foreign)
                self.assertEqual(len(rejected),1)
                self.assertIn('changed',rejected[0]['reason'])
            values=iter([foreign,foreign,replace(foreign,start=foreign.start+1)])
            rejected=guard.source_foreign_holders(info.st_dev,info.st_ino,wrapper,None,root,lambda pid: next(values))
            self.assertEqual(len(rejected),1);self.assertIn('changed',rejected[0]['reason'])

    def test_real_proc_readonly_copy_descriptor_and_writable_descriptor(self):
        # Real /proc fdinfo and an independent bounded Python reader. No VM,
        # repository disk, native script or shared-source modification occurs.
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'source';source.write_bytes(b'cold source fixture');info=source.stat()
            for mode,expected in [('rb',0),('r+b',1)]:
                code='import sys; f=open(sys.argv[1],sys.argv[2]); print("ready",flush=True); sys.stdin.readline()'
                child=subprocess.Popen([sys.executable,'-u','-c',code,str(source),mode],stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE,start_new_session=True,text=True)
                try:
                    self.assertEqual(child.stdout.readline().strip(),'ready');audit=[]
                    rejected=guard.source_foreign_holders(info.st_dev,info.st_ino,guard.identity(os.getpid()),audit=audit)
                    self.assertEqual(len(rejected),expected)
                    actual=[r for r in audit if r['pid']==child.pid]
                    self.assertEqual(len(actual),1);self.assertTrue(actual[0]['stable_double_read'])
                    self.assertEqual(actual[0]['read_only'],not expected)
                    child.stdin.write('\n');child.stdin.flush();self.assertEqual(child.wait(timeout=5),0)
                finally:
                    if child.poll() is None: child.terminate();child.wait(timeout=5)
                    child.stdin.close();child.stdout.close()

    def test_resource_before_and_during_floors(self):
        guard.resource_guard(guard.BEFORE_FLOOR, guard.MEM_FLOOR, True)
        guard.resource_guard(guard.FLOOR, guard.MEM_FLOOR, False)
        for free, memory, before in [(guard.BEFORE_FLOOR - 1, guard.MEM_FLOOR, True),
                                     (guard.FLOOR - 1, guard.MEM_FLOOR, False),
                                     (guard.BEFORE_FLOOR, guard.MEM_FLOOR - 1, True),
                                     (guard.FLOOR, guard.MEM_FLOOR - 1, False)]:
            with self.assertRaises(guard.GuardError):
                guard.resource_guard(free, memory, before)

    def test_controls_require_prior_receipt_review_and_observer_bound(self):
        proposal = json.loads(guard.DEFAULT_PROPOSAL.read_text())
        frame = guard.RUN / 'screen-001.png'
        prior = {'sequence': 1, 'status': 'sent; application effect requires review', 'screenshot': str(frame)}
        self.assertEqual(guard.validate_control(2, proposal, prior, frame, None)['keys'], [['meta_l','r']])
        self.assertEqual(guard.validate_control(2, proposal, prior, guard.RUN / 'screen-035.png', None)['keys'], [['meta_l','r']])
        for bad in [None, prior | {'sequence': True}, prior | {'sequence': 2}, prior | {'status': 'FAIL'}]:
            with self.assertRaises(guard.GuardError):
                guard.validate_control(2, proposal, bad, frame, None)
        with self.assertRaises(guard.GuardError):
            guard.validate_control(2, proposal, prior, guard.RUN / 'foreign.png', None)
        with self.assertRaises(guard.GuardError):
            guard.validate_control(2, proposal, prior, guard.RUN / 'screen-000.png', None)
        prior['sequence'] = 2
        self.assertEqual(guard.validate_control(3, proposal, prior, frame, None)['text'],'C:\\VXDLAB\\W64OUT.EXE')
        prior['sequence'] = 3
        for age in [None, 49.99]:
            with self.assertRaises(guard.GuardError):
                guard.validate_control(4, proposal, prior, frame, age)
        self.assertTrue(guard.validate_control(4, proposal, prior, frame, 50)['capture'])
        with self.assertRaises(guard.GuardError):
            guard.validate_control(4, proposal, prior, guard.RUN / 'screen-035.png', 50)
        prior['sequence']=4
        self.assertTrue(guard.validate_control(5,proposal,prior,frame,50)['finish'])
        for bad in [0,6,True]:
            with self.assertRaises(guard.GuardError): guard.validate_control(bad,proposal,prior,frame,50)

    def test_atomic_new_requests_never_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'request.json'
            guard.atomic_json(path, {'sequence': 1}, new=True)
            with self.assertRaises(FileExistsError):
                guard.atomic_json(path, {'sequence': 2}, new=True)
            self.assertEqual(json.loads(path.read_text()), {'sequence': 1})
            self.assertEqual(len(list(Path(directory).iterdir())), 1)

    def test_reviewed_screenshot_rejects_dotdot_and_symlink_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / 'owned'
            run.mkdir()
            outside = root / 'other'
            outside.mkdir()
            (run / 'capture-001.png').write_bytes(b'actual screenshot fixture')
            (outside / 'capture-002.png').write_bytes(b'outside fixture')
            self.assertEqual(guard.verified_screenshot(run / 'capture-001.png', run), run / 'capture-001.png')
            (run / 'alias').symlink_to(outside, target_is_directory=True)
            for path in [run / '..' / 'other' / 'capture-002.png', run / 'alias' / 'capture-002.png']:
                with self.assertRaises(guard.GuardError):
                    guard.verified_screenshot(path, run)

    def test_actual_pinned_capture_producer_png_and_ppm_consumed(self):
        proposal=json.loads(guard.DEFAULT_PROPOSAL.read_text())
        for fallback in [False,True]:
            with tempfile.TemporaryDirectory() as directory:
                run=Path(directory).resolve()
                frame,calls=actual_capture_fixture(run,fallback=fallback)
                screenshot=Path(frame['screenshot'])
                self.assertEqual(screenshot.name,'screen-002.ppm' if fallback else 'screen-002.png')
                self.assertEqual(frame['screenshot_status'],'captured')
                evidence=guard.verified_capture_evidence(screenshot,proposal,run)
                self.assertEqual(evidence['screenshot_sha256'],frame['sha256'])
                self.assertEqual(evidence['dimensions'],(2,1))
                self.assertEqual(len(evidence['actual_producer_sidecars']),3)
                self.assertEqual(len(calls),2 if fallback else 1)
                self.assertFalse(evidence['visual_scene_verified_by_guard'])

    def test_actual_producer_first_request_forwarded_atomically(self):
        proposal=json.loads(guard.DEFAULT_PROPOSAL.read_text())
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();run=root/'owned';run.mkdir();output=root/'receipt';output.mkdir();(output/'requests').mkdir()
            frame,_=actual_capture_fixture(run)
            wrapper=guard.identity(os.getpid());qemu=who(818,900,wrapper.pid,818,tuple(qemu_argv()))
            with mock.patch.object(guard,'RUN',run):
                trial=guard.GuardedRun(proposal,guard.DEFAULT_PROPOSAL,guard.DEFAULT_PROPOSAL_SHA,output,True)
                trial.qemu=guard.OwnedProcess(qemu,901,'qemu');trial.record['actual_qemu_argv_verified']=True
                incoming={'sequence':1,'proposal_sha256':guard.DEFAULT_PROPOSAL_SHA,'wrapper_start':wrapper.start,
                          'reviewed_screenshot':frame['screenshot'],'reviewed_screenshot_sha256':frame['sha256'],
                          'visual_review_explicit':True}
                guard.atomic_json(output/'requests/0001.json',incoming,new=True)
                real=guard.verified_capture_evidence;real_screenshot=guard.verified_screenshot
                with mock.patch.object(guard,'identity',return_value=qemu),mock.patch.object(guard,'validate_qemu_argv') as argv_check,\
                     mock.patch.object(guard,'verified_screenshot',side_effect=lambda path,r=run:real_screenshot(path,r)),\
                     mock.patch.object(guard,'verified_capture_evidence',side_effect=lambda p,j:real(p,j,run)):
                    trial.controls()
                argv_check.assert_called_once_with(qemu.argv)
                self.assertEqual(json.loads((run/'gui-control.json').read_text()),guard.EXPECTED_CONTROLS[0])
                self.assertEqual(trial.sent_sequence,1);self.assertEqual(trial.last_sequence,0)
                self.assertEqual(trial.record['controls'][0]['phase'],'forwarded')
                self.assertEqual(trial.record['controls'][0]['actual_capture_evidence']['screenshot_sha256'],frame['sha256'])
                self.assertEqual(list(run.glob('.gui-control.json.*')),[])

    def test_capture_actual_data_and_provider_provenance_rejects_mutations(self):
        proposal=json.loads(guard.DEFAULT_PROPOSAL.read_text())
        with tempfile.TemporaryDirectory() as directory:
            run=Path(directory).resolve();frame,_=actual_capture_fixture(run);screenshot=Path(frame['screenshot'])
            for name,bad in [('runner-source.py',b'foreign producer'),('screen-002-vga.bin',b'incomplete'),
                             ('screen-002-registers.txt',b'not actual registers'),('screen-002.png',b'not an image')]:
                path=run/name;original=path.read_bytes();path.write_bytes(bad)
                with self.assertRaises((guard.GuardError,OSError)):guard.verified_capture_evidence(screenshot,proposal,run)
                path.write_bytes(original)
            renamed=run/'capture-002.png';renamed.write_bytes(screenshot.read_bytes())
            with self.assertRaises(guard.GuardError):guard.verified_capture_evidence(renamed,proposal,run)
            renamed=run/'screen-0002.png';renamed.write_bytes(screenshot.read_bytes())
            with self.assertRaises(guard.GuardError):guard.verified_capture_evidence(renamed,proposal,run)
            alias=run/'screen-003.png';alias.symlink_to(screenshot)
            with self.assertRaises(guard.GuardError):guard.verified_capture_evidence(alias,proposal,run)
            outside=run/'other';outside.mkdir();external=outside/'screen-002-vga.bin';external.write_bytes(b'\0'*4000)
            vga=run/'screen-002-vga.bin';vga.unlink();vga.symlink_to(external)
            with self.assertRaises(guard.GuardError):guard.verified_capture_evidence(screenshot,proposal,run)

    def later_capture_trial(self, root, sequence, prior_number, reviewed_number):
        run=root/'owned';run.mkdir();output=root/'receipt';output.mkdir();(output/'requests').mkdir()
        prior_frame,_=actual_capture_fixture(run,prior_number)
        frame,_=actual_capture_fixture(run,reviewed_number)
        proposal=json.loads(guard.DEFAULT_PROPOSAL.read_text())
        trial=guard.GuardedRun(proposal,guard.DEFAULT_PROPOSAL,guard.DEFAULT_PROPOSAL_SHA,output,True)
        qemu=who(818,900,trial.wrapper.pid,818,tuple(qemu_argv()))
        trial.qemu=guard.OwnedProcess(qemu,901,'qemu')
        trial.record.update(status='RUNNING_REQUIRES_ROOT_VISUAL_CONTROL',actual_qemu_argv_verified=True)
        trial.last_sequence=sequence-2;trial.sent_sequence=sequence-1
        trial.last_reviewed_capture_number=prior_number-1
        prior={'name':guard.EXPECTED_CONTROLS[sequence-2]['name'],'sequence':sequence-1,
               'status':'sent; application effect requires screenshot/readback verification',
               'screenshot':prior_frame['screenshot']}
        guard.atomic_json(run/'gui-control-receipt.json',prior)
        trial.save()
        return run,output,trial,qemu,frame,prior

    def test_later_actual_automatic_capture_controls_link_prior_receipt_and_forward(self):
        # Actual producer filenames reproduce the real immediate-DOS/latest-desktop
        # and immediate-welcome/latest-Run transitions without asserting GUI content.
        for sequence,prior_number,reviewed_number in [(2,15,35),(3,40,43)]:
            with self.subTest(sequence=sequence),tempfile.TemporaryDirectory() as directory:
                root=Path(directory).resolve()
                run,output,trial,qemu,frame,prior=self.later_capture_trial(root,sequence,prior_number,reviewed_number)
                real=guard.verified_capture_evidence;real_screenshot=guard.verified_screenshot
                with mock.patch.object(guard,'RUN',run),\
                     mock.patch.object(guard,'identity',side_effect=lambda pid:trial.wrapper if pid==trial.wrapper.pid else qemu),\
                     mock.patch.object(guard,'validate_qemu_argv'),\
                     mock.patch.object(guard,'verified_screenshot',side_effect=lambda p,r=run:real_screenshot(p,r)),\
                     mock.patch.object(guard,'verified_capture_evidence',side_effect=lambda p,j:real(p,j,run)):
                    guard.submit_control(output,sequence,Path(frame['screenshot']))
                    queued=json.loads((output/'requests'/f'{sequence:04d}.json').read_text())
                    self.assertEqual(queued['prior_receipt_sequence'],sequence-1)
                    self.assertEqual(queued['prior_receipt_sha256'],guard.digest_file(run/'gui-control-receipt.json'))
                    trial.controls()
                self.assertEqual(json.loads((run/'gui-control.json').read_text()),guard.EXPECTED_CONTROLS[sequence-1])
                self.assertEqual(trial.last_sequence,sequence-1);self.assertEqual(trial.sent_sequence,sequence)
                self.assertEqual(trial.last_reviewed_capture_number,reviewed_number)
                self.assertEqual(trial.record['controls'][-1]['actual_capture_evidence']['capture_number'],reviewed_number)
                self.assertFalse(trial.record['controls'][-1]['actual_capture_evidence']['visual_scene_verified_by_guard'])
                self.assertEqual(list(run.glob('.gui-control.json.*')),[])

    def test_later_capture_stale_and_changed_prior_receipt_never_forward(self):
        for failure in ['predates-prior','reuses-review','changed-prior','wrong-sequence','missing-link']:
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as directory:
                root=Path(directory).resolve()
                number=14 if failure=='predates-prior' else 35
                run,output,trial,qemu,frame,prior=self.later_capture_trial(root,2,15,number)
                real=guard.verified_capture_evidence;real_screenshot=guard.verified_screenshot
                with mock.patch.object(guard,'RUN',run),\
                     mock.patch.object(guard,'identity',side_effect=lambda pid:trial.wrapper if pid==trial.wrapper.pid else qemu),\
                     mock.patch.object(guard,'validate_qemu_argv'),\
                     mock.patch.object(guard,'verified_screenshot',side_effect=lambda p,r=run:real_screenshot(p,r)),\
                     mock.patch.object(guard,'verified_capture_evidence',side_effect=lambda p,j:real(p,j,run)):
                    guard.submit_control(output,2,Path(frame['screenshot']))
                    if failure=='reuses-review':trial.last_reviewed_capture_number=35
                    if failure=='changed-prior':guard.atomic_json(run/'gui-control-receipt.json',prior|{'utc':'changed'})
                    if failure in ['wrong-sequence','missing-link']:
                        path=output/'requests/0002.json';queued=json.loads(path.read_text())
                        if failure=='wrong-sequence':queued['prior_receipt_sequence']=2
                        else:queued.pop('prior_receipt_sha256')
                        guard.atomic_json(path,queued)
                    with self.assertRaises(guard.GuardError):trial.controls()
                self.assertFalse((run/'gui-control.json').exists())
                self.assertEqual(trial.sent_sequence,1)

    def test_control_submit_requires_actual_prior_success_before_atomic_inbox(self):
        for prior in [None,{'sequence':True,'status':'sent;'},{'sequence':2,'status':'sent;'},
                      {'sequence':1,'status':'FAIL'}]:
            with self.subTest(prior=prior),tempfile.TemporaryDirectory() as directory:
                root=Path(directory).resolve();run=root/'owned';run.mkdir();output=root/'receipt';output.mkdir();(output/'requests').mkdir()
                frame,_=actual_capture_fixture(run)
                wrapper=guard.identity(os.getpid())
                guard.atomic_json(output/'guard-receipt.json',{'status':'RUNNING_REQUIRES_ROOT_VISUAL_CONTROL',
                    'actual_qemu_argv_verified':True,'wrapper':guard.asdict(wrapper),'proposal_sha256':guard.DEFAULT_PROPOSAL_SHA})
                if prior is not None:guard.atomic_json(run/'gui-control-receipt.json',prior)
                real=guard.verified_screenshot
                with mock.patch.object(guard,'RUN',run),mock.patch.object(guard,'verified_screenshot',side_effect=lambda p:real(p,run)):
                    with self.assertRaises(guard.GuardError):guard.submit_control(output,2,Path(frame['screenshot']))
                self.assertEqual(list((output/'requests').iterdir()),[])

    def test_guard_failure_receipt_precedes_stop_and_keeps_before_after(self):
        proposal = json.loads(guard.DEFAULT_PROPOSAL.read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pin = root / 'immutable'
            pin.write_bytes(b'preserved-source')
            output = root / 'receipt'
            output.mkdir()
            (output / 'requests').mkdir()
            values = {str(pin): guard.digest_file(pin)}
            with mock.patch.object(guard, 'capture_sources', return_value=values), mock.patch.object(guard, 'RUN', root / 'uncreated-run'):
                trial = guard.GuardedRun(proposal, guard.DEFAULT_PROPOSAL, guard.DEFAULT_PROPOSAL_SHA, output, True)
                def stopped():
                    observed = json.loads((output / 'guard-receipt.json').read_text())
                    self.assertEqual(observed['status'], 'FAIL')
                    self.assertTrue(observed['source_before'][str(pin)]['matches'])
                    self.assertIsNone(trial.runner)
                    self.assertIsNone(trial.qemu)
                with mock.patch.object(trial, 'check', side_effect=guard.GuardError('injected resource failure')), \
                        mock.patch.object(trial, 'stop', side_effect=stopped) as stop, \
                        mock.patch.object(trial, 'own_run_lock') as runlock, mock.patch.object(guard.subprocess, 'Popen') as spawn:
                    self.assertEqual(trial.run(), 1)
                stop.assert_called_once()
                runlock.assert_not_called()
                spawn.assert_not_called()
                result = json.loads((output / 'guard-receipt.json').read_text())
                self.assertEqual(result['status'], 'FAIL')
                self.assertTrue(result['source_after'][str(pin)]['matches'])
                self.assertFalse(result['native_executed'])
                self.assertFalse((root / 'uncreated-run').exists())

    def test_after_pin_failure_cannot_return_success(self):
        proposal = json.loads(guard.DEFAULT_PROPOSAL.read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pin = root / 'immutable'
            pin.write_bytes(b'preserved-source')
            output = root / 'receipt'
            output.mkdir()
            (output / 'requests').mkdir()
            values = {str(pin): guard.digest_file(pin)}
            with mock.patch.object(guard, 'capture_sources', return_value=values), mock.patch.object(guard, 'RUN', root / 'uncreated-run'):
                trial = guard.GuardedRun(proposal, guard.DEFAULT_PROPOSAL, guard.DEFAULT_PROPOSAL_SHA, output, False)
                def changed(**kwargs):
                    pin.write_bytes(b'changed-source')
                with mock.patch.object(trial, 'check', side_effect=changed), \
                        mock.patch.object(guard, 'validate_runner_capability', return_value={'scope': 'after-pin fixture'}):
                    self.assertEqual(trial.run(), 1)
                result = json.loads((output / 'guard-receipt.json').read_text())
                self.assertEqual(result['status'], 'FAIL')
                self.assertTrue(result['after_pin_failure'])
                self.assertFalse(result['source_after'][str(pin)]['matches'])

    def test_real_owned_non_vm_process_pidfd_exit_race(self):
        # A bounded Python fixture, not the native runner or QEMU. Retain its
        # real pidfd before allowing natural exit, then consume ESRCH safely.
        child = subprocess.Popen([sys.executable, '-u', '-c', 'import sys; print("ready",flush=True); sys.stdin.readline()'],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, start_new_session=True, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), 'ready')
            process = guard.capture_process(child.pid, 'runner')
            self.assertIsNotNone(process)
            self.assertEqual(process.who.session, child.pid)
            child.stdin.write('\n')
            child.stdin.flush()
            self.assertEqual(child.wait(timeout=5), 0)
            self.assertEqual(guard.signal_owned(process, signal.SIGTERM), 'already-gone')
            os.close(process.pidfd)
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=5)
            child.stdin.close()
            child.stdout.close()

    def test_spawn_handshake_transient_argv_and_executable_keep_one_identity(self):
        wrapper = who(pid=55, session=55)
        pending = who(ppid=55, session=55, argv=('pre-exec',))
        candidate = guard.OwnedProcess(pending, 900, 'runner-candidate')
        final = replace(pending, session=101, argv=('python3', 'exact-runner'))
        samples, checks, elapsed = [], [], [0.0]
        values = iter([pending, replace(final, exe_inode=51), final, final])
        captured = guard.await_spawn_identity(candidate, wrapper, final.argv, (4, 50), samples, checks.append,
            read_identity=lambda pid: next(values), clock=lambda: elapsed[0], pause=lambda n: elapsed.__setitem__(0, elapsed[0]+n))
        self.assertEqual(captured.who, final)
        self.assertEqual(captured.pidfd, 900)
        self.assertEqual(checks, [None, None, final, final])
        self.assertEqual(len(samples), 4)

    def test_spawn_handshake_reuse_timeout_exit_and_resource_failure(self):
        wrapper = who(pid=55)
        final = who(ppid=55, argv=('python3', 'exact-runner'))
        candidate = guard.OwnedProcess(final, 901, 'runner-candidate')
        for observed in [replace(final, start=final.start+1), None, replace(final, state='Z')]:
            with self.assertRaises(guard.GuardError):
                guard.await_spawn_identity(candidate, wrapper, final.argv, (4,50), [], lambda owner: None,
                    read_identity=lambda pid: observed)
        elapsed=[0.0];samples=[]
        with self.assertRaisesRegex(guard.GuardError, 'within two seconds'):
            guard.await_spawn_identity(candidate, wrapper, final.argv, (4,50), samples, lambda owner: None,
                read_identity=lambda pid: replace(final,argv=('foreign',)), clock=lambda: elapsed[0],
                pause=lambda n: elapsed.__setitem__(0,elapsed[0]+n))
        self.assertGreater(len(samples), 2)
        def failed(owner):
            self.assertEqual(owner,final)
            raise guard.GuardError('injected startup resource floor')
        with self.assertRaisesRegex(guard.GuardError, 'resource floor'):
            guard.await_spawn_identity(candidate,wrapper,final.argv,(4,50),[],failed,read_identity=lambda pid: final)

    def test_failed_spawn_adopts_for_stop_only_two_exact_current_reads(self):
        wrapper = who(pid=55)
        initial = who(ppid=55, argv=('bootstrap',))
        candidate = guard.OwnedProcess(initial,902,'runner-candidate')
        final = replace(initial,argv=('python3','exact-runner'))
        adopted=guard.verified_spawn_for_stop(candidate,wrapper,final.argv,(4,50),read_identity=lambda pid: final)
        self.assertEqual(adopted.who,final)
        self.assertEqual(adopted.pidfd,902)
        for mismatch in [replace(final,start=final.start+1),replace(final,argv=('foreign',)),
                         replace(final,session=9),replace(final,ppid=9),None,replace(final,state='Z')]:
            self.assertIsNone(guard.verified_spawn_for_stop(candidate,wrapper,final.argv,(4,50),read_identity=lambda pid: mismatch))
        values=iter([final,replace(final,exe_inode=77)])
        self.assertIsNone(guard.verified_spawn_for_stop(candidate,wrapper,final.argv,(4,50),read_identity=lambda pid: next(values)))

    def test_real_popen_child_exec_transition_with_retained_pidfd(self):
        # The real child performs a delayed exec with the same PID/start. No
        # VM, native script or guest disk is used by this transition fixture.
        final_code='import sys; print("postexec",flush=True); sys.stdin.readline()'
        final_argv=['python3','-u','-c',final_code]
        bootstrap='import os,time; time.sleep(0.15); os.execv('+repr(sys.executable)+','+repr(final_argv)+')'
        child=subprocess.Popen(['python3','-u','-c',bootstrap],executable=sys.executable,
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,start_new_session=True,text=True)
        candidate=None
        try:
            candidate=guard.capture_spawn_candidate(child)
            self.assertIsNotNone(candidate)
            wrapper=guard.identity(os.getpid());info=os.stat(sys.executable);samples=[]
            captured=guard.await_spawn_identity(candidate,wrapper,final_argv,(info.st_dev,info.st_ino),samples,
                lambda owner: None,child_poll=child.poll)
            self.assertEqual(captured.pidfd,candidate.pidfd)
            self.assertEqual(captured.who.start,candidate.who.start)
            self.assertEqual(captured.who.argv,tuple(final_argv))
            self.assertTrue(any(s['argv']!=final_argv for s in samples))
            self.assertEqual(child.stdout.readline().strip(),'postexec')
            child.stdin.write('\n');child.stdin.flush()
            self.assertEqual(child.wait(timeout=5),0)
            self.assertEqual(guard.signal_owned(captured,signal.SIGTERM),'already-gone')
        finally:
            if child.poll() is None:
                child.terminate();child.wait(timeout=5)
            if candidate: os.close(candidate.pidfd)
            child.stdin.close();child.stdout.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
