# SPDX-License-Identifier: GPL-2.0-only
"""Small host models for ownership/proof boundaries; never starts QEMU."""
import contextlib
import ctypes
import dataclasses
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[4]
NATIVE = ROOT / 'shizukudos/supervisor/native_win98'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m = load('checkpoint_adapter_tests', NATIVE / 'private_checkpoint_adapter.py')
checkpoint = load('adapter_actual_checkpoint', NATIVE / 'private_checkpoint.py')
owned = load('adapter_actual_owned', NATIVE / 'owned_capture.py')
guards = load('adapter_actual_guards', NATIVE / 'build.py')
info = load('adapter_actual_info', ROOT / 'shizukudos/tools/shzinfo.py')

FLAT = '''FlatView #7
 AS "memory", root: system
 AS "cpu-memory-0", root: system
 Root memory region: system
  0000000000000000-000000000009ffff (prio 0, ram): pc.ram
  00000000000a0000-00000000000fffff (prio 1, rom): pc.bios
  0000000000100000-000000007fffffff (prio 0, ram): pc.ram @0000000000100000 kvm
  0000000080000000-00000000ffffffff (prio 0, i/o): pci-hole
  0000000100000000-000000017fffffff (prio 0, ram): pc.ram @0000000080000000 kvm

FlatView #2
 AS "I/O", root: io
 Root memory region: io
  0000000000000000-000000000000ffff (prio 0, i/o): io

'''

MODEL_PROGRAM = '''import json, socket, sys
config=json.load(open(sys.argv[2]))
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
 listener.bind(sys.argv[1]);listener.listen(1)
 conn,_=listener.accept()
 with conn,conn.makefile('rb') as stream:
  conn.sendall(b'{"QMP":{}}\\n')
  state='paused';flat=config['flat'];base=config['base']
  for line in stream:
   request=json.loads(line);command=request['execute'];args=request.get('arguments',{});answer={}
   if command=='qmp_capabilities':pass
   elif command=='query-status':answer={'running':state=='running','status':state}
   elif command=='query-version':answer={'qemu':{'major':10,'minor':1,'micro':0},'package':'EXPLICIT HOST MODEL'}
   elif command=='query-memory-size-summary':answer={'base-memory':base,'plugged-memory':0}
   elif command=='human-monitor-command':
    if args!={'command-line':'info mtree -f'}:raise RuntimeError('unexpected HMP')
    answer=flat
   elif command=='fixture-set':
    state=args.get('state',state);flat=args.get('flat',flat)
   elif command=='stop':state='paused'
   elif command=='pmemsave':
    with open(args['filename'],'wb') as destination:destination.write(b'X'*args['size'])
   else:raise RuntimeError('unexpected modeled request')
   conn.sendall((json.dumps({'id':request['id'],'return':answer})+'\\n').encode())
'''


def budget(lane=None):
    return {'schema': 'shizuku.private-checkpoint-budget.v1', 'private': True,
            'approved': True, 'scope': 'private_ram_checkpoint_only',
            'approved_lane': str(lane or (checkpoint.NAS_WORKSPACE / 'fada/owned-checkpoints')),
            'disk_bytes': 2 << 30, 'capture_bytes': 16 << 20,
            'total_bytes': (2 << 30) + (16 << 20), 'retained_free_bytes': 17 << 30,
            'timeout_seconds': 10}


class AdapterControls(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory(prefix='checkpoint-adapter-host-') as temporary:
            out = Path(temporary)
            program, config = out / 'model.py', out / 'model.json'
            program.write_text(MODEL_PROGRAM); program.chmod(0o600)
            config.write_text(json.dumps({'flat': FLAT, 'base': 4 << 30})); config.chmod(0o600)
            qemu_path = Path(sys.executable).resolve()
            child = subprocess.Popen([str(qemu_path), '-I', '-B', str(program), str(out / 'qmp.sock'), str(config), '-machine', 'q35'],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            pidfd = os.pidfd_open(child.pid)
            monitor = None
            try:
                monitor = owned.OwnedQMP(out / 'qmp.sock', child.pid, time.monotonic() + 30)
                paths = {'controller': NATIVE / 'run_vm.py', 'qemu': qemu_path,
                         'owned_qmp': Path(owned.__file__), 'checkpoint_helper': Path(checkpoint.__file__),
                         'checkpoint_adapter': Path(m.__file__), 'info_header': ROOT / 'shizukudos/supervisor/include/shz_info.h',
                         'info_parser': Path(info.__file__), 'compiler': Path(shutil.which('gcc')).resolve(),
                         'model_program': program, 'model_config': config}
                with contextlib.ExitStack() as stack:
                    sources = []

                    def lease(name, path):
                        digest = hashlib.sha256(path.read_bytes()).hexdigest()
                        fd, check = stack.enter_context(guards.read_leased(path, digest, path.stat().st_size))
                        source = checkpoint.ReadLease(name, path, fd, digest, path.stat().st_size, check)
                        sources.append(source)
                        return source

                    for name, path in paths.items(): lease(name, path)
                    roles = {name: name for name in ('controller', 'qemu', 'owned_qmp', 'checkpoint_helper', 'checkpoint_adapter')}
                    runtime = m.OwnedRuntime(child, pidfd, monitor, checkpoint, owned, tuple(sources), roles)
                    yield out, runtime, child, monitor, sources, lease
            finally:
                if monitor is not None: monitor.close()
                if child.poll() is None:
                    child.terminate()
                    try: child.wait(timeout=3)
                    except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=3)
                os.close(pidfd)

    def prepare_binding(self, out, runtime, sources, lease):
        observation = out / 'ram.json'
        runtime.write_observation(observation)
        lease('ram_observation', observation)
        by_name = {source.name: source for source in sources}
        layout = out / 'layout.json'
        m.prove_layout(checkpoint, info, by_name['info_header'], by_name['info_parser'], by_name['compiler'], layout)
        lease('layout_receipt', layout)
        approval = out / 'budget.json'
        approval.write_text(json.dumps(budget())); approval.chmod(0o600)
        lease('budget', approval)
        references = {name: name for name in checkpoint.REQUIRED_REFS}
        return references

    def binding(self, out, runtime, sources, lease):
        references = self.prepare_binding(out, runtime, sources, lease)
        return runtime.bind(info, tuple(sources), references)

    def test_flatview_selects_full_system_view_and_high_ram_without_total_bound(self):
        result = m.parse_flatview(FLAT, 4 << 30)
        self.assertEqual(result['ranges'], [[0, 0xa0000], [0x100000, 0x80000000], [0x100000000, 0x180000000]])
        self.assertEqual(len(result['entries']), 5)
        self.assertEqual(m.parse_flatview(FLAT.replace('FlatView #7', 'FlatView #99'), 4 << 30), result)

    def test_flatview_truncation_overlap_wrong_root_and_main_offset_refuse(self):
        for text in (FLAT.rstrip(), FLAT.replace('root: system', 'root: pci'),
                     FLAT.replace('0000000080000000-00000000ffffffff', '0000000070000000-00000000ffffffff'),
                     FLAT.replace('pc.ram @0000000080000000', 'pc.ram @0000000100000000'),
                     FLAT.replace('(prio 0, i/o): pci-hole', '(prio 0, mystery): pci-hole'),
                     FLAT.replace('Root memory region: system', 'Root memory region: pci')):
            with self.subTest(text=text[:80]), self.assertRaises(ValueError): m.parse_flatview(text, 4 << 30)

    def test_readonly_nv_and_device_ram_never_become_main_ram(self):
        changed = FLAT.replace('(prio 0, ram): pc.ram @0000000080000000', '(prio 0, rom): pc.ram @0000000080000000')
        self.assertEqual(m.parse_flatview(changed, 4 << 30)['ranges'], [[0, 0xa0000], [0x100000, 0x80000000]])
        for kind in ('nv-ram', 'ramd', 'romd'):
            result = m.parse_flatview(FLAT.replace('(prio 0, ram): pc.ram @0000000080000000', '(prio 0, '+kind+'): pc.ram @0000000080000000'), 4 << 30)
            self.assertEqual(len(result['ranges']), 2)

    def test_actual_process_pidfd_peer_and_held_sources_bind_existing_api(self):
        with self.fixture() as (out, runtime, child, monitor, sources, lease):
            original_deadline = monitor.deadline
            binding = self.binding(out, runtime, sources, lease)
            self.assertIsInstance(binding.adapter, checkpoint.ControllerAdapter)
            self.assertIsInstance(binding.reservation, checkpoint.Reservation)
            self.assertEqual(binding.adapter.assert_owned()['pid'], child.pid)
            self.assertEqual(binding.adapter.observe_ram()['ranges'][-1], (0x100000000, 0x180000000))
            self.assertEqual(monitor.deadline, original_deadline)
            self.assertFalse(binding.proof['controller_wiring_integrated'])
            self.assertFalse(binding.proof['Windows98_boot_verified'])
            for source in sources:
                self.assertEqual(fcntl.fcntl(source.fd, fcntl.F_GETLEASE), fcntl.F_RDLCK)

    def test_prelaunch_is_observation_only_and_running_observation_refuses(self):
        with self.fixture() as (out, runtime, _, monitor, sources, lease):
            monitor.call('fixture-set', {'state': 'prelaunch'})
            record = runtime.write_observation(out / 'probe.json', allow_prelaunch=True)
            self.assertEqual(record['status']['status'], 'prelaunch')
            self.assertEqual(record['scope'], 'read_only_prelaunch_protocol_probe')
            with self.assertRaises(RuntimeError): runtime.write_observation(out / 'capture.json')
            monitor.call('fixture-set', {'state': 'running'})
            with self.assertRaises(RuntimeError): runtime.write_observation(out / 'running.json', allow_prelaunch=True)

    def test_owner_exit_wrong_pidfd_and_socket_loss_refuse(self):
        with self.fixture() as (_, runtime, child, monitor, sources, _):
            pipe, writer = os.pipe()
            try:
                with self.assertRaises((RuntimeError, ValueError)):
                    m.OwnedRuntime(child, pipe, monitor, checkpoint, owned, tuple(sources), runtime.roles)
            finally: os.close(pipe); os.close(writer)
            monitor.close()
            with self.assertRaises((RuntimeError, OSError)): runtime.assert_owned()
            child.terminate(); child.wait(timeout=3)
            with self.assertRaises((RuntimeError, OSError)): runtime.assert_owned()

    def test_source_bad_hash_and_lost_read_lease_refuse(self):
        with self.fixture() as (_, runtime, child, monitor, sources, _):
            original = sources[0]
            bad = (dataclasses.replace(original, sha256='0'*64),) + tuple(sources[1:])
            with self.assertRaises(RuntimeError): m.OwnedRuntime(child, runtime.pidfd, monitor, checkpoint, owned, bad, runtime.roles)
            fcntl.fcntl(original.fd, fcntl.F_SETLEASE, fcntl.F_UNLCK)
            try:
                with self.assertRaises(RuntimeError): runtime.assert_owned()
            finally: fcntl.fcntl(original.fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)

    def test_observed_map_drift_refuses_after_binding(self):
        with self.fixture() as (out, runtime, _, monitor, sources, lease):
            binding = self.binding(out, runtime, sources, lease)
            monitor.call('fixture-set', {'flat': FLAT.replace('000000017fffffff', '000000017fffefff')})
            with self.assertRaises(RuntimeError): binding.adapter.observe_ram()

    def test_real_c_nested_and_outer_layout_proof_is_pinned(self):
        with self.fixture() as (out, _, _, _, sources, _):
            pins = {source.name: source for source in sources}
            result = m.prove_layout(checkpoint, info, pins['info_header'], pins['info_parser'], pins['compiler'], out/'layout.json')
            self.assertEqual(result['layouts']['shz_info_t']['size'], ctypes.sizeof(info.Info))
            self.assertEqual(result['layouts']['shz_domain_info_t']['fields']['kind']['offset'], info.DomainInfo.kind.offset)
            self.assertEqual(result['layouts']['shz_blob_t']['fields']['base']['bytes'], 8)
            self.assertFalse(result['complete_toolchain_closure_verified'])
            self.assertEqual(json.loads((out/'layout.json').read_text()), result)

    def test_generated_source_and_executed_binary_substitution_refuse_success(self):
        for target, phase in (('layout.c', 'compile.stdout'), ('layout', 'probe.stdout'), ('probe.stdout', 'probe.stdout')):
            with self.subTest(target=target), self.fixture() as (out, _, _, _, sources, _):
                pins = {source.name: source for source in sources}
                original_check = checkpoint._lease_check
                substituted = False

                def substitute(source):
                    nonlocal substituted
                    original_check(source)
                    directories = list(out.glob('layout-*'))
                    if not substituted and directories and (directories[0]/phase).exists():
                        trigger = directories[0]/phase
                        if phase == 'compile.stdout' or trigger.stat().st_size:
                            path = directories[0]/target
                            if path.exists():
                                payload = (path.read_bytes().replace(b'size shz_info_t ', b'size shz_info_t 0')
                                           if target == 'probe.stdout' else b'substituted bytes that did not produce the proof')
                                path.rename(path.with_name(target+'.displaced'))
                                path.write_bytes(payload)
                                substituted = True

                with mock.patch.object(checkpoint, '_lease_check', substitute):
                    with self.assertRaises((RuntimeError, OSError)):
                        m.prove_layout(checkpoint, info, pins['info_header'], pins['info_parser'], pins['compiler'], out/'bad.json')
                self.assertTrue(substituted)
                self.assertFalse((out/'bad.json').exists())

    def test_layout_hash_and_interpretation_use_one_stable_output_snapshot(self):
        with self.fixture() as (out, _, _, _, sources, _):
            pins = {source.name: source for source in sources}
            original_read = Path.read_text
            interpreted = None

            def changed_second_read(path, *args, **kwargs):
                nonlocal interpreted
                text = original_read(path, *args, **kwargs)
                if path.name == 'probe.stdout':
                    interpreted = text.replace('size shz_info_t ', 'size shz_info_t 0').encode()
                    return interpreted.decode()
                return text

            with mock.patch.object(Path, 'read_text', changed_second_read):
                result = m.prove_layout(checkpoint, info, pins['info_header'], pins['info_parser'], pins['compiler'], out/'layout.json')
            if interpreted is not None:
                self.assertEqual(result['commands'][1]['stdout_sha256'], hashlib.sha256(interpreted).hexdigest())

    def test_layout_parent_uid_is_checked_before_any_command(self):
        with self.fixture() as (out, _, _, _, sources, _):
            pins = {source.name: source for source in sources}
            original_stat = Path.stat

            def changed_uid(path, *args, **kwargs):
                item = original_stat(path, *args, **kwargs)
                if path == out:
                    values = list(item); values[4] = os.getuid()+1
                    return os.stat_result(values)
                return item

            with mock.patch.object(Path, 'stat', changed_uid), mock.patch.object(m.subprocess, 'Popen', wraps=subprocess.Popen) as launch:
                with self.assertRaises(ValueError):
                    m.prove_layout(checkpoint, info, pins['info_header'], pins['info_parser'], pins['compiler'], out/'bad.json')
                self.assertEqual(launch.call_count, 0)

    def test_layout_timeout_exit_race_still_reaps_and_preserves_original(self):
        with self.fixture() as (out, _, _, _, sources, _):
            pins = {source.name: source for source in sources}
            child = mock.Mock(pid=999999)
            child.wait.side_effect = [subprocess.TimeoutExpired('modeled compiler', 10), 0]
            with mock.patch.object(m.subprocess, 'Popen', return_value=child), mock.patch.object(m.os, 'killpg', side_effect=ProcessLookupError()):
                with self.assertRaises(subprocess.TimeoutExpired):
                    m.prove_layout(checkpoint, info, pins['info_header'], pins['info_parser'], pins['compiler'], out/'bad.json')
            self.assertEqual(child.wait.call_count, 2)
            self.assertFalse((out/'bad.json').exists())

    def test_layout_publication_boundary_artifact_swap_invalidates_success(self):
        with self.fixture() as (out, _, _, _, sources, _):
            pins = {source.name: source for source in sources}
            original_link = checkpoint._link_fd
            substituted = False

            def replace_after_link(fd, directory, name):
                nonlocal substituted
                original_link(fd, directory, name)
                if name == 'layout.json':
                    binary = next(out.glob('layout-*/layout'))
                    binary.rename(binary.with_name('layout.displaced'))
                    binary.write_bytes(b'changed after publication'); substituted = True

            with mock.patch.object(checkpoint, '_link_fd', replace_after_link):
                with self.assertRaises(RuntimeError):
                    m.prove_layout(checkpoint, info, pins['info_header'], pins['info_parser'], pins['compiler'], out/'layout.json')
            self.assertTrue(substituted)
            self.assertFalse((out/'layout.json').exists())

    def test_layout_artifact_terminal_close_failure_invalidates_success(self):
        with self.fixture() as (out, _, _, _, sources, _):
            pins = {source.name: source for source in sources}
            original_close = os.close
            failed = False

            def fail_binary_close(fd):
                nonlocal failed
                try: path = os.readlink('/proc/self/fd/%d' % fd)
                except OSError: path = ''
                original_close(fd)
                if not failed and path.endswith('/layout') and (out/'layout.json').exists():
                    failed = True; raise OSError('modeled consumed binary close failure')

            with mock.patch.object(m.os, 'close', fail_binary_close):
                with self.assertRaisesRegex(OSError, 'consumed binary close'):
                    m.prove_layout(checkpoint, info, pins['info_header'], pins['info_parser'], pins['compiler'], out/'layout.json')
            self.assertTrue(failed)
            self.assertFalse((out/'layout.json').exists())

    def test_owned_absolute_deadline_increase_refuses(self):
        with self.fixture() as (_, runtime, _, monitor, _, _):
            monitor.deadline += 10
            with self.assertRaises(RuntimeError): runtime.assert_owned()

    def test_layout_receipt_missing_execution_pins_or_boolean_exit_is_refused(self):
        for failure in ('source-pins', 'exit-type', 'binary-pin'):
            with self.subTest(failure=failure), self.fixture() as (out, runtime, _, _, sources, lease):
                references = self.prepare_binding(out,runtime,sources,lease)
                record = json.loads((out/'layout.json').read_text())
                if failure == 'source-pins': record['source_before'] = record['source_after'] = {}
                elif failure == 'exit-type': record['commands'][0]['exit_code'] = False
                else: record['probe_binary_sha256'] = 'missing'
                bad=out/'bad-layout.json';bad.write_text(json.dumps(record));bad.chmod(0o600)
                lease('bad-layout',bad);references['layout_receipt']='bad-layout'
                with self.assertRaises(RuntimeError): runtime.bind(info,tuple(sources),references)

    def test_nested_layout_change_with_unchanged_outer_size_is_refused(self):
        with self.fixture() as (out, _, _, _, sources, _):
            pins = {source.name: source for source in sources}
            changed = type('BadDomain', (ctypes.Structure,), {'_fields_': [(('generation' if name=='kind' else 'kind' if name=='generation' else name), kind) for name,kind in info.DomainInfo._fields_]})
            old, old_info = info.DomainInfo, info.Info
            changed_info = type('BadInfo', (ctypes.Structure,), {'_fields_': [(name, changed*8 if name=='domains' else kind) for name,kind in info.Info._fields_]})
            self.assertEqual(ctypes.sizeof(changed_info), ctypes.sizeof(old_info))
            self.assertTrue(all(getattr(changed_info,name).offset == getattr(old_info,name).offset for name,_ in old_info._fields_))
            info.DomainInfo = changed
            info.Info = changed_info
            try:
                with self.assertRaises(RuntimeError):
                    m.prove_layout(checkpoint, info, pins['info_header'], pins['info_parser'], pins['compiler'], out/'bad.json')
            finally: info.DomainInfo, info.Info = old, old_info
            self.assertFalse((out/'bad.json').exists())

    def test_proof_parent_swap_is_refused_and_never_publishes_success(self):
        with tempfile.TemporaryDirectory(prefix='checkpoint-proof-parent-') as temporary:
            base=Path(temporary); parent=base/'parent';parent.mkdir(mode=0o700)
            displaced=base/'displaced'; swapped=False

            def change():
                nonlocal swapped
                if not swapped:
                    parent.rename(displaced);parent.mkdir(mode=0o700);swapped=True

            with self.assertRaises(RuntimeError): m._publish(checkpoint,parent/'proof.json',{'status':'PASS'},change)
            self.assertFalse((parent/'proof.json').exists())
            self.assertFalse((displaced/'proof.json').exists())

    def test_budget_requires_explicit_private_approval_exact_reservation(self):
        with self.fixture() as (out, _, _, _, _, lease):
            for field, value in (('approved',False),('scope','public'),('disk_bytes',4096),
                                 ('total_bytes',2<<30),('retained_free_bytes',1),('approved_lane','/tmp/unapproved')):
                payload=budget(); payload[field]=value
                path=out/('budget-'+field+'.json');path.write_text(json.dumps(payload));path.chmod(0o600)
                source=lease('bad-'+field,path)
                with self.subTest(field=field), self.assertRaises(ValueError): m.read_budget(checkpoint,source)

    def test_unsafe_commands_and_unreserved_dump_do_not_reach_monitor(self):
        with self.fixture() as (out, runtime, _, _, sources, lease):
            binding=self.binding(out,runtime,sources,lease)
            with self.assertRaises(ValueError): binding.adapter.call('cont')
            with self.assertRaises(ValueError): binding.adapter.call('pmemsave',{'val':0x80000000,'size':4096,'filename':'/tmp/unsafe.bin'})
            with self.assertRaises(ValueError): binding.adapter.call('pmemsave',{'val':0x100000000,'size':(16<<20)+1,'filename':'/tmp/unsafe.bin'})

    def test_pmemsave_request_boundary_swap_cannot_select_unapproved_inode(self):
        with self.fixture() as (out, runtime, _, _, sources, lease):
            with mock.patch.object(checkpoint, 'NAS_WORKSPACE', out):
                binding = self.binding(out, runtime, sources, lease)
            lane = binding.reservation.approved_lane
            lane.mkdir(parents=True, mode=0o700)
            destination = lane/'chunk.raw'; destination.touch(mode=0o600)
            displaced = lane/'chunk.displaced'
            unapproved = out/'unapproved.raw'; unapproved.write_bytes(b'UNCHANGED'); unapproved.chmod(0o600)
            original_check = runtime.assert_owned
            swapped = False

            def replace_destination():
                nonlocal swapped
                result = original_check()
                if runtime.capture_bytes_requested and not swapped:
                    destination.rename(displaced); destination.symlink_to(unapproved); swapped = True
                return result

            with mock.patch.object(runtime, 'assert_owned', replace_destination):
                with self.assertRaises((RuntimeError, ValueError, OSError)):
                    binding.adapter.call('pmemsave', {'val':0x100000, 'size':4096, 'filename':str(destination)})
            self.assertTrue(swapped)
            self.assertEqual(unapproved.read_bytes(), b'UNCHANGED')
            self.assertEqual(displaced.read_bytes(), b'X'*4096)

    def test_pmemsave_success_uses_held_fd_and_charges_separate_budget(self):
        with self.fixture() as (out, runtime, _, monitor, sources, lease):
            with mock.patch.object(checkpoint, 'NAS_WORKSPACE', out):
                binding = self.binding(out, runtime, sources, lease)
            lane = binding.reservation.approved_lane; lane.mkdir(parents=True, mode=0o700)
            destination = lane/'chunk.raw'; destination.touch(mode=0o600)
            runtime.capture_bytes_requested = binding.reservation.total_bytes-4096
            with mock.patch.object(monitor, 'call', wraps=monitor.call) as requests:
                self.assertEqual(binding.adapter.call('pmemsave', {'val':0x100000, 'size':4096, 'filename':str(destination)}), {})
                dumps = [item for item in requests.call_args_list if item.args[0] == 'pmemsave']
                self.assertEqual(len(dumps), 1)
                descriptor = dumps[0].args[1]['filename']
                self.assertRegex(descriptor, '^/proc/%d/fd/[0-9]+$' % os.getpid())
                self.assertFalse(Path(descriptor).exists())
                second = lane/'exhausted.raw'; second.touch(mode=0o600)
                with self.assertRaises(RuntimeError):
                    binding.adapter.call('pmemsave', {'val':0x100000, 'size':1, 'filename':str(second)})
                self.assertEqual(len([item for item in requests.call_args_list if item.args[0] == 'pmemsave']), 1)
            self.assertEqual(destination.read_bytes(), b'X'*4096)
            self.assertEqual(runtime.capture_bytes_requested, binding.reservation.total_bytes)


if __name__ == '__main__': unittest.main()
