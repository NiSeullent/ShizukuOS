# SPDX-License-Identifier: GPL-2.0-only
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('pci_preparation', Path(__file__).resolve().parents[1] / 'native_pci_preparation.py')
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


def text(words, start=0):
    return '\n'.join('%08x:' % (start + i * 4) + ''.join(' 0x%08x' % w for w in words[i:i+4])
                     for i in (0, 4, 8)) + '\n'


def fixture():
    data = {name: name.encode() for name in adapter.PRODUCER_PINS}
    def pin(name):
        raw = data[name]
        return {'path': '/synthetic/' + name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    built = {'status': 'ACTUAL_NEW_PUBLIC_PREPARATION_FIRMWARE_COMPILED_NOT_RUN', 'source_unchanged': True,
             'VM_executed': False, 'Windows98_boot_verified': False,
             'source_sha256': {'prepare_pci.c': pin('firmware_sources')['sha256'], 'efi.h': pin('firmware_header')['sha256']},
             'artifact': {'bytes': len(data['firmware']), 'sha256': pin('firmware')['sha256'], 'machine': 'AMD64',
                          'subsystem': 'EFI_APPLICATION', 'imports': [], 'relocations': True}}
    data['firmware_build_receipt'] = json.dumps(built).encode()
    pins = {name: pin(name) for name in data}
    data.update(qemu=b'held qemu executable', firmware_code=b'held OVMF code')
    artifacts = {name: pin(name) for name in ('qemu', 'firmware_code')}
    argv = ['/synthetic/qemu', '-machine', 'q35']
    raw = b'\0'.join(s.encode() for s in argv) + b'\0'
    sha = hashlib.sha256(raw).hexdigest()
    observed = {'status': 'ACTUAL_NEW_PUBLIC_PREPARATION_OBSERVATION', 'VM_executed': True,
        'Windows98_boot_verified': False, 'HostGrant_transmitted': False, 'originals_after_match': True,
        'shared_ROOT_lock_released': True, 'actual_parent_wait_status': 0, 'actual_exit_code': 0,
        'input_pins': {**pins, **artifacts}, 'argv': argv,
        'argv_binding': {'matches': True, 'expected_argv': argv, 'actual_argv': argv,
            'expected_sha256': sha, 'actual_sha256': sha, 'expected_bytes': len(raw), 'actual_bytes': len(raw)},
        'owned_process': {'argv': argv, 'argv_sha256': sha, 'argv_bytes': len(raw), 'argv_hex': raw.hex(),
                          'argv_terminal_nul': True, 'executable_sha256': artifacts['qemu']['sha256']},
        'flatview_text': '00000000e0000000-00000000efffffff (prio 0, i/o): pcie-mmcfg-mmio\n', 'devices': {}}
    for role, words in [(1, [0x11111234, 7, 0x03000002, 0, 0x80000008, 0, 0x81012000, 0, 0, 0]),
                        (2, [0x10011af4, 0x00100007, 0x01000000, 0, 0x6001, 0x81011000, 0, 0, 12, 0x3800])]:
        address = 0xe0000000 + (role * 8) * 4096
        observed['devices'][str(role)] = {'role': role, 'bdf': role * 8,
            'reads': [{'offset': 0, 'text': text(words), 'words': words} for _ in range(2)],
            'actual_preparation_QMP_reads': [{'address': address, 'text': text(words, address)} for _ in range(2)]}
    plan = {'status': 'PASS_FRESH_PRIVATE_VM_INPUTS_PREPARED_NOT_RUN', 'private': True, 'VM_executed': False,
            'qemu_argv': argv, 'input_pins': observed['input_pins']}
    return observed, pins, lambda row, maximum: data[Path(row['path']).name], plan


class PreparationAdapter(unittest.TestCase):
    def test_raw_flags_and_upper_bar_preserved(self):
        observed, pins, reader, plan = fixture()
        rows = adapter.validate_observation(observed, pins, reader, plan)
        self.assertEqual(rows[0]['raw_bars'], [0x80000008, 0, 0x81012000, 0, 0, 0])
        self.assertEqual(rows[1]['raw_bars'], [0x6001, 0x81011000, 0, 0, 12, 0x3800])

    def test_admission_refuses_false_claims_and_mutations(self):
        for case in ('desktop', 'grant', 'cleanup', 'source', 'argv', 'qmp', 'words', 'missing_role', 'duplicate_build', 'recipe'):
            with self.subTest(case=case):
                observed, pins, reader, plan = fixture()
                if case == 'desktop': observed['Windows98_boot_verified'] = True
                elif case == 'grant': observed['HostGrant_transmitted'] = True
                elif case == 'cleanup': observed['actual_parent_wait_status'] = True
                elif case == 'source': reader = lambda row, maximum: b'changed'
                elif case == 'argv': observed['owned_process']['argv_hex'] = ''
                elif case == 'qmp': observed['devices']['1']['actual_preparation_QMP_reads'][1]['text'] = text([0] * 10, 0xe0008000)
                elif case == 'words': observed['devices']['2']['reads'][0]['words'][4] = 0x6000
                elif case == 'missing_role': del observed['devices']['2']
                elif case == 'recipe': plan['qemu_argv'] = ['/qemu', '-machine', 'pc']
                elif case == 'duplicate_build': pins = copy.deepcopy(pins); del pins['observer_source']
                with self.assertRaises(ValueError): adapter.validate_observation(observed, pins, reader, plan)

    def test_target_paths_are_not_promoted_and_device_options_are_exact(self):
        observed, pins, reader, plan = fixture()
        observed['argv'] = ['/synthetic/qemu', '-name', 'public', '-device', 'VGA', '-drive',
                            'if=none,id=esp,format=raw,file=/public.img', '-serial',
                            'file:/proc/self/fd/20', '-qmp', 'unix:/public.sock,server=on,wait=off']
        plan['qemu_argv'] = ['/synthetic/qemu', '-name', 'private', '-device', 'VGA', '-drive',
                            'if=none,id=esp,format=raw,file=/private.img', '-serial',
                            'file:/private.log', '-qmp', 'unix:/private.sock,server=on,wait=off']
        self.assertEqual(adapter.recipe_layout(observed['argv']), adapter.recipe_layout(plan['qemu_argv']))
        sha = adapter.validate_target_recipe(observed, plan)
        self.assertEqual(sha, hashlib.sha256(json.dumps(plan['qemu_argv'], separators=(',', ':')).encode()).hexdigest())
        plan['qemu_argv'][4] = 'virtio-vga'
        with self.assertRaises(ValueError): adapter.validate_target_recipe(observed, plan)
        plan['qemu_argv'][4] = 'VGA'
        plan['input_pins'] = copy.deepcopy(plan['input_pins'])
        plan['input_pins']['firmware_code']['sha256'] = 'different'
        with self.assertRaises(ValueError): adapter.validate_target_recipe(observed, plan)

    def test_snapshot_offsets_and_surplus_refused(self):
        words = list(range(10))
        self.assertEqual(adapter.parse_snapshot(text(words), 0), tuple(words))
        for raw in (text(words) + '00000030: 0x00000000\n', text(words).replace('00000010:', '00000014:')):
            with self.assertRaises(ValueError): adapter.parse_snapshot(raw, 0)

    def test_missing_and_malformed_artifact_pins_refused(self):
        bad_pins = ({}, None, {'bytes': 1, 'sha256': 'a' * 64},
                    {'path': '/synthetic/qemu', 'bytes': 1},
                    {'path': '/synthetic/qemu', 'bytes': 1, 'sha256': 'abc'})
        for name in ('qemu', 'firmware_code'):
            for bad in bad_pins:
                with self.subTest(name=name, bad=bad):
                    observed, pins, reader, plan = fixture()
                    observed['input_pins'][name] = bad
                    # Preserve the original exploit: both parties agree on invalid pins.
                    if name == 'qemu': observed['owned_process']['executable_sha256'] = None
                    with self.assertRaises(ValueError): adapter.validate_observation(observed, pins, reader, plan)
        for field, values in {'path': ('', 'relative', '/synthetic/../qemu', '/synthetic/qemu\0'),
                              'bytes': (0, -1, True, '1'),
                              'sha256': (None, 'a' * 63, 'G' * 64)}.items():
            for name in ('qemu', 'firmware_code'):
                for value in values:
                    with self.subTest(name=name, field=field, value=value):
                        observed, pins, reader, plan = fixture()
                        observed['input_pins'][name][field] = value
                        with self.assertRaises(ValueError): adapter.validate_observation(observed, pins, reader, plan)

    def test_source_path_and_executable_binding_refused(self):
        for path in ('', 'relative', '/synthetic/../observer_source', '/synthetic/observer_source\0'):
            observed, pins, reader, plan = fixture()
            pins['observer_source']['path'] = path
            with self.assertRaises(ValueError): adapter.validate_observation(observed, pins, reader, plan)
        observed, pins, reader, plan = fixture()
        observed['input_pins']['qemu']['path'] = '/different/qemu'
        with self.assertRaises(ValueError): adapter.validate_observation(observed, pins, reader, plan)

    def test_held_artifact_bytes_required(self):
        for name in ('qemu', 'firmware_code'):
            observed, pins, reader, plan = fixture()
            bad_reader = lambda row, maximum: b'changed' if Path(row['path']).name == name else reader(row, maximum)
            with self.assertRaises(ValueError): adapter.validate_observation(observed, pins, bad_reader, plan)

    def test_target_pin_and_missing_executable_sha_refused(self):
        for name in ('qemu', 'firmware_code'):
            for bad in ({}, None, {'path': '/synthetic/' + name, 'bytes': True, 'sha256': 'a' * 64}):
                with self.subTest(name=name, bad=bad):
                    observed, pins, reader, plan = fixture()
                    plan['input_pins'] = copy.deepcopy(plan['input_pins'])
                    plan['input_pins'][name] = bad
                    with self.assertRaises(ValueError): adapter.validate_observation(observed, pins, reader, plan)
        for bad in (None, '', 'abc', 'b' * 64):
            observed, pins, reader, plan = fixture()
            observed['owned_process']['executable_sha256'] = bad
            with self.assertRaises(ValueError): adapter.validate_observation(observed, pins, reader, plan)

    def test_source_pin_sha_shape_refused_before_reader(self):
        for bad in (None, '', 'abc', 'G' * 64):
            observed, pins, reader, plan = fixture()
            pins['observer_source']['sha256'] = bad
            touched = []
            def checked_reader(row, maximum):
                touched.append(Path(row['path']).name)
                return reader(row, maximum)
            with self.assertRaises(ValueError): adapter.validate_observation(observed, pins, checked_reader, plan)
            self.assertNotIn('observer_source', touched)

    def test_reader_cannot_mutate_admitted_snapshot(self):
        observed, pins, reader, plan = fixture()
        def mutating_reader(row, maximum):
            raw = reader(row, maximum)
            observed['devices']['1']['bdf'] = 255
            observed['input_pins']['qemu']['sha256'] = None
            pins['observer_source']['path'] = ''
            plan['qemu_argv'] = ['changed']
            row['sha256'] = None
            return raw
        rows = adapter.validate_observation(observed, pins, mutating_reader, plan)
        self.assertEqual([row['bdf'] for row in rows], [8, 16])

    def test_separate_target_firmware_path_is_read_from_custody(self):
        observed, pins, reader, plan = fixture()
        plan['input_pins'] = copy.deepcopy(plan['input_pins'])
        plan['input_pins']['firmware_code']['path'] = '/private/firmware_code'
        touched = []
        def checked_reader(row, maximum):
            touched.append(row['path'])
            return reader(row, maximum)
        self.assertEqual(len(adapter.validate_observation(observed, pins, checked_reader, plan)), 2)
        self.assertIn('/synthetic/firmware_code', touched)
        self.assertIn('/private/firmware_code', touched)

    def test_ecam_exact_name_and_geometry_required(self):
        regions = ('00000000e0000000-00000000efffffff (prio 0, i/o): pcie-mmcfg-mmio-FAKE',
                   '00000000e0000000-00000000efffffff (prio 0, i/o): pcie-mmcfg-mmio extra',
                   '00000000e0000001-00000000efffffff (prio 0, i/o): pcie-mmcfg-mmio',
                   '00000000e0000000-00000000e000ffff (prio 0, i/o): pcie-mmcfg-mmio',
                   '00000000e0000000-00000000dfffffff (prio 0, i/o): pcie-mmcfg-mmio',
                   '00000000e0000000-00000000ffffffff (prio 0, i/o): pcie-mmcfg-mmio')
        for region in regions:
            with self.subTest(region=region):
                observed, pins, reader, plan = fixture()
                observed['flatview_text'] = region + '\n'
                with self.assertRaises(ValueError): adapter.validate_observation(observed, pins, reader, plan)
        observed, pins, reader, plan = fixture()
        observed['flatview_text'] = '  ' + observed['flatview_text'].replace('\n', ' \r\n')
        self.assertEqual(len(adapter.validate_observation(observed, pins, reader, plan)), 2)
        # QEMU may repeat the same aperture in mirrored address spaces.
        observed['flatview_text'] *= 2
        self.assertEqual(len(adapter.validate_observation(observed, pins, reader, plan)), 2)
        observed['flatview_text'] += '00000000d0000000-00000000dfffffff (prio 0, i/o): pcie-mmcfg-mmio\n'
        with self.assertRaises(ValueError): adapter.validate_observation(observed, pins, reader, plan)


class ActualCallerControls(unittest.TestCase):
    def selection(self):
        observed,pins,reader,plan=fixture()
        raw=json.dumps(observed).encode()
        row={'path':'/synthetic/observation','bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        def held(pin,maximum):
            return raw if pin['path']==row['path'] else reader(pin,maximum)
        return {'observation':row,'producer_pins':pins},plan,held

    def test_original_observation_hash_and_target_plan_required(self):
        selected,plan,held=self.selection()
        self.assertEqual(len(adapter.admit_selection(selected,plan,held)),2)
        selected['observation']['sha256']='a'*64
        with self.assertRaises(ValueError):adapter.admit_selection(selected,plan,held)
        selected,plan,held=self.selection()
        with self.assertRaises(ValueError):adapter.admit_selection(selected,{},held)

    def test_current_paused_qmp_has_exact_device_raw_bars_and_no_grant(self):
        selected,plan,held=self.selection()
        expected=adapter.admit_selection(selected,plan,held)
        observed,_,_,_=fixture()
        class Monitor:
            def __init__(self):self.calls=[];self.changed=False
            def call(self,command,arguments=None):
                self.calls.append((command,arguments))
                if command=='query-status':return {'running':False,'status':'paused'}
                if command=='query-pci':return [{'bus':0,'devices':[
                    {'slot':1,'function':0,'id':{'vendor':0x1234,'device':0x1111},'class_info':{'class':0x0300}},
                    {'slot':2,'function':0,'id':{'vendor':0x1af4,'device':0x1001},'class_info':{'class':0x0100}}]}]
                line=arguments['command-line']
                if line=='info mtree -f':return 'FlatView #0\n AS "memory", root: system\n Root memory region: system\n  00000000e0000000-00000000efffffff (prio 0, i/o): pcie-mmcfg-mmio\n\n'
                address=int(line.split()[-1],16)
                role=1 if address==0xe0008000 else 2
                words=list(observed['devices'][str(role)]['reads'][0]['words'])
                if self.changed:words[4]^=16
                return text(words,address)
        monitor=Monitor();guarded=[]
        result=adapter.current_qmp_observation(expected,monitor,lambda:guarded.append(True))
        self.assertFalse(result['HostGrant_transmitted']);self.assertFalse(result['device_authority_admitted'])
        self.assertEqual(len(guarded),2*len(monitor.calls))
        self.assertEqual(set(c for c,_ in monitor.calls),{'query-status','query-pci','human-monitor-command'})
        monitor.changed=True
        with self.assertRaises(ValueError):adapter.current_qmp_observation(expected,monitor,lambda:None)
        monitor.changed=False
        with self.assertRaisesRegex(ValueError,'owner failed'):
            adapter.current_qmp_observation(expected,monitor,lambda:(_ for _ in ()).throw(ValueError('owner failed')))


if __name__ == '__main__':
    unittest.main()
