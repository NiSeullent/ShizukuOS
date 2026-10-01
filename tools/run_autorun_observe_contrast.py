#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Root-coordinated standalone diagnostic: preserve the parent's exit 7.

Three owned guests use one ordinary native fixture and identical runtime bytes.
Only K14's explicit observation token differs from its default-OFF case. This
diagnostic never establishes publisher functionality or Windows 98 execution.
No guest is launched on import. The coordinating root agent alone runs main.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
AREA = ROOT / 'build/modern-apps'
HELPER = ROOT / 'tools/capture_modern_app_interactive_v5.py'
HELPER_SHA = '62691fa5f144969f5509dc2a6c51eb1aae2a3218602c879d397cf3407f96896f'
FIXTURE_SHA = '43764c884d4ccc52a754315ec5da446076657952ab97d3e6435edf85b4d5ad02'
FIXTURE = '\\SHZ\\TESTS\\T_AUTORUN_OBSERVE.EXE'
CONTROL = '\\SHZ\\TESTS\\AUTORUN_OBS.TXT'
CONTROL_BYTES = (f'image=C:{FIXTURE}\ncmdline=T_AUTORUN_OBSERVE.EXE\n'
                 'cwd=C:\\SHZ\\TESTS\ntimeout=40\n').encode('ascii')
PINS = {
    'K13': ('kernel-v13-thread-capacity',
            '8e2df8486f79af2cdde3c99508c5f962a1e9357fa62cd1bd696314a9f1382c0c',
            'e69daa23b5d98cf2ce4ded8d61322331446effbbb02e02ab7965862b0136141f'),
    'K14': ('kernel-v14-autorun-observe',
            'd2c96a5dc2087c978c8d07734f6f7e4ea477e57e6b7e4edc0c5aed1fc739a7a7',
            '589ec66659a88846575a801eede2b1312cb34b100b648cca5b33a566e8a85d1b')}
STUB_SHA = 'ec83208dc46cdca7fb30bc4ba08d0fae13107ba636695b89702dc766727d1265'
CASES = (('k13-no-option', 'K13', False), ('k14-default-off', 'K14', False),
         ('k14-explicit-15s', 'K14', True))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load_helper():
    if digest(HELPER.read_bytes()) != HELPER_SHA:
        raise ValueError('Reviewed ownership helper changed')
    spec = importlib.util.spec_from_file_location('contrast_owned_v5', HELPER)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper


def archive_files(raw):
    if len(raw) < 16 or raw[:8] != b'SHZARC01':
        raise ValueError('Invalid native archive magic')
    count, reserved = struct.unpack_from('<II', raw, 8)
    header = 16 + count * 136
    if not 1 <= count <= 4096 or reserved or header > len(raw):
        raise ValueError('Invalid native archive header')
    records, names, spans = [], set(), []
    for i in range(count):
        name_raw, offset, size = struct.unpack_from('<120sQQ', raw, 16 + i * 136)
        name, separator, padding = name_raw.partition(b'\0')
        if not separator or any(padding):
            raise ValueError('Native archive name lacks canonical NUL padding')
        name = name.decode('ascii')
        key = name.casefold()
        if (not name.startswith('\\') or '/' in name or '..' in name.split('\\')
                or key in names or offset < header or offset + size > len(raw)):
            raise ValueError('Invalid or duplicate native archive entry')
        names.add(key)
        spans.append((offset, offset + size))
        records.append((name, raw[offset:offset + size]))
    spans.sort()
    if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
        raise ValueError('Overlapping native archive entries')
    return records


def overlay_control(records):
    if any(name.casefold() == CONTROL.casefold() for name, _ in records):
        raise ValueError('Control path already exists; no payload may be replaced')
    records = [*records, (CONTROL, CONTROL_BYTES)]
    offset = 16 + len(records) * 136
    header = bytearray(b'SHZARC01' + struct.pack('<II', len(records), 0))
    payload = bytearray()
    for name, raw in records:
        header.extend(struct.pack('<120sQQ', name.encode('ascii'), offset, len(raw)))
        payload.extend(raw)
        offset += len(raw)
    packed = bytes(header + payload)
    if archive_files(packed) != records:
        raise ValueError('Repacked native payloads differ')
    return packed


def native_inputs(helper, runtime):
    receipt_path = runtime.parent / 'receipt.json'
    raw = helper.read_regular_bytes(runtime, 512 * 1024 * 1024)
    receipt_raw = helper.read_regular_bytes(receipt_path, 16 * 1024 * 1024)
    proof = helper.strict_json(receipt_raw)
    if (proof.get('status') != 'PASS'
            or proof.get('mode') != 'ordinary-native-frozen-subset-build-and-immutable-runtime-merge'
            or proof.get('archive_sha256') != digest(raw)):
        raise ValueError('Runtime lacks its exact successful ordinary native build receipt')
    sources = [(name, pin) for name, pin in proof['sources'].items()
               if name.endswith('/t_autorun_observe.c')]
    if len(sources) != 1 or sources[0][1] != FIXTURE_SHA:
        raise ValueError('Ordinary build must consume the unchanged native fixture')
    if digest(helper.read_regular_bytes(Path(sources[0][0]), 65536)) != FIXTURE_SHA:
        raise ValueError('Native fixture source changed after compilation')
    files = archive_files(raw)
    matching = [(name, data) for name, data in files if name.casefold() == FIXTURE.casefold()]
    additions = {name.casefold(): pin for name, pin in proof['replaced_or_added'].items()}
    if len(matching) != 1 or additions.get(FIXTURE.casefold()) != digest(matching[0][1]):
        raise ValueError('Exact compiled native fixture is absent or differs from receipt')
    image = matching[0][1]
    if len(image) < 64 or image[:2] != b'MZ':
        raise ValueError('Native fixture is not a PE image')
    pe = struct.unpack_from('<I', image, 60)[0]
    if pe + 6 > len(image) or image[pe:pe+4] != b'PE\0\0' or struct.unpack_from('<H', image, pe+4)[0] != 0x8664:
        raise ValueError('Native fixture is not x64 PE')
    return raw, files, {'receipt': str(receipt_path), 'receipt_sha256': digest(receipt_raw),
                        'archive_sha256': digest(raw), 'fixture_sha256': digest(image),
                        'fixture_source_sha256': FIXTURE_SHA}


def kernel_inputs(helper):
    inputs, kernels, proofs = {}, {}, {}
    for name, (directory, receipt_sha, kernel_sha) in PINS.items():
        receipt = AREA / directory / 'kernel-build-receipt.json'
        binary = receipt.parent / 'kernel64s/KERNEL64S.BIN'
        stub = binary.parent / 'boot.elf'
        raw = helper.read_regular_bytes(receipt, 1024 * 1024)
        proof = helper.strict_json(raw)
        if (digest(raw) != receipt_sha or proof.get('status') != 'PASS'
                or proof.get('mode') != 'ordinary-standalone-kernel-build-frozen-source'
                or proof['kernel']['sha256'] != kernel_sha or proof['stub']['sha256'] != STUB_SHA):
            raise ValueError('Exact reviewed ordinary kernel receipt required')
        for path, pin, bound in ((binary, kernel_sha, 2 * 1024 * 1024), (stub, STUB_SHA, 65536)):
            if digest(helper.read_regular_bytes(path, bound)) != pin:
                raise ValueError('Reviewed kernel/stub changed')
            inputs[str(path)] = pin
        inputs[str(receipt)] = receipt_sha
        kernels[name] = (stub, binary)
        proofs[name] = proof
    old, new = proofs['K13']['sources'], proofs['K14']['sources']
    changed = [p for p in old.keys() & new.keys() if old[p] != new[p]]
    if (changed != ['shizukudos/kernel64/main.c']
            or new.keys() - old.keys() != {'shizukudos/kernel64/autorun_observe.c'}
            or old.keys() - new.keys()):
        raise ValueError('K13/K14 differ beyond the reviewed observation hook')
    return inputs, kernels


def semantic_oracle(serial, observe, returncode, timed_out=False):
    """Strict diagnostic semantics; initial app exit remains 7 in every case."""
    if type(observe) is not bool:
        raise ValueError('Observer selection must be boolean')
    checks = []
    def check(name, condition):
        checks.append({'check': name, 'passed': bool(condition)})
    def unique(pattern):
        matches = list(re.finditer(pattern, serial, re.M))
        return matches[0] if len(matches) == 1 else None
    started = unique(r'^K64 autorun: started pid ([1-9][0-9]*)$')
    parent = unique(r'^K64 observation fixture: actual parent pid ([1-9][0-9]*) exits 7 after real child pid ([1-9][0-9]*) acquired its process handle$')
    result = unique(r'^K64 autorun: result exited exit=([0-9a-f]+) faulted=([0-9]+) reaped=([0-9-]+) after ([0-9]+) ms$')
    child = unique(r'^K64 observation fixture: real child pid ([1-9][0-9]*) survived actual parent pid ([1-9][0-9]*) exit ([0-9]+) after delayed scheduling$')
    observer = unique(r'^K64 observation: post-autorun scheduling for at most 15 s; original result retained$')
    ended = unique(r'^K64 observation: bounded post-autorun scheduling ended; original result retained$')
    bridge = unique(r'^K64 subsys64: loopback self-test \(no peer domain in the standalone profile\)$')
    final = unique(r'^Kernel64 [^\r\n]+: done, 0 self-test failure\(s\)$')
    exit0 = unique(r'^SHZ-EXIT:0$')
    check('owned guest completed normally, without host timeout', not timed_out and returncode == 1)
    check('unique actual autorun start, fixture parent, and ordinary result', started and parent and result
          and serial.count('K64 autorun: started pid ') == 1
          and serial.count('K64 observation fixture: actual parent pid ') == 1
          and serial.count('K64 autorun: result ') == 1)
    coherent_parent = (started and parent and result and started.group(1) == parent.group(1)
                       and parent.group(1) != parent.group(2) and started.start() < result.start()
                       and parent.start() < result.start())
    check('actual parent PID matches autorun and differs from actual child', coherent_parent)
    check('original nonzero diagnostic exit 7 retained, fault 0, proc_wait success 0',
          result and result.group(1, 2, 3) == ('7', '0', '0') and int(result.group(4)) < 40000)
    check('normal bridge and standalone shutdown remain after original result',
          result and bridge and final and exit0 and result.start() < bridge.start() < final.start() < exit0.start()
          and serial.count('SHZ-EXIT:') == 1 and 'K64 test FAIL' not in serial
          and not re.search(r'^K64 subsys64.*(?:FAIL|[1-9][0-9]* failed)', serial, re.M))
    app_region = serial[started.start():bridge.start()] if started and bridge else serial
    check('no actual app-phase exception, killed process, missing import or unsupported call',
          not re.search(r'K64 exc:|unhandled exception|K64: process .* killed:|unresolved import|'
                        r'K32 unsupported:|result (?:start-failed|timeout)|process creation failed', app_region))
    child_count = serial.count('K64 observation fixture: real child pid ')
    observer_count = serial.count('K64 observation:')
    if observe:
        check('one exact bounded observer interval between original result and bridge',
              result and observer and ended and bridge and observer_count == 2
              and result.start() < observer.start() < ended.start() < bridge.start())
        check('real child reports same handles-derived parent exit 7 during observation',
              coherent_parent and child and observer and ended and child_count == 1
              and child.group(1, 2, 3) == (parent.group(2), parent.group(1), '7')
              and observer.start() < child.start() < ended.start())
    else:
        check('observation remains OFF and delayed child marker is absent', observer_count == 0 and child_count == 0)
    return {'status': 'DIAGNOSTIC_PASS' if all(c['passed'] for c in checks) else 'DIAGNOSTIC_FAIL',
            'checks': checks, 'original_application_expected_exit': 7,
            'app_functionality_verified': False, 'windows98_execution_verified': False}


def command_for(qemu, stub, kernel, runtime, serial, observe):
    append = f'shz.noapps shz.autorun=C:{CONTROL} shz.exctrace'
    if observe:
        append += ' shz.autorun-observe=15'
    return [str(qemu), '-machine', 'pc', '-accel', 'kvm', '-cpu', 'max', '-m', '3072',
            '-nodefaults', '-display', 'none', '-kernel', str(stub), '-initrd', f'{kernel},{runtime}',
            '-append', append, '-serial', f'file:{serial}', '-device',
            'isa-debug-exit,iobase=0xf4,iosize=0x04', '-no-reboot']


def run_case(helper, out, command):
    start, owned, errors, timed_out = time.monotonic(), None, [], False
    with (out / 'qemu.log').open('xb') as log:
        proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True, close_fds=True)
        try:
            owned = helper.capture_owned_guest(proc, command)
            while proc.poll() is None:
                if time.monotonic() - start >= 180:
                    timed_out = True
                    break
                time.sleep(0.1)
        except BaseException as error:
            errors.append(str(error))
        finally:
            try:
                if proc.poll() is None:
                    if owned is None:
                        owned = helper.capture_owned_guest(proc, command)
                    helper.require_owned_guest(proc, owned)
                    try:
                        signal.pidfd_send_signal(owned['pidfd'], signal.SIGKILL, None, 0)
                    except ProcessLookupError:
                        pass
                proc.wait(timeout=10)
            except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
                errors.append('Owned cleanup: ' + str(error))
            if owned is not None:
                os.close(owned['pidfd'])
    return proc.returncode, timed_out, errors, owned['identity'] if owned else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root-owned-run', action='store_true', help='Only coordinating root agent may launch the three guests')
    parser.add_argument('--runtime', type=Path, required=True, help='Ordinary frozen-subset WIN64.IMG containing the exact native fixture')
    parser.add_argument('--out', type=Path, required=True, help='New owned directory directly under build/modern-apps')
    args = parser.parse_args()
    if not args.root_owned_run or os.geteuid() != 0:
        parser.error('Root-coordinated explicit guest launch required')
    if (not args.out.is_absolute() or args.out.parent != AREA.resolve(strict=True)
            or args.out.exists() or args.out.is_symlink() or ',' in str(args.out)
            or any(c.isspace() for c in str(args.out))):
        parser.error('Output must be a new canonical direct child of owned build/modern-apps')
    helper = load_helper()
    base, records, native_proof = native_inputs(helper, args.runtime)
    inputs, kernels = kernel_inputs(helper)
    qemu = Path(helper.runner.qemu.DEFAULT_QEMU).resolve(strict=True)
    inputs[str(qemu)] = helper.sha256(qemu)
    inputs[str(HELPER)] = HELPER_SHA
    inputs[str(Path(__file__).resolve())] = helper.sha256(Path(__file__).resolve())
    inputs[str(args.runtime)] = digest(base)
    inputs[native_proof['receipt']] = native_proof['receipt_sha256']
    for source, pin in helper.SOURCE_PINS.items():
        inputs[str(ROOT / source)] = pin
    overlay = overlay_control(records)
    # All input and archive gates above precede file creation and every launch.
    args.out.mkdir(mode=0o700)
    runtime = args.out / 'WIN64.IMG'
    with runtime.open('xb') as stream:
        stream.write(overlay)
    inputs[str(runtime)] = digest(overlay)
    cases = []
    for name, kernel_name, observe in CASES:
        if any(helper.sha256(Path(path)) != pin for path, pin in inputs.items()):
            raise ValueError('Frozen contrast input changed before guest launch')
        out = args.out / name
        out.mkdir(mode=0o700)
        stub, kernel = kernels[kernel_name]
        command = command_for(qemu, stub, kernel, runtime, out / 'serial.log', observe)
        helper.atomic_json(out / 'inputs.json', {'command': command, 'inputs': inputs,
                            'native': native_proof, 'host_seconds_limit': 180,
                            'guest_autorun_seconds_limit': 40, 'observer_seconds': 15 if observe else 0}, new=True)
        returncode, timed_out, errors, owner = run_case(helper, out, command)
        serial_path = out / 'serial.log'
        serial_raw = helper.read_regular_bytes(serial_path, 16 * 1024 * 1024) if serial_path.exists() else b''
        result = semantic_oracle(serial_raw.decode('utf-8', errors='replace'), observe, returncode, timed_out)
        unchanged = all(helper.sha256(Path(path)) == pin for path, pin in inputs.items())
        result.update({'case': name, 'command': command, 'qemu_returncode': returncode,
                       'timed_out': timed_out, 'ownership_errors': errors, 'owned_guest': owner,
                       'serial_sha256': digest(serial_raw), 'inputs_unchanged': unchanged})
        if errors or not unchanged:
            result['status'] = 'DIAGNOSTIC_FAIL'
        helper.atomic_json(out / 'result.json', result, new=True)
        cases.append(result)
        if errors:  # An unclosed owned process must prevent the next launch.
            break
    passed = len(cases) == 3 and all(case['status'] == 'DIAGNOSTIC_PASS' for case in cases)
    result = {'status': 'CONTRAST_DIAGNOSTIC_PASS' if passed else 'CONTRAST_DIAGNOSTIC_FAIL',
              'cases': cases, 'native': native_proof, 'inputs': inputs,
              'overlay_sha256': digest(overlay), 'unchanged_payloads': len(records),
              'control_sha256': digest(CONTROL_BYTES), 'original_application_expected_exit': 7,
              'app_functionality_verified': False, 'windows98_execution_verified': False}
    helper.atomic_json(args.out / 'result.json', result, new=True)
    print(result['status'])
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
