#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Root-owned offline Win98 construction observation; default validates only.

This uses real installed disk/SeaBIOS/native K64 artifacts and fresh writable
ESP/VARS clones. A passed construction gate is never a Windows 98 desktop,
VMM channel, native W64 or target-app success claim. No keyboard or arbitrary
QMP requests are accepted by this observer.
"""
import sys
sys.dont_write_bytecode = True
import argparse
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

ROOT = next(p for p in Path(__file__).resolve().parents if (p/'shizukudos/kbuild.py').is_file())
SOURCE = ROOT/'build/modern-apps/native-foundation-source-v1'
BUILD = ROOT/'build/modern-apps/native-win98-boot-candidate-v1'
BUILD_SHA = 'b8bdc3296f30652aad491adec6bfda76b3010a9d207cfe0025b8da01540b0489'
SOURCE_SHA = '6031b293d3a310b96c49698c3e4b7ec8ec7a7ecd13632f1cb8da097fe7f5aefb'
FOUNDATION = ROOT/'build/modern-apps/native-foundation-runner-source-v1/frozen-v1/tools/run_native_supervisor_foundation.py'
FOUNDATION_SHA = 'e5f969103450887dc3bb4911ad8ae6720b32ab96285ec633b242e50568167e63'
PRODUCER = SOURCE/'win98-frozen-v1/shizukudos/supervisor/native_win98/build_candidate.py'
PRODUCER_SHA = '717e51cd5992376eaf199839b5bd6d2013212835e5c422f26540cfa37a95bb10'
ESP_BYTES = 2304 << 20


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def helpers():
    # Bootstrap only exact immutable helper source; never current kernel/main.
    if hashlib.sha256(FOUNDATION.read_bytes()).hexdigest() != FOUNDATION_SHA:
        raise ValueError('frozen foundation reader mismatch')
    base = module(FOUNDATION, 'native_win98_foundation_reader')
    if base.sha(PRODUCER) != PRODUCER_SHA:
        raise ValueError('frozen owned copy producer mismatch')
    return base, module(PRODUCER, 'native_win98_owned_clone')


def inputs(base):
    receipt, source = BUILD/'result.json', SOURCE/'win98-candidate-source-receipt-v1.json'
    if base.sha(receipt) != BUILD_SHA or base.sha(source) != SOURCE_SHA:
        raise ValueError('frozen Win98 candidate/build receipt mismatch')
    built, staged = json.loads(receipt.read_text()), json.loads(source.read_text())
    if built['status'] != 'PASS_OWNED_WIN98_BOOT_CANDIDATE_NOT_RUN' or built['VM_executed'] or not built['cold_source_unchanged'] or not built['source_before_after_match']:
        raise ValueError('genuine unexecuted owned build required')
    if staged['source_count'] != 18 or not staged['original_nine_unchanged']:
        raise ValueError('exact reviewed opt-in source epoch required')
    pins = {Path(p):h for p,h in built['input_pins'].items()}
    pins.update({BUILD/p:h for p,h in built['artifacts'].items()})
    pins.update({SOURCE/'win98-frozen-v1'/p:h for p,h in staged['sources_sha256'].items()})
    pins.update({base.HELPERS/p:h for p,h in base.HELPER_PINS.items()})
    pins.update({receipt:BUILD_SHA, source:SOURCE_SHA, FOUNDATION:FOUNDATION_SHA,
                 PRODUCER:PRODUCER_SHA, base.QEMU:base.QEMU_SHA, base.CODE:base.CODE_SHA})
    for path,digest in pins.items():
        if base.sha(path) != digest:
            raise ValueError('frozen native Win98 input drift')
    if (BUILD/'esp-build/esp.img').stat().st_size != ESP_BYTES:
        raise ValueError('actual owned ESP geometry mismatch')
    if base.CODE.stat().st_size+(BUILD/'OVMF_VARS.fd').stat().st_size != 4 << 20:
        raise ValueError('actual firmware flash geometry mismatch')
    return pins


def resources(out, clone=False, live=False):
    free = shutil.disk_usage(out.parent).free
    available = int(re.search(r'^MemAvailable:\s+(\d+)', Path('/proc/meminfo').read_text(), re.M)[1])*1024
    required = (17 << 30)+((64 << 20) if clone else 1 << 20)
    required_ram = ((4 if live else 8) << 30)+(512 << 20)
    if free < required or available < required_ram:
        raise RuntimeError('17GiB disk floor plus clone/capture margin and real4GiB reserve+512MiB margin; prelaunch also budgets4GiB guest')
    return {'disk_free_bytes':free, 'MemAvailable_bytes':available,
            'mode':'live_VM_reserve' if live else 'prelaunch_including_guest',
            'required_available_RAM_bytes':required_ram}


def reflink_clone(base, producer, source, target, expected, size):
    # Linux FICLONE creates a distinct writable inode with genuine filesystem
    # copy-on-write extents. Unsupported filesystems fail; no full-copy fallback
    # can consume the reserved space. The source read lease excludes writers.
    with producer.read_leased(source, expected, size) as (fd, checkpoint):
        destination = os.open(target, os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC, 0o600)
        try:
            before = os.fstat(fd)
            owned = os.fstat(destination)
            if (before.st_dev, before.st_ino) == (owned.st_dev, owned.st_ino):
                raise ValueError('fresh owned clone must have a distinct inode')
            checkpoint()
            fcntl.ioctl(destination, 0x40049409, fd)  # FICLONE from linux/fs.h
            checkpoint()
            os.fsync(destination)
            after = os.fstat(destination)
            if after.st_size != size or (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino):
                raise ValueError('owned reflink geometry/identity mismatch')
            if base.sha(target) != expected:
                raise ValueError('owned reflink full-byte SHA mismatch')
            checkpoint()
        finally:
            os.close(destination)


def checks(info, serial):
    result = []
    def add(name, passed):
        result.append({'name':name, 'passed':bool(passed)})
    add('actual handoff magic version C-sized layout', info.magic == 0x3031505553485a53 and info.version == 3 and info.size == ctypes.sizeof(type(info)))
    add('genuine L1 VMX EPT unrestricted backend', {'LONG_MODE','VMX','VMX_ENABLED','EPT','UNRESTRICTED','BACKEND_VMX'} <= set(info.caps()))
    add('actual opt-in installed disk RAM geometry', info.loader_flags & 1 and info.guest_ram_size == 128 << 20 and info.disk_size == 2 << 30 and info.disk_base and info.guest_ram_base)
    add('genuine Supervisor stage without global error', info.stage in (5,6) and not info.status and not info.last_error and info.vendor() == 'GenuineIntel')
    domains = info.to_dict()['domains']
    add('only configured Win98 and native K64 domains', set(domains) == {'WIN98','KERNEL64'})
    win98, native = domains.get('WIN98'), domains.get('KERNEL64')
    add('actual Win98 VMCS exited and scheduled without failure', win98 and win98['kind'] == 3 and win98['generation'] == 1 and win98['state'] in (1,2) and not win98['error'] and win98['exits'] > 0 and win98['run_slices'] > 0)
    add('actual real BIOS console output', 'SeaBIOS (version' in serial)
    add('actual primary ATA BIOS boot attempt', 'Booting from Hard Disk' in serial)
    if native:
        evidence = native['evidence']
        # A real Win98 peer keeps subsys64_start inside its genuine service
        # loop. report_final/exit evidence is published only after SHUTDOWN,
        # so unpublished final slots are never treated as passed tests here.
        add('actual native K64 resident without domain error', native['state'] in (1,2) and not native['error'] and native['exits'] > 0)
        add('actual native Long Mode VMCS', native['last_efer'] & 0xd01 == 0xd01 and native['last_cr4'] & 0x20 and native['last_cs'] == 8 and native['last_rip'] >= 0xffffffff80000000)
        add('actual native paging timer mutex demand-page evidence', evidence[0] & 0x80010001 == 0x80010001 and evidence[1] == native['last_cr3'] and evidence[1] and evidence[2] >= 10 and evidence[3] == 20000 and evidence[4] == 10000 and evidence[5] == 16)
        add('actual native ring3 and contained fault evidence', evidence[6] == 0x2a002a and evidence[7] & 0xffffffff == 0xc0000096 and evidence[8] & 0xffffffff == 0xc0000005 and evidence[9] & 0xffffffff == 0xc0000005 and evidence[12] == 0 and evidence[24] & 0xffff >= 1 and evidence[24] >> 16 >= 2)
        add('actual mapped channel and resident endpoint marker', 'SHZ: IPC channel 2: KERNEL64 <-> WIN98' in serial and 'K64 subsys64: serving WIN64 subsystem requests from domain 5 on channel 2' in serial)
        add('actual completed selftest serial has no reported failure', 'K64 test PASS: Win64 console app runs to exit code 7 twice without a fault' in serial and 'K64 test FAIL:' not in serial)
        value = evidence[30]
        add('genuine tiny PE twice exit7 no fault reaped', value & 0xffffffff == 7 and not (value >> 32 & 1) and value >> 33 & 1 and value >> 34 & 1)
        add('actual AMD64 above4GiB PE and argument count', evidence[19] == 0x140000000 and evidence[20] == 1 and evidence[21] == 2 and evidence[22] == 0 and evidence[23] == 3)
        add('both actual tiny PE console markers', serial.count('hello from Win64 PE32+: argc=2 argv1=first') == 2)
    else:
        add('native K64 actual evidence exists', False)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=600)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    out = args.out
    if not 60 <= args.timeout <= 900 or not out.is_absolute() or out.resolve() != out or not out.is_relative_to(ROOT/'build/modern-apps') or out.exists():
        parser.error('fresh canonical owned output and60..900 seconds required')
    base, producer = helpers()
    if not args.execute:
        pins = inputs(base)
        print(json.dumps({'status':'VALIDATED_NO_VM', 'input_pins':len(pins), 'build_sha256':BUILD_SHA}))
        return
    out.mkdir()
    record = {'status':'FAIL', 'VM_executed':False, 'Windows98_boot_verified':False,
              'Windows98_desktop_verified':False, 'native_W64_positive_verified':False,
              'Win98_VMM_channel_mapping_verified':False, 'Win98_request_roundtrip_verified':False,
              'native_final_shutdown_or_selftest_report_verified':False,
              'target_apps_verified':False, 'construction_gate_only':True, 'captures':[]}
    proc = pidfd = qmp = owner = None
    command, pins = [], {}
    own_source_before = base.sha(Path(__file__).resolve())
    try:
        pins = inputs(base)
        record['resources_before'] = resources(out, clone=True)
        sys.path.insert(0, str(base.HELPERS/'shizukudos/tools'))
        import qemu, shzinfo
        shzinfo.selfcheck(producer.COMPILE/'source')
        original = BUILD/'esp-build/esp.img'
        expected = pins[original]
        esp, variables = out/'esp-owned.img', out/'OVMF_VARS-owned.fd'
        reflink_clone(base, producer, original, esp, expected, ESP_BYTES)
        record['ESP_clone_method'] = 'actual Linux FICLONE distinct inode and full-byte SHA verified'
        shutil.copyfile(BUILD/'OVMF_VARS.fd', variables)
        if base.sha(variables) != pins[BUILD/'OVMF_VARS.fd']:
            raise ValueError('fresh variable clone mismatch')
        serial, sock = out/'serial.log', out/'qmp.sock'
        command = [str(base.QEMU), '-name','shz-native-installed-win98-construction', '-machine','q35', '-accel','kvm', '-cpu','host,+vmx', '-m','4096M', '-smp','1', '-nodefaults', '-nic','none', '-display','none', '-device','VGA', '-no-reboot',
                   '-drive',f'if=pflash,format=raw,unit=0,readonly=on,file={base.CODE}',
                   '-drive',f'if=pflash,format=raw,unit=1,file={variables}',
                   '-drive',f'if=none,id=esp,format=raw,file={esp}', '-device','virtio-blk-pci,drive=esp,bootindex=1',
                   '-serial',f'file:{serial}', '-qmp',f'unix:{sock},server=on,wait=off']
        record.update(command=command, owned_images=[str(esp),str(variables)])
        if inputs(base) != pins:
            raise ValueError('prelaunch frozen input drift')
        resources(out)
        with (out/'qemu.stderr').open('wb') as err:
            proc = subprocess.Popen(command, cwd=out, stdout=subprocess.DEVNULL, stderr=err)
        record['VM_executed'] = True
        pidfd = os.pidfd_open(proc.pid)
        owner = base.identity(proc.pid)[0]
        base.verify_owned(proc, owner, command)
        record['owner'] = {'pid':proc.pid, 'starttime':owner, 'pidfd_opened':True}
        qmp = qemu.QMP(sock, timeout=20)
        deadline, next_capture, number = time.monotonic()+args.timeout, 0, 0
        info = None
        while time.monotonic() < deadline:
            base.verify_owned(proc, owner, command)
            record['resources_live'] = resources(out, live=True)
            raw = qemu.read_guest_memory(qmp, shzinfo.REGION_BASE, shzinfo.INFO_BYTES, out/'info-current.bin')
            observed = shzinfo.Info.parse(raw)
            if observed.magic == shzinfo.MAGIC:
                info = observed
            if time.monotonic() >= next_capture:
                number += 1
                screen = out/f'screen-{number:03d}.ppm'
                qmp.call('screendump', {'filename':str(screen)})
                cpu = qemu.cpu_state(qmp)
                (out/f'cpu-{number:03d}.txt').write_text(cpu)
                record['captures'].append({'sequence':number, 'image':screen.name, 'sha256':base.sha(screen), 'stage':info.stage if info else None})
                next_capture = time.monotonic()+30
            if info and (info.stage == 0xdead or info.domains[5].state in (3,4)):
                break
            time.sleep(1)
        base.verify_owned(proc, owner, command)
        qmp.call('stop')
        final = qemu.read_guest_memory(qmp, shzinfo.REGION_BASE, shzinfo.INFO_BYTES, out/'info-final.bin')
        info = shzinfo.Info.parse(final)
        qmp.call('screendump', {'filename':str(out/'screen-final.ppm')})
        (out/'cpu-final.txt').write_text(qemu.cpu_state(qmp))
        record['info'] = info.to_dict()
        record['checks'] = checks(info, serial.read_text(errors='replace'))
        qmp.call('quit')
        proc.wait(timeout=15)
        record['checks'].append({'name':'owned QEMU normal exit0', 'passed':proc.returncode == 0})
        record['status'] = 'PASS_CONSTRUCTION_OBSERVATION_ONLY' if all(c['passed'] for c in record['checks']) else 'FAIL'
    except BaseException as exc:
        record['error'] = f'{type(exc).__name__}: {exc}'
    finally:
        if qmp:
            qmp.close()
        if proc and proc.poll() is None:
            try:
                if pidfd is None:
                    pidfd = os.pidfd_open(proc.pid)
                signal.pidfd_send_signal(pidfd, signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                    proc.wait(timeout=5)
            except BaseException as exc:
                record['owned_stop_error'] = f'{type(exc).__name__}: {exc}'
        if pidfd is not None:
            os.close(pidfd)
        record['qemu_exit_code'] = proc.returncode if proc else None
        record['owned_QEMU_stopped'] = proc is None or proc.poll() is not None
        try:
            record['frozen_inputs_unchanged'] = bool(pins) and inputs(base) == pins
            record['observer_source_unchanged'] = base.sha(Path(__file__).resolve()) == own_source_before
        except BaseException as exc:
            record['frozen_inputs_unchanged'] = False
            record['final_input_error'] = f'{type(exc).__name__}: {exc}'
        if not record['owned_QEMU_stopped'] or not record['frozen_inputs_unchanged'] or not record.get('observer_source_unchanged'):
            record['status'] = 'FAIL'
        record['input_pins'] = {str(p):h for p,h in pins.items()}
        record['preserved_files'] = {str(p.relative_to(out)):base.sha(p) for p in out.iterdir() if p.is_file()}
        (out/'result.json').write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps({'status':record['status'], 'receipt':str(out/'result.json'), 'owned_QEMU_stopped':record['owned_QEMU_stopped']}))
    raise SystemExit(0 if record['status'] == 'PASS_CONSTRUCTION_OBSERVATION_ONLY' else 1)


if __name__ == '__main__':
    main()
