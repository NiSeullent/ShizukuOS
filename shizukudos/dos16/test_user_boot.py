#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded DOS10 user boot: no keys before startup, prompt I/O and cold reopen.

Only owned image/VARS copies are written. No networking or physical disks.
This tests the pinned FreeDOS/FreeCOM compatibility bootstrap, not Windows 98.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
MARKERS = {'normal': 'SHZ-DOS10: READY NORMAL', 'recovery': 'SHZ-DOS10: READY RECOVERY'}


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def ordinary(path):
    path = Path(path).expanduser().resolve(strict=True)
    if not stat.S_ISREG(path.stat().st_mode) or Path('/dev') in path.parents:
        raise ValueError('An ordinary file is required; physical devices are refused')
    return path


def send_text(qmp, text):
    names = {' ': 'spc', '.': 'dot', ':': 'shift-semicolon', '\\': 'backslash',
             '>': 'shift-dot', '-': 'minus', '\n': 'ret'}
    for ch in text:
        key = names.get(ch, 'shift-' + ch.lower() if ch.isupper() else ch)
        qmp.hmp('sendkey ' + key + ' 10')
        time.sleep(0.025)


def await_marker(serial, marker, proc, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = serial.read_bytes() if serial.exists() else b''
        if marker.encode() in data:
            return data.decode('ascii', 'replace')
        if proc.poll() is not None:
            break
        time.sleep(0.05)
    raise ValueError('Guest startup/input marker was not reached within the bounded timeout')


def snapshot_failure(tools, qmp, serial, output, result):
    """Best-effort bounded evidence, while the owned guest is still available."""
    snapshot = {'qmp_available': qmp is not None, 'guest_stopped': False,
                'captures': {}, 'errors': {}}
    result['failure_snapshot'] = snapshot

    def capture(name, operation):
        try:
            return True, operation()
        except Exception as exc:
            snapshot['errors'][name] = f'{type(exc).__name__}: {exc}'
            return False, None

    if qmp is None:
        snapshot['errors']['qmp'] = 'QMP unavailable at the time of failure'
    else:
        # Each monitor read has a short socket deadline; guest memory is capped
        # at the first MiB, including the IVT, real-mode stacks and VGA page.
        if getattr(qmp, 'socket', None) is not None:
            capture('qmp_timeout', lambda: qmp.socket.settimeout(2))
        snapshot['guest_stopped'], _ = capture('stop', lambda: qmp.call('stop'))

        def registers():
            state = tools.cpu_state(qmp)
            result['cpu_registers'] = state
            path = output / 'failure-registers.txt'
            path.write_text(state)
            snapshot['captures']['cpu_registers'] = {'path': path.name}
        capture('cpu_registers', registers)

        raw_path = output / 'failure-screen.bin'
        available, raw = capture('vga_raw', lambda: tools.read_guest_memory(qmp, 0xB8000, 4000, raw_path))
        if available:
            snapshot['captures']['vga_raw'] = {'path': raw_path.name, 'address': 0xB8000, 'size': 4000}

            def screen_text():
                screen = tools.decode_text_page(raw)
                result['screen'] = screen
                path = output / 'failure-screen.txt'
                path.write_text('\n'.join(screen) + '\n')
                snapshot['captures']['vga_text'] = {'path': path.name}
            capture('vga_text', screen_text)

        memory_path = output / 'failure-memory-000000-0fffff.bin'
        available, _ = capture('low_memory', lambda: tools.read_guest_memory(qmp, 0, 1 << 20, memory_path))
        if available:
            snapshot['captures']['low_memory'] = {'path': memory_path.name, 'address': 0, 'size': 1 << 20}

    def serial_text():
        result['serial_text'] = serial.read_bytes().decode('ascii', 'replace')
        snapshot['captures']['serial'] = {'path': serial.name}
    capture('serial', serial_text)


def boot(args, tools, disk, output, profile, write_command=None, existing=False):
    output.mkdir()
    serial = output / 'serial.log'
    # Linux AF_UNIX paths are bounded independently of filesystem paths. Keep
    # the socket short even when a portable checkout or evidence path is long.
    sockets = tempfile.TemporaryDirectory(prefix='shzdos10-')
    socket = Path(sockets.name) / 'qmp.sock'
    cmd = [args.qemu, '-name', 'shizuku-dos10-private-test', '-machine', 'q35',
           '-accel', args.accel, '-cpu', 'host' if args.accel == 'kvm' else 'qemu64',
           '-m', '128', '-smp', '2', '-display', 'none', '-monitor', 'none', '-vga', 'std',
           '-drive', f'file={disk},format=raw,if=none,id=d0,cache=writethrough',
           '-device', 'ide-hd,drive=d0,bus=ide.0,bootindex=1',
           '-qmp', f'unix:{socket},server=on,wait=off', '-serial', f'file:{serial}',
           '-net', 'none', '-no-reboot']
    if args.firmware == 'uefi':
        vars_copy = output / 'OVMF_VARS.fd'
        shutil.copyfile(args.firmware_vars, vars_copy)
        cmd += ['-drive', f'if=pflash,unit=0,format=raw,readonly=on,file={args.firmware_code}',
                '-drive', f'if=pflash,unit=1,format=raw,file={vars_copy}']
    result = {'command': cmd, 'profile': profile, 'firmware': args.firmware,
              'pre_start_keyboard_events': 0}
    started = time.monotonic()
    proc = None
    qmp = None
    quit_requested = False
    failure = None
    with (output / 'qemu.stderr').open('wb') as errors:
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=errors)
            qmp = tools.QMP(socket, timeout=min(20, args.timeout))
            log = await_marker(serial, MARKERS[profile], proc, args.timeout)
            if 'SHZ-EXIT:' in log or profile == 'normal' and 'SHZ-DOS10: STARTUP' not in log:
                raise ValueError('Conformance exit or missing normal startup in the user boot')
            if args.firmware == 'uefi':
                position = 0
                markers = (r'BdsDxe: starting Boot\w+', r'csm_bin_base: 0xe0000',
                           r'BIOS proxy ready \(AP \d+\)',
                           r'bootdev: Boot device: PCI 00:1f\.2 type=HDD', re.escape(MARKERS[profile]))
                for pattern in markers:
                    match = re.search(pattern, log[position:])
                    if not match:
                        raise ValueError('UEFI/CSMWrap path marker is absent or out of order: ' + pattern)
                    position += match.end()
            # Reaching a marker is insufficient: type commands through the actual PS/2 keyboard.
            time.sleep(0.2)
            if existing:
                send_text(qmp, 'type USER.OK\n')
                time.sleep(0.2)
            if write_command:
                send_text(qmp, write_command + '\n')
            send_text(qmp, 'SHZREADY.COM P\n')
            log = await_marker(serial, 'SHZ-DOS10: USER PROBE', proc, 15)
            time.sleep(0.2)
            screen_raw = tools.read_guest_memory(qmp, 0xB8000, 4000, output / 'screen.bin')
            screen = tools.decode_text_page(screen_raw)
            (output / 'screen.txt').write_text('\n'.join(screen) + '\n')
            result.update(serial_text=log, screen=screen, cpu_registers=tools.cpu_state(qmp),
                          persistent_prompt=any(('SHZC:\\>' if profile == 'normal' else 'RECOVERYC:\\>') in row for row in screen),
                          reopened_text_seen=not existing or any('DOS10-USER-FILE' in row for row in screen))
            if args.firmware == 'uefi':
                firmware = tools.read_guest_memory(qmp, 0xE0000, 0x20000, output / 'csm-firmware.bin')
                result['guest_CSM_signatures'] = {s.decode(): firmware.find(s) for s in (b'IFE$', b'CSMPPrxy')}
                if any(offset < 0 for offset in result['guest_CSM_signatures'].values()):
                    raise ValueError('Guest BIOS does not carry the real CSM table/proxy signatures')
            if not result['persistent_prompt'] or not result['reopened_text_seen']:
                raise ValueError('Actual permanent prompt or reopened guest file text is missing')
            if args.png:
                from PIL import Image
                ppm, png = output / 'screen.ppm', output / 'screen.png'
                qmp.call('stop')
                try:
                    qmp.call('screendump', {'filename': str(ppm)})
                    with Image.open(ppm) as captured:
                        rgb = captured.convert('RGB')
                        if not any(lo != hi for lo, hi in rgb.getextrema()):
                            raise ValueError('Actual guest screenshot is blank')
                        rgb.save(png)
                        result['screenshot'] = {'path': str(png), 'sha256': digest(png),
                                                'width': rgb.width, 'height': rgb.height}
                finally:
                    qmp.call('cont')
            qmp.call('quit')
            quit_requested = True
        except BaseException as exc:
            failure = exc
            result.update(status='FAIL', error=str(exc), error_type=type(exc).__name__)
            try:
                snapshot_failure(tools, qmp, serial, output, result)
            except BaseException as snapshot_exc:
                result.setdefault('failure_snapshot', {}).setdefault('errors', {})['snapshot'] = (
                    f'{type(snapshot_exc).__name__}: {snapshot_exc}')
            raise
        finally:
            try:
                try:
                    if qmp:
                        qmp.close()
                finally:
                    try:
                        if proc:
                            try:
                                proc.wait(timeout=10 if quit_requested else 0.1)
                            except subprocess.TimeoutExpired:
                                proc.terminate()
                                try:
                                    proc.wait(timeout=5)
                                except subprocess.TimeoutExpired:
                                    proc.kill()
                                    proc.wait(timeout=5)
                    finally:
                        sockets.cleanup()
            except BaseException as cleanup_exc:
                if failure is None:
                    raise
                result['failure_snapshot']['errors']['cleanup'] = f'{type(cleanup_exc).__name__}: {cleanup_exc}'
            finally:
                if failure is not None:
                    result.update(qemu_exit_code=proc.returncode if proc is not None else None,
                                  seconds=round(time.monotonic() - started, 3))
                    try:
                        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
                    except BaseException:
                        # An unwritable evidence directory cannot replace the
                        # original startup/input exception being propagated.
                        pass
    result.update(qemu_exit_code=proc.returncode, seconds=round(time.monotonic() - started, 3))
    if result['qemu_exit_code'] != 0:
        raise ValueError('QEMU did not exit cleanly after the owned test')
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=Path, default=HERE.parents[1])
    p.add_argument('--image', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--qemu', default='/usr/libexec/qemu-kvm')
    p.add_argument('--accel', choices=('tcg', 'kvm'), default='tcg')
    p.add_argument('--firmware', choices=('bios', 'uefi'), default='bios')
    p.add_argument('--firmware-code', type=Path)
    p.add_argument('--firmware-vars', type=Path)
    p.add_argument('--timeout', type=int, default=120)
    p.add_argument('--recovery', action='store_true', help='Also test missing/nonzero startup and SHZSAFE.TAG recovery (BIOS recommended)')
    p.add_argument('--png', action='store_true', help='Keep real QMP guest screenshots as PNG (requires Pillow)')
    args = p.parse_args(argv)
    if args.png:
        try:
            from PIL import Image
        except ImportError:
            p.error('--png requires the installed Pillow screenshot reader')
    if not 10 <= args.timeout <= 600:
        p.error('timeout must be 10..600 seconds')
    image = ordinary(args.image)
    source_hash = digest(image)
    out = args.out.expanduser().resolve()
    if out.exists() or not out.parent.is_dir() or Path('/dev') in out.parents:
        p.error('A new owned output directory with an existing parent is required')
    if args.firmware == 'uefi':
        if not args.firmware_code or not args.firmware_vars:
            p.error('UEFI requires a matching CODE/VARS pair')
        args.firmware_code = ordinary(args.firmware_code)
        args.firmware_vars = ordinary(args.firmware_vars)
    tools_path = args.repo.resolve() / 'shizukudos/tools'
    sys.path.insert(0, str(tools_path))
    import qemu as tools
    import fatimg
    out.mkdir()
    runs = []
    normal = out / 'normal.img'
    shutil.copyfile(image, normal)
    try:
        runs.append(boot(args, tools, normal, out / 'cold-1', 'normal', 'echo DOS10-USER-FILE>USER.OK'))
        if fatimg.read_bytes(fatimg.partition_spec(normal), 'USER.OK') != b'DOS10-USER-FILE\r\n':
            raise ValueError('Guest-created normal file differs in on-disk readback')
        runs.append(boot(args, tools, normal, out / 'cold-2', 'normal', existing=True))
        if fatimg.read_bytes(fatimg.partition_spec(normal), 'USER.OK') != b'DOS10-USER-FILE\r\n':
            raise ValueError('Guest-created file did not survive cold reboot')
        if args.recovery:
            for reason in ('missing', 'nonzero', 'safe-tag'):
                disk = out / ('recovery-' + reason + '.img')
                shutil.copyfile(image, disk)
                spec = fatimg.partition_spec(disk)
                if reason == 'missing':
                    subprocess.run(['mdel', '-i', spec, '::SHZSTART.BAT'], check=True, capture_output=True)
                elif reason == 'safe-tag':
                    flag = out / 'SHZSAFE.TAG'
                    flag.write_bytes(b'recovery host fixture\r\n')
                    fatimg.copy_in(spec, [(flag, 'SHZSAFE.TAG')])
                else:
                    failure = out / 'FAIL.COM'
                    failure.write_bytes(b'\xb8\x01\x4c\xcd\x21')  # mov ax,4c01h; int 21h
                    batch = out / 'FAILSTART.BAT'
                    batch.write_bytes(b'@ECHO OFF\r\nC:\\FAIL.COM\r\n')
                    subprocess.run(['mdel', '-i', spec, '::SHZSTART.BAT'], check=True, capture_output=True)
                    fatimg.copy_in(spec, [(failure, 'FAIL.COM'), (batch, 'SHZSTART.BAT')])
                runs.append(boot(args, tools, disk, out / ('recovery-' + reason), 'recovery', 'echo RECOVERY-OK>RECOV.OK'))
                if fatimg.read_bytes(spec, 'RECOV.OK') != b'RECOVERY-OK\r\n':
                    raise ValueError('Recovery prompt did not support actual guest file creation')
        if digest(image) != source_hash:
            raise ValueError('Original image changed during owned-copy tests')
        result = {'status': 'PASS_DOS10_COMPATIBILITY_USER_BOOT', 'image_sha256': source_hash,
                  'firmware': args.firmware, 'runs': runs, 'source_image_unchanged': True,
                  'physical_USB_tested': False, 'Windows98_executed': False,
                  'complete_MS_DOS_compatibility': False,
                  'Kernel32_Kernel64_WDDMWrapper_native_Windows98_connection_complete': False}
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'status': result['status'], 'runs': len(runs), 'out': str(out)}, indent=2))
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        (out / 'result.json').write_text(json.dumps({'status': 'FAIL', 'error': str(exc), 'completed_runs': runs}, indent=2) + '\n')
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
