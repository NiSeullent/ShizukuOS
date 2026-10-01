#!/usr/bin/env python3
"""Observe the ordinary actual Chromium trial through a private QMP endpoint."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'shizukudos/tests'))
import run_k64_chromium as chromium
from capture_modern_app import QMP


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel', type=Path, required=True)
    p.add_argument('--runtime', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--chromium', type=Path, required=True)
    p.add_argument('--chromium-image', type=Path, required=True)
    p.add_argument('--timeout', type=int, default=180)
    p.add_argument('--guest-timeout', type=int, default=160)
    p.add_argument("--ipc-diagnostic", action="store_true")
    p.add_argument("--multiprocess", action="store_true", help="Use ordinary renderer subprocesses; retain mandatory --no-sandbox")
    args = p.parse_args()
    if not 60 <= args.timeout <= 1200 or not 1 <= args.guest_timeout < args.timeout:
        p.error('bounded host timeout 60..1200 and smaller guest timeout required')
    args.out = args.out.resolve()
    args.out.mkdir(exist_ok=False, parents=True)
    chromium.K64S, chromium.WIN64 = args.kernel.resolve(), args.runtime.resolve()
    inputs = [Path(__file__).resolve(), Path(chromium.__file__),
              chromium.K64S/'boot.elf', chromium.K64S/'KERNEL64S.BIN',
              chromium.WIN64/'WIN64.IMG', args.chromium/'chrome.exe', args.chromium/'chrome.dll']
    before = {str(path.resolve()): digest(path) for path in inputs}
    app_args = chromium.DEFAULT_ARGS
    if args.multiprocess:
        # The normal default now matches the actual passing multiprocess trial.
        # Retain this historical flag without changing the executed arguments.
        assert '--single-process' not in app_args.split()
    assert '--no-sandbox' in app_args.split()
    report = {'status': 'DIAGNOSTIC_RUNNING', 'inputs_before': before,
              'chromium_arguments': app_args, 'multiprocess': '--single-process' not in app_args.split(),
              'app_functionality_verified': False, 'samples': []}
    receipt = args.out/'qmp-diagnostic.json'

    def save():
        temporary = receipt.with_suffix('.tmp')
        temporary.write_text(json.dumps(report, indent=2)+'\n')
        temporary.replace(receipt)

    original_popen = subprocess.Popen
    observers = []
    with tempfile.TemporaryDirectory(prefix='shz-chrome-diag-') as temporary:
        endpoint = Path(temporary)/'qmp.sock'

        class ObservedProcess(original_popen):
            def __init__(self, command, *a, **kw):
                observed = isinstance(command, list) and command and command[0] == chromium.qemu.DEFAULT_QEMU
                if observed:
                    command.extend(['-qmp', f'unix:{endpoint},server=on,wait=off'])
                    report['actual_command'] = list(command)
                super().__init__(command, *a, **kw)
                if observed:
                    report['owned_popen_pid'] = self.pid
                    save()
                    thread = threading.Thread(target=sample, args=(self,), daemon=True)
                    observers.append(thread)
                    thread.start()

        def sample(proc):
            start = time.monotonic()
            connection = None
            try:
                for target in (x for x in (50, 52, 54, 80, 82, 84, 140, 200, 260, 400, 520, 800, 1100) if x < args.timeout-5):
                    while proc.poll() is None and time.monotonic()-start < target:
                        time.sleep(.2)
                    if proc.poll() is not None:
                        break
                    if connection is None:
                        connection = QMP(endpoint)
                    registers = connection.command('human-monitor-command', {'command-line': 'info registers'})
                    rsp = re.search(r'\bRSP=([0-9a-fA-F]{16})\b', registers)
                    item = {'host_elapsed_seconds': round(time.monotonic()-start, 3),
                            'status': connection.command('query-status'),
                            'cpus': connection.command('query-cpus-fast'),
                            'registers': registers,
                            'stack': connection.command('human-monitor-command', {'command-line': 'x/32gx 0x'+rsp[1]}) if rsp else None,
                            'stack_address_from_saved_registers': rsp[1] if rsp else None,
                            'observation_limit': 'Sequential live register and memory reads; guest is not stopped.'}
                    report['samples'].append(item)
                    save()
            except (OSError, RuntimeError, ValueError) as error:
                report['observation_error'] = str(error)
                save()
            finally:
                if connection:
                    connection.close()

        subprocess.Popen = ObservedProcess
        sys.argv = [str(Path(chromium.__file__)), '--chromium', str(args.chromium),
                    '--chromium-image', str(args.chromium_image), '--out', str(args.out),
                    '--timeout', str(args.timeout), '--guest-timeout', str(args.guest_timeout), '--accel', 'kvm',
                    '--args', app_args]
        if args.ipc_diagnostic: sys.argv.append("--ipc-diagnostic")
        try:
            status = chromium.main()
        finally:
            subprocess.Popen = original_popen
            for thread in observers:
                thread.join(timeout=15)
            report['inputs_after'] = {str(path.resolve()): digest(path) for path in inputs}
            report['inputs_unchanged'] = report['inputs_after'] == before
            report['status'] = 'DIAGNOSTIC_COMPLETE_APPLICATION_RESULT_SEPARATE'
            save()
    return status


if __name__ == '__main__':
    raise SystemExit(main())
