#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded actual Kernel32 allocator host tests; never launches a guest.

Project includes are captured before dependency discovery or compilation. Every
allocator executable consumes those copies. External SDK/support/sanitizer
inputs remain the declared host environment, not a fully sealed toolchain.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
UNIT = ROOT / 'shizukudos/tests/test_k32_memory_concurrency.c'
MEMORY = ROOT / 'shizukudos/kernel32/mem.c'
FLAGS = ['-std=gnu11', '-O2', '-fPIE', '-Wall', '-Wextra', '-Werror',
         '-Wno-int-to-pointer-cast', '-Wno-pointer-to-int-cast', '-pthread']
MODES = ('pmm', 'heap', 'guards', 'mixed-pmm', 'mixed-heap')
CLEANUP_SECONDS = 2.0


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def group_members(pgid):
    """Only the new session/group created for this invocation is owned."""
    members = {}
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            fields = (entry / 'stat').read_text().rsplit(') ', 1)[1].split()
            if int(fields[2]) == pgid and int(fields[3]) == pgid:
                members[int(entry.name)] = {'state': fields[0], 'start': fields[19]}
        except (OSError, IndexError, ValueError):
            continue
    return members


def run_owned(argv, timeout=60):
    """Bound work separately from a <=2s owned-group cleanup/drain/reap.

    Linux subreaping applies only to this host runner process. No shared group
    or unrelated child is signaled/reaped. A terminal parent is insufficient:
    even successful parents may leave children or inherited output pipes.
    """
    proc = None
    output, errors = b'', b''
    timed_out = False
    infrastructure_error = None
    cleanup = {'passed': False, 'limit_seconds': CLEANUP_SECONDS, 'signals': [],
               'reaped_descendants': [], 'owned_pgid': None, 'group_empty': False,
               'drain_complete': False, 'direct_reaped': False}
    leader_start = None
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
            raise OSError(ctypes.get_errno(), 'cannot enable local child subreaper')
        proc = subprocess.Popen(list(map(str, argv)), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True)
        cleanup['owned_pgid'] = proc.pid
        leader_start = group_members(proc.pid).get(proc.pid, {}).get('start')
        output, errors = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        timed_out = True
        output, errors = error.output or b'', error.stderr or b''
    except BaseException as error:
        infrastructure_error = repr(error)
    finally:
        if proc is not None:
            started = time.monotonic()
            deadline = started + CLEANUP_SECONDS
            pgid = proc.pid
            def members():
                found = group_members(pgid)
                # Never signal a reused session leader with a different start.
                if pgid in found and leader_start is not None and found[pgid]['start'] != leader_start:
                    raise RuntimeError('owned group identity changed; refused group signal')
                return found
            def live():
                return {pid: state for pid, state in members().items() if state['state'] != 'Z'}
            try:
                cleanup['descendants_observed'] = sorted(pid for pid in members() if pid != pgid)
                if live():
                    try:
                        os.killpg(pgid, signal.SIGTERM)
                        cleanup['signals'].append('TERM')
                    except ProcessLookupError:
                        pass
                    grace = min(deadline, time.monotonic() + 0.15)
                    while live() and time.monotonic() < grace:
                        time.sleep(0.01)
                if live():
                    try:
                        os.killpg(pgid, signal.SIGKILL)
                        cleanup['signals'].append('KILL')
                    except ProcessLookupError:
                        pass
                try:
                    output, errors = proc.communicate(timeout=max(0.01, deadline - time.monotonic()))
                    cleanup['drain_complete'] = True
                except subprocess.TimeoutExpired as error:
                    output, errors = error.output or output, error.stderr or errors
                    for stream in (proc.stdout, proc.stderr):
                        if stream is not None:
                            stream.close()
                    proc.wait(timeout=max(0.01, deadline - time.monotonic()))
                cleanup['direct_reaped'] = proc.returncode is not None
                while time.monotonic() < deadline:
                    # Negative PID waits only for children in OUR group. The
                    # direct child was reaped by communicate/wait above.
                    while True:
                        try:
                            pid, status = os.waitpid(-pgid, os.WNOHANG)
                        except ChildProcessError:
                            break
                        if not pid:
                            break
                        cleanup['reaped_descendants'].append({'pid': pid, 'status': status})
                    if not members():
                        break
                    time.sleep(0.01)
                cleanup['remaining_group_pids'] = sorted(members())
                cleanup['group_empty'] = not cleanup['remaining_group_pids']
                cleanup['passed'] = (cleanup['group_empty'] and cleanup['drain_complete'] and
                                     cleanup['direct_reaped'])
            except BaseException as error:
                cleanup['error'] = repr(error)
                # Best-effort bounded recovery still uses only the owned identity.
                # A cleanup error remains a rejected invocation even if recovery succeeds.
                try:
                    if live():
                        os.killpg(pgid, signal.SIGKILL)
                        cleanup['signals'].append('KILL-recovery')
                except (OSError, RuntimeError):
                    pass
                for stream in (proc.stdout, proc.stderr):
                    if stream is not None:
                        stream.close()
                try:
                    proc.wait(timeout=max(0.01, deadline - time.monotonic()))
                    cleanup['direct_reaped'] = True
                    while time.monotonic() < deadline:
                        try:
                            pid, status = os.waitpid(-pgid, os.WNOHANG)
                        except ChildProcessError:
                            break
                        if pid:
                            cleanup['reaped_descendants'].append({'pid': pid, 'status': status})
                        elif not members():
                            break
                        else:
                            time.sleep(0.01)
                    cleanup['remaining_group_pids'] = sorted(members())
                    cleanup['group_empty'] = not cleanup['remaining_group_pids']
                except BaseException as recovery_error:
                    cleanup['recovery_error'] = repr(recovery_error)
            cleanup['seconds'] = round(time.monotonic() - started, 3)
        else:
            cleanup.update(passed=True, group_empty=True, drain_complete=True,
                           direct_reaped=True, seconds=0, remaining_group_pids=[])
    decode = lambda value: value.decode(errors='replace') if isinstance(value, bytes) else value or ''
    return {'argv': list(map(str, argv)), 'exit_code': None if timed_out else
            125 if infrastructure_error or not cleanup['passed'] else proc.returncode,
            'parent_exit_code': proc.returncode if proc is not None else None,
            'stdout': decode(output), 'stderr': decode(errors), 'timed_out': timed_out,
            'infrastructure_error': infrastructure_error, 'cleanup': cleanup}


def captured_caller(out, snapshots, origins, production_before, commands):
    """Shared real caller for suite commands and process-lifecycle controls."""
    frozen = out / 'source'
    def stable_sources():
        return (digest(MEMORY) == production_before and
                all(origins[rel].read_bytes() == data and (frozen / rel).read_bytes() == data
                    for rel, data in snapshots.items()))
    def call(argv, label, timeout=60):
        started = time.monotonic()
        if not stable_sources():
            item = {'argv': list(map(str, argv)), 'exit_code': 125,
                    'stdout': '', 'stderr': 'source snapshot mismatch; refused before command\n', 'timed_out': False,
                    'cleanup': {'passed': True, 'not_started': True}}
        else:
            item = run_owned(argv, timeout)
        item['label'] = label
        item['seconds'] = round(time.monotonic() - started, 3)
        item['timeout_seconds'] = timeout
        (out / (label + '.log')).write_text(item['stdout'] + item['stderr'])
        commands.append(item)
        return item
    return call, stable_sources


def validate_summary(stdout, mode):
    """A zero process exit alone cannot certify a missing/truncated/wrong phase."""
    lines = [line for line in stdout.splitlines() if line.startswith('K32_MEMORY_ACTUAL_C')]
    if len(lines) != 1 or stdout.strip() != lines[0]:
        return {'valid': False, 'reason': 'expected exactly one phase summary'}
    line = lines[0]
    pairs = re.findall(r'\b([a-zA-Z_]+)=([^ ;]+)', line)
    fields = dict(pairs)
    if len(fields) != len(pairs):
        return {'valid': False, 'reason': 'duplicate summary field'}
    errors = []
    if fields.get('mode') != mode or not line.endswith('; host-only'):
        errors.append('wrong mode/scope')
    def number(name):
        value = fields.get(name, '')
        if not value.isdecimal():
            errors.append('missing/invalid ' + name)
            return -1
        return int(value)
    count = number('checks')
    if number('failures') != 0:
        errors.append('phase failures')
    if mode == 'guards':
        if count != 162204:
            errors.append('guard check count')
    else:
        if number('owners') != 6 or number('epochs') != 1200:
            errors.append('owner/epoch declaration')
        if mode in ('pmm', 'heap'):
            if count != (42000 if mode == 'pmm' else 34800) or fields.get('IRQ') != 'restored':
                errors.append('producer check count/IRQ')
        else:
            comparisons = number('live_span_comparisons')
            base = (15 if mode == 'mixed-pmm' else 14) * 7200 + 25
            if not 0 <= comparisons <= 36000 or count != base + comparisons:
                errors.append('mixed check count/span comparisons')
            if number('allocations') != 7200 or number('frees') != 7200:
                errors.append('incomplete independent ownership lifecycles')
            if number('peak_host_call_intervals') < 2 or number('overlapping_alloc_free_intervals') <= 0:
                errors.append('no observed overlapping host call intervals')
            if fields.get('IF') != 'on-off-preserved' or number('ledger_allocator_calls') != 0:
                errors.append('IF/ledger boundary')
    return {'valid': not errors, 'reason': '; '.join(errors), 'fields': fields}


def lane_bytes():
    return sum(q.stat().st_size for p in (ROOT / 'build').glob('k32-memory*')
               for q in ([p] if p.is_file() else p.rglob('*')) if q.is_file())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--guards-only', action='store_true')
    selection.add_argument('--mixed-only', action='store_true')
    parser.add_argument('--memory-source', type=Path,
                        help='optional original mem.c copy under this worktree build/; current production is never replaced')
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / 'build'):
        parser.error('output must be a fresh directory under this worktree build/')
    selected_memory = args.memory_source.resolve() if args.memory_source else MEMORY
    if args.memory_source and (not selected_memory.is_file() or not selected_memory.is_relative_to(ROOT / 'build')):
        parser.error('memory-source must be an existing local build/ copy')
    if lane_bytes() >= 64 << 20:
        parser.error('aggregate allocator-lane output budget exhausted')
    out.mkdir(parents=True)
    frozen = out / 'source'
    production_before = digest(MEMORY)
    snapshots, origins = {}, {}
    pending = [UNIT, Path(__file__).resolve()]
    while pending:
        logical = pending.pop().resolve()
        if not logical.is_relative_to(ROOT):
            raise RuntimeError('quoted include escapes project')
        rel = str(logical.relative_to(ROOT))
        if rel in snapshots:
            continue
        origin = selected_memory if logical == MEMORY else logical
        data = origin.read_bytes()
        snapshots[rel] = data
        origins[rel] = origin
        for include in re.findall(rb'^\s*#\s*include\s*"([^"\n]+)"', data, re.M):
            pending.append(logical.parent / include.decode())
    before = {rel: hashlib.sha256(data).hexdigest() for rel, data in sorted(snapshots.items())}
    for rel, data in snapshots.items():
        target = frozen / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    compilers = {name: Path(shutil.which(name)).resolve() for name in ('gcc', 'clang')}
    tools = {str(path): digest(path) for path in compilers.values()}
    (out / 'before.json').write_text(json.dumps({'sources': before,
        'origins': {rel: str(path) for rel, path in origins.items()},
        'compiler_drivers': tools, 'production_memory_sha256': production_before,
        'capture_before_dependency_discovery': True}, indent=2) + '\n')
    commands, dependencies, summaries = [], {}, {}

    call, stable_sources = captured_caller(out, snapshots, origins, production_before, commands)

    # Actual child timeout uses the same kill/reap subprocess boundary; its
    # expected timeout is a host runner control, never an allocator PASS.
    timeout_control = call([sys.executable, '-c', 'import time; time.sleep(5)'], 'timeout-control', timeout=1)
    passed = timeout_control['timed_out'] and timeout_control['seconds'] < 3 and timeout_control['cleanup']['passed']
    for name, compiler in compilers.items():
        result = call([compiler, *FLAGS, '-MM', frozen / UNIT.relative_to(ROOT)], name + '-dependencies')
        if result['exit_code'] != 0 or result['stderr'] or not result['cleanup']['passed']:
            passed = False
            continue
        actual = []
        for token in shlex.split(result['stdout'].replace('\\\n', ' ').split(':', 1)[1]):
            path = Path(token).resolve()
            if not path.is_relative_to(frozen):
                raise RuntimeError('compiler dependency outside captured project tree')
            rel = str(path.relative_to(frozen))
            if rel not in snapshots or digest(path) != before[rel]:
                raise RuntimeError('compiler consumed uncaptured dependency')
            actual.append(rel)
        dependencies[name] = sorted(set(actual))
        binary = out / (name + '-allocator')
        extra = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'] if name == 'clang' else []
        result = call([compiler, *FLAGS, *extra, frozen / UNIT.relative_to(ROOT), '-pie', '-o', binary], name + '-compile')
        if result['exit_code'] != 0 or result['stderr'] or not result['cleanup']['passed']:
            passed = False
            continue
        modes = ('guards',) if args.guards_only else MODES[3:] if args.mixed_only else MODES
        for mode in modes:
            result = call([binary, mode], name + '-' + mode)
            summary = validate_summary(result['stdout'], mode)
            summaries[name + '/' + mode] = summary
            passed &= (result['exit_code'] == 0 and not result['timed_out'] and
                       not result['stderr'] and summary['valid'] and result['cleanup']['passed'])
    after = {rel: digest(path) for rel, path in origins.items()}
    stable = stable_sources() and all(digest(path) == sha for path, sha in tools.items())
    modes = ('guards',) if args.guards_only else MODES[3:] if args.mixed_only else MODES
    expected_summaries = {name + '/' + mode for name in compilers for mode in modes}
    passed &= set(summaries) == expected_summaries
    result = {'status': 'PASS' if passed and stable else 'FAIL',
        'scope': 'Actual C allocators with low host mappings/IRQ adapters; active payload ledger retires before free; host-only.',
        'sources_before': before, 'sources_after': after, 'source_origins': {rel: str(path) for rel, path in origins.items()},
        'compiler_drivers_before': tools, 'compiler_drivers_after': {path: digest(path) for path in tools},
        'production_memory_before': production_before, 'production_memory_after': digest(MEMORY),
        'inputs_unchanged': stable, 'snapshot_before_dependency_discovery': True,
        'actual_project_dependencies': dependencies, 'phase_summaries': summaries,
        'expected_phase_summaries': sorted(expected_summaries), 'timeout_control_passed': bool(timeout_control['timed_out'] and timeout_control['seconds'] < 3 and timeout_control['cleanup']['passed']),
        'commands': commands, 'external_environment_sealed': False, 'guest_executed': False,
        'physical_ap_executed': False, 'generic_page_table_smp_verified': False,
        'artifact_sha256': {str(p.relative_to(out)): digest(p) for p in out.rglob('*') if p.is_file()},
        'owned_output_bytes': sum(p.stat().st_size for p in out.rglob('*') if p.is_file()),
        'aggregate_lane_bytes_before_result': lane_bytes()}
    if lane_bytes() > 64 << 20:
        raise RuntimeError('aggregate allocator-lane output cap exceeded')
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'inputs_unchanged': stable,
                      'outputs': result['owned_output_bytes'], 'result': str(out / 'result.json')}))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
