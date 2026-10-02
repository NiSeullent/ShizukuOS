#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Source-bound host execution of actual subsys64 pump_slot; no VM or NAS."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
UNIT = HERE / 'tests/test_native_worker_reap_fada.c'
FLAGS = ['-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
         '-ffunction-sections', '-fdata-sections']
CASES = ('teardown-not-started', 'teardown-in-progress', 'threads-still-alive',
         'process-still-running', 'teardown-complete', 'killed-process-complete', 'teardown-progresses',
         'PMA-cancellation-pending-reap')
RED_CASES = {'teardown-not-started', 'teardown-in-progress', 'teardown-progresses', 'PMA-cancellation-pending-reap'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dependencies(text):
    return {Path(word).resolve() for word in shlex.split(text.replace('\\\n', ' ').split(':', 1)[1])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--expect-red', action='store_true')
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to((ROOT / 'build').resolve()):
        parser.error('--out must be a new owned local directory inside this worktree build/')
    tools = {name: Path(shutil.which(name) or name).resolve(strict=True) for name in ('gcc', 'clang')}
    source_paths = {Path(__file__).resolve(), UNIT}
    discovery = []
    for compiler, executable in tools.items():
        argv = [str(executable), *FLAGS, '-MM', str(UNIT)]
        result = subprocess.run(argv, text=True, capture_output=True, timeout=60)
        if result.returncode:
            raise RuntimeError('dependency discovery failed: ' + result.stderr)
        discovered = dependencies(result.stdout)
        if any(not path.is_relative_to(ROOT) for path in discovered):
            raise RuntimeError('unexpected non-project dependency')
        source_paths.update(discovered)
        discovery.append({'compiler': compiler, 'argv': argv, 'stdout': result.stdout})
    def source_hashes():
        return {str(path.relative_to(ROOT)): digest(path) for path in sorted(source_paths)}
    def tool_hashes():
        return {str(path): digest(path) for path in tools.values()}
    before, tool_before = source_hashes(), tool_hashes()
    out.mkdir(parents=True)
    for source in source_paths:
        destination = out / 'source-preimage' / source.relative_to(ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
        if digest(destination) != before[str(source.relative_to(ROOT))]:
            raise RuntimeError('source changed while capturing input snapshot')
    report = {'schema': 1, 'passed': False, 'red_confirmed': False,
              'VM_executed': False, 'Windows98_executed': False,
              'scope': 'Actual native pump_slot body and IPC event framing; scheduler/proc_wait/IRQ/notify boundaries modeled. No owner loop, VM, Windows or NAS execution.',
              'external_dependencies_scope': 'Compiler-discovered project dependencies and compiler drivers pinned; system headers/libraries remain host environment.',
              'started_utc': datetime.now(timezone.utc).isoformat(),
              'sources_sha256': before, 'compiler_driver_sha256': tool_before,
              'dependency_discovery': discovery, 'commands': [], 'tests': []}
    def execute(argv, label):
        result = subprocess.run(list(map(str, argv)), text=True, capture_output=True, timeout=60)
        (out / (label + '.log')).write_text(result.stdout + result.stderr)
        report['commands'].append({'argv': list(map(str, argv)), 'label': label,
                                   'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
        return result
    try:
        for compiler, executable in tools.items():
            binary, depfile = out / compiler, out / (compiler + '.d')
            extra = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'] if compiler == 'clang' else []
            result = execute([executable, *FLAGS, *extra, '-MMD', '-MF', depfile,
                              UNIT, '-Wl,--gc-sections', '-o', binary], compiler + '-compile')
            if result.returncode:
                raise RuntimeError(compiler + ' compile failed: ' + result.stderr)
            if not dependencies(depfile.read_text()).issubset(source_paths):
                raise RuntimeError('compile consumed unpinned project source')
            for case in CASES:
                result = execute([binary, case], compiler + '-' + case)
                red = args.expect_red and case in RED_CASES
                valid = (result.returncode == 1 and 'FAIL native worker reap boundary:' in result.stderr
                         and 'unfinished=1 teardown=' in result.stderr) if red else (
                         result.returncode == 0 and re.fullmatch(
                             r'PASS \d+ actual native worker reap checks \(' + re.escape(case) +
                             r'\); scheduler/reap/IRQ boundaries modeled; no VM\n', result.stdout) is not None)
                report['tests'].append({'compiler': compiler, 'case': case, 'expected_red': red,
                                        'expected_behavior': valid, 'returncode': result.returncode})
                if not valid:
                    raise RuntimeError(compiler + ': unexpected case behavior: ' + case)
                print(compiler + ': ' + ('RED confirmed ' if red else 'PASS ') + case, flush=True)
        after, tool_after = source_hashes(), tool_hashes()
        report.update(sources_sha256_after=after, compiler_driver_sha256_after=tool_after,
                      inputs_unchanged=before == after and tool_before == tool_after)
        if not report['inputs_unchanged']:
            raise RuntimeError('source/compiler changed during verification')
        report['artifact_sha256'] = {path.name: digest(path) for path in out.iterdir()
                                     if path.is_file() and path.suffix != '.json'}
        report['red_confirmed'] = args.expect_red
        report['passed'] = not args.expect_red
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
