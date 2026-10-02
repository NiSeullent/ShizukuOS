#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise actual kernel main.c with privileged/init/worker host boundaries."""
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
UNIT = HERE / 'tests/test_kernel_entry.c'
FLAGS = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wshadow']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to((ROOT / 'build').resolve()):
        parser.error('--out must be a new directory inside this worktree build/')
    compilers = {}
    for name in ('gcc', 'clang'):
        executable = shutil.which(name)
        if executable is None:
            parser.error('required local compiler missing: ' + name)
        compilers[name] = Path(executable).resolve()
    # Compiler-discovered project closure includes actual .c inclusions and all
    # current entry/header dependencies; no lexical source-only assertion.
    sources = {Path(__file__).resolve(), UNIT}
    discovery = []
    for compiler, executable in compilers.items():
        for kernel in ('32', '64'):
            for standalone in (False, True):
                argv = [str(executable), *FLAGS, '-DTEST_KERNEL' + kernel,
                        *(['-DSHZ_STANDALONE'] if standalone else []), '-MM', str(UNIT)]
                result = subprocess.run(argv, text=True, capture_output=True, timeout=60)
                if result.returncode:
                    raise RuntimeError('dependency discovery failed: ' + result.stderr)
                discovery.append({'argv': argv, 'stdout': result.stdout, 'stderr': result.stderr,
                                  'exit_code': result.returncode})
                dependency_text = result.stdout.replace('\\\n', ' ').split(':', 1)[1]
                for item in shlex.split(dependency_text):
                    path = Path(item).resolve()
                    if not path.is_relative_to(ROOT):
                        raise RuntimeError('unexpected non-project dependency: ' + str(path))
                    sources.add(path)
    def hashes():
        return {str(path.relative_to(ROOT)): digest(path) for path in sorted(sources)}
    def compiler_hashes():
        return {str(path): digest(path) for path in compilers.values()}
    before, compiler_before = hashes(), compiler_hashes()
    out.mkdir(parents=True)
    snapshot = out / 'source-preimage'
    for path in sources:
        destination = snapshot / path.relative_to(ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(path.read_bytes())
        if digest(destination) != before[str(path.relative_to(ROOT))]:
            raise RuntimeError('source changed during preimage capture: ' + str(path))
    report = {'schema': 1, 'passed': False, 'VM_executed': False, 'Windows98_executed': False,
              'scope': 'Actual production kernel entry, privileged/init/runtime worker boundaries substituted; simulated owner lifetime only.',
              'external_dependencies_scope': 'Compiler-discovered project sources and compiler drivers pinned; host system headers/libraries remain compiler environment.',
              'started_utc': datetime.now(timezone.utc).isoformat(),
              'sources_sha256': before, 'compiler_driver_sha256': compiler_before,
              'dependency_discovery': discovery, 'commands': [], 'tests': []}
    def run(argv, label):
        entry = {'argv': list(map(str, argv)), 'label': label}
        report['commands'].append(entry)
        result = subprocess.run(entry['argv'], text=True, capture_output=True, timeout=60)
        entry.update(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)
        (out / (label + '.log')).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(label + ' failed with exit ' + str(result.returncode) + ': ' + result.stderr.strip())
        return result.stdout.strip()
    common = ['foundation-exited', 'foundation-failed', 'foundation-owner-invalid',
              'foundation-owner-hcall-failed', 'diagnostic', 'legacy-tail', 'malformed-nul',
              'partial-tail', 'mixed-profile', 'invalid-channel', 'duplicate-profile']
    try:
        for compiler, executable in compilers.items():
            run([executable, '--version'], compiler + '-version')
            for kernel in ('32', '64'):
                for standalone in (False, True):
                    profile = compiler + '-k' + kernel + ('-standalone' if standalone else '-supervisor')
                    binary = out / profile
                    depfile = out / (profile + '.d')
                    run([executable, *FLAGS, '-DTEST_KERNEL' + kernel,
                         *(['-DSHZ_STANDALONE'] if standalone else []),
                         *(['-fsanitize=address,undefined', '-fno-omit-frame-pointer'] if compiler == 'clang' else []),
                         '-MMD', '-MF', depfile, UNIT, '-o', binary], profile + '-compile')
                    used = depfile.read_text().replace('\\\n', ' ').split(':', 1)[1]
                    for item in shlex.split(used):
                        dependency = Path(item).resolve()
                        if dependency not in sources:
                            raise RuntimeError('compile consumed unpinned source: ' + str(dependency))
                    cases = common + (['legacy-k32-service'] if kernel == '32' else
                                      ['foundation-owner-running', 'foundation-owner-waiting'])
                    total = 0
                    for case in cases:
                        result = run([binary, case], profile + '-' + case)
                        match = re.fullmatch(r'PASS (\d+) actual production entry boundary checks \(([^)]+)\), simulated=(\d+) ms; no VM executed', result)
                        if not match or match[2] != case:
                            raise RuntimeError(profile + ': incomplete or mismatched case evidence')
                        count, simulated = int(match[1]), int(match[3])
                        total += count
                        report['tests'].append({'profile': profile, 'case': case, 'checks': count,
                                                'simulated_ms': simulated, 'result': result})
                    print(profile + ': PASS ' + str(len(cases)) + ' actual entry cases / ' + str(total) + ' assertions; no VM executed')
        after, compiler_after = hashes(), compiler_hashes()
        report.update(sources_sha256_after=after, compiler_driver_sha256_after=compiler_after,
                      inputs_unchanged=before == after and compiler_before == compiler_after)
        if not report['inputs_unchanged']:
            raise RuntimeError('project or compiler source changed during verification')
        report['artifact_sha256'] = {path.name: digest(path) for path in out.iterdir()
                                     if path.is_file() and path.suffix != '.json'}
        report['passed'] = True
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
