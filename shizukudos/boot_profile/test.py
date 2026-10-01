#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host checks of the production boot policy. No VM, media or network access."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to((ROOT / 'build').resolve()) or out.exists():
        parser.error('--out must be a new directory inside this worktree build/')
    sources = [HERE / 'win98_foundation.h', HERE / 'tests/test_win98_foundation.c',
               Path(__file__).resolve(), ROOT / 'shizukudos/abi/shz_abi.h']
    tools = {}
    for name in ('gcc', 'clang'):
        located = shutil.which(name)
        if located is None:
            parser.error('required local compiler missing: ' + name)
        tools[name] = Path(located).resolve()
    def source_hashes():
        return {str(path.relative_to(ROOT)): digest(path) for path in sources}
    def tool_hashes():
        return {str(path): digest(path) for path in tools.values()}
    before, tool_before = source_hashes(), tool_hashes()
    out.mkdir(parents=True)
    report = {'schema': 1, 'passed': False, 'VM_executed': False, 'Windows98_executed': False,
              'started_utc': datetime.now(timezone.utc).isoformat(),
              'scope': 'Production foundation policy, host execution and freestanding compile only; no runtime integration or native guest acceptance.',
              'sources_sha256': before, 'compiler_driver_sha256': tool_before,
              'external_dependencies_scope': 'Host system headers/libraries are compiler environment, not pinned project source.',
              'commands': [], 'tests': []}
    def run(argv, label):
        entry = {'argv': list(map(str, argv)), 'label': label}
        report['commands'].append(entry)
        result = subprocess.run(entry['argv'], text=True, capture_output=True, timeout=60)
        entry.update(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)
        (out / (label + '.log')).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(label + ' failed with exit ' + str(result.returncode))
        return result.stdout.strip()
    flags = ['-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wpedantic', '-Wshadow']
    try:
        for compiler in ('gcc', 'clang'):
            run([tools[compiler], '--version'], compiler + '-version')
            extra = [] if compiler == 'gcc' else ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            for standalone in (False, True):
                label = compiler + ('-standalone' if standalone else '-supervisor')
                binary = out / label
                run([tools[compiler], *flags, *extra, *(['-DSHZ_STANDALONE'] if standalone else []),
                     HERE / 'tests/test_win98_foundation.c', '-o', binary], label + '-compile')
                result = run([binary], label + '-run')
                if not result.startswith('PASS ') or 'no VM executed' not in result:
                    raise RuntimeError(label + ' did not emit complete host-policy evidence')
                report['tests'].append({'profile': label, 'result': result})
                print(label + ': ' + result)
        unit = out / 'freestanding.c'
        unit.write_text('#include "' + str(HERE / 'win98_foundation.h') + '"\n'
                        'int policy(const shz_bootinfo_t *bi) { return shz_win98_foundation_policy(bi); }\n')
        for target in ('i486-unknown-none-elf', 'x86_64-unknown-none-elf'):
            for standalone in (False, True):
                label = target + ('-standalone' if standalone else '-supervisor')
                run([tools['clang'], '-target', target, '-ffreestanding', '-fno-builtin', *flags,
                     *(['-DSHZ_STANDALONE'] if standalone else []), '-c', unit,
                     '-o', out / (label + '.o')], label + '-compile')
                print(label + ': freestanding production header PASS')
        after, tool_after = source_hashes(), tool_hashes()
        report.update(sources_sha256_after=after, compiler_driver_sha256_after=tool_after,
                      inputs_unchanged=before == after and tool_before == tool_after)
        if not report['inputs_unchanged']:
            raise RuntimeError('source or compiler inputs changed during verification')
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
