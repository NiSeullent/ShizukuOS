#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Test real native hypercall codegen with modeled privileged register replies."""
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
UNIT = HERE / 'tests/test_hcall_registers.c'
CASES = ('domain-state', 'channel-info', 'domain-error', 'time-64', 'null-result')
WARNINGS = ['-std=gnu11', '-g', '-Wall', '-Wextra', '-Werror', '-Wshadow']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dependencies(output):
    return [Path(p).resolve() for p in shlex.split(output.replace('\\\n', ' ').split(':', 1)[1])]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to((ROOT / 'build').resolve()):
        parser.error('--out must be a new directory inside this worktree build/')
    tools = {}
    for name in ('gcc', 'clang', 'objdump', 'nm'):
        executable = shutil.which(name)
        if executable is None:
            parser.error('required local tool missing: ' + name)
        tools[name] = Path(executable).resolve()
    profiles = []
    for compiler in ('gcc', 'clang'):
        for optimization in ('O2', 'O3'):
            profiles.append((compiler + '-' + optimization, compiler, ['-' + optimization]))
    profiles.append(('clang-O2-asan', 'clang', ['-O2', '-fsanitize=address,undefined', '-fno-omit-frame-pointer']))
    free_profiles = []
    for compiler in ('gcc', 'clang'):
        for arch, target in (('i486', ['-m32', '-march=i486']), ('x64', ['-m64', '-mno-red-zone'])):
            for standalone in (False, True):
                label = compiler + '-' + arch + ('-standalone' if standalone else '-native')
                flags = ['-O2', '-ffreestanding', '-fno-pic', '-fno-pie', '-fno-stack-protector',
                         '-DSHZ_HCALL_COMPILE_ONLY', *target,
                         *(['-DSHZ_STANDALONE'] if standalone else [])]
                free_profiles.append((label, compiler, flags, standalone))
    sources = {Path(__file__).resolve(), UNIT,
               ROOT / 'shizukudos/supervisor/src/domain.c',
               ROOT / 'shizukudos/supervisor/src/vmx_asm.asm'}
    discovery = []
    for _, compiler, flags in profiles + [(label, compiler, flags) for label, compiler, flags, _ in free_profiles]:
        argv = [str(tools[compiler]), *WARNINGS, *flags, '-MM', str(UNIT)]
        result = subprocess.run(argv, text=True, capture_output=True, timeout=30)
        discovery.append({'argv': argv, 'exit_code': result.returncode,
                          'stdout': result.stdout, 'stderr': result.stderr})
        if result.returncode:
            raise RuntimeError('dependency discovery failed: ' + result.stderr)
        for path in dependencies(result.stdout):
            if not path.is_relative_to(ROOT):
                raise RuntimeError('unexpected external project dependency: ' + str(path))
            sources.add(path)
    before = {str(p.relative_to(ROOT)): digest(p) for p in sorted(sources)}
    tool_before = {name: {'path': str(p), 'sha256': digest(p)} for name, p in tools.items()}
    out.mkdir(parents=True)
    for path in sources:
        copy = out / 'source-preimage' / path.relative_to(ROOT)
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_bytes(path.read_bytes())
        if digest(copy) != before[str(path.relative_to(ROOT))]:
            raise RuntimeError('source changed during capture: ' + str(path))
    report = {'schema': 1, 'passed': False, 'VM_executed': False, 'Windows98_executed': False,
              'scope': 'Actual khc.h VMCALL with host SIGILL/SIGSEGV register boundary; current dispatcher replies modeled, no VM executed. i486 is compile/disassembly only.',
              'external_dependencies_scope': 'Compiler-discovered project dependencies and reviewed dispatcher/entry assembly captured; system headers/libraries/compiler firmware are not fully pinned.',
              'started_utc': datetime.now(timezone.utc).isoformat(),
              'sources_sha256': before, 'tools': tool_before,
              'dependency_discovery': discovery, 'commands': [], 'tests': [], 'freestanding': []}

    def run(argv, label, allow_failure=False):
        entry = {'argv': list(map(str, argv)), 'label': label}
        report['commands'].append(entry)
        result = subprocess.run(entry['argv'], text=True, capture_output=True, timeout=30)
        entry.update(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)
        (out / (label + '.log')).write_text(result.stdout + result.stderr)
        if result.returncode and not allow_failure:
            raise RuntimeError(label + ' failed: ' + result.stderr.strip())
        return result

    def check_dependencies(depfile):
        if any(p not in sources for p in dependencies(depfile.read_text())):
            raise RuntimeError('compiler consumed uncaptured project dependency')

    try:
        for name, tool in tools.items():
            run([tool, '--version'], name + '-version')
        for label, compiler, flags in profiles:
            binary, depfile = out / label, out / (label + '.d')
            run([tools[compiler], *WARNINGS, *flags, '-MMD', '-MF', depfile,
                 UNIT, '-o', binary], label + '-compile')
            check_dependencies(depfile)
            for case in CASES:
                result = run([binary, case], label + '-' + case, allow_failure=True)
                expected = 'PASS ' + case + ': 6 real-helper checks, dispatcher register replies modeled; no VM executed'
                passed = result.returncode == 0 and result.stdout.strip() == expected and not result.stderr
                report['tests'].append({'profile': label, 'case': case, 'passed': passed,
                                        'checks': 6 if passed else 0, 'exit_code': result.returncode,
                                        'stdout': result.stdout, 'stderr': result.stderr})
            failures = [t['case'] for t in report['tests'] if t['profile'] == label and not t['passed']]
            print(label + ': ' + ('FAIL ' + ', '.join(failures) if failures else 'PASS 5 cases / 30 checks') + '; no VM executed')
        for label, compiler, flags, standalone in free_profiles:
            obj, depfile = out / (label + '.o'), out / (label + '.d')
            run([tools[compiler], *WARNINGS, *flags, '-MMD', '-MF', depfile,
                 '-c', UNIT, '-o', obj], label + '-compile')
            check_dependencies(depfile)
            disassembly = run([tools['objdump'], '-dr', obj], label + '-disassembly').stdout
            undefined = run([tools['nm'], '-u', obj], label + '-undefined').stdout
            vmcalls = len(re.findall(r'\bvmcall\b', disassembly))
            if standalone:
                if vmcalls or not re.fullmatch(r'\s*U shz_standalone_hcall\s*', undefined):
                    raise RuntimeError(label + ': standalone forwarding changed')
            elif vmcalls != 2 or undefined.strip():
                raise RuntimeError(label + ': native VMCALL/codegen closure invalid')
            report['freestanding'].append({'profile': label, 'passed': True,
                                           'vmcall_instructions': vmcalls,
                                           'undefined_symbols': undefined.strip()})
            print(label + ': PASS compile/disassembly; no guest executed')
        report['sources_sha256_after'] = {str(p.relative_to(ROOT)): digest(p) for p in sorted(sources)}
        report['tools_after'] = {name: {'path': str(p), 'sha256': digest(p)} for name, p in tools.items()}
        report['inputs_unchanged'] = before == report['sources_sha256_after'] and tool_before == report['tools_after']
        if not report['inputs_unchanged']:
            raise RuntimeError('captured project source or tool changed during verification')
        report['artifact_sha256'] = {p.name: digest(p) for p in out.iterdir()
                                     if p.is_file() and p.suffix != '.json'}
        report['passed'] = all(t['passed'] for t in report['tests'])
        if not report['passed']:
            raise RuntimeError('caller live values corrupted by production hypercall constraints')
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
