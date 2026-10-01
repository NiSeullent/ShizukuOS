#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Verify complete CreateDirectoryEx bodies and strict AMD64 objects; no VM."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--win64-root', type=Path, required=True)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--native-fixture', type=Path)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    w64 = args.win64_root.resolve()
    candidate = (args.candidate or w64/'kernel32/k32_directory_template.c').resolve()
    native = (args.native_fixture or w64/'tests/t_directory_template.c').resolve()
    host = Path(__file__).with_suffix('.c').resolve()
    script = Path(__file__).resolve()
    utf = w64/'kernel32/k32_utf.c'
    paths = [candidate, native, host, script, utf, w64/'kernel32/k32.h',
             w64/'include/nt.h', w64/'tests/k32test.h', w64/'crt/shzcrt.h']
    inputs = {path: path.read_bytes() for path in paths}
    args.output_dir.mkdir(parents=True, exist_ok=False)
    runs = []
    overall = True
    productions = []
    for path in [candidate, utf]:
        source = inputs[path].decode()
        directive = '#include "k32.h"'
        assert source.count(directive) == 1
        productions.append(source.replace(directive, '/* Platform header supplied by the host contract. */'))
    with tempfile.TemporaryDirectory(prefix='shz-directory-template-') as folder:
        temp = Path(folder)
        for name, source in zip(['directory_template_production.inc', 'actual_utf_production.inc'], productions):
            (temp/name).write_text(source)
            (args.output_dir/name).write_text(source)
        (temp/'test.c').write_bytes(inputs[host])
        for compiler, flags, label in [
                ('gcc', ['-O2'], 'gcc'),
                ('clang', ['-O1', '-g', '-fsanitize=address,undefined',
                           '-fno-sanitize-recover=all', '-fno-omit-frame-pointer'], 'clang-san')]:
            executable = temp/label
            command = [compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', *flags,
                       '-I', str(temp), str(temp/'test.c'), '-o', str(executable)]
            build = subprocess.run(command, text=True, capture_output=True, timeout=60)
            record = {'label': label, 'compile_command': command, 'compile_returncode': build.returncode,
                      'compile_stdout': build.stdout, 'compile_stderr': build.stderr}
            if build.returncode:
                overall = False
            else:
                run = subprocess.run([str(executable)], text=True, capture_output=True, timeout=60)
                record.update(run_returncode=run.returncode, run_stdout=run.stdout, run_stderr=run.stderr)
                match = re.search(r'DIRECTORY_TEMPLATE_HOST: (\d+) checks PASS', run.stdout)
                record['checks'] = int(match.group(1)) if match else None
                if run.returncode or not match:
                    overall = False
            runs.append(record)
    native_flags = ['x86_64-w64-mingw32-gcc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
                    '-I', str(w64/'kernel32'), '-I', str(w64/'include'),
                    '-I', str(w64/'tests'), '-I', str(w64/'crt')]
    for source, label, extra in [(candidate, 'native-kernel32', []),
                                 (native, 'native-fixture', ['-Wno-unused-function'])]:
        output = args.output_dir/(label+'.o')
        command = [*native_flags, *extra, '-c', str(source), '-o', str(output)]
        build = subprocess.run(command, text=True, capture_output=True, timeout=60)
        record = {'label': label, 'compile_command': command, 'compile_returncode': build.returncode,
                  'compile_stdout': build.stdout, 'compile_stderr': build.stderr}
        if build.returncode:
            overall = False
        else:
            record['object_sha256'] = digest(output.read_bytes())
        runs.append(record)
    unchanged = all(path.read_bytes() == data for path, data in inputs.items())
    overall = overall and unchanged
    result = {'status': 'HOST_AND_STRICT_NATIVE_OBJECT_PASS_ROOT_DLL_GUEST_PENDING' if overall else 'VALIDATION_FAILED',
              'runs': runs, 'source_pins': {str(path): digest(data) for path, data in inputs.items()},
              'sources_unchanged': unchanged,
              'host_adaptation': 'Only the candidate and existing UTF source k32.h include directives replaced; full function bodies unchanged.',
              'native_fixture_warning_suppression': 'Wno-unused-function only for pre-existing unused static helpers in k32test.h.',
              'limits': 'Host filesystem model with actual existing UTF conversion, native object compilation only; no DLL linkage, VM, native fixture execution or Office PASS.'}
    (args.output_dir/'validation-result.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'status': result['status'], 'runs': [{'label': r['label'], 'compile_returncode': r['compile_returncode'],
                    'run_returncode': r.get('run_returncode'), 'checks': r.get('checks')} for r in runs]}))
    if not overall:
        for run in runs:
            if run['compile_returncode'] or run.get('run_returncode'):
                print(run.get('compile_stderr', ''), run.get('run_stderr', ''))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
