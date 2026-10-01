#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Validate bare ANSI exports with unchanged W snapshots/UTF; no VM."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--win64-root', type=Path, required=True)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--native-fixture', type=Path)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    w64 = args.win64_root.resolve()
    candidate = (args.candidate or w64/'kernel32/k32_module_ansi.c').resolve()
    native = (args.native_fixture or w64/'tests/t_module_ansi.c').resolve()
    host = Path(__file__).with_suffix('.c').resolve()
    paths = [candidate, native, host, Path(__file__).resolve(), w64/'kernel32/k32_procinfo.c',
             w64/'kernel32/k32_utf.c', w64/'kernel32/k32.h', w64/'include/nt.h',
             w64/'tests/k32test.h', w64/'crt/shzcrt.h']
    inputs = {path: path.read_bytes() for path in paths}
    source = inputs[candidate].decode()
    assert source.count('#include "k32.h"') == 1 and source.count('#include <tlhelp32.h>') == 1
    source = source.replace('#include "k32.h"', '/* Host supplies platform declarations. */')
    source = source.replace('#include <tlhelp32.h>', '/* Host supplies the actual-width Toolhelp declarations. */')
    utf = inputs[w64/'kernel32/k32_utf.c'].decode()
    assert utf.count('#include "k32.h"') == 1
    utf = utf.replace('#include "k32.h"', '/* Host supplies platform declarations. */')
    provider = inputs[w64/'kernel32/k32_procinfo.c'].decode()
    start = provider.index('typedef struct { ULONG pid, ppid, threads, cls; char name[32]; } k_proc;')
    end_marker = 'K32API BOOL WINAPI Module32NextW(HANDLE h, LPMODULEENTRY32W me) { return module_entry(h, me, 0); }'
    end = provider.index(end_marker, start) + len(end_marker)
    actual_toolhelp = provider[start:end]
    format_start = provider.index('static int format_path(')
    format_end = provider.index('\n}\n', format_start) + 3
    actual_format = provider[format_start:format_end]
    generated = {'module_ansi.inc': source, 'actual_utf.inc': utf,
                 'actual_toolhelp.inc': actual_toolhelp, 'actual_format_path.inc': actual_format}
    args.output_dir.mkdir(parents=True, exist_ok=False)
    runs = []
    overall = True
    with tempfile.TemporaryDirectory(prefix='shz-module-ansi-') as directory:
        temp = Path(directory)
        for name, body in generated.items():
            (temp/name).write_text(body)
            (args.output_dir/name).write_text(body)
        (temp/'test.c').write_bytes(inputs[host])
        for compiler, flags, label in [
                ('gcc', ['-O2'], 'gcc'),
                ('clang', ['-O1', '-g', '-fsanitize=address,undefined',
                           '-fno-sanitize-recover=all', '-fno-omit-frame-pointer'], 'clang-san')]:
            executable = temp/label
            command = [compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-pthread', *flags,
                       '-I', str(temp), str(temp/'test.c'), '-o', str(executable)]
            build = subprocess.run(command, text=True, capture_output=True, timeout=60)
            row = {'label': label, 'compile_command': command, 'compile_returncode': build.returncode,
                   'compile_stdout': build.stdout, 'compile_stderr': build.stderr}
            if build.returncode:
                overall = False
            else:
                run = subprocess.run([str(executable)], text=True, capture_output=True, timeout=60)
                match = re.search(r'MODULE_ANSI_HOST: (\d+) checks PASS', run.stdout)
                row.update(run_returncode=run.returncode, run_stdout=run.stdout, run_stderr=run.stderr,
                           checks=int(match.group(1)) if match else None)
                if run.returncode or not match:
                    overall = False
            runs.append(row)
    flags = ['x86_64-w64-mingw32-gcc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
             '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-I', str(w64/'kernel32'),
             '-I', str(w64/'include'), '-I', str(w64/'tests'), '-I', str(w64/'crt')]
    for path, label, extra in [(candidate, 'native-kernel32', []),
                               (candidate, 'native-kernel32-unicode', ['-DUNICODE']),
                               (native, 'native-fixture', ['-Wno-unused-function'])]:
        output = args.output_dir/(label+'.o')
        command = [*flags, *extra, '-c', str(path), '-o', str(output)]
        build = subprocess.run(command, text=True, capture_output=True, timeout=60)
        row = {'label': label, 'compile_command': command, 'compile_returncode': build.returncode,
               'compile_stdout': build.stdout, 'compile_stderr': build.stderr}
        if build.returncode:
            overall = False
        else:
            row['object_sha256'] = sha(output.read_bytes())
            if path == candidate:
                dump = subprocess.run(['x86_64-w64-mingw32-objdump', '-s', '-j', '.drectve', str(output)],
                                      text=True, capture_output=True, check=True)
                (args.output_dir/(label+'-exports.txt')).write_text(dump.stdout)
                object_data = output.read_bytes()
                assert b'-export:"Module32First"' in object_data and b'-export:"Module32Next"' in object_data
                assert b'-export:"Module32FirstW"' not in object_data and b'-export:"Module32FirstA"' not in object_data
        runs.append(row)
    unchanged = all(path.read_bytes() == data for path, data in inputs.items())
    overall = overall and unchanged
    result = {'status': 'HOST_AND_NATIVE_OBJECT_PASS_ROOT_DLL_GUEST_PENDING' if overall else 'VALIDATION_FAILED',
              'runs': runs, 'source_pins': {str(path): sha(data) for path, data in inputs.items()},
              'sources_unchanged': unchanged,
              'adaptation': 'Candidate header directives only adapted; candidate function bodies and existing UTF body unchanged. Existing complete Toolhelp function region and format_path extracted without edits. Host macro W API adapter only injects oversized/unterminated output after the actual W function executes once.',
              'provider_regions': {'toolhelp_start_line': provider[:start].count('\n') + 1,
                                   'toolhelp_end_line': provider[:end].count('\n') + 1,
                                   'format_start_line': provider[:format_start].count('\n') + 1,
                                   'format_end_line': provider[:format_end].count('\n') + 1},
              'limits': 'Host query/event/heap/lock adapters, synthetic actual-width input records; no DLL linkage, VM/native execution or Steam PASS. Native fixture includes genuine DLL copy/load for actual Unicode names and immutable snapshots.'}
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
