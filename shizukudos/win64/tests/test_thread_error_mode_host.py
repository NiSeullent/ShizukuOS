#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Test whole production thread-mode bodies with real host threads; no VM."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    w64 = Path(__file__).resolve().parents[1]
    paths = [w64/'ntdll/thread_error_mode.c', w64/'kernel32/k32_thread_error_mode.c',
             w64/'tests/t_thread_error_mode.c', Path(__file__), Path(__file__).with_suffix('.c')]
    snapshots = {p: p.read_bytes() for p in paths}
    productions = []
    for path, include in zip(paths[:2], ['ntdll_int.h', 'k32.h']):
        text = snapshots[path].decode()
        directive = f'#include "{include}"'
        assert text.count(directive) == 1
        productions.append(text.replace(directive, '/* Platform header supplied by the host contract. */'))
    runs = []
    with tempfile.TemporaryDirectory(prefix='shz-thread-error-mode-') as folder:
        temp = Path(folder)
        (temp/'ntdll_thread_error_mode_production.inc').write_text(productions[0])
        (temp/'kernel32_thread_error_mode_production.inc').write_text(productions[1])
        (temp/'test.c').write_bytes(snapshots[paths[4]])
        for compiler, flags, label in [
                ('gcc', ['-O2'], 'gcc'),
                ('clang', ['-O1', '-g', '-fsanitize=address,undefined',
                           '-fno-sanitize-recover=all', '-fno-omit-frame-pointer'], 'clang-san')]:
            exe = temp/label
            command = [compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-pthread', *flags,
                       '-I', str(temp), str(temp/'test.c'), '-o', str(exe)]
            build = subprocess.run(command, text=True, capture_output=True, timeout=60)
            if build.returncode:
                raise SystemExit(build.stdout+build.stderr)
            run = subprocess.run([str(exe)], text=True, capture_output=True, timeout=60)
            if run.returncode:
                raise SystemExit(run.stdout+run.stderr)
            count = int(re.search(r'THREAD_ERROR_MODE_HOST: (\d+) checks PASS', run.stdout).group(1))
            runs.append({'compiler': compiler, 'label': label, 'compile_command': command,
                         'checks': count, 'stdout': run.stdout, 'stderr': run.stderr,
                         'returncode': run.returncode})
    for path, data in snapshots.items():
        assert path.read_bytes() == data, ('Source changed during host validation', str(path))
    args.output_dir.mkdir(parents=True, exist_ok=False)
    for name, text in zip(['ntdll-production.inc', 'kernel32-production.inc'], productions):
        (args.output_dir/name).write_text(text)
    result = {'status': 'HOST_PRODUCTION_CONTRACT_PASS_NATIVE_GUEST_PENDING', 'runs': runs,
              'source_pins': {str(p.relative_to(w64.parent)): hashlib.sha256(data).hexdigest()
                              for p, data in snapshots.items()},
              'adaptation': 'Only the two platform include directives replaced; complete production bodies unchanged.',
              'sources_unchanged': True,
              'limits': 'Host TEB adapter and actual pthread isolation; no guest/app pass, inherited effective process mode, or UI claim.'}
    (args.output_dir/'host-result.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'status': result['status'], 'runs': [{'label': r['label'], 'checks': r['checks']} for r in runs]}))


if __name__ == '__main__':
    main()
