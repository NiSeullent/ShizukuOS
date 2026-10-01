#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Validate explicit PE budgets against the pinned original Chromium core DLL.

Host-only: never maps executable pages, starts a guest or calls target code.
The unchanged default parser and runtime admission policy remain in force.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ARCHIVE_SHA = 'af0a1a5eb80a21ff2364b4974ca254d3a3af0bf087db9f5af4232672cb3a53df'
CORE_SHA = 'f8decffdf2970597ffcab390f583cefeb3f97be697a2422b0a336a2697969158'


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1048576), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-record', type=Path, required=True)
    parser.add_argument('--artifact-dir', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    record_path = args.input_record.resolve(strict=True)
    record_path.relative_to(ROOT / 'build')
    input_record = json.loads(record_path.read_text())
    archive = Path(input_record['archive']).resolve(strict=True)
    core = Path(input_record['file']).resolve(strict=True)
    core.relative_to(ROOT / 'build')
    if (input_record['archive_sha256'] != ARCHIVE_SHA or sha(archive) != ARCHIVE_SHA or
            input_record['member'] != 'chrome-win/chrome.dll' or
            input_record['sha256'] != CORE_SHA or sha(core) != CORE_SHA or
            input_record['bytes'] != 283207168 or core.stat().st_size != 283207168 or
            input_record['entry_points_called'] != 0 or input_record['native_executed']):
        parser.error('exact preserved Chromium 157.0.8080.0 input required')
    artifacts = args.artifact_dir.resolve(strict=True)
    artifacts.relative_to(ROOT / 'build')
    build_path = artifacts / 'build-result.json'
    build = json.loads(build_path.read_text())
    fixture = artifacts / 'PE32FIX.DLL'
    fixture_record = [r for r in build['artifacts'] if Path(r['path']).resolve() == fixture]
    if build['status'] != 'PASS' or len(fixture_record) != 1 or sha(fixture) != fixture_record[0]['sha256']:
        parser.error('exact completed linked fixture required')
    native_key = 'ntwin32/native_loader/native.c'
    if not build.get('sources', {}).get(native_key) or sha(HERE / 'native.c') != build['sources'][native_key]:
        parser.error('native execution source differs from the frozen fixture build')
    output = args.out.resolve()
    output.relative_to(ROOT / 'build')
    if output.exists():
        parser.error('use a fresh output directory')
    clang = shutil.which('clang')
    if not clang:
        parser.error('Clang with address/undefined sanitizer support required')
    compiler = Path(clang).resolve()
    held = [HERE / name for name in ('pe.c', 'pe.h', 'large_image_test.c', 'test_large_images.py')]
    held += [record_path, archive, core, build_path, fixture, compiler, HERE / 'native.c']
    pins = {str(p): sha(p) for p in held}
    output.mkdir(parents=True)
    frozen = output / 'frozen'
    frozen.mkdir()
    for source in held[:4]:
        shutil.copyfile(source, frozen / source.name)
    command = [str(compiler), '--no-default-config', '-std=c11', '-O1', '-g',
               '-Wall', '-Wextra', '-Werror', '-Wno-misleading-indentation',
               '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
               '-fno-omit-frame-pointer', str(frozen / 'pe.c'),
               str(frozen / 'large_image_test.c'), '-o', str(output / 'large-image-test')]
    result = {'status': 'FAIL', 'scope': 'host structural parsing and explicit budgets only',
              'input_pins': pins, 'commands': [command], 'entry_points_called': 0,
              'native_executed': False, 'application_functionality_verified': False,
              'default_file_limit_MiB': 32, 'default_image_limit_MiB': 64,
              'native_execution_source_changed': False, 'runtime_admission_changed': False,
              'default_relocation_limit': 262144, 'opt_in_relocation_ceiling': 8388608}
    try:
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=120)
        (output / 'compile.log').write_text(compiled.stdout + compiled.stderr)
        compiled.check_returncode()
        run = [str(output / 'large-image-test'), str(fixture), str(core)]
        result['commands'].append(run)
        tested = subprocess.run(run, capture_output=True, text=True, timeout=120)
        (output / 'test.log').write_text(tested.stdout + tested.stderr)
        tested.check_returncode()
        result['controls'] = json.loads(tested.stdout)
        if result['controls']['status'] != 'PASS' or any(sha(Path(p)) != v for p, v in pins.items()):
            raise ValueError('controls failed or a held input changed')
        result['status'] = 'PASS'
    except Exception as error:
        result['error'] = str(error)
        raise
    finally:
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'controls': result['controls'],
                      'receipt': str(output / 'result.json')}))


if __name__ == '__main__':
    main()
