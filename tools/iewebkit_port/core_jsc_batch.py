#!/usr/bin/env python3
"""Compile missing genuine JSC members into a new, bounded private batch.

SPDX-License-Identifier: MIT
Preserves the historical Ninja tree. This does not link or execute an engine.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shlex
import shutil
import subprocess
import time

from core_archive_receipt import file_pin, private_path
from core_build import runtime_link_input, terminate_owned_build_session
from core_link_jsc import caller_dependency_command, caller_dependency_paths, DEPENDENCY_TARGET

FLOOR = 20 * 1024**3
LIMIT = 128 * 1024**2


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (180, 180))
    resource.setrlimit(resource.RLIMIT_AS, (6 * 1024**3, 6 * 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024**2, 64 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--count', type=int, default=4, choices=range(1, 9))
    args = parser.parse_args()
    work = args.work.resolve(strict=True)
    build = private_path(work / 'build-jsc-win9x', work)
    output = private_path(args.output, work, exists=False)
    if output.exists() or shutil.disk_usage(work).free < FLOOR + 256 * 1024**2 + LIMIT:
        raise ValueError('Require a new output and the unchanged floor plus batch allowance')
    output.mkdir(mode=0o700)
    (output / 'tmp').mkdir()
    observed = {}

    def observe(path):
        path = Path(path).resolve(strict=True)
        if str(path) not in observed:
            observed[str(path)] = file_pin(path)
        return observed[str(path)][0]

    report = {'schema': 'iewebkit-genuine-jsc-compile-batch-v1', 'members': [], 'steps': [],
        'limits': {'floor_bytes': FLOOR, 'output_bytes': LIMIT, 'cpu_seconds_per_compiler': 180,
                   'address_space_bytes': 6 * 1024**3, 'batch_wall_seconds': 900, 'workers': 1},
        'linked_engine': False, 'native_execution': False, 'provider_rendering_gpu_pass': False,
        'historical_tree_written': False,
        'link_profile': 'Old generated link rule is not certified; v5 regeneration required before linking.'}
    receipt = output / 'batch.json'
    started = time.monotonic()
    minimum_free = shutil.disk_usage(work).free

    def save():
        report['minimum_free_bytes'] = minimum_free
        receipt.write_text(json.dumps(report, indent=2) + '\n')

    def guard():
        nonlocal minimum_free
        minimum_free = min(minimum_free, shutil.disk_usage(work).free)
        total = sum(p.stat().st_size for p in output.rglob('*') if p.is_file())
        if minimum_free < FLOOR or total > LIMIT or time.monotonic() - started > 900:
            raise RuntimeError('Owned JSC batch reached its floor/output/wall bound')

    def check_inputs():
        for name, pin in observed.items():
            if file_pin(Path(name)) != pin:
                raise ValueError('Actual compiler/config/source/header input changed: ' + name)

    def run(argv, name):
        guard()
        log = output / (name + '.log')
        env = dict(os.environ, TMPDIR=str(output / 'tmp'))
        with log.open('wb') as stream:
            child = subprocess.Popen(argv, cwd=build, env=env, stdout=stream, stderr=subprocess.STDOUT,
                                     start_new_session=True, preexec_fn=limits)
            try:
                while child.poll() is None:
                    time.sleep(.5)
                    guard()
            except BaseException:
                terminate_owned_build_session(child)
                raise
        row = {'argv': argv, 'cwd': str(build), 'returncode': child.returncode,
               'log': observe(log)}
        report['steps'].append(row)
        save()
        if child.returncode:
            raise RuntimeError('Actual genuine source compile failed: ' + str(log))
        return log

    try:
        for p in [Path(__file__), build / 'build.ninja', build / 'compile_commands.json',
                  build / 'cmakeconfig.h', build / 'CMakeCache.txt']:
            observe(p)
        config = (build / 'cmakeconfig.h').read_text()
        for macro, value in {'IEWEBKIT_WIN9X': 1, 'USE_WINDOWS_EVENT_LOOP': 1,
                'ENABLE_C_LOOP': 1, 'ENABLE_JIT': 0, 'ENABLE_WEBASSEMBLY': 0,
                'ENABLE_DFG_JIT': 0, 'ENABLE_FTL_JIT': 0, 'ENABLE_STATIC_JSC': 1}.items():
            if ('#define ' + macro + ' ' + str(value)) not in config.splitlines():
                raise ValueError('Current actual generated compiler profile differs: ' + macro)
        runtime_object, binding = runtime_link_input(args.runtime)
        report['current_paired_runtime'] = binding
        for row in binding['input_pins']:
            if observe(Path(row['path']))['sha256'] != row['sha256']:
                raise ValueError('Current paired runtime changed')
        graph = (build / 'build.ninja').read_text().replace('$\n', '')
        rules = [line for line in graph.splitlines() if line.startswith('build lib/libJavaScriptCore.a: ')]
        if len(rules) != 1:
            raise ValueError('Require the exact genuine JSC archive rule')
        tokens = shlex.split(rules[0].split(': ', 1)[1])[1:]
        targets = []
        for token in tokens:
            if token in ('|', '||'):
                break
            if not token.endswith(('.obj', '.o')) or '$' in token:
                raise ValueError('Unsupported genuine archive member')
            targets.append(token)
        pending = [target for target in targets if not (build / target).exists()]
        report['historical_inventory'] = {'archive_members': len(targets),
                'existing_members': len(targets) - len(pending), 'remaining_members': len(pending)}
        entries = json.loads((build / 'compile_commands.json').read_text())
        selected = []
        for target in pending[:args.count]:
            candidates = [entry for entry in entries if (' -o ' + target + ' -c ') in entry.get('command', '')]
            if len(candidates) != 1:
                raise ValueError('Actual missing-member compiler command is ambiguous: ' + target)
            entry = candidates[0]
            argv = shlex.split(entry['command'])
            if Path(entry['directory']).resolve() != build or argv.count('-o') != 1 or argv.count('-c') != 1:
                raise ValueError('Compiler source/output/cwd selection differs')
            source = private_path(Path(argv[argv.index('-c') + 1]), work)
            observe(source)
            observe(Path(argv[0]))
            for tool in ['cc1plus', 'as']:
                selected_tool = subprocess.run([argv[0], '-print-prog-name=' + tool], check=True,
                        text=True, capture_output=True).stdout.strip()
                observe(Path(selected_tool) if '/' in selected_tool else Path(shutil.which(selected_tool)))
            dest = output / (str(len(selected)).zfill(2) + '-' + source.name + '.obj')
            argv[argv.index('-o') + 1] = str(dest)
            selected.append((target, source, dest, argv))
        save()
        for index, (target, source, dest, argv) in enumerate(selected):
            query_log = run(caller_dependency_command(argv), str(index) + '-dependencies')
            dependencies = caller_dependency_paths(query_log.read_text(), build)
            if source not in dependencies:
                raise ValueError('Actual source missing from preprocessor dependencies')
            for path in dependencies:
                observe(path)
            check_inputs()
            dep = output / (dest.name + '.d')
            run([*argv, '-MD', '-MF', str(dep), '-MT', DEPENDENCY_TARGET], str(index) + '-compile')
            if set(caller_dependency_paths(dep.read_text(), build)) != set(dependencies):
                raise ValueError('Actual compile dependency closure changed')
            check_inputs()
            report['members'].append({'target': target, 'source': observe(source),
                    'object': observe(dest), 'dependency_file': observe(dep),
                    'compiler_input_count': len(dependencies)})
            report['immutable_inputs'] = [pin[0] for pin in observed.values()]
            save()
            print(json.dumps({'compiled': len(report['members']), 'target': target}), flush=True)
        check_inputs()
        guard()
        report['compile_batch_passed'] = True
    except BaseException as error:
        report['failure'] = str(error)
        report['compile_batch_passed'] = False
        raise
    finally:
        report['immutable_inputs'] = [pin[0] for pin in observed.values()]
        save()
    print(json.dumps({'receipt': str(receipt), 'compiled': len(report['members']),
                     'minimum_free_bytes': minimum_free}), flush=True)


if __name__ == '__main__':
    main()
