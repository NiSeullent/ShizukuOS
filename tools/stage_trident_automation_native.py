#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze three opt-in native inputs and their verified sources; launch nothing."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
from verify_trident_automation_native import (
    AUTOMATION_SOURCES, OBSERVER_SOURCES, RUNTIME_SOURCES, RUNTIME_EXPORTS,
    artifact, build_logs, prepared_sources, read, receipt, sources,
)

ROOT = Path(__file__).resolve().parents[1]
BOOT_BUILD = Path('/root/Win98-Modern-boot/build')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(read(path, 16 * 1024 ** 2)).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for label in ('automation', 'runtime', 'observer'):
        parser.add_argument('--' + label + '-receipt', type=Path, required=True)
        parser.add_argument('--' + label + '-sha256', required=True)
    parser.add_argument('--stage', type=Path, required=True)
    args = parser.parse_args()
    stage = args.stage.absolute()
    require(stage == stage.resolve() and stage.parent.resolve() == BOOT_BUILD.resolve() and not stage.exists()
            and not stage.is_symlink(), 'select a fresh direct child of owned boot build')
    receipts, paths, merged, copies = {}, {}, {}, {}
    for label in ('automation', 'runtime', 'observer'):
        path = getattr(args, label + '_receipt').absolute()
        expected = getattr(args, label + '_sha256')
        require(path.resolve().is_relative_to((ROOT / 'build').resolve()), 'receipt outside owned build')
        r = receipt(path, expected, 16 * 1024 ** 2)
        require(r.get('passed') is True, 'receipt did not pass: ' + label)
        expected_sources = {'automation': AUTOMATION_SOURCES,
                            'runtime': RUNTIME_SOURCES,
                            'observer': OBSERVER_SOURCES}[label]
        require(set(r['source_sha256']) == expected_sources, 'unexpected build source profile')
        sources(r, expected_sources, path.parent / 'source', merged)
        build_logs(r, path.parent)
        for name, sha in r['source_sha256'].items():
            relative = Path(name)
            require(not relative.is_absolute() and '..' not in relative.parts, 'invalid source path')
            source = path.parent / 'source' / relative
            require(source.resolve().is_relative_to((path.parent / 'source').resolve())
                    and digest(source) == sha, 'frozen source pin mismatch: ' + name)
            require(digest(ROOT / relative) == sha, 'current source drift: ' + name)
            require(name not in merged or merged[name] == sha, 'conflicting shared source ABI: ' + name)
            merged[name] = sha
            copies['source/' + name] = (source, sha)
        step_names = set()
        for step in r['steps']:
            log = Path(step['log'])
            require(log.resolve().is_relative_to(path.parent.resolve())
                    and type(step['returncode']) is int and step['returncode'] == 0
                    and digest(log) == step['sha256'], 'build step/log failed')
            require(log.name not in step_names, 'duplicate step-log basename')
            step_names.add(log.name)
            copies['build-logs/' + label + '/' + log.name] = (log, step['sha256'])
        receipts[label], paths[label] = r, path
        copies[label + '-build.json'] = (path, expected)
    require(receipts['automation'].get('kind') == 'genuine-mshtml-automation-component-build', 'wrong Automation receipt')
    require(receipts['runtime'].get('profile') == 'bounded-local-trident-quickjs-v1', 'wrong runtime receipt')
    require(receipts['observer'].get('kind') == 'win98-trident-owned-child-observer-build', 'wrong observer receipt')
    require(all(type(receipts[label].get('schema')) is int and receipts[label]['schema'] == 1
                for label in ('automation', 'observer')), 'unexpected component receipt schema')
    require(isinstance(receipts['observer'].get('nonce'), str)
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', receipts['observer']['nonce']),
            'invalid observer nonce')
    profile = receipts['observer'].get('profiles', {}).get('automation')
    require(isinstance(profile, dict) and all(profile.get(k) == v for k, v in {
        'self': 'C:\\GOPLAB\\M98AURUN.EXE', 'supervisor_log': 'C:\\GOPLAB\\AURUN.LOG',
        'child_stdout': 'C:\\GOPLAB\\AUOUT.LOG', 'child': 'C:\\GOPLAB\\M98AUTPR.EXE',
        'child_log': 'C:\\GOPLAB\\AUT13.LOG', 'child_timeout_ms': 240000,
        'reap_timeout_ms': 5000}.items()), 'observer path/deadline profile differs')
    runtime = receipts['runtime']
    prepared_sources(runtime, paths['runtime'].parent / 'prepared')
    for name, sha in runtime['prepared_sha256'].items():
        source = Path(name)
        base = paths['runtime'].parent / 'prepared'
        require(source.resolve().is_relative_to(base.resolve()) and digest(source) == sha,
                'prepared runtime source pin mismatch')
        copies['runtime-prepared/' + str(source.relative_to(base))] = (source, sha)
    selected = paths['runtime'].parent / 'selected.h'
    require(hashlib.sha256(read(selected, 65536)).hexdigest()
            == runtime['embedded_fixture_header_sha256'], 'embedded fixture pin mismatch')
    copies['runtime-selected.h'] = (selected, digest(selected))
    inputs = []
    for label, filename in (('automation', 'M98AUTPR.EXE'), ('runtime', 'M98QJS.DLL'), ('observer', 'M98AURUN.EXE')):
        row = receipts[label]['artifacts'][filename]
        source = paths[label].parent / filename
        require(row.get('pe98_gate') == 'pass' and digest(source) == row['sha256'], 'native artifact/gate mismatch')
        size = source.stat().st_size
        require(type(row.get('size', row.get('bytes'))) is int
                and size == row.get('size', row.get('bytes'))
                and 0 < size <= 1024 ** 2, 'native input size mismatch')
        artifact(receipts[label], filename, {'bytes': size, 'sha256': row['sha256']},
                 65536 if label == 'observer' else 524288)
        if label == 'runtime':
            instructions = row.get('i486_instructions')
            require(isinstance(instructions, dict)
                    and set(instructions) == {'instructions_decoded', 'post_i486_families'}
                    and type(instructions['instructions_decoded']) is int
                    and 0 < instructions['instructions_decoded'] <= 1048576
                    and instructions['post_i486_families'] == 'absent'
                    and isinstance(row.get('exports'), list) and len(row['exports']) == 9
                    and set(row['exports']) == RUNTIME_EXPORTS,
                    'runtime instruction/export gate missing')
        if label == 'observer':
            require(row.get('i486_instruction_gate') == 'pass', 'observer instruction gate missing')
        if label == 'automation':
            require(row.get('adapter') == 'statically embedded', 'fixture adapter profile missing')
        copies[filename] = (source, row['sha256'])
        inputs.append(dict(source=str(stage / filename), guest='C:\\GOPLAB\\' + filename,
                           bytes=size, sha256=row['sha256']))
    # Validation above is read-only. Create one fresh private stage only after
    # every source, shared ABI, successful build log and native input agrees.
    stage.mkdir()
    for name, (source, sha) in copies.items():
        destination = stage / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        require(digest(destination) == sha, 'stage readback mismatch: ' + name)
    manifest = dict(schema=1, kind='isolated-guest-file-inputs', inputs=inputs,
        nonce=receipts['observer']['nonce'], command='C:\\GOPLAB\\M98AURUN.EXE', network_required=False,
        outputs=['C:\\GOPLAB\\AUT13.LOG', 'C:\\GOPLAB\\AURUN.LOG', 'C:\\GOPLAB\\AUOUT.LOG'],
        source_receipts=[dict(path=str(stage / (label + '-build.json')),
            sha256=getattr(args, label + '_sha256')) for label in ('automation', 'runtime', 'observer')])
    output = stage / 'guest-files.json'
    output.write_text(json.dumps(manifest, indent=2) + '\n')
    provenance = dict(schema=1, kind='genuine-mshtml-native-frozen-stage',
        manifest_sha256=digest(output), source_sha256=merged,
        stage_sha256={name: sha for name, (_, sha) in copies.items()},
        native_execution=False, native_visual_input=False, browser_integration=False,
        html5_wasm=False, global_registration=False, vm_operations=False)
    (stage / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    print(json.dumps(dict(manifest=str(output), sha256=digest(output), native_execution=False)))


if __name__ == '__main__':
    main()
