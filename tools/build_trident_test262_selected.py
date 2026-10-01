#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run pinned positive synchronous Test262 fixtures in the real local runtime.

This is a selected semantic-fixture adapter, not a complete Test262 host.
Unsupported host, module, async and negative-test protocols are reported.
No VM, global configuration or original upstream file is changed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile
import urllib.request
import yaml

ROOT = Path(__file__).resolve().parents[1]
REVISION = '7ab7fafa0003f73fc85c1b95d88094d33f7eb8bd'
ARCHIVE_SHA = '1d497a1e7430094a41d06f38db775df4a63db5d587b2a8b08aba6fad5de19585'
OWN = {'src/m98_trident_script.c', 'src/m98_trident_script_port.c',
       'src/m98_trident_script_fp.c', 'tests/m98_trident_script_platform_host.c'}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def digest(path):
    path = Path(path)
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16 << 20,
         'bounded regular input required: ' + str(path))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def official_sources(source):
    """Derive selection hashes from the pinned archive, not a mutable manifest."""
    archive = source / 'test262.tar.gz'
    if not source.exists():
        need(source.parent == ROOT / 'build', 'new source must be a direct owned build child')
        source.mkdir()
        url = 'https://codeload.github.com/tc39/test262/tar.gz/' + REVISION
        with urllib.request.urlopen(url, timeout=60) as incoming, archive.open('xb') as destination:
            count = 0
            while data := incoming.read(1 << 20):
                count += len(data)
                need(count <= 16 << 20, 'pinned archive download exceeded bound')
                destination.write(data)
        fresh = True
    else:
        fresh = False
    need(digest(archive) == ARCHIVE_SHA, 'pinned official archive changed')
    pins = {}
    with tarfile.open(archive, 'r:gz') as tar:
        for member in tar:
            prefix, _, name = member.name.partition('/')
            need(prefix == 'test262-' + REVISION, 'unexpected pinned archive root')
            chosen = (name in {'LICENSE', 'INTERPRETING.md', 'package.json'}
                      or name.startswith('harness/') and name.endswith('.js')
                      or name.startswith('test/built-ins/') and name.endswith('.js')
                      and any(key in name for key in ('getOrInsert', 'Iterator/concat',
                          'Uint8Array/from', 'Uint8Array/prototype/to', 'Uint8Array/prototype/setFrom')))
            if not chosen:
                continue
            need(member.isfile() and not member.issym() and 0 <= member.size <= 1 << 20
                 and not Path(name).is_absolute() and '..' not in Path(name).parts and name not in pins,
                 'unsupported selected archive member')
            with tar.extractfile(member) as stream:
                data = stream.read((1 << 20) + 1)
            need(len(data) == member.size, 'selected archive member size differs')
            pins[name] = hashlib.sha256(data).hexdigest()
            if fresh:
                path = source / 'source' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open('xb') as output:
                    output.write(data)
    need(len(pins) <= 512 and 'LICENSE' in pins and 'harness/assert.js' in pins,
         'incomplete/unbounded selected official sources')
    if fresh:
        report = dict(schema=1, revision=REVISION,
            url='https://codeload.github.com/tc39/test262/tar.gz/' + REVISION,
            archive_sha256=ARCHIVE_SHA, archive_bytes=archive.stat().st_size,
            files=pins, full_conformance_verified=False, native_execution=False)
        (source / 'source-receipt.json').write_text(json.dumps(report, indent=2) + '\n')
    return pins


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-receipt', type=Path, required=True)
    parser.add_argument('--runtime-sha256', required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    own_pins = {n: digest(ROOT / n) for n in
                ['tools/build_trident_test262_selected.py', 'tests/m98_trident_test262_host.c']}
    source, output = args.source.resolve(), args.out.absolute()
    need(output == output.resolve() and output.parent == ROOT / 'build'
         and not output.exists(), 'fresh owned build output required')
    need(source.is_relative_to(ROOT / 'build'), 'source outside owned build')
    runtime_path = args.runtime_receipt.resolve()
    need(runtime_path.is_relative_to(ROOT / 'build')
         and digest(runtime_path) == args.runtime_sha256, 'runtime receipt pin')
    runtime = json.loads(runtime_path.read_text())
    need(runtime.get('passed') is True and
         runtime.get('profile') == 'bounded-local-trident-quickjs-v1', 'real passed runtime required')
    for name, sha in runtime['source_sha256'].items():
        need(digest(ROOT / name) == sha and
             digest(runtime_path.parent / 'source' / name) == sha, 'runtime source drift')
    for name, sha in runtime['prepared_sha256'].items():
        need(digest(name) == sha, 'runtime prepared source drift')
    official = official_sources(source)
    upstream = json.loads((source / 'source-receipt.json').read_text())
    need(upstream['revision'] == REVISION and upstream['archive_sha256'] == ARCHIVE_SHA
         and upstream['files'] == official, 'pinned official Test262 selection required')
    for name, sha in upstream['files'].items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts
             and digest(source / 'source' / name) == sha, 'upstream source drift')
    objects, names, flags = [], {}, None
    for row in runtime['object_cache']:
        recipe = row['recipe']
        if '-mfpmath=387' not in recipe['flags'] or '-fsanitize=address,undefined' in recipe['flags']:
            continue
        unit = Path(recipe['source'])
        if not (unit.is_relative_to(runtime_path.parent / 'prepared') or str(unit.relative_to(ROOT)) in OWN):
            continue
        need(digest(unit) == recipe['source_sha256']
             and digest(row['object']) == row['sha256'], 'cached object provenance mismatch')
        if unit in names:
            need(names[unit] == row['key'], 'conflicting cached object generations')
            continue
        if flags is None:
            flags = recipe['flags']
        need(recipe['flags'] == flags, 'mixed interpreter host flags')
        names[unit] = row['key']
        objects.append(row['object'])
    required = {Path(name) for name in runtime['prepared_sha256'] if name.endswith('.c')} | {ROOT / n for n in OWN}
    need(set(names) == required, 'incomplete coherent host runtime object set')
    output.mkdir()
    steps = []

    def run(command, label):
        result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=30)
        log = output / (label + '.log')
        log.write_bytes(result.stdout + result.stderr)
        steps.append(dict(command=command, returncode=result.returncode,
                          log=str(log), sha256=digest(log)))
        need(result.returncode == 0, 'own build step failed: ' + label)

    binary = output / 'semantic-host'
    run(['gcc', *flags, '-Wall', '-Wextra', '-Werror',
         'tests/m98_trident_test262_host.c', *objects, '-Wl,--gc-sections',
         '-lm', '-pthread', '-o', str(binary)], 'link')
    # Meaningful controls: a thrown assertion and an infinite loop must fail;
    # a fresh bounded runtime must execute a successful synchronous assertion.
    controls = []
    for name, code, success in [('positive', 'if (2+2!==4) throw Error("bad"); void 0;', True),
                                ('throw', 'throw Error("deliberate control");', False),
                                ('interrupt', 'for (;;) {}', False)]:
        path = output / (name + '.js'); path.write_text(code)
        result = subprocess.run([str(binary), str(path)], capture_output=True, timeout=5)
        need((result.returncode == 0) == success, 'semantic adapter control failed')
        controls.append(dict(case=name, returncode=result.returncode, expected_success=success))
    base = source / 'source'
    (output / 'fixtures').mkdir()
    cases, excluded = [], []
    for name in sorted(n for n in upstream['files'] if n.startswith('test/') and n.endswith('.js')):
        text = (base / name).read_text()
        match = re.search(r'/\*---(.*?)---\*/', text, re.S)
        need(match is not None, 'missing official metadata')
        metadata = yaml.safe_load(match[1])
        modes = metadata.get('flags', [])
        includes = ['assert.js', 'sta.js', *metadata.get('includes', [])]
        need(all(re.fullmatch(r'[A-Za-z0-9_.-]+\.js', h) and 'harness/' + h in upstream['files'] for h in includes),
             'unknown official harness include')
        reason = None
        if 'negative' in metadata or any(f not in {'onlyStrict', 'noStrict', 'generated'} for f in modes):
            reason = 'host adapter does not implement this negative/module/raw/async protocol'
        if any('$262' in code or '$DONE' in code or re.search(r'\bprint\s*\(', code)
               for code in [text, *((base / 'harness' / h).read_text() for h in includes)]):
            reason = 'requires unimplemented Test262 host bindings'
        if reason:
            excluded.append(dict(path=name, reason=reason)); continue
        variants = [True] if 'onlyStrict' in modes else [False] if 'noStrict' in modes else [False, True]
        for strict in variants:
            # Preserve global-script execution, include order, fresh realm and
            # strict directive. Normalize only the final completion value for
            # the scalar ABI; no assertions or feature implementations change.
            fixture = output / 'fixtures' / ('%04d.js' % len(cases))
            fixture.write_text(('"use strict";\n' if strict else '') + text + '\n;void 0;\n')
            command = [str(binary), *(str(base / 'harness' / h) for h in includes), str(fixture)]
            result = subprocess.run(command, capture_output=True, timeout=5)
            cases.append(dict(path=name, strict=strict, returncode=result.returncode,
                              features=metadata.get('features', []),
                              fixture=str(fixture), fixture_sha256=digest(fixture),
                              diagnostics=result.stderr.decode('utf-8', errors='replace')[:2048]))
    for name, sha in own_pins.items():
        need(digest(ROOT / name) == sha, 'adapter source drift during test')
        frozen = output / 'source' / name
        frozen.parent.mkdir(parents=True, exist_ok=True)
        frozen.write_bytes((ROOT / name).read_bytes())
        need(digest(frozen) == sha, 'frozen adapter source changed')
    need(digest(source / 'test262.tar.gz') == ARCHIVE_SHA and
         all(digest(base / n) == h for n, h in official.items()), 'official source drift during execution')
    report = dict(schema=1, kind='selected-Test262-semantic-fixtures-host-only',
        upstream_revision=REVISION, upstream_archive_sha256=ARCHIVE_SHA,
        upstream_receipt_sha256=digest(source / 'source-receipt.json'),
        runtime_receipt_sha256=args.runtime_sha256, source_sha256=own_pins,
        binary_sha256=digest(binary), metadata_parser_version=yaml.__version__,
        runtime_bounds=dict(memory_bytes=33554432, stack_bytes=262144,
                            interrupt_checks=1000, job_limit=128),
        steps=steps, controls=controls, cases=cases, excluded=excluded,
        passed=sum(c['returncode']==0 for c in cases), failed=sum(c['returncode']!=0 for c in cases),
        full_test262_host_protocol=False, full_es2026_conformance_verified=False,
        native_guest_execution=False, browser_integration=False, user_objective_complete=False)
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k:report[k] for k in ['kind','passed','failed','excluded','full_es2026_conformance_verified']}))
    return 1 if report['failed'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
