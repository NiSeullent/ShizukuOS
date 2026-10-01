#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Resume an exact stopped compiler proof without duplicating its source tree.

Only recorded, hash-verified completed objects are reused. Partial output from
the interrupted compiler is never used. A fresh receipt preserves the failure.
"""
import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESERVE, WRITE, OUTPUT = 20 * 1024**3, 256 * 1024**2, 16 * 1024**2
PIN = 'db11d0fe6a169c457e23d007e20404643d067aa8'
STOPPED = '09ddc931c44ca3f29f5fc7281b4cb1a830b2e2bfbbab45750cecee439384de44'


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--prior', required=True)
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    prior = Path(args.prior).resolve(strict=True)
    out = Path(args.out).resolve()
    require(prior.is_relative_to(HERE / 'build') and out.is_relative_to(HERE / 'build')
            and not out.exists(), 'immutable owned prior and fresh output required')
    require(digest(prior / 'result.json') == STOPPED, 'exact resource-stopped v4 receipt')
    old = json.loads((prior / 'result.json').read_text())
    require(old['status'] == 'INCOMPLETE' and old['error'] == '20 GiB reserve'
            and old['wine_commit'] == PIN, 'expected genuine stopped proof')
    base_file = Path(old['base_receipt']['path']).resolve(strict=True)
    base = base_file.parent
    require(base.is_relative_to(HERE / 'build'), 'owned original source base')
    source = json.loads(base_file.read_text())
    wine = base / 'wine'

    def verify():
        require(digest(prior / 'result.json') == STOPPED, 'old failure receipt drift')
        require(digest(base_file) == old['base_receipt']['sha256'], 'original source receipt drift')
        for section in ('original', 'generated_headers', 'prepared_headers'):
            for name, row in source[section].items():
                require(digest(wine / name) == row['sha256'], 'original/header drift: ' + name)
        for name, sha in old['own_sources'].items():
            require(digest(prior / 'own' / name) == sha and digest(HERE / name) == sha,
                    'old frozen/current compiler source drift: ' + name)
        for name, sha in old['generated'].items():
            require(digest(prior / 'generated' / name) == sha, 'generated parser drift')
        for name, row in old['generator_data'].items():
            require(digest(Path(name)) == row['sha256']
                    and digest(prior / row['frozen_copy']) == row['sha256'], 'generator closure drift')
        for row in old['tools'].values():
            require(digest(Path(row['path'])) == row['sha256'], 'actual installed compiler/tool drift')
        for name, row in old['objects'].items():
            require((prior / name).stat().st_size == row['bytes']
                    and digest(prior / name) == row['sha256'], 'completed object drift: ' + name)
        for step in old['steps']:
            require(digest(prior / step['log']) == step['sha256'], 'old compiler log drift')
        for mode, outputs in old['outputs'].items():
            for name, row in outputs.items():
                require(digest(prior / (mode + '-output') / name) == row['sha256'],
                        'actual compiled bytecode output drift')
        for kind, filename in (('normal_host_result', 'normal-shader-test'),
                               ('normal_container_result', 'normal-container-test')):
            row = old[kind]
            require(digest(prior / row['log']) == row['sha256']
                    and digest(prior / filename) == row['binary_sha256'], 'normal proof drift')
        require(digest(prior / 'own' / 'fixture.h') == old['fixture']['header_sha256'],
                'original fixture drift')

    verify()
    require(shutil.disk_usage(HERE).free - 64 * 1024**2 >= RESERVE,
            '20 GiB reserve and small compiler margin')
    out.mkdir()
    (out / 'tmp').mkdir()
    (out / 'own').mkdir()
    (out / 'objects').mkdir()
    shutil.copyfile(Path(__file__).resolve(), out / 'own' / 'compiler_resume.py')
    (out / 'own' / 'compiler_resume.py').chmod(0o400)
    receipt = {key: value for key, value in old.items()
               if key.endswith('_verified') or key in ('wine_commit', 'vkd3d_version', 'fixture',
                    'base_receipt', 'source_and_license_closure', 'genuine_units', 'tools',
                    'network_operations', 'vm_operations', 'global_install', 'peer_sources_modified')}
    receipt.update(schema=1, stage='exact-stopped-genuine-shader-compiler-continuation',
        status='INCOMPLETE', prior_receipt={'path': str(prior / 'result.json'), 'sha256': STOPPED},
        own_sources={'compiler_resume.py': digest(Path(__file__).resolve())},
        reused_consumer_sources=old['own_sources'], reused_generated=old['generated'],
        reused_objects={}, objects={}, steps=[], outputs={'normal': old['outputs']['normal']},
        normal_host_result={**old['normal_host_result'], 'source_directory': str(prior)},
        normal_container_result={**old['normal_container_result'], 'source_directory': str(prior)},
        guards={'reserve_bytes': RESERVE, 'write_budget_bytes': WRITE, 'output_budget_bytes': OUTPUT,
                'jobs': 1}, compiler_headers={},
        host_shader_negative_scope='Valid-checksum oversized SHDR declared DWORD length; '
                                   'header/length rejection, not an unknown-opcode test.',
        spirv_validation_scope='Independent structural checks; spirv-val is not installed; '
                               'no SPIR-V instruction execution or Vulkan device.')

    def guard():
        used = logs = 0
        for path in (HERE / 'build').rglob('*'):
            try:
                if path.is_file() and not path.is_symlink():
                    size = path.stat().st_size
                    used += size
                    if path.suffix == '.log':
                        logs += size
            except FileNotFoundError:
                pass
        free = shutil.disk_usage(out).free
        require(used <= WRITE, 'aggregate 256 MiB graphics allocation budget')
        require(logs <= OUTPUT, 'aggregate 16 MiB logs')
        require(free >= RESERVE, '20 GiB reserve')
        receipt['guards']['peak_owned_bytes'] = max(used, receipt['guards'].get('peak_owned_bytes', 0))
        receipt['guards']['minimum_free_bytes'] = min(free, receipt['guards'].get('minimum_free_bytes', 2**63))

    def run(label, command, timeout=120):
        guard()
        log = out / (label + '.log')
        env = os.environ.copy()
        env['TMPDIR'], env['VKD3D_DEBUG'] = str(out / 'tmp'), 'none'
        start = time.monotonic()
        with log.open('wb') as stream:
            process = subprocess.Popen([str(x) for x in command], cwd=out, env=env,
                stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                while process.poll() is None:
                    guard()
                    require(time.monotonic() - start < timeout, 'bounded compiler timeout')
                    time.sleep(.1)
                guard()
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                raise
        row = {'label': label, 'command': [str(x) for x in command], 'returncode': process.returncode,
               'log': str(log.relative_to(out)), 'sha256': digest(log),
               'duration_seconds': round(time.monotonic() - start, 3)}
        receipt['steps'].append(row)
        require(process.returncode == 0, 'genuine compiler/test failure: ' + label)
        return row

    try:
        guard()
        units = [base / p if p.startswith('wine/') else prior / p for p in old['genuine_units']]
        require(len(units) == 23, 'complete genuine shader compilation closure')
        consumers = units + [prior / 'own' / 'compiler_host.c']
        # Recover the exact old validated compiler flags, replacing only output paths.
        sample = next(s['command'] for s in old['steps'] if s['label'] == 'sanitize-compile-0')
        flags = sample[1:sample.index('-MD')]
        compiler = old['tools']['clang']['path']
        objects = []
        deps = []
        for index, path in enumerate(consumers):
            name = 'objects/sanitize-' + str(index) + '.o'
            if name in old['objects']:
                obj = prior / name
                receipt['reused_objects'][str(obj)] = old['objects'][name]
                deps.append(obj.with_suffix('.d'))
            else:
                obj = out / name
                dep = obj.with_suffix('.d')
                run('sanitize-compile-' + str(index), [compiler, *flags, '-MD', '-MF', dep,
                                                     '-c', path, '-o', obj])
                receipt['objects'][name] = {'source': str(path), 'sha256': digest(obj), 'bytes': obj.stat().st_size}
                deps.append(dep)
            objects.append(obj)
        extra = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        binary = out / 'sanitize-shader-test'
        run('sanitize-link', [compiler, *extra, *objects, '-Wl,--gc-sections', '-pthread', '-lm', '-o', binary])
        destination = out / 'sanitize-output'
        destination.mkdir()
        row = run('sanitize-test', [binary, destination])
        receipt['sanitize_host_result'] = {'log': row['log'], 'sha256': row['sha256'],
                                           'binary_sha256': digest(binary), 'compiler': compiler}
        receipt['outputs']['sanitize'] = {p.name: {'sha256': digest(p), 'bytes': p.stat().st_size}
                                           for p in destination.iterdir()}
        require(receipt['outputs']['normal'] == receipt['outputs']['sanitize'], 'normal/sanitizer bytecode mismatch')
        run('sanitize-elf-imports', [old['tools']['readelf']['path'], '-d', binary])
        container = []
        for name in ('container.c', 'host.c'):
            path = base / 'own' / name
            require(digest(path) == source['own_sources'][name], 'frozen container consumer drift')
            obj = out / 'objects' / ('sanitize-container-' + name + '.o')
            dep = obj.with_suffix('.d')
            run('sanitize-container-' + name, [compiler, *flags, '-I' + str(base / 'own'),
                                               '-MD', '-MF', dep, '-c', path, '-o', obj])
            receipt['objects'][str(obj.relative_to(out))] = {'source': str(path), 'sha256': digest(obj),
                                                            'bytes': obj.stat().st_size}
            deps.append(dep)
            container.append(obj)
        container_binary = out / 'sanitize-container-test'
        run('sanitize-container-link', [compiler, *extra, *objects[:-1], *container,
                                        '-Wl,--gc-sections', '-pthread', '-lm', '-o', container_binary])
        row = run('sanitize-container-test', [container_binary])
        receipt['sanitize_container_result'] = {'log': row['log'], 'sha256': row['sha256'],
                                                'binary_sha256': digest(container_binary), 'compiler': compiler}
        peflags = [x for x in flags if x not in ('-DHAVE_PTHREAD_H=1', '-DHAVE_DLFCN_H=1',
                    '-D_POSIX_C_SOURCE=200809L', '-D_GNU_SOURCE=1', *extra)] + [
                    '-D__WINE_PE_BUILD', '-D_UCRT', '-D_WIN32', '-D_ACRTIMP=', '-fshort-wchar',
                    '-mabi=ms', '-mcx16', '-I' + str(wine / 'include/msvcrt')]
        peobjects = []
        for index, path in enumerate(units):
            obj = out / 'objects' / ('pe-' + str(index) + '.o')
            dep = obj.with_suffix('.d')
            run('pe-compile-' + str(index), [old['tools']['x86_64-w64-mingw32-gcc']['path'],
                                             *peflags, '-MD', '-MF', dep, '-c', path, '-o', obj])
            receipt['objects'][str(obj.relative_to(out))] = {'source': str(path), 'sha256': digest(obj),
                                                            'bytes': obj.stat().st_size}
            peobjects.append(obj)
            deps.append(dep)
        library = out / 'libgenuine-vkd3d-shader-amd64.a'
        run('pe-archive', [old['tools']['x86_64-w64-mingw32-ar']['path'], 'rcs', library, *peobjects])
        receipt['amd64_library'] = {'path': str(library), 'sha256': digest(library), 'bytes': library.stat().st_size}
        run('pe-symbols', [old['tools']['x86_64-w64-mingw32-nm']['path'], '-g', library])
        run('sanitize-symbols', [old['tools']['nm']['path'], '-g', binary])
        # Installed headers are captured now; old v4 never completed this stage.
        # This is a current dependency closure, not a claim of an old header snapshot.
        receipt['header_capture_scope'] = ('Current installed header copies from all reused/fresh .d files; '
                                           'v4 had not captured installed headers before interruption.')
        deps += list((prior / 'objects').glob('normal*.d'))
        for dep in deps:
            require(dep.is_file(), 'completed compiler dependency file missing')
            for name in dep.read_text().replace('\\\n', ' ').split(':', 1)[1].split():
                path = Path(name).resolve(strict=True)
                if path.is_relative_to(base) or path.is_relative_to(prior) or path.is_relative_to(out):
                    continue
                require(path.is_relative_to('/usr'), 'compiler header outside installed toolchain')
                if str(path) in receipt['compiler_headers']:
                    continue
                frozen = out / 'compiler-headers' / path.relative_to('/')
                frozen.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, frozen)
                frozen.chmod(0o400)
                require(digest(path) == digest(frozen), 'installed header copy drift')
                receipt['compiler_headers'][str(path)] = {'sha256': digest(path), 'bytes': frozen.stat().st_size,
                                                          'frozen_copy': str(frozen.relative_to(out))}
                guard()
        verify()
        require(digest(Path(__file__).resolve()) == receipt['own_sources']['compiler_resume.py']
                and digest(out / 'own/compiler_resume.py') == receipt['own_sources']['compiler_resume.py'],
                'continuation source drift')
        for key in ('actual_host_dxbc_container_verified', 'actual_host_hlsl_dxbc_compile_verified',
                    'actual_host_dxbc_spirv_compile_verified', 'actual_host_pinned_dxbc_disassembly_verified'):
            receipt[key] = True
        receipt['status'] = 'HOST_SHADER_COMPILER_PASS_AND_AMD64_LIBRARY_BUILT'
        guard()
    except BaseException as exc:
        receipt['status'], receipt['error'] = 'INCOMPLETE', str(exc)
    finally:
        (out / 'result.json').write_text(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'out': str(out), 'status': receipt['status'], 'error': receipt.get('error'),
                      'objects': len(receipt['objects']), 'reused': len(receipt['reused_objects']),
                      'guards': receipt['guards']}))
    return 0 if receipt['status'] == 'HOST_SHADER_COMPILER_PASS_AND_AMD64_LIBRARY_BUILT' else 1


if __name__ == '__main__':
    raise SystemExit(main())
