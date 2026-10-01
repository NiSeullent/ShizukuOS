#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Read-only continuation inventory. Never install, fetch, build or launch tools."""
import argparse
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import shutil
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
BUILD_FREE = 22_595_387_392
NATIVE_FREE = 22_058_516_480
AVAILABLE_RAM = 6 * 1024 ** 3
HASH_LIMIT = 96 * 1024 ** 2
TOOLS = (
    'git', 'gcc', 'g++', 'clang', 'clang++', 'make', 'cmake', 'ninja',
    'bison', 'flex', 'patch', 'tar', 'ar', 'nm', 'objdump',
    'i686-w64-mingw32-gcc', 'i686-w64-mingw32-g++',
    'i686-w64-mingw32-objdump',
)
ARCHIVES = (
    ('project', 'build/mesa-softpipe-audit-v1/input/mesa-26.2.3.tar.xz',
     '1628058a8d2c0615975de5a15ab7bbb9638c50000b5bed9456ff423ea034a81f'),
    ('project', 'build/trident-script-sources/quickjs-2026-06-04.tar.xz',
     'b376e839b322978313d929fd20663b11ba58b75df5a46c126dd19ea2fa70ad2a'),
    ('project', 'build/trident-script-sources/musl-c4e1bb3994c14ed5112c894d15a451bf00f0d501.tar.gz',
     'b124fa46818a524d373a176b3262a9c26f421d5972073110f3fe51690a9ac4f1'),
    ('project', 'build/wasm-runtime-sources-v3/wamr.tar.gz',
     '620d40c4c67269f371a46ef4923d398ef96cdf569a7f66e6aab70788e235f907'),
    ('project', 'build/tls13/upstream/mbedtls-4.2.0.tar.bz2',
     '2bed9d713b4668f76553b097e72b8aa30bc8f112a940d7ae228d524bbde6ffea'),
    ('tls', 'build/secure-transport/upstream/mbedtls-3.6.7.tar.bz2',
     'a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6'),
    ('project', 'build/wasm-fixture-tools-v1/wabt-1.0.42-linux-x64.tar.gz',
     '84895407a6bbb80e918f33b16b2fb2206021c150b6bc9ff6f761263a745ab131'),
)
# Markers identify known dependencies, not their complete validated closures.
CACHE_MARKERS = (
    ('project', 'build/trident-script-v10/result.json'),
    ('project', 'build/wasm-runtime-v24/result.json'),
    ('project', 'build/wasm-memory-profile-v8/result.json'),
    ('project', 'build/wasm-qjs-v11/result.json'),
    ('project', 'build/wasm-qjs-memory-v4/result.json'),
    ('project', 'build/wasm-spec-selected-sources-v2/source-pin.json'),
    ('project', 'build/wasm-fixture-tools-v1/tool-pin.json'),
    ('project', 'build/glsl-generator-dependencies-v3/result.json'),
    ('project', 'build/mesa-softpipe-audit-v1/source-pins.json'),
    ('project', 'build/tls13-i486-v2/result.json'),
    ('boot', 'build/trident-script-native-5abe-20261001-v1/guest-files.json'),
    ('boot', 'build/wasm-numeric-native-5abe-20261001-v2/guest-files.json'),
    ('boot', 'build/tls13-i486-native-5abe-20261001-v1/guest-files.json'),
)


def inspect_file(path, expected=None, verify=False):
    row = {'path': str(path), 'status': 'missing', 'verification': 'presence_only'}
    if expected:
        row['expected_sha256'] = expected
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or any(p.is_symlink() for p in path.parents):
            row['status'] = 'not_regular_or_symlink'
            return row
        row.update(status='present', bytes=info.st_size)
        if expected and verify:
            row['verification'] = 'sha256'
            if info.st_size > HASH_LIMIT:
                row['status'] = 'exceeds_hash_read_bound'
                return row
            value = hashlib.sha256()
            with path.open('rb') as handle:
                before = os.fstat(handle.fileno())
                total = 0
                while True:
                    chunk = handle.read(min(1024 ** 2, HASH_LIMIT + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > HASH_LIMIT:
                        row['status'] = 'exceeds_hash_read_bound'
                        return row
                    value.update(chunk)
                after = os.fstat(handle.fileno())
            fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if fields(info) != fields(before) or fields(before) != fields(after) or total != info.st_size:
                row['status'] = 'changed_during_read'
            else:
                row['sha256'] = value.hexdigest()
                row['status'] = 'sha256_match' if row['sha256'] == expected else 'sha256_mismatch'
    except FileNotFoundError:
        pass
    except OSError as error:
        row.update(status='unreadable', error=str(error))
    return row


def memory_available():
    try:
        for line in Path('/proc/meminfo').read_text().splitlines():
            if line.startswith('MemAvailable:'):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def package_version(name):
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None
    except (OSError, ValueError):
        return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', action='store_true', help='print JSON to stdout; no output file')
    parser.add_argument('--verify-archives', action='store_true', help='read bounded archive bytes and compare fixed SHA256')
    parser.add_argument('--boot-root', type=Path, default=ROOT.parent / 'Win98-Modern-boot')
    parser.add_argument('--tls-root', type=Path, default=ROOT.parent / 'Win98-Modern-tls13-7707')
    args = parser.parse_args(argv)
    roots = {'project': ROOT, 'boot': args.boot_root.absolute(), 'tls': args.tls_root.absolute()}
    tools = {name: shutil.which(name) for name in TOOLS}
    packages = {name: package_version(name) for name in ('pefile', 'PyYAML', 'Mako', 'MarkupSafe')}
    archives = [inspect_file(roots[group] / name, pin, args.verify_archives) for group, name, pin in ARCHIVES]
    caches = [inspect_file(roots[group] / name) for group, name in CACHE_MARKERS]
    free = shutil.disk_usage(ROOT).free
    available = memory_available()
    resources = {'free_bytes': free, 'mem_available_bytes': available,
                 'host_build_min_free_bytes': BUILD_FREE, 'native_min_free_bytes': NATIVE_FREE,
                 'min_available_memory_bytes': AVAILABLE_RAM,
                 'host_build_disk_floor_met': free >= BUILD_FREE,
                 'native_disk_floor_met': free >= NATIVE_FREE,
                 'memory_floor_met': available is not None and available >= AVAILABLE_RAM,
                 'measurement': 'single snapshot; no reservation or running guard'}
    missing = [name for name, path in tools.items() if path is None]
    present = {'present', 'sha256_match'}
    incomplete = (not sys.platform.startswith('linux') or sys.version_info < (3, 10) or
                  bool(missing) or any(packages[n] is None for n in ('pefile', 'PyYAML')) or
                  any(row['status'] not in present for row in archives + caches) or
                  not resources['host_build_disk_floor_met'] or not resources['memory_floor_met'])
    result = {'schema': 1, 'official_site': 'https://m98.nyase.kr', 'project_root': str(ROOT),
              'python': {'executable': sys.executable, 'version': sys.version.split()[0],
                         'minimum_version_met': sys.version_info >= (3, 10)},
              'linux_host': sys.platform.startswith('linux'), 'tools': tools, 'missing_tools': missing,
              'optional_vm_tool_path': shutil.which('qemu-system-i386'),
              'installed_package_metadata_versions': packages, 'archives': archives,
              'known_cache_markers': caches, 'resources': resources,
              'inventory_complete': not incomplete, 'read_only': True,
              'commands_executed': False, 'cache_closure_verified': False,
              'build_reproducibility_verified': False, 'native_execution_verified': False,
              'full_standards_apps_os_certified': False,
              'windows_licensed_media': 'must be supplied locally; not inspected',
              'limitations': ['PATH presence is not compiler/runtime/version validation',
                              'Installed metadata does not validate isolated Mako/module closure',
                              'Cache markers do not validate receipts, logs, objects or absolute paths',
                              'Frozen GLSL and SIMD drafts remain unbuilt']}
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print('공식 배포처: https://m98.nyase.kr\n작업 위치: ' + str(ROOT))
        print('읽기 전용 환경 목록입니다. 빌드·native 실행 성공을 인증하지 않습니다.')
        print('누락된 도구: ' + (', '.join(missing) or '없음'))
        print('Python 설치 메타데이터: ' + json.dumps(packages, ensure_ascii=False))
        for row in archives + caches:
            print(row['status'] + ': ' + row['path'])
        print('자원 순간 측정: ' + json.dumps(resources, ensure_ascii=False))
        print('Windows 라이선스 매체는 로컬에서 별도로 준비해야 합니다.')
        print('추가 준비 필요' if incomplete else '목록상 준비됨; 전체 검증 및 실행은 별도 필요')
    return 2 if incomplete else 0


if __name__ == '__main__':
    sys.exit(main())
