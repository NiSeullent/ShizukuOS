#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prepare/publish approved continuation artifacts to the existing m98 origin.

Default is a read-only plan. Only the designated site owner may use --publish.
No Git operation, nginx/DNS/service change, remote hosting or VM operation.
"""
import argparse
import datetime
import fcntl
import hashlib
import html
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import time
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = 'https://m98.nyase.kr'
FLOOR = 22_058_516_480
RESERVE = 16 * 1024 ** 2
MAX_ARTIFACT = 8 * 1024 ** 3
MAX_TOTAL = 12 * 1024 ** 3
MAX_SITE_FILES = 20_000
SUFFIXES = {'source_tar': ('.tar.xz', '.tar.gz'), 'source_zip': '.zip',
            'git_bundle': '.bundle', 'iso': '.iso', 'evidence': '.tar.xz'}
REQUIRED = {'source_tar', 'source_zip', 'git_bundle', 'iso'}
FALSE_FLAGS = ('full_modern_features_verified', 'modern_apps_verified', 'os_certified')


def need(condition, message):
    if not condition:
        raise ValueError(message)


def pairs(rows):
    result = {}
    for key, value in rows:
        need(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def canonical(path, directory=False):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path,
         'existing canonical absolute path required')
    need(not any(p.is_symlink() for p in [path, *path.parents]), 'symlink input rejected')
    mode = path.stat().st_mode
    need(stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode), 'wrong input file type')
    return path


def sha_file(path, limit=MAX_ARTIFACT):
    canonical(path)
    before = path.stat()
    need(before.st_size <= limit, 'file exceeds read bound')
    value = hashlib.sha256()
    count = 0
    with path.open('rb') as handle:
        opened = os.fstat(handle.fileno())
        while True:
            chunk = handle.read(min(1024 ** 2, limit + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            need(count <= limit, 'file grew beyond read bound')
            value.update(chunk)
        after = os.fstat(handle.fileno())
    shape = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(shape(before) == shape(opened) == shape(after) and count == before.st_size,
         'file changed during read')
    return value.hexdigest(), count


def read_manifest(path, approved_sha, artifact_root):
    need(re.fullmatch('[0-9a-f]{64}', approved_sha), 'literal approved manifest SHA256 required')
    path = canonical(path)
    need(sha_file(path, 256 * 1024)[0] == approved_sha, 'unapproved input manifest')
    raw = path.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == approved_sha, 'manifest changed before parsing')
    data = json.loads(raw, object_pairs_hook=pairs)
    need(set(data) == {'schema', 'release_id', 'commit_sha', 'artifacts',
                      'iso_mixed_provenance', 'iso_provenance_note', *FALSE_FLAGS},
         'exact input manifest fields required')
    need(type(data['schema']) is int and data['schema'] == 1, 'manifest schema')
    need(isinstance(data['release_id'], str) and
         re.fullmatch('[a-z0-9][a-z0-9_-]{0,63}', data['release_id']), 'safe release id')
    need(isinstance(data['commit_sha'], str) and re.fullmatch('[0-9a-f]{40}', data['commit_sha']),
         'exact main commit SHA required')
    need(data['iso_mixed_provenance'] is True and all(data[k] is False for k in FALSE_FLAGS),
         'mixed ISO and incomplete feature scope must remain explicit')
    note = data['iso_provenance_note']
    need(isinstance(note, str) and 1 <= len(note) <= 2000 and '\x00' not in note,
         'reviewed public ISO provenance note required')
    rows = data['artifacts']
    need(isinstance(rows, list) and 4 <= len(rows) <= 5, 'four artifacts plus optional evidence only')
    names = set()
    roles = set()
    total = 0
    for row in rows:
        need(isinstance(row, dict) and set(row) == {'role', 'filename', 'source', 'size', 'sha256'},
             'exact artifact fields required')
        role, name = row['role'], row['filename']
        need(isinstance(role, str) and role in SUFFIXES and role not in roles, 'unique allowed artifact role')
        need(isinstance(name, str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}', name)
             and name.endswith(SUFFIXES[role]) and name not in names, 'unique role-specific basename')
        need(type(row['size']) is int and 1 <= row['size'] <= MAX_ARTIFACT, 'bounded positive artifact size')
        need(isinstance(row['sha256'], str) and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'artifact SHA')
        need(isinstance(row['source'], str), 'artifact source path')
        source = canonical(Path(row['source']))
        need(source.is_relative_to(artifact_root), 'artifact outside explicit approved export root')
        need(sha_file(source) == (row['sha256'], row['size']), 'artifact SHA/size differs')
        roles.add(role)
        names.add(name)
        total += row['size']
    need(REQUIRED <= roles and total <= MAX_TOTAL, 'required artifacts or total bound differ')
    need(sha_file(path, 256 * 1024)[0] == approved_sha, 'late input manifest drift')
    return data


def current_release(base, expected):
    current = base / 'current'
    need(current.is_symlink(), 'existing current symlink required')
    literal = os.readlink(current)
    release = canonical(current.resolve(strict=True), directory=True)
    need(release.parent == base / 'releases' and release == expected,
         'current differs from caller-approved release')
    canonical(release / 'site', directory=True)
    return release, literal


def inventory(release):
    records = {}
    for parent, directories, names in os.walk(release, followlinks=False):
        for name in directories + names:
            path = Path(parent) / name
            need(not path.is_symlink(), 'internal release symlink needs separate review')
            need(not name.startswith('.') and path.suffix.lower() not in
                 {'.key', '.pem', '.p12', '.pfx', '.conf'}, 'private/control-looking release path rejected')
        for name in names:
            path = Path(parent) / name
            relative = path.relative_to(release).as_posix()
            need(relative.startswith('site/'), 'only existing public site content may be cloned')
            digest, size = sha_file(path)
            records[relative] = {'sha256': digest, 'size': size, 'mode': stat.S_IMODE(path.stat().st_mode)}
            need(len(records) <= MAX_SITE_FILES, 'existing site file count bound')
    need('site/index.html' in records, 'existing home index missing')
    return records


def public_metadata(data, approved_sha):
    return {'schema': 1, 'official_site': ORIGIN, 'release_id': data['release_id'],
            'main_commit_sha': data['commit_sha'], 'input_manifest_sha256': approved_sha,
            'iso_mixed_provenance': True, 'iso_provenance_note': data['iso_provenance_note'],
            **{name: False for name in FALSE_FLAGS},
            'glsl_status': 'DRAFT_UNVERIFIED', 'wasm_simd_status': 'DRAFT_UNVERIFIED',
            'artifacts': [{k: row[k] for k in ('role', 'filename', 'size', 'sha256')}
                          for row in data['artifacts']]}


def download_page(public, english=False):
    language = 'en' if english else 'ko'
    title = 'Continue development in another environment' if english else '다른 환경에서 이어서 개발하기'
    scope = ('Development checkpoint with mixed ISO provenance. Full modern features, apps and the OS '
             'are not certified. GLSL and SIMD are unbuilt DRAFT_UNVERIFIED. Supply licensed Windows '
             'media locally when required. Historical bounded native checks do not certify this ISO.'
             if english else '여러 출처를 포함한 ISO와 개발 체크포인트입니다. 전체 최신 기능·앱·OS는 '
             '인증되지 않았습니다. GLSL과 SIMD는 빌드되지 않은 DRAFT_UNVERIFIED입니다. 필요한 '
             'Windows 설치 매체는 정당한 라이선스로 로컬에서 준비해야 합니다. 이전의 한정된 '
             'native 검사는 이 ISO 전체의 인증이 아닙니다.')
    rows = ''.join('<tr><td>' + html.escape(r['role']) + '</td><td><a download href="' +
                   quote(r['filename']) + '">' + html.escape(r['filename']) + '</a></td><td>' +
                   str(r['size']) + '</td><td><code>' + r['sha256'] + '</code></td></tr>'
                   for r in public['artifacts'])
    bundle = next(r['filename'] for r in public['artifacts'] if r['role'] == 'git_bundle')
    commands = 'sha256sum --check SHA256SUMS\ngit clone --branch main ./' + bundle + \
               ' Win98-Modern\ncd Win98-Modern\npython3 -B tools/check_continuation_environment.py'
    intro = ('Source archives permit editing without GitHub. The Git bundle preserves main history. '
             'Build cache and test evidence require the separately listed evidence package; their '
             'inclusion is not inferred from source or ISO downloads. Read docs/CONTINUE_IN_ANOTHER_ENVIRONMENT.md '
             'after extraction. Verify the commit against manifest.json.' if english else
             '소스 압축 파일은 GitHub 없이 편집할 수 있고 Git bundle은 main 이력을 보존합니다. '
             '빌드 캐시·시험 증거는 별도 증거 묶음의 목록을 확인해야 하며, 소스나 ISO에 모두 '
             '포함됐다고 가정하면 안 됩니다. 압축을 푼 뒤 docs/CONTINUE_IN_ANOTHER_ENVIRONMENT.md를 '
             '읽고 커밋을 manifest.json과 비교하세요.')
    return ('<!doctype html><html lang="' + language + '"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1"><title>' + title +
            '</title><style>body{font:16px system-ui;max-width:1100px;margin:3em auto;padding:0 1em;'
            'line-height:1.6}table{border-collapse:collapse;width:100%}td,th{border:1px solid #bbb;'
            'padding:.5em;text-align:left}code{overflow-wrap:anywhere}pre{white-space:pre-wrap}'
            '.table{overflow:auto}</style></head><body><nav><a href="' + ORIGIN + '/">m98.nyase.kr</a> · '
            '<a href="' + ('index.html' if english else 'en.html') + '">' +
            ('한국어' if english else 'English') + '</a></nav><h1>' + title + '</h1><p>' + scope +
            '</p><p>' + html.escape(public['iso_provenance_note']) + '</p><p>' + intro +
            '</p><p><code>' + public['main_commit_sha'] + '</code></p><div class="table">'
            '<table><thead><tr><th>Role</th><th>Download</th><th>Bytes</th><th>SHA256</th>'
            '</tr></thead><tbody>' + rows + '</tbody></table></div><p><a href="manifest.json">manifest.json</a> · '
            '<a href="SHA256SUMS">SHA256SUMS</a></p><pre>' + html.escape(commands) +
            '</pre></body></html>\n').encode('utf-8')


def atomic_bytes(path, payload, exclusive=False):
    need(not exclusive or not path.exists(), 'new publication path already exists')
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.m98-new')
    with temporary.open('xb') as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.chmod(0o644)
    os.replace(temporary, path)  # Never write or chmod an inherited hardlinked file.


def same_current(base, previous, literal):
    need((base / 'current').is_symlink() and os.readlink(base / 'current') == literal and
         (base / 'current').resolve(strict=True) == previous, 'current release changed concurrently')


def switch(base, target_literal, release_id):
    temporary = base / ('current-' + release_id + '.m98-new')
    need(not temporary.exists() and not temporary.is_symlink(), 'switch temporary exists')
    temporary.symlink_to(target_literal)
    os.replace(temporary, base / 'current')


def origin_hash(curl, route, output, number, expected_size, insecure):
    headers = output / ('origin-' + str(number) + '.headers')
    errors = output / ('origin-' + str(number) + '.stderr')
    command = [curl, '--disable', '--silent', '--show-error', '--fail', '--noproxy', '*',
               '--proto', '=https', '--resolve', 'm98.nyase.kr:443:127.0.0.1',
               '--connect-timeout', '5', '--max-time', '180', '--dump-header', str(headers)]
    if insecure:
        command.append('--insecure')
    command.append(ORIGIN + route)
    value = hashlib.sha256()
    count = 0
    deadline = time.monotonic() + 190
    with errors.open('xb') as err:
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=err, start_new_session=True)
        try:
            need(child.stdout is not None, 'curl stream unavailable')
            while True:
                need(time.monotonic() < deadline, 'origin check deadline')
                ready, _, _ = select.select([child.stdout], [], [], 0.2)
                if not ready:
                    continue
                chunk = os.read(child.stdout.fileno(), 1024 ** 2)
                if not chunk:
                    break
                count += len(chunk)
                need(count <= expected_size, 'origin response exceeds expected byte count')
                value.update(chunk)
            need(child.wait(timeout=5) == 0, 'origin curl failed')
            need(headers.stat().st_size <= 128 * 1024, 'origin header read bound')
            status = re.findall(rb'^HTTP/\S+ (\d{3})', headers.read_bytes(), re.MULTILINE)
            need(status and status[-1] == b'200', 'origin response is not HTTP200')
            need(count == expected_size, 'origin response byte count differs')
        except BaseException:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)
            raise
        finally:
            if child.stdout:
                child.stdout.close()
    return value.hexdigest(), count


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--artifact-root', required=True, type=Path)
    parser.add_argument('--expected-current', required=True, type=Path)
    parser.add_argument('--base', type=Path, default=Path('/srv/m98'))
    parser.add_argument('--publish', action='store_true', help='designated site owner only; plan is default')
    parser.add_argument('--origin-insecure', action='store_true', help='explicitly record no TLS certificate verification')
    args = parser.parse_args(argv)
    base = canonical(args.base, directory=True)
    canonical(base / 'releases', directory=True)
    artifact_root = canonical(args.artifact_root, directory=True)
    data = read_manifest(args.manifest, args.manifest_sha256, artifact_root)
    previous, literal = current_release(base, canonical(args.expected_current, directory=True))
    before = inventory(previous)
    new = base / 'releases' / data['release_id']
    need(not new.exists() and not new.is_symlink(), 'release id already used')
    need(not (previous / 'site/downloads' / data['release_id']).exists(), 'download release id already used')
    need(previous.stat().st_dev == (base / 'releases').stat().st_dev, 'hardlinks require one filesystem')
    total = sum(row['size'] for row in data['artifacts'])
    plan = {'status': 'READ_ONLY_PLAN', 'official_site': ORIGIN, 'release_id': data['release_id'],
            'existing_public_file_count': len(before), 'artifact_count': len(data['artifacts']),
            'copy_bytes': total, 'minimum_free_bytes_before_copy': FLOOR + total + RESERVE,
            'actual_free_bytes': shutil.disk_usage(base).free,
            'origin_verification_performed': False, 'published': False,
            'actual_site_owner_approval_required': True, 'no_nginx_service_git_vm_operations': True}
    if not args.publish:
        same_current(base, previous, literal)
        print(json.dumps(plan, indent=2))
        return 0
    curl = shutil.which('curl')
    need(curl is not None, 'local curl required only for explicit publication')
    need(shutil.disk_usage(base).free >= FLOOR + total + RESERVE, 'shared free floor plus copy reservation not met')
    output = ROOT / 'build/m98-continuation-publication' / data['release_id']
    need(not output.exists(), 'fresh private receipt directory required')
    output.mkdir(parents=True)
    receipt = dict(plan, status='PREPARING', previous_release=str(previous), release=str(new),
                   certificate_validation=not args.origin_insecure, public_edge_verified=False,
                   private_receipt_directory=str(output), origin_checks=[], rollback=False)
    activated = False
    # This lock does not replace coordination with the designated site owner.
    with (base / '.continuation-publish.lock').open('a+b') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            same_current(base, previous, literal)
            need(inventory(previous) == before, 'old release drift before preparation')
            new.mkdir()
            for relative in before:
                dest = new / relative
                dest.parent.mkdir(parents=True, exist_ok=True)
                os.link(previous / relative, dest, follow_symlinks=False)
            destination = new / 'site/downloads' / data['release_id']
            destination.mkdir(parents=True, exist_ok=False)
            for row in data['artifacts']:
                need(shutil.disk_usage(base).free >= FLOOR + row['size'] + RESERVE, 'copy free floor')
                source = Path(row['source'])
                need(sha_file(source) == (row['sha256'], row['size']), 'source drift before copy')
                target = destination / row['filename']
                with source.open('rb') as incoming, target.open('xb') as outgoing:
                    while True:
                        chunk = incoming.read(1024 ** 2)
                        if not chunk:
                            break
                        need(outgoing.tell() + len(chunk) <= row['size'], 'source grew while copying')
                        outgoing.write(chunk)
                        need(shutil.disk_usage(base).free >= FLOOR + RESERVE, 'shared floor during copy')
                    outgoing.flush()
                    os.fsync(outgoing.fileno())
                target.chmod(0o644)
                need(sha_file(target) == (row['sha256'], row['size']), 'copied artifact differs')
            public = public_metadata(data, args.manifest_sha256)
            atomic_bytes(destination / 'manifest.json', (json.dumps(public, ensure_ascii=False, indent=2) + '\n').encode(), True)
            atomic_bytes(destination / 'index.html', download_page(public), True)
            atomic_bytes(destination / 'en.html', download_page(public, True), True)
            sums = ''.join(sha_file(p)[0] + '  ' + p.name + '\n' for p in sorted(destination.iterdir()))
            atomic_bytes(destination / 'SHA256SUMS', sums.encode('ascii'), True)
            home = ['site/index.html', 'site/ko/index.html', 'site/en/index.html']
            for relative in home:
                if relative not in before:
                    continue
                source = previous / relative
                need(source.stat().st_size <= 1024 ** 2, 'home page bound')
                original = source.read_bytes()
                need(original.count(b'</nav>') == 1, 'unambiguous existing home navigation required')
                english = '/en/' in relative
                route = '/downloads/' + data['release_id'] + ('/en.html' if english else '/index.html')
                text = 'Source, history and ISO' if english else '소스 · Git 이력 · ISO'
                addition = ('<a href="' + ORIGIN + route + '">' + text + '</a>').encode()
                updated = original.replace(b'</nav>', addition + b'</nav>', 1)
                need(updated.replace(addition, b'', 1) == original, 'home update must be additive only')
                atomic_bytes(new / relative, updated)
            for directory, _, _ in os.walk(new):
                Path(directory).chmod(0o755)  # Directories are fresh, never hardlinked.
            need(inventory(previous) == before, 'old release changed during hardlink preparation')
            read_manifest(args.manifest, args.manifest_sha256, artifact_root)
            after = inventory(new)
            for relative, row in before.items():
                if relative not in home:
                    need(after[relative] == row, 'inherited site content changed')
            need(shutil.disk_usage(base).free >= FLOOR + RESERVE, 'final publication free floor')
            same_current(base, previous, literal)
            activated = True
            switch(base, str(new), data['release_id'])
            for index, (relative, row) in enumerate(after.items()):
                route = '/' + quote(relative[len('site/'):], safe='/')
                need(origin_hash(curl, route, output, index, row['size'], args.origin_insecure) ==
                     (row['sha256'], row['size']), 'origin body differs: ' + route)
                receipt['origin_checks'].append({'path': route, 'sha256': row['sha256'], 'size': row['size'], 'status': 'PASS'})
            need((base / 'current').resolve(strict=True) == new, 'current changed during origin checks')
            need(inventory(previous) == before and inventory(new) == after, 'late old/new release drift')
            read_manifest(args.manifest, args.manifest_sha256, artifact_root)
            receipt.update(status='PASS', published=True, origin_verification_performed=True,
                           old_release_unchanged=True, external_novnc_routes_modified=False,
                           scope='Exact loopback HTTPS Host/SNI bodies only; no external edge or VM acceptance')
            atomic_bytes(output / 'result.json', (json.dumps(receipt, ensure_ascii=False, indent=2) + '\n').encode(), True)
        except BaseException as error:
            receipt.update(status='FAILED', error=str(error), published=False)
            if activated:
                if (base / 'current').is_symlink() and os.readlink(base / 'current') == str(new):
                    switch(base, literal, data['release_id'] + '-rollback')
                    receipt['rollback'] = True
                else:
                    receipt['rollback_refused_due_to_concurrent_owner_change'] = True
            atomic_bytes(output / 'failed-result.json', (json.dumps(receipt, ensure_ascii=False, indent=2) + '\n').encode(), True)
            raise
    print(json.dumps({'status': 'PASS', 'official_downloads': ORIGIN + '/downloads/' + data['release_id'] + '/',
                      'receipt': str(output / 'result.json'), 'public_edge_verified': False}))
    return 0


if __name__ == '__main__':
    previous_handlers = {}

    def interrupted(signum, frame):
        raise InterruptedError('publication interrupted by signal ' + str(signum))

    if '--publish' in sys.argv[1:]:
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous_handlers[number] = signal.signal(number, interrupted)
    try:
        exit_code = main()
    finally:
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)
    sys.exit(exit_code)
