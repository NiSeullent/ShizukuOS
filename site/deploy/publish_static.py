#!/usr/bin/env python3
"""Publish only reviewed m98 static assets to the existing local origin.

Creates a new immutable release, swaps only /srv/m98/current, and validates
every exact response through loopback HTTPS with m98 Host/SNI. A failed check
restores the previous symlink. No nginx, DNS or unrelated service is changed.
"""
import argparse
from contextlib import contextmanager
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / 'site'
BASE = Path('/srv/m98')
SMALL_LIMIT = 8 * 1024 * 1024
# The measured 2026-10-01 candidate is 284,164,096 bytes (271 MiB).
# Only streamed ISO inputs use this bound; ZIPs and static assets stay at 8 MiB.
ISO_LIMIT = 512 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
STATIC = ('index.html', 'preview.html', 'styles.css', 'preview.css', 'preview.js',
          'dead-screen.html', 'dead-screen.css', 'dead-screen.js',
          'dead-screen-preview.wasm', 'en/index.html', 'en/preview.html',
          'en/preview.js', 'en/dead-screen.html', 'en/evidence/preview.json',
          'favicon.svg', 'evidence/preview.json', 'downloads/SHZGOP.zip',
          'downloads/SHZGOP.zip.sha256', 'downloads/SHZNPP.zip',
          'downloads/SHZNPP.zip.sha256', 'downloads/SHZNPP-README.md',
          'downloads/shizuku-modern-preview-2026.10.01.zip',
          'downloads/shizuku-modern-preview-2026.10.01.zip.sha256',
          'downloads/dead-screen-preview-source.zip',
          'downloads/dead-screen-preview-source.zip.sha256')
AUTHORSHIP_STATIC = ('authorship/index.html', 'authorship/styles.css',
                    'authorship/evidence.json', 'authorship/handoff.html')
AUTHORSHIP_IMAGES = {
    'npp-cold-open.png': 'cb630d9533decbe718cdaddd79f93ec8b9d7da3ebd3eaaadcfdc62d5695a9990',
    'npp-keyboard-saved.png': '10699734c6334687e95b8b6150f98bef3a27d9acda7f06ac4c2f78f702787417',
    'gop-start.png': '574a70e9ee600e7f458eb6c93e54ae8ac88584addd0887e8af78328c510e2062',
    'gop-gdi.png': '41bf02431b194a3889eac4f80da8ceb22ec390875fcdd084a9c6bf9593288eb4',
    'legcord-welcome.png': '28fc8a9c451a610160ca833be12056e9497fb5bf85753a6169d3d3bbadf62238',
    'chromium-loading.png': 'ca6b5ce2e239170b91fc4372b98979efa6f3c7cf73f16efcd501c2be4282453e',
}
COMPONENT_INSTALLER_MANIFEST_SHA = 'ad97f8e8bee8d72dc57176028ebb83ab31618f11bebab5d0cdeb3f87127ff059'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def open_regular(path, limit):
    """Refuse links, special files and oversized inputs before reading them."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        stream = os.fdopen(fd, 'rb')
    except OSError as exc:
        raise ValueError('Readable regular file required: ' + str(path)) from exc
    info = os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
        stream.close()
        raise ValueError('File exceeds reviewed type/size bounds: ' + str(path))
    return stream


def read_small(path):
    with open_regular(path, SMALL_LIMIT) as stream:
        data = stream.read(SMALL_LIMIT + 1)
        if len(data) > SMALL_LIMIT:
            raise ValueError('Static file grew beyond the reviewed bound')
        return data


def stream_digest(stream, limit=ISO_LIMIT):
    digest = hashlib.sha256()
    count = 0
    while True:
        chunk = stream.read(CHUNK_BYTES)
        if not chunk:
            return count, digest.hexdigest()
        count += len(chunk)
        if count > limit:
            raise ValueError('Stream exceeds reviewed size bound')
        digest.update(chunk)


def file_snapshot(stream):
    info = os.fstat(stream.fileno())
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def verify_download(path, expected_bytes, expected_sha):
    with open_regular(path, ISO_LIMIT) as stream:
        size, digest = stream_digest(stream)
    if (size, digest) != (expected_bytes, expected_sha):
        raise ValueError('Downloaded ISO size/hash differs')


class IsoDownload:
    """Retain the reviewed input handle until the immutable copy is complete."""
    def __init__(self, stream, snapshot, metadata):
        self.stream = stream
        self.snapshot = snapshot
        self.metadata = metadata
        self.name = metadata['artifact']['path']

    def close(self):
        self.stream.close()

    def prefix(self):
        self.stream.seek(0)
        return self.stream.read(2048)

    def copy_to(self, destination):
        if file_snapshot(self.stream) != self.snapshot:
            raise ValueError('Reviewed ISO changed before copying')
        self.stream.seek(0)
        digest = hashlib.sha256()
        count = 0
        with open(destination, 'xb') as target:
            while True:
                chunk = self.stream.read(CHUNK_BYTES)
                if not chunk:
                    break
                count += len(chunk)
                if count > self.metadata['artifact']['bytes']:
                    raise ValueError('Reviewed ISO grew while copying')
                target.write(chunk)
                digest.update(chunk)
        expected = self.metadata['artifact']
        if ((count, digest.hexdigest()) != (expected['bytes'], expected['sha256'])
                or file_snapshot(self.stream) != self.snapshot):
            raise ValueError('Reviewed ISO changed while copying')
        verify_download(destination, expected['bytes'], expected['sha256'])


def load_iso_boot_evidence(path, metadata, builder_receipt_sha256):
    """Accept the desktop producer's shipped-ISO proof, publishing no raw paths."""
    raw = read_small(Path(path))
    result = json.loads(raw)
    if (not isinstance(result, dict) or result.get('status') != 'PASS'
            or result.get('test') != 'shizukudos/tests/run_k64_desktop.py'):
        raise ValueError('Successful shipped desktop producer result required')
    iso = result.get('iso')
    artifact = metadata['artifact']
    if (not isinstance(iso, dict) or type(iso.get('bytes')) is not int
            or iso['bytes'] != artifact['bytes'] or iso.get('sha256') != artifact['sha256']
            or result.get('boot_disk_sha256') != artifact['sha256']
            or not isinstance(iso.get('receipt'), dict)
            or iso['receipt'].get('sha256') != builder_receipt_sha256
            or not isinstance(iso.get('frozen'), str) or not iso['frozen']):
        raise ValueError('Desktop evidence must identify this exact ISO and builder receipt')

    def passing_checks(rows, required):
        if not isinstance(rows, list) or not 0 < len(rows) <= 256:
            raise ValueError('Nonempty bounded desktop checks required')
        names = []
        for row in rows:
            if (not isinstance(row, dict) or row.get('status') != 'PASS'
                    or not isinstance(row.get('check'), str) or not row['check']):
                raise ValueError('Every desktop check must pass')
            names.append(row['check'])
        if len(set(names)) != len(names) or not required.issubset(names):
            raise ValueError('Complete unambiguous desktop acceptance gates required')

    members = {'EFI/BOOT/BOOTX64.EFI': 'BOOTX64.EFI', 'SHZDOS/KERNEL64S.BIN': 'KERNEL64S.BIN',
               'SHZDOS/WIN64.IMG': 'WIN64.IMG', 'EFI/SHIZUKU/BOOT.INI': None, 'SHZDOS/KERNEL64.INI': None}
    shipped = iso.get('efi_members_sha256')
    inputs = result.get('inputs')
    if not isinstance(shipped, dict) or not isinstance(inputs, dict) or not isinstance(inputs.get('artifacts'), dict):
        raise ValueError('Source-bound shipped EFI component hashes required')
    for member, name in members.items():
        if (not isinstance(shipped.get(member), str) or not re.fullmatch('[a-f0-9]{64}', shipped[member])
                or name is not None and inputs['artifacts'].get(name) != shipped[member]):
            raise ValueError('Shipped EFI component source binding differs')
    required = {
        'WIN64.IMG contains the production desktop',
        'ISO frozen as an identical read-only private copy',
        'extracted EFI payload is the actual firmware-selected El Torito image',
        'shipped ISO selects Kernel64 without harness injection',
        'shipped ISO selects the production desktop command',
        'ISO matches its builder receipt', 'ISO builder receipt describes production desktop media',
        'source ISO unchanged while freezing and inspecting it', 'boot template remained unchanged',
        'source shipped ISO unchanged after both cold boots',
        'ISO builder receipt unchanged after both cold boots',
        'all inputs still match their current sources at completion',
    }
    for name in (name for name in members.values() if name is not None):
        required.update((name + ' matches its build receipt',
                         'shipped ISO ' + name + ' matches source-bound current build', 'original ' + name + ' unchanged'))
    for kind in ('loader', 'kernel', 'runtime'):
        required.update((kind + ' build records source hashes', kind + ' build matches current source', kind + ' receipt unchanged'))
    required.update('ISO receipt binds shipped ' + member for member in members)
    for number in (1, 2):
        required.update('boot-' + str(number) + ': ' + suffix for suffix in (
            'host independently extracted guest-written file', 'disk bytes equal exact host-selected text',
            'FAT32 volume consistent after guest writes', 'prepared seed file unchanged'))
    passing_checks(result.get('checks'), required)
    boots = result.get('boots')
    if not isinstance(boots, list) or len(boots) != 2:
        raise ValueError('Exactly two actual cold boot records required')
    data_disk = result.get('data_disk')
    if not isinstance(data_disk, str) or not data_disk:
        raise ValueError('The same independently checked writable data disk is required')
    boot_required = {
        'UEFI boot manager selected Kernel64 and exited firmware boot services',
        'real UEFI GOP driver initialized before desktop', 'AHCI driver mounted writable FAT32 D: volume',
        'production boot did not execute all-T application suite',
        'desktop registered its actual GUI window as the system shell',
        'production shell reached its own GUI readiness marker',
        'desktop persists while idle instead of a timed test screen',
        'Explorer enumerated the independently prepared writable D: volume',
        'editor reopened the saved file with expected length', 'editor read exact host-selected text back',
        'desktop launched/reaped real Win64 child with documented exit code',
        'production shell exited cleanly only after F10',
        'Kernel64 flushed writable volume and intentionally stopped QEMU successfully',
        'production boot never ran the all-T suite',
    }
    variables = []
    for number, boot in enumerate(boots, 1):
        if (not isinstance(boot, dict) or type(boot.get('boot')) is not int or boot['boot'] != number
                or boot.get('status') != 'PASS' or boot.get('boot_medium') != 'shipped-iso-cd'
                or type(boot.get('qemu_exit_code')) is not int or boot['qemu_exit_code'] != 1
                or boot.get('data_disk') != data_disk):
            raise ValueError('Successful production shipped-CD cold boots required')
        gates = boot_required | ({'editor saved new nonempty text through real disk driver'} if number == 1 else set())
        passing_checks(boot.get('checks'), gates)
        command = boot.get('command')
        if not isinstance(command, list) or not 1 < len(command) <= 256 or not all(isinstance(value, str) for value in command):
            raise ValueError('Actual bounded QEMU command required')
        def values(option):
            return [command[index + 1] for index, value in enumerate(command[:-1]) if value == option]
        if values('-machine') != ['q35'] or any(value in command for value in ('-kernel', '-initrd', '-append')):
            raise ValueError('Production q35 boot must not inject a harness kernel')
        drives = [dict(part.split('=', 1) for part in value.split(',')) for value in values('-drive')]
        firmware = [drive for drive in drives if drive.get('if') == 'pflash']
        code = [drive for drive in firmware if drive.get('unit') == '0']
        var = [drive for drive in firmware if drive.get('unit') == '1']
        cd = [drive for drive in drives if drive.get('id') == 'boot']
        if (len(firmware) != 2 or len(code) != 1 or len(var) != 1
                or code[0].get('readonly') != 'on' or not code[0].get('file') or not var[0].get('file')
                or len(cd) != 1 or cd[0].get('file') != iso['frozen']
                or cd[0].get('readonly') != 'on' or cd[0].get('media') != 'cdrom'
                or 'ide-cd,drive=boot,bus=ide.1,bootindex=1' not in values('-device')):
            raise ValueError('Real UEFI firmware and unchanged shipped CD command required')
        variables.append(var[0]['file'])
    if variables[0] == variables[1]:
        raise ValueError('Each cold boot must use its own fresh firmware variables')
    return {'sha256': sha(raw), 'cold_boots': 2, 'firmware': 'UEFI', 'platform': 'QEMU q35 / Shizuku Kernel64'}


def open_iso(path, source_commit, iso_boot_evidence=None):
    """Admit only the public ISO identified by the builder's adjacent receipt."""
    if not isinstance(source_commit, str) or not re.fullmatch('[a-f0-9]{40}', source_commit):
        raise ValueError('An exact lowercase source commit is required')
    path = Path(path)
    if path.suffix != '.iso' or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}\\.iso', path.name):
        raise ValueError('A bounded ISO filename is required')
    stream = open_regular(path, ISO_LIMIT)
    try:
        before = file_snapshot(stream)
        receipt_bytes = read_small(path.with_suffix('.json'))
        receipt = json.loads(receipt_bytes)
        if (not isinstance(receipt, dict)
                or receipt.get('private') is not False
                or type(receipt.get('bytes')) is not int
                or receipt['bytes'] != before[2]
                or not isinstance(receipt.get('sha256'), str)
                or not re.fullmatch('[a-f0-9]{64}', receipt['sha256'])
                or not isinstance(receipt.get('iso'), str)
                or Path(receipt['iso']).resolve(strict=True) != path.resolve(strict=True)
                or not isinstance(receipt.get('git'), dict)
                or receipt['git'].get('revision') != source_commit
                or type(receipt['git'].get('dirty')) is not bool):
            raise ValueError('Matching public ISO builder receipt required')
        stream.seek(32768)
        if stream.read(7) != b'\x01CD001\x01':
            raise ValueError('ISO9660 primary descriptor required')
        stream.seek(0)
        size, digest = stream_digest(stream)
        if (size != receipt['bytes'] or digest != receipt['sha256']
                or file_snapshot(stream) != before):
            raise ValueError('ISO differs from the reviewed builder receipt')
        version = source_commit[:12] + '-' + digest[:12]
        metadata = {
            'schema': 'win98modern.public-development-iso.v1',
            'version': 'development-' + version,
            'product': 'ShizukuOS',
            'release_target': '1.0.0',
            'release_channel': 'development',
            'distribution_origin': 'https://m98.nyase.kr',
            'artifact': {'path': 'downloads/shizukuos-development-' + version + '.iso',
                         'bytes': size, 'sha256': digest, 'content_type': 'application/octet-stream'},
            'source_commit': source_commit, 'source_tree_dirty': receipt['git']['dirty'],
            'scope': 'public-development-iso', 'private': False,
            'windows98_media_included': False,
            'validation': {'boot_status': 'not-verified-for-this-download',
                           'windows98_installer_complete': False, 'latest_apps_complete': False,
                           'component_runtime_results_are_separate': True},
        }
        if iso_boot_evidence is not None:
            metadata['validation']['boot_evidence'] = load_iso_boot_evidence(iso_boot_evidence, metadata, sha(receipt_bytes))
            metadata['validation']['boot_status'] = 'verified-uefi-development-desktop-two-cold-boots'
        return IsoDownload(stream, before, metadata)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        stream.close()
        raise ValueError('Public ISO admission failed: ' + str(exc)) from exc


def render_iso_homepage(data, metadata, language):
    """Derive localized ISO download copy without editing the source ZIP pages."""
    text = data.decode('utf-8')
    prefix = './' if language == 'ko' else '../' if language == 'en' else None
    if prefix is None:
        raise ValueError('Unsupported download page language')
    old = prefix + 'downloads/shizuku-modern-preview-2026.10.01.zip'
    new = prefix + metadata['artifact']['path']
    if text.count('href="' + old + '"') != 4:
        raise ValueError('The reviewed four download links changed')
    text = text.replace('href="' + old + '"', 'href="' + new + '"')
    size = format(metadata['artifact']['bytes'] / 1000000, '.2f') + ' MB'
    checksum = new + '.sha256'
    release = prefix + 'downloads/release.json'
    commit = metadata['source_commit']
    source = 'https://github.com/NiSeullent/Win98-Modern/tree/' + commit
    boot_verified = metadata['validation']['boot_status'] == 'verified-uefi-development-desktop-two-cold-boots'
    if language == 'ko':
        replacements = (
            ('>다운로드</a>', '>ISO 다운로드</a>'),
            ('>지금 바로 다운로드</a>', '>개발 ISO 지금 다운로드</a>'),
            ('개발 미리보기 · 2026.10.01 · ZIP 1.67 MB', '개발 부팅 ISO · ' + size),
            ('GOP 기본 그래픽 드라이버 + Notepad++ 호환 구성 + 소스', 'Shizuku 부팅 환경과 개발 구성요소'),
            ('Windows 98 설치본과 앱 원본은 별도입니다.', 'Microsoft Windows 98 설치 파일과 앱 원본은 별도입니다.'),
            ('ShizukuOS<br>1.0.0 개발판', 'ShizukuOS<br>1.0.0 개발 부팅 ISO'),
            ('드라이버와 앱 호환 구성, 설치 안내를 한 파일에 담았습니다.', 'Shizuku 부팅 환경과 개발 구성요소를 시험 VM에서 살펴보세요.'),
            ('ZIP 1.67 MB · Windows 98 SE용 구성', 'ISO ' + size + ' · 개발 부팅용'),
            ('운영체제 ISO와 자동 설치 프로그램은 포함되어 있지 않습니다. GOP 부팅 구성과 앱 설치는 아래 안내를 따라 준비하세요.',
             '이 ISO는 Shizuku 개발 부팅 이미지입니다. Windows 98 설치 파일은 포함되지 않으며 완성된 Windows 98 설치본이 아닙니다. 개별 ZIP은 드라이버와 앱 호환 구성을 제공합니다.'),
            ('시험용 Windows 98 SE 설치본에 적용하세요.', '개발 ISO는 시험용 가상머신에 연결하세요.'),
            ('<h3>다운로드하고 압축 풀기</h3><p>두 가지 구성과 “먼저 읽어주세요” 안내가 들어 있습니다.</p>',
             '<h3>ISO를 가상머신에 연결하기</h3><p>받은 ISO를 시험 VM의 CD/DVD로 연결해 Shizuku 개발 부팅 환경을 살펴보세요.</p>'),
            ('수동 설치용 개발 미리보기입니다. 새 설치본에서 이 ZIP만으로 설치하는 과정은 아직 검증 중입니다.',
             ('UEFI 개발 데스크톱 두 번 콜드 부팅과 실제 저장·다시 열기 시험을 통과했습니다. Windows 98 자동 설치와 최신 앱 전체 지원은 아직 개발 중입니다. 개별 호환 ZIP은 별도의 Windows 98 SE 설치본에 수동 적용합니다.'
              if boot_verified else '이 다운로드의 실제 부팅과 Windows 98 자동 설치는 아직 검증되지 않았습니다. 최신 앱 전체 지원은 개발 중입니다. 개별 호환 ZIP은 별도의 Windows 98 SE 설치본에 수동 적용합니다.')),
        )
        details = ('<p class="small">개발 ISO · ' + size + ' · 소스 <a href="' + source + '">' + commit[:12]
                   + '</a></p><p><a href="' + checksum + '">ISO 체크섬</a> · <a href="' + release
                   + '">배포 정보</a> · <a href="' + old + '" download>호환 구성 ZIP · 1.67 MB</a></p>')
    else:
        replacements = (
            ('>Download</a>', '>ISO download</a>'),
            ('>Download now</a>', '>Download development ISO</a>'),
            ('Development preview · 2026.10.01 · ZIP 1.67 MB', 'Development boot ISO · ' + size),
            ('GOP graphics driver + Notepad++ compatibility package + source', 'Shizuku boot environment and development components'),
            ('A development ZIP, not a full OS ISO. Windows 98 and the original apps are separate.',
             'A Shizuku development boot image. Microsoft Windows 98 setup files and original apps are separate.'),
            ('ShizukuOS<br>1.0.0 development candidate', 'ShizukuOS<br>1.0.0 development boot ISO'),
            ('The driver, compatibility components and setup guide in one package.', 'Explore the Shizuku boot environment and development components in a test VM.'),
            ('ZIP 1.67 MB · Windows 98 SE components', 'ISO ' + size + ' · Development boot image'),
            ('No operating system ISO, app originals or automatic installer is included. Prepare the matching GOP boot configuration and app prerequisites using the setup guide.',
             'This is a Shizuku development boot image. It does not contain Microsoft Windows 98 setup files or provide a completed Windows 98 installation. The individual ZIPs supply driver and app compatibility components.'),
            ('Use a disposable Windows 98 SE installation.', 'Attach the development ISO to a disposable test VM.'),
            ('<h3>Download and extract</h3><p>The ZIP contains both packages and a readme to get you started.</p>',
             '<h3>Attach the ISO to a test VM</h3><p>Use the downloaded ISO as the VM’s CD/DVD to explore the Shizuku development boot environment.</p>'),
            ('This is a manual development preview. Installing it from scratch on a fresh machine has not been accepted. The app trial used Windows 98 SE Korean and the dedicated compatibility launcher.',
             ('The UEFI development desktop passed two cold boots and real save/reopen tests. Automatic Windows 98 installation and complete support for the latest apps are still in development. Apply the individual compatibility ZIPs manually to a separate Windows 98 SE installation.'
              if boot_verified else 'Booting this download and automatic Windows 98 installation remain unverified. Complete support for the latest apps is still in development. Apply the individual compatibility ZIPs manually to a separate Windows 98 SE installation.')),
        )
        details = ('<p class="small">Development ISO · ' + size + ' · Source <a href="' + source + '">' + commit[:12]
                   + '</a></p><p><a href="' + checksum + '">ISO checksum</a> · <a href="' + release
                   + '">Release information</a> · <a href="' + old + '" download>Compatibility ZIP · 1.67 MB</a></p>')
    for before, after in replacements:
        if before not in text:
            raise ValueError('Reviewed download copy changed')
        text = text.replace(before, after)
    marker = '<details class="download-details"><summary>'
    if text.count(marker) != 2:
        raise ValueError('Reviewed download details changed')
    position = text.index('</summary>', text.index(marker)) + len('</summary>')
    text = text[:position] + details + text[position:]
    return text.encode('utf-8')


def response_headers(data):
    blocks = data.decode('ascii').strip().replace('\r\n', '\n').split('\n\n')
    lines = blocks[-1].splitlines()
    match = re.fullmatch(r'HTTP/(?:1\.[01]|2|3) ([0-9]{3})(?: .*)?', lines[0])
    if not match:
        raise ValueError('Expected origin HTTP response headers')
    headers = {}
    for line in lines[1:]:
        name, value = line.split(':', 1)
        key = name.lower()
        if key in headers:
            raise ValueError('Duplicate origin response header')
        headers[key] = value.strip()
    return int(match[1]), headers


def validate_iso_headers(head, ranged, body, metadata, expected_prefix):
    status, headers = response_headers(head)
    size = metadata['artifact']['bytes']
    if (status != 200 or headers.get('content-length') != str(size)
            or headers.get('content-type') != 'application/octet-stream'):
        raise ValueError('ISO HEAD identity differs')
    status, headers = response_headers(ranged)
    if (status != 206 or headers.get('content-length') != '2048'
            or headers.get('content-range') != 'bytes 0-2047/' + str(size)
            or len(body) != 2048 or body != expected_prefix):
        raise ValueError('ISO partial download identity differs')


def validate_translation(original, translated):
    """Permit localized copy and asset paths, preserving every evidence fact."""
    localized = json.loads(json.dumps(translated))
    original_collections = original['collections']
    if len(localized['collections']) != len(original_collections):
        raise ValueError('English evidence collections differ')
    for source, target in zip(original_collections, localized['collections']):
        if source.keys() != target.keys():
            raise ValueError('English evidence fields differ')
        for field in ('title', 'platform', 'display', 'result', 'scope'):
            if not isinstance(target[field], str) or not target[field].strip():
                raise ValueError('English evidence copy missing: ' + field)
            target[field] = source[field]
        if (not isinstance(target['observations'], list)
                or len(target['observations']) != len(source['observations'])
                or not all(isinstance(text, str) and text.strip()
                           for text in target['observations'])):
            raise ValueError('English observations differ')
        target['observations'] = source['observations']
        if len(source['frames']) != len(target['frames']):
            raise ValueError('English evidence frames differ')
        for original_frame, english_frame in zip(source['frames'], target['frames']):
            if original_frame.keys() != english_frame.keys():
                raise ValueError('English frame fields differ')
            expected_src = '../../evidence/images/' + Path(original_frame['src']).name
            if english_frame['src'] != expected_src:
                raise ValueError('English original image path differs')
            english_frame['src'] = original_frame['src']
            for field in ('caption', 'alt', 'chapter', 'runLabel'):
                if not isinstance(english_frame[field], str) or not english_frame[field].strip():
                    raise ValueError('English frame copy missing: ' + field)
                english_frame[field] = original_frame[field]
    if localized != original:
        raise ValueError('English translation changed an evidence fact')


def add_authorship_assets(assets):
    """Add only the reviewed development checkpoint and unchanged captures."""
    assets.update({name: read_small(SITE / name) for name in AUTHORSHIP_STATIC})
    manifest = json.loads(assets['authorship/evidence.json'])
    if (manifest['schema'] != 'win98modern.authorship-evidence.v2'
            or manifest['release_state'] != 'development_checkpoint'
            or manifest['full_project_goal_complete'] is not False
            or manifest['current_checkpoint']['release_0_9_complete'] is not False):
        raise ValueError('Reviewed incomplete development checkpoint required')
    records = manifest['screenshots']
    expected_paths = {'./images/' + name for name in AUTHORSHIP_IMAGES}
    if len(records) != len(expected_paths) or {row['src'] for row in records} != expected_paths:
        raise ValueError('Authorship capture allowlist differs')
    for row in records:
        relative = Path(row['src'])
        name = 'authorship/images/' + relative.name
        data = read_small(SITE / name)
        if (row['pixel_transform'] is not False
                or row['kind'] != 'original-guest-capture'
                or row['sha256'] != AUTHORSHIP_IMAGES[relative.name]
                or sha(data) != row['sha256']
                or not data.startswith(b'\x89PNG\r\n\x1a\n')):
            raise ValueError('Reviewed original Authorship PNG changed: ' + name)
        assets[name] = data
    results = {row['id']: row for row in manifest['results']}
    gui = results['chromium-gui']
    headless = results['chromium-headless']
    if (gui['version'] != '157.0.8079.0' or gui['revision'] != '1706750'
            or gui['raw_record_rewritten'] is not False
            or gui['app_functionality_verified'] is not False
            or gui['native_windows98_verified'] is not False
            or gui['local_page_loaded'] is not False
            or gui['actual_exit'] != '0xc0000005'
            or headless['executable_tree_sha_pinned_in_legacy_result'] is not False
            or headless['disk_image_byte_audit_performed_for_this_page'] is not False
            or headless['native_windows98_verified'] is not False):
        raise ValueError('Authorship Chromium provenance or scope differs')
    return len(records)


def add_component_installer_proof(assets, directory):
    """Publish only four pinned, unchanged captures of the component installer.

    This dated proof is independent of shipped-ISO acceptance. Its public
    manifest deliberately contains no owned inputs or private lab paths.
    """
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Regular component proof directory required')
    data = read_small(directory / 'manifest.json')
    if sha(data) != COMPONENT_INSTALLER_MANIFEST_SHA:
        raise ValueError('Reviewed component installer provenance or scope differs')
    manifest = json.loads(data)
    frames = manifest['frames']
    allowed = {'manifest.json', *(frame['file'] for frame in frames)}
    if {path.name for path in directory.iterdir()} != allowed:
        raise ValueError('Component proof directory must contain only the four reviewed PNGs and manifest')
    prefix = 'evidence/component-installer/'
    for frame in frames:
        image = read_small(directory / frame['file'])
        if (len(image) != frame['bytes'] or sha(image) != frame['sha256']
                or image[:16] != b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'
                or int.from_bytes(image[16:20], 'big') != frame['width']
                or int.from_bytes(image[20:24], 'big') != frame['height']):
            raise ValueError('Reviewed original component installer PNG changed')
        assets[prefix + frame['file']] = image
    assets[prefix + 'manifest.json'] = data
    return manifest


def render_component_installer_homepage(data, manifest, language):
    text = data.decode('utf-8')
    if language == 'ko':
        prefix = './'
        title = '설치하고, 다시 켜 봤습니다.'
        scope = 'Shizuku 구성요소 설치 검증'
        intro = '2026-10-01 · 실제 시험 VM 4회: 취소, 선택한 디스크 설치, UEFI와 BIOS 콜드 부팅.'
        pending = 'Windows 98의 MS-DOS 대체와 최신 앱 전체 지원은 개발 중입니다.'
        details = '이 화면은 Shizuku 구성요소 시험 기록입니다. 내려받는 ISO의 부팅 검증은 배포 정보에서 별도로 확인하세요.'
        link = '화면 원본과 검증 범위'
        captions = (
            ('직접 고른 디스크만.', '디스크를 선택해 내용을 확인하고, 취소 경로에서는 실제 쓰기가 없음을 검사했습니다.'),
            ('설치 후 파일까지 확인.', '선택한 디스크에 기록한 뒤 파티션, 시스템 파일과 설치 결과를 별도로 검사했습니다.'),
            ('UEFI로 다시 켜기.', '설치한 디스크로 새 VM을 켜서 데스크톱과 편집기를 열고 정상 종료했습니다.'),
            ('BIOS에서도 다시 켜기.', '같은 설치본을 BIOS로 콜드 부팅해 데스크톱과 편집기를 확인했습니다.'),
        )
    elif language == 'en':
        prefix = '../'
        title = 'Installed, then cold-booted.'
        scope = 'Shizuku component installer verification'
        intro = '2026-10-01 · Four real test VMs: cancel, selected-disk install, UEFI and BIOS cold boots.'
        pending = 'Replacing MS-DOS for Windows 98 and complete latest-app support remain in development.'
        details = 'These are Shizuku component test records. Check release information separately for boot verification of the ISO you download.'
        link = 'Original captures and verification scope'
        captions = (
            ('Only the selected disk.', 'The disk review and cancel path were tested, including proof that cancellation performed no writes.'),
            ('Installed files checked, too.', 'The selected disk was written, then its partitions, system files and installation result were checked independently.'),
            ('A fresh UEFI boot.', 'A new VM booted the installed disk, opened the desktop and editor, and shut down normally.'),
            ('A fresh BIOS boot, too.', 'The same installation cold-booted through BIOS and displayed its desktop and editor.'),
        )
    else:
        raise ValueError('Unsupported component proof language')
    cards = []
    for frame, (heading, caption) in zip(manifest['frames'], captions):
        image = prefix + 'evidence/component-installer/' + frame['file']
        cards.append('<a class="showcase-card" href="' + image + '"><img src="' + image
                     + '" width="' + str(frame['width']) + '" height="' + str(frame['height'])
                     + '" loading="lazy" alt="' + scope + ': ' + heading
                     + '"><div class="showcase-copy"><span class="badge">' + scope
                     + '</span><h3>' + heading + '</h3><p>' + caption + '</p></div></a>')
    section = ('<section class="showcase" aria-labelledby="component-installer-title"><div class="section-title"><div><p class="eyebrow">'
               + scope + '</p><h2 id="component-installer-title">' + title
               + '</h2></div></div><p>' + intro + '</p><div class="showcase-grid">'
               + ''.join(cards) + '</div><p class="small">' + pending + ' ' + details
               + ' <a href="' + prefix + 'evidence/component-installer/manifest.json">' + link + '</a></p></section>\n')
    marker = '<section class="final-download"'
    if text.count(marker) != 1:
        raise ValueError('Reviewed component proof insertion point changed')
    return text.replace(marker, section + marker, 1).encode('utf-8')


def prepare_assets(iso_path=None, iso_source_commit=None, iso_boot_evidence=None,
                   component_installer_proof=None):
    if (iso_path is None) != (iso_source_commit is None):
        raise ValueError('Both --iso and --iso-source-commit are required')
    if iso_boot_evidence is not None and iso_path is None:
        raise ValueError('--iso-boot-evidence requires --iso and --iso-source-commit')
    manifest = json.loads(read_small(SITE / 'evidence/preview.json'))
    if manifest['schema'] != 1 or manifest['live']['available']:
        raise ValueError('Reviewed recorded preview manifest required')
    assets = {name: read_small(SITE / name) for name in STATIC}
    validate_translation(manifest, json.loads(assets['en/evidence/preview.json']))
    authorship_images = add_authorship_assets(assets)
    # Each redistributed component download remains bound to its reviewed bytes.
    expected_downloads = {
        'downloads/SHZGOP.zip': '5fdc6ca5942012b6d29a291ca85e6ad4e5ca28421477394bfd2909c64f9c5dbb',
        'downloads/SHZNPP.zip': '9ae5a7628f99783e79b935a6eb04dfdc38ddafd02e540079877ae3dcac7df042',
        'downloads/shizuku-modern-preview-2026.10.01.zip': '6b322139ff1b2417b6a1792f036082f284883d095e4bda57d560c85c57f958e7',
        'downloads/dead-screen-preview-source.zip': '9a41d2ab8af79b79e72eb63f160eca95c9c159259ddc938940c711f751af7b72',
    }
    for name, expected in expected_downloads.items():
        if sha(assets[name]) != expected:
            raise ValueError('Reviewed download changed: ' + name)
        checksum = assets[name + '.sha256'].decode('ascii')
        if checksum != expected + '  ' + Path(name).name + '\n':
            raise ValueError('Download checksum changed: ' + name)
    if sha(assets['dead-screen-preview.wasm']) != '7156b7bb536b2388df3cb6052c40d08789478c0c9d445281c39b9fc0a7ba54fb':
        raise ValueError('Reviewed game preview changed')
    images = set()
    for collection in manifest['collections']:
        for frame in collection['frames']:
            relative = Path(frame['src'])
            if relative.is_absolute() or relative.parts[0] != 'images' or len(relative.parts) != 2:
                raise ValueError('Only bounded original image assets may be published')
            if relative.suffix != '.png' or relative.name in ('.', '..'):
                raise ValueError('Expected bounded PNG asset')
            name = (Path('evidence') / relative).as_posix()
            data = read_small(SITE / name)
            if sha(data) != frame['sha256'] or not data.startswith(b'\x89PNG\r\n\x1a\n'):
                raise ValueError('Reviewed original PNG changed')
            assets[name] = data
            images.add(name)
    iso = None
    component_proof = None
    try:
        if iso_path is not None:
            iso = open_iso(iso_path, iso_source_commit, iso_boot_evidence)
            assets['downloads/release.json'] = (json.dumps(iso.metadata, indent=2) + '\n').encode()
            assets[iso.name + '.sha256'] = (iso.metadata['artifact']['sha256'] + '  ' + Path(iso.name).name + '\n').encode('ascii')
            assets['index.html'] = render_iso_homepage(assets['index.html'], iso.metadata, 'ko')
            assets['en/index.html'] = render_iso_homepage(assets['en/index.html'], iso.metadata, 'en')
        if component_installer_proof is not None:
            component_proof = add_component_installer_proof(assets, component_installer_proof)
            assets['index.html'] = render_component_installer_homepage(assets['index.html'], component_proof, 'ko')
            assets['en/index.html'] = render_component_installer_homepage(assets['en/index.html'], component_proof, 'en')
        if not images or len(assets) + (iso is not None) > 128:
            raise ValueError('Unexpected static publication size')
        return {'assets': assets, 'images': images, 'authorship_images': authorship_images,
                'iso': iso, 'component_installer_proof': component_proof}
    except Exception:
        if iso is not None:
            iso.close()
        raise


@contextmanager
def publication_lock(path):
    """Serialize this site's cooperating publishers without changing services."""
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600)
    except OSError as exc:
        raise ValueError('Scoped publication lock cannot be opened') from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
            raise ValueError('Owned regular publication lock required')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError('Another m98 publication is active') from exc
        yield
    finally:
        os.close(fd)


def current_is(release):
    try:
        return (BASE / 'current').is_symlink() and (BASE / 'current').resolve(strict=True) == release
    except OSError:
        return False


def write_receipt(path, payload):
    """Expose a PASS receipt only after its complete write and close succeed."""
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', suffix='.tmp', dir=path.parent)
    temporary = Path(name)
    try:
        try:
            stream = os.fdopen(fd, 'wb')
        except Exception:
            os.close(fd)
            raise
        with stream:
            if stream.write(payload) != len(payload):
                raise OSError('Incomplete publication receipt write')
        if read_small(temporary) != payload:
            raise OSError('Publication receipt bytes differ after close')
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def publish(prepared):
    with publication_lock(BASE / 'publish.lock'):
        _publish(prepared)


def _publish(prepared):
    assets = prepared['assets']
    images = prepared['images']
    authorship_images = prepared['authorship_images']
    iso = prepared['iso']
    manifest = json.loads(assets['evidence/preview.json'])
    if not images or len(assets) + (iso is not None) > 128:
        raise ValueError('Unexpected static publication size')
    previous = (BASE / 'current').resolve(strict=True)
    if not previous.is_relative_to(BASE / 'releases'):
        raise ValueError('Existing scoped m98 release required')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')
    release = BASE / 'releases' / stamp
    output = ROOT / 'build/m98-self-host'
    capture = output / ('origin-' + stamp)
    hashes = {name: sha(data) for name, data in assets.items()}
    if iso is not None:
        hashes[iso.name] = iso.metadata['artifact']['sha256']
    release.mkdir(parents=True, exist_ok=False)
    for name, data in assets.items():
        dest = release / 'site' / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        dest.chmod(0o644)
    if iso is not None:
        destination = release / 'site' / iso.name
        iso.copy_to(destination)
        destination.chmod(0o644)
    for directory in [release, *[path for path in release.rglob('*') if path.is_dir()]]:
        directory.chmod(0o755)
    capture.mkdir(parents=True, exist_ok=False)
    staged = BASE / ('current-' + stamp)
    staged.symlink_to(release)
    checks = []
    try:
        os.replace(staged, BASE / 'current')
        for index, name in enumerate(hashes):
            dest = capture / str(index)
            large = iso is not None and name == iso.name
            command = ['curl', '--silent', '--show-error', '--fail', '--noproxy', '*',
                       '--insecure', '--resolve', 'm98.nyase.kr:443:127.0.0.1',
                       '--max-time', '180' if large else '10', '--output', str(dest),
                       'https://m98.nyase.kr/' + name]
            if large:
                command[1:1] = ['--max-filesize', str(iso.metadata['artifact']['bytes'])]
            fetched = subprocess.run(command, capture_output=True, text=True, timeout=190 if large else 15)
            if fetched.returncode:
                raise RuntimeError('Origin fetch failed: ' + name)
            if large:
                verify_download(dest, iso.metadata['artifact']['bytes'], hashes[name])
                count = iso.metadata['artifact']['bytes']
            else:
                body = read_small(dest)
                if sha(body) != hashes[name]:
                    raise ValueError('Origin returned different bytes: ' + name)
                count = len(body)
            checks.append({'path': '/' + name, 'status': 'PASS',
                           'bytes': count, 'sha256': hashes[name]})
        if iso is not None:
            head = capture / 'iso-head.headers'
            ranged = capture / 'iso-range.headers'
            body = capture / 'iso-range.body'
            common = ['curl', '--silent', '--show-error', '--fail', '--noproxy', '*',
                      '--insecure', '--resolve', 'm98.nyase.kr:443:127.0.0.1', '--max-time', '10']
            url = 'https://m98.nyase.kr/' + iso.name
            for command in (common + ['--head', '--output', str(head), url],
                            common + ['--header', 'Range: bytes=0-2047', '--max-filesize', '2048',
                                      '--dump-header', str(ranged), '--output', str(body), url]):
                response = subprocess.run(command, capture_output=True, text=True, timeout=15)
                if response.returncode:
                    raise RuntimeError('ISO HEAD/Range fetch failed')
            validate_iso_headers(read_small(head), read_small(ranged), read_small(body), iso.metadata, iso.prefix())
        if not current_is(release):
            raise RuntimeError('m98 current changed during validation; later publication preserved')
        receipt = {'status': 'PASS', 'release': str(release), 'previous_release': str(previous),
                   'static_files': hashes, 'origin_checks': checks, 'origin_check_count': len(checks),
                   'certificate_validation': False, 'public_edge_verified': False,
                   'preview_images': len(images), 'collections': len(manifest['collections']),
                   'authorship_images': authorship_images,
                   'authorship_state': 'development_checkpoint',
                   'languages': ['ko', 'en'], 'game_demo_native_execution': False,
                   'scope': 'Exact loopback HTTPS origin bodies with m98 Host/SNI. Public Cloudflare challenge is not counted as successful external fetch.'}
        if iso is not None:
            receipt['iso_release'] = iso.metadata
            receipt['iso_head_and_range_verified'] = True
        if prepared.get('component_installer_proof') is not None:
            receipt['component_installer_proof'] = prepared['component_installer_proof']
        path = output / ('release-' + stamp + '.json')
        payload = (json.dumps(receipt, indent=2) + '\n').encode()
        write_receipt(path, payload)
    except Exception:
        # Older publishers may not acquire our lock. Preserve their release if
        # they replaced current while this publication was being validated.
        if current_is(release):
            rollback = BASE / ('rollback-' + stamp)
            rollback.symlink_to(previous)
            os.replace(rollback, BASE / 'current')
        raise
    print(json.dumps({'status': 'PASS', 'release': str(release), 'checks': len(checks),
                      'receipt': str(path), 'sha256': sha(payload)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iso', type=Path, help='reviewed public development ISO with adjacent builder JSON receipt')
    parser.add_argument('--iso-source-commit', help='exact source revision from the public ISO builder receipt')
    parser.add_argument('--iso-boot-evidence', type=Path, help='optional PASS shipped-ISO result from run_k64_desktop.py')
    parser.add_argument('--component-installer-proof', type=Path,
                        help='optional directory containing four reviewed component-installer PNGs and the pinned public manifest')
    args = parser.parse_args()
    if (args.iso is None) != (args.iso_source_commit is None):
        parser.error('Both --iso and --iso-source-commit are required')
    if args.iso_boot_evidence is not None and args.iso is None:
        parser.error('--iso-boot-evidence requires --iso and --iso-source-commit')
    prepared = prepare_assets(args.iso, args.iso_source_commit, args.iso_boot_evidence,
                              args.component_installer_proof)
    try:
        publish(prepared)
    finally:
        if prepared['iso'] is not None:
            prepared['iso'].close()


if __name__ == '__main__':
    main()
