#!/usr/bin/env python3
"""Append one original standalone Legcord frame; preserve native Win98 records."""
import datetime
import hashlib
import json
from pathlib import Path

ROOT = Path('/root/Win98-Modern-boot')
RUN = Path('/root/Win98-Modern-apps-cb43/build/modern-apps/legcord-v33-k11-actual')
OBS_SHA = 'fd6a3236dcc813637a04f3f385065ca9e42db5b7d072c9b08786f5bfeb9af485'
IMAGE_SHA = '28fc8a9c451a610160ca833be12056e9497fb5bf85753a6169d3d3bbadf62238'
BEFORE_SHA = '708aae28ee721594e649bca2172847b06202135c72bca5efb5edbb48096f1f1a'


def sha(path):
    before = path.stat()
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for part in iter(lambda: stream.read(1048576), b''):
            digest.update(part)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError('Input changed during read: ' + str(path))
    return digest.hexdigest()


def main():
    out = ROOT / 'build/legcord-runtime-preview-export-20261001T0916-v1'
    manifest_path = ROOT / 'site/evidence/preview.json'
    observation_path = RUN / 'observation.json'
    image_path = RUN / 'screen-545.png'
    if out.exists() or sha(manifest_path) != BEFORE_SHA:
        raise ValueError('Fresh export and exact retained eleven collections required')
    if sha(observation_path) != OBS_SHA or sha(image_path) != IMAGE_SHA:
        raise ValueError('Exact original observation and QMP image required')
    observation = json.loads(observation_path.read_text())
    manifest = json.loads(manifest_path.read_text())
    if (len(manifest['collections']) != 11 or manifest['live']['available']
            or observation['guest_os'] != 'ShizukuDOS Kernel64 standalone'
            or observation['app_functionality_verified']
            or observation['windows98_execution_verified']
            or not observation['inputs_unchanged']):
        raise ValueError('Actual standalone-only observation boundary changed')
    for name, pin in observation['inputs'].items():
        if sha(Path(name)) != pin:
            raise ValueError('Held app observation input changed: ' + name)
    capture = next(c for c in observation['captures'] if c['path'] == str(image_path))
    if capture['sha256'] != IMAGE_SHA or capture['vm_status']['status'] != 'running':
        raise ValueError('Original running-guest capture required')
    old_assets = {}
    for collection in manifest['collections']:
        for frame in collection['frames']:
            path = ROOT / 'site/evidence' / frame['src']
            if sha(path) != frame['sha256']:
                raise ValueError('Retained original image changed')
            old_assets[str(path)] = frame['sha256']
    caption = 'Legcord 1.3.0의 실제 설치 화면입니다. 독립 64비트 실행기에서 기록했으며 Windows 98 내부 연결은 구현 중입니다.'
    collection = {
        'id': 'legcord-runtime-setup',
        'title': 'Legcord 설치 화면 · 독립 64비트 실행기',
        'platform': 'ShizukuDOS Kernel64 · 독립 실행 시험',
        'display': '1024 × 768 · 소프트웨어 화면 출력',
        'result': '실제 설치 화면 표시 · 전체 앱 검증은 진행 중',
        'observations': ['공식 Legcord 1.3.0 배포본의 설치 화면을 실제로 표시했습니다.',
                         'Electron의 HTML 화면이 표시됐습니다. Discord 접속과 전체 조작은 아직 검증하지 못했습니다.'],
        'scope': 'Windows 98 내부에서 실행한 화면은 아닙니다. Windows 98과의 실행·화면·입력 연결 및 Discord 기능은 구현 중입니다. 시험의 전체 결과는 미완료이며 정상 종료도 확인되지 않았습니다.',
        'applicationExecuted': True,
        'applicationFunctionalityVerified': False,
        'windows98ExecutionVerified': False,
        'normalExitVerified': False,
        'observationQemuReturnCode': observation['qemu_returncode'],
        'frames': [{'src': './images/legcord-runtime-setup.png', 'kind': 'guest-capture',
                    'sha256': IMAGE_SHA, 'width': 1024, 'height': 768,
                    'caption': caption, 'alt': caption, 'chapter': 'Legcord 설치 화면',
                    'runLabel': '독립 Kernel64 · Windows 98 내부 연결 전',
                    'captureSeconds': capture['seconds'], 'captureSource': 'qmp-monitor',
                    'receiptSha256': OBS_SHA}],
    }
    html_path = ROOT / 'site/index.html'
    before_html = html_path.read_bytes()
    old_text = 'Chromium·Electron 실행 경로와 Discord 화면·네트워크 연결 검증 필요.'
    new_text = '독립 64비트 실행기에서 실제 Legcord 1.3.0 설치 화면 표시. Windows 98 내부 연결·Discord 접속은 구현 중. <a href="./preview.html?view=legcord-runtime-setup">실제 설치 화면 보기</a>'
    if before_html.decode().count(old_text) != 1:
        raise ValueError('Exact retained Legcord progress row required')
    image = image_path.read_bytes()
    if hashlib.sha256(image).hexdigest() != IMAGE_SHA:
        raise ValueError('Original image changed before copying')
    dest = ROOT / 'site/evidence/images/legcord-runtime-setup.png'
    if dest.exists():
        raise ValueError('Fresh public image required')
    out.mkdir()
    (out / 'preview-before.json').write_bytes(manifest_path.read_bytes())
    (out / 'index-before.html').write_bytes(before_html)
    (out / 'observation.json').write_bytes(observation_path.read_bytes())
    dest.write_bytes(image)
    manifest['collections'].append(collection)
    manifest['generatedUtc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    html_path.write_text(before_html.decode().replace(old_text, new_text))
    for name, pin in old_assets.items():
        if sha(Path(name)) != pin:
            raise ValueError('Prior image changed during export')
    result = {'status': 'RECORDED_STANDALONE_SETUP_ONLY', 'utc': manifest['generatedUtc'],
              'observation': {'path': str(observation_path), 'sha256': OBS_SHA},
              'retained_collections': 11, 'retained_original_images': len(old_assets),
              'new_collection': collection, 'inputs': observation['inputs'],
              'manifest_before_sha256': BEFORE_SHA, 'manifest_after_sha256': sha(manifest_path),
              'index_before_sha256': hashlib.sha256(before_html).hexdigest(),
              'index_after_sha256': sha(html_path), 'source_sha256': sha(Path(__file__)),
              'application_functionality_verified': False, 'windows98_execution_verified': False}
    (out / 'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'result': str(out / 'result.json'),
                      'sha256': sha(out / 'result.json')}))


if __name__ == '__main__':
    main()
