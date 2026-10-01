#!/usr/bin/env python3
"""Append original Win98 controls captures; never launch or accept applications."""
import datetime
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / 'build/shizukudos/csm/run-win98-gop-native-null-delay-address-20261001T0147'
PINS = {
    RUN / 'result.json': '599df88d89c576734f52561bb86452c0a395ade04810dea345a7f39bfebf3884',
    RUN / 'native-controls-review.json': 'ba6ae2f1f9221bab3b0cf7a7c880322ac93f382ce52df86bedc13936ede460dc',
    ROOT / 'build/native-controls-independent-20261001T0402-v2/result.json': '4effe5acd8f01dba4d9da00fea216527974b0bb98d5d031b16ff59deb7f0c6f0',
}
FRAMES = (
    ('009', 'native-app-desktop.png', '실제 Windows 98 부팅', 'Shizuku 기본 그래픽 드라이버로 부팅한 실제 Windows 98 바탕화면입니다.'),
    ('061', 'native-app-thread.png', '스레드 격리와 종료', '실제 작업 스레드의 데이터 격리와 종료 후 알림을 확인했습니다.'),
    ('074', 'native-app-functions.png', '함수 연결', '실제 Windows 98 함수를 연결·호출하고 작업 스레드가 끝난 뒤 해제했습니다.'),
    ('090', 'native-app-wait.png', '대기와 깨우기', '실제 작업 스레드의 대기·깨우기 순서와 정상 종료를 확인했습니다.'),
)

def sha(raw): return hashlib.sha256(raw).hexdigest()
def load(path, pin=None):
    raw = path.read_bytes()
    if pin and sha(raw) != pin: raise ValueError('Changed retained receipt: ' + str(path))
    return json.loads(raw)

def main():
    out = ROOT / 'build/native-controls-preview-export-20261001T0548-v1'
    out.mkdir(exist_ok=False)
    raw = load(RUN / 'result.json', PINS[RUN / 'result.json'])
    native = load(RUN / 'native-controls-review.json', PINS[RUN / 'native-controls-review.json'])
    independent = load(next(p for p in PINS if p.parent.name.startswith('native-controls-independent')), '4effe5acd8f01dba4d9da00fea216527974b0bb98d5d031b16ff59deb7f0c6f0')
    if (independent['status'] != 'SCOPED_NATIVE_CONTROLS_ACCEPTED' or independent['check_count'] != 113 or
            not all(i['pass'] is True for i in independent['checks']) or independent['target_application_success'] or
            raw['qemu_exit_code'] != 0 or raw['status'] != 'NEEDS-VISUAL-REVIEW' or
            not raw['prepared_source_unchanged'] or not raw['originals_unchanged']):
        raise ValueError('Incomplete scoped native evidence')
    files = []
    for item in native['files']:
        p = Path(item['path']).resolve(strict=True)
        if not p.is_relative_to(RUN) or p.stat().st_size != item['bytes'] or sha(p.read_bytes()) != item['sha256']:
            raise ValueError('Retained small readback changed')
        files.append(item)
    if len(files) != 37: raise ValueError('Expected complete37 readback corpus')
    path = ROOT / 'site/evidence/preview.json'
    before = path.read_bytes(); manifest = json.loads(before)
    if len(manifest['collections']) != 10 or manifest['live']['available']:
        raise ValueError('Expected retained10 recorded collections')
    old_assets = []
    for c in manifest['collections']:
        for f in c['frames']:
            p = ROOT / 'site/evidence' / f['src']
            if sha(p.read_bytes()) != f['sha256']: raise ValueError('Previous image changed')
            old_assets.append({'path': str(p), 'sha256': f['sha256']})
    if len({i['path'] for i in old_assets}) != 38: raise ValueError('Expected retained38 original images')
    (out / 'preview-before.json').write_bytes(before)
    captures = {Path(i['screenshot']).name: i for i in raw['captures'] if i.get('screenshot')}
    frames = []
    for number, name, chapter, caption in FRAMES:
        capture = captures['screen-' + number + '.png']; source = Path(capture['screenshot']).resolve(strict=True)
        data = source.read_bytes(); dest = ROOT / 'site/evidence/images' / name
        if not source.is_relative_to(RUN) or sha(data) != capture['sha256'] or capture['screenshot_status'] != 'captured':
            raise ValueError('Original capture changed')
        if data[:8] != b'\x89PNG\r\n\x1a\n' or struct.unpack('>II', data[16:24]) != (1280, 800) or dest.exists():
            raise ValueError('Fresh original1280x800 PNG required')
        dest.write_bytes(data)
        frames.append({'src': './images/' + name, 'kind': 'guest-capture', 'sha256': sha(data),
                       'width': 1280, 'height': 800, 'caption': caption, 'alt': caption, 'chapter': chapter,
                       'runLabel': '앱 호환 기능 시험 · 실제 Windows 98 GOP', 'captureSeconds': capture['seconds'],
                       'captureSource': 'qmp-monitor', 'receiptSha256': PINS[RUN / 'result.json'],
                       'verificationReceiptSha256': '4effe5acd8f01dba4d9da00fea216527974b0bb98d5d031b16ff59deb7f0c6f0'})
    collection = {'id': 'native-app-foundations', 'title': '앱 호환 기능 시험 · 실제 Windows 98',
        'platform': 'Microsoft Windows 98 4.10.2222 한국어',
        'display': '1280 × 800 · Shizuku 기본 그래픽 드라이버 · KVM',
        'result': '작업 스레드·함수 연결·대기 기능 확인',
        'observations': ['실제 Windows 98 안에서 작업 스레드의 데이터 격리와 종료 알림을 확인했습니다.',
                         '실제 시스템 함수 연결과 주소 기반 대기·깨우기 시험을 각각28개 통과했습니다.',
                         '세 시험의 자식 프로세스가 실제로 정상 종료했고 기존 드라이버와 편집기 파일도 유지됐습니다.'],
        'scope': '앱 실행에 필요한 기능을 확인한 시험입니다. Chromium의 브라우저 화면과 웹 탐색, Legcord·LibreOffice·Steam의 Windows 98 구동은 계속 구현 중입니다.',
        'rawRunStatuses': ['NEEDS-VISUAL-REVIEW'], 'applicationExecuted': False, 'ChromiumGUIAcceptance': False,
        'outerObserverOwnOSExitVerified': False, 'physicalWorkerCessationEstablished': False,
        'nativeControlsAccepted': True, 'actualChildNormalExits': 3, 'frames': frames}
    manifest['collections'].append(collection)
    manifest['generatedUtc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    after = (json.dumps(manifest, ensure_ascii=False, indent=2) + '\n').encode()
    if json.loads(after)['collections'][:-1] != json.loads(before)['collections']:
        raise ValueError('Prior collections changed')
    path.write_bytes(after)
    receipt = {'status': 'SCOPED_ORIGINAL_PREVIEW_EXPORT_PASS', 'utc': manifest['generatedUtc'],
        'receipts': [{'path': str(p), 'sha256': pin} for p, pin in PINS.items()], 'readback_files': files,
        'old_assets': old_assets, 'old_collections': 10, 'retained_old_unique_images': 38,
        'new_collection': collection['id'], 'new_frames': frames, 'manifest_before_sha256': sha(before),
        'manifest_after_sha256': sha(after), 'source_sha256': sha(Path(__file__).read_bytes()),
        'native_test_reexecuted': False, 'ChromiumGUIAcceptance': False,
        'scope': 'Three pinned native receipts,37 exact small readbacks,4 original PNGs; no2GiB rehash/VM/service/publisher/DNS/target execution.'}
    p = out / 'result.json'; p.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'status': receipt['status'], 'result': str(p), 'sha256': sha(p.read_bytes())}))

if __name__ == '__main__': main()
