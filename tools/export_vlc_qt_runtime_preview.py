#!/usr/bin/env python3
"""Export original native VLC Qt/video frames with the observed exit failure."""
import datetime
import hashlib
import json
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / 'build/shizukudos/csm/run-win98-gop-vlc-fullchain-qt9-storage-20261001T093100'
OUT = ROOT / 'build/vlc-qt-runtime-preview-export-20261001T1050-v4'
BEFORE = 'aff77022c061a103a7f3bf3b55b66e600ef782d04cc180425b7c82da52ea19b6'
PINS = {
    RUN / 'result.json': '3db47a5fdb630149149445a3e4efb788dee708562060cf42d62f02ce529ce323',
    RUN / 'qt9-video-stream-proof/result.json': '855afbf6379d55f3549e51da6b389d10e5ac1aa4b116f6a0c61c69ff83487d91',
    RUN / 'native-qt9-vlc-video-review.json': 'c208db2f7d1c6e7473466d62b495211e0ed6380114afcead8379e106cc8c32df',
    RUN / 'native-qt9-vlc-fault-identity-correction.json': 'a9446874f2b2e018e0a180c47b30a257c06b703f472952972a24f86b2c097098',
    ROOT / 'build/qt9-rpc-exit-independent-review-20261001T1040-v1/qt9-native-scoped-review.json': 'fc7fdb51a18d6ab3a7b3108633e45fbddea30a08a49684de9b85c436e624a69d',
    ROOT / 'build/qt9-rpc-exit-independent-review-20261001T1040-v1/rpcrt4-exit-mapping-review.json': 'acfd05fbf40a759309e3c722768b0b356abdbfd3fe167ad8d4d2e87f96988298',
}


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


def require(pass_, message):
    if not pass_:
        raise ValueError(message)


def main():
    manifest_path = ROOT / 'site/evidence/preview.json'
    require(not OUT.exists() and sha(manifest_path) == BEFORE, 'Fresh export and exact twelve original collections required')
    for path, pin in PINS.items():
        require(sha(path) == pin, 'Frozen receipt changed: ' + str(path))
    raw = json.loads((RUN / 'result.json').read_text())
    review = json.loads((RUN / 'native-qt9-vlc-video-review.json').read_text())
    correction = json.loads((RUN / 'native-qt9-vlc-fault-identity-correction.json').read_text())
    proof = json.loads((RUN / 'qt9-video-stream-proof/result.json').read_text())
    peer = json.loads((ROOT / 'build/qt9-rpc-exit-independent-review-20261001T1040-v1/qt9-native-scoped-review.json').read_text())
    require(raw['qemu_exit_code'] == 0 and raw['originals_unchanged'] and raw['prepared_source_unchanged'], 'Stopped unchanged native run required')
    post = RUN / 'windows-uefi.raw'
    post_sha = sha(post)
    require(post_sha == raw['owned_disk_sha256_after_run'] == proof['actual_full_postraw_sha256'] == review['actual_full_postraw_sha256'], 'Independent whole stopped disk hash must bind the logs')
    require(review['status'] == 'FAIL-VLC-CLEAN-EXIT' and not review['native_checks']['clean_exit_without_fault'], 'Preserve real VLC exit failure')
    require(correction['corrected_module'] == 'RPCRT4.DLL' and correction['byte_binding']['fault_rva'] == 0x181C, 'Additive RPC identity correction required')
    require(peer['VLC_scope']['actual_Qt_GUI_and_changing_local_video'] and peer['VLC_scope']['clean_exit'] == 'FAIL', 'Independent scoped native acceptance required')
    require(len(proof['files']) == 84 and all(f['status'] == 'PASS' for f in proof['files']), 'Exact held graph required')
    logs = {}
    for row in proof['logs']:
        path = Path(row['path'])
        require(path.stat().st_size == row['bytes'] and sha(path) == row['sha256'], 'Fresh exact native output required')
        logs[row['guest']] = path.read_text(encoding='utf-8-sig')
    boot = logs['VXDLAB/QTBOOT.LOG']
    work = logs['VXDLAB/QTWORK.LOG']
    require(boot.count('EXACT_INPUT_SHA256=00000001') == 6 and 'OWN_RUNTIME_MODE_FLAGS=00000080\n' in boot, 'Six pins and actual native WINXP valid bit required')
    require('ACTUAL_WAIT_RESULT=00000000\n' in boot and 'ACTUAL_CHILD_EXIT_CODE=00000000\n' in boot, 'Actual diagnostic child wait and OS exit required')
    require('QT_IMPORTS_INSPECTED=0000028D\n' in work and 'UNRESOLVED_IMPORTS=00000000\n' in work and 'OWN_MODULE_RELEASE_FAILURES=00000000\n' in work, 'All 653 resolved imports required')
    require(sum(line.startswith('RESOLVED_OWNER=') for line in work.splitlines()) == 13, 'Thirteen actual owner records required')
    require('QT_NATIVE_LOAD_HANDLE=6E100000\n' in work and 'QT_NATIVE_LOAD_SUCCESS=00000001\n' in work and 'QT_NATIVE_LOAD_ERROR=00000000\n' in work, 'Actual non-null Qt native load required')
    # Compare only the real video interior, excluding playhead, taskbar and clock.
    interiors = []
    roi_rows = []
    for row in review['video_roi']:
        path = RUN / ('screen-%03d.png' % row['original_index'])
        with Image.open(path) as picture:
            require(picture.size == (1280, 800), 'Original GOP dimensions required')
            rgb = picture.convert('RGB').crop((503, 193, 662, 313)).tobytes()
        require(hashlib.sha256(rgb).hexdigest() == row['rgb_sha256'], 'Real ROI hash changed')
        colors = {tuple(rgb[n:n + 3]) for n in range(0, len(rgb), 3)}
        require(len(colors) == 2, 'Only native two-color video content expected')
        interiors.append(rgb)
        roi_rows.append(row)
    changed = sum(interiors[0][n:n + 3] != interiors[2][n:n + 3] for n in range(0, len(interiors[0]), 3))
    require(changed == review['interior_changed_pixels_162_to164'] == 4200, 'Actual video content must change')
    manifest = json.loads(manifest_path.read_text())
    require(len(manifest['collections']) == 12 and not manifest['live']['available'], 'Retain recorded collection boundary')
    old_assets = {}
    for collection in manifest['collections']:
        for frame in collection['frames']:
            path = ROOT / 'site/evidence' / frame['src']
            require(sha(path) == frame['sha256'], 'Prior original screenshot changed')
            old_assets[str(path)] = frame['sha256']
    specs = [
        (162, 'vlc-qt-video-1.png', 'VLC의 실제 메뉴·재생 버튼과 00:11 지점의 시험 영상입니다.'),
        (163, 'vlc-qt-video-2.png', '같은 실제 플레이어에서 영상 내용과 재생 위치가 바뀌었습니다.'),
        (164, 'vlc-qt-video-3.png', '00:17 지점의 실제 영상입니다. 영상 영역에서 4,200개 픽셀이 바뀌었습니다.'),
        (184, 'vlc-qt-exit-error.png', '종료할 때 실제 RPCRT4 오류 창이 떴습니다. 정상 종료 검증은 실패했습니다.'),
        (194, 'vlc-qt-exit-details.png', '실제 종료 오류의 코드·스택입니다. 오류 창을 닫은 뒤의 종료 코드 0은 정상 종료 성공을 뜻하지 않습니다.'),
    ]
    frames = []
    images = {}
    for index, name, caption in specs:
        capture = next(c for c in raw['captures'] if Path(c['screenshot']).name == 'screen-%03d.png' % index)
        original = Path(capture['screenshot'])
        data = original.read_bytes()
        require(hashlib.sha256(data).hexdigest() == capture['sha256'], 'Exact original QMP PNG required')
        dest = ROOT / 'site/evidence/images' / name
        require(not dest.exists(), 'Fresh additive public image required')
        images[dest] = data
        frames.append({'src': './images/' + name, 'kind': 'guest-capture', 'sha256': capture['sha256'],
                       'width': 1280, 'height': 800, 'caption': caption, 'alt': caption,
                       'chapter': '실제 VLC 영상' if index < 170 else '남아 있는 종료 오류',
                       'captureSeconds': capture['seconds'], 'captureSource': 'qmp-monitor',
                       'runLabel': '실제 Windows 98 · UEFI GOP', 'receiptSha256': PINS[RUN / 'result.json']})
    collection = {'id': 'vlc-qt-video-gop', 'title': 'VLC 실제 플레이어와 영상 · Windows 98 GOP',
                  'platform': '실제 Microsoft Windows 98 SE · UEFI 부팅', 'display': '1280 × 800 · Shizuku 기본 GOP 그래픽 드라이버',
                  'result': '실제 메뉴·영상 재생 확인 · 종료 오류 수정 중',
                  'observations': ['VLC 3.0.24의 실제 메뉴와 재생 버튼, 움직이는 시험 영상을 확인했습니다.',
                                   '정상 종료는 RPCRT4 오류로 실패했습니다. 소리 출력은 아직 검증하지 않았습니다.'],
                  'scope': '실제 Windows 98에서 기록한 화면입니다. Qt 진단 실행 후의 플레이어 시험이며, 진단 실행의 영향은 별도 부팅에서 확인 중입니다. 영상은 160×120 시험 AVI입니다. 전체 앱·음성·3D 가속 성공을 뜻하지 않습니다. 오류 창을 닫은 뒤의 종료 코드 0은 정상 종료 성공이 아닙니다.',
                  'applicationExecuted': True, 'windows98ExecutionVerified': True,
                  'applicationFunctionalityVerified': False, 'normalExitVerified': False,
                  'audioVerified': False, 'realQtPlayerVerified': True, 'changingVideoVerified': True,
                  'frames': frames}
    html_path = ROOT / 'site/index.html'
    html = html_path.read_text()
    changes = {
        './preview.html?view=vlc-video-gop': './preview.html?view=vlc-qt-video-gop',
        './evidence/images/vlc-video-1.png': './evidence/images/vlc-qt-video-1.png',
        '영상 출력과 내용 변화를 확인했습니다. 전체 플레이어와 소리는 개발 중입니다.': '실제 메뉴와 재생 버튼, 움직이는 영상을 확인했습니다. 소리·종료 오류는 개발 중입니다.',
        '실제 Windows 98에서 영상 변화 확인. 전체 조작 화면·음성·정상 종료는 개발 중입니다.': '실제 Windows 98에서 메뉴·재생 버튼·영상 확인. 소리와 종료 오류는 개발 중입니다.',
    }
    for before, after in changes.items():
        require(before in html, 'Retained homepage target changed')
        html = html.replace(before, after)
    OUT.mkdir(parents=True, exist_ok=False)
    (OUT / 'preview-before.json').write_bytes(manifest_path.read_bytes())
    (OUT / 'index-before.html').write_bytes(html_path.read_bytes())
    for path, data in images.items():
        path.write_bytes(data)
    manifest['collections'].append(collection)
    manifest['generatedUtc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    html_path.write_text(html)
    require(all(sha(Path(path)) == pin for path, pin in old_assets.items()), 'All prior images retained exactly')
    result = {'status': 'NATIVE_QT_GUI_AND_CHANGING_VIDEO_ONLY_CLEAN_EXIT_FAIL',
              'receipts': {str(path): pin for path, pin in PINS.items()},
              'independent_stopped_postraw_sha256': post_sha, 'source_sha256': sha(Path(__file__)),
              'retained_collections': 12, 'retained_images': len(old_assets),
              'manifest_before_sha256': BEFORE, 'manifest_after_sha256': sha(manifest_path),
              'new_collection': collection, 'video_roi': roi_rows, 'changed_video_pixels': changed,
              'whole_application_verified': False, 'clean_exit_verified': False, 'audio_verified': False}
    (OUT / 'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'receipt': str(OUT / 'result.json'), 'sha256': sha(OUT / 'result.json')}))


if __name__ == '__main__':
    main()
