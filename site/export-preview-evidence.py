#!/usr/bin/env python3
"""Export selected unmodified guest captures after verifying their run receipts.

Writes only site/evidence (selected PNG bytes and a public manifest). It neither
boots guests nor installs tools, and never publishes private raw run receipts.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
CSM = ROOT / 'build/shizukudos/csm'
MANUAL = CSM / 'run-win98-uefi-q35-kvm-helper-id-gui-manual'
COLD = CSM / 'run-win98-uefi-q35-kvm-native-vxd-shared-data'
DESKTOP = ROOT / 'build/desktop-harness-iso/20260930T132352-fr68teka'
INSTALL = CSM / 'run-win98-uefi-q35-kvm-gop-driver-install'
INSTALL_RECEIPT = 'e1cff27d0ab07c77b32e345aa85b1bd6738ca4f54ad63f905d7eab0956625c6a'
INSTALL_REVIEW = 'a631ae988b2f5f08df7b3bf5799a51debff67cb56c07cb685a859d14da718c4c'
NATIVE_GOP = CSM / 'run-win98-uefi-q35-kvm-gop-ne-selector-probe'
NATIVE_GOP_RECEIPT = 'fe3ff557d190676e8e82433cd47825786245d4bcda5e21cab3fdec65cf657296'
NATIVE_GOP_REVIEW = '864adb8dc50e76ceefce3007cad2e9b0478e114cf1bf93cba485ebe71f63847a'
NATIVE_GOP_DECODING = '7eaa9132350362b5b2c0bc2831d9dbc21e0de81e46317c7d56000c4c25e86f6a'
NATIVE_GOP_DECODER = 'bef00758bdaba26ce3ec5225ac4a8da9aa44eca2ed75bbf9ae628f909c183d58'
MONITOR_AUDIT = CSM / 'gop-monitor-correction-audit-20260930T155157/correction-audit.json'
MONITOR_AUDIT_SHA = 'a01cef2ab1b74594fcac22a68d97450ff513560b446f2621c817dba1ff6b9969'
NATIVE_FILE = CSM / 'run-win98-uefi-q35-kvm-gop-native-providers-and-file'
NATIVE_FILE_RECEIPT = '447f265637cee62d858092cf7acfdb08c0c55fb846369517763185ed3e9f8026'
NATIVE_FILE_REVIEW = '9b2da011af1368cf5d0ff555eeee63235194d1f3fabc4145e2a677d1772a59bd'
LATEST_NPP = CSM / 'run-win98-latest-npp-execute-20260930T1657'
LATEST_NPP_PROOF = ROOT / 'build/native-npp-controls/latest-npp-trial-20260930T1714/result.json'
LATEST_NPP_PROOF_SHA = 'f0ea413eaf74b72f1fd0d62c0283e357dc68dd90b66dfe7e52804a9c2b2f7003'
LATEST_NPP_COLD = CSM / 'run-win98-latest-npp-cold-reopen-20260930T1722'
LATEST_NPP_COLD_PROOF = ROOT / 'build/native-npp-controls/cold-reopen-proof-20260930T1729/result.json'
LATEST_NPP_COLD_PROOF_SHA = '1b387e4ac6091d28a7fa79c87d038b42cc5669156dd7d05ad41a0ad431b88e53'
LATEST_NPP_GOP = CSM / 'run-win98-gop-latest-npp-environment-v3-20260930T1748'
LATEST_NPP_GOP_PROOF_SHA = '4969701e15e2170caa6927bdb9cd2c40a34367d3666d7487caa00f8170e1bfa5'
LATEST_NPP_GOP_COLD = CSM / 'run-win98-gop-latest-npp-cold-v3-20260930T1807'
LATEST_NPP_GOP_COLD_PROOF_SHA = 'e945062ad535c5e2b61f7ee39be91c308d1103b29ff3d44d0f5b2e3455d40175'
MANUAL_RECEIPT = 'bef6c72dac399ddab964f8eb6b86ec48ccc26f94668870bcd86ffc7656b433a3'
COLD_RECEIPT = 'b6ca2f23a6b1afac62ff26187937d3b23650dffef3eaddf8e1a8193a8eca06aa'
VLC_FIRST = CSM / 'run-win98-gop-vlc-video-20260930T2250'
VLC_FIRST_RAW_SHA = '49592049aee85b8a080e4fed11869a2cbaecfff0e05eb23d064d5dfbc7b9b41b'
VLC_FIRST_READBACK_SHA = '2c10babca9a67868f12669ded7f4ced56f399e0081f0f2d55c5540fb764f8da7'
VLC_FIRST_REVIEW_SHA = 'f3e7dc672c5e0ed60d27682b41d73ce026ae176e08e182007643c4d2728da678'
VLC_FIRST_CORRECTION_SHA = 'a88fe6258ea3dfa80c13741eff7176a3503282ae0248cdf55c076175dc354bce'
VLC_FIRST_INDEPENDENT = ROOT / 'build/vlc-first-trial-independent-review-l6eeblga/result.json'
VLC_FIRST_INDEPENDENT_SHA = 'c9c9e9faae54f2efa64af7700087695f75b06c150b24c4c128101a3a0dbeb635'
VLC_VIDEO = CSM / 'run-win98-gop-vlc-filelogger-video-20260930T2338'
VLC_VIDEO_RAW_SHA = '3fb19e2bbe77de4ac1bb9f1695d6e90d55987f02733c83657187b4cec670bd08'
VLC_VIDEO_READBACK_SHA = 'a4abb473e2424f2ff334a108bb967cfbc3751fe951c831e4502966e59fe3607c'
VLC_VIDEO_REVIEW_SHA = '82bedbd977cf57bdc23e312a910ac5d0cda1e61d24821518fa0068e91c368aa8'
VLC_VIDEO_INDEPENDENT = ROOT / 'build/vlc-corrected-video-independent-78hysydr/result.json'
VLC_VIDEO_INDEPENDENT_SHA = 'c4fd102f2bdbb08af26a93e58e3ab9f533394959687c1f4aac327327c272371f'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    data = path.read_bytes()
    return json.loads(data), digest(data)


def native_run(folder, expected):
    result, result_sha = load(folder / 'result.json')
    review, review_sha = load(folder / 'visual-review.json')
    if result_sha != expected or review['receipt_sha256'] != result_sha:
        raise ValueError(f'Native review does not identify the frozen run: {folder.name}')
    if result['profile'] != 'actual-win98-uefi-csmwrap':
        raise ValueError('A native Windows 98 run is required')
    return result, review, result_sha, review_sha


def export_frame(source, expected, filename, receipt_sha, run_label, caption, chapter, seconds=None):
    path = Path(source).resolve()
    path.relative_to(ROOT / 'build')
    data = path.read_bytes()
    if digest(data) != expected:
        raise ValueError(f'Screenshot no longer matches its capture receipt: {path.name}')
    if data[:16] != b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR':
        raise ValueError('Expected an original PNG guest capture')
    width, height = struct.unpack('>II', data[16:24])
    if not 0 < width <= 16384 or not 0 < height <= 16384:
        raise ValueError('Invalid capture dimensions')
    frame = {'src': f'./images/{filename}', 'kind': 'guest-capture',
             'sha256': expected, 'width': width, 'height': height,
             'caption': caption, 'alt': caption, 'chapter': chapter,
             'runLabel': run_label, 'receiptSha256': receipt_sha}
    if seconds is not None:
        frame['captureSeconds'] = seconds
    return frame, data


def all_pass(checks):
    return bool(checks) and all(item['status'] == 'PASS' for item in checks)


def vlc_startup_failure_frames():
    """Preserve an actual startup failure without treating child exit as playback."""
    run, run_sha = load(VLC_FIRST / 'result.json')
    readback, readback_sha = load(VLC_FIRST / 'vlc-first-trial-readback.json')
    review, review_sha = load(VLC_FIRST / 'native-vlc-first-trial-review.json')
    correction, correction_sha = load(VLC_FIRST / 'native-vlc-first-trial-review-correction.json')
    independent, independent_sha = load(VLC_FIRST_INDEPENDENT)
    if (run_sha != VLC_FIRST_RAW_SHA or readback_sha != VLC_FIRST_READBACK_SHA or
            review_sha != VLC_FIRST_REVIEW_SHA or
            correction_sha != VLC_FIRST_CORRECTION_SHA or
            independent_sha != VLC_FIRST_INDEPENDENT_SHA):
        raise ValueError('Frozen first VLC failure evidence changed')
    if (run['profile'] != 'actual-win98-uefi-csmwrap' or
            run['status'] != 'NEEDS-VISUAL-REVIEW' or run['qemu_exit_code'] != 0 or
            not run['originals_unchanged'] or not run['prepared_source_unchanged'] or
            readback['status'] != 'SCOPED-VLC-STARTUP-FAIL' or
            not readback['source_disk_unchanged'] or
            readback['raw_receipt_sha256'] != run_sha or
            readback['postdisk_sha256'] != run['owned_disk_sha256_after_run'] or
            review['status'] != 'FAIL' or review['raw_receipt']['sha256'] != run_sha or
            review['readback_receipt']['sha256'] != readback_sha or
            independent['status'] != 'SCOPED-NATIVE-VLC-STARTUP-FAIL' or
            independent['checks_passed'] != independent['checks_total'] or
            independent['checks_total'] != 156 or
            not all(c['pass'] for c in independent['checks']) or
            not independent['failure_preserved']):
        raise ValueError('Expected the bounded native VLC startup failure')
    if (independent['gui_acceptance'] or independent['video_playback_acceptance'] or
            independent['audible_audio_acceptance'] or
            independent['audio_child_exit_observed'] or
            independent['observer_own_os_exit_observed'] or
            independent['video_child_actual_exit'] != 0 or
            independent['file_logger_missing_is_sole_root_cause_proven']):
        raise ValueError('VLC evidence exceeds the observed startup/exit scope')
    if ({r['sha256'] for r in independent['source_receipts']} !=
            {run_sha, readback_sha} or readback['staged_original47_verified'] != 47 or
            readback['protected_files_verified'] != 27 or len(readback['files']) != 76 or
            set(readback['absent_outputs']) != {'VLCLAB/VIDEO.LOG', 'VLCLAB/AUDIO.LOG'}):
        raise ValueError('Expected all frozen app inputs, protected files and fresh logs')
    # Preserve the earlier mistaken count and bind its additive correction.
    if (review['actual_checks']['original47_appinputs_and27_protected_files_exact'] or
            correction['status'] != 'PRESERVATION-GATE-CORRECTED-APP-STARTUP-FAIL-RETAINED' or
            correction['original_review']['sha256'] != review_sha or
            not correction['original_review']['unchanged'] or
            correction['actual_readback']['sha256'] != readback_sha or
            not correction['corrected_value'] or not all(correction['checks'].values()) or
            not correction['application_verdict'].startswith('FAIL:') or
            {k: v['count'] for k, v in correction['groups'].items()} !=
            {'staged': 47, 'preserved': 27, 'watch': 2}):
        raise ValueError('Expected the additive count correction with startup failure retained')
    for record in readback['files']:
        path = Path(record['path']).resolve()
        if path.parent != VLC_FIRST / 'vlc-trial-readback':
            raise ValueError('VLC readback escaped the original owned run')
        data = path.read_bytes()
        if (record['status'] != 'PASS' or len(data) != record['bytes'] or
                digest(data) != record['sha256']):
            raise ValueError('Original VLC staged/protected/log bytes changed')
    video = set(readback['watch_logs']['VIDWATCH.LOG'].splitlines())
    audio = set(readback['watch_logs']['AUDWATCH.LOG'].splitlines())
    if (not {'ACTUAL_CHILD_EXIT_CODE=00000000',
             'STATUS=ACTUAL_CHILD_NORMAL_ZERO_EXIT',
             'GUI_MEDIA_ACCEPTANCE_REQUIRES_SEPARATE_ORIGINAL_GUEST_EVIDENCE=1'} <= video or
            any(line.startswith('ACTUAL_CHILD_EXIT_CODE=') for line in audio)):
        raise ValueError('Actual video/audio process observations changed')
    frames, blobs = [], {}
    for original, name, chapter, caption in [
        ('screen-040.png', 'vlc-first-video-error.png', '영상 실행 오류',
         '원본 VLC 3.0.24를 Windows 98 GOP 화면에서 실행했지만 옵션 또는 플러그인 오류로 시작에 실패했습니다.'),
        ('screen-137.png', 'vlc-first-video-exit.png', '오류 후 종료 값 확인',
         '오류 창을 닫은 뒤 실제 VLC 자식 프로세스의 종료 값은 0입니다. 영상 재생 성공을 뜻하지 않습니다.'),
        ('screen-187.png', 'vlc-first-audio-error.png', '음성 실행 오류',
         '음성 시험에서도 시작 오류가 나타났습니다. 종료 값과 실제 음성 출력은 확인되지 않았습니다.')]:
        path = VLC_FIRST / original
        captures = [c for c in run['captures']
                    if Path(c.get('screenshot', '')).resolve() == path]
        inspected = [r for r in independent['original_frames']
                     if Path(r['path']).resolve() == path]
        if (len(captures) != 1 or len(inspected) != 1 or
                not inspected[0]['viewed_original'] or
                captures[0]['sha256'] != inspected[0]['sha256']):
            raise ValueError('VLC failure frame is not uniquely bound to its original review')
        frame, blob = export_frame(path, captures[0]['sha256'], name, run_sha,
            'VLC 3.0.24 · 첫 Windows 98 GOP 실행', caption, chapter,
            captures[0].get('seconds'))
        frame.update(captureSource='qmp-monitor',
                     verificationReceiptSha256=independent_sha)
        frames.append(frame)
        blobs[name] = blob
    return frames, blobs, [review_sha, readback_sha, independent_sha, correction_sha]


def vlc_rendering_frames():
    """Export real video motion while retaining the whole-player GUI failure."""
    from PIL import Image
    run, run_sha = load(VLC_VIDEO / 'result.json')
    readback, readback_sha = load(VLC_VIDEO / 'vlc-corrected-rendering-readback.json')
    review, review_sha = load(VLC_VIDEO / 'native-vlc-corrected-rendering-review.json')
    independent, independent_sha = load(VLC_VIDEO_INDEPENDENT)
    if (run_sha, readback_sha, review_sha, independent_sha) != (
            VLC_VIDEO_RAW_SHA, VLC_VIDEO_READBACK_SHA,
            VLC_VIDEO_REVIEW_SHA, VLC_VIDEO_INDEPENDENT_SHA):
        raise ValueError('Frozen corrected VLC rendering evidence changed')
    if (run['profile'] != 'actual-win98-uefi-csmwrap' or
            run['status'] != 'NEEDS-VISUAL-REVIEW' or run['qemu_exit_code'] != 0 or
            not run['originals_unchanged'] or not run['prepared_source_unchanged'] or
            review['status'] != 'PARTIAL-VIDEO-RENDERED-PLAYER-GUI-FAIL' or
            readback['status'] != review['status'] or
            review['raw_receipt']['sha256'] != run_sha or
            review['readback']['sha256'] != readback_sha or
            readback['raw_run_receipt_sha256'] != run_sha or
            readback['postdisk_sha256'] != run['owned_disk_sha256_after_run'] or
            independent['source_review_sha256'] != review_sha or
            independent['status'] != 'PARTIAL_REAL_VIDEO_RENDERING_QT_GUI_FAIL' or
            len(independent['checks']) != 184 or
            not all(c['pass'] for c in independent['checks'])):
        raise ValueError('Expected bounded native VLC video rendering with GUI failure')
    if (independent['full_player_GUI_verified'] or independent['actual_child_exit_observed'] or
            independent['audio_executed'] or independent['persisted_FILE_LOG_contents_available'] or
            independent['whole_screen_inequality_used'] or independent['screenshots_edited'] or
            readback['counts'] != {'exact_staged_inputs': 47, 'exact_protected_setup_pins': 27,
                                  'log_entries': 2, 'total': 76} or len(readback['files']) != 76):
        raise ValueError('VLC rendering scope exceeds actual evidence')
    logs = {}
    for record in readback['files']:
        path = Path(record['path']).resolve()
        if path.parent != VLC_VIDEO / 'vlc-trial-readback':
            raise ValueError('Corrected VLC readback escaped its owned run')
        data = path.read_bytes()
        if len(data) != record['bytes'] or digest(data) != record['sha256']:
            raise ValueError('Corrected VLC staged/protected/log bytes changed')
        if record['group'] == 'log':
            logs[path.name] = data
        elif record['status'] != 'PASS':
            raise ValueError('Corrected VLC preservation check failed')
    if (logs['log-1-VIDEO.LOG'] != b'' or
            b'ACTUAL_CHILD_EXIT_CODE=' in logs['log-0-VIDWATCH.LOG'] or
            not all(not review['actual_checks'][key] for key in (
                'full_qt_player_controls', 'persisted_video_log_contents',
                'actual_normal_child_exit_observed', 'audio_execution'))):
        raise ValueError('Unobserved VLC log/exit/GUI scope changed')
    frames, blobs = [], {}
    reviewed = {Path(item['path']).resolve(): item
                for item in review['frames_visually_reviewed_originals']}
    for index, record in enumerate(independent['frames']):
        path = Path(record['original']).resolve()
        if path.parent != VLC_VIDEO or record['strict_interior_roi'] != [114, 133, 273, 253]:
            raise ValueError('Exact original video region required')
        with Image.open(path) as original:
            roi = original.convert('RGB').crop(tuple(record['strict_interior_roi']))
            pixels = roi.tobytes()
            colors = set(roi.getdata())
            yellow = sum(all(roi.getpixel((x, y)) == (240, 180, 32)
                             for y in range(120)) for x in range(159))
        if (digest(pixels) != record['interior_rgb_sha256'] or
                colors != {(24, 40, 120), (240, 180, 32)} or
                yellow != [46, 73, 99][index] or
                yellow != record['yellow_full_height_columns'] or
                reviewed[path]['sha256'] != record['sha256']):
            raise ValueError('Original video interior motion no longer matches')
        frame, blob = export_frame(path, record['sha256'], f'vlc-video-{index + 1}.png',
            run_sha, 'VLC 3.0.24 · Windows 98 GOP 영상 출력',
            '실제 VLC 영상 영역의 노란색 막대가 시간에 따라 늘어납니다. 전체 조작 화면과 정상 종료는 미확인입니다.',
            f'영상 프레임 {index + 1}', reviewed[path]['seconds'])
        frame.update(captureSource='qmp-monitor', verificationReceiptSha256=independent_sha)
        frames.append(frame)
        blobs[f'vlc-video-{index + 1}.png'] = blob
    if len(frames) != 3:
        raise ValueError('Three original video frames required')
    path = VLC_VIDEO / 'screen-080.png'
    if str(path) not in independent['originals_personally_viewed']:
        raise ValueError('Original Qt failure frame review required')
    record = reviewed[path]
    frame, blob = export_frame(path, record['sha256'], 'vlc-video-qt-error.png', run_sha,
        'VLC 3.0.24 · Windows 98 GOP 영상 출력',
        '실제 메모장에 열린 실행 기록에 Qt 화면 구성 요소의 로드 실패가 보입니다. 디스크의 기록 파일은 0바이트입니다.',
        '남은 화면 구성 오류', record['seconds'])
    frame.update(captureSource='qmp-monitor', verificationReceiptSha256=independent_sha)
    frames.append(frame)
    blobs['vlc-video-qt-error.png'] = blob
    # Bind every selected unchanged PNG to the original QMP capture list.
    for frame, path in zip(frames, [Path(row['original']) for row in independent['frames']] + [path]):
        captures = [c for c in run['captures'] if Path(c.get('screenshot', '')).resolve() == path]
        if len(captures) != 1 or captures[0]['sha256'] != frame['sha256']:
            raise ValueError('Selected VLC video frame is not an original QMP capture')
    return frames, blobs, [run_sha, readback_sha, review_sha, independent_sha]


def monitor_gop_frames():
    """Export original monitor captures; preserve and supersede prior reviews."""
    from PIL import Image
    audit, audit_sha = load(MONITOR_AUDIT)
    if (audit_sha != MONITOR_AUDIT_SHA or
            audit['kind'] != 'additive-native-gop-monitor-review-correction' or
            audit['status'] != 'PASS-NATIVE-WIN98-GOP-GUI-GDI' or
            audit['full_project_goal_complete'] or len(audit['runs']) != 2):
        raise ValueError('Expected the exact additive native monitor audit')
    frames, blobs = [], {}
    for index, row in enumerate(audit['runs']):
        folder = Path(row['run']).resolve()
        folder.relative_to(CSM)
        run, run_sha = load(folder / 'result.json')
        _, old_review_sha = load(folder / 'visual-review.json')
        if (run_sha != row['execution_receipt_sha256'] or
                old_review_sha != row['old_visual_review_sha256'] or
                run['profile'] != 'actual-win98-uefi-csmwrap' or
                run['status'] != row['execution_status_preserved'] or
                not row['originals_unchanged'] or not row['prepared_parent_unchanged'] or
                row['monitor_visible_native_win98'] != 'PASS' or
                not row['old_visual_review_preserved_unchanged']):
            raise ValueError('Original native run or preserved review changed')
        image_path = Path(row['screenshot']).resolve()
        if image_path.parent != folder:
            raise ValueError('Monitor capture escaped its frozen run')
        matches = [c for c in run['captures'] if Path(c.get('screenshot', '')).resolve() == image_path]
        if len(matches) != 1 or matches[0]['sha256'] != row['screenshot_sha256']:
            raise ValueError('Original QMP capture is not bound to the run')
        reports = {}
        for record in row['fresh_reports']:
            path = Path(record['path']).resolve()
            data = path.read_bytes()
            if (path.parent != folder or len(data) != record['bytes'] or
                    digest(data) != record['sha256'] or record['freshness'] != 'new-in-owned-run'):
                raise ValueError('Fresh native report changed')
            reports[path.name] = data.decode('ascii').splitlines()
        probe = reports['guest-output-SHZPRB.LOG']
        exit_report = reports['guest-output-SHZEXIT.TXT']
        if not {'OS_MAJOR=4', 'OS_MINOR=10', 'OS_BUILD=2222', 'STATUS=PASS',
                'GDI_FILL=PASS', 'GDI_COPY=PASS', 'DISPLAY_READBACK=PASS'} <= set(probe):
            raise ValueError('Actual native GDI success is required')
        if not {'WAIT_RESULT=0', 'PROCESS_EXIT=0'} <= set(exit_report):
            raise ValueError('Actual native child exit was not successful')
        if len(row['installed_exact_driver_files']) != 2:
            raise ValueError('Expected both installed native driver files')
        for record in row['installed_exact_driver_files']:
            path = Path(record['path']).resolve()
            if (path.parent != folder or not record['matches_frozen_input'] or
                    digest(path.read_bytes()) != record['sha256']):
                raise ValueError('Installed driver bytes changed')
        if index == 1:
            proof = row['independent_QMP_pixels']
            _, proof_sha = load(Path(proof['independent_physical_pattern_receipt']))
            if proof_sha != proof['independent_physical_pattern_sha256'] or proof['status'] != 'PASS':
                raise ValueError('Physical pattern proof changed')
            # Recheck the actual monitor independently of its physical-memory proof.
            x, y, width, height = proof['guest_reported_coordinates']
            if (x, y, width, height) != (19, 38, 160, 96):
                raise ValueError('Unexpected native pattern geometry')
            bgr = bytearray()
            with Image.open(image_path) as image:
                if image.size != (1280, 800):
                    raise ValueError('Unexpected monitor geometry')
                image = image.convert('RGB')
                for py in range(height):
                    for px in range(width):
                        expected = (208, 64, 48) if 16 <= px < 72 and 12 <= py < 52 else (16, 96, 160)
                        actual = image.getpixel((x + px, y + py))
                        if actual != expected:
                            raise ValueError('Native monitor GDI pixel differs from the real probe')
                        bgr.extend(reversed(actual))
            fnv = 2166136261
            for value in bgr:
                fnv = ((fnv ^ value) * 16777619) & 0xffffffff
            if (digest(bgr) != proof['BGR_sha256'] or f'{fnv:08x}' != proof['BGR_FNV1a'] or
                    proof['exact_pixel_comparisons'] != width * height):
                raise ValueError('Actual monitor pattern hash differs')
        name = 'win98-gop-monitor-start.png' if index == 0 else 'win98-gop-monitor-gdi.png'
        caption = ('UEFI GOP로 부팅한 실제 Windows 98에서 시작 메뉴를 열었습니다.' if index == 0 else
                   '설치된 Shizuku 기본 그래픽 드라이버로 실제 Windows 98의 그리기·복사·화면 읽기를 확인했습니다.')
        frame, blob = export_frame(image_path, row['screenshot_sha256'], name, run_sha,
            f'Windows 98 · GOP 콜드 부팅 {index + 1}', caption,
            '시작 메뉴' if index == 0 else '그래픽 시험 창', row['seconds'])
        frame.update(captureSource='qmp-monitor', monitorScanout='verified',
                     correctionAuditSha256=audit_sha)
        frames.append(frame); blobs[name] = blob
    return frames, blobs, audit_sha


def physical_gop_frames():
    """Bind faithful pixel decodes to exact original validated physical captures."""
    from PIL import Image
    run, run_sha = load(NATIVE_GOP / 'result.json')
    review, review_sha = load(NATIVE_GOP / 'visual-review.json')
    decoding, decoding_sha = load(NATIVE_GOP / 'framebuffer-decoding.json')
    if (run_sha, review_sha, decoding_sha) != (NATIVE_GOP_RECEIPT, NATIVE_GOP_REVIEW, NATIVE_GOP_DECODING):
        raise ValueError('Frozen native GOP surface receipts differ')
    if (review['execution_receipt_sha256'] != run_sha or
            decoding['execution_receipt_sha256'] != run_sha or
            digest((NATIVE_GOP / 'framebuffer-decoder.py').read_bytes()) != NATIVE_GOP_DECODER or
            decoding['decoder_source_sha256'] != NATIVE_GOP_DECODER or
            review['status'] != 'INCOMPLETE-MONITOR-SCANOUT' or
            run['status'] != 'NEEDS-VISUAL-REVIEW' or
            not all(review['source_unchanged'].values())):
        raise ValueError('Frozen historical native surface proof changed')
    for log in review['fresh_logs']:
        if digest(Path(log['path']).read_bytes()) != log['sha256']:
            raise ValueError('Fresh native probe logs differ')
    if not review['native_windows98']['native_gdi_fill_copy_display_readback'].startswith('PASS:'):
        raise ValueError('Actual native GDI probe did not pass')
    frames, blobs = [], {}
    for stem, name, chapter, caption in [
        ('screen-011', 'win98-native-gop-desktop.png', 'Windows 98 바탕화면', 'GOP 화면 메모리에서 직접 읽은 실제 Windows 98 바탕화면입니다.'),
        ('screen-032', 'win98-native-gop-run.png', '실행 창 열기', '실제 키보드 입력으로 Windows 98 실행 창을 열었습니다.'),
        ('screen-061', 'win98-native-gop-start.png', '시작 메뉴 열기', '실제 키보드 입력으로 Windows 98 시작 메뉴를 열었습니다.')]:
        rows = [row for row in decoding['samples'] if row['capture'] == stem]
        captures = [row for row in run['captures'] if Path(row.get('screenshot', '')).stem == stem]
        if len(rows) != 1 or len(captures) != 1:
            raise ValueError('A unique native physical capture is required')
        row, capture = rows[0], captures[0]
        sample = capture['physical_framebuffer']
        handover = capture['firmware_gop_handover']
        locator = handover['persistent_locator']
        raw_path, png_path = Path(row['raw']), Path(row['decoded'])
        if raw_path.parent != NATIVE_GOP or png_path.parent != NATIVE_GOP:
            raise ValueError('Native GOP decode paths escaped the frozen run')
        raw = raw_path.read_bytes()
        if (locator['validation_status'] != 'PASS' or sample['status'] != 'captured' or
                sample['physical'] != locator['framebuffer_base'] or
                sample['sha256'] != row['raw_sha256'] or digest(raw) != row['raw_sha256'] or
                len(raw) != row['raw_bytes'] or len(raw) != sample['bytes'] or
                len(raw) != locator['visible_bytes'] or
                (row['width'], row['height'], row['pitch']) != (1280, 800, 5120)):
            raise ValueError('Physical GOP pixels are not bound to validated firmware memory')
        descriptor = handover['descriptor_page']
        descriptor_bytes = Path(descriptor['path']).read_bytes()
        if (digest(descriptor_bytes) != descriptor['sha256'] or
                descriptor['sha256'] != row['descriptor_sha256'] or
                descriptor_bytes[64:80] != bytes.fromhex('0000ff0000ff0000ff000000000000ff')):
            raise ValueError('Native GOP descriptor or BGRX masks differ')
        # Verify all decoded RGB pixels independently; never synthesize a frame.
        expected_rgb = bytearray(row['width'] * row['height'] * 3)
        expected_rgb[0::3], expected_rgb[1::3], expected_rgb[2::3] = raw[2::4], raw[1::4], raw[0::4]
        with Image.open(png_path) as image:
            if image.size != (row['width'], row['height']) or image.mode != 'RGB' or image.tobytes() != expected_rgb:
                raise ValueError('Decoded PNG changed the original physical GOP pixels')
        frame, blob = export_frame(png_path, row['decoded_sha256'], name, run_sha,
            'Windows 98 · 네이티브 GOP 화면 메모리', caption, chapter, capture.get('seconds'))
        frame.update(captureSource='physical-gop-framebuffer', rawSha256=row['raw_sha256'],
                     decoderSha256=NATIVE_GOP_DECODER, monitorScanout='verified-by-additive-audit',
                     correctionAuditSha256=MONITOR_AUDIT_SHA)
        frames.append(frame); blobs[name] = blob
    return frames, blobs, review_sha


def native_file_frames():
    """Export a distinct genuine GOP boot with cold reopen and new file save."""
    run, run_sha = load(NATIVE_FILE / 'result.json')
    review, review_sha = load(NATIVE_FILE / 'visual-review-native-provider-and-file.json')
    if (run_sha != NATIVE_FILE_RECEIPT or review_sha != NATIVE_FILE_REVIEW or
            review['execution_receipt']['sha256'] != run_sha or
            run['profile'] != 'actual-win98-uefi-csmwrap' or
            review['status'] != 'PASS-NATIVE-WIN98-GOP-COLD-GUI-PROVIDER-AND-FILE' or
            review['full_goal_complete'] or not review['no_mmio_requests'] or
            not review['verification']['originals_unchanged'] or
            not review['verification']['prepared_source_unchanged'] or
            review['verification']['qemu_exit'] != 0):
        raise ValueError('Native GOP file trial no longer matches its scoped review')
    records = [*review['driver_files'], review['native_notepad_file'],
               review['native_provider']['log'], review['native_provider']['exit']]
    for record in records:
        path = Path(record['path']).resolve()
        data = path.read_bytes()
        if (path.parent != NATIVE_FILE or len(data) != record['bytes'] or
                digest(data) != record['sha256']):
            raise ValueError('Actual native driver, saved file or provider output changed')
    saved = review['native_notepad_file']
    provider = review['native_provider']
    if (saved['status'] != 'PASS' or saved['freshness'] != 'changed-in-owned-run' or
            saved['sha256'] == saved['baseline_sha256'] or
            Path(saved['path']).read_bytes() != (saved['expected_text'] + '\r\n').encode('ascii') or
            provider['checks'] != 14 or provider['failures'] != 0 or
            provider['actual_child_wait'] != 0 or provider['actual_child_exit'] != 0 or
            provider['application_launched']):
        raise ValueError('Expected actual file persistence and scoped provider behavior')
    lines = Path(provider['log']['path']).read_text().splitlines()
    exit_lines = Path(provider['exit']['path']).read_text().splitlines()
    if (sum(line.startswith('PASS ') for line in lines) != 14 or
            any(line.startswith('FAIL ') for line in lines) or
            not {'CHECKS=0000000E', 'FAILURES=00000000', 'APPLICATION_LAUNCHED=0'} <= set(lines) or
            not {'WAIT_RESULT=00000000', 'PROCESS_EXIT=00000000'} <= set(exit_lines)):
        raise ValueError('Actual native provider checks or child exit failed')
    frames, blobs = [], {}
    for basename, filename, chapter, caption in [
        ('screen-034.png', 'win98-gop-file-desktop.png', '새 GOP 부팅',
         '새 UEFI GOP 부팅에서 실제 Windows 98 바탕화면을 확인했습니다.'),
        ('screen-103.png', 'win98-gop-file-reopen.png', '기존 파일 다시 열기',
         '새 GOP 부팅 뒤 이전 실행에서 저장한 파일을 Windows 98 메모장으로 열었습니다.'),
        ('screen-133.png', 'win98-gop-file-save.png', '새 내용 입력·저장',
         'GOP 화면에서 새 내용을 입력하고 저장했습니다. 저장된 43바이트도 별도로 읽어 확인했습니다.')]:
        path = NATIVE_FILE / basename
        captures = [c for c in run['captures'] if Path(c.get('screenshot', '')).resolve() == path]
        reviews = [r for r in review['visual_review'] if Path(r['artifact']['path']).resolve() == path]
        if len(captures) != 1 or len(reviews) != 1 or captures[0]['sha256'] != reviews[0]['artifact']['sha256']:
            raise ValueError('Expected one exact original monitor capture and scoped visual review')
        capture = captures[0]
        frame, blob = export_frame(path, capture['sha256'], filename, run_sha,
            'Windows 98 · GOP 파일 저장 시험', caption, chapter, capture.get('seconds'))
        frame.update(captureSource='qmp-monitor', monitorScanout='verified',
                     verificationReceiptSha256=review_sha)
        frames.append(frame); blobs[filename] = blob
    return frames, blobs, review_sha


def latest_npp_frames():
    """Export successful app operations while preserving the failed full trial."""
    proof, proof_sha = load(LATEST_NPP_PROOF)
    run, run_sha = load(LATEST_NPP / 'result.json')
    if (proof_sha != LATEST_NPP_PROOF_SHA or run_sha != proof['runner_result_sha256'] or
            proof['status'] != 'FAIL' or len(proof['checks']) != 15 or
            sum(c['status'] == 'PASS' for c in proof['checks']) != 14 or
            not proof['native_save_as_verified'] or not proof['warm_reopen_verified'] or
            proof['clean_exit_verified'] or proof['cold_app_reopen_verified'] or
            proof['gop_display_verified'] or not proof['owned_vm_stopped'] or
            run['profile'] != 'actual-win98-uefi-csmwrap'):
        raise ValueError('Expected exact partial latest-app trial with failed clean exit')
    checks = {c['check']: c for c in proof['checks']}
    if checks['latest NPP clean process exit']['status'] != 'FAIL':
        raise ValueError('Do not promote the preserved latest-app exit failure')
    readbacks = {record['guest']: record for record in proof['readback']}
    for record in readbacks.values():
        path = Path(record['host']).resolve()
        path.relative_to(LATEST_NPP_PROOF.parent / 'readback')
        data = path.read_bytes()
        if len(data) != record['bytes'] or digest(data) != record['sha256']:
            raise ValueError('Exact latest-app post-VM readback changed')
    saved = readbacks['NPPLAB/NPPQA.TXT']
    app = readbacks['NPPLAB/APP/NPP.EXE']
    if (Path(saved['host']).read_bytes() != b'Latest NPP 8.9.8.1 Windows98 Save As proof\r\n' or
            app['sha256'] != '986ffd50fb51e4b08737d1c47a4aca8e681adb628789228e5f538bfb954d2eb5' or
            not all(record['absent'] for record in proof['freshness_baseline'])):
        raise ValueError('Actual unchanged latest app and fresh saved file are required')
    observer = Path(readbacks['GOPLAB/APP.LOG']['host']).read_text()
    if ('class="Notepad++"' not in observer or 'WM_CLOSE_POSTED_COUNT=1\n' not in observer or
            'TERMINATED_BY_PROBE=1\n' not in observer or 'TARGET_EXIT_CODE=1460\n' not in observer):
        raise ValueError('Actual GUI observation and failed process exit must remain explicit')
    frames, blobs = [], {}
    for basename, filename, chapter, caption in [
        ('screen-073.png', 'latest-npp-edit.png', '실제 편집',
         '실제 Windows 98에서 최신 Notepad++ 8.9.8.1로 내용을 입력했습니다.'),
        ('screen-077.png', 'latest-npp-save-dialog.png', '새 파일 저장 창',
         '호환 구성 요소가 제공한 실제 Windows 98 저장 창으로 새 파일을 저장했습니다.'),
        ('screen-083.png', 'latest-npp-saved.png', '새 파일 저장 확인',
         '새 NPPQA.TXT를 저장했습니다. 실제 디스크에서 읽은 44바이트가 입력한 내용과 일치합니다.'),
        ('screen-100.png', 'latest-npp-reopen.png', '같은 실행에서 다시 열기',
         '문서를 닫은 뒤 같은 Notepad++ 실행에서 저장한 파일을 다시 열었습니다.'),
        ('screen-106.png', 'latest-npp-exit-fault.png', '정상 종료 실패',
         '저장·다시 열기 뒤 프로그램 종료에서 오류가 발생했습니다. 전체 앱 시험은 실패로 남겼습니다.')]:
        path = LATEST_NPP / basename
        captures = [c for c in run['captures'] if Path(c.get('screenshot', '')).resolve() == path]
        if len(captures) != 1:
            raise ValueError('Latest-app original capture is not uniquely bound to its run')
        capture = captures[0]
        frame, blob = export_frame(path, capture['sha256'], filename, run_sha,
            'Notepad++ 8.9.8.1 · 실제 Windows 98', caption, chapter, capture.get('seconds'))
        frame.update(captureSource='qmp-monitor', verificationReceiptSha256=proof_sha)
        frames.append(frame); blobs[filename] = blob
    cold_proof, cold_proof_sha = load(LATEST_NPP_COLD_PROOF)
    cold_run, cold_run_sha = load(LATEST_NPP_COLD / 'result.json')
    if (cold_proof_sha != LATEST_NPP_COLD_PROOF_SHA or
            cold_proof['status'] != 'PASS' or len(cold_proof['checks']) != 6 or
            not all_pass(cold_proof['checks']) or not cold_proof['cold_reopen_verified'] or
            cold_proof['clean_exit_verified'] or cold_proof['gop_display_verified'] or
            cold_proof['application_full_acceptance'] != 'FAIL' or
            not cold_proof['owned_vm_stopped'] or
            cold_run_sha != cold_proof['runner_result_sha256'] or
            cold_run['profile'] != 'actual-win98-uefi-csmwrap' or
            cold_proof['source_postdisk_sha256'] != proof['postdisk_sha256']):
        raise ValueError('Expected separate cold reopen without promoting clean exit or GOP')
    for record in cold_proof['checks'][:4]:
        filename = record['check'].rsplit('/', 1)[-1]
        data = (LATEST_NPP_COLD_PROOF.parent / filename).read_bytes()
        if len(data) != record['bytes'] or digest(data) != record['sha256']:
            raise ValueError('Cold application readback changed')
    if ((LATEST_NPP_COLD_PROOF.parent / 'NPPQA.TXT').read_bytes() !=
            b'Latest NPP 8.9.8.1 Windows98 Save As proof\r\n'):
        raise ValueError('Cold application file must retain the exact saved bytes')
    path = LATEST_NPP_COLD / 'screen-021.png'
    captures = [c for c in cold_run['captures'] if Path(c.get('screenshot', '')).resolve() == path]
    if len(captures) != 1:
        raise ValueError('Cold application original capture must be uniquely bound')
    capture = captures[0]
    frame, blob = export_frame(path, capture['sha256'], 'latest-npp-cold-reopen.png',
        cold_run_sha, 'Notepad++ 8.9.8.1 · 별도 콜드 부팅',
        '새 부팅 뒤 원본 Notepad++에서 저장한 NPPQA.TXT를 열었습니다. 디스크의 실제 44바이트도 다시 확인했습니다.',
        '새 부팅 뒤 파일 열기', capture.get('seconds'))
    frame.update(captureSource='qmp-monitor', verificationReceiptSha256=cold_proof_sha)
    frames.insert(4, frame); blobs['latest-npp-cold-reopen.png'] = blob
    return frames, blobs, proof_sha, cold_proof_sha


def latest_npp_gop_frames():
    """Bind original combined-app captures to native exits and exact readbacks."""
    proof, proof_sha = load(LATEST_NPP_GOP / 'native-gop-latest-npp-review.json')
    run, run_sha = load(LATEST_NPP_GOP / 'result.json')
    limits = proof['limits']
    if (proof_sha != LATEST_NPP_GOP_PROOF_SHA or
            run_sha != proof['raw_result_sha256'] or
            run_sha != 'dc600f031150f6440a4c1ce3b657a7d71c0e7b6f57f2549b7f733d3cd453708f' or
            proof['status'] != 'SCOPED-NATIVE-GOP-NPP-PASS' or
            len(proof['checks']) != 26 or not all_pass(proof['checks']) or
            run['profile'] != 'actual-win98-uefi-csmwrap' or
            run['status'] != 'NEEDS-VISUAL-REVIEW' or proof['raw_receipt_mutated'] or
            limits['full_project_complete'] or limits['unassisted_NPP_exit_verified'] or
            not limits['scope_requires_native_field_interpreter'] or
            not limits['no_target_binary_or_FS_patch'] or
            limits['other_first_chance_exceptions_passed_to_OS'] != 4 or
            limits['native_worker_shutdown_exit_ffffffff_count'] != 3 or
            limits['other_second_chance_exceptions_logged'] != 0):
        raise ValueError('Expected exact scoped GOP application success with preserved limits')

    def bound_record(record, folder=LATEST_NPP_GOP):
        path = Path(record['path']).resolve()
        path.relative_to(folder)
        data = path.read_bytes()
        if digest(data) != record['sha256'] or ('bytes' in record and len(data) != record['bytes']):
            raise ValueError('Combined GOP app evidence bytes changed')
        return data

    readback = json.loads(bound_record(proof['readback_receipt']))
    providers = json.loads(bound_record(proof['provider_receipt']))
    if (readback['freshness_baseline']['status'] != 'absent-in-verified-owned-source' or
            readback['freshness_baseline']['source_sha256'] !=
            '19a4b010a60c4ffdadbdcd59fa002e4a7a345fc33c10af272ea717aec9faa596' or
            len(providers['files']) != 15 or not all_pass(providers['files'])):
        raise ValueError('Fresh new document and unchanged prerequisite bytes are required')
    files = {row['guest']: row for row in readback['files']}
    for row in [*readback['files'], *providers['files']]:
        bound_record(row)
        if 'expected_sha256' in row and row['sha256'] != row['expected_sha256']:
            raise ValueError('Installed prerequisite no longer matches its frozen input')
    text = b'Latest NPP 8.9.8.1 Windows98 Save As proof\r\n'
    if any(bound_record(files[guest]) != text for guest in
           ['C:\\NPPLAB\\NPPQA.TXT', 'C:\\NPPLAB\\NPPGOP.TXT']):
        raise ValueError('Exact original and newly saved 44-byte documents are required')
    identities = {
        'C:\\NPPLAB\\APP\\NPP.EXE': '986ffd50fb51e4b08737d1c47a4aca8e681adb628789228e5f538bfb954d2eb5',
        'C:\\WINDOWS\\SYSTEM\\SHZGOP.DRV': 'ac4610852e637681373cccc2c812af558ec6324c29aab28593d6f8f0e6bcd3fa',
        'C:\\WINDOWS\\SYSTEM\\SHZGOP.VXD': '991cf215c8074202702e4345f58245a02656eeb2b1ac9b202bc9beefd2344a2d'}
    if any(files[guest]['sha256'] != sha for guest, sha in identities.items()):
        raise ValueError('Unchanged official app and actual GOP driver pair are required')
    logs = {}
    for record in proof['native_logs']:
        if record['freshness'] != 'new-in-owned-run' or record['status'] != 'captured':
            raise ValueError('Native process results must be fresh guest outputs')
        logs[Path(record['path']).name] = bound_record(record).decode('ascii').splitlines()
    native = logs['guest-output-ENVNPP.LOG']
    outer = logs['guest-output-ENVNEXIT.LOG']
    if (not {'MODEL_NTGLOBALFLAG=00000000', 'MODEL_PROCESS_FLAGS=00000000',
             'TARGET_HASH_PE_CHAINS=PASS', 'ACTUAL_PROCESS_EXIT=00000000',
             'STATUS=SCOPED_NPP_DESKTOP_EXIT_ZERO', 'HELPER_EXIT=00000000',
             'ARMED_THREADS=00000078', 'RETIRED_THREADS=00000078',
             'SECURE_EVENTS=00000001', 'OTHER_EXCEPTIONS_PASSED=00000004'} <= set(native) or
            not {'CREATED=00000001', 'WAIT_RESULT=00000000', 'PROCESS_EXIT=00000000'} <= set(outer) or
            sum(line.startswith('DR_SET_READBACK=PASS ') for line in native) != 120 or
            sum(line.startswith('FIELD_LOAD=INTERPRETED ') and 'KIND=SECURE ' in line
                for line in native) != 1 or
            sum(line.startswith('THREAD_EXIT=') and 'CODE=ffffffff ' in line
                for line in native) != 3):
        raise ValueError('Actual native app, helper and waiter exits or limited field bridge differ')
    old, old_sha = load(LATEST_NPP_PROOF)
    if old_sha != LATEST_NPP_PROOF_SHA or old['status'] != 'FAIL':
        raise ValueError('Historical unassisted exit failure must remain intact')
    frames, blobs = [], {}
    for basename, filename, chapter, caption in [
        ('screen-046.png', 'latest-npp-gop-open.png', 'GOP 부팅 뒤 파일 열기',
         '실제 Windows 98 GOP 화면에서 원본 Notepad++ 8.9.8.1로 이전에 저장한 파일을 열었습니다.'),
        ('screen-054.png', 'latest-npp-gop-save-dialog.png', '새 파일 저장 창',
         'GOP 화면의 새 편집 문서에서 실제 Windows 98 저장 창을 열었습니다.'),
        ('screen-059.png', 'latest-npp-gop-saved.png', '새 파일 저장 확인',
         '새 NPPGOP.TXT를 저장했습니다. 디스크에서 읽은 44바이트가 입력한 내용과 일치합니다.'),
        ('screen-063.png', 'latest-npp-gop-document-closed.png', '문서 닫기',
         '저장한 새 문서를 닫고 원래 문서가 유지되는지 확인했습니다.'),
        ('screen-066.png', 'latest-npp-gop-reopen.png', '같은 실행에서 다시 열기',
         '같은 앱 실행에서 새 NPPGOP.TXT를 다시 열어 경로와 내용을 확인했습니다.'),
        ('screen-069.png', 'latest-npp-gop-exit.png', '정상 종료',
         'Alt+F4로 앱을 닫았습니다. 실제 앱·호환 실행기·대기 프로세스의 종료 값이 모두 0이었습니다.')]:
        path = LATEST_NPP_GOP / basename
        captures = [c for c in run['captures'] if Path(c.get('screenshot', '')).resolve() == path]
        reviewed = [r for r in proof['screenshots'] if Path(r['path']).resolve() == path]
        if len(captures) != 1 or len(reviewed) != 1 or captures[0]['sha256'] != reviewed[0]['sha256']:
            raise ValueError('Original combined GOP app capture is not uniquely bound')
        capture = captures[0]
        frame, blob = export_frame(path, capture['sha256'], filename, run_sha,
            'Notepad++ 8.9.8.1 · 실제 Windows 98 GOP', caption, chapter, capture.get('seconds'))
        if (frame['width'], frame['height']) != (1280, 800):
            raise ValueError('Expected exact native GOP monitor dimensions')
        frame.update(captureSource='qmp-monitor', verificationReceiptSha256=proof_sha,
                     monitorScanout='verified')
        frames.append(frame); blobs[filename] = blob
    return frames, blobs, proof_sha


def latest_npp_gop_cold_frames():
    """Export the separate cold/keyboard trial without hiding its key correction."""
    folder = LATEST_NPP_GOP_COLD
    proof, proof_sha = load(folder / 'native-gop-latest-npp-cold-keyboard-review.json')
    run, run_sha = load(folder / 'result.json')
    correction = proof['shortcut_correction']
    limits = proof['limits']
    if (proof_sha != LATEST_NPP_GOP_COLD_PROOF_SHA or
            proof['status'] != 'SCOPED-NATIVE-GOP-NPP-COLD-KEYBOARD-PASS' or
            run_sha != proof['raw_result_sha256'] or
            run_sha != '13f76fc4f6870a61d5067b76b7c47a49b7d40ddcd9310f271d5d8cbd1fab8ada' or
            run['status'] != 'NEEDS-VISUAL-REVIEW' or
            run['profile'] != 'actual-win98-uefi-csmwrap' or proof['raw_receipt_mutated'] or
            len(proof['checks']) != 25 or not all_pass(proof['checks']) or
            proof['previous_successful_scope']['sha256'] != LATEST_NPP_GOP_PROOF_SHA or
            correction['immutable_source_affected'] or not correction['final_prior_files_exact'] or
            not correction['earlier_raw_trace_preserved'] or
            limits['full_project_complete'] or limits['unassisted_NPP_exit_verified'] or
            not limits['requires_native_field_interpreter'] or
            limits['armed_retired_threads'] != 146 or
            limits['other_first_chance_exceptions_passed_to_OS'] != 4 or
            limits['worker_shutdown_exit_ffffffff_count'] != 3):
        raise ValueError('Exact bounded cold/keyboard success and corrected key trace required')

    def bound(record):
        path = Path(record['path']).resolve()
        path.relative_to(folder)
        data = path.read_bytes()
        if digest(data) != record['sha256'] or ('bytes' in record and len(data) != record['bytes']):
            raise ValueError('Cold keyboard evidence bytes changed')
        return data

    readback = json.loads(bound(proof['readback_receipt']))
    providers = json.loads(bound(proof['provider_receipt']))
    files = {row['guest']: row for row in readback['files']}
    for row in [*readback['files'], *providers['files']]:
        bound(row)
    if len(providers['files']) != 15 or not all_pass(providers['files']):
        raise ValueError('All original prerequisites must remain exact')
    original = b'Latest NPP 8.9.8.1 Windows98 Save As proof\r\n'
    typed = b'Latest NPP 8.9.8.1 GOP keyboard proof\r\n'
    if (bound(files['C:\\NPPLAB\\NPEDGOP.TXT']) != typed or
            bound(files['C:\\NPPLAB\\NPPGOP.TXT']) != original or
            bound(files['C:\\NPPLAB\\NPPQA.TXT']) != original or
            files['C:\\NPPLAB\\APP\\NPP.EXE']['sha256'] !=
            '986ffd50fb51e4b08737d1c47a4aca8e681adb628789228e5f538bfb954d2eb5'):
        raise ValueError('Distinct fresh39-byte file and restored exact44-byte originals required')
    native, outer = [bound(row).decode('ascii').splitlines() for row in proof['native_logs']]
    if (any(row['freshness'] != 'new-in-owned-run' for row in proof['native_logs']) or
            not {'TARGET_HASH_PE_CHAINS=PASS', 'MODEL_NTGLOBALFLAG=00000000',
                 'MODEL_PROCESS_FLAGS=00000000', 'ACTUAL_PROCESS_EXIT=00000000',
                 'HELPER_EXIT=00000000', 'ARMED_THREADS=00000092',
                 'RETIRED_THREADS=00000092', 'SECURE_EVENTS=00000001'} <= set(native) or
            not {'CREATED=00000001', 'WAIT_RESULT=00000000', 'PROCESS_EXIT=00000000'} <= set(outer) or
            sum(line.startswith('DR_SET_READBACK=PASS ') for line in native) != 146):
        raise ValueError('Actual repeat application/helper/waiter exits and native events required')
    frames, blobs = [], {}
    for basename, filename, chapter, caption in [
        ('screen-015.png', 'latest-npp-gop-cold-open.png', '다음 GOP 부팅에서 다시 열기',
         '다음 콜드 부팅에서 이전에 저장한 NPPGOP.TXT를 열었습니다. 원래 44바이트 내용과 경로가 일치했습니다.'),
        ('screen-020.png', 'latest-npp-gop-keyboard.png', '다른 내용 직접 입력',
         '실제 키보드로 기존 문서와 다른 내용을 입력했습니다. 편집기의 새 내용은 39바이트입니다.'),
        ('screen-038.png', 'latest-npp-gop-keyboard-saved.png', '다른 내용의 새 파일 저장',
         '직접 입력한 내용을 새 NPEDGOP.TXT에 저장했습니다. 실제 디스크의 39바이트도 확인했습니다.'),
        ('screen-049.png', 'latest-npp-gop-original-restored.png', '기존 파일 내용 복원·확인',
         '시험 중 저장 대상 선택을 바로잡았습니다. 기존 파일 두 개의 원래 내용과 새 파일을 최종 디스크에서 대조했습니다.'),
        ('screen-053.png', 'latest-npp-gop-cold-exit.png', '다음 부팅에서도 정상 종료',
         '다음 GOP 부팅에서도 Alt+F4로 정상 종료했습니다. 실제 앱·호환 실행기·대기 프로세스 종료 값이 모두 0입니다.')]:
        path = folder / basename
        captures = [c for c in run['captures'] if Path(c.get('screenshot', '')).resolve() == path]
        reviewed = [r for r in proof['screenshots'] if Path(r['path']).resolve() == path]
        if len(captures) != 1 or len(reviewed) != 1 or captures[0]['sha256'] != reviewed[0]['sha256']:
            raise ValueError('Cold app capture is not uniquely bound to original review')
        frame, blob = export_frame(path, captures[0]['sha256'], filename, run_sha,
            'Notepad++ 8.9.8.1 · 다음 Windows 98 GOP 부팅', caption, chapter,
            captures[0].get('seconds'))
        frame.update(captureSource='qmp-monitor', verificationReceiptSha256=proof_sha,
                     monitorScanout='verified')
        frames.append(frame); blobs[filename] = blob
    return frames, blobs, proof_sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'site/evidence')
    args = parser.parse_args()
    output = args.output.resolve()
    # The only public export location is inside this bounded asset directory.
    output.relative_to(ROOT / 'site')
    manual, manual_review, manual_sha, manual_review_sha = native_run(MANUAL, MANUAL_RECEIPT)
    cold, cold_review, cold_sha, cold_review_sha = native_run(COLD, COLD_RECEIPT)
    readback = manual_review['exact_host_readback']
    if manual_review['functional_gui_verdict'] != 'PASS' or readback['status'] != 'PASS':
        raise ValueError('Native GUI and actual saved-file readback were not verified')
    if digest(Path(readback['path']).read_bytes()) != readback['sha256']:
        raise ValueError('Native saved-file readback changed')
    if not cold_review['cold_persisted_notepad_file'].startswith('PASS;'):
        raise ValueError('A separate cold boot did not verify the persisted native file')
    # Preserve the failed driver trial; that result must never become a GUI PASS.
    if cold['status'] != 'FAIL' or not cold_review['native_driver'].startswith('FAIL;'):
        raise ValueError('Unexpected native driver-trial verdict; update evidence explicitly')
    desktop, desktop_sha = load(DESKTOP / 'result.json')
    if desktop['status'] != 'PASS' or not all_pass(desktop['checks']) or len(desktop['boots']) != 2:
        raise ValueError('A complete shipped-ISO desktop two-boot result is required')
    if any(boot['status'] != 'PASS' or not all_pass(boot['checks'])
           or boot['boot_medium'] != 'shipped-iso-cd' for boot in desktop['boots']):
        raise ValueError('Both genuine ISO boots must pass every recorded check')
    install, install_sha = load(INSTALL / 'result.json')
    install_review, install_review_sha = load(INSTALL / 'visual-review.json')
    if install_sha != INSTALL_RECEIPT or install_review_sha != INSTALL_REVIEW:
        raise ValueError('Installation evidence changed')
    if (install['profile'] != 'actual-win98-uefi-csmwrap' or
            not install_review['installation_class'].startswith('PASS:') or
            not install_review['originals_unchanged'] or
            'stock VGA until restart' not in install_review['active_backend']):
        raise ValueError('Expected scoped native class installation, not rendering')
    copies = install_review['installed_file_readback']
    if len(copies) != 2 or any(not c['matches_frozen_input'] or
            digest(Path(c['path']).read_bytes()) != c['sha256'] for c in copies):
        raise ValueError('Installed driver bytes are not bound to the review')

    monitor_frames, blobs, monitor_audit_sha = monitor_gop_frames()
    file_frames, file_blobs, file_review_sha = native_file_frames()
    blobs.update(file_blobs)
    npp_frames, npp_blobs, npp_proof_sha, npp_cold_proof_sha = latest_npp_frames()
    blobs.update(npp_blobs)
    npp_gop_frames, npp_gop_blobs, npp_gop_proof_sha = latest_npp_gop_frames()
    blobs.update(npp_gop_blobs)
    npp_gop_cold_frames, npp_gop_cold_blobs, npp_gop_cold_proof_sha = latest_npp_gop_cold_frames()
    npp_gop_frames.extend(npp_gop_cold_frames)
    blobs.update(npp_gop_cold_blobs)
    native_gop_frames, physical_blobs, native_gop_review_sha = physical_gop_frames()
    blobs.update(physical_blobs)
    vlc_frames, vlc_blobs, vlc_review_shas = vlc_startup_failure_frames()
    blobs.update(vlc_blobs)
    vlc_video_frames, vlc_video_blobs, vlc_video_review_shas = vlc_rendering_frames()
    blobs.update(vlc_video_blobs)
    selections = [
        (manual, MANUAL, 'screen-036.png', 'win98-saved.png', manual_sha,
         'Windows 98 · 첫 번째 부팅', '실제 Windows 98 메모장에서 입력한 내용을 UEFIQA.TXT로 저장했습니다.', '메모장 저장'),
        (cold, COLD, 'screen-015.png', 'win98-cold-reopen.png', cold_sha,
         'Windows 98 · 새 콜드 부팅', '새 콜드 부팅 뒤 UEFIQA.TXT를 열어 같은 내용을 확인했습니다.', '재시작 후 다시 열기')]
    native_frames = []
    for result, folder, basename, name, receipt, label, caption, chapter in selections:
        matches = [c for c in result['captures'] if Path(c['screenshot']).name == basename]
        if len(matches) != 1 or Path(matches[0]['screenshot']).resolve() != (folder / basename).resolve():
            raise ValueError('Selected native capture is not uniquely recorded')
        capture = matches[0]
        frame, blob = export_frame(capture['screenshot'], capture['sha256'], name,
                                   receipt, label, caption, chapter, capture.get('seconds'))
        native_frames.append(frame)
        blobs[name] = blob
    installed_captures = [c for c in install['captures']
                          if Path(c['screenshot']).name == 'screen-075.png']
    if len(installed_captures) != 1:
        raise ValueError('Installation screenshot is not uniquely recorded')
    capture = installed_captures[0]
    if Path(capture['screenshot']).resolve() != (INSTALL / 'screen-075.png').resolve():
        raise ValueError('Installation capture path mismatch')
    install_frame, blob = export_frame(capture['screenshot'], capture['sha256'],
        'win98-driver-installed.png', install_sha, 'Windows 98 · 드라이버 설치',
        'Windows 98 설치 마법사 완료 후 어댑터 이름과 SHZGOP 드라이버 파일을 확인했습니다.',
        '드라이버 설치 확인', capture.get('seconds'))
    blobs['win98-driver-installed.png'] = blob
    gop_frames = []
    for boot_index, screenshot_label, name, caption, chapter in [
        (0, 'desktop-ready', 'gop-desktop.png', '제작한 ISO에서 부팅한 Shizuku 독립 데스크톱입니다.', 'ISO 첫 부팅'),
        (0, 'editor-saved', 'gop-editor-saved.png', '편집기에서 D:\\DESKTOP.TXT를 실제 FAT32 디스크에 저장했습니다.', '파일 저장'),
        (1, 'editor-cold-boot', 'gop-cold-reopen.png', '같은 디스크로 두 번째 콜드 부팅한 뒤 저장한 25바이트를 다시 열었습니다.', '두 번째 콜드 부팅')]:
        boot = desktop['boots'][boot_index]
        matches = [s for s in boot['screenshots'] if s['label'] == screenshot_label]
        if len(matches) != 1:
            raise ValueError('Selected desktop capture is not uniquely recorded')
        shot = matches[0]
        frame, blob = export_frame(shot['path'], shot['sha256'], name, desktop_sha,
                                   f'Shizuku GOP · ISO 부팅 {boot_index + 1}', caption, chapter)
        gop_frames.append(frame)
        blobs[name] = blob
    manifest = {
        'schema': 1, 'generatedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'live': {'available': False, 'reason': 'An authenticated owner endpoint is not connected.'},
        'collections': [
            {'id': 'native-gop-monitor', 'title': 'Windows 98 UEFI GOP 실제 화면',
             'platform': 'Microsoft Windows 98 4.10.2222 한국어',
             'display': '1280 × 800 · Shizuku 기본 그래픽 드라이버 · KVM',
             'result': '실제 모니터의 시작 메뉴·그리기·복사 확인',
             'observations': ['두 번의 콜드 부팅에서 실제 Windows 98의 GOP 화면을 확인했습니다.',
                              '게스트 그래픽 시험 창의 15,360개 픽셀을 모니터 원본과 독립적으로 비교했습니다.',
                              '실제 그래픽 시험 프로세스의 정상 종료를 확인했습니다.'],
             'scope': '시험 VM의 고정 GOP 모드에서 확인했습니다. 기존 검토의 화면 출력 판정은 후반 원본 캡처를 확인한 추가 검증 기록으로 정정했습니다. GPU 3D 가속, 전체 하드웨어와 최신 앱은 계속 구현 중입니다.',
             'rawRunStatuses': ['NEEDS-VISUAL-REVIEW', 'NEEDS-VISUAL-REVIEW'],
             'correctionAuditSha256': monitor_audit_sha, 'frames': monitor_frames},
            {'id': 'latest-npp-gop', 'title': '최신 Notepad++ · Windows 98 GOP',
             'platform': 'Microsoft Windows 98 4.10.2222 한국어',
             'display': '1280 × 800 · Shizuku 기본 그래픽 드라이버 · 앱 호환 실행기 · KVM',
             'result': 'GOP 저장·다음 부팅에서 다시 열기·직접 입력·정상 종료 확인',
             'observations': ['원본 Notepad++ 8.9.8.1을 실제 Windows 98의 GOP 화면에서 실행했습니다.',
                              '새 파일의 실제 44바이트와 원본 앱·드라이버 파일을 디스크에서 별도로 확인했습니다.',
                              '다음 부팅에서도 저장한 파일을 열었고, 다른 내용을 직접 입력해 새 39바이트 파일로 저장·정상 종료했습니다.'],
             'scope': '전용 앱 호환 실행기를 사용한 시험입니다. 실행기 없이 종료한 이전 시험의 오류는 그대로 보존했습니다. 재부팅 시험 중 저장 대상 선택을 바로잡고 기존 문서를 복원·대조했습니다. DOS 비디오 안내에서 키 입력이 필요하며, GPU 3D 가속과 다른 최신 앱은 구현 중입니다.',
             'rawRunStatuses': ['NEEDS-VISUAL-REVIEW'],
             'applicationTrialStatus': 'SCOPED-NATIVE-GOP-NPP-PASS',
             'requiresNativeFieldInterpreter': True, 'cleanExitVerified': True,
             'unassistedCleanExitVerified': False, 'newFileColdReopenVerified': True,
             'repeatTrialPreviousFilesFinalBytesRestored': True,
             'firstChanceExceptionsPassedToOS': 4, 'workerShutdownExitFFFFFFFFCount': 3,
             'reviewSha256': [npp_gop_proof_sha, npp_gop_cold_proof_sha], 'frames': npp_gop_frames},
            {'id': 'vlc-video-gop', 'title': 'VLC 3.0.24 · 실제 영상 출력',
             'platform': 'Microsoft Windows 98 4.10.2222 한국어',
             'display': '1280 × 800 · Shizuku 기본 그래픽 드라이버 · KVM',
             'result': '영상 내용 변화 확인 · 전체 조작 화면 오류 해결 중',
             'observations': ['공식 VLC 3.0.24가 실제 Windows 98 GOP 화면에서 시험 영상을 출력했습니다.',
                              '영상 내부만 비교해 노란색 막대의 폭이 46·73·99픽셀로 바뀌는 것을 확인했습니다.',
                              'Qt 화면 구성 요소는 로드에 실패했습니다. 정상 종료와 음성 출력은 아직 확인되지 않았습니다.'],
             'scope': '실제 영상 출력의 부분 검증입니다. 전체 플레이어 사용 완료를 뜻하지 않습니다. 실행 기록은 화면에서 확인했지만 디스크의 기록 파일은 0바이트이며, VM 종료는 앱이나 Windows의 정상 종료를 증명하지 않습니다.',
             'rawRunStatuses': ['NEEDS-VISUAL-REVIEW'],
             'applicationTrialStatus': 'PARTIAL_REAL_VIDEO_RENDERING_QT_GUI_FAIL',
             'guiAcceptance': False, 'videoRegionMotionVerified': True,
             'cleanExitVerified': False, 'audibleAudioVerified': False,
             'reviewSha256': vlc_video_review_shas, 'frames': vlc_video_frames},
            {'id': 'vlc-first-startup', 'title': 'VLC 3.0.24 · 첫 실행 오류',
             'platform': 'Microsoft Windows 98 4.10.2222 한국어',
             'display': '1280 × 800 · Shizuku 기본 그래픽 드라이버 · KVM',
             'result': '첫 영상·음성 시작 실패 기록 보존',
             'observations': ['원본 VLC 실행 파일과 호환 구성을 설치한 뒤 새 Windows 98 GOP 부팅에서 실행했습니다.',
                              '영상 시험의 오류 창을 닫은 뒤 실제 프로세스 종료 값은 0이었습니다. 재생 성공은 아닙니다.',
                              '공식 파일 로거 플러그인을 보완한 뒤 영상 출력은 별도 기록에서 부분 확인했습니다.'],
             'scope': '첫 실행의 오류와 원본 캡처를 보존한 기록입니다. 동작하는 VLC 창·영상 재생·실제 음성 출력은 확인하지 못했습니다. 음성 프로세스 종료도 미확인입니다. 플러그인 누락 외에 다른 문제가 남아 있을 수 있습니다.',
             'rawRunStatuses': ['NEEDS-VISUAL-REVIEW'],
             'applicationTrialStatus': 'FAIL', 'guiAcceptance': False,
             'videoPlaybackVerified': False, 'audibleAudioVerified': False,
             'videoChildActualExitCode': 0, 'audioChildExitObserved': False,
             'reviewSha256': vlc_review_shas, 'frames': vlc_frames},
            {'id': 'native-gop-file', 'title': 'Windows 98 GOP 파일 저장·다시 열기',
             'platform': 'Microsoft Windows 98 4.10.2222 한국어',
             'display': '1280 × 800 · Shizuku 기본 그래픽 드라이버 · KVM',
             'result': '이전 파일 다시 열기와 새 내용 저장 확인',
             'observations': ['새 콜드 부팅 뒤 이전 파일을 메모장으로 열었습니다.',
                              'GOP 화면에서 입력한 새 내용이 디스크의 실제 43바이트와 일치했습니다.',
                              '같은 Windows 98에서 API 제공 모듈의 동작 시험 14개와 정상 종료도 확인했습니다.'],
             'scope': '이 기록의 편집기는 Windows 98 기본 메모장입니다. 최신 Notepad++ 실행 결과는 별도 GOP 앱 기록에서 확인할 수 있습니다. 부팅 중 기존 한국어 DOS 비디오 구성 요소의 안내에서 키 입력이 필요했습니다.',
             'rawRunStatuses': ['NEEDS-VISUAL-REVIEW'],
             'reviewSha256': [file_review_sha], 'frames': file_frames},
            {'id': 'latest-npp', 'title': '최신 Notepad++ 8.9.8.1',
             'platform': 'Microsoft Windows 98 4.10.2222 한국어',
             'display': '640 × 480 · 기본 VGA · KernelEx 및 앱 호환 구성 요소 · KVM',
             'result': '편집·새 파일 저장·새 부팅 뒤 파일 열기 확인, 정상 종료 실패',
             'observations': ['배포처의 원본 실행 파일을 그대로 사용했습니다.',
                              '새 파일 저장 창에서 저장한 실제 44바이트를 디스크에서 별도로 확인했습니다.',
                              '별도 콜드 부팅에서도 원본 앱으로 저장한 파일을 열었습니다. 프로그램 종료 오류는 보존했습니다.'],
             'scope': '이전 전체 시험의 실패를 보존한 기록입니다. 전용 앱 호환 실행기를 사용하는 새 GOP 실행의 정상 종료 결과는 별도 GOP 앱 기록에서 확인할 수 있습니다.',
             'rawRunStatuses': ['NEEDS-VISUAL-REVIEW'], 'applicationTrialStatus': 'FAIL',
             'coldReopenVerified': True,
             'reviewSha256': [npp_proof_sha, npp_cold_proof_sha], 'frames': npp_frames},
            {'id': 'native-gop-surface', 'title': 'Windows 98 네이티브 GOP 화면 메모리',
             'platform': 'Microsoft Windows 98 4.10.2222 한국어',
             'display': '1280 × 800 · 32비트 GOP 화면 메모리 · KVM',
             'result': '바탕화면·입력·GDI 진단의 실제 화면 메모리 확인',
             'observations': ['설치된 Shizuku 기본 그래픽 드라이버가 실제 Windows 98에서 초기화됐습니다.',
                              '바탕화면·실행 창·시작 메뉴의 실제 픽셀을 검증된 화면 메모리에서 직접 읽었습니다.',
                              '게스트의 그리기·복사·읽기 진단과 정상 종료를 확인했습니다.'],
             'scope': '화면 메모리의 원래 픽셀을 크기·내용 변경 없이 PNG로 읽은 기록입니다. 모니터 출력도 같은 실행의 후반 원본 캡처로 확인했고, 추가 검증 기록이 기존 판정을 정정합니다. 최신 앱 실행은 별도 구현 중입니다.',
             'correctionAuditSha256': monitor_audit_sha,
             'rawRunStatuses': ['NEEDS-VISUAL-REVIEW'], 'reviewSha256': [native_gop_review_sha],
             'frames': native_gop_frames},
            {'id': 'native-win98', 'title': '실제 Windows 98',
             'platform': 'Microsoft Windows 98 4.10.2222 한국어', 'display': '640 × 480 · KVM · UEFI/CSM',
             'result': '메모장 저장과 콜드 부팅 후 다시 열기 확인',
             'observations': ['실제 Windows 98 바탕 화면과 메모장을 실행했습니다.',
                              '게스트에서 저장한 파일을 호스트에서도 읽어 내용과 해시를 확인했습니다.',
                              '새 콜드 부팅 뒤 같은 파일이 다시 열렸습니다.'],
             'scope': '이 화면은 기본 VGA로 실행한 이전 기록입니다. 해당 실행의 네이티브 VxD 적재 시험 실패는 보존했습니다. 현재 GOP 드라이버 결과는 별도 GOP 기록에서 확인할 수 있습니다.',
             'rawRunStatuses': [manual['status'], cold['status']],
             'reviewSha256': [manual_review_sha, cold_review_sha], 'frames': native_frames},
            {'id': 'independent-gop', 'title': 'Shizuku 독립 GOP 데스크톱',
             'platform': 'ShizukuDOS Kernel64 · 자체 Win64 런타임', 'display': '1280 × 800 · UEFI GOP · KVM',
             'result': '제작한 ISO에서 두 번의 콜드 부팅 시험 통과',
             'observations': ['실제 키보드 입력으로 파일을 작성하고 다시 열었습니다.',
                              '두 부팅 모두 FAT32 디스크의 저장된 25바이트를 호스트에서 별도로 확인했습니다.',
                              '자식 앱 실행·정상 종료, 디스크 flush와 shutdown이 확인됐습니다.'],
             'scope': '이 화면은 별도 Shizuku 커널과 자체 셸입니다. Microsoft Windows 98 실행 화면이나 Windows 98 디스플레이 드라이버 검증 결과로 사용하지 않습니다.',
             'rawRunStatuses': [desktop['status']], 'frames': gop_frames},
            {'id': 'native-driver-install', 'title': 'Windows 98 드라이버 설치',
             'platform': 'Microsoft Windows 98 4.10.2222 한국어',
             'display': '640 × 480 · KVM · 설치 확인 화면',
             'result': 'Shizuku 기본 그래픽 드라이버 설치 확인',
             'observations': ['실제 Windows 98의 디스플레이 변경 마법사를 완료했습니다.',
                              '어댑터 속성에서 Shizuku 이름과 DRV·VXD 파일을 확인했습니다.',
                              '설치된 두 파일의 실제 바이트가 시험 입력과 일치합니다.'],
             'scope': '이 설치 확인 화면은 재시작 전 기본 VGA로 표시했습니다. 이후 GOP 드라이버의 실제 출력 결과는 GOP 기록에서 확인할 수 있습니다. 최신 앱 실행은 계속 구현 중입니다.',
             'rawRunStatuses': [install['status']],
             'reviewSha256': [install_review_sha], 'frames': [install_frame]}]
    }
    # Validate everything before the first export write; keep originals byte exact.
    images = output / 'images'
    images.mkdir(parents=True, exist_ok=True)
    for name, data in blobs.items():
        (images / name).write_bytes(data)
        if (images / name).read_bytes() != data:
            raise ValueError('Export changed original PNG bytes')
    payload = json.dumps(manifest, ensure_ascii=False, indent=2).encode() + b'\n'
    (output / 'preview.json').write_bytes(payload)
    print(json.dumps({'status': 'PASS', 'scope': 'original captures, faithful physical pixel decodes and receipt integrity only',
                      'images': len(blobs), 'manifest_sha256': digest(payload),
                      'bytes': sum(map(len, blobs.values())), 'output': str(output)}))


if __name__ == '__main__':
    main()
