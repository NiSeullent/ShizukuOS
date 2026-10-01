#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prepare an additive Authorship page from fixed genuine execution evidence.

Default: validate only. --out writes a fresh owned source bundle, never deploys.
No VM, application, repository builder, image editing or network operation.
"""
import argparse
import hashlib
import html
import io
import json
import os
from pathlib import Path
import stat

ROOT = Path(__file__).resolve().parents[1]
BOOT = Path('/root/Win98-Modern-boot')
CSM = BOOT/'build/shizukudos/csm'
MODERN = ROOT/'build/modern-apps'
NPP = CSM/'run-win98-gop-latest-npp-cold-v3-20260930T1807'
GOP = CSM/'run-win98-uefi-q35-kvm-gop-ne-selector-probe'
GDI = CSM/'run-win98-uefi-q35-kvm-gop-ne-selector-30s-mmio'
LEG = MODERN/'legcord-v33-k11-actual'
CHR = MODERN/'chromium-v34-k13-multiprocess-actual'
PINS = {
    NPP/'native-gop-latest-npp-cold-keyboard-review.json': 'e945062ad535c5e2b61f7ee39be91c308d1103b29ff3d44d0f5b2e3455d40175',
    NPP/'result.json': '13f76fc4f6870a61d5067b76b7c47a49b7d40ddcd9310f271d5d8cbd1fab8ada',
    CSM/'gop-monitor-correction-audit-20260930T155157/correction-audit.json': 'a01cef2ab1b74594fcac22a68d97450ff513560b446f2621c817dba1ff6b9969',
    GOP/'result.json': 'fe3ff557d190676e8e82433cd47825786245d4bcda5e21cab3fdec65cf657296',
    GDI/'result.json': 'a3b1e42ec719cb4de75e2986e653e5fe9c547752429f13c48ac80e51bced629b',
    LEG/'observation.json': 'fd6a3236dcc813637a04f3f385065ca9e42db5b7d072c9b08786f5bfeb9af485',
    CHR/'result.json': '7aa0079ee82c01e06fd4117111d05776177eb7c93f16cad1126f809282df0f63',
}
FRAMES = (
    ('npp-cold-open.png', NPP/'screen-015.png', 'cb630d9533decbe718cdaddd79f93ec8b9d7da3ebd3eaaadcfdc62d5695a9990', (1280, 800), 'npp'),
    ('npp-keyboard-saved.png', NPP/'screen-038.png', '10699734c6334687e95b8b6150f98bef3a27d9acda7f06ac4c2f78f702787417', (1280, 800), 'npp'),
    ('gop-start.png', GOP/'screen-061.png', '574a70e9ee600e7f458eb6c93e54ae8ac88584addd0887e8af78328c510e2062', (1280, 800), 'gop'),
    ('gop-gdi.png', GDI/'screen-089.png', '41bf02431b194a3889eac4f80da8ceb22ec390875fcdd084a9c6bf9593288eb4', (1280, 800), 'gop'),
    ('legcord-welcome.png', LEG/'screen-545.png', '28fc8a9c451a610160ca833be12056e9497fb5bf85753a6169d3d3bbadf62238', (1024, 768), 'legcord'),
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_verified(path, expected):
    if path != path.resolve(strict=True):
        raise ValueError('Evidence path is not canonical: '+str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 32*1024*1024:
            raise ValueError('Evidence is not a bounded regular file')
        raw = os.pread(fd, before.st_size+1, 0)
        after = os.fstat(fd)
        current = os.stat(path, follow_symlinks=False)
        key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
        if len(raw) != before.st_size or key(before) != key(after) or key(after) != key(current):
            raise ValueError('Evidence changed during read')
        if digest(raw) != expected:
            raise ValueError('Pinned original evidence changed: '+str(path))
        return raw
    finally:
        os.close(fd)


def decoded_png(raw, dimensions):
    from PIL import Image
    with Image.open(io.BytesIO(raw)) as image:
        if image.format != 'PNG' or image.size != dimensions:
            raise ValueError('Original PNG format/dimensions differ')
        image.verify()
    with Image.open(io.BytesIO(raw)) as image:
        image.load()


def capture_record(data, path, expected):
    matches = [c for c in data['captures']
               if c.get('screenshot', c.get('path')) == str(path)]
    if len(matches) != 1 or matches[0]['sha256'] != expected:
        raise ValueError('Original frame is not uniquely bound to its actual capture receipt')


def semantic_checks(data):
    npp = data[NPP/'native-gop-latest-npp-cold-keyboard-review.json']
    raw = data[NPP/'result.json']
    if (npp['status'] != 'SCOPED-NATIVE-GOP-NPP-COLD-KEYBOARD-PASS'
            or raw['status'] != 'NEEDS-VISUAL-REVIEW'
            or raw['profile'] != 'actual-win98-uefi-csmwrap'
            or npp['raw_result_sha256'] != PINS[NPP/'result.json']
            or npp['raw_receipt_mutated']
            or len(npp['checks']) != 25
            or any(c['status'] != 'PASS' for c in npp['checks'])
            or not npp['limits']['requires_native_field_interpreter']
            or npp['limits']['full_project_complete']
            or npp['limits']['unassisted_NPP_exit_verified']
            or not npp['limits']['old_NPPGOP_cold_reopen_verified']
            or npp['limits']['new_NPEDGOP_cold_reopen_verified']):
        raise ValueError('Native NPP scope changed')
    audit = data[CSM/'gop-monitor-correction-audit-20260930T155157/correction-audit.json']
    if (audit['status'] != 'PASS-NATIVE-WIN98-GOP-GUI-GDI'
            or audit['full_project_goal_complete'] or len(audit['runs']) != 2):
        raise ValueError('Native GOP audit scope changed')
    for row, folder in zip(audit['runs'], (GOP, GDI)):
        if (row['execution_receipt_sha256'] != PINS[folder/'result.json']
                or data[folder/'result.json']['profile'] != 'actual-win98-uefi-csmwrap'
                or row['monitor_visible_native_win98'] != 'PASS'
                or not row['originals_unchanged']
                or not row['old_visual_review_preserved_unchanged']):
            raise ValueError('Native GOP original/audit binding differs')
    leg = data[LEG/'observation.json']
    if (leg['app'] != 'legcord' or leg['guest_os'] != 'ShizukuDOS Kernel64 standalone'
            or leg['app_functionality_verified'] or leg['windows98_execution_verified']
            or not leg['inputs_unchanged'] or leg['capture_errors']
            or '--no-sandbox' not in leg['actual_startup_command'].split()):
        raise ValueError('Legcord standalone observation scope changed')
    chrome = data[CHR/'result.json']
    if (chrome['status'] != 'PASS' or not chrome['expected_line_seen']
            or chrome['expected_line'] != '<p id="m">ShizukuDOS M2 probe 42</p>'
            or chrome['exit_code'] != 0 or chrome['faulted'] or chrome['ended_by'] != 'exited'
            or chrome['qemu_timed_out'] or chrome['loader_failures']
            or chrome['exceptions'] or chrome['chromium_fatal'] or chrome['unsupported_calls']
            or not {'--headless', '--no-sandbox', '--dump-dom'}.issubset(chrome['chrome_args'].split())
            or '--single-process' in chrome['chrome_args'].split()
            or not any(chrome['expected_line'] in line for line in chrome['chrome_output_lines'])):
        raise ValueError('Actual headless Chromium DOM/normal-exit scope changed')


def collect():
    consumed = {path: read_verified(path, pin) for path, pin in PINS.items()}
    data = {path: json.loads(raw) for path, raw in consumed.items()}
    semantic_checks(data)
    assets = {}
    frames = []
    for name, path, pin, dimensions, app in FRAMES:
        raw = read_verified(path, pin)
        decoded_png(raw, dimensions)
        folder = path.parent
        capture_record(data[folder/('observation.json' if app == 'legcord' else 'result.json')], path, pin)
        if app == 'npp':
            reviewed = [r for r in data[NPP/'native-gop-latest-npp-cold-keyboard-review.json']['screenshots']
                        if r['path'] == str(path)]
            if len(reviewed) != 1 or reviewed[0]['sha256'] != pin:
                raise ValueError('Native NPP frame review differs')
        assets['images/'+name] = raw
        consumed[path] = raw
        receipt = PINS[folder/('observation.json' if app == 'legcord' else 'result.json')]
        review = PINS[NPP/'native-gop-latest-npp-cold-keyboard-review.json'] if app == 'npp' else (
            PINS[CSM/'gop-monitor-correction-audit-20260930T155157/correction-audit.json'] if app == 'gop' else receipt)
        frames.append({'src': './images/'+name, 'kind': 'original-guest-capture',
                       'sha256': pin, 'width': dimensions[0], 'height': dimensions[1],
                       'app': app, 'capture_receipt_sha256': receipt, 'review_sha256': review,
                       'pixel_transform': False, 'thumbnail_method': 'CSS containment only'})
    # Recheck every original before returning any prepared output.
    for path, raw in consumed.items():
        if read_verified(path, digest(raw)) != raw:
            raise ValueError('Original evidence changed after validation')
    catalogue = {
        'schema': 'win98modern.authorship-evidence.v1', 'as_of_utc': '2026-10-01',
        'proposed_version': '0.9', 'release_state': 'preparation', 'published_by_this_tool': False,
        'repository': 'https://github.com/NiSeullent/Win98-Modern',
        'full_project_goal_complete': False, 'screenshots': frames,
        'results': [
            {'id': 'npp', 'platform': 'installed Microsoft Windows 98 SE', 'version': '8.9.8.1',
             'verified': ['old44B_document_cold_reopen', 'distinct39B_keyboard_save', 'actual_application_exit0'],
             'requires_native_field_interpreter': True, 'unassisted_exit_verified': False,
             'new39B_document_cold_reopen_verified': False, 'gpu3d_verified': False,
             'receipt_sha256': PINS[NPP/'result.json'],
             'review_sha256': PINS[NPP/'native-gop-latest-npp-cold-keyboard-review.json']},
            {'id': 'gop', 'platform': 'installed Microsoft Windows 98 SE through UEFI/CSMWrap',
             'verified': ['original_monitor_start_menu', 'native_GDI_pattern_monitor_readback'],
             'fixed_mode': '1280x800', 'gpu3d_verified': False,
             'additive_correction_audit_sha256': PINS[CSM/'gop-monitor-correction-audit-20260930T155157/correction-audit.json']},
            {'id': 'chromium', 'platform': 'ShizukuDOS Kernel64 standalone', 'version': '157.0.8081.0',
             'verified': ['headless_multiprocess_DOM42', 'actual_normal_exit0'],
             'command': data[CHR/'result.json']['chrome_args'], 'screenshot': None,
             'screenshot_status': 'not_captured_in_this_headless_trial',
             'native_windows98_verified': False, 'graphical_browser_verified': False,
             'network_navigation_verified': False, 'receipt_sha256': PINS[CHR/'result.json']},
            {'id': 'legcord', 'platform': 'ShizukuDOS Kernel64 standalone', 'version': '1.3.0',
             'verified': ['original_welcome_setup_rendered'], 'discord_functionality_verified': False,
             'native_windows98_verified': False, 'clean_exit_verified': False,
             'observation_ended_by': data[LEG/'observation.json']['product_classification']['ended_by'],
             'receipt_sha256': PINS[LEG/'observation.json']},
        ],
    }
    return catalogue, assets, {str(path): digest(raw) for path, raw in consumed.items()}


def page(catalogue):
    cards = [
        ('npp', '실제 Windows 98 · GOP', 'Notepad++ 8.9.8.1',
         '저장한 파일을 다시 부팅한 뒤 열고, 다른 내용을 직접 입력해 새 파일로 저장했습니다. 앱의 정상 종료도 확인했습니다.',
         '전용 앱 호환 실행기를 사용한 결과입니다. 새 39바이트 파일의 재부팅 후 열기는 아직 별도 시험하지 않았습니다.',
         'npp-cold-open.png', '실제 Windows 98에서 Notepad++로 저장한 파일을 다시 연 원본 화면',
         '../preview.html?view=latest-npp-gop'),
        ('gop', '실제 Windows 98 · UEFI', '익숙한 바탕 화면, GOP로',
         'UEFI 부팅 뒤 설치된 Shizuku 기본 그래픽 드라이버로 시작 메뉴와 실제 화면 그리기를 확인했습니다.',
         '1280 × 800 고정 모드의 시험 결과이며, GPU 3D 가속과 모든 하드웨어 지원은 개발 중입니다.',
         'gop-start.png', 'UEFI GOP로 출력한 실제 한국어 Windows 98 시작 메뉴',
         '../preview.html?view=native-gop-monitor'),
        ('legcord', '독립 64비트 실행 시험', 'Legcord 1.3.0의 첫 화면',
         '원본 Legcord의 Welcome 화면과 Get Started 버튼을 실제 실행 화면에서 확인했습니다.',
         'Windows 98 내부 연결과 Discord 접속은 개발 중입니다. 이 관찰 시험은 제한 시간으로 끝났습니다.',
         'legcord-welcome.png', '독립 Kernel64에서 실제로 렌더링된 Legcord Welcome 설정 화면',
         '../preview.html?view=legcord-runtime-setup'),
    ]
    articles = []
    for ident, badge, title, body, scope, name, alt, link in cards:
        frame = next(f for f in catalogue['screenshots'] if f['src'] == './images/'+name)
        extra = ('<a class="record-link extra" href="./images/npp-keyboard-saved.png">직접 입력·저장 원본 →</a>'
                 if ident == 'npp' else '<a class="record-link extra" href="./images/gop-gdi.png">그리기 시험 원본 →</a>'
                 if ident == 'gop' else '')
        articles.append(f'''<article class="card" id="{ident}">
<a class="capture" href="./images/{name}" aria-label="{html.escape(alt)} 원본 보기"><img src="./images/{name}" width="{frame['width']}" height="{frame['height']}" alt="{html.escape(alt)}" loading="lazy"><span>실제 실행 원본 · 크게 보기 ↗</span></a>
<div class="card-copy"><span class="badge">{badge}</span><h2>{title}</h2><p>{body}</p><p class="scope">{scope}</p><a class="record-link" href="{link}">실행 기록 보기 →</a> {extra}</div></article>''')
    articles.append('''<article class="card chromium" id="chromium">
<div class="dom-result"><span>실제 실행 결과 · 화면 없는 시험</span><strong>42</strong><p>페이지의 계산 결과를 DOM에서 확인</p><code>&lt;p id="m"&gt;ShizukuDOS M2 probe 42&lt;/p&gt;</code><small>이 영역은 실행 결과 텍스트입니다. 브라우저 사진이 아닙니다.</small></div>
<div class="card-copy"><span class="badge">독립 64비트 실행 시험</span><h2>Chromium 157.0.8081.0</h2><p>실제 다중 프로세스 실행으로 페이지의 DOM 결과와 정상 종료를 확인했습니다.</p><p class="scope">화면 없는 headless 시험입니다. 그래픽 브라우저·웹 탐색·Windows 98 내부 실행은 계속 구현 중이며, 이 시험에는 스크린샷이 없습니다.</p><a class="record-link" href="./evidence.json">검증 범위와 기록 보기 →</a></div></article>''')
    return '''<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="Windows 98 Shizuku Modern Edition의 제작과 검증 기록. 실제 Windows 98의 Notepad++·UEFI GOP 화면과 독립 실행기의 Chromium·Legcord 결과를 확인하세요.">
<title>Authorship · Windows 98 Shizuku Modern Edition</title><link rel="stylesheet" href="./styles.css"><link rel="icon" type="image/svg+xml" href="../favicon.svg"></head>
<body><a class="skip" href="#main">본문으로 건너뛰기</a><div class="shell">
<header><a class="brand" href="../index.html"><span class="brand-mark" aria-hidden="true">98</span><span>Windows 98<small>Shizuku Modern Edition</small></span></a><nav aria-label="주 메뉴"><a href="../index.html">다운로드</a><a href="../preview.html">실제 실행 화면</a><a href="#credits" aria-current="page">Authorship</a></nav></header>
<main id="main"><section class="intro"><p class="eyebrow">AUTHORSHIP / 개발·검증 기록</p><div class="intro-line"><h1>직접 만들고,<br>실제로 확인한 기록.</h1><span class="version">0.9 준비 중</span></div>
<p class="lead">Windows 98 Shizuku Modern Edition을 개발하며 확인한 화면과 실행 결과입니다. 원본 사진을 그대로 보여 드리고, 각 프로그램이 현재 동작하는 환경을 함께 표시합니다.</p>
<p class="date">2026년 10월 1일 기준 · 0.9는 제안된 개발 버전이며 아직 출시되지 않았습니다.</p></section>
<section class="gallery" aria-label="실제 실행 결과">''' + '\n'.join(articles) + '''</section>
<section class="progress"><h2>다음으로 연결할 기능</h2><p>Chromium의 그래픽 화면과 웹 탐색, Legcord의 Discord 접속, 최신 오픈소스 Office의 문서 작업, Steam의 실제 기능을 계속 구현합니다. 독립 64비트 실행 결과를 Windows 98 내부의 화면·입력과 연결하는 작업도 진행 중입니다.</p></section>
<section class="credits" id="credits"><div><p class="eyebrow">SOURCE / 출처와 기여</p><h2>개발 기록은 소스와 함께.</h2><p>프로젝트의 작성자와 변경 내역은 공개 저장소에 기록합니다. 프로그램의 원본 화면은 각각 Notepad++, Chromium, Legcord 프로젝트의 실제 배포 프로그램에서 얻었습니다.</p></div>
<div class="credit-links"><a href="https://github.com/NiSeullent/Win98-Modern">NiSeullent / Win98-Modern ↗</a><a href="https://github.com/NiSeullent/Win98-Modern/commits/main/">작성·변경 이력 ↗</a><a href="https://github.com/NiSeullent/Win98-Modern/blob/main/LICENSE">프로젝트 라이선스 ↗</a><a href="./evidence.json">원본 이미지 SHA-256과 검증 범위 →</a></div></section></main>
<footer><p>Windows 98 Shizuku Modern Edition · 0.9 준비</p><p>Microsoft Windows 설치 미디어·제품 키는 제공하지 않습니다.</p><a href="#main">맨 위로 ↑</a></footer></div></body></html>
'''


CSS = '''*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:#f5f6f1;color:#173c3c;font-family:system-ui,-apple-system,"Noto Sans KR",sans-serif;line-height:1.7}a{color:inherit;text-decoration:none}a:focus-visible{outline:3px solid #5a58d9;outline-offset:5px}.shell{width:min(1184px,calc(100% - 56px));margin:auto}header{display:flex;justify-content:space-between;align-items:center;gap:24px;padding:28px 0;border-bottom:1px solid #cdd8d2}.brand{display:flex;align-items:center;gap:12px;font-weight:750;line-height:1.3}.brand small{display:block;font-size:12px;letter-spacing:.02em;font-weight:500;margin-top:4px}.brand-mark{background:#007b78;color:#fff;border:2px solid #164947;box-shadow:3px 3px 0 #173c3c;font-size:19px;padding:7px 10px}nav{display:flex;gap:24px;font-size:14px}nav a[aria-current]{font-weight:750;border-bottom:2px solid #0c716b}.skip{position:absolute;top:-80px;left:16px;background:white;padding:10px;z-index:5}.skip:focus{top:10px}.intro{padding:64px 0 44px}.eyebrow{font-size:12px;font-weight:700;letter-spacing:.12em;color:#4b6860}.intro-line{display:flex;justify-content:space-between;align-items:flex-start;gap:20px}h1{font-size:clamp(38px,5.5vw,64px);line-height:1.22;letter-spacing:-.045em;margin:14px 0 20px}.version{font-size:13px;white-space:nowrap;background:#e3e9c7;border:1px solid #91a372;padding:8px 14px;margin-top:20px}.lead{max-width:720px;font-size:18px;color:#46615a}.date{font-size:13px;color:#5c6c64}.gallery{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:24px}.card{background:#fff;border:1px solid #c6d3cb;box-shadow:3px 3px 0 #e4e8df;overflow:hidden}.capture{display:block;background:#007e7e;border-bottom:1px solid #c6d3cb}.capture img{display:block;width:100%;height:auto;aspect-ratio:8/5;object-fit:contain}.capture span{display:block;background:#eaf1ed;padding:7px 16px;font-size:11px;color:#48615b}.card-copy{padding:28px}.badge{display:inline-block;font-size:11px;background:#edf2e9;color:#395848;padding:4px 9px;border:1px solid #d4dfd0}.card h2{margin:14px 0 10px;font-size:26px;line-height:1.3;letter-spacing:-.035em}.card p{margin:12px 0}.scope{font-size:13px;color:#62736a}.record-link{display:inline-block;font-size:13px;font-weight:700;margin-top:9px;border-bottom:1px solid #98b4a6}.dom-result{display:flex;min-height:352px;flex-direction:column;align-items:flex-start;justify-content:center;background:#122e37;color:#d9e5df;padding:34px;border-bottom:1px solid #c6d3cb}.dom-result>span{font-size:12px;color:#a1c2b9}.dom-result strong{font-size:76px;line-height:1.2;color:#bef1c1;font-weight:550;margin:8px 0}.dom-result p{font-size:15px;margin:0 0 18px}.dom-result code{font-size:12px;max-width:100%;overflow-wrap:anywhere;white-space:normal}.dom-result small{display:block;font-size:11px;color:#a1b8b5;margin-top:20px}.progress{padding:36px;border:1px solid #c6d3cb;background:#e9eee3;margin-top:38px}.progress h2,.credits h2{font-size:25px;letter-spacing:-.03em;margin:0 0 12px}.progress p{margin:0;max-width:960px}.credits{display:grid;grid-template-columns:1.2fr 1fr;gap:48px;padding:60px 0}.credits p{max-width:590px}.credit-links{display:flex;flex-direction:column;gap:12px;justify-content:center}.credit-links a{font-size:14px;padding:10px 0;border-bottom:1px solid #ccd8cd}footer{display:flex;gap:24px;align-items:center;flex-wrap:wrap;padding:24px 0 36px;border-top:1px solid #cdd8d2;font-size:11px;color:#637369}footer p{margin:0}footer a{margin-left:auto}@media(max-width:760px){.shell{width:calc(100% - 32px)}header{align-items:flex-start;flex-direction:column;padding:22px 0;gap:22px}nav{gap:22px;font-size:13px}.intro{padding:38px 0 28px}.intro-line{display:block}.version{display:inline-block;margin:0}.lead{font-size:16px}.gallery{grid-template-columns:1fr;gap:20px}.card-copy{padding:22px}.card h2{font-size:24px}.dom-result{min-height:300px;padding:26px}.progress{padding:24px}.credits{grid-template-columns:1fr;gap:18px;padding:36px 0}footer{display:block}footer>*{display:block;margin:10px 0!important}}@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
'''


def prepare(out):
    if out.exists() or out.is_symlink() or out.parent != out.parent.resolve(strict=True):
        raise ValueError('Fresh canonical output required')
    if out != ROOT/'site/authorship-v09' and not out.is_relative_to(MODERN.resolve(strict=True)):
        raise ValueError('Output must be the owned Authorship source path or ignored modern-apps stage')
    catalogue, assets, inputs = collect()
    assets.update({'index.html': page(catalogue).encode(),
                   'styles.css': CSS.encode(),
                   'evidence.json': (json.dumps(catalogue, ensure_ascii=False, indent=2)+'\n').encode()})
    out.mkdir(mode=0o755)
    for name, raw in assets.items():
        dest = out/name
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open('xb') as stream:
            stream.write(raw)
    return {'status': 'PREPARED_NOT_PUBLISHED', 'inputs': inputs,
            'outputs': {name: digest(raw) for name, raw in assets.items()},
            'source_sha256': digest(Path(__file__).read_bytes()), 'source_edits_outside_new_bundle': 0,
            'vm_exec': 0, 'image_transforms': 0, 'publication': False,
            'chromium_screenshot_available': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    if args.out:
        print(json.dumps(prepare(args.out.absolute()), indent=2))
    else:
        catalogue, _, inputs = collect()
        print(json.dumps({'status': 'VALIDATION_ONLY', 'original_inputs': len(inputs),
                          'real_pngs': len(catalogue['screenshots']),
                          'publication': False, 'chromium_screenshot_available': False}))


if __name__ == '__main__':
    main()
