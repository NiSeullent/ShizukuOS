#!/usr/bin/env python3
"""Bundle the two already reviewed open-source downloads without changing them."""
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DOWNLOADS = ROOT / 'site/downloads'
PINS = {
    'SHZGOP.zip': '5fdc6ca5942012b6d29a291ca85e6ad4e5ca28421477394bfd2909c64f9c5dbb',
    'SHZNPP.zip': '9ae5a7628f99783e79b935a6eb04dfdc38ddafd02e540079877ae3dcac7df042',
}
README = '''Windows 98 Shizuku Modern Edition — 개발 미리보기

포함 파일
• SHZGOP.zip: Shizuku 기본 그래픽 드라이버, 설치 INF, 소스와 라이선스.
• SHZNPP.zip: 최신 Notepad++ 8.9.8.1용 호환 실행기와 DLL, 소스와 라이선스.
• SHZNPP-README.md: 앱 호환 구성의 설치 안내와 확인된 범위.

Windows 98 설치본, Windows 라이선스, Notepad++ 원본은 별도로 준비하세요.
이 파일은 완성된 운영체제 ISO나 자동 설치 프로그램이 아닙니다.

시작하기
1. 본인의 Windows 98 SE 설치본을 복제해 시험용 환경을 준비하세요.
2. SHZGOP.zip 안의 안내에 따라 드라이버와 대응 GOP 부팅 구성을 준비하세요.
   드라이버만으로 일반 Windows 98이 UEFI 부팅되는 것은 아닙니다.
3. Notepad++는 SHZNPP-README.md의 사전 준비와 수동 설치 순서를 따르세요.
   KernelEx 4.5.2, Unicode Layer, 공식 x86 Notepad++ 원본이 필요합니다.

확인된 동작
실제 Windows 98에서 UEFI GOP 화면 출력, 편집, 저장, 다음 부팅에서 다시 열기,
최신 Notepad++의 전용 실행기를 통한 정상 종료를 확인했습니다.
새 설치본에서 이 ZIP만으로 설치하는 과정은 아직 검증하지 않았습니다.
Chromium, Legcord/Discord, LibreOffice, Steam과 GPU 3D 가속은 개발 중입니다.

실제 실행 화면: https://m98.nyase.kr/preview.html
소스: https://github.com/NiSeullent/Win98-Modern

각 ZIP의 대응 소스와 개별 라이선스 고지를 함께 보관하세요.
이 묶음에는 Windows 파일, 상용 앱, 설치 디스크나 VM 이미지가 없습니다.
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    output = ROOT / 'build/m98-preview-download-20261001-v1'
    target = DOWNLOADS / 'shizuku-modern-preview-2026.10.01.zip'
    assert not output.exists() and not target.exists(), 'Fresh bundle output required'
    members = {name: (DOWNLOADS / name).read_bytes() for name in PINS}
    assert all(sha(members[name]) == pin for name, pin in PINS.items())
    members['SHZNPP-README.md'] = (DOWNLOADS / 'SHZNPP-README.md').read_bytes()
    members['먼저 읽어주세요.txt'] = README.encode('utf-8-sig')
    manifest = {'product': 'Windows 98 Shizuku Modern Edition',
                'version': '2026.10.01 development preview',
                'kind': 'reviewed component bundle',
                'operating_system_image': False,
                'members': {name: {'bytes': len(data), 'sha256': sha(data)} for name, data in members.items()}}
    members['MANIFEST.json'] = (json.dumps(manifest, ensure_ascii=False, indent=2) + '\n').encode()
    output.mkdir()
    with zipfile.ZipFile(target, 'x') as archive:
        for name, data in members.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    with zipfile.ZipFile(target) as archive:
        assert archive.testzip() is None and set(archive.namelist()) == set(members)
        assert all(archive.read(name) == data for name, data in members.items())
    payload = target.read_bytes()
    checksum = target.with_name(target.name + '.sha256')
    checksum.write_text(sha(payload) + '  ' + target.name + '\n', encoding='ascii')
    result = {'status': 'PASS_EXACT_REVIEWED_COMPONENT_BUNDLE',
              'path': str(target), 'bytes': len(payload), 'sha256': sha(payload),
              'members': manifest['members'], 'source_sha256': sha(Path(__file__).read_bytes()),
              'original_components_unchanged': all(sha((DOWNLOADS / n).read_bytes()) == h for n, h in PINS.items()),
              'operating_system_image': False, 'fresh_install_verified': False}
    (output / 'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
