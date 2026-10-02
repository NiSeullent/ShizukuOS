# ShizukuOS · Win98-Modern

실제 Windows 98을 현대 하드웨어와 앱에 맞게 확장하는 운영체제 개발 프로젝트입니다. **ShizukuDOS 10이 MS-DOS 기반을 대체**하고 Kernel32·Kernel64·Supervisor가 Windows 98의 실행 기반을 지원합니다. 최종 제품은 **ShizukuOS 1.0.0**이며 현재는 개발 중입니다.

[공식 홈페이지](https://m98.nyase.kr/) · [다운로드](https://m98.nyase.kr/downloads.html) · [검증 화면](https://m98.nyase.kr/preview.html) · [문서 안내](docs/README.md) · [English](https://m98.nyase.kr/en/)

## 목표와 현재 상태

완료 목표는 정의한 전체 Windows API의 100% 호환, [필수 앱](docs/TARGET_APPS.md)의 실제 기능, 멀티코어·앱별 CPU 실행 모드·하드웨어 가상화, PAE를 통한 사용 가능한 RAM 전체 활용, 현대 저장장치·USB·그래픽 지원입니다. 각 항목은 실제 Windows 98에서 검증합니다.

| 항목 | 확인한 범위 | 남은 작업 |
| --- | --- | --- |
| 실제 Windows 98 부팅·그래픽 | Q35/KVM의 UEFI·고정 GOP 모드에서 Windows 98 GUI와 GDI 렌더링 | ShizukuDOS로 DOS 기반 교체, 실기기 지원, GPU 3D 가속 |
| Notepad++ 8.9.8.1 x86 | 제한된 구성에서 편집·Save As·재열기·콜드 재열기·정상 종료 | 수동 전제와 전용 런처 없는 실행, 새 설치본의 패키지 설치 검증 |
| VLC 3.0.24 x86 | 실제 Windows 98 GOP에서 Qt UI와 변하는 영상 프레임 | 정상 종료의 RPC 오류, 오디오, 전체 기능 검증 |
| Kernel32·Kernel64·Supervisor | 구성요소 빌드·API·독립 데스크톱 시험 | 실제 Windows 98과 서비스·화면·입력·파일 연결 |
| Chromium·Legcord/Discord·Office·Steam·Supermium·VS Code·Chrome·Firefox | 소스·로더·API와 개별 실행 단계 개발 | 필수 앱의 실제 기능과 정상 종료 검증 |

기존 Windows 98 GOP 부팅은 **원래 Microsoft DOS 경로를 사용한 제어군**입니다. ShizukuDOS의 DOS 교체 성공으로 계산하지 않습니다. 독립 Shizuku 데스크톱 시험도 실제 Windows 98의 완료 결과와 구분합니다. 각 결과의 조건과 원본 기록은 [아키텍처 감사](docs/SHIZUKUDOS_WINDOWS98_ARCHITECTURE.md), [그래픽 검증](docs/SHIZUKU_BASIC_GRAPHICS.md), [앱 인계](docs/CONTINUE_MODERN_APPS.md)에 있습니다.

## 시작하기

새 환경의 준비와 전체 빌드 순서는 [다른 환경에서 이어서 개발하기](docs/CONTINUE_ON_ANOTHER_MACHINE.md)를 따릅니다. 기본 개발 호스트는 x86-64 Linux이며 Python 3, C/C++·MinGW 빌드 도구, QEMU와 OVMF 등이 필요합니다.

구성요소의 기본 빌드·호스트 시험:

```sh
python3 platform/build.py
python3 platform/test.py
```

웹을 로컬에서 확인:

```sh
python3 -m http.server 8080 --bind 127.0.0.1 --directory site
```

브라우저에서 `http://127.0.0.1:8080/`을 엽니다. 사이트는 정적 파일로 구성되어 별도의 프런트엔드 패키지 설치가 필요하지 않습니다.

실제 Windows 98 시험에는 본인의 설치 매체와 비공개 설치본이 필요합니다. 원본을 보존하고 별도 복제본에서 시험합니다. 기존 `build.ps1`·`src/`·KernelEx 경로는 [과거 호환성 기록](docs/COMPATIBILITY.md)과 [VM 기록](vm/README.md)을 위한 회귀 경로로 유지합니다.

## 배포와 기여

**ISO 배포는 [m98.nyase.kr](https://m98.nyase.kr/)에서만 제공합니다.** GitHub에는 공개 개발 소스와 패치를 게시합니다. 개발 ISO·구성요소 ZIP의 제공 여부, 해시와 검증 범위는 다운로드 페이지에서 확인합니다. 자체 설치 시스템과 실제 Windows 98·필수 앱의 전체 완료 조건은 아직 개발 대상입니다.

Microsoft 설치 파일·제품 키·설치된 VM·앱 원본·비밀 값은 공개 소스나 패키지에 포함하지 않습니다. 코드 변경 시 출처와 파일별 라이선스를 보존하고, 빌드·호스트 시험·실제 게스트 실행을 각각 기록합니다.

[배포 기준](docs/OFFICIAL_DISTRIBUTION.md) · [라이선스](LICENSE) · [외부 코드 출처](THIRD_PARTY.md) · [사이트 개발·배포](site/README.md)
