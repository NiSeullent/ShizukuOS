# ShizukuOS

**ShizukuOS**는 자체 데스크톱과 실행 환경을 갖추는 운영체제입니다.
공통 기반은 **ShizukuOS Core**이며 ShizukuDOS, kernel·driver layers,
VM services, Linux subsystem과 native runtime을 통합합니다.
최종 제품 목표는 **ShizukuOS 1.0.0**이며 현재 개발 중입니다.

[공식 홈페이지](https://m98.nyase.kr/) · [다운로드](https://m98.nyase.kr/downloads.html) · [검증 화면](https://m98.nyase.kr/preview.html) · [문서 안내](docs/README.md) · [English](https://m98.nyase.kr/en/)

## 설계와 현재 구현

[Absolute Architecture Definition](docs/SHIZUKUOS_ARCHITECTURE_CONTRACT.md)이
플랫폼 정체성과 시스템 구성의 원문 기준입니다. 기존 저장소의 이름과 코드 출처는
현재 운영체제 경계를 정하지 않습니다. [통합 아키텍처](docs/INTEGRATED_ARCHITECTURE.md)와
[목표·현재 상태](docs/SHIZUKUOS_TARGET.md)는 재사용할 소스와 남은 연결을 설명합니다.
공개 저장소는 [NiSeullent/ShizukuOS](https://github.com/NiSeullent/ShizukuOS)입니다.

기존 한국어 `shizukudos/win64/apps/shizuku_shell`을 자체 실행 파일 셸로 확장합니다.
`SHIZUKU_SHELL.EXE` 패키징과 기본 시작 경로가 소스에 연결되어 있습니다.
Slade·Flute·Jade는 데이터로 정의하고 실행 파일 교체 없이 바꾸는 셸 테마입니다.
ShizukuVM, chkrnl, SHZLB.sys/Linux sandbox/POSIX/ShizukuLB, Nix-backed `pkgs`,
관리형 X 창, WebKit Terrasphere·Muzik·Sapphire·Folio와 필수 소리도 구현 목표입니다.
이 이름이나 소스 연결만으로 기능이 완성됐다고 주장하지 않습니다.

Win32 x86/x64 호환성, 실제 64비트 부팅·설치, 표준 장치·노트북·가속,
계정·elevate·권한·샌드박싱, ShizukuFS, Chromium·Legcord/Discord·최신 오픈소스
Office·Steam의 유용한 동작도 계속 개발합니다. [전체 승인 기준](docs/SHIZUKUOS_FULL_GOAL_ACCEPTANCE.md)은
실제 ShizukuOS에서 실행된 기능과 원본 증거로 판정합니다.

## 기존 결과의 범위

| 기록 | 확인한 범위 | 전체 시스템 완료와의 관계 |
| --- | --- | --- |
| Windows 98 GOP 그래픽 | 기존 Q35/KVM UEFI·고정 GOP의 Windows 98 GUI/GDI 제어군 | 선택적 레거시 프로필의 기록입니다. 새 Core·설치·가속 완료를 의미하지 않습니다. |
| Notepad++ 8.9.8.1 x86 | 제한된 구성의 편집·Save As·재열기·cold reopen·종료 | 기존 입력과 전제의 앱 기록입니다. 새 설치본의 패키지·앱 승인이 필요합니다. |
| VLC 3.0.24 x86 | 기존 Windows 98 GOP의 Qt UI와 변하는 영상 프레임 | audio·정상 종료·전체 기능과 새 설치에서의 동작이 남아 있습니다. |
| Kernel32·Kernel64·Supervisor와 native shell | 구성요소 소스·빌드·호스트/독립 시험 | actual ShizukuOS의 현재 산출물로 실행·지속성·장치·앱을 확인해야 합니다. |
| 현대 앱 이식 | source·loader·API·DLL·개별 실행 단계 | Chromium·Legcord·Office·Steam의 실제 기능·종료 검증이 남아 있습니다. |

과거 Microsoft DOS 제어군, 독립 커널 시험, 호스트 모델과 정적 검사는 각 원래
범위를 유지합니다. 사진·목업·built image·boot만으로 기능을 완료 처리하지 않습니다.
원본 기록은 [기존 아키텍처 감사](docs/SHIZUKUDOS_WINDOWS98_ARCHITECTURE.md),
[그래픽 기록](docs/SHIZUKU_BASIC_GRAPHICS.md), [앱 인계](docs/CONTINUE_MODERN_APPS.md)에 있습니다.

## 개발 시작

[다른 환경에서 이어서 개발하기](docs/CONTINUE_ON_ANOTHER_MACHINE.md)를 따릅니다.
기본 개발 호스트는 x86-64 Linux이며 Python 3, C/C++·MinGW, QEMU와 OVMF 등
해당 구성요소의 도구가 필요합니다. 실행할 범위와 자원은 현재 workspace에서 확인합니다.

```sh
python3 platform/build.py
python3 platform/test.py
```

사이트는 정적 파일입니다. 로컬 확인 예시:

```sh
python3 -m http.server 8080 --bind 127.0.0.1 --directory site
```

`http://127.0.0.1:8080/`에서 확인합니다. 선택적 Windows 98 프로필 시험에는
본인의 비공개 매체·설치본을 사용하고 원본을 보존한 별도 소유 복제본에서 실행합니다.
기존 `build.ps1`·`src/`·KernelEx 경로와 [VM 기록](vm/README.md)은 과거 회귀 범위를 유지합니다.

## 배포와 기여

ISO는 적용 가능한 설치·부팅·드라이버 release gates를 검증한 뒤 nginx의
[m98.nyase.kr](https://m98.nyase.kr/)에서 제공합니다. 최종 전체 시스템 기준은 별도로
유지합니다. 홈페이지·다운로드는 외부망에서 확인하며 공개 페이지에 private VNC를
노출하지 않습니다. GitHub에는 허용된 개발 소스와 패치를 게시합니다.
제공되는 산출물·해시·검증 범위는 다운로드 페이지를 확인합니다.

Microsoft 설치 파일·제품 키·설치된 VM·비공개 앱 원본·비밀 값은 공개하지 않습니다.
외부 코드의 출처·라이선스를 보존하고 실제로 실행한 검사와 남은 제약을 기록합니다.

[배포 기준](docs/OFFICIAL_DISTRIBUTION.md) · [라이선스](LICENSE) · [외부 코드 출처](THIRD_PARTY.md) · [사이트 개발·배포](site/README.md)
