# Windows 98 Shizuku's Second Edition

Windows 98를 현대 하드웨어와 애플리케이션에 맞게 확장하는 **개발 중인 운영체제 프로젝트**입니다. 새 개발 경로는 독자 구현인 **NTWrapper9x**(커널 기반), **NTWin32Wrapper9x**(앱 호환성), **NTWDDMWrapper9x**(그래픽), **PCI-E 확장**, **ShizukuDOS UEFI**로 구성합니다. Windows 8.1/10/11 수준의 기능은 목표이며 아직 달성하지 않았습니다.

새 경로의 빌드·시험·현재 한계는 [독립 플랫폼 개발 안내](platform/README.md)와 [네이티브 계층 검증 기록](docs/NATIVE_PLATFORM_CHECKPOINT.md)에 있습니다. 이 빌드는 KernelEx·Wine·ReactOS 구현이나 기존 `m98wrap.dll`을 사용하지 않습니다. `NTW32.DLL`의 기존 Windows 98 네이티브 함수 호출은 유지합니다.

```sh
python3 platform/build.py
python3 platform/test.py
```

새 `NTW32.DLL`은 SRW·InitOnce·틱 확장·동적 API 조회 13개 함수를 제공합니다. 실제 DLL의 32비트 호출·재배치 시험을 통과했고, 독자 LE 형식의 `NTWRAP9X.VXD`와 VMM 조회 경로를 구현했습니다. ShizukuDOS는 x64 UEFI를 종료하고 자체 32비트 보호 모드 커널로 전환해 커널 코어와 소프트웨어 그래픽을 실행했습니다.

이 증거와 실제 Windows 98의 VxD/앱 시험은 별도로 기록합니다. 사용자 제공 Windows 98 SE 매체의 해시를 검증해 별도 설치 환경을 준비했으며, 새 DLL의 Windows 98 실행은 아직 검증하지 않았습니다. UEFI 전환 성공은 Windows 98 GUI 부팅을 뜻하지 않습니다.

## 기존 경로의 보존 기록

아래는 참고 저장소에서 이어받은 **KernelEx 기반 경로와 과거 Windows 호스트의 시험 기록**입니다. 기존 라이선스·출처·재현 자료를 보존하며, 새 독립 계층의 구현이나 실행 증거로 합산하지 않습니다. 기존 `build.ps1`은 이 경로의 회귀 시험용입니다.

## 현재 구현

- `KERNEL32.DLL`의 89개 API 이름을 KernelEx용 DLL에 제공: 문자열 비교·매핑, CPU 그룹/NUMA 조회, 패키지 식별 조회, 날짜·시간·로캘 정보, 펌웨어/DEP 상태, 64비트 틱, 정밀 시각 호환 호출, 임계 구역·SRW 잠금·조건 변수·InitOnce 4종, 스레드풀 work·callback 12종, SList 7종, FLS·스레드·파이버 수명 관리 13종, 파일·프로세스 정보 조회, 앱 재시작 설정 조회 등. 함수마다 구현 범위와 게스트 검증 수준이 다릅니다.
- 별도 KernelEx USER32 라이브러리 `M98USER.DLL`에 클립보드 알림·형식 조회 API 3개를 추가했습니다. 설치된 Windows 98에서 정적 import를 포함한 시험 6개가 통과했습니다. 등록 창의 수명, 여러 변경 알림, 데이터 형식, 원래 클립보드 복구 범위와 남은 제약은 [클립보드 이식 기록](docs/CLIPBOARD_PORT.md)에 있습니다.
- 별도 KernelEx GDI32 라이브러리 `M98GDI.DLL`에 `GdiAlphaBlend`, `GdiTransparentBlt`, `GdiGradientFill` 세 별칭을 추가했습니다. 설치된 Windows 98의 KernelEx 보조 그래픽 DLL을 확인한 뒤 위임하며, 게스트 직접 호출과 콜드 부팅 후 정적 import의 각 14개 제한 계약 사례가 통과했습니다. [GDI 이식 기록](docs/GDI_ALPHA_PORT.md)에 백엔드 식별, 픽셀 시험, 미지원 범위를 기록했습니다.
- 개발 중인 별도 `M98CTLP.DLL`은 KernelEx에서 `COMCTL32` 서수 381(`LoadIconWithScaleDown`)과 345(`TaskDialogIndirect`)를 연결합니다. PNG가 들어 있는 아이콘 그룹의 제한된 직접 호출과 콜드 부팅 후 두 서수의 정적 import 시험이 설치된 Windows 98에서 통과했습니다. 345는 일부 일반 버튼만 지원하며, [COMCTL 이식 기록](docs/COMCTL_ORDINAL_PORT.md)과 [0.1.8 검증 기록](docs/RELEASE_0_1_8_CHECKPOINT.md)에 범위가 있습니다.
- Wine의 Unicode 대문자 매핑표와 문자열 비교 알고리즘, ReactOS의 임계 구역 인수 검사 로직을 선별 이식했습니다. 함수별 출처와 라이선스는 [THIRD_PARTY.md](THIRD_PARTY.md)에 있습니다.
- 호스트에서 32비트 DLL과 Windows 98 호환 시험 프로그램을 빌드하고 실행할 수 있습니다. 앱 로컬 `dbghelp.dll`, `dwmapi.dll`, `bcrypt.dll` 브리지도 포함합니다.
- KernelEx Shell API 라이브러리에 `SHCreateItemFromParsingName`, `SHParseDisplayName`, 일부 파일 선택 동작의 `SHOpenFolderAndSelectItems`를 구현했습니다. 세 함수의 정적 import 시험과 직접 호출 시험이 Windows 98 게스트를 통과했습니다.
- 테마 서비스가 없는 Windows 98용 UXTHEME API 브리지는 직접 호출 시험을 통과했습니다. KernelEx의 기존 UXTHEME 내보내기를 보존한 시험용 통합 DLL이 Notepad++의 정적 테마 import를 통과했습니다.
- [VxKex 소스 분석](docs/VXKEX_SOURCE_AUDIT.md)은 Windows 7의 IFEO/NT 로더 의존성과 Win98에서 다시 설계해야 할 지점을 기록합니다. 검사한 Git 트리의 재사용 허가가 확인되지 않아 VxKex 코드는 복사하지 않았습니다.
- [공개 KernelEx 개조판 조사](docs/PUBLIC_KERNELEX_VARIANTS.md)는 Kext/Kstub, Kex22 변경 사항, 원본 KernelEx, Wine·ReactOS 자료를 소스·라이선스·실제 구현 수준별로 구분하고 다음 API 작업에 반영합니다.

일부 API는 **부분 구현**입니다. `GetFileInformationByHandleEx`는 Basic/Standard 정보만 제공하며 변경 시각·실제 할당 크기를 추정하고 삭제 대기 상태를 알 수 없습니다. `GetTickCount64`는 DLL 로드 후의 32비트 틱 롤오버를 추적하지만, 49.7일 이상 켜진 시스템에 처음 로드될 때 이전 롤오버 횟수는 알 수 없습니다. `GetSystemTimePreciseAsFileTime`은 Windows 98의 시계 정밀도만 제공합니다. 자세한 상태는 [호환성 현황](docs/COMPATIBILITY.md)에 있습니다.

## 실험용 패치 다운로드

[0.1.7-preview 프리릴리스](https://github.com/NiSeullent/Win98-Modern/releases/tag/v0.1.7-preview)는 기존 Windows 98 SE 설치본에 적용할 DLL과 재빌드 가능한 소스를 제공합니다. 압축 파일 SHA-256은 `8ea6f1d092956d7c0f0f61a83965f5731ca9bbb891323d5ef8847e4f6e2043e4`입니다. [설치·복구 순서](release/INSTALL-ko.md)와 [이번 검증 범위](docs/RELEASE_0_1_7_CHECKPOINT.md)를 먼저 확인하세요. Windows 설치 이미지나 완성된 운영체제 prebuilt는 포함하지 않습니다.

다음 0.1.8 미리보기에는 COMCTL32 서수와 PNG 아이콘 처리를 넣어 시험 중입니다. 공개 ZIP의 최종 해시와 릴리스 링크는 패키징·독립 재빌드·배포 검증 후 기록합니다. 현재 0.1.7 다운로드에는 `M98CTLP.DLL`이 없습니다.

## 빌드와 시험

Windows 호스트의 32비트 LLVM MinGW(`i686-w64-mingw32-gcc`)와 Python이 필요합니다. 최초 한 번 `python -m pip install -r tests/requirements.txt`로 PE 검증 의존성을 설치합니다.

```powershell
.\build.ps1
cd build
.\smoke.exe
```

빌드 결과는 `build/m98wrap.dll`, `build/smoke.exe`, `build/import_probe.exe`, `build/memprobe.exe`, `build/memstress.exe`, `build/cpuapp.exe`와 `build/app-profiles.ini`입니다. DLL과 CPU 런처의 import는 Windows 98에 존재하는 `KERNEL32.DLL` 함수로 제한했습니다. 빌드 중 [PE98 정적 검사](tests/check_pe98.py)가 DLL의 32비트 형식, 로더 버전, 의존 DLL, 가져오기 함수, KernelEx 진입점을 확인합니다. `smoke.exe`는 API 테이블과 주요 동작을 검사하고, `import_probe.exe`는 최신 API 두 개를 KERNEL32에서 **정적으로 import**해 KernelEx 경로를 검사합니다. 두 시험은 직접 설치한 Windows 98 SE 게스트에서 각각 PASS를 확인했습니다. `memstress.exe`는 여러 프로세스의 페이지 읽기·쓰기를 측정하지만 [물리 RAM 4GB 인증 시험](memory/README.md)은 아닙니다. Windows 98 게스트에서의 실제 결과는 [VM 기록](vm/README.md)을 참조하세요.

추가 앱 로컬 DLL `build/dbghelp.dll`, `build/dwmapi.dll`, `build/bcrypt.dll`은 해당 앱의 폴더에서만 시험합니다. Windows 98 게스트에서 BCRYPT와 DWMAPI 직접 호출 시험을 통과했습니다. `build/m98shell.dll`의 세 Shell 함수도 게스트 직접 호출과 정적 import 시험을 통과했습니다. 시험용 UXTHEME KnownDLL의 시스템 글꼴 함수와 `GetTimeFormatEx`, `GetProductInfo`, `GetDateFormatEx`, `GetFinalPathNameByHandleW`, `FindFirstStreamW`, `GetLocaleInfoEx`, 재시작 관련 API 3개, `RegGetValueW`는 게스트 정적 import 시험을 통과했습니다. InitOnce 4종·스레드풀 work/callback 12종·SList 7종·NLS 2종·FLS/lifecycle 13종의 최신 정적 호출 시험과 MSVCRT 종료 콜백·89-entry 표본 시험도 가속 Win98 게스트에서 통과했습니다. 통합 회귀 시험 묶음 10개와 USER32 클립보드 시험 6개가 통과했습니다. GDI32 별칭 세 개도 게스트 정적 호출에서 14개 제한 사례를 통과했습니다. COMCTL32 최종 후보 `M98CTL3.DLL`을 연결한 Notepad++ 8.9.8은 앞선 `WM_CREATE` 충돌과 아이콘 501 경고를 넘어 12초 관찰 동안 편집 창을 표시했습니다. 같은 최종 후보에서 기존 텍스트 파일을 열어 수정하고 `Ctrl+S`로 저장한 뒤 게스트 파일을 다시 읽어 내용과 해시를 확인했습니다. 새 문서의 Save As 창은 열리지 않았고 닫을 때 잘못된 페이지 오류가 발생했습니다. 게스트 검사에서 저장 대화상자 COM 클래스가 등록되지 않아 `0x80040154`가 반환됐습니다. [0.1.8 검증 기록](docs/RELEASE_0_1_8_CHECKPOINT.md)과 [저장 창 조사](docs/NPP_SAVE_DIALOG_TRIAGE.md)에 범위와 남은 작업을 기록했습니다.

API 이식은 [전체 목록과 기능 묶음 작업 방식](docs/API_PORTING_CAMPAIGN.md)을 따릅니다. SDK 후보 151,330개를 모두 유지하고 Wine·ReactOS·One-Core·KernelEx 및 VxKex 참조 메타데이터를 함께 색인합니다. `porting/groups.json`의 공통 기반 의존성과 기능 묶음으로 작업을 배정합니다. 앱의 PE import와 실행 오류는 이 작업의 회귀 시험에 사용합니다. `unknown_or_native`는 Windows 98 기본 API일 수도 있으므로 미지원 판정이 아닙니다.

[원격 시험 도구](remote/README.md)는 COM1 기반 명령 실행, 검증 후 파일 교체,
명시적 시험 묶음과 GUI 창 진단을 제공합니다. 시험 VM의 16450 COM1 경로에서
전송 시험 3/3, 직접 API 시험 5/5가 통과했고 정상 종료 명령도 게스트에서
검증했습니다. 16550A 설정의 이전 부팅 오류 원인은 아직 확인되지 않았습니다.
현재 공개 다운로드의 안정성 증거와 개발 코드를 구분합니다.

## KernelEx 연결

[KernelEx 4.5.2](https://sourceforge.net/projects/kernelex/files/KernelEx/4.5.2/)를 Windows 98 게스트에 설치하기 전에 [Microsoft Layer for Unicode 1.1.3790.0](https://legacyupdate.net/download-center/download/4237/platform-software-development-kit-redistributable-microsoft-layer-for-unicode-on-windows-95-98-and-me-systems-1.1.3790.0)을 설치해 `C:\WINDOWS\SYSTEM\UNICOWS.DLL`을 준비합니다. 그런 다음 KernelEx를 설치하고 `m98wrap.dll`을 KernelEx 설치 폴더에 복사합니다. 같은 폴더의 `core.ini`에서 기본 설정의 `contents=std,kexbases,kexbasen`을 `contents=std,kexbases,kexbasen,m98wrap`으로 바꿉니다. 반드시 원본 `core.ini`를 백업하고 재부팅합니다. 호스트에서 설치본 설정을 편집할 때는 `tools/patch-core-ini.ps1 -InputPath ... -OutputPath ...`를 쓸 수 있습니다. 이 도구는 기존 인코딩과 줄바꿈을 보존하며, [인코딩 회귀 시험](tests/test_patch_core_ini.py)으로 확인했습니다. [integration/core.ini](integration/core.ini)는 제공된 KernelEx 소스의 설정을 바꾼 예시입니다. 설치본 설정이 다르면 통째로 덮어쓰지 말고 해당 줄만 수정하세요.

## 다음 범위

- 전체 API 후보와 공개 소스 선언 목록을 먼저 고정하고, 공통 기반과 API 기능 묶음을 이식한 뒤 실제 Win98 직접 호출·정적 import·앱 회귀 시험으로 검증합니다. 미구현·stub·별칭을 목록에서 빼거나 호환성 완료로 세지 않습니다.
- 새로 작성하는 [ShizukuDOS](shizukudos/)는 독립 부팅, FAT12 파일 읽기, 제한된 `.COM` 실행과 기본 DOS 인터럽트, 원래 하드디스크 부트 경로로의 체인로드를 가속 VM에서 검증했습니다. Windows 98의 `IO.SYS`를 대체해 GUI까지 부팅하는 기능은 아직 구현되지 않았습니다.
- 별도 [ShizukuDOS SMP 시험기](shizukudos/smp/README.md)는 BIOS/ACPI 환경의 2·4 CPU 가속 VM에서 보조 CPU 기동과 BSP·AP의 동시 계산, CPU별 결과 검증을 통과했습니다. 이는 독립 부팅 시험기의 병렬 작업이며, Windows 98 VMM의 멀티코어 스케줄러는 아직 구현되지 않았습니다.
- 새 [ShizukuFS v0](shizukufs/README.md)는 독립 블록 형식과 호스트의 생성·파일 왕복·무결성 검사를 제공합니다. 8GiB 희소 이미지의 4GiB 초과 오프셋 시험을 통과했지만 DOS/Win98 파일시스템 드라이버나 부팅 볼륨은 아직 아닙니다.
- [로컬 prebuilt 생성기](prebuilt/README.md)는 사용자의 설치된 VM을 독립 전체 복제하고 해시·가상화 설정을 검사합니다. Microsoft 파일이 들어 있는 VM 이미지는 공개 저장소나 릴리스에 배포하지 않습니다.
- [앱별 CPU 호환성 설계](cpu/)는 기종 프로필·시작 경로를 먼저 정의합니다. 명령어셋과 실행 속도를 앱별로 강제하려면 실제 명령어 중재/변환 계층이 추가로 필요합니다. Windows 98 GUI의 멀티코어 사용은 DOS만 바꿔서는 달성되지 않습니다.
- 새 완료 목표는 PAE를 통해 CSM 부팅 가능한 최신 시스템의 사용 가능한 물리 RAM 전체를 다루는 것입니다. 이는 처음 요청한 4 GiB를 포함하며, 32비트 주소 공간의 PCI/MMIO 구멍 위쪽 페이지까지 고려해야 합니다. 별도 [ShizukuDOS PAE 시험기](shizukudos/pae/README.md)는 5GiB 가속 VM에서 물리 주소 4GiB+4KiB의 읽기·쓰기·복구를 통과했습니다. 현재 Windows 98 메모리 관리자는 개조되지 않았고, `MaxPhysPage`로 인식량을 제한하는 설정은 이 목표를 달성하지 않습니다.
- Skylake급 CSM 환경의 AHCI/xHCI는 별도 Win9x 드라이버가 필요합니다. 현재 [drivers/](drivers/)에는 구현 계획과 안전한 레지스터 해석 코드가 있으며, 실제 드라이버는 아직 아닙니다. 시험 가능한 실기기 모델은 아직 제공되지 않아 하드웨어 지원 범위를 검증하지 못했습니다.
- [NVMe 기초 코드](drivers/nvme/README.md)는 PCI 장치와 컨트롤러 능력 레지스터를 읽는 호스트 모의 시험을 통과했습니다. 별도 BIOS 게스트에서도 VirtualBox 에뮬레이터의 BAR 길이를 호스트에서 검증한 뒤 `CAP`·`VS` 레지스터만 읽고, 현재 가속 로그를 확인했습니다. 명령 큐, DMA, 부팅, 설치용 블록 드라이버는 아직 없습니다. CSM NVMe 설치에는 별도의 BIOS 부팅 서비스 또는 부트 드라이버 경로가 필요합니다.

Microsoft ISO와 설치 키는 저장소에 포함하지 않습니다.

## 프로젝트 스킬

[win98-modern-lab](skills/win98-modern-lab/SKILL.md) 스킬은 API 이식, 실제 게스트 시험, ShizukuDOS·CPU·PAE·드라이버, 라이선스와 공개 절차를 하나의 재사용 가능한 작업 지침으로 담았습니다. 저장소의 `skills/win98-modern-lab` 폴더를 Codex 개인 스킬 폴더로 복사해 다른 작업에서도 사용할 수 있습니다. 이 PC에는 개인 스킬로도 설치했으며 두 사본 모두 형식 검사를 통과했습니다. 스킬 작성 자체는 기능 구현이나 앱 구동 증거가 아닙니다.

## 장기 호환성 목표

현재 완료 목표는 **Windows API 전체 표면의 100% 호환성**과 Chromium 150, Supermium, VLC, Notepad++, VS Code 필수 앱의 실제 구동입니다. 측정 기준과 앱별 검증 범위는 [대상 앱과 API 기준](docs/TARGET_APPS.md)에 기록합니다. 현재 KERNEL32 API 표에는 89개 항목이 있으나 모두의 완전한 의미 검증을 뜻하지는 않습니다. 날짜·시간·로캘·제품 정보 함수, 파일 핸들 경로 함수와 FAT32 스트림 오류 동작의 제한된 범위는 설치된 KernelEx 정적 import 및 직접 호출 게스트 시험을 통과했습니다. [고정 SDK 10.0.28000.2705 목록](docs/SDK_INVENTORY.md)은 후보 레코드 151,330건의 재현 가능한 집계이며, 중복·데스크톱 적용 범위를 판정하기 전이므로 최종 API 분모나 호환성 점수가 아닙니다. [PE 가져오기 측정 도구](docs/PE_IMPORT_COVERAGE.md)는 앱별 누락 API를 찾는 보조 지표입니다.
