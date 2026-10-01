# ShizukuDOS 10 — ShizukuOS 1.0.0 구성요소

ShizukuDOS는 **Windows 98을 위한 MS-DOS 대체 기반**입니다. Kernel32·Kernel64·WDDMWrapper도 이 Windows 98 통합을 위한 내장 구성요소입니다. 현재 DOS 부팅은 고정 FreeDOS ke2046·FreeCOM 소스와 기록된 패치를 사용하는 호환 부트스트랩입니다. Windows 98 GUI·커널 브리지 연결과 MS-DOS 전체 호환성이 완성됐다는 뜻은 아닙니다.

현행 이미지에서 ShizukuDOS 0.1을 폐지했습니다. ISO는 <https://m98.nyase.kr/>에서 배포하고 GitHub에는 공개 소스·패치만 둡니다. 최종 제품은 자체 설치 기능을 갖춘 **ShizukuOS 1.0.0**이며, 남은 요구사항을 검증하기 전에는 개발 상태로 표시합니다.

개발 데스크톱의 실제 유저랜드에는 Classic과 ShizukuOS 테마 선택을 제공합니다.
`F6` 또는 Theme 버튼으로 선택하며 설정은 데이터 디스크에 저장합니다.
이는 Windows 98 전체 유저랜드 테마 연결을 완료한 결과는 아닙니다.
[데스크톱과 테마 구현](win64/apps/shzdesk/README.md)에 동작과 검증 범위가 있습니다.

## 현재 DOS10 빌드

Linux 빌드 호스트의 Python 3, NASM, mtools와 Open Watcom 환경을 사용합니다. 필요한 공개 업스트림·도구는 기존 소스 빌더가 `build/`에 준비합니다. [다른 호스트 안내](../docs/CONTINUE_ON_ANOTHER_MACHINE.md)의 컴파일러·펌웨어 전제도 확인하세요.

```sh
python3 shizukudos/tools/shz.py build
# 명시적으로 선택해도 같은 정상 DOS10 경로입니다.
python3 shizukudos/tools/shz.py build --profile dos10
```

출력은 `build/shizukudos/dos16/shizukudos-dos10.img`입니다. 하나의 MBR/FAT16 이미지가 BIOS와 x64 UEFI → CSMWrap → SeaBIOS CSM16 경로를 제공합니다. UEFI 경로에는 Secure Boot 해제와 2개 이상의 논리 CPU가 필요합니다. 여기서 실제로 시작하는 것은 DOS 호환 셸이며 아직 Windows 98 GUI는 아닙니다.

`AUTOEXEC.BAT`은 `SHZSTART.BAT`을 자동 실행하고 **영구 COMMAND.COM 프롬프트**를 유지합니다. 정상 시작에 키 입력·PAUSE·EXIT가 필요하지 않습니다. 시작 파일이 없거나 실패하면 복구 프롬프트로 넘어가고, `SHZSAFE.TAG`로 다음 부팅부터 시작을 건너뛸 수 있습니다. 기존 F5/F8 우회·추적 기능과 `RECOVER.BAT`을 유지합니다. 실제 디스크 오류·매체 교체·치명적 오류의 입력 요구는 지우지 않습니다.

## 실제 부팅 검사

새 출력 디렉터리를 사용하며 기존 VM이나 원본 이미지에 쓰지 않습니다. 아래는 명령 예시이며 자기 호스트의 QEMU와 같은 세트의 OVMF CODE/VARS 경로를 지정하세요.

```sh
mkdir -p build/shizukudos/dos16/user-tests
python3 shizukudos/dos16/test_user_boot.py \
  --image build/shizukudos/dos16/shizukudos-dos10.img \
  --out build/shizukudos/dos16/user-tests/bios \
  --qemu /usr/bin/qemu-system-x86_64 --firmware bios --recovery
python3 shizukudos/dos16/test_user_boot.py \
  --image build/shizukudos/dos16/shizukudos-dos10.img \
  --out build/shizukudos/dos16/user-tests/uefi \
  --qemu /usr/bin/qemu-system-x86_64 --firmware uefi \
  --firmware-code /usr/share/OVMF/OVMF_CODE_4M.fd \
  --firmware-vars /usr/share/OVMF/OVMF_VARS_4M.fd
```

검사는 시작 전 키를 보내지 않고 정상 자동 실행, 실제 키보드 명령에 의한 파일 생성, 온디스크 내용, 콜드 부팅 후 재열기를 확인합니다. `--recovery`는 시작 파일 없음·비정상 종료·safe tag 세 복구 경로의 파일 생성도 검사합니다. QEMU TCG 결과는 하드웨어 가속 성공이 아닙니다. 실기기 USB 부팅·Windows 98 실행·8개 최신 앱·전체 MS-DOS 호환성은 별도 목표입니다.

Supervisor의 기본 `esp.img`에는 정상 DOS10 디스크가 들어갑니다. 기존 DOS·interkernel 검사는 명시적인 `esp-conformance.img`와 `shizukudos-dos16-{hd32,dual}.img`를 사용합니다. 이 검사 이미지는 시험 마지막에 `SHZEXIT.COM`으로 정지하므로 제품 부팅으로 사용하지 않습니다.

## 보존된 0.1 개발 자료

과거 설명 원문은 [README-pre-dos10.md](../docs/merge-history/20261001/dos10-entrypoints/README-pre-dos10.md)에 보존합니다. `boot.asm`·`stage2.asm`·FAT12 생성 함수와 과거 증거도 개발 기록입니다. `build_image.py`의 기본 실행은 DOS10을 빌드하며, 기존 0.1 입력은 명시적 `--historical-fixture`에서만 받습니다. PowerShell `build.ps1 -HistoricalFixture`도 같은 기록용 선택이며 현행 ISO에 포함하지 않습니다. 기존 VirtualBox 0.1 실행 스크립트를 현행 제품 시작 방법으로 사용하지 마세요.

FreeDOS·FreeCOM·CSMWrap·SeaBIOS의 정확한 소스 리비전, 적용 패치와 라이선스는 `upstream/manifest.json`, 빌드 영수증 및 동봉 소스·라이선스를 확인합니다. 외부 커널의 브랜딩만으로 native Shizuku 구현이나 Windows 98 DOS 교체가 입증되지는 않습니다.

## English

ShizukuDOS 10 is the intended MS-DOS replacement for Windows 98. Kernel32, Kernel64 and WDDMWrapper serve that same Windows 98 architecture. The current normal boot uses a pinned FreeDOS/FreeCOM compatibility bootstrap; the genuine Windows 98 GUI/kernel bridge is still in development.

On a Linux build host, run `python3 shizukudos/tools/shz.py build`. The default produces `shizukudos-dos10.img`, bootable through BIOS or x64 UEFI-CSMWrap with at least two logical CPUs. AUTOEXEC automatically calls SHZSTART and returns to a permanent DOS prompt; missing/nonzero startup or SHZSAFE.TAG selects recovery. F5/F8 and RECOVER remain available.

Use the bounded owned-copy tests above for keyboard-created file persistence and recovery. Their results do not establish hardware acceleration, physical USB support, complete DOS compatibility, native Windows 98 or eight-app completion. ISO distribution is exclusive to m98.nyase.kr; GitHub carries source and patches. Retired 0.1 developer inputs require an explicit historical-fixture flag and are absent from the current product medium.
