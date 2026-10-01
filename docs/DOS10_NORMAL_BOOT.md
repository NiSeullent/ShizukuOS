# ShizukuDOS 10 정상 자동 부팅

ShizukuOS 1.0.0의 ShizukuDOS는 Windows 98을 위한 MS-DOS 대체 기반입니다. Kernel32·Kernel64·WDDMWrapper도 같은 Windows 98 통합의 내장 구성요소입니다. 이 변경은 정상 DOS 셸이 자동으로 시작되도록 합니다. 현재 실행 커널·셸은 고정 FreeDOS ke2046·FreeCOM 소스와 기록된 패치를 사용하는 임시 호환 부트스트랩입니다. Windows 98 GUI 및 native 커널 브리지를 완성한 것으로 표시하지 않습니다.

## 멈춤의 원인과 변경

기존 `shizukudos-dos16-hd32.img`의 AUTOEXEC은 적합성 시험을 실행한 뒤 `SHZEXIT.COM 0`으로 끝납니다. 이 프로그램의 UART 완료 표시 뒤 HLT 루프는 시험 설계입니다. 제품 시작 화면으로 사용하면 셸에 돌아오지 않습니다. 기존 시험 이미지의 내용과 생성 함수는 보존했습니다.

새 `shizukudos-dos10.img`는 BIOS의 MBR → FAT16 → KERNEL.SYS와 UEFI x64의 CSMWrap → SeaBIOS CSM16 → 같은 MBR 경로를 갖습니다. 빈 AUTOEXEC 때문에 발생할 수 있는 날짜·시간 입력을 피하고, 실제 시작 파일을 실행한 뒤 `/P` 영구 COMMAND.COM을 유지합니다. 정상 시작에는 PAUSE·EXIT·사용자 키 입력이 필요하지 않습니다.

`SHZSTART.BAT`이 없거나 비정상 반환하면 복구 프롬프트가 열립니다. 루트의 `SHZSAFE.TAG`도 복구를 선택합니다. `RECOVER.BAT`과 기존 F5/F8 부팅 우회·추적 기능을 보존합니다. F5/F8의 짧은 선택 시간, 부팅 장치 선택 시간, 실제 매체 교체·치명적 디스크 오류에 대한 입력 요구는 제거하지 않았습니다. Supervisor의 부팅 메뉴도 제한 시간 뒤 정책에 따라 진행하는 기존 동작입니다.

`SHZREADY.COM`은 실제 DOS에서 실행되는 짧은 COM 프로그램입니다. UART에 시작·정상·복구·입력 확인 표시를 출력하고 INT 21h로 셸에 정상 반환합니다. 시험용 SHZEXIT의 정지 동작을 정상 부팅에 넣지 않습니다.

## 빌드와 이미지 선택

Linux에서 `python3 shizukudos/tools/shz.py build`의 기본 프로필은 `dos10`입니다. `shizukudos/build_image.py`도 기본 실행에서 같은 DOS10 빌더를 호출합니다. 과거 FAT12 0.1 생성 기능은 명시적 `--historical-fixture`, PowerShell에서는 `-HistoricalFixture`로만 접근하는 개발 자료입니다. 현행 설치 ISO에 0.1 파일·메뉴를 포함하지 않습니다.

| 용도 | 파일 | 영수증 키 |
| --- | --- | --- |
| 정상 BIOS/UEFI DOS10 | `build/shizukudos/dos16/shizukudos-dos10.img` | DOS16 `artifacts["dos10.img"]` |
| 정상 Supervisor 입력 | `build/shizukudos/supervisor/esp.img`의 `SHZDOS/DISK.IMG` | Supervisor `artifacts["disk.img (input)"]` |
| 기존 DOS·interkernel 적합성 시험 | `shizukudos-dos16-hd32.img`, `shizukudos-dos16-dual.img`, `esp-conformance.img` | `hd32.img`, `dual.img`, `conformance-disk.img (input)` |

DOS16 영수증의 `user_boot`는 프로필·정확한 생성 소스 해시·FAT 파일별 바이트 수와 SHA-256을 기록합니다. `user_boot.members["SHZREADY.COM"]`은 `shizukudos/dos16/user/ready.asm`의 조립 결과입니다. 제품 ISO 빌더는 정상 이미지의 영수증 키와 실제 ESP의 DISK.IMG 바이트를 함께 확인해야 합니다. 예전 `hd32.img`와 정상 ESP를 섞으면 검증이 실패하는 것이 맞습니다.

## 검사와 범위

`shizukudos/dos16/test_user_boot.py`는 새 출력 디렉터리에 원본 디스크와 OVMF VARS의 소유한 복사본만 만들고, 네트워크 없이 제한 시간 QEMU를 실행합니다. 시작 전에 키를 보내지 않습니다. READY 뒤 실제 PS/2 키 입력으로 파일을 작성하고 FAT에서 정확한 내용으로 읽은 다음, 두 번째 cold boot의 TYPE 출력으로 지속성을 확인합니다. `--recovery`는 시작 파일 없음·비정상 반환·safe tag 세 경우에서 복구 셸의 실제 파일 작성을 검사합니다.

UEFI 검사는 실제 OVMF → CSMWrap debug 경로의 순서와 guest BIOS 메모리의 CSM 테이블·proxy 서명도 확인합니다. 현재 harness는 Q35/AHCI·표준 VGA와 debug 출력을 제공하는 OVMF 구성을 사용합니다. 다른 펌웨어 로그나 하드웨어에서의 부팅은 별도 검증이 필요합니다. UEFI-CSMWrap에는 Secure Boot 해제와 두 개 이상의 논리 CPU가 필요합니다.

실행 예시는 `shizukudos/README.md`에 있습니다. QEMU TCG 검증은 하드웨어 가속 성공을 뜻하지 않습니다. 물리 USB, native ShizukuDOS의 완전한 MS-DOS 호환성, Windows 98의 실제 GUI/브리지, 8개 최신 앱·드라이버·가속은 계속 남은 구현·검증 목표입니다. 공개 ISO는 m98.nyase.kr 전용이고 GitHub에는 소스·패치를 둡니다. Microsoft 설치 매체나 키는 포함하지 않습니다.

## English

The normal DOS10 image automatically executes SHZSTART and keeps a permanent DOS prompt. Missing/nonzero startup or SHZSAFE.TAG selects recovery. Existing F5/F8 and RECOVER remain available; conformance disks intentionally ending in SHZEXIT stay explicit developer QA inputs.

This is the pinned FreeDOS/FreeCOM compatibility bootstrap for ShizukuDOS's intended role as the MS-DOS replacement for Windows 98. Kernel32, Kernel64 and WDDMWrapper belong to that Windows 98 architecture. BIOS and UEFI-CSMWrap component tests establish automatic shell startup and actual keyboard/file persistence, not complete DOS compatibility, physical USB support, acceleration or native Windows 98/eight-app completion. ISO distribution is exclusive to m98.nyase.kr; GitHub carries source and patches.
