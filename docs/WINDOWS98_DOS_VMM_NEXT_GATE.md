# ShizukuDOS → genuine Windows 98: 다음 구현 지점

초기 목표는 Windows 98에서 MS-DOS를 ShizukuDOS로 대체하는 것입니다. Kernel32·Kernel64·WDDMWrapper는 같은 기반의 구성요소입니다. 현재 `docs/SHIZUKUDOS_WINDOWS98_ARCHITECTURE.md`, `SHIZUKUOS_ARCHITECTURE_SUPPLEMENT.md`, `SHIZUKUOS_TARGET.md`와 README의 목표 설명은 이 의미를 유지합니다. DOS10 셸, CSM 자동 시작, 독립 K64 데스크톱/앱 증거는 구성요소 검증으로 남겨야 합니다.

| 연결 지점 | 현재 코드와 장애물 | 필요한 다음 작업 |
| --- | --- | --- |
| Supervisor의 실제 WIN98 peer | 기본 `supervisor/src/main.c`는 DOS16/K32/K64만 생성합니다. `src/kdom.c::ipc_channels_create`는 양쪽 peer가 살아야 channel 2를 매핑합니다. `kernel64/subsys64.c`는 WIN98 peer가 없으면 bridge idle입니다. | 이번 opt-in constructor/config 이식을 실제 소스 빌드 후 격리 게스트에서 시험합니다. Windows low memory `0x7000`을 보존하고 CHANNEL_INFO/VxD discovery가 실제 peer로 연결되는지 확인합니다. |
| Windows VMM endpoint | `ntwrapper/vxd/native.c`의 CPUID gate/VMCALL과 VMM MapPhys, `bridge.c::w64_open`의 ABI/channel/header gate, `ntwin32/win64/ntw64.c`의 DeviceIoControl 연결은 구현돼 있습니다. 최신 MODERN_APPS_CAMPAIGN의 nativeV9은 실제 load/query/reject50/query/close 2회·child/observer OS exit0의 수락된 **negative** 증거입니다. | 설치된 실제 Windows에서 채널 mapping과 ABI/header를 통과하는 positive OPEN, 왕복 RPC, 닫기, GUI와 앱 단계별 증거를 확보합니다. 과거 VxD loader 실패를 최신 결과처럼 쓰지 않습니다. |
| 원본 DOS 대조군 | `shizukudos/iosys_uefi/prepare.py`와 direct-iosys.patch는 명시된 원본 IO.SYS를 검사하고 원본 MSLOAD `0070:0208`로 들어갑니다. CSM Win98 시험도 원본 MBR/IO.SYS 경로입니다. | 이 경로는 genuine Windows 대조군으로 보존합니다. ShizukuDOS가 원본 DOS를 대체했다는 증거로 취급하지 않습니다. |
| ShizukuDOS → WIN.COM | 현재 `dos16/build.py::build_kernel`은 C/NASM WIN31SUPPORT를 켜지 않고 Windows용 WIN.COM 부팅 profile도 없습니다. | 사용자 소유 Windows 볼륨 사본에서 측정 가능한 별도 Windows profile과 실행 경로를 만듭니다. 원본 DOS 대조군과 startup/instance 요구를 비교한 뒤 기능 단위로 구현합니다. |
| INT2F / DOSMGR / resident-state | pinned upstream `kernel/inthndlr.c::int2F_12_handler`의 1605/1606/1607(DOSMGR), `hdr/win.h`, `kernel/kernel.asm`의 WinStartupInfo/patch/instance table이 다음 지점입니다. 현재 support query는 요청을 넓게 수락하면서 FIXME가 남아 있고 instance query 및 WinOLDAP MCB save/restore가 미완성입니다. `kernel/entry.asm`에는 crit-section crash 주석도 있습니다. | 원본 Windows 98 시작 과정에서 실제 요구하는 PSP/MCB/SDA/instance 계약을 추적합니다. 지원 응답은 구현하고 검증한 항목만 반환하며 Windows 전환/복귀/오류 경로를 구현합니다. 플래그 활성화만으로 완료를 주장하지 않습니다. |

이번 native-domain 소스 단계는 원본 DOS 대조군과 WIN98↔K64 연결의 준비입니다. MS-DOS 대체, genuine Windows UEFI GUI, GOP 기본 드라이버·가속, Chromium/Legcord/Office/Steam의 Windows 호스트 실행은 여전히 별도 acceptance gate입니다. 공개 소스/패치만 전달하며 사용자 디스크·OEM 파일·ROM·개인 validation 이미지는 전달하지 않습니다.
