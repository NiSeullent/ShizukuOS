# ShizukuDOS 10.0 — 상태 (STATUS)

`BASELINE.md`가 참조하는 문서. 증거 종류는 BASELINE과 같다:
`SOURCE` · `BUILT` · `HOST_TESTED` · `GUEST_RUN` · `HARDWARE` · `USER_REPORTED`.
"이번 세션"은 KVM이 없는 클라우드 컨테이너(Ubuntu 24.04, QEMU 8.2 TCG, mingw-w64 13, clang 18)에서 재현한 결과다.
원 개발 호스트(VMX·KVM 있음)의 결과를 이 문서가 대신 주장하지 않는다.

## 1. 이번 세션에서 직접 재현한 결과

| 항목 | 증거 | 결과 |
| --- | --- | --- |
| Win64 런타임 빌드(ntdll 70·kernel32 213 export, `-Werror`) | BUILT | PASS. 수정 전에는 링크 실패 (아래 2절) |
| 모든 import가 대상 DLL의 export에 존재 (t_hello→kernel32 13/ntdll 1, kernel32→ntdll 76) | BUILT (objdump 정적 점검) | 미해결 0 |
| PE32+ 파서 3,823,047 검사 + 15만 변이 퍼즈, ASan/UBSan | HOST_TESTED | PASS |
| 커널 간 ABI 모델 2,200,357 검사, ASan/UBSan/TSan, 독립 Python 디코드 | HOST_TESTED | PASS |
| Kernel32(ELF32)·Kernel64(ELF64) 빌드 | BUILT | PASS. 수정 전에는 Kernel64 링크 실패 |
| DOS16(FreeDOS ke2046 + FreeCOM) 재현 가능 빌드 | BUILT | PASS. 수정 전에는 이미지 해시가 매번 달랐음 |
| DOS16 레거시 BIOS 부팅(SeaBIOS, **TCG**) | GUEST_RUN | PASS (T_MODE/T_BIOS/T_COM/T_EXE, 종료코드 42) |
| `shz.py test --suite host` | — | VERIFIED (5 PASS) |
| `shz.py test --suite win98-regression` | HOST_TESTED / GUEST_RUN(TCG) | 19 PASS / 0 FAIL / 1 SKIP / 1 BLOCKED |
| 기존 UEFI x64 부팅, UEFI→32비트 PM 핸드오프 | GUEST_RUN (**TCG**) | PASS |
| NT 드라이버 호스트: 미수정 x64 `.sys` 3개 로드+DriverEntry, IRP/DPC/타이머/스레드, PCI(edu) BAR/IRQ(공유 INTx 체인)+`pci_claim ntdrv:shzpci`, 사용자 모드 NtLoadDriver→IOCTL (`run_k64_ntdrv.py`) | GUEST_RUN (**TCG**) | PASS 10/10 (provider export 185) |
| 드라이버 import 커버리지 (`import_coverage.py --ntoskrnl`) | HOST_TESTED | 시험 드라이버 3개 25/25; N2 ReactOS 코퍼스 23개 중 로드 가능 1개(null.sys), ntoskrnl 103/313 |

`win98-regression`의 BLOCKED는 설치된 Windows 98 체크포인트(`build/win98-lab`, 사용자 제공 자산) 부재,
SKIP은 Notepad++ (USER_REPORTED만 존재, 이 스위트는 게스트를 실행하지 않음)이다. Notepad++ 성공/실패를 이 문서는 단정하지 않는다.

### 1b. 실구동 스크린샷 (`docs/shizukudos10/screenshots/`, GUEST_RUN TCG)

`run_k64_gui.py --png`가 찍은 실제 QEMU screendump다. 각 장면은 호스트 계산값과 비교를 통과한 뒤에만 저장한다.
`k64-status.png`(T_GUI_STATUS): `C:\SHZ\SYS64`의 시스템 DLL **17개 전부**를 한 프로세스에서 `LoadLibraryW`로 올리고
DLL마다 첫 export를 `GetProcAddress`로 해석한다(러너가 패킹된 DLL 목록과 대조해 하나라도 빠지면 FAIL).
`RtlGetVersion` 10.0.22631, 물리 메모리, PCI 기능별 바인딩된 커널 드라이버(`gfx_fb`, `net_rtl8139`)도 같은 화면에 나온다.
이 화면을 만들며 고친 결함: `NtQueryDirectoryFile`의 FileName 오프셋이 커널 96·kernel32 92로 어긋나 `FindFirstFileW`가
아무 파일도 찾지 못했다(→ Windows 오프셋, 클래스 1/2/3/12/37/38). `GlobalMemoryStatusEx`가 쓰는 정보 클래스 0x100이 커널에
없어 물리 메모리가 0이었다. 아직 이 화면에 없는 것: Chromium·Electron, NT 커널 드라이버 호스트, Windows 98 본체.

## 2. 이번 세션에서 고친 결함 (원인 → 수정)

1. `RtlExitUserProcess`/`RtlExitUserThread`: `nt.h`에 `noreturn`이 이미 선언돼 있다. 생성 코드로 확인함
   (`NtTerminateProcess` 뒤에 `ret` 없이 `hlt; jmp`).
2. `ShzProcessHeap`: nt.h에서는 ntdll 내부 함수(비수출)로 선언, kernel32 두 파일은 같은 이름의 PEB 읽기 매크로로 덮어쓰고
   `k32_core.c`는 매크로 없이 호출해 **kernel32 링크가 실패**했다. `nt.h`의 PEB 기반 `static inline` 하나로 통일하고
   중복 매크로, ntdll의 함수 본체, 정의된 적 없는 `k32_process_heap` 선언을 제거했다.
3. `win64/build.py`의 K32API export 정규식이 아무것도 잡지 못해 `kernel32.def`에 forwarder 7개뿐이었다 → import 라이브러리가 비어
   t_hello 링크가 실패. 패턴을 분리해 214개 함수를 export한다.
4. mingw-w64 헤더가 `InterlockedIncrement`→`_InterlockedIncrement`로 치환해 실제 Win32 이름이 export되지 않았다 → 정의 앞에서 `#undef`.
5. `shzcrt.c`의 `-Werror=int-in-bool-context`.
6. `kbuild.py`가 Kernel64에 `win64/pe_parse.c`를 링크하지 않아 Kernel64 링크 실패 → `extra_c`로 링크.
7. `fatimg.py`: `mformat -v`가 볼륨 라벨 엔트리에 현재 시각을 기록해 DOS16 이미지가 재현되지 않았다 → `SOURCE_DATE_EPOCH` 고정.
8. Kernel64가 `fs_init()`도, `fs_load_archive()`도 호출하지 않아 WIN64.IMG(ntdll/kernel32/T_HELLO)가 **마운트되지 않았고**
   부팅 자체시험이 Win64 프로세스를 시작하지 않았다 → `kmain`에서 마운트, 자체시험이 `T_HELLO.EXE`를 두 번 실행(종료코드 7, 무결함,
   두 번째 실행이 모든 페이지를 반환). 증거 슬롯 19–23·30을 Supervisor 하니스(`check_win64`)가 호스트 쪽에서 검증한다.
   `t_hello`는 슬롯 16–18(ring-3 "high" 시험 사용)과 충돌하지 않게 19–21로 옮겼다.
9. 이식성: QEMU/OVMF 경로 탐색(Fedora·Debian/Ubuntu), `ntwin32/loader/evidence.py` 글꼴 대체.

## 2b. 통합 Shizuku SE ISO (`tools/build_shizuku_se_iso.py`, 시험: `shz.py test --suite iso`)

> **대체됨:** 이 절의 ISO 구성(BIOS 플로피 에뮬레이션 + UEFI 엔트리, USB 하이브리드 아님)과 `tools/test_shizuku_se_iso.py`는
> 2e절의 VM 설치 ISO와 부팅 매트릭스로 바뀌었다. 아래 표는 당시 기록으로만 남긴다.

한 ISO에 ShizukuDOS 0.1(자체 구현, BIOS 플로피 에뮬레이션), ShizukuDOS 10.0(외부 FreeDOS 프로필 + Supervisor + Kernel32/64 + WIN64.IMG,
UEFI El Torito), NTWrapper9x/NTWin32Wrapper9x/NTWDDMWrapper9x 산출물을 담는다. 두 프로필은 서로 다른 디렉터리로 분리 표기한다.
Microsoft 파일은 넣지 않는다. 사용자 소유 Windows 98 미디어는 `--win98-media`로 별도 `-private` ISO에만 겹쳐 넣고 `build/`(git 무시)에 둔다.

| 항목 | 증거 | 결과 (QEMU TCG, KVM 없음) |
| --- | --- | --- |
| El Torito 2엔트리(BIOS fd1.4 + UEFI 0xEF), 부팅 이미지 바이트 일치, EFI 이미지 FAT + `BOOTX64.EFI` | GUEST_RUN/HOST_TESTED | PASS 6 |
| BIOS(SeaBIOS)로 ISO 부팅 → `A:\>` 프롬프트, `DIR`에 NTW32.DLL/NTWRAP9X.VXD/NTWGPROB.EXE | GUEST_RUN | PASS 4 |
| UEFI(OVMF)로 ISO 부팅 → Supervisor 로더 시작, VMX 없음을 보고하고 펌웨어로 복귀 | GUEST_RUN | PASS 3 (**멀티커널 부팅이 아니라 VMX 불가 경로**) |
| Supervisor 위의 DOS16/Kernel32/Kernel64/Win64 도메인 | — | BLOCKED (Intel VMX 필요) |
| Windows 98 설치 완료 | — | **BLOCKED, 검증되지 않음** (미디어 없음). `INSTALL.BAT`은 실행하지 못했다 |

전체: 14 PASS / 0 FAIL / 5 BLOCKED → INCOMPLETE. ISO는 CD/DVD 전용(USB 하이브리드 아님). `--win98-media` 경로는 표식된 합성 자리표시 파일로
코드 경로만 시험했으며 Windows가 설치된다는 증거가 아니다.

## 2c. 한 디스크로 레거시 BIOS와 UEFI 부팅: CSMWrap (`shizukudos/csm`, 외부 재사용 프로필)

FreeDOS 같은 IO.SYS급 DOS 커널은 PC BIOS 인터럽트 서비스를 쓴다. UEFI 전용(class 3) 기계에서는 이것을 외부 프로젝트
**[CSMWrap](https://github.com/CSMWrap/CSMWrap)**(LGPL-2.1)이 제공한다. 이 부분은 독자 구현이 아니다. CSMWrap은 UEFI 앱으로 실행되어
PAM으로 E0000h–FFFFFh 쓰기 잠금을 풀고, **SeaBIOS CSM 빌드**(CSMWrap/seabios-csmwrap, LGPL-3.0)를 E0000h에 둔다. 그리고
UEFI 메모리 맵을 E820으로 바꾸고, ACPI/SMBIOS/MP/$PIR 표를 준비하고, VGA OpROM(없으면 SeaVGABIOS)을 실행한다. 이어서
`ExitBootServices` 뒤 Legacy16 호출(InitializeYourself → DispatchOprom → UpdateBbs → PrepareToBoot → Boot)로 **자신을 읽어 온
디스크의 MBR**을 레거시 방식으로 부팅한다. SMM을 쓸 수 없으므로 AP 하나를 "system thread"(BIOS 프록시)로 예약하고 MADT/MP 표에서
숨긴다. BIOS 프록시는 V86 모드(EMM386 등)에서 온 BIOS 호출과 UEFI ResetSystem 콜백을 처리한다. 그래서 **논리 CPU가 2개 이상**이어야 한다.
1 vCPU로 실행하면 `No AP available for BIOS proxy`와 PANIC으로 멈춘다(아래 음성 시험으로 확인). 2 vCPU이면 DOS는 CPU 1개를 본다.

- 고정: `shizukudos/upstream/manifest.json`의 `csmwrap` 7f30b740 항목과 서브모듈 7개를 고정했다. 서브모듈과 라이선스는
  seabios 578d260b(LGPL-3.0), picoefi af14129e(BSD-2/BSD-2-Patent/BSD-3/MIT), uACPI 338dc389(MIT), flanterm dfa1922c(BSD-2),
  nanoprintf 526cbca5(Unlicense OR 0BSD), cc-runtime dae79833(Apache-2.0 WITH LLVM-exception), freestnd-c-hdrs 097259a8(0BSD)이다.
  `shzlib.ensure_upstream`은 가져오기 전에 상위 커밋에 기록된 서브모듈 커밋(gitlink)과 `.gitmodules` URL을 매니페스트와 대조한다.
  `shz.py package`는 서브모듈을 포함한 원본 트리를 `upstream-source/csmwrap-7f30b740c352.tar.gz`로 넣는다. 이것이 LGPL 소스 제공이다.
- 빌드(`shizukudos/csm/build.py`)는 `.git`이 없는 복사본에서 `make -j4 ARCH=x86_64 BUILD_VERSION=3.1.2-25-g7f30b74 all`로 한다.
  SeaBIOS `.version`=`578d260b`로 두어 버전이 `578d260b-CSMWrap-3.1.2-25-g7f30b74`로 고정되고, `git describe` 표류나
  빌드 시각·호스트명이 붙지 않는다. **로컬 패치는 없다.** 원본 트리가 그대로 빌드되고, 재현성은 make 변수와 `.version` 파일만으로 얻었다.
- 산출물 sha256: `CSMWRAP.EFI` ba791a92…6907(466,944 B), `Csm16.bin` 59f55daf…fab1, `vgabios.bin` 897da3a0…ff30.
  `shizukudos-dos16-dual.img`는 90b3246a…b07e이고 두 번 빌드해도 같다. `hd32.img`는 dcfbdccb…a3af로 **변경 전과 바이트 단위로 같다**.
- `dual.img`: hd32와 같은 MBR, FAT16(LBA 63), FreeDOS 부트섹터·커널·FreeCOM에 `T_INTS.COM`(AUTOEXEC에서 T_BIOS 다음)을 더했다.
  여기에 `\EFI\BOOT\BOOTX64.EFI`(=CSMWrap)와 `\EFI\BOOT\csmwrap.ini`(`serial=true`, COM1 115200)를 넣었다.

| 항목 | 증거 | 결과 (QEMU 8.2.2 **TCG**, KVM 없음) |
| --- | --- | --- |
| `shz.py test --suite host` (CSMWrap·hd32·dual 각 2회 빌드 동일, 서브모듈 핀) | BUILT | VERIFIED 8 PASS |
| dual.img를 **레거시 BIOS**로 부팅(QEMU SeaBIOS 1.16.3, q35, AHCI, 256 MiB, 2 vCPU): `dos16/test_csm.py --image dual …` | GUEST_RUN | PASS (검사 54개). `-machine pc`(i440FX, IDE, 64 MiB, 1 vCPU)에서도 PASS |
| 같은 dual.img를 **UEFI**로 부팅(OVMF 2024.02, CSM 없음) → CSMWrap → SeaBIOS CSM16 → 같은 MBR → FreeDOS, 같은 하드웨어: `csm/test_qemu.py` | GUEST_RUN | PASS (검사 72개, SHZ-EXIT까지 9–17초, 호스트 부하에 따라) |
| 두 경로의 DOS16 결과(T_MODE/T_BIOS/T_COM/T_EXE, 종료코드 42)와 host 검사 판정 | GUEST_RUN | 동일. RESULT.TXT 차이는 T_BIOS `EXT`(=INT 15h 88h, 아래 표)뿐 |
| 1 vCPU UEFI 부팅(음성) | GUEST_RUN | CSMWrap이 `No AP available for BIOS proxy`로 중단하고 DOS는 시작되지 않음 |

UEFI 경로를 실제로 탔다는 증거(`build/shizukudos/csm/run-uefi-csmwrap/result.json`)는 다음과 같다.
- QEMU 인자: OVMF CODE는 읽기 전용 pflash이고 VARS는 실행마다 새 사본이며 `-bios`는 없다.
- 4 GiB 바로 아래 256 KiB를 QMP로 덤프하면 OVMF_CODE_4M.fd의 끝부분과 **바이트 단위로 같다**. 그 안에 SeaBIOS 문자열은 없다.
  레거시 실행에서는 같은 영역이 `bios-256k.bin`과 같다.
- 직렬 로그에 다음이 이 순서로 나온다. OVMF `BdsDxe: starting Boot0001 … Sata(…)`, CSMWrap의 `serial = true`(ini 읽음), `Unlock!`,
  `csm_bin_base: 0xe0000`, `BIOS proxy ready (AP 1)`, `Boot device: PCI 00:1f.2 type=HDD`, `csmwrap e820 map has 22 items`, 그리고 DOS의 `SHZ-EXIT:0`.
- 런타임 E/F 세그먼트에 CSM 전용 서명 `IFE$`(EFI_COMPATIBILITY16_TABLE)와 `CSMPPrxy`(BIOS 프록시 메일박스)가 Csm16.bin과 같은 오프셋에 있다.
  F 세그먼트는 Csm16.bin과 93.7% 같고 QEMU SeaBIOS와는 11.7%만 같다. 레거시 경로는 반대로 CSM 서명이 없고 QEMU SeaBIOS와 96.4% 같다.
- 화면 첫 줄이 `SeaBIOS (version 578d260b-CSMWrap-3.1.2-25-g7f30b74)`다. 레거시 경로에서는 `1.16.3-debian-1.16.3-2`다.
- DOS가 본 E820은 CSMWrap이 UEFI 메모리 맵에서 만든 표와 같다. SeaBIOS는 자기 high PMM 영역 안에서만 RAM과 reserved를 옮긴다.
  ACPI/NVS 구간은 모두 그대로이고 덮는 바이트 수도 같다.

### T_INTS: BIOS 인터럽트 커버리지 (`dos16/tests/t_ints.asm` → `INTS.TXT`, 호스트 검사 `dos16/ints.py`)

T_INTS는 BIOS 호출을 모두 먼저 끝낸 뒤에 INT 21h를 쓴다. 그래서 DOS의 ^C 검사가 INT 16h 시험 키를 가져가지 못한다. 결과는 원시
레지스터 값으로 남기고, 호스트가 명세와 디스크 바이트로 검증한다. INT 13h 쓰기는 MBR과 첫 파티션 사이의 빈 LBA 2(CHS 03h)와
LBA 3(LBA 43h)에만 한다. 호스트가 실행 후 디스크에서 그 바이트를 직접 확인하고, LBA 0/1/4/63은 바뀌지 않았는지 확인한다.
FreeDOS 사용처는 고정된 ke2046 트리를 grep해 얻었다(`ints.FREEDOS_USE`).

| 서비스 | FreeDOS ke2046이 부르는 곳 | 기준 명세 | 레거시 ↔ UEFI+CSMWrap |
| --- | --- | --- | --- |
| INT 11h, 12h (+BDA 410h/413h/40Eh) | main.c, initdisk.c / kernel.asm, initoem.c | IBM PC/AT TR, RBIL | 일치 (4226h, 639 KiB, EBDA 9FC0h) |
| INT 13h 00h/02h/03h/08h/15h/41h/42h/43h/48h | initdisk.c, dsk.c→floppy.asm, 부트섹터(41h/42h/02h) | RBIL, Phoenix EDD 1.1/3.0 | 모두 일치 (EDD 3.0, 64/16/63, 65520섹터, 48h는 AHCI에서 1Ah바이트) |
| INT 15h E820h(24·20바이트 요청, 연속 호출) | 부르지 않음(XMS 드라이버가 씀) | ACPI 6.x §15 | **다름(설명됨)**: 레거시 9항목(fw_cfg) vs CSM 24항목(UEFI 맵 변환). 양쪽 다 ECX=20, 중첩 없음, 0–9FC00h RAM = INT 12h |
| INT 15h E801h, 88h | 부르지 않음 | RBIL | **다름(설명됨)**: 레거시 3C00h/0EFDh·FC00h vs CSM 1C00h/0·1C00h. 각 경로의 E820에서 1 MiB부터 연속 RAM으로 계산한 값과 일치. OVMF가 800000h–808000h를 ACPI NVS로 두어 CSM 쪽은 7 MiB |
| INT 15h C0h, 2400h–2403h | 부르지 않음(A20은 XMS 경유) | IBM PS/2 BIOS TR, RBIL | 일치 (F000:E6F5 model FC; A20 끄기→FFFF:0500 겹침, 켜기→해제) |
| INT 16h 00h/01h/10h/11h (05h로 넣은 키), 02h/12h | console.asm(BDA 496h bit4면 10h/11h) / 02h·12h는 BDA 417h 직접 읽음 | RBIL | 일치 (차단 없음) |
| INT 1Ah 00h/02h/04h | rdpcclk.asm / initclk.c | RBIL | 값은 시각이라 다름. 양쪽 다 BCD 유효, 틱과 RTC 차이 < 1초, 날짜 = 호스트 UTC 날짜 |
| INT 10h 0Eh/0Fh/03h, 12h BL=10h, 1A00h, 4F00h/4F01h | 0Eh/0Fh만 사용 | RBIL, VBE 3.0 | 일치. 예외는 커서 행(CSM SeaBIOS의 `Press ESC for boot menu.` 3줄)과 VBE 선형 프레임버퍼 주소(FD000000h vs 80000000h, PCI BAR를 SeaBIOS와 OVMF가 각각 배정) |

비교 결과는 39개 일치, 10개 설명된 차이, 0개 설명되지 않은 차이다(`run-uefi-csmwrap/ints-compare.txt`).
두 실행은 같은 이미지, q35, AHCI, 256 MiB, 2 vCPU, TCG를 썼고 펌웨어만 다르다. 하니스는 이 조건도 검사한다.

한계(검증하지 않은 것 포함)는 다음과 같다.
- **TCG만** 실행했다. KVM과 실제 UEFI class 3 PC에서는 실행하지 않았다.
- **VMX/Supervisor와는 무관하다.** CSMWrap은 가상화가 아니라 펌웨어 층이다. DOS는 CPU에서 진짜 Real Mode로 돈다(T_MODE CR0.PE=0,
  QMP 레지스터로 독립 확인).
- **SeaVGABIOS 한계**: 이 실행에서 CSMWrap은 QEMU stdvga 카드의 자체 OpROM을 썼다(`Video Initialisation Succeed with OpROM`).
  그래서 INT 10h 결과가 레거시와 같다. VGA OpROM이 없는 GPU에서는 SeaVGABIOS(프레임버퍼 위 텍스트 에뮬레이션)로 대체되는데,
  업스트림 README에 따르면 VGA 레지스터를 직접 다루는 DOS 프로그램(대부분의 게임, EDIT 등)은 제대로 동작하지 않는다. 그 경로는 실행하지 않았다.
- E801h/88h만 보는 XMS 드라이버는 OVMF 위에서 확장 메모리를 7 MiB만 본다. HIMEMX처럼 E820을 먼저 쓰는 드라이버는 해당하지 않는다.
- CSM SeaBIOS는 부팅 메뉴 프롬프트 때문에 약 2.5초를 기다린다.
- Secure Boot는 꺼져 있어야 한다(CSMWrap은 서명되지 않았다. 시험한 OVMF_CODE_4M.fd는 non-secboot 변형).
- CPU 1개는 OS에서 숨겨진다. 논리 CPU가 1개인 기계는 지원하지 않는다.
- 기본값 `iommu_disable=true`로 IOMMU를 끈다.

재현 명령은 다음과 같다. `python3 shizukudos/csm/build.py`, `python3 shizukudos/dos16/build.py`, `python3 shizukudos/csm/test_qemu.py`
(`--accel auto`가 기본이고 legacy 비교와 1 vCPU 음성 시험을 포함한다). 또는 `shz.py build --profile dual-bios-uefi-csm`과
`shz.py test --suite boot`를 쓴다(두 항목이 추가되었다).

## 2d. UEFI 부트 매니저: BOOT.INI 정책, CSMWrap 대체, Kernel64 직접 부팅 (uefi-bootmgr, `shizukudos/supervisor/loader`)

`\EFI\BOOT\BOOTX64.EFI`(Supervisor 로더, `supervisor/build.py`)가 이제 부트 매니저 역할도 한다. 정책 파일은 `\EFI\SHIZUKU\BOOT.INI`이고
엄격 파서(`loader/bootini.c`, libc 없음, 호스트에서 ASan/UBSan으로 시험)를 쓴다. 문법은 `key = value` 한 줄에 하나, `;`/`#` 주석 줄,
LF/CRLF, 최대 4096바이트, 줄당 255자다. 모르는 키, 중복 키, 섹션, 인라인 주석, 제어·비ASCII 바이트, 잘못된 값이 있으면 **파일 전체를
거부**하고 줄 번호와 이유를 출력한 뒤 아무것도 시작하지 않고 펌웨어로 돌아간다. 파일이 없으면 내장 정책(`mode=auto`)을 쓴다.

| 키 | 값 | 동작 |
| --- | --- | --- |
| `mode` | `auto`(기본) | Intel VMX 백엔드를 쓸 수 있으면 Supervisor. 아니면 `auto_kernel64=yes`이고 `\SHZDOS\KERNEL64S.BIN`이 있을 때 Kernel64 직접 부팅(ExitBootServices 전에 거부되면 CSM으로 넘어감). 그 밖에는 CSM |
| | `supervisor` | Supervisor만. VMX가 없으면 이유를 출력하고 펌웨어로 복귀 |
| | `csm` | 항상 CSM: 같은 볼륨의 CSMWrap을 `LoadImage`/`StartImage`(ExitBootServices 전). 파일 없음·이미지 아님·Secure Boot 거부·CPU 1개는 각각 이유를 출력하고 복귀 |
| | `kernel64` | 독립 실행형 Long Mode Kernel64를 **VMX 없이** 직접 부팅 |
| `csm_path` | `\EFI\SHIZUKU\CSMWRAP.EFI`(기본) | 절대 FAT 경로만(`/`, `.`/`..`, 와일드카드, 드라이브 문자 거부) |
| `auto_kernel64` | `yes` / `no`(기본) | 위 `auto` 설명 참고 |
| `menu_timeout` | `0`(기본, 메뉴 없음) – `30` | 초. 콘솔(OVMF는 COM1에도)에 한 글자 메뉴를 띄운다: A/Enter = 위 정책, K = Kernel64 직접, C = CSM, S = Supervisor. 키가 없으면 정책대로 간다(C3, 커밋 d4b8ce9) |

`\SHZDOS\KERNEL64.INI`(선택)는 같은 문법에 `cmdline = <출력 가능 ASCII>` 키 하나만 받는다. 값은 잘라내지 않는다(너무 길면 거부).

**Kernel64 직접 부팅(`mode=kernel64`).** `kernel64/standalone/boot32.c`(Multiboot 스텁)가 하는 일을 UEFI에서 한다.
`\SHZDOS\KERNEL64S.BIN`(`kbuild.py`의 `-DSHZ_STANDALONE` 빌드, 하이퍼콜을 커널 안에서 COM1/PIT/RTC로 처리)을 물리 1 MiB에,
`\SHZDOS\WIN64.IMG`를 32 MiB에 읽는다. 0x1000–0x4FFF에 부트 페이지 표(항등 + 상위 절반, 2 MiB 페이지), 0x7000에 부트 정보를 둔다.
이 고정 범위는 쓰기 전에 모두 `AllocatePages(AllocateAddress)`로 확보한다. 그래서 펌웨어가 그곳에 살아 있는 것(로더, 스택, 펌웨어
페이지 표)이 없음을 보장한다. `ram_size`와 펌웨어 구멍은 Multiboot 스텁과 **같은 계획**(`kernel64/standalone/memholes.h`, C3, 커밋 d4b8ce9)으로 정한다.
ExitBootServices 뒤 쓸 수 있는 메모리(Loader/BootServices Code·Data, Conventional, WB)에서 부트 페이지, 커널 창 [1, 3) MiB, initrd는
반드시 RAM이어야 한다. 힙 창 [3, 15) MiB 안의 구멍은 힙에서 울타리로 막고(8 MiB 이상 남아야 함), 그 위의 구멍은 페이지 할당기에서 뺀다.
구멍 목록은 0x6000에 넘긴다. RAM 끝은 256 MiB 한도 아래에서 쓸 수 있는 가장 높은 주소(2 MiB 단위, 맨 위 페이지가 RAM)다. 부팅 전에 GetMemoryMap으로 계획하고, `uefi/boot.c`의 재시도(맵 키가 바뀌면 다시 읽음)로 ExitBootServices를 한 뒤
**최종 맵으로 다시 계산**한다. 그다음 0x5000에 복사한 트램펄린이 CR3/GDT를 바꾸고 CR4=PAE로 맞춘 뒤 RDI=0x7000으로
0xFFFFFFFF80100000에 진입한다. ExitBootServices 전의 거부 사유는 5단계 페이징(LA57), 파일 없음·크기, KERNEL64.INI 오류, RAM 부족
(이때 가장 큰 사용 가능 구간도 출력), 고정 범위를 펌웨어가 점유(점유한 descriptor 출력), Supervisor용 `KERNEL64.BIN`을 잘못 둔 경우다.
모두 펌웨어로 돌아간다.

**OVMF와 S3.** OVMF는 S3가 켜져 있으면(QEMU 기본) SEC/PEI 임시 RAM(0x800000부터)을 `EfiACPIMemoryNVS`로 예약한다. Kernel64는 이
구간을 덮지 않는다. 처음 구현은 1 MiB부터의 연속 구간이 8 MiB에서 끝나서 **거부**했다. C3(커밋 d4b8ce9)부터는 이 NVS가 힙 창 안의 구멍
3개(0x800000+0x8000, 0x80b000+0x1000, 0x810000+0xf0000, 996 KiB)가 되어 힙에서 울타리로 막히고 Kernel64가 그대로 뜬다(`kernel64-s3`).
S3를 끄면 이 구멍은 없고, 맨 위 `EfiRuntimeServicesData` 두 곳만 페이지 할당기에서 빠진다(RAM 236 → 254 MiB).

**ABI 1.1(`abi/shz_abi.h`, `SHZ_ABI_MINOR` 0→1).** `shz_bootinfo_t` **끝에만** 추가했다(1.0 접두부 176바이트는 그대로, 새 크기 472).
추가 필드는 `fb_base, fb_size, fb_width, fb_height, fb_pitch(바이트), fb_format(SHZ_FB_RGBX8888/BGRX8888), fb_bpp, cmdline_size,
cmdline[256]`이고 플래그 `SHZ_BIF_UEFI_DIRECT`를 더했다. 읽는 쪽은 `SHZ_BOOTINFO_HAS(bi, field)`로 작성자의 `size`를 확인한다.
- Supervisor(`kdom.c`)는 같은 구조체를 0으로 채워 쓴다.
- `boot32.c`는 Multiboot 명령줄을 그대로 복사한다(QEMU/GRUB은 이미지 경로를 앞에 붙인다).
- Kernel64 `main.c`는 작성자의 `size`만큼만 복사하고, 명령줄과 GOP 프레임버퍼를 로그로 남긴다.
- 창 관리자 GOP 백엔드용 **훅**은 `k64_boot_framebuffer()`(`kernel64/k64.h`)다. `gfx_fb.c`가 부를 수 있으며 아직 호출자는 없다.
  Bochs VBE 경로는 바뀌지 않았다. 프레임버퍼는 direct map 밖에 있으므로 `mmio_map()`으로 매핑해야 한다.

| 항목 (`supervisor/test_bootmgr.py`, QEMU 8.2.2 **TCG**, OVMF 2024.02 실행마다 VARS 사본, 256 MiB) | 증거 | 결과 |
| --- | --- | --- |
| BOOT.INI/KERNEL64.INI 파서 호스트 시험 65건(ASan/UBSan). C3 뒤 78건(`menu_timeout` 13건 추가) | HOST | PASS |
| `auto`: Intel(VMX 없음), BOOT.INI 없음 → CSMWrap → SeaBIOS CSM16 → FreeDOS, 실행 후 디스크를 `dos16/verify.py`로 검증 | GUEST_RUN | PASS ×2 (최종 실행 2회) |
| `csm`(AMD, CRLF·주석·대소문자 혼합 BOOT.INI), `legacy`(같은 MBR 디스크를 SeaBIOS 레거시로) | GUEST_RUN | PASS ×2 (최종 실행 2회) |
| `supervisor`(VMX 없음 → 거부·복귀), `missing`/`missing-default`(CSMWrap 없음), `malformed-key`/`malformed-mode`, `not-an-image`, `one-cpu` | GUEST_RUN (OVMF `BdsDxe: failed to start … <상태>`로 복귀 확인) | PASS ×2 |
| `kernel64`: BOOT.INI `mode=kernel64` + KERNEL64.INI, S3 끔 → Kernel64 직접 실행. `tests/run_k64_standalone.py`의 파서·판정 그대로 + WIN64.IMG 영수증의 T_*.EXE 30개 모두 exit 0 + 로더가 최종 맵으로 계산한 RAM = 커널이 본 RAM + ABI 1.1(472바이트, UEFI-direct 플래그) + cmdline 그대로 + GOP 모드 양쪽 일치 | GUEST_RUN | PASS ×2 (최종 실행 2회) |
| `auto-kernel64`: `auto_kernel64=yes`, VMX 없음 → 같은 Kernel64 실행 | GUEST_RUN | PASS ×2 (최종 실행 2회) |
| `auto-k64-fallback`: S3 켬 → NVS 때문에 Kernel64 거부(ExitBootServices 전) → CSM → FreeDOS 검증. **C3 뒤:** NVS는 더 이상 거부 사유가 아니므로 Supervisor용 `KERNEL64.BIN`을 `KERNEL64S.BIN` 자리에 두어 거부시킨다 | GUEST_RUN | PASS ×2 (최종 실행 2회), C3 뒤 PASS |
| `kernel64-nvs` / `-missing` / `-wrong-image` / `-bad-ini`: 거부 후 펌웨어 복귀(Out of Resources / Not Found / Load Error / Invalid Parameter). **C3 뒤:** `kernel64-nvs`는 `kernel64-s3`(S3 켬, Kernel64 실행, 구멍 5개 중 NVS 3개는 힙에서 996 KiB 울타리, 로더와 커널의 구멍 수 일치)로 바뀌었다 | GUEST_RUN | PASS ×2 (최종 실행 2회), C3 뒤 PASS |
| `menu-timeout`(C3): `menu_timeout=1`, 키 없음 → 정책 `auto` → CSM → FreeDOS 검증. 키 K로 고르는 경로는 `tools/test_shizuku_se_boot_matrix.py`의 `k64direct`가 COM1로 입력해 시험한다 | GUEST_RUN | PASS |
| vBIOS 감사(`docs/shizukudos10/VBIOS_INT_AUDIT.md`)와 `supervisor/test_vbios.py`(ROM을 QEMU `-bios`로 + `bios.c` 호스트) | HOST + TCG | 53/53 PASS. Supervisor 안의 실행은 **BLOCKED**(VMX 없음) |

최종 상태(커밋 뒤 코드 변경 없음)로 두 번 실행했다.
1. `shz.py test --suite boot`(세션 `build/shizukudos/bootmgr/runs/20260929T173252-t98y7b6t`): 부트 매니저 17개 사례와 파서가 모두 PASS(검사 290개).
   같은 스위트에서 vBIOS 53/53, Kernel32·Kernel64 Multiboot 독립 실행(바뀐 `boot32.c` 포함)도 PASS였다. 스위트 전체는
   25 PASS / 1 FAIL / 3 BLOCKED이다. FAIL 1건은 `DOS16 … [KVM]`으로, `/dev/kvm`이 없어서 생긴 기존 항목이다.
2. `supervisor/test_bootmgr.py` 단독 실행(세션 `…/runs/20260929T173949-s_2g6s1l`): 17/17 PASS, 파서 65/65 PASS.
   Kernel64 직접 부팅은 호스트 부하에 따라 SHZ-EXIT까지 39–67초 걸렸다.

이보다 앞선 개발 중 실행 한 번에서는 `auto-kernel64`가 `T_NET_LOOP.EXE` 때문에 FAIL이었다(아래 불안정한 시험 항목).
T_NET_LOOP은 부트 경로와 무관하다.
3. C3 변경 뒤(커밋 ab0b616, 세션 `…/runs/20260929T214222-2l0hbqxe`): 18/18 PASS, 파서 78/78 PASS. 그 전의 C3 개발 중 전체 실행
   (d4b8ce9 직전)은 17/18이었다. `kernel64`(S3 끔)에서 `T_NET_LOOP.EXE`의 "no physical page leak across 2 socket rounds"(57907 → 57898)가
   실패했고, 같은 사례를 두 번 더 돌린 결과는 PASS였다(아래 불안정한 시험 항목).

한계와 BLOCKED 항목은 다음과 같다.
- **VMX 경로는 실행하지 않았다.** `mode=auto`에서 VMX가 있을 때 Supervisor를 고르는 분기와 `mode=supervisor` 성공 경로는 이 컨테이너에서
  BLOCKED다(`/dev/kvm` 없음). TCG만 썼고 KVM과 실제 PC에서는 실행하지 않았다. Secure Boot는 꺼져 있어야 한다(로더와 CSMWrap 모두 서명 없음).
- Kernel64 직접 부팅은 부트 페이지·커널 창 [1, 3) MiB·initrd가 RAM이고, 힙 창에 8 MiB 이상, 전체 64 MiB 이상이 있어야 한다(위 설명).
  OVMF의 S3는 켜도 된다(C3). AP는 펌웨어가 세워 둔 상태로 남는다(Kernel64는 CPU 1개만 쓴다).
- **불안정한 시험(부트 경로와 무관)**: `T_NET_LOOP.EXE`가 가끔 실패한다. 로더 없이 기존 Multiboot 경로(`run_k64_standalone.py --accel tcg`)
  에서도 4회 중 1회 접근 위반(`c0000005 at 7ffb000015a8`)으로 죽었고, UEFI 직접 부팅에서는 3회 중 1회 `a socket with a full send buffer is not
  writable` 검사가 실패했다. 나머지 T_*.EXE 29개와 커널 자체시험은 같은 실행에서 모두 PASS였다. 이 시험이 실패하면 `kernel64`/`auto-kernel64`
  사례는 FAIL로 기록되며, 가리지 않는다.

재현: `python3 shizukudos/kbuild.py && python3 shizukudos/win64/build.py && python3 shizukudos/dos16/build.py && python3 shizukudos/csm/build.py
&& python3 shizukudos/supervisor/build.py && python3 shizukudos/supervisor/test_bootmgr.py`(`--case <이름>` 반복 가능).
`shz.py test --suite boot`는 사례마다 기록을 하나씩 남긴다.

## 2e. VM 설치 ISO 하나 (에이전트 C3 "vm-install-iso")

빌더 `tools/build_shizuku_se_iso.py`(공용 `tools/shizuku_se_media.py`, 드라이버 저장소 `tools/shizuku_se_drivers.py`),
보조 raw 디스크 `tools/build_shizuku_se_disk.py`, 시험 `tools/test_shizuku_se_boot_matrix.py` = `shz.py test --suite media`
(`--suite iso`는 같은 것의 별칭). 설명서와 VM 프로필: `docs/shizukudos10/MEDIA.md`(ISO 안에는 `VMPROFIL.TXT`).

- **ISO 하나, 하이브리드:** BIOS El Torito 기본 엔트리 = `isolinux.bin`(no-emulation, boot info table 검증) → `menu.c32`
  메뉴(COM1에도 출력, COM1 키 입력 가능): **K** Kernel64(`mboot.c32 BOOT.ELF --- KERNEL64S.BIN --- WIN64.IMG`),
  **D** DOS16 FreeDOS 프로필(`memdisk harddisk` + hd32 디스크 이미지), **1** ShizukuDOS 0.1(`memdisk floppy`),
  **I** 설치(I1의 SHZSETUP: `BOOT.ELF shz.setup=auto --- KERNEL64S.BIN --- \SHZ\SETUP\INSTALL.IMG`, 배포용 응답 파일
  `install/shzsetup.ini`로 `mkpayload.py --out build/shizukudos/install-media`가 만든다). UEFI El Torito FAT 이미지 = `\EFI\BOOT\BOOTX64.EFI`
  (C2의 로더 겸 부트 매니저) + `\EFI\SHIZUKU\CSMWRAP.EFI`(C1의 `shizukudos/csm/build.py` 산출물, CSMWRAP.INI) +
  `\EFI\SHIZUKU\BOOT.INI`(`mode = auto`, `auto_kernel64 = no`, `menu_timeout = 5`) + `\SHZDOS\`(KERNEL64S.BIN 포함).
  **UEFI Shell·startup.nsh는 쓰지 않는다**(임시 경로 삭제). isohybrid: `isohdpfx.bin` MBR, MBR 파티션 2(0xEF)와 GPT 항목이 EFI 이미지를
  가리킨다. 드라이버 저장소 `\DRIVERS\<package>\`(원본 그대로) + `HWIDS.TXT` 색인, Win98 SE 오버레이, SHZSE, 제3자 부분
  (FreeDOS, CSMWrap+서브모듈, syslinux 데비안 소스 패키지)의 라이선스와 대응 소스.
- **UEFI 부트 매니저 메뉴(C3, 로더에 추가):** `BOOT.INI menu_timeout`(0–30초) 동안 한 글자를 기다린다. 키 없음/A/Enter = 정책
  (`auto`: VMX가 있으면 Supervisor, 없으면 CSM → 같은 매체의 레거시 메뉴), **K = Kernel64 직접**, C = CSM, S = Supervisor.
- **OVMF S3와 Kernel64(요청 1의 조정):** Multiboot 스텁과 부트 매니저가 같은 RAM 계획 `kernel64/standalone/memholes.h`를 쓴다
  (위 2d절). S3 NVS(8–9 MiB)는 힙 창 [3, 15) MiB 안의 구멍으로 힙에서 울타리로 막고(`mem.c heap_init`: 쓰지 않는 보초 블록),
  그 위 구멍은 페이지 할당기에서 뺀다. 구멍이 16개를 넘으면 실패 대신 RAM을 그 아래에서 끝낸다. 호스트 시험
  `kernel64/standalone/test_memplan.py`(15건 × -m32/64비트 ASan·UBSan, `shz.py` host 스위트). chain1의 힙 3..15 MiB와
  `link.ld`의 3 MiB 검사는 그대로 지킨다(커널 창의 구멍은 거부).
- **syslinux 고정:** `manifest.json` upstreams 끝의 `syslinux` = Ubuntu noble `3:6.04~git20190206.bf6db5b4+dfsg1-3ubuntu3`.
- **설치된 디스크의 BIOS 부팅(I1이 C3에 남긴 BLOCKED 항목):** `install/mkpayload.py`가 고정된 syslinux 6.04를 `esp.img`에
  설치한다(SHZSETUP이 p1을 쓰는 LBA 2048 자리에서, raw 매체 디스크와 같은 배치). I1의 GPT 보호 MBR 코드 → ESP의 syslinux 부트 섹터
  → `ldlinux.sys` → `syslinux.cfg` 기본(5초) = Kernel64(`mboot.c32 \SHZDOS\K64STUB.ELF --- KERNEL64S.BIN --- WIN64.IMG`),
  두 번째 = DOS16(memdisk). I1의 `tests/run_install.py`: **40 PASS / 0 FAIL / 0 BLOCKED**(전에는 2 BLOCKED; UEFI 두 번째 부팅도 S3 켬).
- **재현성:** 커밋 e43555e의 깨끗한 트리에서 전체 재빌드 두 번 → 같은 ISO
  `9c8fffec5c6c93c9c8a9749def1120063e876cb7cd104d6917eabd732e671e04`(93,323,264바이트). raw 디스크 두 번 →
  `60334f734333f802f62f7580d79143cc2126a0c136b25cdbe6aadcab0cc6c14c`(134,217,728바이트). (그 전 ab0b616: ISO `83ca6b59…`, SHZSETUP 없음.)

부팅 매트릭스 (QEMU 8.2.2 TCG, KVM 없음, q35, `-cpu max`, 2 vCPU, 512 MiB, OVMF는 S3 켬(QEMU 기본), 위 ISO/디스크, 한 번에 QEMU 하나):

| 펌웨어 | 매체 | Kernel64(레거시 메뉴) | DOS16 | ShizukuDOS 0.1 | Kernel64 직접(UEFI 메뉴 K) | 설치 줄 | 판정 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| SeaBIOS | ISO를 CD로 | PASS | PASS | PASS | 해당 없음 | PASS | PASS |
| SeaBIOS | ISO를 하드디스크로(USB 스틱 이미지) | PASS | PASS | PASS | 해당 없음 | 해당 없음 | PASS |
| SeaBIOS | raw 디스크 | PASS | PASS | PASS | 해당 없음 | 해당 없음 | PASS |
| OVMF | ISO를 CD로 | PASS | PASS | PASS | PASS | PASS | PASS |
| OVMF | ISO를 하드디스크로 | PASS | PASS | PASS | PASS | 해당 없음 | PASS |
| OVMF | raw 디스크 | PASS | PASS | PASS | PASS | 해당 없음 | PASS |

**설치 줄(요청 2):** ISO를 CD로(AHCI 포트 1) + 빈 512 MiB 디스크(AHCI 포트 0)로 부팅해 메뉴 I를 고른다(OVMF에서는 부트 매니저 → 키 없음
→ CSM → isolinux). SHZSETUP이 응답 파일 `Select=first`로 `ahci0`를 골라 설치하고 전원을 끈다(`SETUP-RESULT: OK`, `SHZ-EXIT:0`).
그 디스크를 호스트에서 I1의 `verify_disk.py`로 매체에 실린 페이로드와 대조한다(23행: GPT·CRC, MBR 코드, ESP 바이트 일치·파일별,
ShizukuFS e2fsck·파일 SHA-256). 이어서 그 디스크만 붙여 **OVMF(S3 켬)**: 설치된 ESP의 로더 → BOOT.INI `mode=kernel64` → Kernel64
직접, 구멍 3개 인계 = 적용, 자체시험 0 실패, `SHZ-EXIT:0`. **SeaBIOS**: `SHZ-MBR ->VBR` → SYSLINUX 6.04 → 스텁 → Kernel64,
자체시험 0 실패, `SHZ-EXIT:0`. 설치 부팅 전후 매체의 sha256이 같음도 확인한다.

- 증거(실행마다 `build/shizuku-se-matrix/<run>/<fw>-<medium>-<entry>/`): Kernel64 = COM1 로그를 `run_k64_standalone.py`로 판정 +
  WIN64.IMG의 나머지 T_*.EXE 37개 모두 `exit=0 faulted=0` + 스텁이 넘긴 구멍 수 = 커널이 적용한 구멍 수; DOS16 = `SHZ-EXIT:0` 뒤
  QMP로 memdisk mBFT → RAM 디스크를 떼어 `dos16/verify.py`로 판정; 0.1 = `A:\>`와 `DIR` 목록; Kernel64 직접 = C2의
  `test_bootmgr.k64_checks`(로더 RAM = 커널 RAM, ABI 1.1 UEFI-direct, GOP, 구멍 일치, CSMWrap 안 돔) + 8 MiB NVS가 힙에서 막힘.
  OVMF 경로는 순서대로 BDS → 로더 → BOOT.INI(auto, menu_timeout=5) → 메뉴 → (키 없음 → CSM → CSMWrap 부팅 장치 → isolinux | K →
  Kernel64 직접)이고, UEFI Shell이 한 번도 뜨지 않았음을 확인한다. OVMF+CSMWrap에서 Kernel64는 구멍 7개(NVS 3개는 힙에서 996 KiB,
  나머지 1492페이지는 할당기 밖)로 510 MiB RAM을 쓰고, Kernel64 직접은 256 MiB 한도 안에서 NVS 구멍 3개만 받는다.
- 실행 기록(ISO `9c8fffec…`, 커밋 e43555e): `final-i1-1` 23/23 PASS(설치 줄 SeaBIOS 69 s, OVMF 192 s),
  `suite-2026-09-29T222602Z`(`shz.py test --suite media`, VERIFIED) 23/23 PASS.
  그 전 ISO `83ca6b59…`(ab0b616, SHZSETUP 없음): `chain1-final-2` 21/21 PASS, `suite-2026-09-29T213259Z` 21/21 PASS.
  그 전 ISO(`c7106b60…`, 커밋 a3ba86e)의 `chain1-final-1`은 20/21이었다. OVMF·ISO를 디스크로·Kernel64에서 `subsys64` 자체시험
  "three malformed slots are dropped"가 실패했다(프로토콜 오류 2/3). 같은 메모리 맵의 다른 두 매체에서는 PASS였고, 원인은 시험의 경쟁이었다.
  `inject_bad_slot()`이 링 head를 공개한 뒤에 슬롯을 망가뜨려서 서비스 스레드가 먼저 정상 QUERY로 처리할 수 있었다. 인터럽트를 막고
  넣도록 고쳤다(커밋 ab0b616).
- 추가(그 전 ISO들): xHCI USB 대용량 저장장치로 붙인 ISO의 Kernel64 PASS(SeaBIOS, OVMF 각 1회).
- 불안정한 시험(부팅 경로와 무관): `run_k64_standalone.py`(QEMU `-kernel`, 구멍 없음) 3회 중 1회 `T_REG_STRESS.EXE` phase 6
  "handles were used successfully while being closed and replaced under them"가 실패했고 2회는 PASS였다. 그대로 기록한다.

**lead 병합 뒤(1bb8bc3, f65c8d6, 939a7cf; 헤드 8c083c4에서 빌드·시험):**
- WIN64.IMG가 Wine 포트(Wine DLL, dwrite 안의 FreeType, Noto·Tahoma 글꼴)를 싣게 되어 15.8 MB가 됐다. ISO는 이제
  wine·freetype·noto-fonts의 라이선스(Wine의 tomcrypt 포함)와 대응 소스도 싣는다. Wine은 빌드가 읽는 파일 + Tahoma의 `.sfd`를
  고정 커밋의 git 객체에서(`git archive`, 트리가 제자리에서 패치·빌드되므로), FreeType은 전체 트리, Noto(OFL, 수정 없이 배포)는
  라이선스만 싣는다. `shizukudos-source.tar.gz`에 빠져 있던 `drivers/ahci_native`(독립 Kernel64에 링크)와 `shizukufs`(libsfs)도
  넣었다. 설치 페이로드는 들어간다(ESP 내용 35 MiB / 128 MiB, INSTALL.IMG 6.8 MB). 단 설치되는 시스템에는 Wine DLL·글꼴이 없다
  (`mkpayload.py`는 Shizuku 자체 모듈만 싣는다).
- 재현성 결함 두 가지를 고쳤다. FreeDOS 커널 배너가 `__DATE__`를 넣어서 날짜가 바뀌면 DOS16 이미지와 ISO가 달라졌다(UTC 자정을
  넘긴 두 빌드에서 발견). `dos16/patches/0002-reproducible-build-date.patch`로 "Jul 29 2026"(매체의 SOURCE_DATE_EPOCH)에 고정했다.
  raw 디스크 FAT32 볼륨 ID가 Kernel64 C:의 고정 일련번호 0x53485A31과 같아서, lead의 `T_K32_FILE.EXE` "D: has a volume serial
  number of its own"이 raw 디스크 Kernel64 실행 3건에서 실패했다. 0x53453938로 바꿨다.
- ISO `d0050091dd1edc585710f2f31e206adbfb3616d1735101ae6023b59c9ff0bf1e`(153,092,096바이트, 커밋 8c083c4, 전체 재빌드 두 번 동일),
  raw 디스크 `e312bff482b6bbfc8f2b18967d7c5ff8c367c377d3d03afd827f8d707e3477aa`(128 MiB, 두 번 동일).
- 시험: `test_memplan.py` 30/30. `test_bootmgr.py` 18/18 + 파서 78/78, `run_install.py --build` 40/0/0(둘 다 3e67378; 그 뒤로는 디스크
  빌더만 바뀜). 매체 스위트 `suite-2026-09-30T011305Z` **23/23 VERIFIED**. 그 전 3e67378 실행은 19/23이었다(볼륨 ID 3건과
  `T_NET_LOOP.EXE` 페이지 누수 검사 1건, 후자는 알려진 불안정 시험). Kernel64 칸은 Win64 시험 프로그램 61개로 이제 칸마다 110–135초 걸린다.

**없는 것:** UEFI 메뉴에서 Kernel64 직접으로 설치를 고르는 항목(설치는 레거시 메뉴 I, UEFI에서는 CSM을 거친다). 설치 줄은 ISO를
CD로 붙인 경우만 돈다(`--install-media`로 다른 매체도 가능). NVMe·eMMC 대상에는 설치해 보지 않았다.

**검증되지 않은 것:** VirtualBox·VMware·Hyper-V 실행(MEDIA.md의 해당 줄은 동작 원리에서 끌어낸 설정), Intel VMX 위의
Supervisor 경로, Secure Boot(서명 없음), 실제 USB 스틱과 실제 하드웨어, 512 MiB 외의 RAM 크기, 1 vCPU UEFI(C1이 CSMWrap 거부를 확인),
실제 제3자 드라이버 패키지.

## 2f. 통합 현황 (lead `wip/shizukudos-10-toydzv`, 검증 체인)

각 에이전트 브랜치는 격리 작업트리에서 lead 위에 병합한 뒤, CI host 잡 전 단계 재현, `kbuild.py`, `win64/build.py`,
`run_k64_standalone.py` 2회, `run_k32_standalone.py`, `run_k64_gui.py`, 그리고 에이전트 자신의 러너를 통과한 경우에만
lead로 옮겼다(검증 트리 해시 = lead 트리 해시). 모두 QEMU TCG, GUEST_RUN.

| 영역 | 들어온 것 | 대표 증거 |
| --- | --- | --- |
| 부팅 | UEFI 부트 매니저(BOOT.INI, Kernel64 직접 부팅, CSMWrap 대체) | `test_bootmgr.py` 17/17, UEFI 부팅 후 상태 화면 스크린샷 |
| 설치 | SHZSETUP(빈 디스크에 GPT+ESP+ShizukuFS 설치), 설치 디스크 UEFI 재부팅 | `run_install.py --build` 전 셀 PASS(BIOS 재부팅은 C3 병합 시) |
| 저장장치 | AHCI 읽기/쓰기, FAT32 D: 쓰기, NVMe(MSI-X, 32 in-flight), SD/SDHCI, ShizukuFS(ext4 형식) E: | `run_k64_disk.py`, `run_k64_storage.py`, `run_k64_sfs.py`(e2fsck 깨끗) |
| 그래픽 | Bochs VBE, virtio-gpu 2D, UEFI GOP 백엔드, user32 485·gdi32 170 export | `run_k64_gui.py`(vga/virtio), `run_k64_gop.py` |
| 로더/런타임 | 로더 재작성(검색 순서, ASLR, 지연 로드, TLS, CFG), API-set 147계약, ucrtbase 847·vcruntime·msvcp, Wine 11 crypt32/dwrite 외 8종 | 상태 화면: 시스템 DLL 32개 전부 로드 |
| 드라이버 | PCI 드라이버 바인딩 기록(상태 화면), NT 드라이버 코퍼스(ReactOS 23종 빌드) + INF 저장소 + shzpnp | `test_inf.py`, `T_SHZPNP` 34/34 |
| 난수 | 커널 엔트로피 풀 + ChaCha20 CSPRNG(`NtShzRandom`), RDRAND 없는 CPU에서도 동작 | 부팅 KAT, qemu64(무 RDRAND)에서 T_WP_CRYPT32 PASS |

Chromium 157 시작 체인(정적 분석, `startup_chain.py`): 적재 시 import 1,346개 중 해결 안 된 것 64개(4.8%, 모두 kernel32).
**Chromium은 아직 게스트에서 실행되지 않았다.** NT 드라이버 호스트(N1), IPC/프로세스 회수(P-ipc), 하이브리드 설치 ISO(C3)는
lead 병합 작업 중이다.

## 3. 이번 세션에서 실행하지 못한 것 (BLOCKED)

| 항목 | 이유 |
| --- | --- |
| Supervisor(Intel VMX) 위의 DOS16 가상 Real Mode, Kernel32, Kernel64, **Win64 앱 실행** | 컨테이너에 `/dev/kvm`이 없어 L1에서 VMX를 볼 수 없다. TCG 부팅은 VMX 백엔드를 시험하지 않는다. 2절 8번의 Win64 자체시험은 **빌드·링크만 됐고 실행되지 않았다** |
| AMD SVM 백엔드 | 로더는 탐지만 하고 백엔드 미구현, AMD 호스트 없음 |
| 외부(제3자) Win64 앱 | 제공·실행된 앱 없음 |
| Windows 98 설치(완료까지)와 설치된 Win98 위의 NTW32/VxD/GDI 회귀 | 사용자 제공 Windows 98 미디어/체크포인트가 이 컨테이너에 없다. 기록된 알려진 실패: VxD 절대경로 로드가 오류 2 / VXDLDR 6 |
| Notepad++ 실행 | USER_REPORTED만 존재 |

## 4. 저장소 반영 상태

브랜치 `wip/shizukudos-10-toydzv`는 원격에 올라가 있다. PR #2, #3이 main에 병합됐고(#3은 squash), 이후 작업은 새 PR로 추적한다.
