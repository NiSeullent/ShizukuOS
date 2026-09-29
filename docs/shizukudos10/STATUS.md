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

`\SHZDOS\KERNEL64.INI`(선택)는 같은 문법에 `cmdline = <출력 가능 ASCII>` 키 하나만 받는다. 값은 잘라내지 않는다(너무 길면 거부).

**Kernel64 직접 부팅(`mode=kernel64`).** `kernel64/standalone/boot32.c`(Multiboot 스텁)가 하는 일을 UEFI에서 한다.
`\SHZDOS\KERNEL64S.BIN`(`kbuild.py`의 `-DSHZ_STANDALONE` 빌드, 하이퍼콜을 커널 안에서 COM1/PIT/RTC로 처리)을 물리 1 MiB에,
`\SHZDOS\WIN64.IMG`를 32 MiB에 읽는다. 0x1000–0x4FFF에 부트 페이지 표(항등 + 상위 절반, 2 MiB 페이지), 0x7000에 부트 정보를 둔다.
이 고정 범위는 쓰기 전에 모두 `AllocatePages(AllocateAddress)`로 확보한다. 그래서 펌웨어가 그곳에 살아 있는 것(로더, 스택, 펌웨어
페이지 표)이 없음을 보장한다. Kernel64는 물리 [0, ram_size) 전체를 소유하므로 `ram_size`는 **1 MiB에서 시작해 ExitBootServices 뒤
쓸 수 있는 메모리(Loader/BootServices Code·Data, Conventional, WB)가 끊기지 않는 구간의 끝**이다. 2 MiB 단위로 내리고 커널 한도
256 MiB로 자른다. 부팅 전에 GetMemoryMap으로 계획하고, `uefi/boot.c`의 재시도(맵 키가 바뀌면 다시 읽음)로 ExitBootServices를 한 뒤
**최종 맵으로 다시 계산**한다. 그다음 0x5000에 복사한 트램펄린이 CR3/GDT를 바꾸고 CR4=PAE로 맞춘 뒤 RDI=0x7000으로
0xFFFFFFFF80100000에 진입한다. ExitBootServices 전의 거부 사유는 5단계 페이징(LA57), 파일 없음·크기, KERNEL64.INI 오류, RAM 부족
(이때 가장 큰 사용 가능 구간도 출력), 고정 범위를 펌웨어가 점유(점유한 descriptor 출력), Supervisor용 `KERNEL64.BIN`을 잘못 둔 경우다.
모두 펌웨어로 돌아간다.

**OVMF와 S3.** OVMF는 S3가 켜져 있으면 SEC/PEI 임시 RAM(0x800000부터)을 `EfiACPIMemoryNVS`로 예약한다. Kernel64는 이 구간을
덮을 수 없다. 그러면 1 MiB부터의 연속 RAM이 8 MiB에서 끝나므로 로더가 **거부**한다(NVS를 덮지 않는다). `-global ICH9-LPC.disable_s3=1`이면
연속 구간이 약 236 MiB다(256 MiB 게스트, 끝은 `EfiRuntimeServicesData`). 실제 PC 펌웨어가 1 MiB 위 낮은 곳에 NVS/예약 구간을 두면
같은 이유로 거부된다. Kernel64가 구멍 있는 메모리 맵을 받게 하는 것은 커널 쪽 작업이며 이번 범위 밖이다.

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
| BOOT.INI/KERNEL64.INI 파서 호스트 시험 65건(ASan/UBSan) | HOST | PASS |
| `auto`: Intel(VMX 없음), BOOT.INI 없음 → CSMWrap → SeaBIOS CSM16 → FreeDOS, 실행 후 디스크를 `dos16/verify.py`로 검증 | GUEST_RUN | PASS ×2 (최종 실행 2회) |
| `csm`(AMD, CRLF·주석·대소문자 혼합 BOOT.INI), `legacy`(같은 MBR 디스크를 SeaBIOS 레거시로) | GUEST_RUN | PASS ×2 (최종 실행 2회) |
| `supervisor`(VMX 없음 → 거부·복귀), `missing`/`missing-default`(CSMWrap 없음), `malformed-key`/`malformed-mode`, `not-an-image`, `one-cpu` | GUEST_RUN (OVMF `BdsDxe: failed to start … <상태>`로 복귀 확인) | PASS ×2 |
| `kernel64`: BOOT.INI `mode=kernel64` + KERNEL64.INI, S3 끔 → Kernel64 직접 실행. `tests/run_k64_standalone.py`의 파서·판정 그대로 + WIN64.IMG 영수증의 T_*.EXE 30개 모두 exit 0 + 로더가 최종 맵으로 계산한 RAM = 커널이 본 RAM + ABI 1.1(472바이트, UEFI-direct 플래그) + cmdline 그대로 + GOP 모드 양쪽 일치 | GUEST_RUN | PASS ×2 (최종 실행 2회) |
| `auto-kernel64`: `auto_kernel64=yes`, VMX 없음 → 같은 Kernel64 실행 | GUEST_RUN | PASS ×2 (최종 실행 2회) |
| `auto-k64-fallback`: S3 켬 → NVS 때문에 Kernel64 거부(ExitBootServices 전) → CSM → FreeDOS 검증 | GUEST_RUN | PASS ×2 (최종 실행 2회) |
| `kernel64-nvs` / `-missing` / `-wrong-image` / `-bad-ini`: 거부 후 펌웨어 복귀(Out of Resources / Not Found / Load Error / Invalid Parameter) | GUEST_RUN | PASS ×2 (최종 실행 2회) |
| vBIOS 감사(`docs/shizukudos10/VBIOS_INT_AUDIT.md`)와 `supervisor/test_vbios.py`(ROM을 QEMU `-bios`로 + `bios.c` 호스트) | HOST + TCG | 53/53 PASS. Supervisor 안의 실행은 **BLOCKED**(VMX 없음) |

최종 상태(커밋 뒤 코드 변경 없음)로 두 번 실행했다.
1. `shz.py test --suite boot`(세션 `build/shizukudos/bootmgr/runs/20260929T173252-t98y7b6t`): 부트 매니저 17개 사례와 파서가 모두 PASS(검사 290개).
   같은 스위트에서 vBIOS 53/53, Kernel32·Kernel64 Multiboot 독립 실행(바뀐 `boot32.c` 포함)도 PASS였다. 스위트 전체는
   25 PASS / 1 FAIL / 3 BLOCKED이다. FAIL 1건은 `DOS16 … [KVM]`으로, `/dev/kvm`이 없어서 생긴 기존 항목이다.
2. `supervisor/test_bootmgr.py` 단독 실행(세션 `…/runs/20260929T173949-s_2g6s1l`): 17/17 PASS, 파서 65/65 PASS.
   Kernel64 직접 부팅은 호스트 부하에 따라 SHZ-EXIT까지 39–67초 걸렸다.

이보다 앞선 개발 중 실행 한 번에서는 `auto-kernel64`가 `T_NET_LOOP.EXE` 때문에 FAIL이었다(아래 불안정한 시험 항목).
T_NET_LOOP은 부트 경로와 무관하다.

한계와 BLOCKED 항목은 다음과 같다.
- **VMX 경로는 실행하지 않았다.** `mode=auto`에서 VMX가 있을 때 Supervisor를 고르는 분기와 `mode=supervisor` 성공 경로는 이 컨테이너에서
  BLOCKED다(`/dev/kvm` 없음). TCG만 썼고 KVM과 실제 PC에서는 실행하지 않았다. Secure Boot는 꺼져 있어야 한다(로더와 CSMWrap 모두 서명 없음).
- Kernel64 직접 부팅은 연속 RAM이 1 MiB부터 64 MiB 이상 있어야 한다. OVMF에서는 S3를 꺼야 한다(위 설명). AP는 펌웨어가 세워 둔 상태로 남는다
  (Kernel64는 CPU 1개만 쓴다).
- **불안정한 시험(부트 경로와 무관)**: `T_NET_LOOP.EXE`가 가끔 실패한다. 로더 없이 기존 Multiboot 경로(`run_k64_standalone.py --accel tcg`)
  에서도 4회 중 1회 접근 위반(`c0000005 at 7ffb000015a8`)으로 죽었고, UEFI 직접 부팅에서는 3회 중 1회 `a socket with a full send buffer is not
  writable` 검사가 실패했다. 나머지 T_*.EXE 29개와 커널 자체시험은 같은 실행에서 모두 PASS였다. 이 시험이 실패하면 `kernel64`/`auto-kernel64`
  사례는 FAIL로 기록되며, 가리지 않는다.

재현: `python3 shizukudos/kbuild.py && python3 shizukudos/win64/build.py && python3 shizukudos/dos16/build.py && python3 shizukudos/csm/build.py
&& python3 shizukudos/supervisor/build.py && python3 shizukudos/supervisor/test_bootmgr.py`(`--case <이름>` 반복 가능).
`shz.py test --suite boot`는 사례마다 기록을 하나씩 남긴다.

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
