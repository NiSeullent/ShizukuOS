# ShizukuDOS 10.0 — vBIOS 인터럽트 감사 (VBIOS_INT_AUDIT)

대상: DOS16 도메인의 가상 BIOS = `shizukudos/supervisor/guest/vbios.asm`(ROM, F000:0000–FFFF)
\+ `shizukudos/supervisor/src/bios.c`·`video.c`(ROM 스텁 `out 0xE0..0xEF, al; iret`가 부르는 Supervisor 서비스).
비교 기준: CSMWrap 고정 클론(7f30b74)에 들어 있는 SeaBIOS(`build/upstream/csmwrap/seabios/src`, CSM 빌드 578d260b)와
Ralf Brown's Interrupt List(RBIL). "FreeDOS 호출" 열은 `build/upstream/freedos-kernel`(ke2046, 커널)과
`build/upstream/freedos-freecom`(셸)을 grep한 결과이며 호출 위치를 적었다.

**라이선스 원칙.** vBIOS는 GPL-2.0-only, SeaBIOS는 LGPL-3.0이다. 이번에 메운 부분은 RBIL·MC146818A 데이터시트·EDD 규격에
적힌 인터페이스 의미에서 새로 작성했고, SeaBIOS는 동작 비교 대상으로만 읽었다(코드 복사 없음, 소스 주석에 명시).

**검증 한계.** vBIOS는 Supervisor의 DOS16 도메인(Intel VMX 필요) 안에서만 실제로 돈다. 이 컨테이너에는 `/dev/kvm`이 없어
**Supervisor 안에서의 실행 검증은 BLOCKED**다. 대신 `shizukudos/supervisor/test_vbios.py`가 다음을 확인한다(모두 VMX 아님):
(1) ROM 이미지 정적 점검, (2) ROM을 QEMU TCG의 머신 BIOS(`-bios`)로 부팅해 리셋 경로·IVT·ROM 자체 구현 서비스를
실제 실행(QEMU의 MC146818 RTC 상대), (3) `bios.c`를 모의 VMCS/장치 헤더로 호스트에서 컴파일해 INT 13h/15h/16h/1Ah 경로를
ASan/UBSan 아래 구동. 하이퍼콜 스텁이 부르는 서비스는 (2)에서 실행되지 않는다(포트 E0h–EFh가 무시됨).

## 1. 함수별 대조표

범례 — vBIOS: ✔ 구현 · ◐ 부분 · ✘ 없음(보통 AH=01h/86h, CF=1) · **new** 이번 변경.

### INT 10h 비디오 (`video.c video_int10`; SeaBIOS `vgasrc/vgabios.c handle_10*`, VBE `vgasrc/vbe.c`)

| AH | vBIOS | SeaVGABIOS | FreeDOS 호출 |
| --- | --- | --- | --- |
| 00h 모드 설정 | ◐ 모드 2/3만(화면 지움), 그 외 무시 | ✔ 텍스트·그래픽 전 모드 | — (FreeCOM 아님) |
| 01h/02h/03h 커서 | ✔ (페이지 0만) | ✔ | 02h: `config.c` 메뉴·`FreeCOM goxy` |
| 05h 페이지 | ◐ 무동작(페이지 0) | ✔ | — |
| 06h/07h 스크롤 | ✔ | ✔ | 06h: `config.c` 메뉴, FreeCOM `CLS` |
| 08h/09h/0Ah 문자 | ✔ | ✔ | — |
| 0Eh TTY | ✔ | ✔ | 커널 `console.asm`(INT 29h), `kernel.asm` |
| 0Fh 모드 조회 | ✔ 3/80열 | ✔ | `kernel.asm cpu_abort`, FreeCOM `CLS` |
| 11h 글꼴 | ◐ 무동작 | ✔ | `config.c` SCREEN=(1111/1112/1114h), `initdisk.c`(verbose) — 무동작이면 25행 유지, BDA 84h도 24로 일치 |
| 12h BL=10h | ✔ | ✔ | — |
| 13h 문자열 | ✔ | ✔ | — |
| 1Ah 표시 조합 | ✔ AL=00h | ✔ | — |
| 0Bh–0Dh, 10h, 1Bh, 1Ch, 4Fh(VBE) | ✘ | ✔ | — |

### INT 11h / 12h (`vbios.asm int11_handler/int12_handler`; SeaBIOS `misc.c handle_11/handle_12`)

둘 다 ✔(ROM이 BDA 40:10h=0222h, 40:13h=639 KiB를 반환). FreeDOS: 11h `main.c InitPrinters/InitSerialPorts`,
`initdisk.c ReadAllPartitionTables`; 12h `kernel.asm`(init 이동), `initoem.c init_oem`.

### INT 13h 디스크 (`bios.c bios_disk`, 드라이브 80h = RAM 디스크; SeaBIOS `disk.c handle_13 → disk_13xx`, `block.c fill_edd`)

| AH | vBIOS | SeaBIOS | FreeDOS 호출 |
| --- | --- | --- | --- |
| 00h/0Dh 리셋, 01h 상태 | ✔ | ✔ | `initdisk.c BIOS_drive_reset`, `floppy.asm FL_RESET`(재시도) |
| 02h/03h/04h CHS | ✔ | ✔ | LBA가 없을 때 `dsk.c LBA_Transfer → fl_read/fl_write/fl_verify` |
| 05h 포맷 | ✘ | ✔ | 플로피만(`FL_FORMAT`) — 플로피 없음 |
| 08h 매개변수 | ✔ 80h(16×63), 드라이브 수 1 | ✔ | `initdisk.c BIOS_nrdrives`, `LBA_Get_Drive_Parameters` |
| 09h/0Ch/10h/11h/14h | ◐ 0Ch/10h/11h/14h 성공만, 09h ✘ | ✔ | — |
| 15h DASD 종류 | ✔ 고정 디스크, CX:DX=섹터 | ✔ | `init_readdasd`(플로피만) |
| 16h/17h/18h 플로피 | ✘ | ✔ | 플로피 장치가 있을 때만(장비 워드상 없음) |
| 41h EDD 설치 확인 | ✔ AH=21h, CX 비트0 | ✔ AH=30h, CX=07h | `LBA_Get_Drive_Parameters` |
| 42h/43h 확장 읽기/쓰기 | ✔ | ✔ | `floppy.asm FL_LBA_READWRITE`(모든 HDD 입출력) |
| **44h 확장 검증** | **new ✔** 범위 검사(RAM 디스크라 검증=범위) | ✔ `disk_1344` | **호출함**: `VERIFY ON`에서 드라이브가 write-with-verify를 보고하지 않으면 43h 뒤에 44h(`dsk.c` `LBA_WRITE_VERIFY`), 트랙 검증 IOCTL. 이전엔 AH=01h/CF=1 → 재시도 후 쓰기 오류 |
| **47h 확장 탐색** | **new ✔** 범위 검사 | ✔ `disk_1347` | 호출 안 함. 41h CX 비트0("고정 디스크 서브셋" = 42h/43h/44h/47h/48h)을 광고하므로 함께 구현 |
| **48h 드라이브 매개변수** | **new ✔** 버퍼 크기 < 1Ah → AH=01h/CF=1, 결과는 정확히 1Ah 바이트(DPTE 없음) | ✔ `fill_generic_edd` | **호출함**(30바이트 버퍼). 이전 구현은 호출자 버퍼 크기를 보지 않고 항상 1Eh 바이트를 써서 1Ah 버퍼를 넘어 썼고 DPTE를 0:0으로 보고 |
| 45h/46h/49h/4Eh | ✘ | ✔ | — |
| 4Bh CD 에뮬 상태 | ✘ (AH=01h/CF=1 = "지원 안 함"으로 올바름) | ✔ `cdemu_134b` | `main.c EmulatedDriveStatus` — `#if 0` 또는 `BootHarddiskSeconds≠0`일 때만 |

### INT 14h 직렬 (`bios.c bios_serial`; SeaBIOS `serial.c handle_1400..1403`)

◐ 00h–03h 구현, DX(포트 번호)를 무시하고 항상 COM1, 01h가 회선 상태 대신 AH=0을 반환. FreeDOS: `main.c InitSerialPorts`
(장비 워드의 포트 수만큼, 여기선 COM1만), `serial.asm`(AUX), `console.asm`(디버그 빌드). 간극으로 기록만 함.

### INT 15h 시스템 (`bios.c bios_system/bios_e820`; SeaBIOS `system.c handle_15`, `clock.c handle_1583/1586`, `apm.c`, `mouse.c`)

| AH/AX | vBIOS | SeaBIOS | FreeDOS 호출 |
| --- | --- | --- | --- |
| 2400h–2403h A20 | ✔ (2403h: BX=3) | ✔ `handle_1524xx` | 커널 없음(HIMEM이 사용, 이미지에 없음) |
| 4Fh 키보드 가로채기 | AH=86h/CF=1 | 동일(`handle_154f` set_invalid_silent) | — |
| 86h 대기 | ✔ TSC 바쁜 대기 | ✔ | — |
| 87h 확장 메모리 이동 | ✔ (디스크립터 권한 검사 없음) | ✔ | — |
| 88h 확장 메모리 | ✔ 최대 FC00h KiB | ✔ | — |
| C0h 구성 표 | ✔ F000:E6F5 | ✔ | — |
| C1h EBDA 세그먼트 | ✘ | ✔ | — (커널은 40:0Eh 직접 읽음) |
| E801h / E820h | ✔ / ✔ (4항목, 20바이트) | ✔ / ✔ | — |
| 52h, 53h(APM), 83h, 89h, 90h/91h, C2h(마우스) | ✘ | ✔ | — |

FreeDOS 커널과 FreeCOM은 INT 15h를 **호출하지 않는다**(`kernel.asm`은 벡터를 저장만 함). 메모리 관리자·DOS 확장기용이다.

### INT 16h 키보드 (`vbios.asm int16_handler` + `bios.c bios_keyboard`; SeaBIOS `kbd.c handle_16xx`)

| AH | vBIOS | SeaBIOS | FreeDOS 호출 |
| --- | --- | --- | --- |
| 00h/10h 읽기(대기) | ✔ 비었으면 스텁이 HLT 후 재시도 | ✔ | `console.asm readkey`, `config.c GetBiosKey`, `kernel.asm` |
| 01h/11h 상태 | ✔ ZF | ✔ | `console.asm`, `intr.asm KEYCHECK`, FreeCOM `keyprsd.c` |
| 02h/12h 시프트 상태 | ◐ AL=0; 12h는 AH를 채우지 않음(AH=12h가 남음) | ✔ `handle_1602/1612` | 호출 안 함(커널은 40:17h 직접 읽음) |
| 05h 키 넣기, 09h 기능 | ✔ | ✔ | — |
| 03h, 0Ah, 92h, A2h, 6Fh | ✘ | ✔(일부) | — |

FreeDOS는 BDA 40:96h 비트4(101키)로 10h/11h 사용 여부를 정한다(`console.asm ConInit`). vBIOS는 0이라 00h/01h를 쓴다.

### INT 17h 프린터 (`bios.c` 포트 E6h; SeaBIOS `serial.c handle_1700..1702`)

◐ 모든 함수가 AH=30h(선택됨+용지 없음) — "프린터 없음"으로 동작. 장비 워드상 프린터 0개라 커널은 초기화(01h)를 부르지 않고,
PRN 사용 시 `printer.asm`이 02h/00h 상태를 보고 오류를 돌려준다.

### INT 18h / 19h (`vbios.asm`; SeaBIOS `boot.c handle_18/handle_19`)

19h ✔ RAM 디스크 MBR을 0:7C00에 적재(포트 E8h), 18h는 메시지 후 정지(다음 장치 시도 없음). FreeDOS: 재부팅 경로에서 19h
(`entry.asm`이 10/13/15/19/1Bh 벡터를 복구한 뒤 원래 19h 호출, `kernel.asm cpu_abort`).

### INT 1Ah 시각 (`vbios.asm rtc_service` + `bios.c bios_time`; SeaBIOS `clock.c handle_1a00..1a07`, `pcibios.c`)

| AH | vBIOS | SeaBIOS | FreeDOS 호출 |
| --- | --- | --- | --- |
| 00h/01h 틱 카운트 | ✔ Supervisor(BDA 40:6Ch/70h) | ✔ | `rdpcclk.asm ReadPCClock`, `wrpcclk.asm WritePCClock`, `dsk.c` 시간 측정 |
| **02h 시각 읽기** | **new ✔ ROM**: UIP 대기, 2진/12시간 모드 → BCD 24시간 변환, DL=DST | ✔ (갱신 중이면 CF=1) | **호출함**: `initclk.c Init_clk_driver`(부팅) |
| **03h 시각 설정** | **new ✔ ROM**: BCD·범위 검사, SET 비트로 정지 후 기록, DST 비트 | ✔ | **호출함**: 모든 DosSetTime(부팅 포함) → `sysclk.c` → `wratclk.asm WriteATClock`. 이전엔 CF=1 |
| **04h 날짜 읽기** | **new ✔ ROM**: 세기 바이트(32h)가 없거나 쓰레기면 1980–2079 창으로 추정 | ✔ | **호출함**: `Init_clk_driver` |
| **05h 날짜 설정** | **new ✔ ROM**: BCD·범위(월 1–12, 일 1–31) 검사 | ✔ | **호출함**: 모든 DosSetDate(부팅 포함). 이전엔 CF=1 |
| 06h/07h 알람 | ✘ | ✔ | — |
| B1xxh PCI BIOS | AH=81h/CF=1 ("없음") | ✔ `pcibios.c` | — |

Supervisor 장치 모델(`devices.c`)은 CMOS 00h–0Dh·32h 읽기를 플랫폼 RTC로 넘기고, **게스트의 00h–0Dh 쓰기는 버린다**
(게스트가 호스트 시계를 바꾸지 못하게 하는 기존 정책). 따라서 Supervisor 아래에서 03h/05h는 RBIL 의미대로 성공(CF=0)하지만
플랫폼 RTC는 바뀌지 않고, DOS 시계는 BDA 틱과 DOS 내부 날짜로 계속 간다. 02h/04h는 이전엔 Supervisor가 호스트 RTC를
UIP 확인·모드 변환 없이 그대로 돌려줬다(2진 모드 RTC나 갱신 순간에는 틀린 값).

### INT 1Eh 디스켓 매개변수 표 (데이터 포인터; SeaBIOS `misc.c diskette_param_table`(F000:EFC7), `hw/floppy.c floppy_setup`)

**new ✔** F000:EFC7(IBM 호환 고정 주소)에 11바이트 1.44 MB 표(AF 02 25 02 12 1B FF 6C F6 0F 08, RBIL "Format of diskette
parameter table"). 이전엔 벡터가 ROM의 `IRET` 코드를 가리켰다. FreeDOS는 부팅 때마다 이 표를 자기 영역으로 복사·수정하고
벡터를 옮긴다(`initdisk.c ReadAllPartitionTables`); 플로피 입출력 때는 `dsk.c`가 섹터/트랙 바이트를 갱신한다.

### BDA에서 FreeDOS가 직접 읽는 값

40:0Eh(EBDA), 40:13h(메모리), 40:17h(시프트), 40:1Ah/80h(KEYBUF=), 40:4Ah(열), 40:6Ch(틱), 40:84h(행), 40:96h(키보드 종류).
vBIOS는 앞의 것들을 `bios.c bios_prepare_guest_memory`·`video.c video_init`에서 채우고 40:17h·40:96h는 0이다.

## 2. 이번 변경으로 메운 간극

| 간극 | FreeDOS 영향 | 구현 위치 | 검증 |
| --- | --- | --- | --- |
| INT 1Ah 03h/05h 없음(CF=1) | 부팅·DATE·TIME마다 호출, RTC 미기록 | `vbios.asm rtc_service` | QEMU `-bios`: 4개 RTC 모드 × 5개 시각 왕복(원시 레지스터가 RTC 형식과 일치), 잘못된 입력 10종 CF=1·무기록, 레지스터 보존 |
| INT 1Ah 02h/04h: UIP·2진/12시간·세기 처리 없음 | 부팅 시 날짜/시각 | `vbios.asm rtc_service`(Supervisor에서 ROM으로 이동) | 위와 같음 |
| INT 1Eh 벡터가 표가 아님 | 부팅 때 복사 | `vbios.asm diskette_param_table` | 정적 점검 + QEMU에서 IVT 1Eh 경유 11바이트 확인 |
| INT 13h 44h 없음 | VERIFY ON 쓰기 실패 | `bios.c bios_disk` | 호스트 하니스: 범위 안/끝/밖, 0블록, 짧은 DAP, 데이터 불변 |
| INT 13h 47h 없음 | 없음(41h 광고와 일치시키기) | `bios.c bios_disk` | 호스트 하니스 |
| INT 13h 48h 버퍼 크기 무시·초과 기록 | 부팅 시 호출(30바이트 버퍼라 이전에도 동작) | `bios.c bios_disk` | 호스트 하니스: 1Eh/1Ah/19h/42h 버퍼 |

변형 시험(mutation)으로 하니스가 실제로 잡는지도 확인했다: 44h 범위 검사에 off-by-one을 넣으면 호스트 검사 2개가,
12시간 모드의 PM 비트를 빼면 QEMU RTC 검사가 실패한다.

## 3. 남은 간극 (FreeDOS 커널·FreeCOM이 호출하지 않음 — 이번에 구현하지 않음)

- INT 10h: 그래픽 모드, 팔레트(10h), 상태 저장(1Bh/1Ch), VBE(4Fh), 글꼴(11h) — 텍스트 80×25만.
- INT 13h: 05h/09h/16h–18h(플로피), 45h/46h/49h(이동식), 4Bh/4Eh; 드라이브 80h 하나만.
- INT 14h: DX 포트 번호 무시, 01h 반환 상태. INT 17h: 실제 LPT 없음.
- INT 15h: C1h(EBDA 세그먼트; C0h 표는 EBDA 비트를 켜 둠), C0h 기능 바이트 비트4가 "INT 09h가 INT 15h/4Fh 호출"을
  주장하지만 vBIOS INT 09h는 호출하지 않음, 53h(APM), 83h/90h/91h, 89h, C2h, E820h 24바이트 확장 속성.
  HIMEMX/JEMM 같은 메모리 관리자를 넣으면 먼저 확인할 부분이다.
- INT 16h: 02h/12h가 BDA 시프트 플래그를 반환하지 않음(12h는 AH 미설정), 03h/0Ah; 40:96h 101키 비트 0.
- INT 18h: 다음 부팅 장치 시도 없음. INT 1Ah: 06h/07h 알람, PCI BIOS.
- 벡터 1Dh/1Fh/41h/46h(비디오·글꼴·고정 디스크 매개변수 표)는 IRET를 가리킴.

## 4. UEFI에서 DOS가 받는 BIOS 서비스 — 두 경로

- **VMX 있음(Supervisor 프로필)**: 위 vBIOS. Supervisor 안의 실행은 이 컨테이너에서 **BLOCKED**.
- **VMX 없음(부트 매니저 `mode=auto`/`csm`)**: 로더가 CSMWrap을 체인로드하고 SeaBIOS CSM16이 실제 PC BIOS 서비스를 제공한다.
  `shizukudos/supervisor/test_bootmgr.py`가 OVMF(TCG)에서 FreeDOS 적합성 프로그램(T_MODE/T_BIOS/T_COM/T_EXE, 종료코드 42)을
  끝까지 실행하고 디스크의 `RESULT.TXT` 등을 호스트에서 검증한다. 이 경로의 BIOS 서비스는 위 표의 SeaBIOS 열이다.
