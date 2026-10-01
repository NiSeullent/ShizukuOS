# ShizukuDOS 0.1

Windows 98 Shizuku's Second Edition 실험을 위한 **처음부터 작성한**, 부팅 가능한 최소 DOS형 환경입니다. FreeDOS 코드는 포함하지 않습니다.

## 현재 구현

- 1.44 MiB FAT12 플로피 이미지, 자체 부트 섹터와 예약 섹터의 16비트 셸
- BIOS 화면 및 COM1 직렬 입출력
- `HELP`, `DIR`, `TYPE`, `EXEC`, `CLS`, `VER`, `MEM`, `STACK`, `PCI`, `REBOOT`
- FAT12 루트 디렉터리와 클러스터 체인을 따라 파일 읽기 (`TYPE HELLO.TXT`)
- 루트 디렉터리의 단일 `.COM` 프로그램을 메모리에 올려 실행한 뒤 셸로 복귀 (`EXEC DEMO.COM`)
- `BOOT`: 첫 하드디스크의 MBR을 불러 기존 운영체제의 부트 경로로 넘김
- `BOOTC`: 첫 하드디스크 MBR의 활성 파티션을 찾아 해당 부트 섹터를 직접 실행
- `PCI`: BIOS PCI 서비스로 AHCI(01:06:01)와 xHCI(0C:03:30) class의 장치를 읽기 전용으로 나열

## 빌드와 VT 가속 부팅 시험

Windows PowerShell에서 `nasm`, Python 3, VirtualBox 7.x가 필요합니다.

```powershell
./shizukudos/run-vbox.ps1
```

이 스크립트는 별도 `ShizukuDOS-Dev` VM을 만들고 기본값으로 Windows Hypervisor Platform의 NEM 엔진을 지정합니다. CPU 가상화 가속을 사용할 수 없으면 부팅 단계에서 실패합니다. 스크린샷, 직렬 출력, 엔진 로그를 `shizukudos/vbox/`에 남깁니다. 빈 가상 AHCI·xHCI 컨트롤러를 추가하여 `PCI` 읽기 진단도 확인할 수 있습니다. 호스트가 VirtualBox 직접 VT-x/AMD-V를 제공한다면 `-Engine hm`을 지정할 수 있습니다. 이 개발 호스트에서는 Windows Hyper-V가 직접 HM 엔진을 점유하여 `VERR_VMX_NO_VMX`가 났고, NEM 엔진으로 실제 부팅했습니다. VirtualBox 로그의 Hyper-V 파티션 생성과 NEM 활성화, VM 실행 상태 및 ShizukuDOS 셸 프롬프트를 확인합니다.

QEMU는 중간 개발 시험에만 사용했습니다. 아래 명령은 이 호스트의 QEMU가 TCG만 제공하므로 프로젝트의 필수 가속 검증으로 취급하지 않습니다.

```powershell
./shizukudos/build.ps1
& 'C:\Program Files\qemu\qemu-system-i386.exe' -machine pc -m 64 -boot a -drive file=shizukudos/build/shizukudos.img,format=raw,if=floppy -display none -monitor none -serial stdio
```

직렬 콘솔에서 `HELP`, `DIR`, `TYPE HELLO.TXT`, `TYPE CHAIN.TXT`, `EXEC DEMO.COM`, `EXEC STD.COM`, `STACK`, `PCI` 등을 입력할 수 있습니다. 데모는 자체 FAT12 이미지에 들어 있습니다. `STACK`은 반복 실행 전후의 셸 `SS:SP`를 비교하는 진단 명령입니다. `BOOT`/`BOOTC` 검증에는 별도의 부팅 가능한 하드디스크 이미지를 함께 연결해야 합니다. 생성된 `.img` 및 `build/` 출력은 저장소에서 제외합니다.

```powershell
./shizukudos/tests/run_com_regression.ps1
```

이 회귀 시험은 VirtualBox NEM 가속을 확인한 다음 `EXEC`를 반복하고 `STD.COM`이 방향 플래그 `DF=1`에서 문자열을 앞으로 출력하는지, 프로그램 종료 뒤 셸 스택이 그대로인지 검사합니다. 실행 후 독립 VM을 종료합니다.

고정 메모리 배치는 다음과 같습니다. 부팅 시 BIOS `INT 12h`가 일반 메모리 448 KiB 이상을 보고해야 시작합니다. 이보다 작은 환경에서는 부팅을 중단합니다.

| 영역 | 실제 주소 | 용도 |
| --- | --- | --- |
| `1000:0000`–`1000:3DFF` | `10000h`–`13DFFh` | 31개 예약 섹터에서 읽은 셸 코드 |
| `2000:0000`–`2000:01FF` | `20000h`–`201FFh` | FAT12 루트 섹터 버퍼 |
| `3000:0000`–`3000:11FF` | `30000h`–`311FFh` | FAT12 테이블 버퍼 |
| `5000:0000`–`5000:FFFF` | `50000h`–`5FFFFh` | `.COM` PSP·코드·프로그램 스택 |
| `6000:0000`–`6000:FFFF` | `60000h`–`6FFFFh` | 셸 스택 (`SS:SP=6000:FFFE`) |

셸 스택은 BIOS가 사용하는 상위 일반 메모리와 EBDA보다 낮습니다.

## 최소 DOS 프로그램 인터페이스

`EXEC`는 FAT12 루트의 8.3 이름을 가진 `.COM` 파일만 실행합니다. 크기는 1~65,024바이트이고, 단일 PSP/프로그램 세그먼트 `5000h`의 오프셋 `0100h`에 적재됩니다. 빈 명령행, `INT 20h` 진입점, 최상위 스택을 구성하며 한 번에 프로그램 하나만 실행합니다.

| 호출 | 현재 동작 |
| --- | --- |
| `INT 21h, AH=02h` | `DL`의 단일 문자를 BIOS 화면과 COM1에 출력합니다. |
| `INT 21h, AH=09h` | `DS:DX`의 `$` 종료 문자열을 출력합니다. |
| `INT 21h, AH=30h` | 자체 버전 0.1을 `AL=0`, `AH=1`로 반환합니다. |
| `INT 21h, AH=4Ch` | `AL` 종료 코드를 셸에 전달하고 인터럽트 벡터를 복원합니다. |
| `INT 20h` | 종료 코드 0으로 셸에 복귀합니다. |

그 밖의 `INT 21h` 서비스는 `CF=1`, `AX=1`로 실패합니다. 파일 열기/쓰기, 메모리 할당, 환경 블록, 파일 제어 블록, 인자 전달, 다중 프로그램 실행은 구현하지 않았습니다. 따라서 일반 DOS 프로그램은 아직 실행 대상이 아닙니다. `tests/demo_com.asm`은 출력, 버전·오류 응답, `AH=4Ch` 종료를, `tests/ret_com.asm`은 near `RET`에서 `INT 20h` 종료를, `tests/std_com.asm`은 `DF=1` 호출과 셸 복귀를 확인합니다.

## 범위와 한계

이 이미지는 아직 Windows 98의 `IO.SYS`·`MSDOS.SYS`·`WIN.COM`·`VMM32`가 기대하는 MS-DOS 7.1 부팅 및 런타임 계약을 구현하지 않습니다. `BOOT`/`BOOTC`는 설치된 Windows 98의 **원래 부트로더와 원래 DOS 커널을 그대로 사용해** 하드디스크로 넘기는 체인로드일 뿐입니다. ShizukuDOS가 Windows 98 GUI의 DOS 코어를 교체하거나 멀티코어를 지원한다는 의미는 아닙니다.

현재 셸에는 완전한 DOS API, 파일 쓰기, 파티션/하드디스크 파일 시스템, 메모리 관리자 및 보호 모드가 없습니다. FAT12 읽기는 루트 디렉터리의 일반 8.3 파일만 다룹니다. CPU 모드와 앱별 명령어·속도 제어는 별도 계층의 후속 과제입니다.

`PCI`는 장치 ID를 발견하기만 합니다. AHCI/xHCI BAR, MMIO, DMA, IRQ 등에 손대지 않으므로 SATA/USB 드라이버가 아닙니다. PCI BIOS가 없는 펌웨어에서는 사용할 수 없습니다.

PCI 함수 번호와 반환값은 [PCI-SIG PCI BIOS 2.1](https://pcisig.com/PCIConventional/Specs/Firmware/Bios_2.1) 인터페이스 및 [SeaBIOS의 해당 구현](https://chromium.googlesource.com/chromiumos/third_party/seabios/+/49bf57b87238ac964ac2ae527b74a7086132e27a/src/pcibios.c)을 기준으로 검증했습니다.

## 체인로드 분리 시험

`tests/chainload_mbr.asm`과 `tests/chainload_vbr.asm`은 전달된 드라이브 번호 `DL=80h`, 세그먼트/스택, 인터럽트 활성 상태를 확인하고 COM1에 시험용 표식을 출력하는 512바이트 부트 섹터입니다. `tests/build_test_hdd.ps1`로 만든 2 MiB 별도 하드디스크 이미지만 연결한 뒤 `BOOT`는 `CHAINLOAD MBR OK`, `BOOTC`는 `CHAINLOAD PARTITION OK` 출력을 확인합니다. Windows 98 설치 중인 디스크나 그 이미지에는 이 시험을 적용하지 않습니다.

## 라이선스

이 디렉터리의 소스는 프로젝트의 GPL-2.0 조건을 따르는 독립 구현입니다. Windows 및 FreeDOS 코드나 이미지가 포함되지 않습니다.
