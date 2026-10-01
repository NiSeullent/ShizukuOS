# ShizukuOS 생산 설치 화면 VM 검증

이 러너는 현재 소스로 빌드한 ShizukuOS 설치 화면을 실제 QEMU 키 입력으로 검증한다. ShizukuDOS는 Windows 98에서 MS-DOS를 대체하기 위한 기반이며 Kernel32·Kernel64는 그 구성요소다. 이 검증의 성공은 구성요소 설치와 데스크톱 재부팅에 대한 증거다. Windows 98 자체의 DOS→VMM 연결, MS-DOS 대체 완료, 최신 앱·드라이버·가속의 Windows 98 내 실행은 별도 목표로 남는다.

기본 실행은 입력 검증만 한다. `--run`을 명시하면 다음 네 VM을 순차 실행한다. 설치된 Windows 이미지나 Microsoft 매체는 입력으로 받지 않는다.

1. UEFI 설치 화면에서 512 MiB 후보 디스크 두 개 중 두 번째 NVMe 디스크 `nvme0n1`을 선택한다. 검토 화면에서 Esc로 돌아온 후 다시 Esc로 취소한다. 실제 종료 이후 정지한 QMP의 두 디스크 `wr_bytes`·`wr_operations`가 모두 0이어야 하고, 두 디스크 전체의 SHA-256도 초기 0 바이트 상태와 같아야 한다.
2. 새 UEFI VM과 새 디스크 두 개에서 다시 `nvme0n1`을 선택하고 `ERASE`를 입력한다. 실제 설치 결과, 종료 상태와 첫 디스크의 전체 0 해시를 확인한다. 첫 디스크의 실제 쓰기 횟수·바이트는 0이고 선택한 두 번째 디스크의 두 쓰기 통계는 양수여야 한다.
3. 설치된 두 번째 디스크를 독립 호스트 검사기로 확인한 뒤 복사본을 새 UEFI VM에서 부팅한다. 실제 데스크톱 표시와 F3 편집기 실행, F10 종료를 확인한다.
4. 다른 복사본을 새 BIOS VM에서 부팅하여 같은 데스크톱 검증을 수행한다.

두 후보 디스크는 각각 512 MiB이며 설치 매체는 128 MiB다. 첫 후보 `d0`은 AHCI 디스크 `ahci0`, 설치 대상 `d1`은 NVMe namespace `nvme0n1`이다. 설치 매체 `d2`는 OVMF가 읽을 수 있는 별도의 `virtio-blk-pci` 장치에 읽기 전용으로 연결한다. 로더가 커널과 설치 아카이브를 RAM으로 불러오며, 현재 Kernel64에는 virtio 디스크 드라이버가 없어 이 매체를 설치 후보로 등록하지 않는다. QEMU 10.1의 `ide-hd`는 읽기 전용 backend를 거부하므로 이 읽기 전용 펌웨어 부팅 경로를 사용한다. 정확한 선택 대상은 `nvme0n1`, 1,048,576 섹터다. 실제 게스트에서 후보 두 개와 선택한 디스크를 확인하지 못하면 실패한다. 설치 후 두 cold 복사본도 NVMe 장치로 연결해 UEFI·SeaBIOS 부팅을 각각 실제 확인한다. BIOS 부팅이 실패하면 그 실패를 기록하며 생략하지 않는다. 취소·설치 디스크, 로그와 화면은 결과 폴더에 보존한다.

현재 AHCI 어댑터는 단일 포트·단일 디스크만 등록한다. 이 러너는 두 AHCI 디스크를 지원한다고 표시하지 않는다. 여러 AHCI 포트 지원에는 공유 HBA 소유와 command engine 상태를 보존하는 별도의 드라이버 구현이 필요하다. 이 구성은 이미 존재하는 AHCI·NVMe 드라이버를 실제로 사용하는 설치 검증 프로필이다.

## 준비

Linux/KVM와 Python의 `pidfd_open`·`pidfd_send_signal`, NVMe 장치를 포함한 QEMU, 4 MiB 규격의 OVMF CODE+VARS 쌍, SeaBIOS, dosfstools, mtools, e2fsprogs가 필요하다. QEMU와 펌웨어의 실제 파일 경로를 명시한다. 심볼릭 링크·장치 파일·FIFO·`/dev`, `/proc`, `/sys` 입력과 출력은 거부한다. `/usr/share/OVMF/OVMF_CODE_4M.fd` 등 배포판별 위치는 다를 수 있다.

현재 배포판 QEMU 10.1은 실제로 읽기 전용 `ide-hd`를 거부했고 NVMe 모델도 포함하지 않았다. 두 실행은 게스트 시작 전 실패했으며 설치 성공으로 집계하지 않는다. 기존 공식 upstream QEMU 10.1.5에서 AHCI·NVMe·읽기 전용 virtio 장치를 일시 정지 상태로 실제 연결해 확인했다. 이 호스트 제어 검사는 게스트 설치·부팅을 대신하지 않는다. 호스트 패키지나 서비스를 바꾸지 않고 명시한 실행기를 사용한다.

`--qemu-data`는 선택한 공식 QEMU의 `vgabios-stdvga.bin`, `kvmvapic.bin` 두 일반 파일만 들어 있는 별도 폴더여야 한다. 러너는 이 경로를 `-L`로 지정하며, 기본 검색 경로에 의존하지 않는다. 입력 캡처는 실행 파일, 실제 ELF 라이브러리와 로더, 두 ROM, OVMF·SeaBIOS 바이트를 고정한다. 라이브러리 해석 결과나 ROM이 바뀌면 다시 캡처하기 전 실행을 거부한다. `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`로 다른 라이브러리를 삽입한 환경도 거부한다. 호스트 제어 시험에서 실행기를 자동 선택하지 않으며 `SHZ_QEMU`, `SHZ_QEMU_DATA`를 명시한다.

Kernel32·Kernel64·DOS10·Win64·Supervisor의 현재 소스 빌드를 먼저 완료하고, `mkpayload.py --desktop`의 새 결과 폴더를 준비한다. `--build`가 기존 바이너리 존재 여부만 확인하는 것으로 현재 소스 빌드를 대신할 수 없다. 러너는 각 완료 영수증의 소스 해시, 로더·커널·런타임 해시, 설치 아카이브의 실제 설치 EXE·런타임·페이로드 바이트를 다시 확인한다. `SYS64`, `FONTS`, `CERTS`, `T_HELLO.EXE`의 현재 런타임 바이트를 확인하며, 빌드에 없는 인증서 파일도 거부한다. 이전 소스 빌드, 이전 자동 시험 페이로드, 중복된 아카이브 경로는 거부한다.

128 MiB FAT 설치 매체는 러너가 새로 만든다. 현재 로더·Kernel64·INSTALL.IMG와 `mode=install`, `menu_timeout=0` 설정을 복사하고 모든 파일을 다시 읽어 같은 해시인지 확인한다. 기존 Supervisor ESP를 수정하지 않는다. 설치 후 BIOS용 Syslinux 부팅 코드가 포함된 desktop 페이로드가 필요하다.

예시의 경로는 각 환경에 맞게 바꾼다. `RUN`의 부모 폴더는 존재해야 하고 결과 폴더와 입력 JSON은 새 이름이어야 한다. 17 GiB 여유 공간을 유지하면서 추가 작업의 절대 상한을 3 GiB로 둔다. 시작 시에는 실제 멤버 입력 크기를 반영해 증명된 최대 사용량을 계산하여 그만큼의 여유 공간을 요구한다. 단계마다 추가 쓰기의 상한과 현재 여유 공간을 다시 확인한다. 저장 위치가 소스 저장소 내부라면 무시되는 `build/` 아래만 허용한다.

3 GiB 예산은 앞 단계의 성공 조건을 통과할 때만 유효하다. 취소 디스크 두 개와 설치의 첫 디스크는 쓰기 통계·전체 0 해시·실제 할당 블록 0을 확인한 뒤 다음 단계로 간다. 마지막 디스크 비용은 설치 원본 512 MiB와 cold 복사본 두 개 1 GiB다. 설치 매체는 128 MiB, 멤버 읽기 검증 파일은 실제 입력 바이트 합계로 최대 128 MiB, 호스트 검사기의 임시 이미지·파일 덤프는 각각 최대 512 MiB로 계산한다. 화면은 최대 1280×1024, 각 화면당 두 파일만 순환 사용한다. 네 VM과 호스트 검사기의 직렬·오류 로그 합계는 128 MiB로 제한한다. 메타데이터 64 MiB와 잘못된 한 프레임의 파일 크기 상한 512 MiB도 보수적으로 포함한다.

로그는 부모 프로세스가 실제 stdout·stderr 파이프를 계속 읽어 기록한다. 제한을 넘으면 증거 불완전과 실패를 기록하고 소유한 프로세스를 종료한다. 제한 때문에 실패 문구를 숨기거나 통과로 변경하지 않는다. 원본 입력, 기존 VM과 기존 증거는 삭제하지 않는다.

```bash
REPO=/path/to/Win98-Modern
RUN="$REPO/build/installer-vm-current"
PAYLOAD="$REPO/build/installer-payload-current"
QEMU=/path/to/NVMe-enabled/qemu-system-x86_64
QEMU_DATA=/path/to/selected-two-ROM-directory

python3 -B "$REPO/shizukudos/install/mkpayload.py" --desktop --out "$PAYLOAD"

python3 -B "$REPO/tools/test_shizukuos_installer_vm.py" \
  --capture-inputs "$REPO/build/installer-inputs-current.json" \
  --repo "$REPO" --build "$REPO/build/shizukudos" --payload "$PAYLOAD" \
  --qemu "$QEMU" --qemu-data "$QEMU_DATA" \
  --ovmf-code /usr/share/edk2/ovmf/OVMF_CODE.fd \
  --ovmf-vars /usr/share/edk2/ovmf/OVMF_VARS.fd \
  --seabios /usr/share/seabios/bios-256k.bin
```

출력의 입력 JSON SHA를 아래 `CAPTURE_SHA`에 넣는다. 기본 검증 후 같은 인자로 `--run --out`을 추가한다. VM당 제한은 기본 900초이며 30–3600초 범위로 조정할 수 있다.

```bash
CAPTURE_SHA=the_64_hex_digits_printed_by_capture
python3 -B "$REPO/tools/test_shizukuos_installer_vm.py" \
  --inputs "$REPO/build/installer-inputs-current.json" --inputs-sha256 "$CAPTURE_SHA"

python3 -B "$REPO/tools/test_shizukuos_installer_vm.py" \
  --inputs "$REPO/build/installer-inputs-current.json" --inputs-sha256 "$CAPTURE_SHA" \
  --run --out "$RUN" --timeout 900
```

## 증거와 판정

`result.json`은 실제로 시작한 VM 수와 각 단계 결과를 기록한다. VM마다 정확한 명령, 직렬 로그, QEMU 오류 로그, 새 VARS, 실제 QMP 화면을 보존한다. 화면은 실제 디스플레이의 두 연속 프레임이 일치할 때 사용하며, 선택·검토·취소 복귀·결과 및 데스크톱·편집기의 변화를 확인한다. 원본 빌드 입력, 읽기 전용 설치 매체와 설치 원본 디스크의 변경 여부도 확인한다.

모든 실제 VM은 `-S`로 첫 게스트 명령 이전에 정지한다. 실제 QOM frontend 모델과 backend 연결, PCI 장치, 소유한 QMP 연결의 raw 디스크 파일·크기·읽기 전용 여부·노드 ID를 확인하고 초기 쓰기 횟수·바이트 0을 기록한 뒤 실행한다. `isa-debug-exit` 장치는 연결하지 않는다. 현재 소스로 빌드된 게스트의 `sa_exit`는 파일시스템 종료 이후 `SHZ-EXIT:0`을 출력하고 `cli; hlt`로 끝난다. 러너는 실제 종료 문구 이후 VM을 정지해 마지막 디스크 통계를 확인한 뒤, 소유한 QMP 프로세스만 종료한다. 게스트의 종료 코드 0과 QMP quit 프로세스 코드 0을 기록하며 ISA exit1을 관찰했다고 표시하지 않는다.

일시 정지된 실제 QEMU의 호스트 제어 시험은 디스크 식별과 초기 통계 확인에 대한 증거다. 그 시험은 게스트 명령을 재개하지 않는다. HMP `qemu-io`의 직접 backend 쓰기는 게스트 frontend 통계에 반영되지 않으므로 전체 바이트 해시 검사도 별도로 유지한다. 실제 설치의 양수 쓰기 통계는 네 VM 게스트 시험에서 확인해야 한다. [QEMU의 qemu-io 구현](https://raw.githubusercontent.com/qemu/qemu/v10.1.0/qemu-io-cmds.c)을 참조한다.

`host-disk-audit.json`과 `.log`는 GPT·ESP·시스템 파일·설치 로그의 독립 확인 결과다. 호스트 검사는 300초, VM은 단계별 제한을 적용한다. 실패하면 부분 증거를 남기고 이 러너가 시작한 프로세스만 종료한다. 호스트 디스크 포맷이나 기존 VM 조작은 하지 않는다.

최종 성공 문구는 `PASS_ACTUAL_PRODUCTION_INSTALLER_VM_COMPONENT_GATE`다. 기존 전체 자동 시험의 `SETUP-RESULT: OK`나 생성자 로그만으로 이 판정을 만들 수 없다. 소스·호스트 검사만 완료한 경우에는 실제 VM 검증이 완료됐다고 보고하지 않는다. 실제 물리 USB 부팅 역시 이 VM 결과로 대신할 수 없다.

English: complete fresh component builds and a desktop installer payload, capture the explicit input paths and SHA-256 pins, validate them, then add `--run --out NEW_DIRECTORY`. The four cold VM runs test cancel-without-writes, the selected-disk installation, and installed UEFI/BIOS desktops. This is a Shizuku component gate; genuine Windows 98 boot and MS-DOS replacement remain separate acceptance requirements.
