# Windows 98 domain: explicit opt-in

ShizukuDOS는 Windows 98에서 MS-DOS를 대체하기 위한 기반이며 Kernel32와 Kernel64는 그 구성요소입니다. 이 경로는 Windows 98과 Kernel64가 함께 실행될 수 있는 Supervisor 연결을 준비합니다. **현재는 사용자 디스크의 기존 DOS를 실행하는 경로이며 MS-DOS 대체, Windows GUI, VMM 연결, 최신 앱 실행 완료를 뜻하지 않습니다.** 기본 DOS10 부팅과 개발자 conformance 부팅은 별도 입력을 유지합니다.

`WIN98CFG.BIN`이 없으면 기존 DOS 부팅을 사용합니다. 정확한 16바이트 설정을 제공할 때만 UEFI `mode=supervisor`에서 WIN98 도메인을 만듭니다. 설정은 little-endian `{0x38395753, 1, 128, 0}`이며 다른 버전·크기·예약값은 거부합니다. SeaBIOS의 실제 재설정 벡터에서 시작하도록 VMCS를 만들고 실제 ATA PIO, IRQ14/PIC, bounded REP PIO와 386 non-PAE 페이지 접근을 처리합니다. Windows 저위 메모리 `0x7000`에 Shizuku bootinfo를 쓰지 않습니다. VxD는 `SHZ_HC_CHANNEL_INFO`로 실제 WIN98↔K64 채널을 조회합니다. Windows 채널만 있을 때 K64가 K32 전용 자가 시험을 실행하지 않습니다.

## Public source checks

Linux에서 Python 3.8 이상, GCC/binutils, NASM, `x86_64-w64-mingw32-gcc`가 필요합니다. 호스트 C 검증은 GCC strict 빌드와 Clang ASan/UBSan을 사용합니다. mtools·dosfstools는 개인 ESP 생성 단계에만 필요합니다. 자동 설치, 다운로드, VM 실행은 없습니다.

```sh
mkdir -p build
python3 shizukudos/supervisor/native_win98/tests/test_inputs.py
python3 shizukudos/supervisor/native_win98/tests/test_vm_preparation.py
python3 shizukudos/supervisor/native_win98/tests/run_host.py --out build/win98-host-checks
python3 shizukudos/supervisor/native_win98/compile.py --out build/win98-components
```

출력 폴더는 새 폴더여야 합니다. `compile.py`는 현재 소스로 전체 freestanding Supervisor payload와 PE32+ EFI loader를 컴파일하고 소스의 실행 전후 해시를 기록합니다. Windows 디스크 없이 실행됩니다. C fixture는 실제 장치/페이지/생성자/채널 함수 본문을 실행하되 EPT/VMCS 및 특권 명령 경계는 모델링합니다. 실제 Windows 부팅 검증은 아닙니다.

## Private installed-disk preparation

사용자에게 사용 권한이 있는 **이미 설치된 정확히 2 GiB raw MBR 디스크**, 정확히 256 KiB SeaBIOS ROM, 설정 파일이 필요합니다. ISO 설치 매체는 이 디스크 입력이 아닙니다. MBR 서명과 SHA를 검사해도 Windows 설치 여부가 증명되지는 않습니다. 디스크의 운영체제 버전, 설치된 NTWRAP9X.VXD/연결 도구와 원본 매체 식별은 실제 게스트 검증 전에 따로 확인해야 합니다. BIOS 그래픽·입력 장치 및 VMM 연결은 아직 실제 부팅 검증이 필요합니다.

```sh
python3 shizukudos/supervisor/native_win98/build.py --make-config /tmp/WIN98CFG.BIN
sha256sum /absolute/owned-win98.raw /absolute/seabios.bin /tmp/WIN98CFG.BIN
python3 shizukudos/supervisor/native_win98/build.py \
  --disk /absolute/owned-win98.raw --disk-sha256 DISK_SHA256 \
  --rom /absolute/seabios.bin --rom-sha256 ROM_SHA256 \
  --config /tmp/WIN98CFG.BIN --config-sha256 CONFIG_SHA256 \
  --validate-only
```

확인한 해시 64자리를 각 placeholder에 넣습니다. 새 설정 파일 경로도 이미 존재하면 덮어쓰지 않습니다. 생성하려면 `--validate-only`를 `--out /absolute/new-private-output`으로 바꿉니다. 소스 저장소 안의 개인 출력은 Git ignored `build/` 아래만 허용합니다. 저장소 밖의 새 출력 폴더도 허용합니다. 최소 17 GiB 여유 공간을 유지하면서 추가 7 GiB 작업 예산을 요구합니다. 심볼릭 링크, 장치/가상 파일 시스템, FIFO, 다른 writer가 열어 둔 입력은 거부합니다. Linux read lease가 제공되지 않는 파일 시스템에서는 생성을 거부하며 검사 강도를 낮추지 않습니다.

선택 입력은 `--kernel32 ... --kernel32-sha256 ...`, `--kernel64 ... --kernel64-sha256 ...`, `--win64-img ... --win64-img-sha256 ...`입니다. K64에는 Supervisor용 **KERNEL64.BIN**을 사용합니다. 독립 부팅용 KERNEL64S.BIN은 이 입력이 아닙니다. WIN64.IMG는 K64 입력이 있어야 하며 현재 64 MiB K64 RAM/32 MiB archive 위치에 맞도록 최대 32 MiB로 제한합니다. 이 입력은 호출자가 별도로 빌드한 파일이며 builder가 K64 전체나 Win64 앱을 새로 컴파일했다고 주장하지 않습니다. Kernel32/64가 없으면 해당 도메인과 IPC 채널도 생성되지 않습니다.

Builder는 원본을 read lease와 SHA로 읽어 새 사본을 만들고, 공개 소스 사본에서 Supervisor를 새로 컴파일합니다. `esp-win98.img`에 설치한 모든 파일을 전부 다시 읽어 크기와 SHA를 확인합니다. 결과 영수증은 `private: true`이며 원본 입력 해시와 소스/컴파일/ESP 파일 목록을 기록합니다. 실패한 출력과 오류 영수증은 보존합니다. ROM·Windows 디스크·ESP·validation 이미지·개인 영수증은 GitHub 공개 소스 또는 공개 다운로드 묶음에 넣지 않습니다.

**게스트 시험은 별도입니다.** 필요한 것은 Intel VMX/EPT/Unrestricted Guest를 제공하는 격리된 4 GiB L1, 읽기 전용 원본의 새 ESP/VARS 사본, 입력별 SHA, 설치된 Windows/VxD 식별입니다. 실제 부팅 → Windows VMM 채널 → Windows GUI → 앱 실행 증거를 각각 확보해야 합니다. 현재 ATA 변경은 게스트 RAM에만 존재하며 원본 디스크에 영속 설치하거나 물리 디스크를 포맷하지 않습니다. 현재 표시 경로는 실제 B8000 텍스트를 렌더링합니다. Windows 그래픽·GOP 드라이버/가속 성과로 해석하면 안 됩니다.

실제 VM 시험 준비에는 `prepare_vm.py --esp ... --esp-sha256 ... --build-receipt ... --build-receipt-sha256 ... --firmware-code ... --firmware-code-sha256 ... --firmware-vars ... --firmware-vars-sha256 ... --qemu ... --qemu-sha256 ... --out ...`을 사용합니다. 모든 경로와 64자리 해시를 명시합니다. builder가 준비한 ESP와 성공 영수증이 일치해야 합니다. OVMF CODE/VARS는 합계가 정확히 4 MiB여야 합니다. 새 ESP/CODE/VARS 사본과 `vm-plan.json`을 만들고 원본별 크기·SHA, 실제 config/disk/SeaBIOS member identity, 4096 MiB/Intel VMX/no-NIC QEMU argv를 기록합니다. 이 도구는 VM을 실행하지 않습니다. **준비 이후 작업 책임자가 기록한 argv로 제한 시간·소유 프로세스 확인·실제 WIN98 도메인 관측을 포함한 VM 시험을 반드시 수행해야 합니다.** 독립 K64의 성공이나 호스트 fixture로 이 시험을 대신하지 않습니다. Windows GUI/VMM/앱과 DOS 대체 수락은 각각 실제 증거가 필요합니다.

## Provenance and remaining DOS replacement

실제 장치/생성자 소스는 보존된 `docs/shizukudos10/reports/checkpoint-20261001/native-win98-candidate/`에서 이식했습니다. 기본 Supervisor의 loader/domain/device seam에만 연결했고 개인 경로·과거 입력 해시·COMPILE 폴더가 고정된 historical `build_candidate.py`는 활성 builder로 사용하지 않습니다. 보존본과 과거 실행 증거는 수정하지 않습니다.

MS-DOS 대체의 다음 구현 지점은 ShizukuDOS의 실제 Windows용 volume 부팅과 `WIN.COM` 실행, DOS→VMM의 INT2F/DOSMGR/resident-state 계약입니다. pinned FreeDOS의 WIN31SUPPORT에는 미구현 instance/MCB 경로와 지나친 지원 응답이 있어 플래그만 켜서 완성이라 할 수 없습니다. 기존 `iosys_uefi`의 원본 IO.SYS→MSLOAD 연결과 이번 기존 DOS 경로는 대조군이며 최종 대체 결과와 구분합니다.

English quick start: run the public host tests and source-only component compile above. For a private ESP, pass your licensed installed 2 GiB raw disk, independently pinned 256 KiB SeaBIOS and freshly generated 16-byte config with all required SHA-256 values. `--validate-only` emits no media; `--out` prepares a private source-bound ESP and never launches a VM. This is a Windows-domain integration component for ShizukuDOS. Actual Windows boot, DOS replacement, VMM, GUI, acceleration and current apps remain unverified.
