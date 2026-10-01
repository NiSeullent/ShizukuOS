# Windows 98용 ShizukuDOS 설치 USB 조합

목표는 **Windows 98의 MS-DOS 기반을 ShizukuDOS로 대체**하고 Kernel32, Kernel64, 호환 라이브러리와 드라이버를 그 안에 통합하는 것입니다. Kernel32와 Kernel64도 Windows 98용 ShizukuDOS의 구성요소입니다. 현재 미디어에 담긴 별도 실행 시험을 이 통합 제품의 완성으로 계산하지 않습니다.

공식 배포는 [m98.nyase.kr](https://m98.nyase.kr/)에서 받습니다. 공개 ShizukuDOS ISO 또는 USB 파일 묶음에는 프로젝트 런타임·설치 프로그램·배포 가능한 구성요소·라이선스·대응 소스가 들어갑니다. **사용자 소유 Windows 98 ISO는 USB의 `OWNMEDIA/WIN98.ISO`에 직접 복사**합니다. 이렇게 조합한 USB와 개인 통합 ISO는 개인용입니다. Windows 설치 미디어나 제품 키를 공홈에 올리지 않습니다.

## 파일 복사 방식

공홈에 게시된 **USB 파일 묶음**을 받은 경우 압축을 풀어 내용물을 FAT32 USB 파티션의 **최상위**에 복사합니다. 묶음 폴더 자체를 USB에 넣지 않습니다. UEFI 펌웨어가 이 파티션을 부팅 가능한 FAT32 시스템 파티션으로 인식해야 합니다. 이미 있는 USB 파티션을 포맷하거나 부트 섹터를 쓰는 작업은 helper가 하지 않습니다.

공개 ISO만 받은 경우 아래 helper로 같은 파일 묶음을 만들 수 있습니다. 준비는 Python 3, `xorriso`, `mtools`가 있는 Linux 또는 WSL 환경에서 합니다. 완성된 파일 묶음을 USB에 복사하는 단계에는 Python이 필요하지 않습니다.

```bash
python3 prepare_install_usb.py stage \
  --iso windows98-shizuku-second-edition.iso \
  --receipt windows98-shizuku-second-edition.json \
  --out usb-copy
```

입력 ISO와 JSON은 같은 공식 배포의 파일이어야 합니다. helper는 ISO의 실제 SHA-256·크기, 공개 배포 표시, 실제 설치 payload 및 EFI 이미지 안의 **모든 파일**을 배포 receipt와 대조합니다. EFI 이미지에만 있던 부팅 파일을 최상위로 꺼내고, 모든 공개 ISO 파일·라이선스·소스도 그대로 보존합니다. 입력 ISO를 수정하지 않습니다.

자신의 Windows 98 ISO를 준비 단계에 함께 복사하려면 다음과 같이 실행합니다.

```bash
python3 prepare_install_usb.py stage \
  --iso windows98-shizuku-second-edition.iso \
  --receipt windows98-shizuku-second-edition.json \
  --win98-iso my-windows98.iso \
  --out usb-copy-private
```

또는 공개 파일 묶음을 USB에 복사한 뒤 `OWNMEDIA` 폴더를 만들고 자신의 ISO를 `WIN98.ISO`라는 이름으로 복사합니다. 결과의 주요 경로는 다음과 같습니다.

```text
USB 루트/
  EFI/BOOT/BOOTX64.EFI
  EFI/SHIZUKU/BOOT.INI
  EFI/SHIZUKU/CSMWRAP.EFI
  SHZDOS/                    ← Kernel32·Kernel64·DOS 이미지·Win64 runtime
  SHZ/K64/                   ← 현재 Kernel64 실행 경로
  SHZ/SETUP/                 ← 실제 ShizukuDOS 설치 payload
  SHZSE/                     ← Windows 98 호환 구성요소 설치 자료
  DRIVERS/
  ShizukuDOS10/LICENSES/
  ShizukuDOS10/SOURCE/
  OWNMEDIA/WIN98.ISO          ← 사용자가 직접 넣는 원본 ISO
  USB-MANIFEST.JSON
  USB-README.TXT
```

`EFI`와 `SHZDOS` 경로를 옮기지 않습니다. 현재 파일 복사 경로는 배포본의 `mode = kernel64` 정책을 보존하며 **UEFI의 Kernel64 직접 실행**을 준비합니다. BIOS용 부트 섹터는 파일 복사만으로 생기지 않습니다. BIOS에서도 부팅해야 한다면 공식 **hybrid ISO를 USB에 이미지로 기록**하는 방식을 사용합니다. 이미지 기록은 대상 USB 내용을 덮어쓰므로 평소 사용하는 미디어 기록 도구에서 대상 장치를 직접 선택합니다. 기존 ISO의 부팅 메뉴와 설치 설명은 [MEDIA.md](shizukudos10/MEDIA.md), [INSTALLER.md](shizukudos10/INSTALLER.md)에 있습니다.

FAT32에서 한 파일은 최대 **4 GiB − 1 byte**입니다. helper는 Windows ISO와 모든 추출 파일의 이 제한을 확인하고 이름 충돌·링크·기존 출력 폴더도 거부합니다. 준비 공간에 17 GiB 여유를 남깁니다.

USB에 복사가 끝났으면 helper로 원본 묶음과 사용자 ISO의 실제 파일을 다시 읽어 확인합니다. 다음은 파일 읽기만 수행합니다.

```bash
python3 prepare_install_usb.py verify --root /media/my-usb --with-win98
```

자신의 ISO를 넣지 않은 공개 묶음은 `--with-win98` 없이 검증할 수 있습니다. 읽기 결과에 자신의 ISO가 있으면 `private: true`로 표시합니다. 운영체제가 만든 추가 파일 등이 있으면 알려주며 묶음의 내용을 임의로 성공 처리하지 않습니다.

## 개인용 통합 ISO

원한다면 사용자가 제공한 정확한 Windows 98 ISO를 기존 통합 미디어 producer에 넣어 **개인용 hybrid ISO** 하나로 만들 수 있습니다. 공식 소스 묶음을 풀어 도구와 빌드 의존성을 준비한 다음, 다른 미디어 빌드가 실행 중이지 않은 개인 소스 작업 폴더에서 실행합니다.

```bash
python3 prepare_install_usb.py combine \
  --source-root ./Win98-Modern \
  --win98-iso ./usb-copy-private/OWNMEDIA/WIN98.ISO \
  --out ./windows98-shizuku-private.iso
```

이 명령을 **명시적으로 실행할 때만** 기존 `tools/build_shizuku_se_iso.py --desktop --win98-media ...`를 실행합니다. 해당 producer는 소스 작업 폴더의 `build/`에 구성요소와 작업 파일을 만들며 필요하면 manifest에 고정된 공개 upstream을 받습니다. 실제 Windows 미디어를 자신의 통합 ISO 안에 복사하고 원본과의 읽기 대조를 수행합니다. 원본 Windows ISO를 덮어쓰지 않습니다. 이미 같은 소스의 receipt와 일치하는 빌드 결과가 있으면 `--reuse-builds`를 추가할 수 있습니다. 원본 ISO의 해시·통합 ISO의 해시·producer receipt는 인접한 `.combination.json`에도 기록합니다. 출력은 새 파일이어야 하고, Git 작업 폴더 안에서는 무시되는 경로만 사용합니다.

기존 producer를 직접 호출하는 방법도 같습니다.

```bash
python3 tools/build_shizuku_se_iso.py --desktop \
  --win98-media /path/to/my-windows98.iso \
  --output build/windows98-shizuku-private.iso
```

## 현재 확인 범위

helper의 시험은 실제 ISO9660 파일과 FAT 이미지의 전체 추출·모든 EFI 파일 읽기 대조·원본 보존·잘못된 입력 거부를 확인하는 **호스트 미디어 준비 시험**입니다. 시험용 파일은 합성된 작은 데이터이며 Windows나 펌웨어를 실행한 결과가 아닙니다. 배포 최종 ISO 자체의 부팅·설치 결과는 그 배포의 별도 검증 기록을 확인합니다.

**USB에 저장한 `WIN98.ISO`를 현재 부팅 메뉴가 바로 마운트하거나 Windows 98 Setup을 실행하지는 않습니다.** 기존 DOS16 payload에는 SHSUCDHD/SHSUCDX 같은 ISO 파일 마운트 경로가 없고, memdisk 메뉴는 준비된 DOS·플로피 디스크 이미지를 사용합니다. 개인 통합 ISO의 `WIN98/`도 원본 설치 파일을 보존하는 조합이며 Windows Setup 부팅을 완료한 것으로 표시하지 않습니다. Windows 98에서 ShizukuDOS가 실제 MS-DOS를 대체하고 Kernel32/Kernel64·최신 앱과 통합되어 동작하는 검증은 추가로 필요합니다. manifest는 이 상태를 미검증으로 기록합니다.
