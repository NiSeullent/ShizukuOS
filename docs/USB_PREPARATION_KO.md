# USB로 준비하기

**Windows 98 Shizuku Modern Edition** 공개 파일 묶음과 **본인이 소유한 `WIN98.ISO`**를 같은 USB에 넣을 수 있습니다. 최상위 목표는 **ShizukuDOS가 MS-DOS를 대체하고 Windows 98을 부팅·확장하는 것**입니다. Kernel32·Kernel64·Supervisor는 모두 Windows 98을 위한 기반입니다. 현재 데스크톱 부팅은 이 구성요소의 검증 프로필이며 별도 제품 목표가 아닙니다.

공개 묶음은 검증용 데스크톱·런타임·동봉 드라이버·소스·라이선스를 담습니다. **MS-DOS 대체 부팅 연결과 Windows 98 설치 프로그램 연결은 추가 구현 중**입니다. 파일을 복사하는 작업과 Windows 98 설치 완료는 구별해야 합니다.

## 가장 간단한 파일 복사

1. [배포 페이지](https://m98.nyase.kr/)에서 실제 게시된 공개 **USB 파일 ZIP**을 받습니다. ISO를 ZIP처럼 풀어 쓰면 안 됩니다. USB ZIP은 ISO 내부의 EFI 부팅 이미지까지 풀어 준비하는 별도 결과물입니다.
2. 이미 준비된 **빈 FAT32 USB**를 사용합니다. ZIP 안의 모든 파일·폴더를 USB 루트에 풉니다. `EFI/BOOT/BOOTX64.EFI`와 `SHZDOS/`가 USB 루트 바로 아래에 있어야 합니다. 소스·라이선스 폴더도 함께 둡니다.
3. 본인 소유 Windows 98 ISO는 이름을 `WIN98.ISO`로 하여 USB 루트에 추가할 수 있습니다. 이때 그 USB는 **개인용**입니다. 원본 ISO를 추가한 폴더·ZIP·통합 ISO는 공개 저장소나 다운로드에 올리지 않습니다.
4. x64 UEFI 부팅 메뉴에서 USB를 선택합니다. 현재 부팅 구성은 Secure Boot를 끈 환경을 요구합니다. 이 경로에서 시작하는 화면은 **Windows 98용 Shizuku 구성요소 검증 데스크톱**입니다.

파일 복사는 BIOS용 USB 부트로더를 설치하지 않습니다. FAT32는 파일 하나당 4 GiB − 1 바이트를 허용합니다. 공개 ZIP 자체는 USB로 복사할 필요 없이 PC에서 풀면 됩니다. 실제 USB·보드에서의 부팅은 별도 검증 대상이며 자동으로 성공을 보증하지 않습니다.

`WIN98.ISO`를 넣었다고 Windows 98 Setup이 시작되지는 않습니다. 현재 Shizuku 설치 메뉴는 구성요소 검증 프로필을 설치하며, 선택한 대상 디스크에 기록합니다. `SHZSE/INSTALL.BAT`도 이미 설치된 Windows 98 안에 다섯 개의 시험 파일을 복사하는 도구입니다. Windows 98 설치기나 완성 드라이버 설치기가 아닙니다.

## 개발자가 공개 ZIP을 만드는 방법

Linux에서 Python 3, `xorriso`, mtools의 `mcopy`가 필요합니다. 준비 도구는 블록 장치·심볼릭 링크·기존 출력 덮어쓰기를 거부합니다. 실제 USB를 포맷하거나 장치에 이미지를 쓰는 기능이 없습니다.

먼저 공개 `--desktop` ISO와 그 빌드 JSON, **동일 파일·최종 소스 커밋**을 독립적으로 검사한 `tools/verify_public_iso.py` 결과 JSON을 준비합니다. 이 준비 도구가 검증기를 대신 실행하지는 않습니다. 세 입력의 SHA-256·크기·소스 커밋이 맞아야 합니다.

```sh
mkdir -p "$HOME/shizuku-output"
python3 tools/prepare_shizuku_usb.py public \
  --iso /path/to/public-desktop.iso \
  --receipt /path/to/public-desktop.json \
  --verification /path/to/public-iso-check/result.json \
  --output "$HOME/shizuku-output/usb-public" \
  --zip "$HOME/shizuku-output/Windows98ShizukuModernEdition-USB-files.zip"
```

출력 폴더·ZIP은 새 경로여야 합니다. ISO의 전체 `HASHES.TXT`와 EFI 이미지의 구성원 영수증을 대조하여 파일별 바이트·SHA-256을 검사합니다. 부팅 설정은 원래 ISO의 바이트를 그대로 유지합니다. `SHIZUKU-USB.json`은 모든 결과 파일의 해시와 공개 ISO·소스 커밋을 기록하며 **USB 부팅 성공을 주장하지 않습니다**.

## 본인 ISO를 검증해서 개인용 폴더 만들기

```sh
python3 tools/prepare_shizuku_usb.py add-win98 \
  --bundle "$HOME/shizuku-output/usb-public" \
  --win98-iso /path/to/my-own-windows98.iso \
  --output "$HOME/shizuku-output/usb-personal"
```

공개 폴더는 유지하고 새 개인용 폴더를 만듭니다. 그 안의 루트 `WIN98.ISO`는 원본과 바이트·SHA-256이 동일해야 합니다. `WIN98-MEDIA.json`은 ISO의 SHA-256·크기·ISO9660 라벨·파일/CAB 개수와 필요한 DOS 파일의 위치를 기록합니다. 라벨만으로 제품의 진위·에디션·사용 권한을 판정하지 않습니다. `SHIZUKU-USB.json`에는 `private: true`가 기록됩니다. 이 개인 폴더 전체를 USB 루트로 복사하세요.

검증은 ISO9660을 읽을 수 있는지, `WIN98` CAB 폴더와 `IO.SYS`·`MSDOS.SYS`·`COMMAND.COM`이 파일 또는 CAB의 이름 목록에 있는지 확인합니다. CAB 압축 해제·제품 진위·Windows 버전까지 검증하지는 않습니다. `SETUP.EXE`의 존재는 별도로 기록하며, 그 정보가 설치 부팅 지원을 뜻하지는 않습니다. ISO를 넣어 둔 상태에서 DOS가 그 ISO를 드라이브로 연결해 주는 기능도 아직 없습니다.

이 DOS 원본 파일 요구는 **임시 기존 매체 경로의 실제 한계**입니다. ShizukuDOS가 MS-DOS를 대체하는 설계를 철회한 것이 아닙니다. 원래 설치 매체를 보존한 채 Windows 98 GUI·커널 브리지까지 이어지는 대체 부팅 경로를 완성해야 합니다.

## 개인용 통합 ISO를 한 번에 준비

소스 클론의 빌드 도구·컴파일러·공개 업스트림 준비가 필요합니다. [다른 환경에서 이어가기](CONTINUE_ON_ANOTHER_MACHINE.md)를 참고하세요. 출력은 공개 소스 폴더 **밖의 새 `-private.iso`**로 지정합니다.

```sh
python3 tools/prepare_shizuku_usb.py private-iso \
  --repo /path/to/Win98-Modern \
  --win98-iso /path/to/my-own-windows98.iso \
  --output "$HOME/shizuku-output/shizuku-with-my-win98-private.iso"
```

이 명령은 먼저 본인 ISO를 검증하고 기존 `build_shizuku_se_iso.py --desktop --win98-media`를 실행합니다. 소스 클론의 `build/`에 빌드 결과와 임시 개인 미디어를 쓰고, 필요한 공개 빌드 소스를 내려받을 수 있습니다. VM·호스트 디스크 포맷·장치 이미지 쓰기를 실행하지 않습니다. 정확한 현재 소스에서 만든 기존 빌드 영수증이 있을 때만 `--reuse-builds`를 추가하세요. 실행할 명령만 먼저 보려면 `private-iso` 대신 `private-command`를 사용합니다.

통합 ISO에는 기존 구성요소 검증 부팅 구성과 `WIN98/` 아래의 Windows 원본 파일이 들어갑니다. ShizukuDOS의 대체 부팅·Windows 98 Setup 연결은 추가 구현 중입니다. 출력 ISO·JSON·`.media.json`은 모두 개인용이며 공개하지 않습니다. 빌더는 파일 배치를 확인하지만, Windows 98을 설치하거나 전체 앱을 검증하지 않습니다.

실제 Windows 98 UEFI/GOP 경로, Chromium·Legcord·LibreOffice·Steam·Supermium·VLC·Notepad++·VS Code, 가속·드라이버·native Dead Screen 목표는 계속 남아 있습니다. 이 묶음의 생성 성공을 해당 목표의 완료로 표시하지 않습니다.

English: [USB_PREPARATION_EN.md](USB_PREPARATION_EN.md).
