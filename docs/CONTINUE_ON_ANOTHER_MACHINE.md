# 다른 환경에서 이어서 개발하기

공개 소스: <https://github.com/NiSeullent/Win98-Modern>. 제품 이름은 **Windows 98 Shizuku Modern Edition**입니다. 이 문서는 2026-10-01 개발 상태를 기준으로 소스부터 다시 시작하는 방법을 설명합니다. `main`의 실제 커밋을 기록하고, 옛 작업 폴더의 `build/`가 있다고 가정하지 마세요.

## 1. 소스와 작업 환경

```sh
git clone --branch main https://github.com/NiSeullent/Win98-Modern.git
cd Win98-Modern
git log -1 --format='%H %s'
git fetch origin '+refs/heads/*:refs/remotes/origin/*'
git switch -c codex/my-continuation
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r tests/requirements.txt -r tools/requirements-test-media.txt
```

위 설치 목록은 `pefile==2024.8.26`, `pycdlib==1.20.0`입니다. 빌드 도구는 별도로 준비합니다. 현재 확인한 기준 호스트는 x86-64 Linux이며 다음 버전을 사용했습니다. 이 표가 다른 버전의 성공을 보증하거나 모든 도구를 해당 버전으로 강제하는 것은 아닙니다.

| 용도 | 기준 도구 |
| --- | --- |
| 호스트 스크립트 | Python 3.12.14 |
| 독립 커널·펌웨어 | GCC 14.3.1, GNU binutils 2.41, NASM 2.16.01 |
| Windows PE32/PE32+ 교차 빌드 | i686/x86_64 MinGW-w64 GCC 15.1.1; 각각의 `dlltool`, `windres`, 헤더 |
| C++ ABI·호스트 검사·WASM | Clang 21.1.8, `clang++`, `lld-link`, `wasm-ld` |
| VM 시험 | QEMU 10.1.0, OVMF CODE/VARS; KVM을 쓰려면 `/dev/kvm` 접근 권한 |
| 웹 게임 검사 | Node 26.3.0 |
| DOS16·16비트 display driver | Open Watcom v2; 빌더가 프로젝트 내부에 준비 |

`git`, `make`, `patch`, `tar`, `xz`, `xxd`, `dpkg-deb`, mtools(`mformat/mmd/mcopy`), dosfstools(`mkfs.fat/fsck.fat`와 `mkfs.vfat/fsck.vfat`), `xorriso`도 필요합니다. GCC는 `-m32`/i486 대상 빌드를 지원해야 하고 MinGW에는 DDK 헤더(`ddk/wdm.h`)가 필요합니다. 추가 Wine 구성 도구는 해당 빌더가 보고하는 누락 항목을 설치하세요.

외부 소스 리비전과 라이선스는 `shizukudos/upstream/manifest.json`, `THIRD_PARTY.md`, 각 구성요소의 NOTICE에 있습니다. 빌더는 공개 업스트림을 `build/upstream/`, 도구를 `build/tools/`로 내려받습니다. Open Watcom의 `Last-CI-build` URL은 바뀌는 자료이므로 실제 사용 해시와 빌드 영수증을 보존해야 합니다. 다른 컴파일러로 같은 소스를 빌드했다는 사실만으로 기존 바이너리 해시와 일치한다고 주장하지 마세요.

## 2. 독립 Shizuku 커널과 데스크톱부터 빌드

저장소 루트에서 순서대로 실행합니다. 각 단계는 `build/`에 결과를 기록하며 DOS16 단계는 공개 FreeDOS/CSMWrap 소스를 가져올 수 있습니다.

```sh
python3 shizukudos/win64/build.py
python3 shizukudos/kbuild.py
python3 shizukudos/dos16/build.py
python3 shizukudos/supervisor/build.py
```

새 호스트의 실행 파일 위치를 선택합니다. 아래는 Debian/Ubuntu 경로 예시이며 기준 AlmaLinux/RHEL 호스트에서는 QEMU가 `/usr/libexec/qemu-kvm`, OVMF가 `/usr/share/edk2/ovmf/OVMF_CODE.fd`와 `OVMF_VARS.fd`였습니다. CODE와 VARS는 **같은 펌웨어 세트·크기**의 쌍을 사용합니다.

```sh
SHZ_QEMU=/usr/bin/qemu-system-x86_64
SHZ_OVMF_CODE=/usr/share/OVMF/OVMF_CODE_4M.fd
SHZ_OVMF_VARS=/usr/share/OVMF/OVMF_VARS_4M.fd

python3 shizukudos/tests/run_k64_gop.py \
  --qemu "$SHZ_QEMU" --firmware-code "$SHZ_OVMF_CODE" \
  --firmware-vars "$SHZ_OVMF_VARS" --display std --timeout 900 --png
python3 shizukudos/tests/run_k64_desktop.py \
  --qemu "$SHZ_QEMU" --firmware-code "$SHZ_OVMF_CODE" \
  --firmware-vars "$SHZ_OVMF_VARS" --accel tcg
```

데스크톱 시험은 실제 입력, 파일 저장·재열기, 자식 프로세스와 두 번의 콜드 부팅을 검사합니다. 이 경로의 `SHZDESK.EXE`와 Kernel64는 프로젝트의 **독립 환경**입니다. Microsoft Windows 98 Explorer 실행 증거로 합산하지 않습니다. 세부 기준은 [DESKTOP_BOOT.md](DESKTOP_BOOT.md)에 있습니다.

독립 환경의 설치 미디어를 만드는 순서:

```sh
python3 shizukudos/install/mkpayload.py --desktop --out build/install-desktop
python3 tools/build_shizuku_se_iso.py \
  --reuse-builds --desktop --setup build/install-desktop --skip-qemu
```

이 ISO와 설치기는 Shizuku 런타임용입니다. Windows 98 설치 파일을 자동으로 포함하는 완성 OS 배포본이 아닙니다. 설치 미디어·VM 시험은 각각 별도이며 빌드 성공만으로 부팅 성공을 판정하지 않습니다.

## 3. 실제 Windows 98 UEFI/GOP 개발

Microsoft Windows 98 SE 설치 매체·사용 권한·제품 키와 자신의 설치된 게스트가 필요합니다. 저장소나 공개 다운로드에는 Microsoft 설치 이미지, 제품 키, 설치된 Windows 가상 디스크, 소유권이 다른 앱 설치 파일이 들어 있지 않습니다. 새 환경에서는 합법적으로 가진 매체로 별도 설치본을 만들거나 자신의 비공개 체크포인트를 옮겨야 합니다.

공개 소스에서 GOP 펌웨어와 Windows 98 기본 그래픽 드라이버를 빌드할 수 있습니다.

```sh
python3 shizukudos/csm/build.py \
  --out build/shizukudos/csm-gop-anchor --firmware-gop
python3 drivers/shizuku_gop/build.py \
  --out build/shizukudos/shizuku-gop-anchor
```

실제 경로는 **OVMF → CSMWrap/SeaBIOS CSM16 → 원래 Win98 MBR/IO.SYS → Windows 98 VMM/GUI**입니다. 펌웨어의 GOP 프로필은 인접 `EFI/BOOT/csmwrap.ini`에 `gop_only=true`가 있어야 하며 `vga=`/`vgabios=`와 혼합하지 않습니다. 그 뒤 게스트의 디스플레이 어댑터 설치에서 `SHZGOP.INF`를 선택합니다. `SHZGOP.DRV`/`SHZGOP.VXD`는 유지된 고정 GOP 모드와 Windows DIBEngine을 사용합니다. [FIRMWARE_GOP.md](../shizukudos/csm/FIRMWARE_GOP.md), [드라이버 안내](../drivers/shizuku_gop/README.md), [실제 그래픽 검증](SHIZUKU_BASIC_GRAPHICS.md)을 먼저 확인하세요.

`shizukudos/csm/test_win98_uefi.py`는 새 일회용 디스크와 VARS를 만드는 기존 체크포인트용 시험기입니다. `--archive`, `--checkpoint-record`, `--snapshot`은 **자신의 실제 입력**이어야 합니다. 입력은 backing file 없는 2 GiB 이하 QCOW2의 단일 CRC64 XZ 압축과 선택한 내부 스냅샷이며 영수증은 archive 경로/해시 및 압축 해제 후 크기/해시를 검증합니다. 임의 ISO나 빈 디스크를 이 인수에 넣어 실행할 수 없습니다. 이동 후 경로가 바뀌면 실제 archive를 다시 검증하여 새 환경의 기록을 만드세요. 영수증의 해시를 통과시키려고 판정 조건을 삭제하지 마세요.

VM을 시작하기 전에 `python3 shizukudos/csm/test_win98_uefi.py --help`로 입력과 펌웨어 인수를 확인합니다. 같은 원본 디스크를 여러 VM에 쓰기 가능하게 연결하지 말고 자신의 비공개 복제본을 사용합니다. GOP 드라이버 설치, 콜드 부팅, 실제 모니터 화면, GDI 픽셀 판독, 앱 실행·저장·정상 종료는 별도 검사입니다. 과거 호스트의 `/root/.../build/...` 파일은 새 클론에 자동으로 생기지 않습니다.

## 4. 현재 확인한 범위와 남은 목표

| 항목 | 2026-10-01 기준 |
| --- | --- |
| 실제 Windows 98 SE UEFI/forced-GOP | Q35/KVM의 1280×800×32 고정 모드에서 GUI·GDI fill/copy/readback 확인 |
| Notepad++ 8.9.8.1 x86 | 실제 Win98 GOP에서 편집·Save As·재열기·콜드 재열기·정상 종료를 제한된 구성으로 확인. 별도 native field interpreter/KernelEx·Unicode Layer 수동 전제 필요 |
| VLC 3.0.24 x86 | 실제 Win98 GOP의 Qt UI와 소프트웨어 AVI 영상 프레임 확인. 정상 종료 시 RPCRT4 오류가 남아 전체 PASS 아님. 오디오·GPU 가속 미완료 |
| Legcord/Discord | 별도 Kernel64의 초기 설정 UI 진전은 실제 Win98 Discord 로그인·채팅 성공을 뜻하지 않음 |
| Chromium·Supermium·LibreOffice·Steam·VS Code | 소스·로더·API·개별 제어 시험 진행 중. 필수 기능 전체 성공 미확인 |
| Dead Screen | 같은 C 소스의 웹 Tetris/Suika 미리보기 공개. 독립 Kernel64 fatal 통합 후보의 native 시험/기본 통합, Win98 VMM 오류 분류는 별도 미완료 |
| 드라이버·가속 | 기본 GOP는 소프트웨어 경로. GPU 3D, 전체 저장·USB·네트워크·입력·광범위 실기기 지원은 남은 목표 |

앱의 고정 입력은 아래 표와 [TARGET_APPS.md](TARGET_APPS.md)에 있습니다. 이 날짜의 자료를 계속 시험할 때는 원본 배포처와 해시를 맞추세요. 이후 최신 버전으로 목표를 갱신한다면 새 배포처·버전·아키텍처·해시·출처를 먼저 기록하고 별도로 검증합니다.

| 필수 앱 | 고정한 입력 |
| --- | --- |
| Chromium | 157.0.8080.0 x86, 공식 snapshot 1707946 |
| Legcord/Discord | Legcord 1.3.0 ia32, 릴리스 Electron 43.2.0 |
| 오픈소스 Office | LibreOffice 26.8.0, Windows x86-64/ARM64 배포 자료 |
| Steam | win64 manifest 1788652215; AMD64 bootstrap와 실제 클라이언트 호환성 작업 |
| Supermium | 144 R5 x86 |
| VLC | 3.0.24 x86 |
| Notepad++ | 8.9.8.1 x86 |
| Visual Studio Code | 1.140.0 x64 |

8개 앱 모두, 정상 종료·영구 저장, 가속·드라이버·설치와 실제 Windows 98 자체 부팅이 완료 목표입니다. x64 앱을 Win98의 PE32 로더가 바로 실행한다고 가정하지 마세요. Supervisor/Kernel64 실행 영역과 실제 Win98 사이의 메모리·파일·화면·입력·네트워크 연결도 구현·검증 대상입니다. 계정이 필요한 Discord/Steam 기능은 실제 계정 세션으로 시험해야 합니다.

`experiments/20261001/`에는 진행 중인 Win98 Supervisor 기반과 Dead Screen 통합 패치·native 제어 소스를 보존합니다. 기본 빌드에 자동 활성화된 완료 기능으로 취급하지 마세요. RPC 수명 관찰자 등의 lab 도구는 원본 시스템 DLL·자신의 게스트와 정확한 해시가 필요하며, 과거 호스트 경로가 없는 상태에서 앱 전체 시험을 자동 재현하지는 않습니다.

Dead Screen의 독립 후보와 같은-C 웹 게임은 소스부터 별도로 빌드할 수 있습니다.

```sh
python3 shizukudos/dead_screen/build.py --out build/dead-screen-new
python3 shizukudos/dead_screen/wasm/build.py --out build/dead-screen-wasm-new
```

새 출력 디렉터리를 사용합니다. 과거 비공개 입력을 다시 확인하는 `--verify-history`는 해당 자료를 가진 개발자용 추가 검사입니다. 새 클론의 기본 소스 빌드 전제로 삼지 않습니다. 호스트 렌더·WASM 검사와 실제 kernel panic/#UD·게임 입력 시험은 구분합니다. 자세한 한계는 [Dead Screen 안내](../shizukudos/dead_screen/README.md)에 있습니다.

## 5. 한국어·영어 웹과 nginx

`site/`가 완성된 정적 웹 소스입니다. Node 패키지 설치나 별도 프런트엔드 빌드 없이 우선 로컬에서 확인할 수 있습니다.

```sh
python3 -m http.server 8080 --bind 127.0.0.1 --directory site
```

- 한국어 배포·기록 미리보기·게임: `/`, `/preview.html`, `/dead-screen.html`
- 영어 배포·기록 미리보기·게임: `/en/`, `/en/preview.html`, `/en/dead-screen.html`
- 실제 기록: `site/evidence/preview.json`, 원본 PNG; 영어 manifest는 같은 기록의 번역
- 소스/개발 패키지: `site/downloads/`; Windows 설치 ISO와 다름
- 웹 게임: `site/dead-screen-preview.wasm`; 재빌드 소스는 `shizukudos/dead_screen/wasm/`

기록 미리보기는 원본 게스트 캡처를 보여줍니다. 웹 게임 traceback은 명시적으로 예시이며 실제 OS 크래시나 Win98 VMM hook 증거가 아닙니다. 현재 연결된 라이브 VM이 있다고 표시하지 않습니다.

운영 nginx 파일은 `site/deploy/m98.nyase.kr.conf`와 `m98-locations.conf`입니다. 기존 호스트는 `/srv/m98/releases/<release>/site`의 불변 릴리스와 `/srv/m98/current` 링크, `/srv/m98/nginx/locations.conf`를 사용합니다. HTML은 캐시하지 않고 옛 `/vnc.html`·`/vnc_lite.html`은 배포 페이지로 보냅니다. 옛 VM은 별도 `/legacy-console/`에 있습니다.

새 nginx 호스트에서는 실제 문서 루트, 인증서, 공통 include, Cloudflare 전달 변수와 기존 console 존재 여부를 자신의 설정에 맞춥니다. 제공 vhost를 그대로 복사하면 기존 서버 전용 `/srv/conf.d/...`와 TLS 경로가 없을 수 있습니다. `site/deploy/publish_static.py`는 **이미 준비된 m98 origin**의 한정된 릴리스 교체·정확한 응답 해시 확인·롤백 도구이며 새 호스트 자동 구축기는 아닙니다. 비밀 키·로그인 정보·DNS 토큰은 커밋하지 않습니다.

공개 주소는 <https://m98.nyase.kr/>와 <https://m98.nyase.kr/en/>입니다. 루프백 origin/browser 검증은 완료했지만 자동 외부 요청은 Cloudflare challenge를 받았으므로 새 환경에서는 외부 브라우저 접근을 별도로 확인합니다. 자세한 운영 설명은 [M98_HOSTING.md](M98_HOSTING.md)에 있습니다.

## English quick start

Clone `main`, record its commit, and create a `codex/` branch. Use an x86-64 Linux build host with Python, GCC/binutils/NASM, both MinGW targets, Clang/LLD, FAT tools, xorriso, QEMU and a matching OVMF CODE/VARS pair. Run the four source builds in section 2, then the explicit GOP/desktop tests using your local firmware paths.

Those tests run standalone Shizuku Kernel64. Genuine Windows 98 tests additionally need your own licensed, installed Windows 98 SE media/checkpoint; Microsoft disks and keys are not distributed. Build the optional CSMWrap GOP profile and native SHZGOP driver using section 3. Preserve the original disk and run on private clones. Eight required applications, hardware acceleration, complete drivers and native Dead Screen integration remain active development goals.

For the bilingual website, serve `site/` locally. Deploy the same static tree through nginx after adapting the existing host-specific configuration. Recorded guest images and the same-C WebAssembly game preview have distinct scopes. Public downloads are development components and corresponding source, not a complete Windows OS installer.
