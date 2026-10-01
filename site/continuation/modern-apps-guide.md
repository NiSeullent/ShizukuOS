# 다른 환경에서 Windows 98 Modern 작업 이어가기

이 문서는 2026-10-01 소스 인계 지점입니다. 목표는 **Windows 98의 MS-DOS 기반을 ShizukuDOS로 대체**하는 것입니다. Kernel32·Kernel64·호환 라이브러리·드라이버는 모두 Windows 98용 ShizukuDOS의 구성요소이며, 별도 커널 실행 시험은 이 통합 제품을 구현하기 위한 단계입니다. `main`에 통합하는 코드는 개발 중인 호환 커널과 공통 API 구현입니다. **Chrome·Chromium·Firefox·Discord/Legcord·Steam·최신 Office가 설치된 Windows 98에서 모두 동작한다는 완료 선언은 아닙니다.** 공개 자료에도 아래 검증 범위를 함께 표시합니다. 실제 기록의 SHA와 공개 입력 핀은 [checkpoint-20261001](shizukudos10/reports/checkpoint-20261001/)에 있습니다.

## 확인된 범위와 다음 작업

| 영역 | 실제 확인 결과 | 남은 작업 |
|---|---|---|
| V44 공통 런타임 | NTDLL·KERNEL32·UCRT 및 7개 시험 EXE 일반 빌드 완료. 변경된 PE의 import 443개 확인 | 이 빌드 성공 자체는 앱 실행 증거가 아님 |
| V44 게스트 API 시험 | 모듈 열거 45, 검색 경로 50, 토큰 19, UCRT 44, CreateFile2/CopyFile2 37, RTL 57: **252개 PASS** | 모두 독립 Kernel64 게스트 시험. 설치된 Win98 시험은 별도 |
| 네이티브 Supervisor 기반 | VMX/EPT, native K64, 실제 콘솔 PE 종료 코드 7 두 번 등 **37개 PASS** | 해당 실행의 도메인은 DOS16/K64. Win98 VMM 연결·현대 앱 실행은 미검증 |
| Chromium | headless 다중 프로세스에서 실제 JavaScript DOM `42`와 정상 종료 확인 | GUI V2는 157.0.8079.0/1706750: 화면 표시 후 공유 메모리 오류와 `c0000005` 종료. 페이지·웹 기능 미완료 |
| Firefox 157.0 | 정식 Mozilla 설치 파일 체크섬 및 원본 73개 파일 확인 | V42 실제 실행은 `mozglue!OpenProcessToken` import 실패. V44 토큰/RTL/file2 기반으로 다시 시험 |
| LibreOffice 26.8.0 | 정식 MSI 및 실제 26.8.0.3 앱 파일 확인 | V42 실제 실행은 `sal3!SetSearchPathMode` 실패. V44 이후 버전 출력, 문서 열기·편집·저장·PDF 변환 재시험 |
| Legcord 1.3.0 | 실제 Welcome 및 설정 화면 표시 | 설정 완료 후 실제 재실행, Discord 로그인·채팅·음성 미검증 |
| Steam | 원본 클라이언트 시작 및 누락 API 위치 확인 | V44의 Module32Next 시험은 통과. 실제 CEF·로그인·라이브러리·게임 실행 미검증 |
| Google Chrome | 정식 enterprise x64 MSI에서 브라우저 154.0.8037.93의 원본 267개 파일을 추출하고 전체 SHA·PE 버전 확인 | 게스트 실행과 브라우저 기능은 아직 미검증. 정식 metadata의 단계적 배포 버전과 구분 |
| 설치된 Win98 네이티브 통합 | opt-in Win98 생성자·ATA/PIC/문자열 PIO 구현 후보와 일반 native 링크 보존 | 실제 Win98 부팅·그래픽·입력·VMM 채널·앱 실행을 계속 구현/검증 |

Chromium GUI V2의 원본 기록은 잘못된 1708403 라벨을 포함합니다. 실제 패키지는 **1706750 / 157.0.8079.0**입니다. 원본 실패 기록은 보존하고 공개 요약에서 바로잡았습니다. 1708403 PDB를 1706750 DLL에 적용하면 안 됩니다. 기존 headless 기록은 이미지 경로로 1708403을 식별하지만 EXE/tree SHA를 기록하지 않았으므로, 최신 패키지 전체 provenance 확인 시험이 추가로 필요합니다.

V43의 MinGW stdio 링크 실패도 삭제하지 않았습니다. V44의 부모/자식 시험 소스는 기존 SHZ CRT를 사용해 실제 일반 링크를 통과했습니다. post-autorun 관찰의 세 가지 실제 대조 실행 및 Legcord 재실행 성공은 이 문서의 252개 API PASS에 포함되지 않습니다.

## 새 작업 환경

Linux x86-64에서 시작합니다. [공식 홈페이지](https://m98.nyase.kr/)의 해당 배포에서 소스 아카이브 또는 Git bundle과 체크섬을 받습니다. 실제 게시된 파일의 SHA-256과 source commit을 먼저 대조합니다. 소스 아카이브는 새 작업 폴더에 풀고, Git bundle을 받았다면 로컬 파일에서 복원합니다. 다음 예의 파일명은 자신이 받은 실제 bundle 이름으로 바꿉니다. 공식 페이지에 게시되지 않은 파일이 존재한다고 가정하지 않습니다.

```sh
git clone /path/to/official-source.bundle Win98-Modern
cd Win98-Modern
git checkout main
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r tests/requirements.txt
python3 -m pip install Pillow
```

필요한 실제 도구는 Python 3.10+, Git, GNU make, GCC/binutils(`gcc -m32` 컴파일 가능한 multilib 포함), NASM, **x86-64 및 i686 mingw-w64**의 GCC/G++·dlltool·windres, Windows 드라이버 빌드에 쓰는 해당 DDK 헤더, mtools, dosfstools, QEMU x86-64입니다. Wine 소스의 host 도구 생성에는 bison·flex·pkg-config와 개발 헤더가 필요할 수 있습니다. 전체 ISO에는 xorriso, CSMWrap 빌드 도구, DOS16용 Open Watcom이 추가됩니다. 패키지 이름은 Linux 배포판별로 다르며 이 문서는 전역 도구나 클라이언트 설정을 자동 변경하지 않습니다.

API 게스트 시험에는 접근 가능한 `/dev/kvm`이 필요합니다. native Supervisor의 VMX 시험에는 Intel VT-x/EPT와 **중첩 VMX가 실제 노출되는** 호스트 및 OVMF가 필요합니다. QEMU의 KVM 사용과 게스트 Supervisor의 VMX 동작은 각각 검증합니다. AMD에서 동일 native VMX 결과를 가정하지 않습니다. QEMU/OVMF 경로는 `shizukudos/tools/qemu.py`가 Fedora/RHEL 및 Debian/Ubuntu 위치에서 찾습니다. TCG 결과는 KVM 또는 native Supervisor 가속 증거로 계산하지 않습니다.

빌드/VM 출력은 `build/` 아래에서만 생성합니다. native Win98 실험은 여유 디스크 17 GiB를 남기며 복제·ESP·읽기 검증 예산을 추가로 확보합니다. 약 3–4 GiB 게스트 RAM 외에도 호스트에 최소 4 GiB를 남깁니다. 설치된 원본 VM은 종료 상태로 보관하고 각 시험은 독립 복사본을 사용합니다.

## 캐시 없는 일반 빌드와 API 시험

과거 개발 머신의 절대 경로, WIN64.IMG, Wine 캐시, 디스크 이미지는 clone에 없습니다. **처음에는 전체 일반 빌드를 실행**해 새 환경의 런타임과 import 라이브러리를 만듭니다. 기본 빌드는 [upstream manifest](../shizukudos/upstream/manifest.json)의 고정 Wine 소스 등을 `build/upstream/`에 가져와 필요한 host 도구/헤더와 PE DLL을 생성합니다. 해당 revision과 패치의 라이선스/출처를 유지합니다.

```sh
mkdir -p build
python3 -B shizukudos/win64/build.py > build/fresh-win64-build.log 2>&1
python3 -B tools/build_isolated_kernel.py --out build/modern-apps/fresh-kernel
```

첫 명령은 전체 runtime DLL·시험·`build/shizukudos/win64/WIN64.IMG` 및 `build-result.json`을 생성합니다. `--no-wineport` 빌드는 Wine 기반 DLL/폰트가 빠지므로 전체 앱용 런타임 대신 사용하지 않습니다. 이 새 환경의 전체 빌드는 아직 다시 실행하지 않았으므로 실패하면 로그와 실제 누락 의존성을 보존하고 해결합니다. 기존 개발 호스트의 V44 SHA를 새 빌드 결과에 붙이지 않습니다.

252개 계약 시험은 다음 여섯 이름으로 재현합니다. 각 실행은 입력 archive의 복사본과 새 기록 폴더를 사용합니다.

```sh
for test in T_MODULE_ANSI T_SEARCH_PATH_MODE T_BASE_TOKEN T_UCRT_LEGACY T_FILE2 T_RTL_BOOTSTRAP; do
  python3 -B shizukudos/tests/run_k64_contract.py \
    --runtime build/shizukudos/win64 \
    --kernel build/modern-apps/fresh-kernel/kernel64s \
    --test "$test.EXE" --accel kvm \
    --out "build/modern-apps/fresh-contract-$test" \
    --timeout 180 --guest-timeout 120 || break
done
```

확인은 `result.json`의 PASS, 실제 정상 앱 종료, `faulted=0`, PASS 행, 실패 없음, 입력 불변 및 현재 KVM 증거로 합니다. `isa-debug-exit` 때문에 QEMU 프로세스 코드 1이 정상 게스트 값 0을 나타낼 수 있습니다. 프로그램 자신의 실패 코드를 QEMU 종료 코드로 덮지 않습니다. `summary_check_count=0`인 기존 기록에서도 개별 `checks` 행을 확인합니다.

후속 부분 빌드는 **새로 생성한** archive를 base로 사용합니다. 아래 도구는 일반 import 라이브러리가 `build/shizukudos/win64/`에 존재해야 합니다. 컴파일하는 동안 관련 소스·헤더·라이브러리를 수정하지 않습니다.

```sh
python3 -B tools/build_frozen_native_subset.py \
  --base build/shizukudos/win64/WIN64.IMG \
  --out build/modern-apps/fresh-common-subset \
  --ntdll --kernel32 --module ucrtbase \
  --test t_module_ansi --test t_search_path_mode --test t_base_token \
  --test t_autorun_observe --test t_ucrt_legacy --test t_file2 \
  --test t_rtl_bootstrap --compile-timeout 900
```

출력 `receipt.json`은 소비한 소스·실제 명령·원본/새 archive SHA·변경 PE·import 확인을 기록합니다. 오래된 NTDLL 494개 ordinal과 Nt/Zw 로컬 별칭, UCRT 861개 ordinal 보존도 실제 PE로 확인합니다. host 계약 검사는 각 시험 README와 다음 도구를 사용합니다.

```sh
python3 -B shizukudos/win64/tests/test_ucrt_legacy_host.py --output-dir build/modern-apps/fresh-ucrt-host
python3 -B shizukudos/win64/tests/test_rtl_bootstrap_host.py --output-dir build/modern-apps/fresh-rtl-host
python3 -B shizukudos/win64/tests/test_module_ansi_host.py \
  --win64-root shizukudos/win64 --output-dir build/modern-apps/fresh-module-host
```

## 정식 앱을 직접 확보하고 다시 시험

정식 URL, 크기, SHA-256, revision은 [publisher-input-pins.json](shizukudos10/reports/checkpoint-20261001/publisher-input-pins.json)에 있습니다. 이동하는 “latest” URL 대신 해당 시험의 버전을 고정합니다. 새 버전을 쓰면 공식 체크섬/REVISIONS, 전체 파일 목록, 실제 PE 버전과 EXE SHA를 새로 기록합니다. 다운로드·원본 앱·Microsoft VC DLL은 개인 입력 폴더에 두고 커밋하거나 ISO에 넣지 않습니다.

- Chromium: 정식 `chrome-win.zip`과 같은 revision의 `REVISIONS`를 받아 안전하게 전체 추출합니다. 1708403은 157.0.8081.0이며 1706750은 157.0.8079.0입니다. ZIP SHA, 258개 전체 파일과 실제 PE identity를 혼합하지 않습니다.
- Firefox: 정식 157.0 한국어 x64 installer와 Mozilla `SHA512SUMS`를 검증합니다. 7-Zip 등으로 **설치 실행 없이** `core/`를 추출합니다. 실험에는 원본 73개 파일을 모두 사용합니다.
- Legcord: 정식 v1.3.0 win-x64 ZIP을 전체 추출합니다. Electron 43.2/Chrome 150이 포함된 앱 자체 패키지입니다. Welcome만으로 Discord 기능을 인증하지 않습니다.
- LibreOffice: 정식 26.8.0 x64 MSI를 `msiextract` 등으로 개인 폴더에 추출합니다. 필요한 app-local VC 14.44.35211 DLL은 자신의 정식 MSI/redistributable에서 확보하고 각 DLL SHA를 기록합니다. 실제 버전·ODT/PDF 왕복 시험을 순서대로 합니다.
- Steam: Valve의 정식 client 설치/패키지를 개인 환경에서 확보합니다. 기존 5624개 파일 클라이언트 시험은 설치 bootstrap을 건너뛴 별도 진단이며 신규 설치 성공이 아닙니다.
- Google Chrome: 공식 enterprise MSI URL은 이동합니다. 기록된 SHA와 일치하지 않으면 다른 패키지로 취급하고 실제 브라우저 PE 버전부터 확인합니다. MSI 다운로드 성공은 Chrome 실행 성공이 아닙니다.

**Chromium/Chrome/Electron/Legcord 실행 인자에는 `--no-sandbox`가 필수**입니다. Steam에는 `--no-sandbox -no-cef-sandbox`를 유지합니다. Firefox에서 같은 인자가 실제 sandbox를 끈다고 가정하지 않습니다. 해당 Mozilla 소스의 `MOZ_DISABLE_CONTENT_SANDBOX` 등 실제 적용 경로를 확인하고 게스트 환경 설정으로 전달해야 합니다. SSL 검증 생략, 거짓 OS/API 성공 응답이나 단일 프로세스 강제로 다중 프로세스 성공을 대체하지 않습니다.

일반 앱 도구는 `shizukudos/tests/run_k64_chromium.py`, `run_k64_electron.py`, `run_k64_productivity.py`입니다. 기본 입력 위치는 **이번 환경에서 생성한** `build/shizukudos/{kernel64s,win64}`입니다. 필요하면 일반 `python3 shizukudos/kbuild.py`로 기본 Kernel64S 출력을 생성하거나 도구의 source-defined 입력 경로를 확인한 독립 runner를 사용합니다. 소스 내 과거 scratch 기본값 대신 `--tree/--chromium`, `--image`, `--out`을 명시합니다.

GUI 도구 `tools/capture_chromium_interactive_v3.py`와 `tools/capture_modern_app_interactive_v5.py`는 기존 검토 시점의 runner SHA를 고정한 역사적 도구입니다. 이번 병합에서 runner가 변경되면 import 단계에서 정상적으로 중단하므로 새 clone에서 바로 실행할 수 있다고 가정하지 않습니다. 현재 runner의 인자·입력·판정 및 host 계약을 검토한 **새 capture epoch**를 만들어야 하며, 이전 SHA를 무조건 갱신하거나 gate를 지우지 않습니다. Chromium 새 도구는 `--publisher-manifest --publisher-revisions`와 전체 258개 파일 identity를 확인하고, 완전한 파일 핀이 없는 manifest에는 원본 `--publisher-archive` 검증도 요구합니다. 실제 화면을 확인한 뒤 입력과 화면 generation/sequence를 기록합니다. post-autorun 추가 관찰은 K14 기능의 실제 대조 시험을 마친 뒤 사용합니다.

공식 public CA를 실제 crypto 경로로 적재하는 시험 helper가 별도로 필요합니다. `tools/seal_carried_public_trust.py`는 **과거 receipt와 원본 CA payload가 있는 환경의 인계 도구**이며 새 clone에서 자동 CA 생성/설치를 수행하지 않습니다. 같은 이름의 파일이나 임의 인증서를 넣어 기존 해시 검증을 우회하지 않습니다.

## 네이티브 Win98 후보 소스 이어가기

[candidate source/manifest](shizukudos10/reports/checkpoint-20261001/native-win98-candidate/manifest.json)는 검토된 Supervisor 후보 18개, generic K64 peer-dispatch 소스 2개와 해당 diff를 보존합니다. 실험중인 구현을 잃지 않도록 **별도 후보 위치**에 넣었으며 기본 Supervisor·shared ABI를 바꾸지 않습니다.

ATA/PIC/REP PIO와 생성자 host 시험 및 일반 native 링크는 확인됐지만 실제 설치된 Win98 부팅은 아직 아닙니다. 후보는 128 MiB 실제 guest RAM, 자신의 설치된 2 GiB disk, 실제 256 KiB SeaBIOS ROM, opt-in 16-byte `WIN98CFG.BIN`/`mode=supervisor`를 사용합니다. 실제 graphics/input/VMM 연결은 후속 작업입니다. generic dispatcher는 실제 K32 peer 존재 여부를 검사해 Win98 채널을 K32 selftest peer로 오인하지 않도록 하는 후보이며 아직 VM 실행 검증이 없습니다.

후보의 `build_candidate.py`는 과거 고정 build receipt를 소비하는 참고 스크립트입니다. 공개본에서는 개발 머신의 cold-disk 절대 경로를 명시적 placeholder로 바꿨고 변경 전/후 SHA를 manifest에 구분했습니다. **그대로 실행할 fresh-clone producer가 아닙니다.** 격리 worktree에서 현재 소스와 ABI를 비교해 후보를 적용하고, 자신의 정당한 Win98 disk/SeaBIOS/OVMF를 인자로 받는 producer를 만든 뒤 모든 일반 빌드와 source/artifact receipt를 재생성합니다. 과거 영수증에 새 입력을 끼워 넣거나 hash gate를 제거하지 않습니다.

`tools/build_native_supervisor_foundation.py`는 일반 native 기반 producer지만 `tools/run_native_supervisor_foundation.py`와 `tools/run_autorun_observe_contrast.py`도 역사적 K13/K14/fixture 핀을 소비합니다. 새 환경에서는 그 입력을 명시한 새 source epoch/검증 도구가 필요합니다. 이 문서는 무조건 성공하는 자동 재개 스크립트를 약속하지 않습니다.

## ISO 생성과 공개/개인 미디어 구분

프로젝트 미디어는 라이선스와 해당 소스를 포함하는 Linux 일반 builder로 생성합니다. 다음은 기존 캐시 대신 필요한 source build를 수행하는 경로입니다.

```sh
SOURCE_DATE_EPOCH=1785283200 python3 -B tools/build_shizuku_se_iso.py \
  --desktop --output build/final-iso/windows98-shizuku-development.iso
```

이 빌드는 xorriso·mtools·dosfstools, 실제 GCC/MinGW/NASM 및 DOS16용 Open Watcom, manifest에 고정된 FreeDOS/FreeCOM·CSMWrap/SeaBIOS·syslinux를 요구합니다. 필요 도구가 없으면 설치 완료로 가장하지 않고 멈춥니다. `--reuse-builds`는 이미 일반 빌드와 현재 receipt를 확인한 환경에서만 사용합니다. ISO builder는 부팅 성공을 인증하지 않으며 실제 BIOS/UEFI boot matrix가 별도입니다. 최종 배포 환경의 manifest·SHA 및 부팅 기록을 확인합니다.

자신의 라이선스가 있는 Windows 98 설치 미디어를 포함한 **개인 ISO**는 별도 생성합니다.

```sh
python3 -B tools/build_shizuku_se_iso.py \
  --desktop --win98-media /path/to/your/licensed-win98.iso \
  --output build/windows98-shizuku-second-edition-private.iso
```

공개 GitHub/공식 페이지/공개 ISO에는 Microsoft 설치 파일·제품 키·VC redistributable·앱 archive·설치 VM disk를 넣지 않습니다. 공개 ISO는 프로젝트 boot/runtime/overlay와 재현 소스입니다. 개인 ISO 또는 VM을 만들 때는 원본 부팅 가능한 disk를 보관하고 독립 복사본만 수정합니다.

설치 USB에는 공개 미디어의 전체 구성과 EFI 파일을 최상위에 복사하고 본인의 Windows 98 ISO를 `OWNMEDIA/WIN98.ISO`에 넣습니다. 실제 파일 준비·원본 보존·읽기 대조 도구와 개인 통합 ISO 명령은 [INSTALL_USB.md](INSTALL_USB.md)에 있습니다. 파일이 담겼다는 결과를 Windows Setup이나 MS-DOS 대체 부팅 성공으로 계산하지 않습니다. 최종 Windows 98 설치와 부팅 경로에서 ShizukuDOS가 실제 DOS 커널과 서비스를 제공해야 합니다.

## 병합 후 작업 순서

현재 `main`을 clone한 상태에서 이 문서의 일반 빌드와 6개 API 계약을 먼저 재현합니다. 그 다음 V44 기반 Firefox/Office/Steam을 다시 시작해 실제 다음 실패를 기록하고 공통 기능으로 수정합니다. Chromium은 정확한 publisher identity로 GUI와 headless를 각각 실행하고 공유 메모리 동작을 조사합니다. Legcord는 실제 setup finish/relaunch와 Discord 기능, native Win98는 부팅 → VMM 채널 → framebuffer/input → 앱 실행 순서로 닫습니다.

과거 여러 작업 환경은 apps·boot/site·theme/TLS·validation·ISO 역할로 나뉘었습니다. 병합 시 최신 boot/site 소스를 오래된 apps 사본으로 덮지 않습니다. 새 에이전트도 파일·VM 소유권을 분리하고 소비 source epoch를 동결합니다. 공개 자료의 PASS는 표시된 시험 범위에만 적용하며 전체 앱 목표는 계속 유지합니다.

## 공개 배포를 서버 밖에서 확인

최종 ISO를 공식 페이지에 배포한 뒤 `tools/verify_m98_public.py`에 배포 manifest의 실제 파일명·SHA256·바이트 수를 전달합니다. 이 도구는 공개 DNS와 정상 HTTPS 검증으로 한국어/영어 홈페이지, 예전 VNC 주소의 홈페이지 이동, Authorship/인계 페이지 및 **전체 ISO 다운로드 해시**를 확인합니다. 다른 머신에서 공식 소스에 담긴 이 도구를 직접 실행할 수 있으며 GitHub 실행 환경에 의존하지 않습니다. origin 주소를 강제로 넣거나 Cloudflare 확인 화면을 성공으로 계산하지 않습니다. 일반 HTTP 응답 검증이며 실제 브라우저 렌더링·OS 부팅 검증과 구분합니다. 실패 기록도 그대로 남깁니다.
