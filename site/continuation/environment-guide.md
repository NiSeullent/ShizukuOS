# 다른 환경에서 이어서 작업하기

공식 배포처는 **[m98.nyase.kr](https://m98.nyase.kr)**입니다. 공홈의 소스
압축 파일 또는 `main` Git bundle로 작업을 옮길 수 있습니다. GitHub 접속은
필수가 아닙니다. 다운로드의 실제 파일명과 SHA256 목록은 공홈의 해당 배포
매니페스트를 사용하세요. 이 문서는 아직 제공되지 않은 파일의 다운로드를
완료했다고 주장하지 않습니다.

공홈에서 받은 파일을 빈 작업 디렉터리에 놓고 먼저 해시를 확인하세요.
아래 파일명은 예시이며, 배포 매니페스트에 적힌 실제 이름으로 바꿔야 합니다.

```sh
sha256sum --check SHA256SUMS
git clone --branch main ./Win98-Modern-main.bundle Win98-Modern
cd Win98-Modern
git rev-parse HEAD
python3 -B tools/check_continuation_environment.py
```

마지막 커밋은 배포 매니페스트의 커밋과 비교하세요. Git bundle 대신 소스
압축 파일을 풀어 편집해도 됩니다. 소스 압축 파일에는 Git 이력이 없을 수
있습니다. 원본 매니페스트와 해시를 함께 보관하세요.

## 준비해야 할 환경과 파일

기존 호스트 빌드는 Linux/POSIX와 Python 3을 사용했습니다. 새 환경의
검토·편집에는 Git과 Python 3.10 이상을 준비하고, 빌드 재현에는 기존에
기록된 Python 3.12 및 도구 버전을 먼저 확인하세요. Windows 호스트에서는
Linux VM 또는 WSL에서 호스트 작업을 할 수 있지만, 이 안내가 그 환경의
빌드 성공을 인증하지는 않습니다.

- 호스트 빌드: GCC/G++, Clang/Clang++, Make, CMake, Ninja, Bison, Flex,
  Patch, Tar와 Binutils. 전체 ASan/UBSan 런타임도 필요합니다. 기존 GLSL
  시도는 GCC ASan 라이브러리 누락으로 링크가 실패했습니다.
- PE 빌드: `i686-w64-mingw32-gcc`, G++와 Objdump. Win98 대상에서 배포판의
  미리 빌드된 C++ 런타임을 그대로 사용할 수 있다고 가정하면 안 됩니다.
- Python 빌드 의존성: `pefile`, PyYAML. GLSL 생성에는 분리된 Mako 1.4.3과
  MarkupSafe 2.1.3 증거 묶음이 필요합니다. 설치는 별도 환경에서 직접
  준비하며, 점검 도구는 설치하거나 모듈 코드를 실행하지 않습니다.
- 공개 원본: Mesa 26.2.3, QuickJS 2026-06-04, 고정 musl/WAMR 리비전,
  Mbed TLS 4.2.0 및 3.6.7, WABT 1.0.42. 공식 원본과 라이선스·고지문을
  보존하고 각 빌더의 고정 SHA256에 맞춰야 합니다. Mesa는
  [공식 아카이브](https://archive.mesa3d.org/), QuickJS는
  [공식 사이트](https://bellard.org/quickjs/)에서 확인할 수 있습니다.

**소스만 받아서는 기존 빌드가 바로 재현되지 않습니다.** `build/`, VM 디스크,
설치 매체와 로그는 Git에서 제외됩니다. 공홈의 별도 증거 묶음 또는 매니페스트
범위를 확인해 원본 아카이브, 도구 묶음, 준비된 소스, 객체 캐시, 영수증과
로그를 옮겨야 합니다. 캐시 파일의 존재가 해시·출처 검증을 대신하지 않습니다.
외부 컴파일러 전체 구성요소의 증거까지 완성된 것으로 간주하면 안 됩니다.

일부 도구는 `/root/Win98-Modern-boot` 및
`/root/Win98-Modern-tls13-7707`의 절대 경로와 이전 영수증을 사용합니다.
새 환경에서 누락된 경로를 임의로 대체하거나 이전 영수증을 수정하지 마세요.
매니페스트에 따른 원본 보존과 별도 새 경로 설정·증거 생성이 필요합니다.
점검에 다른 캐시 위치를 알려줄 수는 있으나 빌더 경로를 바꾸지는 않습니다.

```sh
python3 -B tools/check_continuation_environment.py --json
python3 -B tools/check_continuation_environment.py --verify-archives \
  --boot-root /ABSOLUTE/Win98-Modern-boot \
  --tls-root /ABSOLUTE/Win98-Modern-tls13-7707
```

Windows 설치 매체와 제품 키는 사용자가 정당한 라이선스로 로컬에서 준비해야
합니다. 소스 배포에 포함된다고 가정하지 마세요. 실제 Win98 시험에는 원본
OEM 파일, 준비된 게스트 디스크, QEMU와 해당 실험의 증거·실행 절차가 별도로
필요합니다. 점검 도구는 VM·서비스를 시작하지 않습니다.

## 이어받는 시점의 검증 상태

역사적 제한 프로파일에서 Script 307개 검사, 숫자 Wasm 265개 검사 및
한정된 MSHTML CSS 소비·화면 시험이 승인되었습니다. 새 환경이나 모든 웹
표준의 인증이 아닙니다. 수정된 TLS i486 호스트·PE 증거는 있으며, 수정 DLL의
실제 Win98 게스트 TLS 시험은 아직 대기 중입니다.

GLSL 9개 파일과 SIMD 6개 파일은 **DRAFT_UNVERIFIED**, 현재 세대의 빌드가
실행되지 않았습니다. 이전 GLSL 세대의 정상 전처리 비교 608개는 통과했지만
전체 sanitizer 링크 및 타입 컴파일 시도는 실패했고 그대로 보존되어 있습니다.
현재 타입 수정과 자원 보호 제어 시험도 실행되지 않았습니다. SIMD의 공개
Wasm 호출 ABI는 숫자 스칼라만 지원하며 벡터 경계는 미해결입니다. 벡터
export는 실행 전 거부하고, 벡터 import·벡터 GC 필드는 지원하지 않습니다.
새 엔진에서 기존 1237 숫자, 386 메모리, 4641 선택 공식 메모리, 622 QuickJS
메모리 검사를 정상 및 전체 ASan/UBSan으로 다시 실행해야 합니다.

HTML DOM, 전체 최신 JavaScript/CSS/Wasm, WebGL/WebGPU, 현대 앱 호환성 및
OS 전체는 인증되지 않았습니다. Legcord/Discord, 최신 오픈소스 Office,
Signal 지원은 계속 필요한 작업입니다. 상세 경계는 각 `docs/TRIDENT_*` 및
`docs/TLS13_I486_*` 문서, 실패 영수증과 고정 소스 프로파일을 함께 보세요.

큰 호스트 빌드 전에는 실제 여유 **22,595,387,392 바이트**와 Linux
`MemAvailable` **6 GiB** 이상을 확인하고 한 번에 하나의 큰 작업을 예약하세요.
512 MiB 실험 예산은 예상 성공 용량이 아닙니다. 실행 중 공유 디스크 바닥은
**22,058,516,480 바이트**이며, native 준비에서도 이 바닥을 유지해야 합니다.
각 빌더의 실제 제한·자기 프로세스 종료·실패 보존 절차를 적용해야 합니다.
점검 출력은 순간 측정으로, 빌드·native 실행 허가나 API 성공 증거가 아닙니다.

점검기는 표준 라이브러리만 쓰고 파일·PATH·설치 메타데이터·자원만 읽습니다.
다운로드, 설치, 빌드, 프로그램 실행, VM 시작, 전역 설정 변경은 없습니다.
기본 아카이브 검사는 존재만 확인하며 `--verify-archives`에서 지정된 파일의
SHA256을 읽습니다. 누락·불일치·자원 부족이 있으면 종료 코드 2를 반환합니다.
