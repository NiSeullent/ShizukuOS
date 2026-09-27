# Windows 98 Shizuku's Second Edition — 독립 계층 검증 기록

2026-09-27. 참고 기준: `NiSeullent/Win98-Modern`의 `1d54ca7`.
개발 브랜치: `codex/shizuku-independent-platform`.
**전체 목표는 진행 중이다. 이 기록은 완성된 Windows 98 배포판이 아니다.**

## 이번에 구현한 것

| 구성 요소 | 실제 구현·시험 | 아직 입증하지 못한 것 |
| --- | --- | --- |
| NTWrapper9x | 독자 핸들·참조 수명·권한 마스크·이벤트 코어, i486 무런타임 라이브러리. 호스트 동시성 시험과 UEFI 종료 후 CPL0 시험 통과 | Windows 98 VxD 적재, VMM 연결, 메모리·스케줄러·I/O 관리자 |
| NTWin32Wrapper9x | KernelEx와 연결하지 않는 `NTW32.DLL`, SRW 7종과 제한된 64비트 틱, 앱 사본의 PE import 재작성. 기존 IAT 주소 보존과 원본 파일 보호 | 새 DLL의 Windows 98 로더·앱 실행, 동적 import·API sets·전체 Win32 호환성 |
| NTWDDMWrapper9x | 독자 소프트웨어 표면, 채움·복사·포맷 변환·화면 표시·완료 fence. 실제 UEFI 화면에 표시 | Windows 98 디스플레이 드라이버, WDDM 바이너리 ABI, D3D·GPU 가속 |
| PCI-E | 설정 읽기, 브리지 탐색, MCFG/ECAM·capability·BAR·DMA 제약 검사. QEMU PCI-E 브리지 아래 xHCI 발견 | 실제 Windows 드라이버 연결, BAR 할당, 인터럽트·DMA·USB/디스크 전송 |
| ShizukuDOS UEFI | 독자 x64 EFI 이미지, GOP, 메모리 맵, ExitBootServices 재시도와 인계 | UEFI에서 DOS 프로그램 실행 및 Windows 98 GUI 부팅 |
| 명칭 | 기본 문서·웹 소스·UEFI 화면에 전체 제품명 적용 | 설치된 Windows UI·시스템 파일의 브랜딩 변경은 아직 없음 |

새 디렉터리의 구현은 프로젝트에서 직접 작성했다. 기존 Wine·ReactOS·KernelEx
기반 소스의 고지를 보존하고 새 빌드에서는 제외했다. 공식 ABI 문서와 출처는
각 디렉터리의 README/PROVENANCE에 기록했다. 이것은 공식적인 클린룸 개발
인증이나 Windows 전체 소스의 독자 구현 완료를 뜻하지 않는다.

## 검증 결과

- 커널·동기화: 핸들 종료/참조 해제, stale handle, 권한 거절, 용량 소진,
  generation 폐기, 자동 이벤트의 단일 소비, SRW 동시성, 틱 wrap 통과.
  네 스레드의 80,000회 배타 갱신과 중간 공유 읽기를 검사했다.
- PE 경로: 실제 MinGW 산출물에 대한 11개 시험 통과. 잘린 파일, 서명/TLS/CLR,
  잘못된 헤더·import, 새 파일만 쓰기, 네이티브 IAT 주소 보존, export/route 일치,
  256개 결정적 변형과 별도 binutils 파싱을 검사했다.
- PCI-E: 엄격한 GCC 빌드와 Clang ASan/UBSan에서 각각 **38,766 assertions** 통과.
- 그래픽: 엄격 빌드와 Clang ASan/UBSan에서 각각 **308,637 assertions** 통과.
  그중 **50,960개**는 모든 유효 사각형의 겹치는 복사에 대한 비교 시험이다.
  x86-64·i386 freestanding object에서 미해결 런타임 심벌이 없다.
- UEFI: 네이티브 및 Clang ASan/UBSan에서 각각 **354 checks** 통과.
  KVM 게스트의 실제 화면과 QMP 가속 상태, 프로세스 종료를 검증했다.
- 독립 리뷰로 커널·그래픽 헤더 이름 충돌과 PE IAT가 헤더/코드를 덮어쓸 수 있는
  오류를 발견해 고쳤다. 네 계층의 헤더 동시 포함을 회귀 검사에 추가했다.

위 숫자는 검증 항목 수이며, 지원 API·장치 수나 Windows 호환성 점수가 아니다.

## 실제 UEFI 게스트

Q35, KVM 활성, 1 vCPU, 256 MiB, 네트워크 없음. 기존 디스크 없이 별도 16 MiB
FAT16 시험 이미지와 펌웨어 변수 사본만 사용했다. 일반 EFI와 PCI 진단 EFI는
서로 다른 파일이다. 둘 다 화면 도달 뒤 프로세스 종료를 확인했다.

| 파일 | SHA-256 |
| --- | --- |
| `BOOTX64.EFI` (11,776 bytes) | `6b963f36433d7acf82671e90bbeed6f71a55aed29c38d709e24062afd6e737d1` |
| `BOOTX64-PCI-TEST.EFI` (17,408 bytes) | `b7fb1c225e51f245b4ad607bb6e8a38542530fea97dbc1fcce4b95c4e8a59e58` |
| `NTW32.DLL` (8,465 bytes) | `fd4fd6789c934d3a4a32ccddb5b4ba8bb8558b73c1dba53402864c56d6e41b78` |
| `NTWPROBE.EXE` (9,728 bytes) | `82c998b9e485b2017bf8b27e11665a9cb4771d3bf911f307a5b7390981083d69` |

PCI 진단은 `00:03.0`의 브리지 `1b36:000c`를 따라 `01:00.0`의 xHCI
`1b36:000d`, class `0c:03:30`을 발견했다. 총 2개 버스·8개 함수이며
`8086:2922` AHCI도 식별했다. 이 진단은 256바이트 CF8/CFC 설정 읽기다.
ECAM은 호스트 계약 시험만 수행했고, NVMe·USB 전송·DMA의 게스트 성공은 없다.

영구 기록: [UEFI VALIDATION.json](../shizukudos/uefi/VALIDATION.json).
정확한 소스·산출물 해시는 `build/platform/manifest.json`,
`shizukudos/uefi/build/build-result.json`과 시험 영수증에 있다.

## 재현과 다음 개발

[플랫폼 안내](../platform/README.md)에 빌드·시험 명령이 있다.
`python3 platform/package.py`는 검증된 독자 소스·산출물·라이선스·증거를
`build/windows98-shizuku-second-edition-foundation.zip`으로 묶는다.
Windows 파일·설치 키·VM 디스크·펌웨어 바이너리는 패키지에 들어가지 않는다.
`python3 platform/verify_package.py`는 별도 디렉터리에 압축을 풀어 소스에서
DLL·시험 앱·커널 라이브러리·EFI를 다시 빌드하고 바이트 단위 해시를 비교한다.
링커 기본 주소와 아카이브 타임스탬프를 고정해 출력 경로가 달라도 재현한다.

현재 서버의 `zuku-compat-win98`는 설치 매체가 없는 빈 이미지이며 수정하지
않았다. 참고 저장소의 과거 Windows 호스트 결과를 새 DLL의 실행 증거로
사용하지 않았다. 다음 구현 단위는 NTWrapper9x의 Win98 VxD/VMM 연결과
독립 앱 로더 경로의 실제 게스트 시험이다. 그 뒤 메모리·IRQ·DMA·I/O 기반,
AHCI/xHCI/NVMe 및 디스플레이 드라이버, Win32 API 기능 묶음을 확장한다.
UEFI-to-DOS/Win98 부팅과 Windows 8.1/10/11 수준의 앱·드라이버 호환성은
별도 완료 기준을 유지한다.
