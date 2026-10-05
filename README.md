# ShizukuOS

**ShizukuOS**는 자체 데스크톱, 실행 환경과 커널 계층을 갖추는 독립 운영체제입니다. 공통 기반은 **ShizukuOS Core**이며 ShizukuDOS, Kernel32·Kernel64, Driver Layer, Native Runtime, ShizukuVM과 Linux Subsystem을 구성요소로 둡니다.

[공식 홈페이지](https://m98.nyase.kr/) · [다운로드](https://m98.nyase.kr/downloads.html) · [사용자·개발 문서](docs/shizukuos/README.md) · [구현·검증 상태](docs/shizukuos/status.md) · [English](https://m98.nyase.kr/en/)

## 현재 개발

자체 실행 파일 데스크톱은 `integration/shizuku-shell`에서 빌드하며 설치된 기본 실행 경로는 `SHZDESK.EXE`입니다. 기존 데스크톱·작업 표시줄·시작·탐색기를 확장합니다. Slade·Flute·Jade를 **설정에서만** 선택하고 Noto Sans 계열 실제 글꼴을 사용합니다.

실제 x64 설치·ISO 없는 UEFI 부팅·native 데스크톱·정상 종료 기록을 보존했습니다. 새 5단계 설치기, 오프라인 계정 도우미, 텍스트·검색·파일 작업과 설정·탐색기 확장을 병렬로 통합하고 있습니다. 빌드 성공은 새 설치본의 기능 완료를 의미하지 않습니다. [기능별 상태](docs/shizukuos/status.md)에 실행과 남은 조건을 구분합니다.

CHAINSAW/SAW는 실제 프로세스 상태·참조·관련 실행 환경을 검사하는 네이티브 종료 경로입니다. 파일 작업은 실제 디스크 쓰기·동기화·내용 확인을 사용하며 계정 서비스는 인증·일반 세션·승격·샌드박싱 권한을 관리합니다.

## 전체 목표

ShizukuOS의 성공 조건은 **부팅 → 드라이버 → 데스크톱 → 테마·소리 → 네트워크·파일 → 앱 → 브라우저·미디어·그래픽 → Linux → 가상화·게임**입니다. Kernel32/64와 DOS 모드의 점진적인 통합, Windows 10 Win32·Win64 API/ABI 호환성, 광범위 표준 장치와 노트북 지원을 계속 개발합니다.

ShizukuVM, `chkrnl /mode linux|msdos`, SHZLB.sys Linux sandbox/POSIX, ShizukuLB, Nix 기반 `pkgs`, Linux GUI 창 통합, Terrasphere·Muzik·Sapphire·Folio와 시스템 유틸리티를 전체 목표로 유지합니다. 모든 기능이 완성된 상태는 아닙니다.

[절대 아키텍처](docs/SHIZUKUOS_ABSOLUTE_ARCHITECTURE.md) · [전체 목표·승인 조건](docs/SHIZUKUOS_FULL_GOAL_ACCEPTANCE.md) · [현재 문서](docs/shizukuos/README.md)

## 개발

전체 프로젝트 소스와 기존 호환 계층·드라이버·도구를 이 저장소에 함께 공개합니다. 새 개발 환경은 [개발 안내](docs/shizukuos/development.md)와 [기존 환경 인계](docs/CONTINUE_ON_ANOTHER_MACHINE.md)를 참고하세요. 기존 컴파일·제작 도구를 사용하고 외부 입력·라이선스·해시를 고정합니다.

과거 Windows 98·앱·그래픽 결과는 각각의 시스템과 입력을 유지한 역사적 회귀 기록입니다. 현재 ShizukuOS의 시스템 경계를 결정하지 않습니다. [기존 그래픽](docs/SHIZUKU_BASIC_GRAPHICS.md), [앱 기록](docs/CONTINUE_MODERN_APPS.md), [호환성](docs/COMPATIBILITY.md)을 보존합니다.

## 배포·라이선스

ISO는 설치·부팅·드라이버와 해당 버전의 실제 승인 조건을 확인한 뒤 **[m98.nyase.kr](https://m98.nyase.kr/)에서만 배포**합니다. GitHub는 개발 소스·패치·문서를 제공합니다. 배포된 파일의 체크섬과 지원 조건은 다운로드 페이지를 기준으로 확인하세요.

비공개 설치 매체·제품 키·개인 실행 디스크·자격 증명은 공개하지 않습니다. 파일별 프로젝트·외부 코드 라이선스와 출처를 보존합니다. 소스 재사용·export 연결·버전 문자열만으로 Windows 10 전체 호환을 주장하지 않습니다.

[프로젝트 라이선스](LICENSE) · [외부 코드 출처](THIRD_PARTY.md) · [공식 배포 정책](docs/OFFICIAL_DISTRIBUTION.md)
