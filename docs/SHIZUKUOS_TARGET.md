# ShizukuOS 목표와 현재 구현

최상위 플랫폼은 **ShizukuOS**, 그 아래 공통 계층은 **ShizukuOS Core**입니다.
[사용자의 절대 아키텍처 정의](SHIZUKUOS_ARCHITECTURE_CONTRACT.md)가 시스템 정체성과
구성의 기준입니다. 최종 제품 목표는 ShizukuOS 1.0.0이며 현재는 개발 중입니다.
이 문서는 목표와 공개 소스에서 확인되는 연결 지점을 구분합니다.

## 기존 구현을 확장하는 시작점

| 범위 | 분류 | 현재 소스와 다음 작업 |
| --- | --- | --- |
| 자체 실행 파일 데스크톱 셸 | PARTIAL | `shizukudos/win64/apps/shizuku_shell/`을 확장합니다. `win64/build.py`가 `\SHZ\SYS64\SHIZUKU_SHELL.EXE`를 패키징하고 `kernel64/autorun.c`가 기본 시작 경로를 선택합니다. 실제 ShizukuOS의 시작·입력·파일 작업·종료 검증이 필요합니다. |
| 글꼴과 GUI | PARTIAL | Win64 USER32/GDI32, gray coverage 합성, 클리핑과 DIB 그리기 경로가 있습니다. GNU Unifont의 bitmap 원본을 사용하는 현재 글꼴 경로의 제한을 유지하며 실제 화면의 한글·AA·합성을 검증합니다. |
| Slade / Flute / Jade | REQUIRES REFACTOR | 기존 셸의 그리기·효과·이전 테마 코드를 재사용하되 데이터 정의와 변경 전파를 구현해야 합니다. Slade가 기본입니다. 팔레트 변경이나 고정 효과만으로 세 테마가 완성된 것으로 세지 않습니다. |
| Core와 실행 모드 | PARTIAL | `shizukudos/dos16/`, `kernel32/`, `kernel64/`, `supervisor/`와 Win64 런타임을 재사용합니다. 디렉터리 이름은 플랫폼의 상위 계층을 결정하지 않습니다. 공통 서비스와 권한의 실제 연결이 필요합니다. |
| 공통 드라이버와 노트북 | PARTIAL | `drivers/common/`, `drivers/shz_laptop/`, `drivers/xhci_usb/`, `kernel64/ntdrv*`, 그래픽·저장장치·네트워크 경로를 확장합니다. 지원 장치별 실제 전송·입력·전원·해제를 확인해야 합니다. |
| 사용자·권한·파일시스템 | PARTIAL | `shizukudos/accounts/`, `sysk32_auth.c`, `sysk32_sec.c`, `win64/apps/elevate/`, `shizukufs/`를 통합합니다. 계정별 지속성, 권한 거부, 샌드박싱, 복구를 실제 시스템에서 검증합니다. |
| ShizukuVM | REUSABLE | Supervisor VMX와 기존 VM 서비스는 기반으로 재사용할 수 있습니다. 사용자용 ShizukuVM API와 VM 수명·장치 계약의 완료를 의미하지 않습니다. |
| Linux / chkrnl / 패키지 / X 창 | MISSING | 이번 공개 소스 범위에서 SHZLB.sys → sandbox → POSIX → ShizukuLB, `chkrnl`, Nix-backed `pkgs`, 관리형 X 창의 완성된 실행 경로는 확인하지 못했습니다. 기존 Core·창·프로세스 서비스를 먼저 연결합니다. |
| Terrasphere / Muzik / Sapphire / Folio | MISSING | 각 이름의 완성된 네이티브 실행 경로는 이번 소스에서 확인하지 못했습니다. WebKit, 기존 미디어·이미지 서비스와 라이선스가 맞는 Folio 엔진을 검토해 재사용합니다. |
| 소리 | PARTIAL | 오디오 관련 기존 구성요소를 검토합니다. `volume1/shizukuossound`의 접근·자산 확인과 실제 출력은 이 문서 작업에서 수행하지 않았습니다. 소리 없는 최종 데스크톱은 허용되지 않습니다. |
| Chromium / Legcord / 최신 오픈소스 Office / Steam | PARTIAL | 기존 이식·로더·API·DLL·소켓 제공자 작업을 이어갑니다. 임포트 해석이나 호스트 알고리즘 통과는 앱 기능 성공이 아닙니다. |

분류는 구현 시작점을 찾기 위한 소스 점검 결과이며 제품 완료 판정이 아닙니다.
공용 API가 존재한다고 실제 장치나 앱의 계약 전체가 구현된 것으로 판단하지 않습니다.

## 셸과 테마

기존 `shizuku_shell`이 자체 셸입니다. 데스크톱·작업 표시줄·시작 인터페이스·
파일 탐색·설정 기능은 이 실행 파일과 적절한 기존 라이브러리를 확장합니다.
개념 예시에 있는 셸 실행 파일 이름마다 별도 프로그램을 만들지 않습니다.
`shz.shell=shzdesk`는 이전 SHZDESK 선택 경로이며, 그 경로의 과거 결과를 새 기본 셸의
완료로 합산하지 않습니다.

Slade·Flute·Jade는 창 크기와 경계, 제목 표시줄, 배경, 투명도와 블러, 글꼴,
아이콘·버튼·메뉴·선택 상태, 작업 표시줄과 시작 인터페이스, 애니메이션, 소리,
배경화면과 커서를 데이터로 정의합니다. 테마 변경은 시스템 실행 파일 교체 없이
사용 중인 셸에 적용되어야 합니다. 이전 Classic/ShizukuOS 팔레트나 18-byte 설정은
재사용 후보이며 이 요구 전체의 구현이 아닙니다.

## 실행 환경과 앱

목표 네이티브 Win32 x86/x64 호환성은 실제 Windows 10 API 동작을 포함합니다.
버전 문자열이나 성공을 반환하는 placeholder로 이를 주장하지 않습니다.
Terrasphere는 WebKit 기반 브라우저, Muzik은 미디어 라이브러리와 재생,
Sapphire는 가벼운 보기와 필요 시 편집 기능 로딩, Folio는 기존 오픈소스 엔진의
통합을 목표로 합니다. 기존 Chromium·Legcord/Discord·Office·Steam 요구도 유지합니다.

ShizukuVM, Linux subsystem, ShizukuLB와 Nix는 Core의 구성요소입니다.
`chkrnl /mode linux`와 `/mode msdos`는 실제 커널 지원 실행 환경을 선택합니다.
Linux X 앱은 Shizuku Window Bridge를 통해 일반 관리형 데스크톱 창으로 표시합니다.
별도의 전체 데스크톱이나 셸 흉내로 대체하지 않습니다.

## 증거와 배포

Windows 98 USER/GDI/Explorer·VxD 경로는 선택적 레거시 호환 프로필입니다.
기존 Windows 98의 GOP, Notepad++, VLC 제어군 결과는 해당 입력과 경로의 기록이며
새 ShizukuOS 아키텍처나 제품 완료 조건을 정의하지 않습니다.

완료는 [전체 승인 기준](SHIZUKUOS_FULL_GOAL_ACCEPTANCE.md)의 기능을 실제
ShizukuOS에서 실행하여 판정합니다. 빌드·호스트 시험·화면 사진만으로 완료하지
않습니다. 자체 설치 시스템의 ISO는 nginx의 `m98.nyase.kr`에서 배포하고 외부망에서
홈페이지·다운로드를 확인합니다. 공개 소스에는 비공개 Microsoft 설치 파일,
설치된 게스트 디스크·키·로컬 실행 정보를 넣지 않습니다.
