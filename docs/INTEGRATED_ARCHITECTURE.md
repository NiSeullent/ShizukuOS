# ShizukuOS 통합 아키텍처

**ShizukuOS가 최상위 운영체제이며 ShizukuOS Core가 공통 실행 기반입니다.**
전체 구성의 유일한 원문 기준은 [Absolute Architecture Definition](SHIZUKUOS_ARCHITECTURE_CONTRACT.md)입니다.
이 문서는 그 정의를 현재 저장소의 구현과 연결합니다. 과거 코드의 출처나 디렉터리
이름으로 제품 경계를 정하지 않습니다.

## 현재 소스와 목표 계층

| 목표 영역 | 재사용할 기존 구현 | 통합 범위 |
| --- | --- | --- |
| ShizukuOS Core / ShizukuDOS | `shizukudos/dos16/`, `kernel32/`, `kernel64/`, `supervisor/` | DOS·protected·long·v8086 모드의 서비스와 수명·권한을 공통 Core 계약에 연결합니다. 현 디렉터리 이름을 상위 플랫폼 이름으로 해석하지 않습니다. |
| Kernel Layer / Native Runtime | Kernel32·Kernel64 서비스, `shizukudos/win64/`, `ntwin32/` | 실제 프로세스·메모리·객체·Win32 x86/x64 계약을 단계적으로 구현합니다. Shizuku Kernel32와 Microsoft KERNEL32.DLL은 다른 구성요소입니다. |
| Driver Layer | `drivers/common/`, 공통 자원 관리, `kernel64/ntdrv*`, 기존 storage/net/gfx/input | Native·Legacy·Wrapped 제공자를 공통 요청·장치 수명에 연결합니다. 작은 장치 차이 때문에 드라이버 전체를 복제하지 않습니다. |
| Shell | `shizukudos/win64/apps/shizuku_shell/`, Win64 USER32/GDI32 | 자체 실행 파일 셸을 확장합니다. 기존 파일·창·설정 서비스를 연결하고 테마 데이터와 공통 UX를 구현합니다. |
| VM Services / ShizukuVM | Supervisor VMX, 장치·채널·VM 실행 기반 | ShizukuOS용 API, VM 생성·실행·중지·회수, 장치와 메모리 계약을 구현합니다. 테스트에 QEMU를 쓰는 것만으로 ShizukuVM이 구현되지는 않습니다. |
| Linux Subsystem | 재사용 가능한 Core·프로세스·창·파일 서비스 | SHZLB.sys, Linux kernel sandbox, POSIX, ShizukuLB, Nix-backed `pkgs`, X 창 브리지를 연결해야 합니다. 이름이나 빈 드라이버 등록만으로 완료하지 않습니다. |
| Native Applications | 기존 런타임·미디어·그래픽·네트워크 및 적합한 외부 엔진 | Terrasphere(WebKit), Muzik, Sapphire, 기존 Folio 통합을 구현합니다. 기존 현대 앱 이식도 계속합니다. |
| Legacy compatibility profile | Windows 98 USER/GDI/Explorer, VxD, `NTW64RUN`/`NTW64GUI`와 브리지 | 해당 실행 경로의 계약과 증거를 유지합니다. 이 프로필의 과거 구조가 ShizukuOS의 시스템 경계를 정하지 않습니다. |

이 표는 구현 위치를 알려 주며 전체 계층이 이미 완성됐다는 뜻이 아닙니다.
각 작업은 EXISTS/PARTIAL/MISSING/BROKEN/REUSABLE/REQUIRES REFACTOR로 분류한 뒤
기존 제공자의 실제 호출 경로를 확인합니다. 세부 상태는 [현재 목표와 구현](SHIZUKUOS_TARGET.md)을 따릅니다.

## 권한과 하드웨어 자원

각 CPU 모드·주소 공간·VM·프로세스에서 실행 주체와 자원 소유자는 명시적이어야 합니다.
현재 소유권을 새 Core 서비스로 옮길 때는 기존 호출자와 백엔드를 함께 연결하며,
단순한 이름 변경이나 디스패처의 성공 반환으로 권한을 이전했다고 하지 않습니다.

- 인터럽트·MMIO·PCI BAR·DMA·장치 큐는 실제로 측정하고 부여받은 자원만 사용합니다.
  주소 폭·범위·길이·정렬과 상위 BAR를 확인하고, 매핑과 장치 세대를 연결합니다.
- 핸들·채널·프로세스·창은 소유자와 세대로 묶습니다. 종료·취소·회수 후에는
  오래된 핸들, 지연 ACK, 재사용된 슬롯이 새 자원을 조작할 수 없어야 합니다.
- 비동기 요청은 실제 제공자의 완료와 취소를 전달합니다. 큐가 가득 찼을 때나
  부분 실패 때 완료를 꾸며내지 않으며, 자원 회수 전에는 참조와 lease를 유지합니다.
- 호출자 포인터·구조 크기·오버플로·권한은 담당 서비스에서 검증합니다.
  JSON 선언, 저장된 receipt, 호스트 테스트의 boolean은 실행 권한이 아닙니다.
- 부작용이나 권한 거부 뒤에 다른 백엔드로 같은 요청을 재실행하지 않습니다.
  지원하지 않는 계약은 정해진 오류를 반환합니다.

스케줄링·페이지 테이블·객체·IRQ·DMA 소유권을 단계적으로 옮기는 작업과,
레거시 프로필의 현재 실행 권한은 별개의 사항입니다. 계정 정책이나 CPU affinity만으로
하드웨어 메모리·DMA 격리를 주장하지 않습니다.

## ABI와 서비스 통합

기존 공유 ABI를 먼저 확인하고 하나의 작성자가 변경을 조정합니다. 구조 크기와
버전, 호출 규약, 반환 오류, 버퍼 수명, 소유자·세대, 취소·종료 의미를 호출자와
제공자가 함께 지켜야 합니다. Windows x64와 System V ABI를 혼용하지 않으며
커널 빌드의 no-red-zone 조건을 보존합니다. ReactOS와 Wine의 계약·수명 처리는
참고 또는 라이선스가 맞는 코드 재사용의 근거이며 구현 성공의 증거는 아닙니다.

현재 선택적 레거시 W64 연결은 `NTW64RUN/NTW64GUI` → `NTW32.DLL` →
`NTWRAP9X.VXD` → Supervisor channel2 → Kernel64 서비스입니다.
GUI 공유 ABI는 `shizukudos/abi/shz_w64_gui.h`, 소유자 계약은 VxD/Core 제공자가
지킵니다. live attestation·owner generation·실제 프레임과 입력·종료를 검증해야 하며,
소스 연결이나 호스트 모델 통과만으로 이 프로필의 실제 실행을 주장하지 않습니다.

## 데스크톱, 그래픽, 테마와 소리

기존 `shizuku_shell`을 실행·패키징되는 ShizukuOS 셸로 확장합니다. 개념 예시의
이름마다 독립 데스크톱·작업 표시줄·탐색기 실행 파일을 만들지 않습니다.
Win64 USER32/GDI32, 클리핑, 메모리 DC, 실제 대상 픽셀 합성과 화면 갱신을 연결합니다.
Gray coverage AA는 대상 색상에 합성되어야 하며 완전한 coverage에서도 픽셀 상위 바이트,
클리핑과 dirty 영역의 의미가 일관되어야 합니다. bitmap 폰트의 coverage 처리와
새로운 outline 폰트·GPU 가속의 완료 주장은 구분합니다.

Slade·Flute·Jade는 셸 소유 테마 데이터입니다. 창 메트릭·제목·경계·배경·투명도·블러,
타이포그래피·아이콘·버튼·메뉴·선택·작업 표시줄·시작 인터페이스·애니메이션·소리·
배경화면·커서를 정의하고 실행 파일 교체 없이 적용합니다. 기존 고정 색상과 효과는
재사용 대상입니다. 그것만으로 데이터 기반 테마 시스템이 완성되지는 않습니다.

소리는 필수입니다. `volume1/shizukuossound` NAS의 기존 자산을 먼저 찾고
출처·허용 범위·실제 출력 장치를 확인합니다. 시작·종료·로그인·로그아웃·오류·경고·
알림·장치 연결의 소리를 연결하며, 필요한 자산이 실제로 없을 때만 새로 만듭니다.

## 가상화와 Linux 실행 환경

ShizukuVM은 Core의 네이티브 가상화 서비스이며 ShizukuOS 자체 API를 제공합니다.
기존 VMX와 QEMU의 적합한 구현·참고 요소를 재사용할 수 있습니다. 외부 하이퍼바이저
API 복제에 시간을 쓰지 않습니다. 가능한 하드웨어 가상화와 실용적인 소프트웨어
fallback을 실제 자원·상태·종료 계약 아래에 둡니다.

`chkrnl /mode linux`와 `/mode msdos`는 커널이 지원하는 실행 환경을 선택합니다.
SHZLB.sys → Linux kernel sandbox → POSIX → ShizukuLB는 Core 내부 구성입니다.
Nix가 패키지 기반이며 `pkgs`는 설치·갱신·제거·검색·저장소 추가·목록·전체 업그레이드를
번역하고 동기화합니다. 별개 패키지 데이터베이스를 만들지 않습니다.
X 세션은 Shizuku Window Bridge를 통해 일반 관리형 ShizukuOS 창으로 나타나야 합니다.

## 통합, 설치와 완료

공통 클래스 드라이버를 재사용하여 ACPI·PCI/PCIe·USB/HID/storage·NVMe·AHCI·IDE,
유선/무선 네트워크·오디오·Bluetooth·GPU/framebuffer/GOP·PS/2·노트북 입력·센서·
전원·디스플레이·파일시스템의 실제 동작을 늘립니다. 장치 인식 문자열만으로
전송·입력·전원 관리·가속이 완료됐다고 하지 않습니다.

자체 설치 시스템은 부팅·UEFI 설치·대상 소유권·파일/섹터 재읽기·지속성과
설치 매체 분리 뒤 cold boot를 검증합니다. 공개 릴리스에 비공개 매체를 넣지 않습니다.
설치 기능의 부분 완료는 native apps·현대 앱·보안·Linux·VM·게임의 최종 목표를
대체하지 않습니다.

[전체 승인 기준](SHIZUKUOS_FULL_GOAL_ACCEPTANCE.md)의 각 기능은 실제 ShizukuOS에서
실행하고 원본 증거의 소스·산출물·입력·결과·정상 종료를 연결해야 합니다.
과거 제어군과 호스트 시험은 원래 범위를 보존합니다. 부팅만 되는 상태, 정적 검사,
미리보기 화면 또는 placeholder는 사용 가능한 운영체제의 완료가 아닙니다.
