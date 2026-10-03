# ShizukuOS 구현과 증거 보완

현재 root platform은 **ShizukuOS**, 공통 기반은 **ShizukuOS Core**입니다.
[Absolute Architecture Definition](SHIZUKUOS_ARCHITECTURE_CONTRACT.md)이 시스템
정체성·계층·필수 기능의 원문 기준이며 이전의 필수 Windows 98 상위 구조를 대체합니다.
[통합 아키텍처](INTEGRATED_ARCHITECTURE.md)는 현재 구현과 그 정의의 연결을 설명합니다.

`shizukudos/dos16`, `kernel32`, `kernel64`, `supervisor`와 Win64 runtime,
기존 drivers·GUI·filesystem·bridges를 재사용합니다. 디렉터리 이름이나 과거 코드의
출처가 시스템 경계가 되지 않습니다. 공유 ABI와 현재 권한·자원 수명은 실제
제공자를 연결할 때까지 보존하며 이름 변경으로 통합 완료를 주장하지 않습니다.

기존 `shizukudos/win64/apps/shizuku_shell`의 실행 파일 셸을 확장합니다.
Slade/Flute/Jade는 셸 소유 데이터 테마이며 개념적인 실행 파일 예시는 중복 구현
요청이 아닙니다. ShizukuVM, chkrnl, Linux subsystem/SHZLB.sys/ShizukuLB,
Nix-backed pkgs, 관리형 X 창과 native apps·sound도 최종 시스템의 필수 목표입니다.
구현 시작점과 미완료 범위는 [목표와 상태](SHIZUKUOS_TARGET.md)에 있습니다.

선택적 Windows 98 compatibility profile의 USER/GDI/Explorer·VxD·W64 bridge는
그 경로의 정확한 계약과 과거 증거를 유지합니다. 원래 Microsoft DOS로 부팅한
제어군, 독립 Kernel64 시험, 호스트 모델과 실제 ShizukuOS 실행 결과는 서로 다른
범위입니다. 이전 사진이나 앱 결과를 새 시스템의 완료로 재분류하지 않습니다.

[전체 승인](SHIZUKUOS_FULL_GOAL_ACCEPTANCE.md)은 실제 ShizukuOS의 실행으로 판정합니다.
boot만 되는 상태, 소스 연결·PE import·호스트 테스트·화면 목업은 기능 완료가 아닙니다.
자체 설치·UEFI·실제 드라이버·계정·권한·modern apps와 전체 Core/desktop 기능을
검증하고 허용된 media만 nginx `m98.nyase.kr`에서 배포합니다. 비공개 원본 설치본,
매체·키·로컬 경로·로그·인계 자료는 공개하지 않습니다.
