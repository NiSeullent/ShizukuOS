# ShizukuOS 구현 전환 계획

파일 이름은 기존 링크를 위해 유지합니다. 현재 시스템 정의는
[ShizukuOS — Absolute Architecture Definition](SHIZUKUOS_ARCHITECTURE_CONTRACT.md)입니다.
ShizukuOS가 root platform이고 ShizukuOS Core가 공통 기반입니다. 이전 문서의
제품 정체성·상위 계층·필수 레거시 셸 조건은 이 정의로 대체합니다.

## 전환 원칙

새 코드를 쓰기 전에 기존 구현과 호출자·제공자·패키징을 조사하고
EXISTS/PARTIAL/MISSING/BROKEN/REUSABLE/REQUIRES REFACTOR로 분류합니다.
현재 `shizukudos/`, `ntwin32/`, `ntwrapper/`, `drivers/`의 디렉터리 이름은
시스템 경계가 아닙니다. 소스 경로를 안정적으로 유지하면서 기능·계약 단위로
실제 Core 서비스에 연결합니다. 이름만 바꾸거나 동등한 실행 파일을 중복 생성하지 않습니다.

ReactOS의 kernel/executive/Win32 계약과 Wine의 loader/API/object 수명 처리를
참고하거나 라이선스가 맞는 부분을 재사용합니다. 파일별 출처와 라이선스를
보존하며 사용자의 비공개 Microsoft 코드·설치 파일·설치본은 공개하지 않습니다.
[외부 코드 기록](THIRD_PARTY_PROVENANCE.md)과 [라이선스 안내](../THIRD_PARTY.md)를 따릅니다.

## 단계별 통합 범위

| 단계 | 기존 기반 | 실제 전환과 검증 |
| --- | --- | --- |
| 1. 구현과 권한 조사 | Kernel32·Kernel64·Supervisor, DOS 모드, Win64 runtime, 기존 드라이버·브리지 | 각 실행 주체의 memory/object/IRQ/MMIO/DMA 소유권과 shared ABI를 기록합니다. 현재 제공자를 보존하고 authority 이전이 필요한 지점을 찾습니다. |
| 2. Core 계약 통합 | 기존 process/thread/syscall/channel/driver 서비스 | 실제 호출자와 제공자를 함께 연결합니다. owner/generation, handle rights, async cancellation, EOF/exit, resource teardown을 검증합니다. |
| 3. 자체 셸과 UX | `win64/apps/shizuku_shell`, USER32/GDI32, 기존 theme·file·settings 서비스 | 기존 `SHIZUKU_SHELL.EXE`를 확장합니다. 실제 화면·AA·입력·파일 작업·설정과 데이터 기반 Slade/Flute/Jade, 필수 소리를 연결합니다. |
| 4. 장치와 설치 | 기존 공통 드라이버, GOP/graphics/storage/network/input, 설치 시스템 | 지원 장치별 실제 전송·입력·전원·재시작과 UEFI 설치·파일/섹터 재읽기·매체 분리 cold boot를 수행합니다. |
| 5. 실행 환경 | VMX와 Core·객체·프로세스·창 제공자 | ShizukuVM 자체 API, `chkrnl`, SHZLB.sys/Linux sandbox/POSIX/ShizukuLB, Nix-backed `pkgs`와 X 창 bridge를 구현합니다. 외부 하이퍼바이저 API나 별도 전체 데스크톱으로 대체하지 않습니다. |
| 6. 앱과 최종 시스템 | native runtime, media/graphics/network 제공자와 적합한 외부 엔진 | WebKit Terrasphere·Muzik·Sapphire·Folio, 현대 앱, utilities·games를 실제 ShizukuOS에서 실행하고 기능·종료·지속성을 확인합니다. |

단계는 기능별로 병렬 진행할 수 있습니다. 기반이 있다는 것과 해당 기능이
완성됐다는 것은 다릅니다. `SHZLB.sys`, native apps, Nix/`pkgs`, ShizukuVM API
등의 현재 공백은 [목표와 구현](SHIZUKUOS_TARGET.md)에 표시하며 빈 DLL·명령이나
호스트 전용 helper를 완성된 시스템 기능으로 세지 않습니다.

## 경로별 계약 보존

Windows 98 USER/GDI/Explorer·VxD와 `NTW64RUN/NTW64GUI` 연결은 선택적 레거시
프로필로 유지합니다. 해당 경로의 실행 권한·채널 attestation·PMA lease·프레임/입력·
종료는 현재 제공자의 실제 계약을 따라야 합니다. 이 프로필을 유지하는 일이
ShizukuOS의 주 셸이나 root platform을 결정하지 않습니다.

새 제공자를 붙일 때는 기존 권한 거부·취소·부분 실패 뒤에 요청을 다른 backend로
반복하지 않습니다. 지연 ACK·종료 이벤트가 재사용한 owner/slot에 영향을 주지
않도록 generation을 확인합니다. host receipts와 선언형 boolean은 live authority의
대체 수단이 아닙니다. Windows x64/System V ABI, kernel no-red-zone과 실제 호출자의
buffer/handle 수명도 유지합니다.

## 완료와 공개 인계

[전체 승인 기준](SHIZUKUOS_FULL_GOAL_ACCEPTANCE.md)은 실제 ShizukuOS의 실행 증거로
판정합니다. 이전 DOS·Windows 98 제어군, 독립 Kernel64 시험, 호스트 모델, 소스·
임포트 검사와 이미지는 각각의 원래 범위를 유지합니다. 그림이나 제품 이름 변경은
이들을 실제 시스템 완료로 바꾸지 않습니다.

한 source area에 한 작성자를 배정하고 공유 ABI·권한·index는 조정합니다.
비공개 `.codex/task-state.md`에는 변경 소스와 실제 검사·실패·다음 연결을 남깁니다.
공개 인계에는 필요한 소스·라이선스·계약·허용된 증거만 포함하며 비공개 매체 경로,
체크섬, 로컬 VM 로그·인계 메모와 인증 정보를 포함하지 않습니다.
ISO는 적용 가능한 release gates를 통과한 뒤 nginx의 `m98.nyase.kr`에서 배포합니다.
