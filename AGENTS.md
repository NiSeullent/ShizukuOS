# ShizukuOS architecture and delivery contract

2026-10-03 사용자 지시가 이전의 DOS 전용·VMM 영구 유지 제한을 대체한다.
`/root/Win98-Modern`은 Windows 98에서 출발한 **독자 Win32 호환 OS인
ShizukuOS**의 작업 공간이다. Windows 98의 외형·유저랜드·기존 코드와 Shizuku
Win32 x86/x64를 함께 사용하는 혼합 OS로 발전시킨다. 커널의 상위 주체는
**ShizukuCore Kernel**이며 구성 계층은 다음과 같다.

```text
ShizukuCore Kernel
├── ShizukuDOS (SZRm)
├── Shizuku32 (SZPrtm)
├── Shizuku64 (SZLm)
└── ShizukuOS (Windows 98)
```

ShizukuDOS도 ShizukuCore의 하위 요소다. 현재 `shizukudos/` 아래의 `dos16/`, `kernel32/`, `kernel64/`,
Windows 98 경로를 이 구성의 출발점으로 사용한다. ShizukuCore의 공통 서비스·권한
관리는 점진적으로 구현할 목표이며, 기존 Supervisor를 개명하거나 공통 코어가 이미
완성됐다고 주장하지 않는다. 현재 FreeDOS/FreeCOM 부트스트랩은 최종 커널의 한계가 아니다.

현재 디렉터리, 부팅 경로, Kernel32/Kernel64, Supervisor, VxD, USER/GDI,
Explorer와 기존 브리지를 유지하며 작은 기능·계약 단위로 코드를 교체한다.
현재 Windows 98 코드가 소유하는 실행·스케줄링·메모리 권한은 해당 경로가
실제로 교체될 때까지 유지하지만, 검증된 Shizuku Kernel 구현으로 점진적으로
이전할 수 있다. Shizuku32의 기존 Kernel32 구현은 Microsoft의 KERNEL32.DLL과 다르다.
제품 이름을 맞추기 위한 일괄 파일명 변경이나 병렬 커널 재작성은 하지 않는다.

ReactOS의 커널·executive·Win32 계약과 Wine의 API·로더·객체 수명 처리를
참고한다. 기존 서비스와 하드웨어 backend를 재사용하고 기능마다 권한 주체를
명확히 한다. 권한 거부나 부작용 뒤 실패를 다른 backend로 재실행하지 않는다.
외부 코드의 출처·라이선스를 보존하고 성공을 반환하는 placeholder로 호환성을
주장하지 않는다. Windows 98 코드 재사용이 Microsoft 소스의 공개 권한을 뜻하지 않는다.

현재 기준은 `docs/INTEGRATED_ARCHITECTURE.md`와
`docs/SHIZUKU_HYBRID_TRANSITION.md`에 있다. 위임·인계에도 이 기준을 전달한다.
이전 계약 원문은 [d612d9f의 AGENTS.md](https://github.com/NiSeullent/Win98-Modern/blob/d612d9f36854c9c6bd2a2a8bd895e99e762fbca7/AGENTS.md)에 보존한다.
기존 감사·실패·부팅·앱 증거의 범위를 바꾸지 않는다. 호스트 시험, 독립 커널
시험, 원본 Microsoft DOS 제어군과 실제 혼합 OS 통합 시험을 구별한다.
기존 15개 기능·앱·보안·설치 요구는 `docs/SHIZUKUOS_FULL_GOAL_ACCEPTANCE.md`를
따르며, 방향 변경만으로 완료 처리하거나 미검증 실행 경로를 성공으로 세지 않는다.

The final 1.0.0 installer uses the project's own installation system. ISO
distribution is exclusive to https://m98.nyase.kr through nginx. GitHub receives
public development files and patches only. Never publish private files,
Microsoft installation media, installed guest images or secrets. User-provided
Windows 98 media stays private.

## Parallel implementation and continuation

Use the current workspace and existing build conventions. Keep one writer per
source area and preserve other sessions' uncommitted changes and live VMs. The
user authorizes active parallel implementation across all fifteen requirements.
Prioritize actual 64-bit boot, installation and recognized working drivers;
Chromium, Legcord, latest open-source Office and Steam remain required in parallel.
Use Sonnet 5.5 or Opus 5.5 and an appropriate effort level for the task. Code
first, then inexpensive affected-source checks; coordinate actual VM acceptance
after integration. Installation/boot/driver qualification also retains all mandatory
application, account and security release gates. Preserve failed evidence and distinguish component checks
from guest installation and useful application operation.

For long tasks maintain a short private `.codex/task-state.md` with changed
paths, actual checks, next integration and remaining release gates. The project
Claude skill is `.claude/skills/shizuku-production/SKILL.md`; portable continuation
instructions are in `docs/CLAUDE_CONTINUATION.md`. Runtime credentials, local
permission settings, machine paths and private media are never committed.
