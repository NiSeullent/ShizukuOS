# 현재 Kernel64 데드 스크린 통합

ShizukuDOS는 Windows 98에서 MS-DOS를 대체하는 기반이며 Kernel32·Kernel64는 그 구성요소다. 이 변경은 Kernel64의 처리되지 않은 심각한 오류에만 데드 스크린을 연결한다. Windows 98의 DOS→VMM 부팅 대체, Windows 예외 가로채기, 최신 앱 구동의 완료 증거는 아니다.

`kernel64/{lib.c,arch.c,main.c,gfx_fb.c,gfx_gop.c,gfx_input.c,gfx_wm.c}`의 작은 연결과 `kbuild.py`의 네 가지 생산용 C 단위 링크로 구현한다. 현재 설치·데스크톱 분기보다 먼저 초기화하되 제어용 명령행 토큰이 없으면 일반 부팅을 계속한다. 기존 driver bugcheck callback과 진단/evidence 출력을 보존한다. 파일·demand·user paging, driver SEH, user fault 처리 뒤 남은 ring-0 예외만 연결하며 ring-3 및 정상 종료는 기존 경로를 유지한다. 그 밖의 console/section 보안/256개 용량/native peer/memory-hole 코드는 변경하지 않는다.

화면은 실제로 매핑된 GOP/BGA framebuffer만 사용한다. 준비되지 않은 화면·입력, 게임 렌더 실패, 재진입 오류에는 정확히 `You session got wasted`와 영문 trace를 출력하고 중단한다. trace는 실제 캡처 IP/SP/BP/CR2/CR3 및 예외 레지스터다. 첫 IP 이후 임의 스택을 따라가는 unwinding은 제공하지 않는다. 게임은 망가진 커널을 재개하지 않으며 별도의 정적 상태만 변경한다.

독립 standalone 프로필은 준비된 PS/2·PIT를 사용해 한국어/영어 선택, 테트리스, 수박 게임을 제공한다. Supervisor 프로필의 소스는 같은 ABI로 링크하지만 준비된 직접 화면·입력이 없어 console hypercall을 통한 영문 fallback만 지원한다. Supervisor 게임, USB 전용 키보드, SMP 오류 takeover 및 실제 물리 장비는 검증하지 않았다.

소스부터 독립 검증하기:

```sh
python3 -B -m unittest discover -s tests -p test_dead_screen_default_integration.py -v
python3 -B shizukudos/dead_screen/build.py --out build/dead-screen-current-check
```

새 출력 폴더만 허용한다. private historical receipts는 기본 빌드의 전제조건이 아니며 `--verify-history`로 요청했을 때만 실제 원본과 비교한다. 이미 기본 통합된 일관된 7개 연결은 그대로 사용하며 결과는 `already-default-integrated`, patch는 빈 파일이다. 부분 통합·중복 연결은 실패한다. bare source를 검사할 때만 복사본에 7개 연결을 적용한다. 기존 frozen source나 receipt를 덮어쓰거나 재인증하지 않는다.

2026-10-01의 V6 panic/#UD/text 실제 cold VM 검증은 SHA256 `d050560d5c535482c08d442b05fdc7db2650b86f6b3a7290ac5d5f3131ab9114`인 과거 별도 held candidate에 관한 것이다. 그 검증에서 실제 PS/2 게임·KO/EN·immutable trace·영문 fallback을 관찰했다. 현재 main을 바탕으로 링크한 새 이미지의 VM 성공으로 전용하지 않는다. 새 candidate의 소스/컴파일/firmware/runtime 입력을 고정하고 같은 세 가지 실제 제어 VM을 다시 실행한 뒤 결과를 별도로 기록해야 한다.

Source and host checks establish integration admission, input hashes and modeled service-boundary behavior. A native link establishes symbol closure and the existing below-3-MiB image/BSS limit. Neither establishes guest or Windows 98 success. Current-main guest acceptance remains pending until its own cold VM controls finish.
