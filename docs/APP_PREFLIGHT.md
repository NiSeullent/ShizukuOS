# 앱 실행 전 정적 진단

`tools/app_preflight.py`는 EXE 또는 DLL 하나의 PE 헤더와 일반·지연 import를
읽고, 현재 NTW32 준비 경로의 수용 여부를 출력한다. 입력 파일을 한 번 읽은
같은 바이트로 SHA-256과 분석 결과를 만든다. 앱을 실행하거나 패치하지 않으며,
파일 출력·다운로드·네트워크 접근도 없다. 결과는 표준 출력으로만 보낸다.

```text
python3 -B tools/app_preflight.py INPUT
python3 -B tools/app_preflight.py INPUT --format markdown
```

성공 종료 코드 `0`은 진단 보고서를 만들었다는 뜻이다. 분석 대상의 실행 성공을
뜻하지 않는다. 읽기 오류나 잘못된 PE 구조는 오류를 표준 오류로 출력하고 `2`로
종료한다. 잘못된 명령행 인자도 `2`로 종료한다. Python 표준 라이브러리와 기존
저장소의 분석·준비 함수만 사용하며 추가 패키지를 설치하지 않는다.

## 결과와 판정 범위

JSON 스키마는 `win98modern.app-preflight.v1`이다. `analyze(path: Path) -> dict`,
`render_markdown(report: dict) -> str`, `main(argv=None) -> int`로 다른 도구에서도
같은 진단을 사용할 수 있다.

| 필드 | 의미 |
| --- | --- |
| `input` | 입력 경로, 동일한 입력 바이트의 SHA-256과 바이트 수 |
| `pe` | machine 정수, `PE32`/`PE32+`, subsystem 정수, `[major, minor]` 버전 및 CLR·certificate table·TLS·load config 존재 여부 |
| `imports` | DLL, 이름 또는 `#서수`, `load`/`delay`, NTW32 라우팅 후보 여부 |
| `paths.stock_win98` | 기본 32비트 Win98 앱 경로의 확정된 헤더·CLR 차단 이유 또는 `unverified` |
| `paths.ntw32` | 실제 준비 함수가 메모리에서 수용하면 `eligible`, 거부하면 `rejected`와 원래 오류 이유 |
| `import_inventory_complete`, `import_inventory_notes` | 정적 import 목록의 완전성 및 제한 |
| `api_set_dlls` | 목록에 나타난 API-set DLL 이름. 매핑이나 동작을 추측하지 않음 |
| `unresolved_by_ntw32` | NTW32 이름 라우팅 후보가 아닌 import. 누락 DLL 또는 미구현 API라는 뜻은 아님 |
| `guest_executed`, `runtime_compatibility` | 각각 항상 `false`, `unverified` |

NTW32 후보는 `ntwin32/routes.json`에 선언된 지원 이름을 **KERNEL32의 일반
이름 import**로 요청한 경우에만 표시한다. 지연 import, 서수, API set이나 다른
DLL의 같은 이름은 후보가 아니다. 후보 표시는 아키텍처·서명·TLS·CFG 등 다른
준비 조건의 충족이나 API 동작의 증거가 아니다.

`ntwin32/prepare.py`의 실제 `prepare(bytes)`를 호출하여 PE32 x86, 서명·CLR,
TLS·load config·CFG, delay descriptor, section-header 여유 공간과 라우팅 조건을
검증한다. 준비 함수가 생성한 바이트는 메모리에서 버리며 원본과 출력 파일을
쓰지 않는다. `eligible`은 현재 준비 함수의 수용 결과이며 Win98 로더의 실제
수용이나 앱 실행을 뜻하지 않는다. 예를 들어 subsystem 6.1은 준비 함수가
보존할 수 있지만 기본 Win98 4.10 경로에는 별도 차단 이유가 남는다.

기본 32비트 Win98 앱 경로는 x86 PE32, GUI/console subsystem 및 4.10 이하의
subsystem 버전을 요구하며 CLR은 별도 런타임 경로가 필요하다. 이 판정은
ShizukuDOS WIN64 서브시스템의 수용 여부를 평가하거나 차단하지 않는다.
이 도구는 원본·게스트 설치 DLL, 앱 동봉 DLL 또는 provider export의 이름
기준을 대조하지 않으므로, 헤더 검사를 통과해도 `stock_win98`은 `unverified`다.

## 파서와 제한

기존 `scan_imports.PEView`의 일반 import 파서와 `measure_pe_coverage.delay_imports`
함수를 재사용한다. 파일을 다시 읽지 않는 PE view가 optional header와 directory
경계를 먼저 검증하고, RVA를 실제 raw section 또는 header 바이트에만 연결한다.
optional header의 크기와 directory 수를 함께 검사하고 certificate directory는
RVA가 아닌 **파일 오프셋**으로 처리한다. 이는 [Microsoft PE 형식 명세](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only)의
optional header 및 certificate table 규칙을 따른다.

Directory가 파일 범위를 벗어나거나, import descriptor가 선언된 directory 안에서
끝나지 않거나, 이름·thunk가 실제 파일에 있는 영역 안에서 끝나지 않으면 보고서를
완성하지 않는다. 가상 zero-fill tail을 뒤에 남은 파일 바이트로 해석하지 않는다.
섹션 또는 directory 범위를 넘는 테이블, 16개를 초과한 directory, 4,096개를
초과한 일반 descriptor와 65,536개를 초과한 thunk는 보수적으로 거부한다.

PE32+의 일반 import는 표시하지만 지연 import의 **이름 목록은 지원하지 않는다**.
해당 directory가 있으면 descriptor·thunk의 경계는 검증하고,
`import_inventory_complete=false`와 명시적 사유를 출력한다. 동적
`LoadLibrary`/`GetProcAddress`, 재귀적 의존 DLL, API-set 해석, export forwarding 및
함수의 실제 의미·동작은 이 정적 목록의 범위 밖이다. 이름 대조 측정은 기존
[PE 가져오기 측정 도구](PE_IMPORT_COVERAGE.md)를 사용한다.

## 병렬 작업 인계

앱 담당자는 이 보고서의 입력 SHA-256, 경로별 차단 이유와 unresolved 목록을
관련 로더·API 담당자에게 전달할 수 있다. 그 후 실제 실행·창 표시·기능 확인
증거는 [미리보기 증거 기준](PREVIEW_EVIDENCE.md)에 따라 별도로 기록한다.
이 보고서만으로 드라이버 작동, 앱 실행 완료 또는 페이지 렌더링 성공을 표시하지
않는다. 파일별 담당 범위를 나누면 다른 세션의 로더·드라이버·게스트 runner를
수정하지 않고 진단과 실행 검증을 병렬로 진행할 수 있다.

## 검증

2026-09-30 구현본에서 다음 명령으로 합성 PE 회귀 테스트 **25개**가 통과했다.

```text
python3 -B -m unittest discover -s tools/tests -p 'test_app_preflight.py' -v
python3 -B tools/app_preflight.py --help
```

테스트는 x86/x64 헤더, 일반·지연·서수 import, API-set 및 확장자 없는 DLL의
후보 제외, subsystem·CLR·서명 경로, 잘린 테이블과 가상 영역·overlay 탈출 거부,
단일 입력 스냅샷과 원본 불변성, JSON·Markdown 출력을 확인한다. 이 검증은
호스트의 정적 진단 계약에 대한 것이며 실제 앱·드라이버 실행 증거는 아니다.
