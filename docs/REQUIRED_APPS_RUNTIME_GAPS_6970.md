# Signal·ONLYOFFICE 실행 의존성과 협업 인계

2026-10-01의 고정 배포본과 실제 바이너리를 조사했다. Signal 8.28.0은
독립 Kernel64 시험에서 프로세스 시작과 10초 heartbeat까지 진행했으나,
90.1초 제한 안에 기능 화면이나 정상 종료를 입증하지 못했다. Modern 테마
시험도 90.2초에 timeout되었지만 UXTHEME 파일 부재는 해소되었다. ONLYOFFICE
9.4.0 x64 기본·Modern 시험 모두 Qt5Gui의 D3D11 직접 import에서 앱 생성
전에 실패했다. 이 문서는
Windows 98에서 두 앱이 동작한다는 판정이나 Windows API 호환률을 제시하지 않는다.

## 입력과 증거 구분

| 대상 | 고정 입력 | 실제 검사 범위 |
| --- | --- | --- |
| Signal 8.28.0 x64 | 공식 설치 파일 141,981,864바이트, SHA-256 `9a9533f9c844144145ebd4bfe096428294e34f93973e035829bfb46a3bf7c90d` | 전체 117개 파일을 준비했고, 네이티브 파일 13개를 검사했다. x86 `resources/elevate.exe`도 별도로 식별했다. |
| ONLYOFFICE 9.4.0 x64 | 공식 ZIP 598,575,987바이트, SHA-256 `22ae48a7813954e5079bff1ea211c6583aba67f34f2d0dbcb2431d4a20e94dfc` | 4,904개 멤버, 네이티브 PE32+ AMD64 파일 335개 전체의 정적 import를 검사했다. x86 배포본으로 대체하지 않았다. |

배포본 버전·해시·발행자 무결성은 각각
`build/modern-required-apps-6970/signal-inventory-v1.json`과
`onlyoffice-x64-inventory-v1.json`에 고정되어 있다. 입력 원본과 준비한
트리는 비공개 시험 자료이며 Git에 포함하지 않는다. [Signal 배포 메타데이터](https://updates.signal.org/desktop/latest.yml),
[ONLYOFFICE 고정 릴리스](https://github.com/ONLYOFFICE/DesktopEditors/releases/tag/v9.4.0).

정적 검사 도구는 [required_app_import_gaps.py](../tools/required_app_import_gaps.py)다.
발행자 inventory와 런타임 DLL의 파일 정체성·해시를 검사 전후에 확인한다.
내보내기 이름 또는 서수의 존재는 호출 의미, DLL 초기화, loader 검색 순서,
동적 함수 조회나 앱 기능 성공을 보장하지 않는다. 일반 import와 지연 import도
같은 실행 단계로 취급하지 않는다.

## 디렉터리와 실제 부팅 아카이브는 다른 입력이다

`/root/Win98-Modern-apps-cb43/build/shizukudos/win64`에는 검사 당시 DLL
51개가 있었다. Signal의 실제 baseline에 봉인된 `WIN64.IMG`에는 SHZARC01
멤버 141개와 `\SHZ\SYS64` DLL 43개가 있다. 실제 아카이브 SHA-256은
`2f3a3facad9f15187ed33e37088082afa3f8c5df2a7e00f4ef42e1af503e16f0`다.

공통 이름 가운데 `KERNEL32`, `ADVAPI32`, `COMCTL32`, `GDI32`, `UCRTBASE`,
`USER32`, `WS2_32`의 실제 아카이브 bytes가 디렉터리 검사 입력과 다르다.
`DXGI`, `IMM32`, `NCRYPT`, `PATHCCH`, `PDH`, `PSAPI`, `SETUPAPI`, `WSOCK32`는
해당 아카이브에 없다. 디렉터리의 후보 수를 그 아카이브에서 실행한 결과에
붙이면 안 된다.

원본 아카이브를 변경하지 않고 실제 DLL 43개, 합계 7,462,730바이트를
새 정적 검사 디렉터리에 추출했다. 경로·별칭·경계·정렬·겹침을 확인했고,
아카이브와 관련된 종료된 Signal 실행 receipt를 해시로 연결했다.
`runtime-archive-static-v1.json`이 그 인계 receipt다. 추출한 DLL을 실행하지 않았다.

| 앱·선택 입력 | import 참조 전체 | 이름·서수 후보 | 내보내기 부재 | 모듈 부재 | 기본 도구의 별도 분류 |
| --- | ---: | ---: | ---: | ---: | --- |
| Signal·디렉터리 51개 | 2,940 | 2,503 | 24 | 116 | API-set 72, 호스트 EXE 별칭 110, 동봉 DLL 45, x86 구조 불일치 70 |
| Signal·실제 아카이브 43개 | 2,940 | 2,456 | 34 | 153 | 위와 동일 |
| ONLYOFFICE·디렉터리 51개 | 47,518 | 14,433 | 1,404 | 8,834 | API-set 1,901, 동봉 DLL 20,946 |
| ONLYOFFICE·실제 아카이브 43개 | 47,518 | 14,384 | 1,391 | 8,896 | 위와 동일 |

각 숫자는 import **참조 횟수**이며 distinct API 개수나 호환률이 아니다.
플러그인과 아직 호출되지 않은 지연 import도 포함한다. ONLYOFFICE의 모듈
부재 참조 대부분인 `MSVCRT.DLL` 8,567회는 여러 VLC 플러그인 등의 전체
패키지 참조다. 모두 최초 앱 시작에 사용된다는 관찰은 없다.

동봉 DLL의 export도 별도로 검사했다. 준비된 실제 DLL bytes가 inventory의
SHA-256과 검사 전후에 일치하며, 동봉 DLL basename은 중복 없이 하나씩이다.
Signal의 DLL 6개에서 위 45개 참조, ONLYOFFICE의 DLL 330개에서 20,946개
참조의 이름·서수 후보를 확인했다. 이 추가 진단은
`required-packaged-export-candidates-v1.json`이다. 가상 정적 그래프에서
동봉 DLL을 우선 선택했으므로 실제 loader 검색 순서와 초기화 성공은 여전히
미검증이다. 표의 기본 도구 분류를 동작 성공으로 소급 변경하지 않았다.

## Signal: 실제 시작 이후와 네이티브 모듈을 나누어 수정

`signal-run-v2/result.json`의 실제 결과는 `FAIL`, `qemu_timed_out=true`,
실행 시간 90.1초다. `serial.log`에는 `Signal.exe` 매핑, pid 60, 스레드
2개인 10초 heartbeat가 있다. 기능 화면, 정상 프로세스 종료 및
`autorun_result`는 확보되지 않았다. 게스트는 독립 AMD64 Kernel64이며
이 receipt의 `windows98_execution_verified`와 `app_functionality_verified`는
모두 false다.
이번 실행의 `network_attached`도 false이며 메시지 연결 시험은 수행하지 않았다.

실제 동적 조회 기록은 다음과 같다. 이 목록의 각 항목이 timeout 원인이라는
판정은 하지 않는다. 특히 `ntdll.__wine_dbg_*`와 EXE의 서수 조회는 선택적
probe인지 호출 경로를 추가로 확인해야 한다.

| 실제 기록 | 현재 조사할 범위 | 담당 영역 |
| --- | --- | --- |
| `api-ms-win-core-fibers-l1-1-2` 미제공, 표에는 `l1-1-1`만 존재 | 요청 버전의 함수·동작 계약을 대조한 뒤 실제 API-set 표와 archive를 다시 고정 | Kernel64 loader/API-set: c009·cb43 |
| `kernelbase.dll` 부재 | fallback 대상과 KnownDLL·API-set 호스트 선택 확인 | Kernel64 loader: c009·cb43 |
| `powrprof.PowerRegisterSuspendResumeNotification` 동적 조회 실패 | 등록/해제·콜백 전달·수명 계약을 실제 전원 이벤트와 함께 구현·시험 | 시스템 API: c009·cb43 |
| `api-ms-win-downlevel-shell32-l1-1-0` unknown contract | 요청한 실제 export 및 fallback 경로 확인 | Kernel64 loader·Shell: c009·cb43 |
| `uxtheme.dll` 부재 | 6970의 별도 Modern provider 아카이브로 비교 실행하고 실제 paint 증거 확보 | 테마 provider·시험: 6970 |

`Signal.exe`의 **일반** import 537개는 실제 baseline 아카이브에서 정적
내보내기 후보가 있다. 그러나 네이티브 `.node` 모듈에는 다음 일반 의존성이
남아 있다. 루트 EXE 하나의 이름 일치로 이 경로들을 완료 처리하지 않는다.

| 실제 동봉 모듈 | 실제 아카이브에서 확인한 일반 import 부재 | 필요한 구현·검증 |
| --- | --- | --- |
| `@signalapp+libsignal-client.node` | `KERNEL32.SetThreadStackGuarantee` | 스레드·fiber별 stack reserve 및 overflow 복구 계약. 무조건 성공 반환으로 대체할 수 없다. |
| `libringrtc-x64.node` | 위 항목과 `GetSystemTimes`, `HeapQueryInformation`, `VerifyVersionInfoA`; `AVRT`, `MSDMO`, `PDH`, `PSAPI`; `OLEAUT32.GetErrorInfo`; waveIn/waveOut 조회·메시지 5개 | 초기화와 호출 기능을 분리하여 관찰. 통화 기능은 실제 오디오 장치·버퍼·이벤트 계약도 필요하다. |
| notifications·windows-ucv `.node` | `OLEAUT32` 서수 200·201 | 실제 서수 배치와 logical-thread error-info 소유권·초기화·취소를 구현·시험 |
| `vulkan-1.dll` | `CFGMGR32` 장치 조회 9개 | 해당 backend가 실제 선택되는지 관찰한 뒤 장치 열거 계약 검증 |
| `resources/elevate.exe` | PE32 ia32, 현재 AMD64 provider와 70회 구조 불일치 | 별도 x86 실행 경로가 필요하다. 이 보조 EXE가 최초 시작에 호출됐다는 증거는 없다. |

[SetThreadStackGuarantee 계약](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadstackguarantee)은
현재 크기 조회, 이전 크기 반환, 크기 감소 무시, reserve보다 큰 요청을
다룬다. 실제 overflow 처리 가능한 공간이 제공되어야 한다.
OLEAUT32의 200·201은 [고정 Wine export specification](https://raw.githubusercontent.com/wine-mirror/wine/df15af3652511150490934682202d45af892f887/dlls/oleaut32/oleaut32.spec)에서
`GetErrorInfo`·`SetErrorInfo`다. [GetErrorInfo 계약](https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-geterrorinfo)은
현재 logical thread의 객체를 caller에게 넘기며 그 상태를 지운다. 값이 없을
때만 S_FALSE를 반환한다. 빈 성공 stub은 이 계약을 충족하지 않는다.

## ONLYOFFICE: Qt와 CEF를 실제 종속 파일로 취급

실제 기본 시험 `onlyoffice-run-v1`은 11.8초, Modern 시험
`onlyoffice-themed-run-v1`은 14.9초 후 FAIL로 끝났다. 두 시험 모두
전체 FAT32 패키지와 Qt5Widgets·Qt5Gui 매핑까지 도달했고,
`qt5gui.dll needs d3d11.dll!D3D11CreateDevice: DLL not found [c0000135]`
때문에 앱 프로세스를 만들지 못했다. 모던 아카이브 봉인과 입력 보존은
통과했으며 실제 테마 paint는 확인되지 않았다.

`DesktopEditors.exe`의 일반 import 154개에는 명확한 이름·모듈 부재가
없지만, 그중 31개는 동봉 `Qt5Core`·`Qt5Widgets`로 향하고 38개는 API-set다.
따라서 루트 EXE 이름 검사만으로 시작 가능하다고 판정할 수 없다.

| 핵심 종속 파일 | 실제 아카이브에서 확인한 일반 의존성 | 담당 영역 |
| --- | --- | --- |
| `Qt5Core.dll` | MSVCP140의 locale·iostream·Lockit·once·error helpers 11개; `MSVCP140_1._Aligned_get_default_resource`; `MPR.WNetGetUniversalNameW`; 파일 변경 통지 3개; `GetConsoleWindow`, `GetEffectiveRightsFromAclW`, `NetShareEnum`, `SHFileOperationW`, `CharNextExA`, `WS2_32` 서수 101 | CRT·kernel·Shell·network: c009·cb43 |
| `Qt5Gui.dll` | `D3D11CreateDevice`, `CreateDXGIFactory1`, `GetConsoleWindow`, MSVCP140 `_Throw_C_error` | CRT·그래픽: c009·cb43 |
| `Qt5Widgets.dll` | MSVCP140_1 resource helper; UXTHEME 7개 일반 import | 테마: 6970; CRT: c009·cb43 |
| `libcef.dll` | 일반 import에서 GDI/USER/kernel 등을 포함한 export 33회 부재, IMM32 등 모듈 참조 88회 부재. 6개 UXTHEME 참조에는 실제 서수 47도 포함 | CEF·renderer·system API: c009·cb43, 테마: 6970 |
| `ascdocumentscore.dll` | MSVCP140 일반 import 116개 부재; `BeginDeferWindowPos`·`DeferWindowPos`·`EndDeferWindowPos`; COMDLG32 `FindTextW` | CRT·문서 UI: c009·cb43 |

현재 cb43의 MSVCP140 바이너리는 named exports 39개다. peer의
`docs/shizukudos10/CRT.md`가 설명하는 iostream·locale 등의 미구현 범위와
실제 ONLYOFFICE import가 겹친다. 함수 이름만 추가하기보다 실제 ABI·객체
배치·exception·소유권·locale 동작을 갖춘 구현 또는 출처·라이선스가 고정된
port가 필요하다. 기존 Chromium·Electron 중심의 “no measured image imports
msvcp140” 전제를 이 Office 패키지에 적용하면 안 된다.

6970의 Modern UXTHEME provider는 24개 export를 제공한다. Signal의 6개
테마 지연 import에는 후보가 있지만, `Qt5Widgets.dll`은 **일반 import**로
`SetWindowThemeAttribute`를 요구하고 그 함수는 현재 provider에 없다.
현재 overlay는 이 Office 테마 의존성을 전부 해결하지 못한다.
[Microsoft 계약](https://learn.microsoft.com/en-us/windows/win32/api/uxtheme/nf-uxtheme-setwindowthemeattribute)은
HWND·속성 종류·속성 포인터·크기를 받는 HRESULT 함수이며, WTA_NONCLIENT의
실제 window 속성을 적용한다. 해당 기능을 지원하지 않는 경우에도 정확한
검증과 오류 계약이 필요하며, 미지원 기능의 성공을 반환해 완료 처리하지 않는다.

## 통합 순서와 완료 증거

1. cb43·c009가 실제 loader/renderer·CRT 변경을 소유한다. 6970은 새로운
   provider와 private overlay만 소유한다. peer source, 활성 VM, 기존 disk,
   공유 실행 순서를 이 문서 작업에서 변경하지 않았다.
2. 부팅에 쓸 `WIN64.IMG`와 kernel·boot input을 다시 봉인하고 **그 실제
   아카이브**의 import 후보를 확인한다. 빌드 디렉터리와 부팅 파일이 같다고
   가정하지 않는다. 각 변경은 focused API 계약 시험 뒤 첫 실패를 확인한다.
3. 변경 전후 동일한 발행자 앱·timeout·명령·데이터를 유지해 baseline과
   Modern overlay를 비교한다. DLL 로드와 실제 색·글꼴·geometry·paint
   결과는 독립 증거다. 테마가 앱 창에 적용되었음을 화면·호출로 확인해야 한다.
4. Signal은 실제 창·입력과 정상 종료, 이어서 연결·메시지·통화 경로를
   각각 검증한다. ONLYOFFICE는 창·입력 이후 DOCX/XLSX/PPTX 생성·편집·저장·
   재열기를 시험한다. 프로세스 시작이나 host tests를 앱 기능 성공으로 세지 않는다.
5. 독립 Kernel64 결과를 native Windows 98 결과로 옮겨 쓰지 않는다.
   Windows 98에서 이 런타임을 호출하는 실제 bridge와 OS TLS 1.3 제공 경로는
   별도 통합·게스트 검증이 남아 있다. TLS 협업 소유자는 7707·5abe다.

## 고정 진단 receipt와 재현

모든 진단 자료는 `build/modern-required-apps-6970` 아래에 별도 이름으로
추가했다. 기존 receipt를 수정하거나 덮어쓰지 않았다.

| receipt | SHA-256 |
| --- | --- |
| `signal-runtime-import-gaps-v4.json` | `1374382c937205ae6788b0a14beb823e8ffb064d0176108bb643ace3ebb51d48` |
| `onlyoffice-x64-runtime-import-gaps-v1.json` | `040623b8b95741edc9b470bae8d80d07c8165c5f5687bce3643f28cb238315d2` |
| `runtime-archive-static-v1.json` | `423d41c2ca8702300b30d662349ebd49f94ffc9d45dceb0989ddfb3845376f1d` |
| `signal-actual-runtime-import-gaps-v1.json` | `106c0df7ce1c2426f593e687eec799619e182b589329203d054628c43e54ec5f` |
| `onlyoffice-x64-actual-runtime-import-gaps-v1.json` | `491aeb08315bac2e83146947a91c6ee4655cf06779a7ecdf3d3fecd6ae53e33d` |
| `required-packaged-export-candidates-v1.json` | `d0ac37232f090943fa1e6e297134a206d6eaa44460657e79fb998fa13bde45e6` |
| `signal-run-v2/result.json` | `c9d84d050c7b0facba217f01b19b5a27c4b23c44fc419d2172595e282b878aef` |
| `signal-run-v2/serial.log` | `4f14255d9a634c4a54b034b6a58678702e92a6c6ac13cb0c9c470c60a684944b` |

기존 inventory와 고정 runtime DLL 디렉터리를 사용한다. 재현 예:

```text
python3 -B tools/required_app_import_gaps.py \
  --inventory build/modern-required-apps-6970/onlyoffice-x64-inventory-v1.json \
  --runtime-dir build/modern-required-apps-6970/runtime-archive-static-v1 \
  --output build/modern-required-apps-6970/onlyoffice-x64-actual-runtime-import-gaps-next.json
```

출력은 아직 없는 새 path를 선택한다. 이 명령은 앱·installer·DLL을
실행하지 않는다. 원본 inventory의 발행자 검증 결과를 참조하며 이 import
진단 자체가 원본 배포본을 다시 다운로드·검증하지는 않는다.
