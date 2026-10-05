# 개발·빌드

공개 저장소는 ShizukuOS의 전체 프로젝트 소스, 기존 호환 계층, 드라이버, 도구와 문서를 함께 보관합니다. 실행 디스크·개인 설치 매체·제품 키·개발자의 자격 증명은 소스 배포에 포함하지 않습니다.

## 소스 위치

| 구성요소 | 경로 |
|---|---|
| Core·Kernel32·Kernel64 | `shizukudos/` |
| 네이티브 Win64 제공자·설치기 | `shizukudos/win64/` |
| 자체 데스크톱 | `integration/shizuku-shell/` |
| 글꼴 제공자 | `integration/shizuku-font/` |
| 이벤트 소리 원본·생성기 | `integration/shizuku-sound/` |
| 설치 미디어 도구 | `integration/installer-media/` |
| ShizukuFS | `shizukufs/v1/` |
| 드라이버·연결 계층 | `drivers/`, `ntwrapper/`, `ntwin32/` |

디렉터리의 과거 이름은 운영체제의 경계를 정하지 않습니다. 같은 서비스를 확장하고 유사한 새 커널·셸·계정 데이터베이스를 중복해서 만들지 않습니다.

## 개발 환경

기본 호스트는 x86-64 Linux입니다. 선택한 경로에 따라 Python 3, GCC, NASM, binutils, x86-64 MinGW, FreeType 소스·헤더, QEMU, OVMF, ISO 도구가 필요합니다. 외부 입력은 기존 manifest·라이선스·해시를 확인합니다.

각 기존 제작 도구의 사용법:

```sh
python3 shizukudos/kbuild.py --help
python3 integration/shizuku-shell/build.py --help
python3 integration/installer-media/candidate_iso.py --help
```

셸은 실제 제공자 DLL을 지정해 빌드하고 결과 PE64 import를 해당 DLL export와 대조합니다. 글꼴 의존성과 라이선스를 같은 입력으로 고정합니다. Kernel64 내부 `ldr_create_ex_t`가 변경됐으므로 모든 호출자를 다시 컴파일해야 합니다. 예전 객체와 새 크기의 구조를 혼합하지 마세요.

현재 통합은 기존 설치 payload 제작기와 ISO 제작기를 재사용합니다. 소스만 받은 상태에서 모든 앱·미디어·외부 의존성을 자동으로 완성하는 빌드를 보장하지 않습니다. 실제 입력, 제작 명령, 산출물 해시와 실패 기록을 함께 남깁니다.

## 검증과 기여

관련 소스를 네이티브 옵션으로 컴파일하고 필요한 수명·권한·파일 경계 검사를 수행한 뒤 실제 ShizukuOS에서 실행합니다. 설치 검증은 새 디스크 설치, 기록 읽기 비교, 미디어 없는 부팅, 일반 계정 파일 저장, 두 번째 부팅과 정상 종료를 연결해야 합니다.

코드 출처와 파일별 라이선스를 보존합니다. 외부 예제·Wine·ReactOS 코드를 참고했다고 전체 API 호환이 달성되는 것은 아닙니다. 새 기능마다 EXISTS / PARTIAL / MISSING / BROKEN / REUSABLE / REQUIRES REFACTOR 분류와 실제 확인 범위를 기록합니다.
