# ShizukuOS 공식 사이트

[m98.nyase.kr](https://m98.nyase.kr/)의 정적 웹 소스입니다. 홈페이지는 프로젝트 상태를, 다운로드는 실제 배포물과 해시를, 미리보기는 실제 게스트의 기록 화면을 보여줍니다. **1.0.0은 최종 목표이며 현재는 개발판입니다.**

## 페이지 구성

| 파일 | 용도 |
| --- | --- |
| `index.html` | 프로젝트 소개·현재 상태 |
| `downloads.html` | 개발 ISO·구성요소·해시·검증 범위 |
| `install.html` | 설치 전제와 개발판 한계 |
| `apps.html` | 필수 앱과 검증 상태 |
| `develop.html` | 공개 소스·개발 시작 안내 |
| `preview.html`·`preview.js` | 원본 게스트 캡처·타임라인 |
| `dead-screen.html` | 같은 C 소스로 만든 웹 게임 미리보기 |
| `en/` | 대응하는 영어 페이지 |
| `evidence/` | 공개 증거 manifest·원본 이미지 |
| `downloads/` | 공개 개발 구성요소 |
| `deploy/` | nginx 설정·게시 도구·호스트 테스트 |

사이트 테마와 웹 게임은 실제 Windows 98의 테마·크래시 처리 완료 증거가 아닙니다. 미리보기는 기록된 화면이며 라이브 VM 연결 상태와 구분합니다.

## 로컬 확인

저장소 루트에서 실행합니다. 별도의 프런트엔드 빌드나 Node 패키지 설치는 필요하지 않습니다.

```sh
python3 -m http.server 8080 --bind 127.0.0.1 --directory site
```

`http://127.0.0.1:8080/`과 `/en/`을 확인합니다. 다른 터미널에서 사이트·게시 제어 검사를 실행합니다.

```sh
python3 -m unittest discover -s site/deploy/tests -p 'test_*.py'
```

## 변경·게시 기준

한국어·영어 경로와 링크를 함께 유지합니다. 다운로드 카드의 파일·크기·해시·검증 범위는 실제 배포물과 맞춥니다. `SHZGOP.zip`은 기본 그래픽 개발 패키지, `SHZNPP.zip`은 수동 전제와 전용 런처가 필요한 Notepad++ 호환성 개발 패키지입니다. 자세한 설정은 [Notepad++ 설치 안내](../docs/NATIVE_NPP_INSTALL.md)에 있습니다.

원본 캡처와 `evidence/preview.json`의 증거를 보존합니다. 새로운 검증은 기존 실패를 지우지 않고 별도 결과로 추가합니다. 실제 Windows 98 GOP는 소프트웨어 그래픽이며 GPU 3D 가속은 별도 목표입니다. ShizukuDOS가 MS-DOS를 대체하는 최종 설계와 독립 구성요소 시험도 구분합니다.

ISO는 공식 사이트에서만 배포하고 GitHub에는 공개 소스·패치를 게시합니다. Microsoft 미디어·설치된 VM·앱 원본·비밀 값은 포함하지 않습니다. 정적 릴리스 교체·검증·롤백 절차는 [호스팅 안내](../docs/M98_HOSTING.md), 공개 범위는 [배포 기준](../docs/OFFICIAL_DISTRIBUTION.md)을 따릅니다.
