# 공식 배포 기준

공식 제품명은 **ShizukuOS**, 최종 배포 목표는 **1.0.0**입니다. 실제 Windows 98의 DOS 기반 교체·설치·드라이버·필수 앱 요구가 모두 검증될 때까지 개발판으로 표시합니다. 설치는 프로젝트 자체 설치 시스템을 사용합니다.

## 배포 위치

| 배포물 | 공식 위치 |
| --- | --- |
| 홈페이지·ISO·개발 구성요소 다운로드 | [m98.nyase.kr](https://m98.nyase.kr/) |
| 영문 안내 | [m98.nyase.kr/en/](https://m98.nyase.kr/en/) |
| 공개 개발 소스·패치 | [GitHub main](https://github.com/NiSeullent/Win98-Modern/tree/main) |
| 실제 게스트 검증 화면 | [기록 미리보기](https://m98.nyase.kr/preview.html) |

**ISO는 m98.nyase.kr에서만 배포합니다.** GitHub 저장소·Release·Pages에 ISO를 올리지 않습니다. 별도의 소유자 전용 Sites 배포는 기존 접근 정책을 유지합니다.

## 다운로드에 표시할 내용

개발 ISO에는 실제 파일 크기·SHA-256·소스 commit·부팅 검증 범위를 함께 게시합니다. 한국어와 영어 페이지가 같은 파일을 가리키게 하고, 구성요소 ZIP은 별도 다운로드로 유지합니다.

개발 부팅 이미지와 완성된 Windows 98 설치 배포본을 구분합니다. 기존 구성요소 시험이 통과했어도 새로 게시하는 ISO의 실행 검증을 대신하지 않습니다. ShizukuDOS 10·Kernel32·Kernel64의 단독 실행도 실제 Windows 98의 DOS 교체 완료를 뜻하지 않습니다.

공개 자료에는 Microsoft 설치 파일·제품 키·설치된 VM·소유권이 다른 앱 원본·TLS 키와 비밀 값을 포함하지 않습니다. 설치 USB에 사용자의 `WIN98.ISO`를 더한 개인 묶음은 공개 개발 묶음과 분리합니다.

## 게시 확인

게시한 파일 전체의 크기·해시와 Range 응답을 확인합니다. 공개 DNS·유효 TLS·실제 브라우저와 서버 밖의 접근도 별도로 확인합니다. 루프백 응답이나 Cloudflare 인증 확인 화면은 외부 접근 성공으로 기록하지 않습니다.

배포 절차와 롤백은 [호스팅 안내](M98_HOSTING.md), 빌드 입력은 [새 환경 개발 안내](CONTINUE_ON_ANOTHER_MACHINE.md)를 따릅니다. 이전 정책 원문은 `merge-history/20261001/distribution-policy/`에 보존합니다.
