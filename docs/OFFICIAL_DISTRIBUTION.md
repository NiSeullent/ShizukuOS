# 공식 배포 기준 — 2026-10-01

공식 홈페이지·다운로드·미리보기는 [m98.nyase.kr](https://m98.nyase.kr), 영문판은 [m98.nyase.kr/en/](https://m98.nyase.kr/en/)에서 제공합니다. nginx의 기본 페이지는 공홈이며 이전 VNC 주소도 공홈으로 이동합니다. 개발 VM 콘솔은 별도 명시적 경로에 있습니다.

공식 제품명은 **ShizukuOS**, 최종 배포 목표 버전은 **1.0.0**입니다. 설치·부팅·실제 앱 동작의 전체 요구사항이 검증되기 전에는 개발판으로 표시합니다. 자체 설치 시스템을 사용하며 현행 배포에서 ShizukuDOS 0.1을 폐지하고 ShizukuDOS 10을 사용합니다.

최신 사용자 지시는 공개 가능한 모든 개발 소스·패치를 커밋하고 GitHub `main`으로 병합하는 것입니다. [GitHub main](https://github.com/NiSeullent/Win98-Modern/tree/main)에서 새 환경으로 clone할 수 있습니다. **ISO는 m98.nyase.kr에서만 배포하며 GitHub 저장소·Release·Pages에 업로드하지 않습니다.** 비공개 파일과 사용자 Microsoft 미디어도 공개하지 않습니다. 이전 정책 원문은 `merge-history/20261001/distribution-policy/`에 역사 자료로 보존합니다.

ShizukuDOS는 MS-DOS를 대체하며 Kernel32·Kernel64 등은 Windows98을 위한 구성요소입니다. 단독 실행 프로필의 검증과 실제 Windows98 전체 경로의 완료를 구별합니다. 임시 Microsoft DOS 매체 의존은 최종 설계가 아닙니다.

공개 개발 ISO는 통합 소스에서 새로 빌드하고, ISO의 실제 크기·SHA256·소스 commit과 실제 부팅 시험 범위를 함께 게시합니다. 한국어·영문 페이지의 기본 버튼은 실제 게시한 ISO를 가리키며 구성요소 ZIP도 유지합니다. 전체 다운로드와 Range 응답, 공개 DNS·유효 TLS·실제 브라우저 및 서버 밖의 실행 환경을 각각 확인합니다. 인증 확인 화면과 localhost 응답은 외부 공홈 성공으로 세지 않습니다.

설치 USB는 Shizuku 부팅 파일·구성요소와 본인의 `WIN98.ISO`를 함께 준비하는 방식입니다. 공개 묶음과 사용자 미디어를 더한 개인 묶음을 구별하고 실제 설치·부팅 검증 범위를 표시합니다. Microsoft 설치 파일·제품 키·비공개 VM·TLS 키는 공개 소스나 공개 다운로드에 포함하지 않습니다.

[새 환경 빌드 안내](CONTINUE_ON_ANOTHER_MACHINE.md), [현대 앱과 native 후보 이어가기](CONTINUE_MODERN_APPS.md), [기존 인계 자료](CONTINUE_IN_ANOTHER_ENVIRONMENT.md)를 함께 확인하세요. 소스 통합이나 개발 ISO 부팅은 전체 최신 앱·GPU 가속·완성된 Windows98 자동 설치의 완료 선언이 아닙니다. 실제 기록과 미완료 항목은 각 원본 증거를 보존합니다.
