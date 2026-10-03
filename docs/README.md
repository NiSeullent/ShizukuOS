# 문서 안내

**ShizukuOS**가 최상위 운영체제이며 **ShizukuOS Core**가 공통 실행 기반입니다. 처음에는 목적에 맞는 안내를 읽고, 구현이나 검증이 필요할 때 원본 기록으로 이동하세요.

## 사용·개발 시작

| 필요한 작업 | 문서 |
| --- | --- |
| 프로젝트 목표와 현재 상태 | [프로젝트 소개](../README.md) |
| 다운로드·배포 원칙 | [공식 배포 기준](OFFICIAL_DISTRIBUTION.md) |
| 새 환경에서 소스 빌드·시험 | [개발 시작 안내](CONTINUE_ON_ANOTHER_MACHINE.md) |
| 필수 앱의 버전·입력 확인 | [대상 앱](TARGET_APPS.md) |
| 현대 앱 개발 이어가기 | [앱 인계](CONTINUE_MODERN_APPS.md) |
| Notepad++ 개발 패키지 수동 설정 | [설치 안내](NATIVE_NPP_INSTALL.md) |
| 사이트 수정·검증 | [사이트 안내](../site/README.md) |
| nginx 배포·운영 | [호스팅 안내](M98_HOSTING.md) |

## 설계와 구현

| 범위 | 문서 |
| --- | --- |
| 최상위 시스템 정의 | [Absolute Architecture Definition](SHIZUKUOS_ARCHITECTURE_CONTRACT.md) |
| 현재 구현과 전체 승인 | [통합 아키텍처](INTEGRATED_ARCHITECTURE.md) · [목표와 상태](SHIZUKUOS_TARGET.md) · [전체 승인](SHIZUKUOS_FULL_GOAL_ACCEPTANCE.md) |
| 기존 Windows 98 호환 프로필의 기록 | [기존 아키텍처 감사](SHIZUKUDOS_WINDOWS98_ARCHITECTURE.md) · [증거 보완](SHIZUKUOS_ARCHITECTURE_SUPPLEMENT.md) |
| Kernel32·Kernel64·Supervisor | [ShizukuDOS](../shizukudos/README.md) |
| 전체 API 이식과 기능 묶음 | [API 작업 방식](API_PORTING_CAMPAIGN.md) · [호환성 기록](COMPATIBILITY.md) |
| 펌웨어 GOP와 Windows 98 그래픽 | [펌웨어 안내](../shizukudos/csm/FIRMWARE_GOP.md) · [GOP 드라이버](../drivers/shizuku_gop/README.md) |
| 독립 플랫폼·드라이버 빌드 | [플랫폼 안내](../platform/README.md) |
| 외부 코드와 라이선스 | [출처·라이선스](../THIRD_PARTY.md) |

## 결과 확인

[기록 미리보기](https://m98.nyase.kr/preview.html)는 실제 게스트의 원본 화면을 보여줍니다. 연결된 라이브 VM으로 표시하지 않습니다.

- [기본 그래픽 검증](SHIZUKU_BASIC_GRAPHICS.md): 실제 Windows 98의 고정 GOP 모드와 GDI 결과.
- [독립 데스크톱 시험](DESKTOP_BOOT.md): Shizuku 구성요소의 입력·저장·재부팅 결과.
- [미리보기 증거](PREVIEW_EVIDENCE.md): 화면과 검증 기록의 연결·공개 범위.
- [VM 기록](../vm/README.md), [0.1.7](RELEASE_0_1_7_CHECKPOINT.md), [0.1.8](RELEASE_0_1_8_CHECKPOINT.md): 기존 KernelEx 경로와 과거 릴리스 결과.

호스트 빌드, 정적 PE 검사, 실제 Windows 98 호출, 앱 창 표시, 앱 기능 성공은 각각 다른 결과입니다. 과거 Windows 98 제어군과 독립 커널·호스트 시험을 현재 ShizukuOS 기능 완료로 합산하지 않습니다. 실제 ShizukuOS의 실행 증거가 필요합니다.

상세 시험·실패·수정 기록은 원본 문서에 보존합니다. 날짜가 있는 기록은 해당 시점의 입력과 결과를 설명하므로 현재 상태를 확인할 때는 아키텍처·앱 인계 문서도 함께 읽으세요.
