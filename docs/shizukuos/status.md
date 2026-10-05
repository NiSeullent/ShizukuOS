# 구현 상태와 검증 범위

기준일: 2026-10-05 UTC. **Pre-Beta 01 통합 중**이며 완성된 일반 목적 OS나 Windows 10 전체 호환을 주장하지 않습니다. 소스 공개, 호스트 검사, 빌드와 실제 OS 실행은 각각 다른 단계입니다.

| 기능 | 분류 | 확인한 범위·남은 작업 |
|---|---|---|
| x64 Core·PE64 실행 | EXISTS / PARTIAL | 실제 UEFI 설치본의 커널·native shell 부팅, 정상 종료·동기화 확인. 전체 ABI 호환은 미완료. |
| 새 5단계 설치기 | PARTIAL / REUSABLE | 실제 화면·대상 선택·최종 경고와 확인 전 쓰기 0회 확인. 실제 EFI 기록·다시 읽기 통과 후 시간 상한으로 중단. 전체 설치·후속 부팅은 미완료. |
| 설치 대상 권한 | PARTIAL | 실제 읽기 전용 원본 결속, 대상 세대·보호 역할·opaque claim, 정상 해제·불확실 I/O 검사를 통과. 새 통합 guest 진행 중. |
| 첫 부팅 계정·일반 세션 | PARTIAL | 기존 인증·PBKDF2·보호된 기록·프로필 연결, 중단 재시도 검사 통과. 실제 설치 후 두 번 부팅 검증 진행 중. |
| CHAINSAW / SAW / tree | EXISTS / PARTIAL | 실제 native 기능 16개 검사 및 설치본 부팅 확인. 손상·강제 경계의 모든 실기기 조건은 미검증. |
| K64 PANIC / NYAN | PARTIAL | 실제 격리된 guest 출력 PCM·비프·고정 비프·무음 경로 확인. 실제 모든 기기·SMP 손상 복구는 미완료. |
| Slade·Flute·Jade·Noto | EXISTS / PARTIAL | 기존 native 실행과 한국어·실제 테마 변경 확인. blur·투명 효과·입력기 등 미완료. |
| 텍스트·파일·검색 연결 | PARTIAL | actual-source 컴파일·호스트 파일 검사 및 import 검증 통과. 새 계정 설치본에서 작업·재부팅 연결 확인 필요. |
| 설정 확장 | PARTIAL / REQUIRES REFACTOR | 기존 테마 창 재사용. 분류·검색·개인 설정·음량·저장소 연결 구현 중. |
| 파일 탐색기 확장 | PARTIAL | 실제 경로·파일 작업 재사용. 정렬·다중 선택·batch·미리보기 구현 중. |
| 소리·Muzik | PARTIAL / REUSABLE | 실제 AC97·PCM 제공자와 원본 CC0 이벤트 소리. 출력 음량·음소거 actual-source 검사 통과. 전체 장치·라이브러리·영상은 미완료. |
| Sapphire·게임 | PARTIAL | 실제 native 소스·실행 경로 존재. 이미지 편집·모든 파일 형식·게임 전체 UX는 추가 검증 필요. |
| AHCI·UEFI GOP·PS/2·ShizukuFS | EXISTS / PARTIAL | 실제 에뮬레이션 설치본 경로 확인. 광범위 실기기 호환·NTFS 우월성은 미증명. |
| ACPI·NVMe·USB·터치패드 | PARTIAL / REUSABLE | 기존 구현·파서·계층 존재. 장치별 transport·binding·실기기 검증 부족. |
| Wi-Fi·Bluetooth·현대 GPU 가속 | MISSING / PARTIAL | 일반적인 실제 native 지원을 완료하지 못함. |
| ShizukuVM | PARTIAL / REUSABLE | 기존 VMX/EPT·도메인 경계 존재. 사용자 VM 서비스·AMD·소프트웨어 fallback 미완료. |
| Linux·SHZLB.sys·ShizukuLB | MISSING / REUSABLE | 기존 Core·권한·창 경계 재사용 후보. 실제 Linux 실행 환경 미완료. |
| Nix + pkgs·Linux GUI | MISSING | Nix 단일 권한 환경·관리형 Linux 창 연결 미완료. |
| Terrasphere·Folio | PARTIAL / MISSING | WebKit embedding 등 재사용 후보. 유용한 브라우징·Folio 통합 미완료. |

## 닫힌 과거 실행 기록

2026-10-05의 CHAINSAW 통합 ISO `70a555f0911903592bc113ea5a42c8b02cec881b3cd8803114c18f9ad4770b55`는 실제 설치 완료·25개 저장소 검사·ISO 없는 UEFI 재부팅 14개 검사·native desktop·정상 종료·동기화 결과가 있습니다. 이 기록은 위 **새 설치기·계정·확장 데스크톱 후보의 실행 증거가 아닙니다**.

현재 통합 Kernel64S `a5c89cd3630187031f58247ce8c853afacf3e73efddd175b3e8d5203bdb0d70a`, 셸 `0d28fe077522e148f38674849edff50d9c90700816b8b2baf5be4df08660a34f`, runtime archive `bc0bd092d170b62da624b4cccc3f0a91014216ed417e7f451df0f60249e41cad`는 전체 커널 빌드·링크와 실제 PE import 제공자 검사를 통과했습니다.

새 설치기의 첫 실제 부팅에서 설치 원본 경로가 커널의 예상 경로와 달라 계속 버튼이 비활성화됐습니다. 대상 디스크 쓰기는 0회였고 실패 기록을 보존했습니다. 기존 설치 원본의 `SHZ/SETUP/PAYLOAD` 경로에 맞춰 커널의 여섯 경로를 수정했으며 권한 검사는 유지했습니다.

수정된 ISO `f9f19b6877919bbb03b72e665f9409d4b6d7b764b357fcfa42ace7edaa2d92e4`는 실제 최종 확인 화면, 대상 세대와 확인 전 쓰기 0회 검사를 통과했습니다. 128MiB EFI 영역의 기록·다시 읽기 검사 후 실행 시간 상한에 도달해 중단됐습니다. 2KiB마다 디스크 명령을 실행하는 전송 경로의 비용을 줄이고 있습니다. 부분 설치 디스크와 실패 기록을 보존했으며 설치 완료·새 계정 부팅을 주장하지 않습니다. 공개 다운로드의 해시는 배포된 파일을 기준으로 별도로 기록합니다.
