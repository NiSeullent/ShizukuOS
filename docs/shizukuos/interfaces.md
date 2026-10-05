# 커널 인터페이스

기존 NT/Win32/Win64 계약을 유지하고 ShizukuOS 확장만 추가합니다. 구조의 크기·호출 규약·원래 export ordinal을 변경하지 않습니다. 구현 근거는 각 헤더와 커널 처리 경로입니다.

| 인터페이스 | 실제 구현 | 계약 |
|---|---|---|
| `NtShzToken` | `abi/shz_auth.h`, `kernel64/sysk32_auth.c` | 기존 syscall `0x9d`. 계정·인증·승격·샌드박스 단일 권한 서비스. |
| 첫 부팅 QUERY / COMPLETE | `abi/shz_firstboot.h`, `kernel64/auth_firstboot.h` | append-only 작업 `0x205` / `0x206`, QUERY reply 112바이트, COMPLETE request 32바이트. UI 인자 자체는 권한이 아님. |
| `NtShzSetupTarget` | `kernel64/setup_target_abi.h`, `setup_native_sys.c` | syscall `0xb6`, 요청·응답 440바이트. 커널이 준비한 installer 인스턴스만 claim 생성. |
| 설치 대상 | `blk_authority.c`, `archive_source.c` | 디스크 전체 식별자·세대·역할·원본 snapshot. claim 없는 새 설치기 raw fallback 없음. |
| `NtShzSaw` | `abi/shz_saw.h`, `kernel64/saw.c` | syscall `0x105`, request 48바이트, result row 104바이트, bounded reply 6688바이트. PID 재사용을 세대로 차단. |
| `NtShzSound` | `abi/shz_audio.h`, `kernel64/audio.c` | 기존 버전·작업 유지. OUTPUT_GET 8 / OUTPUT_SET 9, 출력 설정 16바이트. 실제 PCM 출력 gain·mute이며 모든 하드웨어 mixer 지원을 의미하지 않음. |

## 설치 작업

0 CAPS, 1 OPEN_SOURCE, 2 SOURCE_INFO, 3 READ_SOURCE, 4 CLOSE_SOURCE, 5 REVIEW, 6 CLAIM, 7 CHECK, 8 READ_SECTORS, 9 WRITE_SECTORS, 10 FLUSH, 11 RELEASE, 12 VALIDATE_SOURCE를 정의합니다. 다른 작업은 미지원으로 거부합니다. source·target handle은 프로세스·PID 세대·서비스 종류와 결속하며 자식에 자동 전달하지 않습니다.

I/O offset은 섹터 단위, length는 바이트 단위입니다. 현재 target I/O는 512바이트 정렬과 최대 64KiB 요청을 사용합니다. 원본 읽기 경로는 실제 부팅 아카이브의 허용된 manifest/ESP 역할만 열 수 있습니다. 일반 raw read/write/flush는 별도 실제 승격 관리자 경계로 제한합니다.

해제 전에 I/O 결과가 불확실하면 일반 쓰기를 재개하지 않습니다. claim과 원본 참조를 격리해 재부팅까지 유지합니다. 실패를 정상 해제로 보고하지 않습니다.

## 수명과 오류

프로세스·파일·작업자는 실제 참조 수명과 종료 동기화를 유지합니다. 커널의 IRQ-off 구간에서 블로킹 파일 I/O를 수행하지 않습니다. 파일 닫기 중 최종 삭제·쓰기 오류를 호출자에게 전달하고 실패한 이름 전환을 성공으로 처리하지 않습니다.

인터페이스 이름의 존재와 link 성공만으로 실행 완료가 성립하지 않습니다. actual-source 호스트 검사와 실제 ShizukuOS 검증을 [상태 문서](status.md)에서 확인하세요.
