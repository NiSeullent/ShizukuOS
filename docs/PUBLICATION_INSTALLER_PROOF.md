# 개발 ISO와 실제 구성요소 설치 화면 게시

ISO는 m98.nyase.kr의 기존 nginx 배포 경로에서만 제공한다. GitHub에는 공개 소스·패치와 사이트 자산을 보존하며 ISO, 설치된 Windows 98 디스크와 사용자 원본 매체는 올리지 않는다.

이번 변경은 ISO 읽기·복사·원본 응답 검증 한도를 512 MiB로 조정한다. 기존 후보는 284,164,096바이트(정확히 271 MiB)라서 이전 256 MiB 한도를 초과했다. 이 파일은 오래된 입력으로 만든 후보이며 이번 변경만으로 게시하거나 승인하지 않는다. ZIP·PNG·JSON·HTML의 8 MiB 한도, 전체 자산 128개 한도와 기존 ZIP 고정 체크섬은 유지된다. 희소 파일 281 MiB 수락과 512 MiB 경계·초과 거부 시험은 호스트 계약 시험이며 실제 ISO 부팅 증거가 아니다.

새 ISO는 정확한 소스 커밋, 공개 builder receipt의 `private: false`, 실제 파일 크기·SHA-256·PVD와 현재 빌드 입력을 확인한 뒤 게시한다. 배포한 바로 그 ISO의 두 번 UEFI 콜드 부팅, 실제 저장·다시 열기와 입력 불변 증거가 필요하다. 이 변경은 기존 `--iso-boot-evidence` 검증과 게시 실패 시 복구 경로를 변경하지 않는다. 증거가 없는 ISO는 검증 완료로 표시되지 않는다. 최종 활성화는 별도 실제 ISO 검증 후 수행한다.

선택적으로 `--component-installer-proof site/evidence/component-installer`를 지정하면 한국어·영어 첫 페이지에 실제 화면 네 장을 추가한다. 기본 호출은 기존 페이지와 자산을 그대로 준비한다. 추가되는 공개 manifest는 고정 SHA-256 `ad97f8e8bee8d72dc57176028ebb83ab31618f11bebab5d0cdeb3f87127ff059`와 정확한 다섯 파일을 요구한다. 사진 수정, 추가 파일, 링크, 다른 결과·원본 입력·완료 상태로 바꾼 manifest는 거부한다.

이 사진은 2026-10-01의 실제 Shizuku 구성요소 설치 시험 기록이다. 시험용 VM 네 대에서 설치 취소, 선택한 NVMe 디스크 설치, 설치 디스크의 UEFI·BIOS 콜드 부팅을 확인했다. 취소 때 두 빈 디스크는 전체 바이트 해시가 0 디스크와 같고 QMP 쓰기 카운터도 0이었다. 설치 때 선택한 디스크만 실제 쓰기 증가가 있었고, 별도 호스트 검사로 파티션과 77개 시스템 파일을 확인했다. 화면에는 실제 설치 검토·설치 완료·UEFI 편집기·BIOS 편집기가 담겼다. PNG 변환 전후 RGB 픽셀은 같으며 화면 위에 문구를 덧붙이지 않았다.

공개 원본 기록 식별자는 결과 SHA-256 `d90bcadbf82a580e11ff925be5249b16d53d7f4d01dada385d335aa65ed8fa15`와 입력 캡처 SHA-256 `e8d25f808e07f2ef7a4594f8241c84ce73c3e9ceb3ece382760b40de013f6087`다. manifest에는 개인 입력·실험 경로가 없다. 이 네 장은 새로 만드는 다운로드 ISO의 부팅 증거를 대신하지 않는다.

ShizukuDOS는 Windows 98에서 MS-DOS를 대체하는 기반이고 Kernel32·Kernel64·WDDMWrapper는 그 구성요소다. 이 설치 시험은 실제 Windows 98의 DOS→VMM 대체나 최신 앱 전체 지원 완료를 증명하지 않는다. manifest의 `windows98_boot_verified`, `ms_dos_replaced`, `latest_apps_complete`, `microsoft_media_included`는 모두 false이며 페이지도 이 범위를 한국어와 영어로 표시한다.

## 작업 공간 계산

읽기 전용 관찰 시 여유 공간은 22,066,417,664바이트였으며 17 GiB를 남기면 작업 가능량은 3,812,806,656바이트였다. 이 값은 이후 다른 작업에 따라 달라진다. 과거 ISO의 99개 파일은 논리 합계 304,964,202바이트, EFI 이미지는 111,149,056바이트였다. 현재 Win64·Kernel32·Kernel64·Supervisor 출력의 실제 할당 합계는 302,931,968바이트다.

이전 ISO와 출력은 검증한 reflink로 보존한다. reflink는 다음 빌드의 새 쓰기까지 무료로 만들지 않는다. 새 빌드·설치 payload, ISO 조합·전체 읽기 확인, 실제 ISO 두 번 콜드 부팅, nginx 게시를 순서대로 진행하고 각 단계에서 실제 추가 할당과 남은 공간을 확인한다. 새 후보 크기가 이전과 비슷할 때 약 2.4 GiB의 계획 여유를 사용하되, 이 관찰치를 다음 실행의 엄격한 상한으로 간주하지 않는다.

ISO 조합 도중 stage·작업 EFI·추출 검증 파일·새 ISO가 동시에 존재할 수 있다. 실제 ISO 부팅 검증은 ISO 전체 복사 한 개, EFI 및 멤버 읽기 결과, 64 MiB 데이터 디스크 두 개와 화면·로그를 추가한다. 게시 시 새 배포 복사와 전체 다운로드 검증으로 실제 ISO 크기의 두 배가 더 필요하다. 512 MiB 한도는 이러한 임시 파일 전체의 공간 보장을 뜻하지 않는다. 새 입력의 실제 크기를 다시 계산하고 17 GiB를 유지할 수 없으면 해당 단계를 실행하지 않는다. 기존 증거·원본 삭제나 보호 여유 축소는 필요하지 않다.

## English quick reference

The ISO alone is allowed up to 512 MiB. Static assets and ZIPs retain their separate 8 MiB bounds and reviewed hashes. Publication still binds the exact source revision, public builder receipt, ISO bytes and independent shipped-ISO cold-boot evidence.

Use the optional `--component-installer-proof site/evidence/component-installer` argument to add four unchanged, pinned captures to both homepages. They document the dated Shizuku component installer test and do not prove the downloaded ISO, genuine Windows 98 replacement or complete latest-app support. Preserve old evidence and check actual free space before each build, boot-test and publication phase.
