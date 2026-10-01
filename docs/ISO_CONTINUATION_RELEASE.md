# 공식 배포용 개발 이어가기 ISO

공식 홈페이지와 새 다운로드 배포처는 **https://m98.nyase.kr** 입니다. 이 작업은 GitHub push, PR, release를 만들지 않습니다.

현재 상태는 **source-only 도구 준비, 실제 remaster 미실행**입니다. 실제 새 ISO 빌드·부팅·배포 완료를 주장하지 않습니다. 주 ISO 담당자의 통합 소스 확정과 작업 인계 전까지 remaster와 VM 실행을 보류합니다.

`tools/remaster_continuation_iso.py`는 검증된 공개 BIOS/UEFI hybrid ISO에 최종 통합 `main` 소스와 독립 복원 가능한 Git bundle을 추가합니다. 기존 부팅 바이너리와 GPL/LGPL/OFL 라이선스·해당 소스·패치는 보존합니다. 결과물은 **개발 이어가기 스냅샷**입니다. 통합 소스로 부팅 런타임을 새로 컴파일한 전체 기능 최종판이라는 의미는 아닙니다.

현재 기준 공개 원본은 161,480,704바이트이며 SHA-256은 `998e0717cb3dc094ed740ae431088f1f91c9fcc37ad90753ccda125ed9d65424`입니다. 원본 JSON 영수증 SHA-256은 `09eacc70dd5a5c133a025213be6a187918995e85c61f9ad54335a0a8e27aa971`입니다. 기존 Kernel64/Win64 등의 빌드 영수증은 `abc160b429f5498a2a5328b05af29e099964d54a` 및 당시 수정 상태를 기록합니다. 새 통합 `main`의 소스 커밋과 기존 바이너리 출처를 각각 `CONTINUE/INTEGRATED-SOURCE.json`과 `CONTINUE/BOOT-BINARY-PROVENANCE.json`에 기록합니다.

최신 JavaScript·CSS·각종 WASM·WebGL·WebGPU 전체 지원 및 Legcord/Discord·Signal·최신 Office 계열 앱 전체 실행 인증은 아직 완료되지 않았습니다. 새 ISO는 Windows 98 설치본 또는 완성 OS 설치 이미지가 아닙니다. Microsoft 설치 파일·제품 키·개인 키·개인 VM 디스크는 공개 배포에 넣지 않습니다.

## 입력과 빌드

먼저 최종 `main` 커밋을 확정하고, 해당 커밋의 gzip tar 소스 패키지와 `refs/heads/main`을 포함하는 자급형 Git bundle을 만듭니다. 소스 패키지는 루트 디렉터리 하나 아래 `LICENSE`, 이 remaster 도구와 계속 작업 안내를 포함해야 합니다. 빌드 디렉터리·개인 설정·VM 이미지·개인 키는 제외합니다. bundle의 객체 무결성과 새 환경 복원은 배포 담당자가 실제 독립 복원으로 확인해야 합니다. remaster 도구는 bundle의 자급형 헤더·main 커밋·전체 파일 해시를 검증하며, 객체 pack 전체 복원 검증을 대신하지 않습니다.

아래 경로와 해시를 실제 최종 산출물로 바꿉니다. 어느 디렉터리에서 실행해도 동작하며 `--output-dir`은 존재하지 않는 새 디렉터리여야 합니다.

```text
python3 -B /absolute/project/tools/remaster_continuation_iso.py \
  --base-iso /absolute/cache/windows98-shizuku-second-edition.iso \
  --base-receipt /absolute/cache/windows98-shizuku-second-edition.json \
  --source-archive /absolute/release/integrated-main-source.tar.gz \
  --source-sha256 <source-tar-sha256> \
  --bundle /absolute/release/integrated-main.bundle \
  --bundle-sha256 <bundle-sha256> \
  --source-commit <full-main-commit> \
  --output-dir /absolute/project/build/publication-20261001/iso \
  --budget-mib 512
```

필요한 호스트 도구는 Python 3.11 이상과 xorriso입니다. 인터넷 접근·업스트림 다운로드·시스템 설정 변경·VM 시작은 하지 않습니다. 쓰기는 새 출력 디렉터리에만 수행합니다. 기존 ISO와 입력 소스·bundle은 읽기 전용으로 취급하고 빌드 끝에 다시 해시를 확인합니다.

시작 시 디스크 여유가 **20 GiB + 전체 작업 예산** 이상이고 가용 RAM이 **6 GiB** 이상이어야 합니다. 실행 중 50ms 간격으로 전체 소유 출력 용량과 디스크·RAM을 확인하고 조건을 벗어나면 새로 시작한 자식 프로세스 그룹만 종료합니다. 출력 예산과 여유 공간 감시는 주기적 검사이므로 검사 사이의 순간 초과를 원자적으로 막지는 못합니다. 자식 프로세스에는 개별 파일 크기 제한을 추가합니다. 다른 세션의 프로세스·디스크·VM을 정리하거나 중단하지 않습니다. 실패한 `.partial` 이미지와 로그는 그대로 남깁니다.

## 결과와 검증 범위

새 출력 디렉터리에는 `windows98-modern-continuation-20261001.iso`, `result.json`, `SHA256SUMS`, 명령 로그 및 추가된 안내·출처 메타데이터가 남습니다. ISO 내부 `CONTINUE/`에는 `SOURCE.tar.gz`, `MAIN.bundle`, 한국어 이어가기 안내, 통합 소스·기존 바이너리 출처, 원본 ISO 영수증과 해시 목록이 들어갑니다.

도구는 원본의 regular 파일 98개를 ISO의 실제 extent 바이트로 읽고 새 ISO의 대응 파일과 비교합니다. ISOLINUX의 부팅 정보 표 8..63바이트만 새 위치에 따라 갱신할 수 있습니다. 기존 라이선스·소스·패치·런타임과 EFI FAT 이미지의 바이트는 동일해야 합니다. 새 소스·bundle·메타데이터 역시 실제 ISO 안의 바이트와 입력 해시가 일치해야 합니다. raw El Torito catalog checksum과 BIOS/UEFI 두 엔트리, ISOLINUX 부팅 정보 표, hybrid MBR 및 GPT의 기본·백업 checksum과 EFI 위치를 검증합니다. 다중 extent 파일은 자동으로 해석하지 않고 거부합니다.

이 검사는 ISO 구조와 바이트 보존의 증거입니다. 실제 부팅 증거는 별도입니다. 공식 배포 전 새 ISO를 읽기 전용으로 연결한 독립 BIOS CD 및 UEFI Kernel64 직접 부팅을 실행하고, 네트워크 없이 실제 serial 로그·종료 상태·ISO 실행 전후 해시를 저장해야 합니다. VM 실행은 배포 담당자의 자원·소유권 확인을 거쳐 별도로 수행합니다. 설치 메뉴를 자동 실행하는 검증은 이 최소 부팅 확인에 포함하지 않습니다.

다른 환경에서 소스만 확인하려면 `SOURCE.tar.gz`를 풉니다. Git 기록을 복원하려면 `git clone MAIN.bundle Win98-Modern` 다음 `git -C Win98-Modern checkout main`을 실행하고 `docs/CONTINUE_IN_ANOTHER_ENVIRONMENT.md`를 읽습니다. 기록된 소스 커밋과 해시를 확인한 후 필요한 구성요소를 실제로 다시 빌드·검증합니다.
