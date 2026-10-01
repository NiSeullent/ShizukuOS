# 공홈 재개 묶음 게시 도구

공식 홈페이지와 새 소스·Git bundle·ISO 배포는 **https://m98.nyase.kr**로
통일합니다. GitHub push·PR·release는 수행하지 않습니다. 기존 공홈 게시의
단일 담당자가 이 절차를 실행해야 합니다. 현재 단계는 **SOURCE_ONLY / HOLD**:
실제 `/srv/m98/current` 변경, curl 요청, nginx·서비스 변경은 수행하지 않았습니다.

`tools/publish_m98_continuation.py`는 표준 라이브러리만 사용합니다. 기본은
읽기 전용 계획 출력이며, 명시적인 `--publish`에서만 새 릴리스를 만들고
현재 링크를 전환합니다. 실제 게시 후 확인에는 로컬 curl이 필요합니다.
기존 게시 도구를 실행하거나 nginx/DNS/서비스/VM/Git을 변경하지 않습니다.

## 승인할 입력

담당자가 최종 main 커밋과 산출물을 정한 뒤, 공개 가능한 파일만 담은 별도
export 디렉터리를 준비합니다. 소스 묶음에는 로컬 사이트 제어 파일,
SSH/TLS private key, 환경 변수·전역 설정·VM 비공개 파일을 넣지 마세요.
Git bundle의 이력에도 비공개 정보가 없음을 별도로 검토해야 합니다.
게시기는 아카이브 내용이나 ISO 라이선스를 새로 인증하지 않으며, 승인된
입력 SHA256과 크기를 검증합니다. 제어용 매니페스트는 공개되지 않습니다.

제어 매니페스트는 정확히 다음 필드를 사용합니다. 숫자·해시는 예시이며
담당자가 실제 파일의 값으로 바꿔 승인해야 합니다. `source`는 export
디렉터리 아래의 canonical 절대 경로이며 심볼릭 링크는 거부합니다.
`source_tar`는 `.tar.xz` 또는 `.tar.gz`를 허용합니다. gzip tar를 받는
remaster 절차에서는 `.tar.gz` 소스 파일의 실제 이름과 해시를 사용하세요.

```json
{
  "schema": 1,
  "release_id": "continuation-20261001-main",
  "commit_sha": "<40-character-final-main-sha>",
  "iso_mixed_provenance": true,
  "iso_provenance_note": "실제 ISO의 원본 매체·프로젝트 구성요소·혼합 출처와 시험 한계를 기재",
  "full_modern_features_verified": false,
  "modern_apps_verified": false,
  "os_certified": false,
  "artifacts": [
    {"role": "source_tar", "filename": "Win98-Modern-source-main.tar.xz", "source": "/EXPORT/Win98-Modern-source-main.tar.xz", "size": 1, "sha256": "<64-character-sha>"},
    {"role": "source_zip", "filename": "Win98-Modern-source-main.zip", "source": "/EXPORT/Win98-Modern-source-main.zip", "size": 1, "sha256": "<64-character-sha>"},
    {"role": "git_bundle", "filename": "Win98-Modern-main.bundle", "source": "/EXPORT/Win98-Modern-main.bundle", "size": 1, "sha256": "<64-character-sha>"},
    {"role": "iso", "filename": "Win98-Modern-development.iso", "source": "/EXPORT/Win98-Modern-development.iso", "size": 1, "sha256": "<64-character-sha>"}
  ]
}
```

추가할 수 있는 다섯 번째 파일은 `role: "evidence"`의 `.tar.xz` 증거 묶음뿐입니다.
각 파일은 최대 8 GiB, 합계 최대 12 GiB입니다. 공개 `manifest.json`에서 로컬
`source` 경로를 제거하고 공개 파일명·SHA256·크기·main 커밋·ISO 출처 설명과
false 검증 범위만 실습니다.

## 계획·게시·복원

기존 `/srv/m98/current`의 실제 대상은 협업 담당자의 게시로 바뀔 수 있습니다.
아래 `--expected-current`는 담당자가 실행 직전에 확인한 실제 릴리스여야
합니다. 기존 릴리스나 최종 산출물 경로를 이 문서의 예시로 고정하면 안 됩니다.

```sh
python3 -B tools/publish_m98_continuation.py \
  --manifest /PRIVATE/approved-publication.json \
  --manifest-sha256 <approved-manifest-sha256> \
  --artifact-root /EXPORT \
  --expected-current /srv/m98/releases/<approved-current-release>
```

위 명령은 계획만 출력하며 파일을 쓰거나 네트워크에 접속하지 않습니다.
단일 게시 담당자가 계획·입력·사이트 상태를 승인한 뒤 같은 명령에
`--publish`를 추가하면 다음 절차를 실행합니다.

1. 로컬 게시 lock을 얻고 승인된 current 대상과 기존 공개 파일 해시를 확인합니다.
2. 동일 filesystem의 새 `releases/<release-id>`에 기존 공개 파일을 hardlink합니다.
   새 디렉터리만 생성하며 내부 symlink나 private/control로 보이는 기존 파일은
   별도 검토가 필요하므로 거부합니다. 기존 파일의 write/chmod는 하지 않습니다.
3. 산출물을 별도로 복사·fsync·재해시하고 `site/downloads/<release-id>/`에
   한국어·영어 안내, 공개 manifest와 SHA256SUMS를 만듭니다. 기존 home index의
   nav에 공홈 다운로드 링크만 추가하며, 반드시 새 파일을 만들어 replace합니다.
   preview/ko/en/assets의 기존 bytes와 외부 noVNC 서비스·경로 설정을 보존합니다.
4. 이전 릴리스·원본 산출물·매니페스트를 다시 검증하고 current symlink를 atomic
   replace합니다. 기존 릴리스와 부분 준비물은 삭제하지 않습니다.
5. 각 새 사이트 파일을 로컬 HTTPS로 요청해 HTTP200·전체 응답 크기·SHA256을
   검증합니다. 정확한 옵션은 `--resolve m98.nyase.kr:443:127.0.0.1`와
   `--noproxy '*'`이며 redirect를 따라가지 않습니다. `--disable`로 curl의 전역
   설정 파일을 읽지 않습니다. 대용량 응답도 메모리에
   모두 쌓거나 디스크에 복제하지 않고 스트림으로 해시합니다.
6. 모든 원본·새 파일을 마지막으로 다시 확인하고 비공개 `build/`에 영수증을
   남깁니다. 실패하면 current가 아직 자기 릴리스를 가리킬 때만 이전 symlink의
   원래 문자열을 복원합니다. 다른 담당자가 current를 바꿨으면 덮어쓰지 않고
   복원 거부를 기록합니다.

CLI의 SIGINT/SIGTERM/SIGHUP은 잡을 수 있는 실패 경로로 전달합니다. SIGKILL,
호스트 장애나 filesystem 손상에서는 자동 복원을 보장할 수 없으므로 단일
담당자가 이전 symlink 대상과 비공개 실패 기록을 확인해 수동 복원해야 합니다.

기본 curl은 인증서를 검증합니다. 기존 로컬 origin 인증서 때문에 담당자가
`--origin-insecure`를 명시하면 인증서 검증은 **false**로 기록됩니다. 두 방식
모두 공개 edge/Cloudflare 외부 접근의 성공을 인증하지 않습니다. noVNC 설정은
전혀 수정하지 않으며, 그 실시간 서비스 기능을 게시 시험으로 인증하지 않습니다.
공개 안내는 ISO 혼합 출처·전체 최신 기능 false·GLSL/SIMD draft를 명시합니다.

기존 사이트에 이미 있던 문구·외부 링크는 이 도구가 전면 개편하지 않습니다.
새 안내와 추가 링크는 공홈만 사용합니다. 최종 홈페이지 문구 정리는 단일
게시 담당자가 별도 검토한 릴리스에서 처리해야 합니다.

## 자원과 한계

산출물 복사 전 실제 여유는 공유 바닥 **22,058,516,480 바이트** + 새 파일
크기 합계 + 16 MiB 이상이어야 합니다. 복사 중·전환 전에도 바닥을 확인합니다.
체크 간 외부 쓰기와 순간 overshoot를 원자적으로 막지는 못합니다. 게시 lock은
협업 담당자와의 단일 owner 예약을 대신하지 않습니다.

이 도구의 source-only 검사는 Python 구문·도움말·메타데이터/페이지 생성만
대상으로 합니다. 실제 hardlink 준비, symlink 전환·실패 복원, origin 응답,
대용량 복사·리소스 제한은 담당자의 승인된 최종 산출물로 아직 실행되지
않았습니다. 최종 배포 성공은 실제 영수증과 응답 해시를 확인한 뒤에만 주장해야
합니다. HTML DOM/전체 웹 표준/현대 앱/OS 목표는 계속 미완성입니다.
