# m98.nyase.kr 운영·배포

공식 사이트는 기존 nginx origin의 정적 파일로 운영합니다. **홈페이지·ISO 다운로드는 [m98.nyase.kr](https://m98.nyase.kr/)**에서 제공하며 공개 범위는 [배포 기준](OFFICIAL_DISTRIBUTION.md)을 따릅니다.

## 운영 구조

| 위치 | 역할 |
| --- | --- |
| `site/` | 한국어·영어 페이지와 공개 자산의 소스 |
| `site/deploy/m98.nyase.kr.conf` | 사이트 전용 nginx vhost 설정 |
| `site/deploy/m98-locations.conf` | 정적·다운로드·기존 콘솔 경로 설정 |
| `/srv/m98/releases/<release>/site` | 불변 정적 릴리스 |
| `/srv/m98/current` | 현재 릴리스 링크 |
| `/srv/m98/nginx/locations.conf` | 운영 nginx의 안정된 경로 설정 |
| `build/m98-self-host/` | 게시·응답 검증 기록 |

기존 운영 vhost는 `/srv/conf.d/nginx/conf.d/m98.nyase.kr.conf`에 있습니다. HTML은 `no-store, no-transform`으로 제공하며 옛 `/vnc.html`·`/vnc_lite.html`은 배포 페이지로 이동합니다. 기존 VM 콘솔은 `/legacy-console/`로 분리되어 있습니다.

기록 미리보기는 원본 게스트 캡처를 사용합니다. 기존 호환성 VM을 새 ShizukuOS 실행 화면으로 표시하지 않습니다. 라이브 연결은 실제 검증한 게스트의 접속 주소가 준비될 때까지 연결되지 않은 상태입니다.

## 수정과 검증

저장소 루트에서 실행합니다.

```sh
python3 -m http.server 8080 --bind 127.0.0.1 --directory site
python3 -m unittest discover -s site/deploy/tests -p 'test_*.py'
```

첫 명령은 로컬 미리보기 서버이며 두 번째 명령은 다른 터미널에서 실행합니다. 테스트는 경로·언어 연결·다운로드 무결성·증거 보존·배포 제어를 검사합니다. 테스트 자체는 운영 사이트를 게시하거나 VM을 부팅하지 않습니다.

## 기존 origin에 게시

ISO 변경 없이 정적 페이지와 기존 구성요소를 게시:

```sh
python3 site/deploy/publish_static.py
```

공개 개발 ISO를 함께 게시하려면 실제 ISO 경로와 빌더 영수증에 기록한 소스 commit을 지정합니다.

```sh
python3 site/deploy/publish_static.py \
  --iso build/<public-image>.iso \
  --iso-source-commit <40-character-lowercase-commit>
```

ISO 옆의 같은 이름의 `.json` 영수증은 파일 경로·크기·해시·commit이 일치하고 `private: false`여야 합니다. 공개 ISO는 최대 512 MiB이며 Microsoft 미디어를 포함한 개인 이미지와 링크·특수 파일은 거절합니다. 실제 배포 ISO의 두 콜드 부팅 결과가 있으면 `--iso-boot-evidence <result.json>`으로 연결할 수 있습니다. 이 결과는 독립 개발 데스크톱의 시험 범위를 표시합니다.

게시기는 공개 자산을 검증하여 새 릴리스에 복사하고 `/srv/m98/current`만 교체합니다. 정확한 루프백 HTTPS 응답·다운로드 크기·해시·Range를 확인한 뒤 PASS 영수증을 기록합니다. 실패 시 이 작업이 여전히 현재 릴리스 링크를 소유하는 경우 이전 링크로 되돌립니다. 게시 잠금이 사용 중이면 새 게시를 거절합니다.

이 도구는 **이미 구성된 m98 origin용**입니다. nginx·DNS·VM·다른 서비스를 자동 변경하지 않습니다. 새 호스트에서는 문서 루트·인증서·공통 include·Cloudflare 전달 설정을 먼저 실제 환경에 맞춥니다. 비밀 키와 토큰은 저장소에 넣지 않습니다.

## 접근 결과 확인

origin 검증과 공개 주소 검증은 별도로 기록합니다. 과거 자동 요청에는 Cloudflare challenge가 있었고, 이후 표준 브라우저 User-Agent를 사용한 일부 공개 HTTPS 경로의 정확한 응답도 기록되었습니다. 이를 모든 클라이언트의 접근 보증으로 확장하지 않습니다. 새 게시 후 실제 외부 브라우저에서 한국어·영어·다운로드·미리보기를 확인하고 서버 밖의 검증 결과를 남깁니다.

최신 게시 판단은 `build/m98-self-host/`의 해당 릴리스 영수증과 현재 링크를 대조합니다. 과거 실패·원본 화면·패키지 해시는 보존하며 사이트 디자인 변경으로 검증 결과를 바꾸지 않습니다.
