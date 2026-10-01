# 공식 배포 기준 — 2026-10-01

공식 홈페이지와 새 소스·Git bundle·ISO 다운로드 배포처는 **https://m98.nyase.kr**입니다. 사용자의 최신 지시에 따라 GitHub에 새 push, PR 또는 release를 게시하지 않습니다. 기존 Git 이력·오픈소스 원본과 라이선스 출처는 보존합니다.

`main` 통합과 공홈 배포는 BOOT 주담당 세션, 사이트 게시·공개 접속 확인은 협업 담당자가 진행합니다. 별도 작업트리의 검토 자료는 주담당에게 전달하며, 서로의 index·서비스·VM을 변경하지 않습니다.

다른 환경으로 옮길 때는 공홈에서 실제 게시된 소스 압축 파일 또는 `main` Git bundle과 해당 SHA256/commit 매니페스트를 사용합니다. [다른 환경에서 이어서 작업하기](CONTINUE_IN_ANOTHER_ENVIRONMENT.md)에 준비물과 읽기 전용 환경 점검 절차가 있습니다. 이 문서는 아직 생성되지 않은 공개 파일이나 완료되지 않은 main 병합·ISO 시험을 완료했다고 주장하지 않습니다.

GLSL/SIMD 초안과 엄격한 TLS native 시험의 준비 소스도 별도로 보존했습니다. 소스 통합·ISO 부팅은 전체 최신 JavaScript/CSS/Wasm, WebGL/WebGPU, Signal·Legcord·최신 Office·OS TLS 1.3 완료 증거가 아닙니다. 각 구성요소의 실제 검증 범위와 미완료 상태는 고정 소스·원래 영수증과 함께 확인해야 합니다. Microsoft Windows 원본, 제품 키, 비공개 VM·TLS 키는 공개 배포에 포함하지 않습니다.
