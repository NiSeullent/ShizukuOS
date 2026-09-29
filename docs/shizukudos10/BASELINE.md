# ShizukuDOS 10.0 — 기준선 (BASELINE)

기준 시각: 2026-09-29. 브랜치 `codex/shizuku-independent-platform`, HEAD `008525b`
(`Record isolated VxD flag experiment and disposable QA acceptance`).
이 문서는 **조사한 사실**과 **이번 세션에서 직접 재현한 결과**, **사용자 보고**를 구분한다.
증거 종류: `SOURCE`(소스 존재) · `BUILT` · `HOST_TESTED`(호스트 모델) · `GUEST_RUN`(실제 게스트 실행) ·
`HARDWARE`(물리 장치) · `USER_REPORTED`(재현하지 못한 사용자 보고).

## 1. 작업 트리 상태

- 시작 시 43개 경로가 이미 수정/미추적이었다(`ntwddm/`, `ntwin32/exception|loader|tls`, `ntwrapper/vxd/v86diag`,
  `docs/*TRIAL*.json` 등, 이전 작업의 산출물). **이번 작업은 그 파일을 수정하지 않았고 커밋·푸시도 하지 않았다.**
- 신규 경로(전부 미추적): `shizukudos/{abi,dos16,kcommon,kernel32,kernel64,supervisor,tools,upstream}`,
  `shizukudos/kbuild.py`, `docs/shizukudos10/`, 이후 `compat/`, `docs/compat/`.
- 적용되는 `AGENTS.md`/`CLAUDE.md`/Cursor 규칙: **없음**(확인함). 기존 규약은 README/`platform/README.md`의 재현 명령과
  각 디렉터리 README, `.github/workflows/independent-platform.yml`.
- 서브모듈: `third_party/KernelEx`(미체크아웃 `-31cdfc3…`). 기존 KernelEx 경로는 회귀 참고용이며 이 작업이 사용하지 않는다.

## 2. 호스트 환경(사실)

| 항목 | 값 |
| --- | --- |
| CPU | Intel Xeon D-1521 (Broadwell-DE), VMX·EPT 있음, SVM 없음 |
| KVM | `/dev/kvm` 있음, `kvm_intel nested=Y` (L1이 VMX를 볼 수 있음) |
| QEMU | 10.1.0 (`/usr/libexec/qemu-kvm`, RHEL 빌드). **플로피 컨트롤러 없음** → DOS 이미지는 HDD로 구성 |
| 펌웨어 | OVMF `/usr/share/edk2/ovmf/OVMF_CODE.fd`, SeaBIOS(QEMU 내장) |
| 도구 | gcc 14.3, clang 21, NASM 2.16, mingw-w64 x86_64/i686 15.1, mtools 4.0.43, Open Watcom 2.0-beta(`build/tools/ow`, 고정 해시) |
| 디스크 | 루트 445 GB 중 약 35 GB 여유 — 로그·이미지 용량 주의 |

중첩 가상화 계층 표기: **L0**=이 Linux 호스트(KVM), **L1**=QEMU q35 + OVMF + Shizuku Supervisor(VMX root),
**L2**=Supervisor가 만든 도메인. L1 내부 기능은 Supervisor가 직접 CPUID/MSR로 탐지한 값만 사용한다.

## 3. 기존 구현의 실제 상태 (조사 결과)

| 영역 | 진입점/파일 | 증거 | 비고 |
| --- | --- | --- | --- |
| NTWrapper9x 코어 | `ntwrapper/core.c` | SOURCE·BUILT·HOST_TESTED (재현: `platform/test.py` PASS) | 핸들·이벤트·수명 코어. UEFI 종료 후 CPL0 시험은 기존 uefi32에서 |
| NTWin32Wrapper9x | `ntwin32/`, `NTW32.DLL` 15개 export | BUILT·HOST_TESTED, 실제 Win98 게스트 통과(**문서 기록**) | KernelEx와 무관. **x64 아님**(PE32) |
| NTWDDMWrapper9x | `ntwddm/` | BUILT·HOST_TESTED, Win98 게스트 GDI 프로브 통과(문서 기록) | 소프트웨어 GDI; WDDM/GPU 아님 |
| PCI-E/AHCI/FAT32/xHCI/USB | `drivers/*` | HOST_TESTED (재현 PASS: AHCI 5,034,065·xHCI 3,032,647 assertions) + 기존 QEMU 게스트 | Windows 98 바인딩 없음, 물리 미검증 |
| ShizukuDOS 0.1 | `shizukudos/boot.asm`, `stage2.asm` | BUILT, VirtualBox NEM 검증(문서) | **FreeDOS 아님**, 자체 미니 셸. 아래 10.0 프로필과 별개 |
| UEFI→32비트 PM | `shizukudos/uefi32` | 재현 PASS(호스트 512 게이트 + KVM 핸드오프) | 커널이라기보다 핸드오프 시험. DOS/VMX 없음 |
| PAE/SMP 시험기 | `shizukudos/pae`, `smp` | 문서 기록 | 이번 세션 재현하지 않음 |
| Windows 98 네이티브 시험 | `docs/NATIVE_*`, `win98lab` | 문서 기록 | NTW32 프로브·GDI 통과, **VxD 로드는 오류 2 / VXDLDR 6으로 실패** |
| Notepad++ (x86) | `docs/NPP_*`, `README.md` | **USER_REPORTED / 문서 기록** | 이번 세션 미재현. 성공·실패를 단정하지 않음 |
| KernelEx 기반 경로 | `src/`, `docs/*PORT*.md` | 기존 저장소의 산출물 | 새 독립 계층의 증거로 합산하지 않음 |

**VMX/SVM/Hypervisor 코드: 이 세션 이전에는 저장소에 없었다**(`git grep`로 확인). Long Mode 관련 문서는 앱 분석·UEFI
시작 환경에 관한 것뿐이며 **Win64 실행 경로는 존재하지 않았다.** FreeDOS 소스/패치/산출물도 없었다.
Wine/ReactOS는 `THIRD_PARTY.md`/`porting/`에 함수 단위 참조 기록만 있었다.

### 이번 세션의 기존 회귀 재현

`python3 shizukudos/tools/shz.py test --suite win98-regression` — 저장소 작업 트리의 **격리 사본**에서 README의 재현 순서를
실행: **20 PASS / 0 FAIL / 1 SKIP / 1 BLOCKED**. 기존 `*/build`는 지난 세션의 `/dev/shm` 링크가 끊어진 상태라
원본 트리에서는 `FileExistsError`가 났고(환경 문제, 원본 미수정), 사본에서 모두 통과했다. BLOCKED/SKIP은 실제 Win98 게스트
회귀(사설 lab 자원 필요)와 Notepad++(USER_REPORTED)이다.

## 4. 이번 세션 이후의 신규 구현 (요약; 세부는 STATUS.md)

- 외부 소스 프로필: **FreeDOS kernel ke2046 + FreeCOM**을 고정 커밋으로 받아 Open Watcom으로 소스 빌드(`shizukudos/dos16`).
- **Shizuku Supervisor**: UEFI x64 로더 + Intel VMX 백엔드(EPT, Unrestricted Guest, 선점 타이머).
- **Kernel32**(Protected Mode)와 **Kernel64**(Long Mode)를 서로 다른 ELF32/ELF64 이미지·툴체인·게스트 도메인으로 구현.
- 커널 간 통신 ABI와 검증된 IPC 라이브러리(`shizukudos/abi`).

## 5. 정책 (기존 독자 구현 vs 신규 외부 재사용)

| 프로필 | 내용 | 표기 |
| --- | --- | --- |
| 독자 구현(기존) | ntwrapper, ntwin32, ntwddm, drivers/*, shizukudos 0.1/uefi* | GPL-2.0-only, 외부 코드 없음을 유지 |
| 외부 재사용(신규) | FreeDOS(GPL-2.0-or-later), 이후 Wine/ReactOS 발췌 | `shizukudos/upstream/manifest.json`에 커밋·라이선스·패치 고정 |
| 신규 독자 구현 | Supervisor, vBIOS, Kernel32/64, ABI, 시험 도구 | `SPDX-License-Identifier: GPL-2.0-only`; 8x8 글꼴은 공개 도메인(출처 헤더 유지) |

두 프로필의 산출물을 섞어 "독자 구현"이라 표시하지 않는다. DOS16 이미지는 외부 프로필이다.
