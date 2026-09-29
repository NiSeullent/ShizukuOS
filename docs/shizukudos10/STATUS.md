# ShizukuDOS 10.0 — 상태 (STATUS)

`BASELINE.md`가 참조하는 문서. 증거 종류는 BASELINE과 같다:
`SOURCE` · `BUILT` · `HOST_TESTED` · `GUEST_RUN` · `HARDWARE` · `USER_REPORTED`.
"이번 세션"은 KVM이 없는 클라우드 컨테이너(Ubuntu 24.04, QEMU 8.2 TCG, mingw-w64 13, clang 18)에서 재현한 결과다.
원 개발 호스트(VMX·KVM 있음)의 결과를 이 문서가 대신 주장하지 않는다.

## 1. 이번 세션에서 직접 재현한 결과

| 항목 | 증거 | 결과 |
| --- | --- | --- |
| Win64 런타임 빌드(ntdll 70·kernel32 213 export, `-Werror`) | BUILT | PASS. 수정 전에는 링크 실패 (아래 2절) |
| 모든 import가 대상 DLL의 export에 존재 (t_hello→kernel32 13/ntdll 1, kernel32→ntdll 76) | BUILT (objdump 정적 점검) | 미해결 0 |
| PE32+ 파서 3,823,047 검사 + 15만 변이 퍼즈, ASan/UBSan | HOST_TESTED | PASS |
| 커널 간 ABI 모델 2,200,357 검사, ASan/UBSan/TSan, 독립 Python 디코드 | HOST_TESTED | PASS |
| Kernel32(ELF32)·Kernel64(ELF64) 빌드 | BUILT | PASS. 수정 전에는 Kernel64 링크 실패 |
| DOS16(FreeDOS ke2046 + FreeCOM) 재현 가능 빌드 | BUILT | PASS. 수정 전에는 이미지 해시가 매번 달랐음 |
| DOS16 레거시 BIOS 부팅(SeaBIOS, **TCG**) | GUEST_RUN | PASS (T_MODE/T_BIOS/T_COM/T_EXE, 종료코드 42) |
| `shz.py test --suite host` | — | VERIFIED (5 PASS) |
| `shz.py test --suite win98-regression` | HOST_TESTED / GUEST_RUN(TCG) | 19 PASS / 0 FAIL / 1 SKIP / 1 BLOCKED |
| 기존 UEFI x64 부팅, UEFI→32비트 PM 핸드오프 | GUEST_RUN (**TCG**) | PASS |

`win98-regression`의 BLOCKED는 설치된 Windows 98 체크포인트(`build/win98-lab`, 사용자 제공 자산) 부재,
SKIP은 Notepad++ (USER_REPORTED만 존재, 이 스위트는 게스트를 실행하지 않음)이다. Notepad++ 성공/실패를 이 문서는 단정하지 않는다.

## 2. 이번 세션에서 고친 결함 (원인 → 수정)

1. `RtlExitUserProcess`/`RtlExitUserThread`: `nt.h`에 `noreturn`이 이미 선언돼 있다. 생성 코드로 확인함
   (`NtTerminateProcess` 뒤에 `ret` 없이 `hlt; jmp`).
2. `ShzProcessHeap`: nt.h에서는 ntdll 내부 함수(비수출)로 선언, kernel32 두 파일은 같은 이름의 PEB 읽기 매크로로 덮어쓰고
   `k32_core.c`는 매크로 없이 호출해 **kernel32 링크가 실패**했다. `nt.h`의 PEB 기반 `static inline` 하나로 통일하고
   중복 매크로, ntdll의 함수 본체, 정의된 적 없는 `k32_process_heap` 선언을 제거했다.
3. `win64/build.py`의 K32API export 정규식이 아무것도 잡지 못해 `kernel32.def`에 forwarder 7개뿐이었다 → import 라이브러리가 비어
   t_hello 링크가 실패. 패턴을 분리해 214개 함수를 export한다.
4. mingw-w64 헤더가 `InterlockedIncrement`→`_InterlockedIncrement`로 치환해 실제 Win32 이름이 export되지 않았다 → 정의 앞에서 `#undef`.
5. `shzcrt.c`의 `-Werror=int-in-bool-context`.
6. `kbuild.py`가 Kernel64에 `win64/pe_parse.c`를 링크하지 않아 Kernel64 링크 실패 → `extra_c`로 링크.
7. `fatimg.py`: `mformat -v`가 볼륨 라벨 엔트리에 현재 시각을 기록해 DOS16 이미지가 재현되지 않았다 → `SOURCE_DATE_EPOCH` 고정.
8. Kernel64가 `fs_init()`도, `fs_load_archive()`도 호출하지 않아 WIN64.IMG(ntdll/kernel32/T_HELLO)가 **마운트되지 않았고**
   부팅 자체시험이 Win64 프로세스를 시작하지 않았다 → `kmain`에서 마운트, 자체시험이 `T_HELLO.EXE`를 두 번 실행(종료코드 7, 무결함,
   두 번째 실행이 모든 페이지를 반환). 증거 슬롯 19–23·30을 Supervisor 하니스(`check_win64`)가 호스트 쪽에서 검증한다.
   `t_hello`는 슬롯 16–18(ring-3 "high" 시험 사용)과 충돌하지 않게 19–21로 옮겼다.
9. 이식성: QEMU/OVMF 경로 탐색(Fedora·Debian/Ubuntu), `ntwin32/loader/evidence.py` 글꼴 대체.

## 2b. 통합 Shizuku SE ISO (`tools/build_shizuku_se_iso.py`, 시험: `shz.py test --suite iso`)

한 ISO에 ShizukuDOS 0.1(자체 구현, BIOS 플로피 에뮬레이션), ShizukuDOS 10.0(외부 FreeDOS 프로필 + Supervisor + Kernel32/64 + WIN64.IMG,
UEFI El Torito), NTWrapper9x/NTWin32Wrapper9x/NTWDDMWrapper9x 산출물을 담는다. 두 프로필은 서로 다른 디렉터리로 분리 표기한다.
Microsoft 파일은 넣지 않는다. 사용자 소유 Windows 98 미디어는 `--win98-media`로 별도 `-private` ISO에만 겹쳐 넣고 `build/`(git 무시)에 둔다.

| 항목 | 증거 | 결과 (QEMU TCG, KVM 없음) |
| --- | --- | --- |
| El Torito 2엔트리(BIOS fd1.4 + UEFI 0xEF), 부팅 이미지 바이트 일치, EFI 이미지 FAT + `BOOTX64.EFI` | GUEST_RUN/HOST_TESTED | PASS 6 |
| BIOS(SeaBIOS)로 ISO 부팅 → `A:\>` 프롬프트, `DIR`에 NTW32.DLL/NTWRAP9X.VXD/NTWGPROB.EXE | GUEST_RUN | PASS 4 |
| UEFI(OVMF)로 ISO 부팅 → Supervisor 로더 시작, VMX 없음을 보고하고 펌웨어로 복귀 | GUEST_RUN | PASS 3 (**멀티커널 부팅이 아니라 VMX 불가 경로**) |
| Supervisor 위의 DOS16/Kernel32/Kernel64/Win64 도메인 | — | BLOCKED (Intel VMX 필요) |
| Windows 98 설치 완료 | — | **BLOCKED, 검증되지 않음** (미디어 없음). `INSTALL.BAT`은 실행하지 못했다 |

전체: 14 PASS / 0 FAIL / 5 BLOCKED → INCOMPLETE. ISO는 CD/DVD 전용(USB 하이브리드 아님). `--win98-media` 경로는 표식된 합성 자리표시 파일로
코드 경로만 시험했으며 Windows가 설치된다는 증거가 아니다.

## 3. 이번 세션에서 실행하지 못한 것 (BLOCKED)

| 항목 | 이유 |
| --- | --- |
| Supervisor(Intel VMX) 위의 DOS16 가상 Real Mode, Kernel32, Kernel64, **Win64 앱 실행** | 컨테이너에 `/dev/kvm`이 없어 L1에서 VMX를 볼 수 없다. TCG 부팅은 VMX 백엔드를 시험하지 않는다. 2절 8번의 Win64 자체시험은 **빌드·링크만 됐고 실행되지 않았다** |
| AMD SVM 백엔드 | 로더는 탐지만 하고 백엔드 미구현, AMD 호스트 없음 |
| 외부(제3자) Win64 앱 | 제공·실행된 앱 없음 |
| Windows 98 설치(완료까지)와 설치된 Win98 위의 NTW32/VxD/GDI 회귀 | 사용자 제공 Windows 98 미디어/체크포인트가 이 컨테이너에 없다. 기록된 알려진 실패: VxD 절대경로 로드가 오류 2 / VXDLDR 6 |
| Notepad++ 실행 | USER_REPORTED만 존재 |

## 4. 저장소 반영 상태

브랜치 `wip/shizukudos-10-toydzv`는 원격에 올라가 있고 PR #2로 추적한다. (초기에는 `git push`가 403으로 거부됐고 이후 접근이 복구됐다.)
