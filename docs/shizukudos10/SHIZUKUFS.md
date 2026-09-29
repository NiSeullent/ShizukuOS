# ShizukuFS v1 — ext4 형식의 대용량 파일 시스템

기준 시각: 2026-09-29. 브랜치 `worktree-agent-a6e461bffe2033fb1`(D1 블록 계층을 포함한 `chain1` 병합 후).
Kernel64 이미지+bss 끝은 0x23F840(≈2.25 MiB)로 `link.ld`의 3 MiB 한계 안이며, ShizukuFS가 더한 것은 텍스트 약 76 KB,
bss 약 6 KB뿐이다(캐시는 페이지 할당자/힙).
증거 종류는 BASELINE.md와 같다: `SOURCE` · `BUILT` · `HOST_TESTED` · `GUEST_RUN`(QEMU 게스트 실행).
이 문서의 모든 수치·결과는 이 세션에서 아래 명령으로 직접 재현한 것이다.

## 1. 스펙 선언

**ShizukuFS v1은 ext4 온디스크 형식 그 자체다.** 새 형식을 만들지 않고, Linux ext2/ext3/ext4와
e2fsprogs가 쓰고 읽는 형식을 그대로 읽고 쓴다(양방향 호환).

- `mkfs.ext4`로 만든 볼륨을 ShizukuFS가 읽고 쓰며, ShizukuFS가 쓴 볼륨은 `e2fsck -f`가 깨끗하다고 판정하고
  e2fsprogs(`debugfs`)가 같은 바이트로 읽는다(§6 매트릭스).
- 저널은 jbd2 형식(내부 저널, 체크섬 v2/v3, revoke, 64-bit 태그). e2fsprogs가 쓴 저널을 ShizukuFS가 재생하고,
  ShizukuFS가 쓴 저널을 e2fsck가 재생한다(§6 jbd2 상호 재생, 크래시 테스트).
- 참고한 명세: Linux 커널 `Documentation/filesystems/ext4/`, e2fsprogs `lib/ext2fs/ext2_fs.h`의 레이아웃,
  `Documentation/filesystems/journalling`/jbd2 형식 기술. **참고만 했고 GPL 소스는 복사하지 않았다**: libsfs는
  명세에서 새로 작성한 GPL-2.0-only 코드다(체크섬 식, 해시 함수(half-MD4/TEA/legacy) 같은 형식 정의상 고정된
  알고리즘은 명세대로 구현).
- 이전 ShizukuFS v0(Python 형식, `shizukufs/*.py`)은 **폐기(deprecated)**. 기존 v0 이미지·테스트용으로만 남긴다
  (`shizukufs/README.md` 상단 표기).

NTFS는 쓰지 않는다. 대용량·NVMe/eMMC 저장장치의 기본 파일 시스템이 ShizukuFS v1이며, Kernel64에서는
블록 레지스트리(`kernel64/blk.h`: AHCI 현재, NVMe/SDHCI 예정)를 통해 같은 코드가 동작한다.

## 2. 구성

| 경로 | 내용 |
| --- | --- |
| `shizukufs/v1/libsfs/` | 이식 가능한 C11 라이브러리(freestanding 가능: 외부 의존은 `memcpy/memset/memmove/memcmp/strlen`과 콜백 표뿐). 할당은 한 번에 최대 4 KiB(`SFS_MAX_ALLOC`) |
| &nbsp;&nbsp;`sfs.h` | 공개 API: mount/unmount/sync/statfs, lookup/stat/readdir/read/write/truncate/create/mkdir/symlink/readlink/unlink/rmdir/rename/set_times/set_mode, 경로 해석 |
| &nbsp;&nbsp;`sfs_super.c` | 슈퍼블록 검증/갱신, 그룹 기술자(crc16/crc32c), 비트맵(미초기화 그룹 계산), 마운트·트랜잭션·orphan 목록 |
| &nbsp;&nbsp;`sfs_inode.c` | inode 캐시(해시+LRU, write-back), 원시 inode 해석/기록, extra-epoch 타임스탬프, i_blocks(huge_file), inode crc32c |
| &nbsp;&nbsp;`sfs_extent.c` | extent 트리(인덱스 노드 포함) 조회/삽입(분할·깊이 증가)/절단(축약), 레거시 블록맵 읽기·해제 |
| &nbsp;&nbsp;`sfs_alloc.c` | 목표 지향 블록 할당, 선할당 윈도우, 지연 해제+revoke, Orlov식 inode 할당 |
| &nbsp;&nbsp;`sfs_dir.c`, `sfs_hash.c` | 선형·htree 디렉터리(조회·삽입·분할·레벨 증가·인덱스 해제), dirent tail/dx tail 체크섬, inline 디렉터리 읽기 |
| &nbsp;&nbsp;`sfs_file.c` | 파일 데이터(직접 extent 단위 I/O, 부분 블록 캐시), 희소 파일, 단계별 truncate, 심볼릭 링크, inline 데이터 읽기 |
| &nbsp;&nbsp;`sfs_jbd2.c` | jbd2: 로드/검증, 3단계 재생(SCAN/REVOKE/REPLAY), ordered 커밋, 체크포인트, clean 표시 |
| &nbsp;&nbsp;`sfs_cache.c`, `sfs_crc.c` | 블록 캐시(해시+LRU, 데이터 write-back, 메타데이터 트랜잭션 고정), CRC32C/CRC16 |
| `shizukufs/v1/tools/` | 호스트 글루(`sfs_host.c`: 이미지 파일 장치, 휘발성 쓰기 캐시 모의), `sfstool`(CLI) |
| `shizukufs/v1/tests/` | 매트릭스, 크래시, 퍼즈, 성능, jbd2 상호 재생, clean-on-sync 테스트 |
| `shizukudos/kernel64/sfs_mount.c` | Kernel64 마운트(blk.h 위의 libsfs, fsnode 매핑, NT 파일 연산) |
| `shizukudos/kernel64/vfs_mounts.[ch]` | 마운트 표(다음 빈 드라이브 문자, 파일 시스템 종류, 장치, flush/shutdown 훅) |
| `shizukudos/win64/tests/t_sfs_rw.c` | `T_SFS_RW.EXE` 게스트 자체 검사 |
| `shizukudos/tests/run_k64_sfs.py` | QEMU 실행 + 호스트 검증(e2fsck -fn, debugfs) |

빌드: `make -C shizukufs/v1`(ASan/UBSan `sfstool`/`sfsfuzz`, -O2 `sfstool-fast`/`sfsperf`, Kernel64 컴파일 플래그
그대로의 freestanding 컴파일 검사). Kernel64는 `shizukudos/kbuild.py`가 libsfs 소스를 두 커널 이미지에 링크한다.

## 3. 기능 표

### 3.1 읽기·쓰기 지원 (마운트 read/write)

| 기능 | 상태 |
| --- | --- |
| 블록 크기 1/2/4 KiB, `64bit`(48비트 블록 번호, 64바이트 기술자), `flex_bg`, `sparse_super`, `sparse_super2`, `meta_bg`, `resize_inode` | 읽기·쓰기 |
| `metadata_csum`(crc32c: 슈퍼블록, 그룹 기술자, 블록/inode 비트맵, inode, extent 블록, 디렉터리 leaf tail, dx 노드, xattr 블록 참조 카운트) — 읽을 때 검증, 쓸 때 생성; `metadata_csum_seed` | 읽기·쓰기 |
| `uninit_bg`/`gdt_csum`(crc16), `BLOCK_UNINIT`/`INODE_UNINIT` 그룹(비트맵 계산·초기화), `itable_unused`(지연 inode 테이블) | 읽기·쓰기 |
| extent 트리(깊이 0–5, 인덱스 노드, unwritten extent는 0으로 읽음; 쓰면 초기화), `huge_file`, `large_file`(필요 시 자동 설정), `extra_isize`(ns 타임스탬프, crtime, 2038년 이후 epoch 비트), `dir_nlink`(65000 초과 시 1) | 읽기·쓰기 |
| 디렉터리: 선형 + htree(half-MD4/TEA/legacy, signed/unsigned, 해시 충돌 연속 비트), 레벨 2(largedir 시 3) 읽기; 쓰기는 leaf 분할(크기 기준 중앙, 연속 비트), 인덱스 노드 분할, 루트 레벨 증가, 1블록 선형 디렉터리의 htree 변환. 인덱스를 더 키울 수 없으면 명세대로 인덱스를 해제(루트·노드를 일반 leaf로 재작성, INDEX 플래그 제거) | 읽기·쓰기 |
| 파일: 희소 파일, 4 GiB 초과(논리 블록 2^32까지), 덮어쓰기/추가/truncate(축소·희소 확장), 레거시 블록맵 파일은 읽기와 삭제(해제) | 읽기·쓰기 |
| 이름 공간: create, mkdir, symlink(fast ≤ 59바이트 / slow), readlink, unlink, rmdir, rename(디렉터리 간 이동, 기존 파일 덮어쓰기, 디렉터리 이동 시 ".." 갱신·순환 방지), set_times, set_mode | 읽기·쓰기 |
| 외부 xattr 블록: 참조 카운트 감소/해제(체크섬 갱신) | 삭제 시 |
| orphan 목록(`s_last_orphan`): 마운트 시 정리, 여러 단계 truncate/unlink의 크래시 보호 | 읽기·쓰기 |
| jbd2: v1/v2 저널 슈퍼블록, revoke, 64bit 태그, csum v2/v3, escape; 쓰기 시 Linux처럼 revoke/64bit/csum_v3 기능 설정 | 읽기·쓰기 |

### 3.2 읽기 전용으로만 마운트(이유는 `sfs_statfs.ro_reason`로 보고)

| 기능 | 이유 |
| --- | --- |
| `extents` 없음(ext2/ext3 블록맵 볼륨) | 새 블록을 블록맵으로 할당하지 않음(읽기·삭제는 가능하나 볼륨 단위로 RO) — `SFS_RO_NO_EXTENTS` |
| `inline_data` | inline 파일·디렉터리는 **읽기 지원**, 쓰기는 미구현 — `SFS_RO_INLINE_DATA` |
| `encrypt`, `casefold`(SipHash), `ea_inode`, `verity`, `quota`, `orphan_file`, `readonly`, fast_commit, 저널 errno, 오류 상태, 알 수 없는 ro_compat | 갱신을 올바르게 할 수 없음 — 각각의 `SFS_RO_*` |
| 재생이 필요한 저널 + 읽기 전용 마운트 요청 | 재생하지 않고 RO(내용이 오래되었을 수 있음을 로그) |

### 3.3 마운트 거부

알 수 없는 incompat 기능, `bigalloc`, `compression`, `journal_dev`(외부 저널 장치 자체), `mmp`, `dirdata`,
4 KiB보다 큰 블록, 장치보다 큰 파일 시스템, 슈퍼블록/그룹 기술자(읽기-쓰기 시) 체크섬 불일치, 구조 불일치.

## 4. 속도 설계

| 최적화 | 효과(§4.1 수치) |
| --- | --- |
| **extent 단위 직접 I/O**: 블록 정렬된 읽기/쓰기는 캐시를 거치지 않고 extent 길이만큼 한 요청(최대 8 MiB)으로 호출자 버퍼와 장치 사이를 이동. 캐시에 남은 더 새로운 dirty 블록은 읽은 뒤 덮어씀 | 1 GiB 순차 쓰기의 장치 요청 수가 블록당 1회에서 extent당 수 회로 |
| **목표 지향 할당 + 선할당 윈도우**: 목표 = 파일 직전 블록의 물리 후속; 파일 끝에서 자라는 파일마다 뒤따르는 빈 구간(32–2048 블록, 파일 크기에 비례)을 메모리에서만 예약해 다른 파일의 할당이 피해 감. 디스크에 기록하지 않으므로 크래시 후 누수 없음 | 128 MiB extent(최대 길이) 연속 |
| **워드 단위 비트맵 탐색**(64비트씩 0xFF…/0 건너뜀), 가득 찬 그룹은 기술자 카운트로 건너뜀 | |
| **htree**: 1블록을 넘는 디렉터리는 자동으로 해시 인덱스로 변환, 분할·레벨 증가로 유지 | 100k 파일 조회가 선형 탐색 대비 수 배 |
| **블록 캐시**(해시 512버킷 + LRU) + **검증 1회**: 체크섬·구조 검증은 장치에서 읽을 때 한 번만(`B_VERIFIED`) | |
| **extent 캐시**(inode당 마지막 extent), **inode 캐시**(해시 + LRU, write-back: 커밋 때 테이블 블록에 기록) | |
| **트랜잭션 묶기**: 메타데이터는 저널 용량의 1/4(최대 4096블록)까지 한 트랜잭션에 모아 커밋(동기화 요청 시에는 즉시). 크기 추정은 버퍼 수 + 해제가 닿는 그룹 수 | 작업당 flush 없음; 10만 파일 삭제가 커밋 2회 |
| **쓰기 합치기**: 선택적 `writev` 콜백으로 인접 블록을 한 요청으로 — 데이터 write-back(블록 번호로 정렬한 묶음), 저널 기술자 묶음(기술자+데이터 블록), 정렬된 체크포인트, 캐시 방출 시 인접 dirty 블록 동반(write-behind) | 10만 파일 생성 쓰기 요청 93,863 → 4,052 |
| **정렬된 체크포인트/저널 쓰기**(블록 번호 순 merge sort), **지연 저널 tail**(랩어라운드·언마운트 때만 저널 슈퍼블록 갱신) | 커밋당 flush 2회 |

### 4.1 성능 수치

`python3 shizukufs/v1/tests/run_perf.py`(1 GiB 순차 + 100,000개 1 KiB 파일, 10개 디렉터리). 같은 새 mkfs.ext4
이미지 복사본에서 최적화 모드와 `SFS_MOUNT_NAIVE` 기준선(직접 I/O·extent 캐시·선할당·htree 생성 없음, 캐시 64블록)
을 비교. 이미지가 호스트 페이지 캐시에 있으므로 **디스크 속도가 아니라 파일 시스템 코드와 I/O 패턴(요청 수·바이트·
flush)** 을 잰다. 호스트는 4코어를 약 18개 에이전트가 공유하는 부하 상태(load average 5–7)였다.

측정: 2026-09-29 19:39–19:47 UTC, 이미지 4 GiB(희소), 캐시 8192블록. 같은 명령을 여러 번 돌렸을 때 시간은 호스트 부하에
따라 ±50% 흔들렸고, **장치 요청 수와 바이트는 매번 같았다**(아래 표의 요청 수가 설계 효과의 안정적인 지표).

| 단계 | 최적화 | 기준선(NAIVE) | 장치 요청(최적화 / 기준선) |
| --- | --- | --- | --- |
| 1 GiB 순차 쓰기(1 MiB 요청) + sync | **1,208 MiB/s** | 173 MiB/s | 쓰기 1,076 / 262,105 |
| 1 GiB 순차 읽기(콜드) | **6,671 MiB/s** | 2,474 MiB/s | 읽기 1,030 / 262,145 |
| 1 KiB 파일 100,000개 생성+쓰기(10개 디렉터리) + sync | **13,070 files/s** | 797 files/s | 쓰기 4,052(450 MiB) / 100,784, 읽기 6,256 / 2,770,299 |
| 무작위 경로 조회 + stat 100,000회(콜드) | **105,164 ops/s** | 2,471 ops/s | 읽기 7,072 / 2,925,761 |
| 같은 조회(웜) | **121,986 ops/s** | 2,407 ops/s | 읽기 0 / 2,925,759 |
| 100,001개 삭제 + sync | **23,502 files/s** | 459 files/s | 쓰기 1,621, 커밋 2 / 쓰기 775, 읽기 5,690,741 |

두 실행 뒤 모두 `e2fsck -fn` 종료 코드 0. 1 GiB 파일은 262,145블록(데이터 262,144 + extent 트리 1)으로 128 MiB extent
8개. 이 세션 중 수치가 바뀐 이유(같은 작업의 이전 측정): 쓰기 합치기(`writev`) 도입 전 1 GiB 쓰기 요청은 1,100,
10만 파일 삭제는 커밋 62회·쓰기 102,203회(400 MiB) → 해제 추정을 그룹 단위로 바꾼 뒤 커밋 2회; 캐시 방출 시
쓰기 묶기 전 10만 파일 생성의 쓰기 요청은 93,863 → 4,052.

## 5. 안정성 설계

- **jbd2 ordered 모드**: 커밋 순서 = dirty 파일 데이터 → revoke 블록 → 기술자 블록 + 메타데이터 사본 → **flush** →
  commit 블록 → **flush** → 제자리 체크포인트. 데이터는 그것을 가리키는 메타데이터보다 먼저 매체에 있다.
- **지연 해제**: 실행 중인 트랜잭션이 해제한 블록은 커밋될 때까지 비트맵에 사용 중으로 남는다. 따라서 ordered
  데이터가 직전 커밋된 메타데이터가 아직 가리키는 블록에 쓰이지 않는다. 메타데이터 블록(디렉터리, extent 노드,
  slow symlink, xattr) 해제는 revoke 레코드를 남겨 이전 트랜잭션 사본이 재생되지 않게 한다.
- **원자적 작업**: 모든 갱신은 한 작업(`sfs_op_begin/end`) 안에서 트랜잭션에 합류한다. 여러 단계가 필요한 큰
  truncate/unlink는 inode를 orphan 목록에 올린 뒤 단계 사이에서만 커밋하므로, 중간 크래시 후에도 다음 마운트(또는
  e2fsck)가 작업을 끝낸다. 쓰기는 청크마다 크기를 갱신한 뒤에만 커밋 지점을 둔다.
- **실패 시 중단**: 수정을 시작한 작업이 I/O·구조 오류로 실패하면 트랜잭션을 버리고 볼륨을 읽기 전용으로 전환
  (디스크는 마지막 커밋 상태 그대로). 예상 가능한 실패(없음/존재/공간 부족)는 수정 전에 검출하거나 되돌린다.
- **모든 구조 검증**: 슈퍼블록 필드 범위, 기술자 위치, 비트맵/inode/extent/디렉터리/dx 체크섬, extent 정렬·겹침·
  범위, 디렉터리 rec_len/name_len, htree 깊이·limit, 저널 태그·revoke 범위, 순환 방지(깊이 한계, 가드 카운터).
  메타데이터 영역(슈퍼블록·GDT·비트맵·inode 테이블)을 가리키는 해제는 거부, 이중 해제는 오류로 처리.
- **clean-on-sync**(Kernel64 마운트 모드): 동기화가 끝나면 볼륨은 “깨끗이 언마운트된” 상태(needs_recovery 해제,
  저널 비움; 저널 없으면 VALID_FS)이고, 다음 갱신이 먼저 사용 중 표시를 한다. 저널에 데이터가 있는데
  needs_recovery가 꺼진 상태는 절대 만들지 않는다(커밋 전 재표시; `run_clean_sync.py`로 검사).

## 6. 검증 매트릭스

모든 호스트 테스트는 `make -C shizukufs/v1 all` 후 실행(검사 대상 `sfstool`/`sfsfuzz`는 ASan+UBSan 빌드, 누수 검사
포함). e2fsprogs 1.47.0(mkfs.ext4, e2fsck, debugfs, dumpe2fs, e2image)이 기준 구현이다. 증거 종류 `HOST_TESTED`,
Kernel64 행은 `GUEST_RUN`.

| 검사 | 명령 | 결과 |
| --- | --- | --- |
| 양방향 매트릭스 | `tests/run_matrix.py` | **14/14 구성 통과**. 읽기-쓰기 11구성: ext4 기본(4 KiB, 64bit, flex_bg, metadata_csum, huge_file, dir_nlink, extra_isize, 5 GiB 희소 파일), `-b 1024`(5 GiB 희소), `-b 2048`, `^metadata_csum`(uninit_bg crc16), `^64bit`, `64bit,huge_file,^flex_bg`(5 GiB 희소), `-T small -I 128`(128바이트 inode), `^has_journal`, `^dir_index`, `meta_bg,^resize_inode -b 1024`, `-g 8192`(다중 그룹). 구성마다 ① mkfs.ext4 -d 트리 1,523–1,524개 항목을 libsfs가 모두 읽어 종류·권한·크기·내용 해시·링크 대상·mtime(2100년, extra epoch)이 호스트와 일치 ② libsfs가 10,765개 작업(생성·덮어쓰기·추가·4 GiB 너머 희소 쓰기·축소/확장 truncate·디렉터리 간 rename·덮어쓰기 rename·디렉터리 이동·unlink·rmdir·fast/slow symlink·6,000항목 디렉터리 생성 후 절반 삭제·Linux가 만든 파일의 수정/삭제) 수행 → `e2fsck -fn` 종료 코드 0·문제 줄 0, `debugfs rdump` 결과가 호스트 미러와 바이트 단위 일치, libsfs 재읽기 일치, debugfs가 libsfs가 쓴 2101년 mtime 표시 ③ 두 번째 세션에서 대부분 삭제 → `e2fsck -fn` 0. 읽기 전용 3구성(ext3 블록맵 + 5 GiB 희소, ext2, `inline_data`): 모든 파일 해시 일치, 쓰기 거부(EROFS), 이미지 바이트 불변, e2fsck 0. **e2fsck -fn 28회 모두 종료 코드 0, 문제 0건** |
| jbd2 상호 재생 | `tests/run_jbd2_interop.py` | **5/5**: debugfs(e2fsprogs의 jbd2 코드)가 쓴 저널(csum v3·v2·없음, 64bit·32bit, 4 KiB·1 KiB; escape된 블록, revoke, commit 없는 트랜잭션)을 libsfs와 e2fsck가 각각 재생 → 대상 블록 5개가 서로·기대값과 일치, libsfs 재생 후 e2fsck -fn 0 |
| 크래시(4 KiB) | `tests/run_crash.py --trials 20 --seed 21` | **20/20**(SIGKILL 10, 전원 차단 10). 전원 차단 = flush 사이의 쓰기를 무작위 부분집합만 반영(재정렬·유실). 두 복구 경로 모두: e2fsck -fy(저널 재생) 후 다른 문제 없음·-fn 0 / libsfs 재생 후 -fn 0, 그리고 `crashverify`: 마지막 sync 이전 파일은 바이트 단위 동일, 이후 건드린 파일은 모든 블록이 그 파일 이력(작업 단위)의 한 버전이거나 0 |
| 크래시(1 KiB, 32bit) | `--trials 10 --seed 31 --mkfs "-b 1024 -O ^64bit"` | **10/10** |
| orphan 크래시 | `tests/run_crash.py --orphan` | **60/60** 크래시 지점: 20 MB 파일의 여러 단계 unlink/truncate(작은 트랜잭션으로 중간 커밋) 중 13번째 쓰기마다 차단 → orphan 26건을 e2fsck도 libsfs도 끝까지 처리, 파일은 원본 그대로이거나 완전히 삭제/절단 |
| clean-on-sync | `tests/run_clean_sync.py` | **3/3**(저널·저널 없음·1 KiB): 마운트 안에서 24회 디스크 상태 검사, 저널에 데이터가 있는데 needs_recovery가 꺼진 상태 0회, 크래시 후 e2fsck 경고 0 |
| 퍼즈 | `tests/run_fuzz.py --iterations 2000 --seed 5` | **통과**: 깨끗한 볼륨(메타데이터 49블록) 2,000회 + 재생 대기 볼륨(메타데이터·저널 1,038블록) 2,000회, 반복마다 1–3블록 손상(비트 반전·임의 바이트·필드 극값·0/0xFF 채움·다른 블록 복사) 후 마운트(RO/RW)·전체 순회·읽기·갱신·언마운트 → 크래시·새니타이저 보고·누수·20초 초과 0. 거부 210회, 순회 오류 11,218건(모두 오류 코드로 반환) |
| 최종 코드 재실행 | 위 명령들, 캐시 방출 묶기(커밋 91a5cf8) 이후 | clean-on-sync 3/3, jbd2 상호 재생 5/5, 크래시 4 KiB **12/12**(seed 41), 1 KiB **6/6**(seed 43), orphan **60/60**, 퍼즈 1,000+1,000회 통과, 매트릭스 **14/14**(첫 실행은 19:37 UTC 호스트 디스크 한도 소진과 겹쳐 debugfs rdump 사본이 잘려 8구성 실패 — e2fsck·libsfs 재읽기는 그때도 전부 통과 — 공간 정리 후 재실행 14/14) |
| 성능 | `tests/run_perf.py` | §4.1 |
| Kernel64 (MBR) | `python3 shizukudos/tests/run_k64_sfs.py` | **36/36 PASS**, `chain1` 병합 후 헤드에서 **38/38 PASS**(병합으로 기본 검사 2개 추가)(QEMU TCG, AHCI `ahci0`, 512 MiB): FAT32 p1 = D:, ShizukuFS p2(MBR 0x83) = **E:** 읽기-쓰기; `T_SFS_RW.EXE`가 모든 파일(32 MiB 희소 포함) 크기·CRC 일치, 쓰기/덮어쓰기/추가/truncate/이름 변경(교체 포함)/삭제/delete-on-close/rmdir/300파일(htree 생성)/100개 삭제/`NtFlushBuffersFile`; 종료 후 호스트: 파티션 `e2fsck -fn` 0·문제 0, needs_recovery 없음·state clean, debugfs로 게스트가 쓴 7개 파일 바이트 일치, 삭제·이동된 이름 없음, OUT/many가 htree이고 정확히 200개, 기존 파일 불변. 기존 standalone 검사(자체 테스트, Win64 앱 전체) 모두 통과 |
| Kernel64 (GPT) | `run_k64_sfs.py --gpt` | **36/36 PASS**, 병합 후 **38/38 PASS**(GPT Linux 파일 시스템 GUID로 인식) |

크래시 테스트가 찾아 고친 결함(재현 명령은 커밋 메시지): truncate의 0 채움 꼬리 블록이 작은 크기의 커밋보다 먼저
기록되면 “옛 크기 + 중간의 0” 상태가 남는 torn truncate → 꼬리 블록을 커밋 뒤로 미룸(`B_LATE`); orphan 정리가
이미 줄어든 i_size로 truncate를 다시 불러 블록이 남음 → EOF 너머 블록 해제, 완료까지 목록 유지; 정리된 inode가
기록 전에 캐시에서 버려짐 → `sfs_iforget`가 먼저 기록. QEMU 실행이 찾은 결함: 깨끗한 상태에서의 두 번째 sync가
슈퍼블록만 담은 트랜잭션을 needs_recovery 없이 커밋 → 커밋 전 재표시 불변식 + `run_clean_sync.py`.

## 7. Kernel64 마운트

- `disk_init()`(D1의 `disk.c`)가 파티션을 스캔하고 FAT32를 D:에 마운트한 뒤 `sfs_probe_all()`을 호출한다.
  모든 파티션(MBR 0x83, GPT Linux 파일 시스템 GUID `0FC63DAF-8483-4772-8E79-3D69D8477DE4`가 보통이지만 판단은
  슈퍼블록 매직)과 파티션 없는 전체 장치를 검사해 ext 슈퍼블록이 있으면 libsfs로 마운트하고
  `vfs_mount_next()`가 **다음 빈 드라이브 문자**를 준다(FAT32가 D:이면 ShizukuFS는 E:).
- 장치: blk.h의 `blk_read/blk_write/blk_flush`(512바이트 섹터, 정렬되지 않은 요청은 섹터 바운스). 검증은 D1의
  **쓰기 가능한 AHCI**(`ahci0p2`, WRITE DMA EXT + FLUSH CACHE EXT)로 했다. NVMe(S1)도 같은 blk.h 계약이면 코드 변경
  없이 동작해야 하나 이 세션에서는 실행하지 않았다.
- NT 파일 연산: 열기/생성(파일·디렉터리), 읽기, 쓰기(희소 확장), `FileEndOfFileInformation`(truncate),
  `FileDispositionInformation`·`FILE_DELETE_ON_CLOSE`(삭제, 빈 디렉터리), `FileRenameInformation`(같은 볼륨 내
  이동·교체), `NtQueryDirectoryFile`, `NtFlushBuffersFile`(커밋+체크포인트+장치 FLUSH, clean 상태로).
  fs.c/sysfile.c 변경은 `fsvol_t`의 선택적 `remove`/`rename` 연산과 그것을 부르는 경로뿐이며, 이 연산이 없는
  볼륨(FAT32)은 기존대로 `STATUS_NOT_SUPPORTED`.
- 종료: 정상 종료(exit 0/1) 하이퍼콜 경로에서 `vfs_shutdown()`이 모든 볼륨을 동기화한다. 그 사이 크래시는 저널
  재생(다음 마운트의 libsfs, 또는 e2fsck/Linux)이 복구한다.
- 메모리: 블록 크기 객체는 페이지 할당자, 나머지는 커널 힙. 볼륨당 캐시 512블록(2 MiB).

## 8. 한계

- 쓰기: `extents` 없는 볼륨(ext2/ext3), inline_data, encrypt, casefold, quota, verity, ea_inode, bigalloc,
  fast_commit 저널은 읽기 전용이거나 거부(§3). 블록맵 파일은 읽기와 삭제만.
- 블록 크기 최대 4 KiB(libsfs의 4 KiB 할당 한계). 디렉터리 크기는 largedir 없으면 2 GiB.
- unwritten extent에 쓰면 extent 전체를 0으로 채운 뒤 초기화(분할하지 않음; Linux fallocate 파일에서만 발생).
- 새 파일의 uid/gid는 0, 권한은 호출자 모드(Kernel64: 0644/0755). 확장 속성·ACL은 만들지 않는다(기존 xattr 블록은
  삭제 시 참조 카운트 처리).
- atime은 갱신하지 않는다(noatime 의미). 한 볼륨은 한 번에 한 스레드(Kernel64는 볼륨 뮤텍스).
- Kernel64 이름 공간: fs.c가 대소문자를 구분하지 않으므로 대소문자만 다른 두 이름 중 먼저 열거된 것만 보인다.
  127바이트를 넘는 이름과 일반 파일/디렉터리 이외의 inode(symlink, 장치, FIFO, 소켓)는 NT 이름 공간에 나타나지
  않는다(로그에 개수). 파일이 실행 이미지로 매핑되어 있는 동안은 쓰기·삭제·이름 변경 거부.
- Kernel64 이름 공간은 디렉터리를 처음 쓸 때 통째로 fsnode(약 250바이트, 커널 힙)로 열거한다(fs.c 설계). 커널 힙이
  12 MiB이므로 한 번에 수만 개를 넘는 항목을 가진 디렉터리는 열거가 중간에 실패할 수 있다(libsfs 자체는 htree로
  수십만 항목도 처리: §4.1의 10만 파일 측정).
- 성능 수치는 호스트 페이지 캐시 위의 측정이며 실제 NVMe/eMMC 처리량이 아니다. Kernel64의 AHCI 경로는 명령당
  512바이트 섹터 하나(D1 드라이버)라 커널 내 처리량은 이 설계의 상한이 아니다.
