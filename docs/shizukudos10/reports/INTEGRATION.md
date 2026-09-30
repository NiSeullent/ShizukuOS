# ShizukuDOS 10 — integration verification (I2)

Each pass: fresh `wip/integration` from `origin/wip/shizukudos-10-toydzv`, agent branches merged one at a time with
`git merge --no-ff` (order: n4-ntdrv-coverage, n3-driver-load, k5-chromium-dlls, k4-chromium-run, r1-release), full gate
set after every merge, failed merges reset off the pass. The newest pass is first. All QEMU runs use `--accel tcg`
(no /dev/kvm) on a 4-core container.

**Environment:** Ubuntu 24.04. apt packages from both jobs of `.github/workflows/independent-platform.yml`, plus
`xxd`, which `shizukudos/csm/build.py` needs; it is not in the workflow list. The container's default `python3` is 3.11
(`/usr/local/bin`), which cannot load apt's `python3-pil` (built for 3.12), so every gate runs with `python3` →
`/usr/bin/python3.12`, the Ubuntu default that CI uses. The first run under 3.11 failed `platform/test.py` at
`ntwin32/tls/test.py` (`ImportError: cannot import name '_imaging' from 'PIL'`). That was the environment, not the tree.

**Gate list, in order:** `platform/build.py`, `platform/test.py`, `platform/abi32/build.py`, vxd build+test, ntwddm make
test/freestanding/sanitize, `platform/freestanding/test.py`, ntwddm/win98 test+build, pcie make + i486 object check,
uefi/uefi32/ahci/fat/xhci/usb/usb_config build+test, win98lab storage/packed/trial tests, native runner + logs,
app_probe (both modes), `ntwin32/exception/test.py`, `win64/tests/test_pe_parse.py` + `abi/test_abi.py`,
`win64/build.py`, `kbuild.py`, `run_k32_standalone.py`, `run_k64_standalone.py` ×2, `run_k64_gui.py`, `run_k64_net.py`,
`run_k64_disk.py`, `run_k64_sfs.py`, `run_k64_ntdrv.py`, `win64/tools/import_coverage.py`, `run_k64_storage.py`,
`dos16/build.py` (the input that `supervisor/build.py` asks for), `supervisor/build.py` + `supervisor/test_bootmgr.py`,
and `shz.py test --suite media` when the tree has it.

## Read first — what the lead needs to know (2026-09-30T10:15Z)

1. **The lead's base is red on two gates, independent of any agent branch.** At base `f97a2de` (and unchanged at `513808d`: `t_disk.c` and the FAT32 code are not in the
   diff between them) `run_k64_disk.py` and `run_k64_storage.py` fail deterministically: `T_DISK.EXE` line `shizukudos/win64/tests/t_disk.c:263`,
   `U_CHECK("delete on D: is refused (not supported)", !DeleteFileA(outs[1]))`, prints `FAIL: delete on D: is refused (not supported)` because K3's commit `a27935f`
   ("FAT32 delete/rename", in the base since PR #9) made `DeleteFileA` on D: work. The delete then removes `D:\OUT\Sub Dir\small.txt` before the read-back, so
   `FAT32 write: the guest read back what it wrote ... OUT/Sub Dir/small.txt: guest (0, 0) host (46, 326510751)`. Reproduced on base `f97a2de` alone in a clean worktree
   (`run_k64_disk.py`: 2 of 29 T_DISK checks failed; `run_k64_storage.py`: same) and identical with k4 merged. The test's expectation (or the feature) needs updating by the owner of
   `t_disk.c` / K3. Until then no merge can turn these two gates green.
2. **`run_k32_standalone.py` hangs intermittently in the base** (about 2 % of runs: base `f97a2de` alone 4 of 240; 3 hangs after `K32 test PASS: #PF handler demand-maps 16 kernel pages`
   with `qemu_rc=-9` after the 120 s timeout, 1 unexpected ring-3 `#GP` with exit code 98). Not caused by k4: the Kernel32 image is byte-identical with and without k4 (below).
3. **`wip/integration` on origin is no longer only I2's merges.** The lead merged PR #30 (`wip/e1-electron`) into it (`d48508a`, 09:35Z). I2 therefore does not reset or force-push it;
   it pushes fast-forward commits on top. The merge commits I2 builds and gates live in local fresh-from-base worktrees, and the tables give (base commit, branch commit, tree hash),
   which the lead reproduces with `git merge --no-ff <branch>` on that base. A tree hash is reproducible only on the same base tree.
4. At the newest base `513808d` (tree `efc0967755f3b5292afa59da444530a4473dd968`) every listed branch merges cleanly on its own by `git merge-tree`:
   n4 `25588c3`, k5 `bbaf38e`, k4 `bf73d7d`, e1 `31a1cc8`, w2 `96c2738` (w1 `06b48ab` and w3 `7b80cee` are already in it). The n4 and k5 conflicts recorded in pass 4 below are therefore stale for
   those tips. Pass 5 starts from `513808d` with the extended order n4, n3, k5, k4, e1, w1, w2, w3 and their runners; nothing about those tips is verified yet.

## Pass 4 — 2026-09-30T08:15:13Z to 10:05Z (COMPLETE for k4 at base `f97a2de`; the lead's base has since moved to `513808d`)

Base `f97a2de87432720fd984c8e67bc3effec6cf9612` (tree `366c85bfb9dd06ce554cc4f020ad74a40ad503b3`). This base already contains
N3 (`f78a07e`, merged by the lead with its own overlap notes), K3/K4-earlier/E1 through `main`, R1 and N4 `f0f7a74`.
Agent tips at the start of the pass: n4 `13c3157`, n3 `f78a07e` (0 commits ahead of the base), k5 `0a0adb9`, k4 `d212e35`;
`wip/r1-release` is not on origin (R1 is in the base). `wip/e1-electron` is not on the I2 merge list; it is in the base via `main`.

| branch | commit | result | tree after merge | notes |
|---|---|---|---|---|
| wip/n4-ntdrv-coverage | `13c3157` | **FAILED at merge** (no gate ran) | — | 6 conflicted files, 15 hunks, not a pure conflict; evidence below |
| wip/n3-driver-load | `f78a07e` | already in the base | — | nothing to merge; its code is covered by the gates of the next row |
| wip/k5-chromium-dlls | `0a0adb9` | **FAILED at merge** (no gate ran) | — | 2 conflicted files, 3 hunks, two mechanisms for the same feature; evidence below |
| wip/k4-chromium-run | `d212e35` | merge commit `7af6b57` (local, not pushed): **NOT PASSED, but no regression against the base.** 33 of 35 gates pass; the two failing gates, `k64_disk` and `k64_storage`, fail identically on the base `f97a2de` without k4 (Read first, item 1); `k32` failed once and passed on rerun, and the same hang exists in the base (item 2) | `ee539fc0191629e1d2d430c4c286ba3ce8d927c2` | merges clean; `run_k64_chromium.py`: FAIL as expected, kernel did not crash (below) |
| wip/r1-release | — | in the base | — | branch not on origin |

Extra runners for this pass: `run_k64_pnp.py` (added by N3, now in the base) inside the gate run; `run_k64_chromium.py` afterwards,
where a FAIL is expected until the Chromium milestone and only a kernel crash or a regression elsewhere counts against a branch.
`run_k64_electron.py` is not run (E1 is not on the merge list; it needs inputs this machine does not have).

### k4 (`d212e35`) — gate results at base `f97a2de` + k4 (merge `7af6b57`, tree `ee539fc0`)

| gate | result | time | note |
|---|---|---|---|
| `platform_build` | PASS | 2s |  |
| `platform_test` | PASS | 27s |  |
| `abi32` | PASS | 5s |  |
| `vxd` | PASS | 4s |  |
| `ntwddm` | PASS | 0s |  |
| `freestanding` | PASS | 1s |  |
| `ntwddm_win98` | PASS | 2s |  |
| `pcie` | PASS | 1s |  |
| `uefi` | PASS | 2s |  |
| `uefi32` | PASS | 2s |  |
| `ahci` | PASS | 3s |  |
| `fat` | PASS | 20s |  |
| `win98lab` | PASS | 6s |  |
| `native_runner` | PASS | 5s |  |
| `app_probe` | PASS | 8s |  |
| `exception` | PASS | 2s |  |
| `xhci` | PASS | 3s |  |
| `usb` | PASS | 17s |  |
| `pe_parse` | PASS | 135s |  |
| `win64_build` | PASS | 227s |  |
| `kbuild` | PASS | 47s |  |
| `k32` | FAIL (first attempt) | 121s | 120 s timeout, hang after the demand-paging test; see below |
| `k32` | PASS (rerun, same tree) | 0s |  |
| `k64_standalone_1` | PASS | 98s |  |
| `k64_standalone_2` | PASS | 94s |  |
| `k64_gui` | PASS | 141s |  |
| `k64_net` | PASS | 235s |  |
| `k64_disk` | FAIL | 98s | `T_DISK.EXE`: `FAIL: delete on D: is refused (not supported)`; same failure on base alone |
| `k64_sfs` | PASS | 100s |  |
| `k64_ntdrv` | PASS | 1s |  |
| `import_coverage` | PASS | 0s |  |
| `k64_storage` | FAIL | 221s | same `T_DISK.EXE` failure; same on base alone |
| `dos16_prereq` | PASS | 6s |  |
| `supervisor` | PASS | 626s |  |
| `media_suite` | PASS | 2362s |  |
| `run_k64_pnp` | BLOCKED, then PASS (2 s, 11 checks) | 2s | first attempt: `BLOCKED: driver corpus not built`; after `ntdrv/corpus/fetch.py` + `build.py --packages` (23 of 27 drivers built) it passes |

The `media` suite (`shz.py test --suite media`) passed in 2362 s. Gates 1 to 21 ran in `p4-k4`, `k32` to `k64_disk` in `p4-k4b`, `k64_sfs` onward in `p4-k4c` (the runner was resumed after each
failure so that one inherited failure does not hide the later gates; nothing was skipped). `import_coverage` and `k64_ntdrv` pass.

**`run_k64_chromium.py` (Chromium snapshot 1706750, `chrome.exe` sha256 `50e3f9ee0aa1c2d55bde01aa822c7a91fa558fa73fdf2648d05bc00b2ba2c93e`, tree of 258 files), `--accel tcg`:**
`status` FAIL (expected until the milestone), `seconds` 16.4, `exit_code` 0x80000003, `faulted` false, `ended_by` exited, `autorun_result`
`K64 autorun: result exited exit=80000003 faulted=0 reaped=0 after 13100 ms`, `expected_line_seen` false, `chrome_output_line_count` 69, `loader_failures` [], `exceptions` [], `qemu_timed_out` false,
`unsupported_calls` []. Furthest point: `FATAL:chrome\common\win\delay_load_failure_support.cc:39] NOTREACHED hit.` (Chromium's fatal delay-load hook; the run's `git.revision` is `7af6b57`,
`dirty` false). The Kernel64 guest ended with `SHZ-EXIT:0`: no kernel crash, and the other gates show no regression from k4.

### Status at 2026-09-30T08:45Z (earlier status of this pass, kept for the record)

- The lead's base moved to `03a564e` (tree `c310a1fa671ae92c9d92c785ea77dbc6be6dde56`) during the pass: PR #16 (this report) and PR #17 (W1 WebKit: `win64/webkit/*`, `run_k64_webkit.py`, `shz.py`, `upstream/manifest.json`).
  The gates below run on `f97a2de` + k4, not on `03a564e` + k4; the two differ by those W1 files and this document.
- n4 is now at `e8de1e9` (5 commits ahead of `03a564e`) and k5 at `39341852` (14 ahead): `git merge-tree` still reports the **same** conflicts
  (n4: the same six `shizukudos/kernel64/ntdrv_*.c` files; k5: `win64/build.py`, `win64/tests/t_u_version.c`). k4 `d212e35` still merges clean.
- **`k32` (run_k64_standalone's sibling `run_k32_standalone.py`) failed once at gate 22 with k4 merged, and the same failure exists in the base without k4.**
  Evidence: (1) gate log `22-k32.log`: `[FAIL] run finished before the timeout  120s, accel=tcg`, `qemu_rc=-9`, `marker=0x0`, serial ends at
  `K32 test PASS: #PF handler demand-maps 16 kernel pages` (the next stage, the ring-3 test, never reports). (2) The Kernel32 image is byte-identical with and without k4:
  `KERNEL32S.BIN` sha256 `5da79d3d88412a2dfdb4...` in both trees, built at the same path (images embed absolute source paths, so only same-path builds compare).
  k4 changes only `win64/kernel32`, `win64/ntdll`, `win64/tests` and docs, not `shizukudos/kernel32`. (3) Repeats: the k4 tree failed 1 of 30 further runs at the same point;
  the base `f97a2de` alone failed 4 of 240 runs (3 at the same point, 1 with an unexpected ring-3 `#GP`: `K32 EXCEPTION #GP (vec 13) err=0 eip=40000011 cs=1b`, exit code 98,
  `[FAIL] ring-3 exit code 42, #GP and #PF contained  42 0x0 0x0`). Each run takes 0 to 1 s when it passes. The test was not skipped, changed or quarantined; the failures are
  reported here as they happened. Cause unknown; it sits in the Kernel32 ring-3 phase (about 2 % of runs) and belongs to whoever owns `shizukudos/kernel32`.

### Why n4 (`13c3157`) was not merged — evidence

`git merge origin/wip/n4-ntdrv-coverage` onto the base: `CONFLICT` in `shizukudos/kernel64/ntdrv_io.c` (6 hunks), `ntdrv_ke.c` (2),
`ntdrv_mm.c` (1), `ntdrv_pnp.c` (2, **add/add**: the base's file has 824 lines from N3, N4's has 1816 lines from its second export
batch), `ntdrv_prov.c` (3), `ntdrv_zw.c` (1). Not a pure text conflict: the two branches implement the same NT-kernel services
differently. Examples from the hunks: IRQL (`ntdrv_ke.c` `set_irql`: N4 keeps a global `g_irql` mirrored into CR8, N3 keeps a per-thread
IRQL behind `cur_irql()`/`write_irql()`); object references (`ntdrv_zw.c`: N4 counts references on device objects, N3's
`ObfReferenceObject` is a no-op that returns 1); `MmInitializeMdl` and `IoBuildPartialMdl` in `ntdrv_mm.c`. `docs/shizukudos10/reports/N3.md`
section "Overlap with N4's second export batch" already lists 40 exports defined on both sides and the merge order it suggests.
Choosing a side per hunk is a design decision in the agents' code, so I2 did not resolve it. N4 needs to be rebased onto the base by
its owner (or the lead reconciles it as N3 describes).
Earlier evidence that N4 itself is sound on an older base: in pass 3 (below) `13c3157` merged cleanly onto `662e756` and passed 25 of 34 gates.

### Why k5 (`0a0adb9`) was not merged — evidence

`git merge origin/wip/k5-chromium-dlls` onto the base: `CONFLICT` in `shizukudos/win64/build.py` (2 hunks) and
`shizukudos/win64/tests/t_u_version.c` (1 hunk). The base (K4, commit `96ddb06`) gives kernel32 and ntdll a VERSIONINFO through
`version_resource(W64 / "ntdll" / "ntdll.rc")` (and the same for kernel32); K5 (`8974020`, "VS_VERSIONINFO in every built DLL and EXE") does the
same through `version_obj("ntdll.dll", ...)`. In `t_u_version.c` the base checks a no-resource PE against `T_HELLO.EXE`, K5 checks a
generated `NORSRC.DLL` fixture and deletes it. Keeping both mechanisms or dropping one changes what the two branches' tests assert, so
I2 did not resolve it. K5 needs to be brought onto the base by its owner.

## Pass 3 — 2026-09-30T07:57:54Z to 08:15Z (ABORTED: the lead moved the base again, nothing here is a PASS for a branch)

Base `662e756387421b706f7522ac935a96f3c6ab9a08` (tree `12ee02209430af9c9266d7fa1f2b1845b5a4802e`).
n4 `13c3157` merged clean as `736f196` (tree `6edb87c0e33d9ea8baadb9d4075eec09ef09d12e`); the 34-gate run was stopped by hand during
`run_k64_net` after gates 1 to 25 had passed (`platform_build` through `k64_gui`). It was stopped because `f97a2de` had merged N3, so
this tree was no longer one the lead could use. Not a failure and not a PASS. At that base n3 (`86cfa8b`) conflicted with n4 in the same
six files, and k4 conflicted with n4 (via the N3 code that k4 carries from `main`).

## Pass 2 — 2026-09-30T07:00:11Z to 07:56Z (ABORTED: base moved)

Base `640a6a4` (tree `4aafc0f8478cbb5674093130a038b13cec8cc085`, identical to `769be99`). n4 `f0f7a74` merged as `6948751`
(tree `4ddb8dab179ce00f7c695589312afcad4a5aa7a1`): gates 1 to 33 passed (through `supervisor`, 610 s); the `media` suite had built the ISO and
the raw disk (both `[PASS]`) and was stopped inside its boot matrix at 07:56Z. Not a PASS. n4 `f0f7a74` is in the lead's base since `4e5456d`.

## Pass 1 — started 2026-09-30T04:58:45Z, finished 06:58Z (superseded: the lead moved to `640a6a4` during the pass)

Base `30c597719071cdd801cc33b84a092d340db46a94` (tree `94c55c94ce0a778a77169d0192315003ab994249`).

| branch | commit merged | result | tree after merge | merge commit |
|---|---|---|---|---|
| (base only) | — | PASSED (all gates) | `94c55c94ce0a778a77169d0192315003ab994249` | — |
| wip/n4-ntdrv-coverage | `f0f7a7429c3a645d99bb167bb2d41886e068a18d` | **PASSED** (all gates) | `ddc04f0a3408a52814ccfec0417fe8b9b53210a6` | `eefd74f` |
| wip/n3-driver-load | — | not on origin | — | — |
| wip/k5-chromium-dlls | — | not on origin | — | — |
| wip/k4-chromium-run | (`f291938` when n4 finished) | not run in this pass; moved to pass 2 on the new base | — | — |
| wip/r1-release | — | not on origin | — | — |

`shz.py test --suite media`: not runnable at `30c5977`. The runner has no such suite (`argument --suite: invalid choice: 'media'`).
Not counted as a failure.

Gate timings, base only: platform_build 2s · platform_test 26s · abi32 4s · vxd 4s · ntwddm 7s · freestanding 1s · ntwddm_win98 2s · pcie 2s · uefi 3s · uefi32 1s · ahci 3s · fat 20s · win98lab 6s · native_runner 5s · app_probe 7s · exception 1s · xhci 4s · usb 15s · pe_parse 131s · win64_build 297s · kbuild 40s · k32 1s · k64_standalone_1 82s · k64_standalone_2 81s · k64_gui 130s · k64_net 221s · k64_disk 98s · k64_sfs 87s · k64_ntdrv 0s · import_coverage 0s · k64_storage 208s · supervisor 0s. Supervisor measured separately, 419s, after the DOS16 prerequisite was built.

Gate timings, after n4: platform_build 2s · platform_test 26s · abi32 5s · vxd 4s · ntwddm 0s · freestanding 1s · ntwddm_win98 2s · pcie 0s · uefi 3s · uefi32 1s · ahci 4s · fat 20s · win98lab 6s · native_runner 5s · app_probe 7s · exception 2s · xhci 3s · usb 15s · pe_parse 128s · win64_build 192s · kbuild 40s · k32 0s · k64_standalone_1 82s · k64_standalone_2 81s · k64_gui 127s · k64_net 218s · k64_disk 88s · k64_sfs 88s · k64_ntdrv 0s · import_coverage 0s · k64_storage 211s · dos16_prereq 7s · supervisor 420s.

Screenshot: `docs/shizukudos10/screenshots/integration-status.png`, from `run_k64_gui.py --accel tcg --png` on tree
`ddc04f0a` (scene PASS).
