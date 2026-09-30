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
