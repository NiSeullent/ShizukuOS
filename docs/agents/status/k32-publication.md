# Kernel32 startup publication regression

Updated: 2026-10-01 19:10 UTC. Worktree: `/root/Win98-Modern-pma-20261002`,
branch `codex/pma-integration-20261002`, base revision
`f8dafa6be91df0bd123c3903c1d7676be6c6a299`.

## Result and scope

The bounded startup race is fixed in `shizukudos/kernel32/user.c`. The existing
`thread_create` makes a thread READY before returning and restores its caller's
interrupt flags. Previously, the timer could select that thread before
`proc_create` stored either the process's thread pointer or the thread's owning
process ID. A ring-3 syscall then saw no owning process; a subsequent ring-3
fault escaped process containment and terminated the component kernel.

`proc_create` now preserves its incoming IRQ flags and masks the UP timer across
the existing thread creation and publication of both ownership links and PID
output. A thread allocation failure detaches the prepared address space from
the unused process slot while masked, restores the original IRQ flags, and
frees that address space. IRQ state is preserved for enabled and disabled
callers. No scheduler/header changes, shared-index operations or commits were
performed by this task.

Actual Windows 98 remains the product OS, with VMM/USER/GDI authoritative;
Kernel32 is an auxiliary backend domain. This evidence covers the standalone
UP component and its production C publication path. It establishes neither
actual Windows 98 integration nor integrated SMP.

## Changes

- `shizukudos/kernel32/user.c`: atomic UP startup publication and allocation-failure rollback.
- `shizukudos/tests/test_k32_publication.c`: includes actual production `sched.c`,
  `user.c` and the real `k32.h` thread layout. Injects a timer opportunity whenever
  IRQ flags become enabled, uses the real runnable selector, and exercises real
  `SYS_GETPID` and `user_fault` ownership/containment paths. Privileged IRQ/MMU
  operations, allocation and fault-exit stack transfer are host substitutes;
  the host does not execute a real CPU context switch or enter ring 3.
- `shizukudos/tests/run_k32_publication_host.py`: bounded GCC/Clang host runner,
  source stability checks, logs and source/executable hashes.
- `shizukudos/tests/run_k32_publication_guest.py`: builds only Kernel32 standalone
  plus the existing Multiboot stub in an isolated directory by overriding
  `kbuild.BUILD`. Uses the complete existing Kernel32 standalone self-test runner
  and evaluator, with guest input hashes and stability checks.
- This status file.

## Red evidence

Historical `build/pma-baseline` receipts and binaries were read without changes.
The original baseline KVM run failed at `user_wild` with fatal ring-3 #PF,
guest exit 98. The preserved TCG baseline passed. Re-running the exact preserved
binary reproduced the same publication failure category at `user_fault` with
fatal ring-3 #GP and guest exit 98, QEMU exit 197:

```sh
python3 -B -c 'from pathlib import Path; import sys; sys.path.insert(0, "shizukudos/tests"); import run_k32_standalone as runner; runner.K32S = Path("build/pma-baseline/kernel32s").resolve(); sys.argv = ["run_k32_standalone.py", "--qemu", "/usr/libexec/qemu-kvm", "--accel", "kvm", "--timeout", "120", "--out", "build/pma-k32-publication/baseline-kvm"]; raise SystemExit(runner.main())'
```

Evidence: `build/pma-k32-publication/baseline-kvm/{serial.log,result.json}`.
The deterministic regression was then run before modifying production C:

```sh
python3 -B shizukudos/tests/run_k32_publication_host.py --out build/pma-k32-publication/host-red
```

Compilation succeeded; the test exited 1 with four expected failures: first
runnable syscall lacked PID, both ownership backlinks were unpublished, first
runnable user fault was uncontained, and failed thread creation leaked the
prepared address space. Evidence:
`build/pma-k32-publication/host-red/{compile.log,run.log,result.json}`.

## Green evidence

All commands below were executed from the worktree root with the final runner
sources. Existing earlier green outputs remain preserved in separate folders.

```sh
python3 -B shizukudos/tests/run_k32_publication_host.py --out build/pma-k32-publication/final-host-gcc
python3 -B shizukudos/tests/run_k32_publication_host.py --cc clang --sanitize --out build/pma-k32-publication/final-host-clang-sanitized
python3 -B shizukudos/tests/run_k32_publication_guest.py --build --accel kvm --out build/pma-k32-publication/final-kvm-1
python3 -B shizukudos/tests/run_k32_publication_guest.py --accel kvm --out build/pma-k32-publication/final-kvm-2
python3 -B shizukudos/tests/run_k32_publication_guest.py --accel tcg --out build/pma-k32-publication/final-tcg
git diff --check
```

- GCC host: all 17 checks PASS, compilation/test exits 0, inputs stable.
- Clang ASan+UBSan host: all 17 checks PASS, compilation/test exits 0,
  no sanitizer errors, inputs stable.
- Fresh isolated freestanding build: PASS, no unresolved symbols; source
  snapshots before/after build match.
- KVM run 1/run 2 and TCG run: all nine complete standalone evaluator checks
  PASS, guest exit 0, completion marker `0x4b333221`. Ring-3 exits 42; #GP and
  #PF return contained statuses `0x8000000d` / `0x8000000e`; zero physical-page
  leakage; timer, mutex, semaphore, sleep, heap and demand-paging checks pass.
  Guest artifacts remained unchanged during each run.
- Whitespace validation: exit 0.

Each output folder contains its own `result.json` and logs. Build commands and
source hashes are recorded in
`build/pma-k32-publication/kernel32s-build-result.json`.

## SHA-256 provenance

| Input/artifact | SHA-256 |
| --- | --- |
| Baseline `user.c` from baseline build receipt and HEAD | `03690b723ac6bce68ab075ab93687c369a5a0e26f857607f5b3d61dd56eaa1aa` |
| Fixed `shizukudos/kernel32/user.c` | `1698d514d8632961f61d5ec40d09ee1ab221d81530c1a3c29bb190b4f35cf3fe` |
| Untouched `shizukudos/kernel32/sched.c` at this build | `4819e88176c90dff11666e7aa59a904fb47178f0748ae78e9414b5f9d45749dc` |
| Untouched `shizukudos/kernel32/k32.h` at this build | `97b924cc350c50c72321ea8dcb1b9f7b51a9f9e90daee8f84be189b183eba51c` |
| Preserved baseline `KERNEL32S.BIN` | `f10e0ad5aa09e62dd1ded0e4cfeb42e22254feac2845a5a057125374b8714a7e` |
| Fixed isolated `KERNEL32S.BIN` | `381b831a49835fca9efc596c6b50192730fd8ed01b15abdaca7a9406f8e5e274` |
| Fixed isolated `kernel32s.elf` | `90a12c20c764ee0d89b991fcc2523dda5b83f8840a332a1375e96259f261bc6a` |
| Shared baseline/fixed `boot.elf` | `a45e18fb70d2b27e75bade14db1c84773b2c525fa1420fff5fb3877bd793e925` |

Remaining gates: root's final combined build and integration regressions after
peer Kernel32 deadline changes; real DOS-to-VMM/service-domain connections;
actual Windows 98 cold boot and native application requests; integrated SMP.
General concurrent process-slot reservation and other allocator error paths
are outside this bounded startup-publication fix.
