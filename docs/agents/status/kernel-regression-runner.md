# Standalone Kernel64 regression runner

Owner: kernel regression runner integration, branch `codex/pma-integration-20261002`, worktree `/root/Win98-Modern-pma-20261002`.

Owned source: only `shizukudos/tests/run_k64_standalone.py` and this report. No kernel, Win64 runtime, product or timing tests, kbuild closure, historical result, index or commit was changed. Generated verification artifacts are confined to `build/pma-kernel-runner/`.

## Change and scope

The runner accepts `--display none|bochs|virtio`. `none` remains the default and adds no graphics device under `-nodefaults`; `bochs` adds exactly `-device VGA`; `virtio` adds exactly `-device virtio-vga` without virgl. All choices retain `-display none` for the host display and execute the unchanged guest checks. The default timeout remains 240 seconds. Display choice, effective QEMU command and explicit timeout are recorded.

`inputs-before.json` is written before QEMU starts, binding the exact stub, kernel and WIN64 image paths and SHA-256 hashes. The final result contains before/after hashes and three mandatory immutability checks; a changed or missing input produces FAIL. Receipt scope explicitly identifies standalone Kernel64/WIN64 component regression and excludes actual Windows 98 boot, Supervisor/VMX/EPT integration, SMP and pixel-output proof.

These are preserved baseline binaries, not a build of the current dirty PMA source tree. Actual Windows 98 remains the product target; this runner improvement does not satisfy its integration acceptance gates.

## Fresh verification commands

Commands run from `/root/Win98-Modern-pma-20261002`; Python verification runs set `PYTHONDONTWRITEBYTECODE=1`.

- Before editing: `python3 shizukudos/tests/run_k64_standalone.py --display bochs --timeout 0` exited 2 with `unrecognized arguments: --display bochs`. Log: `build/pma-kernel-runner/before-cli.log`.
- `python3 shizukudos/tests/run_k64_standalone.py --help` exited 0 and documents all device mappings and default none. Log: `build/pma-kernel-runner/help.log`.
- `python3 build/pma-kernel-runner/check_integrity_guard.py` exited 0: its disposable subprocess fixture replays original guest evidence and mutates its own stub; the runner returns 1/FAIL, all original guest-result checks PASS, and the stub's immutability check FAIL. This is a hash-guard behavior check, not guest execution proof. Logs/receipts: `build/pma-kernel-runner/integrity-guard.log` and `integrity-fixture/run/{inputs-before,result}.json`.
- `python3 -m unittest discover -s shizukudos/tests -p 'test_observation_diagnostic.py' -v` passed six existing tests. Log: `build/pma-kernel-runner/observation-diagnostic.log`.
- `/usr/libexec/qemu-kvm --version`, `-device VGA,help` and `-device virtio-vga,help` exited 0; installed QEMU is 10.1.0. Logs: `build/pma-kernel-runner/qemu-{version,vga-help,virtio-help}.log`.
- `git diff --check -- shizukudos/tests/run_k64_standalone.py` passed.
- `python3 build/pma-kernel-runner/run_preserved_baseline.py --qemu /usr/libexec/qemu-kvm --accel kvm --display bochs --timeout 600 --memory 256 --out build/pma-kernel-runner/bochs` runs the full real guest. The small harness only redirects `K64S` to `build/pma-baseline/kernel64s` while retaining the same imported `build/shizukudos/win64/WIN64.IMG`; it does not rebuild or copy an input. The 600-second bound is explicit for this invocation and does not change the 240-second default.

## Artifact bindings

| Actual input | SHA-256 before execution |
|---|---|
| `build/pma-baseline/kernel64s/boot.elf` | `b9746b523b7b6f125acf256fb8ad7ef3d98f83dd5bf0a03f15d19ab654a3ff97` |
| `build/pma-baseline/kernel64s/KERNEL64S.BIN` | `c36296203db1c4e50d23cbcb44e3ee331f982fd3e0e741dbee7074f67dde80b2` |
| `build/shizukudos/win64/WIN64.IMG` | `a098a49fdf686973d5246f74e7f61d8257afced11ab28a11a7f4bd47c0dc7a7e` |

Runner source SHA-256: `5aa026474df47605ca027c094ebd94b6b7a88e8379a8dbbb14d3f6bb0aed73ab`.

## Result and limitations

Fresh full KVM execution passed in **198.9 seconds**, runner exit 0, **21/21 checks** (18 original guest-result checks plus three input immutability checks). The guest reached `SHZ-EXIT:0` with zero self-test failures. QEMU's debug-exit return is 1 as expected for guest exit 0. Every input's after-run SHA-256 matches its before-run hash above; an independent post-run hash read also matches.

The actual configured device is `VGA`; serial line 286 confirms `K64 gfx: display backend Bochs VBE, 1024x768x32, back buffer 3072 KiB`, and line 1876 binds PCI `1234:1111` to `gfx_fb (Bochs VBE)`. The command receipt includes `-device VGA` directly.

Live receipts: `build/pma-kernel-runner/bochs/{inputs-before,result}.json`; raw guest evidence: `bochs/serial.log`; console output: `build/pma-kernel-runner/bochs-console.log`. `build/pma-kernel-runner/verification-summary.json` records independent artifact hashes and verification assertions. Its first helper invocation failed because raw guest serial contains non-UTF-8 bytes; rerunning with the runner's existing `errors="replace"` read policy passed. The raw serial bytes were preserved without rewriting.

| Verification artifact | SHA-256 |
|---|---|
| `bochs/result.json` | `b8a08391d585ad89c245487f51bcb7d3d7011d38614516fcc8ed2fc355e16c91` |
| `bochs/inputs-before.json` | `532ff04abf4990459620845f502d4786df6268535635b8cc70911f4544b3d65d` |
| `bochs/serial.log` | `97e45ab5f2afec903da5934672ebb64c50b217bf598ac45a782d5a44fcefc27a` |

Historical no-device receipts remain unchanged: `build/pma-baseline/k64/result.json` reports FAIL/240.3 seconds with timeout and incomplete end markers; `k64-long/result.json` reports FAIL/191.6 seconds with eight Win64 app failures. The parent-controlled same-binary VGA execution is PASS/239.7 seconds at `k64-display/result.json`; that historical command array omitted the externally injected device. The new runner records its configured device directly in both the command and receipt.

Virtio device support is documented and QEMU accepts its device help, but a full virtio guest run has not been performed. Standalone guest input tests may report their existing SKIP markers when no host keyboard/mouse stimuli arrive; this runner adds no skip or suppression. It does not take screenshots or verify displayed pixels, run actual Windows 98 or prove SMP behavior. No broader product-suite result is claimed.
