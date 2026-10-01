# Runtime-only Win98 native acceptance

The frozen QuickJS port and selected musl math helpers have actual host tests,
but no native Windows 98 execution receipt yet. This verifier accepts only a
fresh, stopped trial of the exact runtime-only fixture. Synthetic parser and
staging tests are rejection controls, never evidence of guest execution.

Final runtime checkpoint: `build/trident-script-v10/result.json`, SHA256
`7e036db6906484a046c1253e4668930c4d85645f492ce2bf9a626fd6a1cbf716`.
The unchanged child observer was rebuilt with the same
`trident-script-v10-20261001` nonce: `build/trident-script-observer-v10/result.json`,
SHA256 `94c5004e13571ffd6de7e814dbbf8080fda853ac0dfd203f50b4d4e1ebb71959`.
The read-only helper is pinned at SHA256
`955be0f0d70a91fa22dbeab27074eeef223699414476d80b8b749dca22252a65`;
the parser compiles those exact bounded bytes after verifying their hash.

The fresh canonical native stage is
`/root/Win98-Modern-boot/build/trident-script-native-5abe-20261001-v1/guest-files.json`,
SHA256 `5ee49445c47e45537e7fbc563dea4007b345f6b6469305c5aa76c7c3e65b57eb`.
The earlier worktree `build/trident-script-native-stage-v10` is retained as
host preparation only: the canonical harness requires source receipts below
its own boot build directory, so that earlier stage cannot launch a native trial.
The corrected stager verifies the exact canonical boot parent before mutation,
while retaining the original runtime and observer receipt bytes unchanged.
Exactly three inputs enter `C:\GOPLAB`: `M98QJS.DLL` (944432 bytes),
`QJS13PR.EXE` (33956 bytes), and `M98JSRUN.EXE` (11912 bytes). The observer
launches the probe with a 60-second child deadline and a 5-second termination
reap deadline. Exactly three outputs are collected: `QJS13.LOG`, `JSRUN.LOG`,
and `JSOUT.LOG`. Exactly two independently approved build receipts, 23 merged
project sources, 45 prepared dependency inputs, 46 original source/licence
files, the embedded semantic header, and all successful build-step logs remain
in the canonical stage. These host metadata files are not additional guest inputs.
The stager validates original bytes and current source pins, refuses existing
or symlink destinations, and launches no VM or network activity.

```text
C:\GOPLAB\M98JSRUN.EXE
```

Native acceptance requires all 307 ordered probe checks, including the complete
returned UTF-16 JSON byte checks for 34 selected ES2026 and 24 selected numeric
semantics; Win98 SE 4.10.2222; exact probe/runtime paths and all nine exports;
real current UTC and finite current local-time offset; Promises, explicit
function receiver, UTF-16/NUL/surrogates, interruption, isolation and generation
checks; and x87 internal control word 0x037f with caller control/status restoration
before and after numeric math. The probe establishes a caller PC53/upward/sticky
invalid environment after DLL loading. The runtime saves and restores full x87
state at API and host-callback boundaries. The component log checks restoration;
it does not independently dump every register or certify historical timezone
data. DLL and probe each have 2 MiB stack reserve / 512 KiB commit and a 256 KiB
script stack limit; the observer has a separate 2 MiB / 64 KiB stack.

The observer must independently log successful CreateProcess, wait completion,
successful GetExitCodeProcess with actual child DWORD zero, flush and handle
closure. Its requested supervisor exit zero is not the actual outer process
exit. QEMU exit zero and manual finish cannot replace observed child completion.
`JSOUT.LOG` must be empty. Fresh collection, absent pre-injection outputs, exact
immutable input hashes, approved harness source, preserved private cold clone,
KVM/128 MiB/two CPUs/no NIC, explicit GOP flags and unchanged 20 GiB reserve are
also required. Symlinks, parent symlinks, duplicate JSON/log keys, nonfinite JSON,
partial logs, missing/failed checks, altered source/log bytes, extra outputs,
and different stack/export/instruction profiles fail closed.

Supply result, manifest and harness hashes from independently reviewed frozen
receipts. Do not calculate a new hash for changed bytes merely to approve them.
For a trusted run result, the exact acceptance command is:

```sh
python3 -B tools/verify_trident_script_native.py \
  --run-result /ABSOLUTE/OWNED-RUN/result.json \
  --run-result-sha256 APPROVED_RESULT_SHA256 \
  --manifest /root/Win98-Modern-boot/build/trident-script-native-5abe-20261001-v1/guest-files.json \
  --manifest-sha256 5ee49445c47e45537e7fbc563dea4007b345f6b6469305c5aa76c7c3e65b57eb \
  --harness-sha256 APPROVED_HARNESS_SOURCE_SHA256 \
  --runtime-build-sha256 7e036db6906484a046c1253e4668930c4d85645f492ce2bf9a626fd6a1cbf716 \
  --observer-build-sha256 94c5004e13571ffd6de7e814dbbf8080fda853ac0dfd203f50b4d4e1ebb71959
```

A PASS certifies the approved runtime-only component scope. It leaves actual
MSHTML DOM/browser navigation, full JavaScript/ES2026, modern CSS, current Wasm,
WebGPU, WebGL and modern applications false. Those are mandatory project targets
requiring their own real implementations and evidence. Shared-memory/Atomics are
disabled in this UI-thread profile; Intl, proper tail calls and Atomics.waitAsync
remain upstream gaps. Host tests do not certify the native original MSVCRT math,
clock, timezone or x87 behavior. No global JScript replacement is installed.
