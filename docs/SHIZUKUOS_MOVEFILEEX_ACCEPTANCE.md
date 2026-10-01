# MoveFileExW counted-name capacity

The converter uses a 320-WCHAR buffer, but the rename request formerly reserved
300 WCHARs. The additive patch gives both buffers the same capacity and checks
the reported count before copying. It preserves the real converter's accepted
299, 300 and 301-character outputs and closes the source handle on rejection.
No whole-stack overflow or sanitizer crash was observed or claimed.

`patches/kernel32/movefileex-path-bounds.patch` targets the exact committed
`shizukudos/win64/kernel32/k32_file.c` preimage pinned in
`SHIZUKUOS_MOVEFILEEX_VALIDATION.json`. Integrators must verify that preimage
before applying the patch. The original production source remains unchanged in
this source-handoff worktree.

The original capacity assertion genuinely failed at compile time. The corrected
candidate passed six commands, with 8,135 checks in both ordinary execution and
AddressSanitizer/UndefinedBehaviorSanitizer execution. The extracted production
functions also compiled against the installed official Win64 SDK, checking the
API signature and error value. The 207 dependency members comprise 204 headers
and three generated test members. An independent read-only review rechecked the
source, output and raw-log hashes. Earlier harness, oracle, compiler-library and
patch-context failures remain preserved and are not product failure evidence.

To reproduce, supply an unchanged source snapshot and a fresh output parent
under this checkout's `build/` directory. The tool does not download anything or
modify the supplied production source. These examples use explicit paths:

```sh
python3 tools/test_movefileex_path_bounds.py \
  --production-source /path/to/unpatched/shizukudos/win64/kernel32/k32_file.c \
  --output-dir /path/to/this-checkout/build/movefileex-repeat/capacity \
  --phase capacity
python3 tools/test_movefileex_path_bounds.py \
  --production-source /path/to/unpatched/shizukudos/win64/kernel32/k32_file.c \
  --output-dir /path/to/this-checkout/build/movefileex-repeat/green \
  --phase green \
  --red-evidence /path/to/this-checkout/build/movefileex-repeat/capacity/result.json
```

The source tool checks the preimage, preserves previous outputs and applies the
patch only to a private test copy. It requires 20 GiB free plus its 8 MiB output
budget and 6 GiB available RAM. Its own child groups have bounded time and memory
and stop when the resource floor is crossed. Sampling cannot reserve resources
against concurrent writers.

Actual Windows, guest, app and OS acceptance remain false. The native kernel's
separate character-count limit remains; this does not establish end-to-end
long-path support. Write-through, cross-volume behavior, other flag semantics,
filesystem durability and crash recovery require separate implementation and
actual runtime tests. Final app acceptance must include save, reopen after a
normal exit, and cold-boot verification on the real ShizukuDOS/Windows 98 target.
