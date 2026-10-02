# Existing-file FAT32 replacement

The original `fat32_rename` removed an existing destination before creating its
replacement. A later write failure could lose the previously saved file. The
genuine original-code regression reproduces that loss after a fresh mount.

`patches/kernel64/fat32-safe-replace.patch` is an additive source handoff against
the exact production `fat32.c` and `fat32.h` preimages pinned in
`SHIZUKUOS_FAT_REPLACEMENT_VALIDATION.json`. It is not applied to the production
files in this worktree. The primary integration owner must apply it, rebuild
the actual runtime and run the native tests.

For replacement of an existing regular file by another regular file, the patch
keeps the destination spelling, SFN alias, case flags and LFN slots. It validates
both data chains and prepares directory beforeimages before writing. It removes
the source name before publishing the target metadata, then reclaims the old
target chain and synchronizes FAT copies and FSInfo. This path needs no new name
slots or data clusters, including on a full volume.

Recoverable read/write/allocation failures restore the prior data and namespace.
The test exercises the real FAT implementation over a byte-memory sector
transport, then calls the actual temporary-file deletion routine and freshly
mounts the bytes before checking the old file. Persistent or partial rollback
failure returns an error and disables writes on that mounted volume. Inspection
and recovery are required before enabling writes again. Tests explicitly report
remaining orphan, FAT-mirror and FSInfo differences in those cases; they do not
certify a clean or durable filesystem. Detected corrupt/shared input chains also
disable writes so caller cleanup cannot free a saved file's shared chain.

The final frozen run reports 165 cases and 157,994 assertions in both ordinary
and full AddressSanitizer/UndefinedBehaviorSanitizer execution, with leak checks.
It covers same/different directories, fragmented data, a 255-unit LFN, full
volumes, all measured read/write/allocation failure positions, partial writes,
empty files, literal case flags, prohibited replacements and shared chains.
The original batch passed 28,226 assertions. Freestanding Kernel64 flags compile
the patched FAT source with no unresolved runtime helpers. The external-image
walker was compiled; the mkfs/mtools/fsck image suite was not executed in this
bounded run. Twelve commands have their expected results, including the genuine
original regression's expected failure; 24 raw logs are preserved.

The earlier accepted generation and two later failed generations remain intact.
One failed because a controller tried to hash a compiler's growing output; the
other exposed a test-fixture cache/setup ordering mistake. The final controller
measures active output sizes and hashes frozen files after writers exit. The
case fixture completes filesystem writes before directly preparing its literal
case byte, then remounts and checks that byte. No production assertion was
weakened. The original-code RED skips only the new failed-output sentinel check
so it reaches the unchanged actual missing-old-file oracle; GREEN checks both.

For a fresh reproduction from an exact unpatched snapshot:

```sh
python3 tools/test_fat32_replace_failure.py \
  --source-root /path/to/unpatched-checkout \
  --phase red --output-dir build/fat32-repeat
python3 tools/test_fat32_replace_failure.py \
  --source-root /path/to/unpatched-checkout \
  --phase green --output-dir build/fat32-repeat \
  --red-sha256 'REPLACE_WITH_ACTUAL_RED_RECEIPT_SHA256'
```

Replace the receipt placeholder with the SHA256 of the actual `red-result.json`
from the first command. For a current checkout containing this exact applied patch:

```sh
python3 tools/test_fat32_replace_failure.py \
  --current-root /path/to/integrated-checkout \
  --phase current --output-dir build/fat32-current-repeat
```

Current mode reverses the patch only in a private snapshot to verify the exact
approved preimage, then tests the supplied current production bytes. The tool
requires canonical explicit source paths and fresh owned outputs; it does not
edit caller sources, start a guest, download packages or change services. Its
combined output budget is 16 MiB, with a 20 GiB disk floor, 6 GiB available RAM,
512 MiB sampled child-group memory cap, 60 seconds per command and 90 seconds
of cumulative command time. Concurrent writers can change resources between
samples. Old generations can be explicitly bound by their receipt hashes.

Kernel execution, actual Office save/reopen, cold-boot theme persistence,
ShizukuDOS replacement, crash atomicity and guaranteed persistent-I/O rollback
remain unverified. The general rename-to-an-absent-target path, global namespace
crosslink recovery, storage barriers and journaling are outside this patch.
Final application acceptance must use the rebuilt ShizukuDOS/Windows 98 target
and verify actual saved files after normal exit, reopen and cold boot.
