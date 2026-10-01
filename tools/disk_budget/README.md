# Wine source cache sharing

`wine_source_share.py` has a fixed scope: the three Win98 Modern Wine source
caches. It proposes only tracked, unmodified original source files from the apps
cache to the boot cache. Locally generated headers, configuration, binaries, Git objects,
VM disks, patched files, and file tails smaller than a complete 4096-byte page
are excluded. Reports are new files under `build/disk-c009`; existing reports
cannot be overwritten.

The planning phase reads source bytes and nonsynchronizing FIEMAP maps. It
records exact file identities, Git blob hashes, full SHA-256 hashes, cache HEADs,
and exclusive page ranges. Already shared pages are excluded. The applying
phase requires the reviewed tool hash and HEADs, reopens those exact paths
without following symlinks or updating access times, obtains advisory locks,
and rejects active or recently modified files. `/proc` checks are snapshots;
they cannot prevent an uncooperative future writer. The kernel independently
compares every submitted range and shares it only when its bytes are equal.

Every modified allocation is followed by full hash and identity checks. File
names, inodes, logical bytes, mode, ownership, link count, access time, and
modification time must remain unchanged. Allocation accounting and change time
are recorded before/after; the filesystem can update change time when it changes
extent ownership. No metadata is forcibly restored. A failure stops the pass
and records the verified work already completed in the append-only JSONL
receipt. There is no deletion, replacement, hardlink, compression, VM action,
network access, or global setting change.

Use a new plan path, review its exact `files` list, then use a new receipt path:

```text
python3 tools/disk_budget/wine_source_share.py --plan build/disk-c009/wine-source-plan.json
python3 tools/disk_budget/wine_source_share.py --apply build/disk-c009/wine-source-plan.json --result build/disk-c009/wine-source-apply.jsonl
```

`exclusive_page_bytes_released` comes from the destination extent maps. The
separately recorded filesystem free-space change includes concurrent host
writes and must not be reported as this pass's exact savings. `st_blocks`
counts shared allocations in every referencing file, so summing `du` totals
does not measure unique physical consumption.

The compare-and-share semantics and required range alignment are documented in
the Linux [FIDEDUPERANGE manual](https://man7.org/linux/man-pages/man2/ioctl_fideduperange.2.html).
The tool neither invokes other repository scripts nor touches reverse-skill.

`host_abi_test.c` checks the installed Linux headers with six C11 static
assertions: the 24-byte header, 32-byte destination record, offsets of the result
fields, and the host ioctl number. Its executable only prints those sizes; it
does not call an ioctl. The existing private `dedupe-abi-test` build passed these
checks. The Python path/range guard checks also passed all 27 cases before the
reviewed apply pass.
