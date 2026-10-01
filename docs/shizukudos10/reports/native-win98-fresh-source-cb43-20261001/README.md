# Frozen Windows 98 Supervisor source candidate

The project goal is ShizukuDOS replacing MS-DOS for Windows 98, with Kernel32 and Kernel64 as Windows 98 components. This handoff preserves a narrower prerequisite: an opt-in installed-Windows98 domain constructor, its native kernel links, and host device tests. A candidate that boots an installed disk through its existing Microsoft IO.SYS is a reference bringup, not completion of the replacement goal.

This directory contains source metadata, sanitized command records and test text. It contains no binary, installed disk, Windows media, product key or machine-private path.

| Record | Executed producer | Actual evidence | Limit |
| --- | --- | --- | --- |
| `native-link-7158.json` | `44f231f0106afab2be97236ceacaa63dce11490f861c82ad3f4e84ece9657f16` | 146 compiler/assembler/link/inspection commands; seven artifacts; 253 patched source files from 272 original committed/export blobs | Native source link only; no VM or installed Windows 98 execution |
| `host-postfix-7158.json` | `203c5c620464ed8c54ae0212e8c8e4fc09815b136c26854b5436b414b823411c` | Three fresh GCC commands and 3,074 host checks: ATA 1,554, string I/O/paging 1,450, PIC 70 | Actual C bodies run against synthetic host inputs; no VMM or Windows execution |
| `review-tests.json`, `tests.log` | Final producer above; tests `8558b119b1340cb4dacd7ddc488ededa6233982974a06c1fbc6b54570abbfc69` | 21 tests, exit 0, no skips; actual read-only `mcopy -V` and `mmd -V` dispatch | Private `--build`, disk leases, VM, GUI/input and target apps have not been exercised |

The final `203c5c62` producer's native `--link` mode was **not re-executed**. The seven earlier native artifact hashes retain their older `44f231f0` producer provenance. The final producer's post-fix host result is separate. Neither record proves Windows 98 boot, MS-DOS replacement, VMM channel mapping, Win64 applications inside Windows 98, GUI/input, Chromium/Firefox/Discord/Steam/Office operation, or a completed public ISO.

The actual native outputs were Kernel32 ELF32/i386 at entry `0x00100000`, Kernel64 ELF64/AMD64 at `0xffffffff80100000`, and Supervisor payload ELF64 at `0x04002000`; the loader was an AMD64 PE32+ EFI application. Exact sizes and hashes are in `native-link-7158.json`. Compiled native Kernel32 still has a QA/IPC session lifetime, and the candidate channel plan connects Win98 to Kernel64. This does not establish a persistent Windows 98 Kernel32 service. The private candidate defaults to carrying Kernel64; `--include-kernel32` is an explicit, unverified additional peer.

The candidate source package already exists at `docs/shizukudos10/reports/checkpoint-20261001/native-win98-candidate/`. Its manifest SHA is `f715aa6b300ab405707a71922beb7aa0ee926dfde155a77cddd69cb1b7554618`. The producer checks its exact manifest, all exported entries, ABI/builders and reviewed patch preimages. It applies the 17 Supervisor patch sections without offsets/fuzzy context and rebases only the reviewed Kernel64 peer dispatch, preserving the standalone observation block. The resulting changed-path allowlist contains 19 files. It does not replace old Supervisor trees wholesale.

## Reproduce the frozen source epoch

Use the exact source commit `7158f51ab413e168088fd2ab13e8a023ebadc3ca` in a clean detached checkout. Run the final producer from the current source repository while pointing its `--source-root` at that frozen checkout. Example absolute paths below are placeholders for your workspace; the output parent must exist and the final output directory must be new.

```sh
git clone https://github.com/NiSeullent/Win98-Modern.git /workspace/Win98-Modern
git -C /workspace/Win98-Modern worktree add --detach /workspace/Win98-Modern-native-7158 7158f51ab413e168088fd2ab13e8a023ebadc3ca
git -C /workspace/Win98-Modern-native-7158 status --porcelain
mkdir -p /workspace/Win98-Modern/build/modern-apps

python3 -B /workspace/Win98-Modern/tools/build_win98_supervisor_candidate.py \
  --source-root /workspace/Win98-Modern-native-7158 \
  --source-commit 7158f51ab413e168088fd2ab13e8a023ebadc3ca \
  --out /workspace/Win98-Modern/build/modern-apps/native-7158-validation
```

Default mode validates immutable Git blobs and creates no output. The producer ignores dirty working files when reading the chosen commit; this is not permission to describe those edits as part of the frozen build. Current main, including the later `6a` integration and DOS compatibility work, may have changed preimages or ABI/builders. Integrating that work requires reviewing and rebasing a new source epoch. Never refresh hardcoded SHAs merely to bypass a refused preimage.

On a modern Linux build host, source-only linking needs Python 3, GCC with 32-bit freestanding support, NASM, GNU binutils and the x86_64 MinGW compiler. No download or global installation is performed by this producer. Supply the actual executable aliases explicitly; real target bytes and alias/target identities are recorded separately. On the tested host `mcopy` and `mmd` both resolve to `mtools`, so preserving the original `argv[0]` is required.

```sh
python3 -B /workspace/Win98-Modern/tools/build_win98_supervisor_candidate.py \
  --source-root /workspace/Win98-Modern-native-7158 \
  --source-commit 7158f51ab413e168088fd2ab13e8a023ebadc3ca \
  --out /workspace/Win98-Modern/build/modern-apps/native-7158-host \
  --host-only --gcc /usr/bin/gcc

python3 -B /workspace/Win98-Modern/tools/build_win98_supervisor_candidate.py \
  --source-root /workspace/Win98-Modern-native-7158 \
  --source-commit 7158f51ab413e168088fd2ab13e8a023ebadc3ca \
  --out /workspace/Win98-Modern/build/modern-apps/native-7158-link \
  --link --gcc /usr/bin/gcc --nasm /usr/bin/nasm \
  --ld /usr/bin/ld --nm /usr/bin/nm --objcopy /usr/bin/objcopy \
  --objdump /usr/bin/objdump --readelf /usr/bin/readelf \
  --mingw /usr/bin/x86_64-w64-mingw32-gcc

python3 -B -m unittest discover -s /workspace/Win98-Modern/tests -p test_win98_supervisor_candidate.py -v
```

The new run writes its own source hashes, exact commands, tool bindings and result. Compare its physical output hashes before asserting it reproduces the earlier native artifacts; this handoff does not claim that comparison has occurred for the final producer.

## Private candidate preparation contract

`--build` is a separate, unexecuted preparation mode. It needs a user's privately installed, cold, exactly 2 GiB Windows 98 disk; an explicit 256 KiB SeaBIOS ROM; and a freshly source-bound Win64 runtime archive no larger than the reviewed loader's **64 MiB** limit. Each input path and SHA is explicit. It does not accept a Windows installation ISO as the installed disk and it does not start a VM.

The runtime builder receipt must record its exact `source_commit` or clean `git.revision`, `archive.sha256`, ordered `archive.files`, and `consumed_sources_sha256`. The source manifest must bind that same commit, archive SHA and exact verified builder-receipt SHA:

```json
{
  "schema": 1,
  "source_commit": "<same exact 40-hex source commit>",
  "archive_sha256": "<actual WIN64.IMG SHA256>",
  "builder_receipt_sha256": "<actual runtime builder receipt SHA256>",
  "consumed_sources_sha256": {
    "<every consumed project input path>": "<same-commit Git blob SHA256>"
  }
}
```

The receipt and manifest consumed-source maps must be equal and match immutable Git blobs. Include Win64 source/resources, ABI/kcommon, Kernel64 export/DDK headers and `ntdrv_prov.c`, `tools/shzlib.py`, and upstream manifests/patches, plus every other consumed project input. A producer-time receipt wrapper may use `source_binding` with `schema`, `source_commit` and the consumed pins; it must preserve the original receipt's Git metadata. Capture the inputs during a fresh actual build. An old receipt without consumed-source pins must be rebuilt; a later current-source sidecar cannot relabel old runtime bytes. Both JSON documents are parsed from the same nofollow descriptor bytes that were bounded and SHA-verified. The archive's actual entries, paths, extents and provider inventory must match the receipt.

The additional explicit private flags are:

```text
--build
--win98-disk /private/your-cold-installed-win98.raw --win98-disk-sha256 <64-hex>
--seabios /private/your-verified-256k-seabios.bin --seabios-sha256 <64-hex>
--runtime /private/your-fresh-WIN64.IMG --runtime-sha256 <64-hex>
--runtime-receipt /private/your-actual-runtime-builder.json --runtime-receipt-sha256 <64-hex>
--runtime-source-manifest /private/your-bound-source-manifest.json --runtime-source-manifest-sha256 <64-hex>
--mkfs-vfat /usr/sbin/mkfs.vfat --mcopy /usr/bin/mcopy --mmd /usr/bin/mmd --fsck-vfat /usr/sbin/fsck.vfat
```

Supply the compiler flags from the `--link` example too. These are a parameter contract, not an executed private-build recipe or proof of acceptance. Keep all installed-disk, ESP, readback and failed output private. Private output is restricted before writes to directories `0700` and files `0600`; the original disk is read-leased and hashed, copies/readbacks are verified, and failures are preserved. The producer requires a 17 GiB floor plus a 7 GiB initial preparation budget and rechecks available space before large writes and while copying. That check is not a reservation against other writers. Private `--build`, real lease-break behavior, actual BIOS/UEFI Windows 98 boot, live VMM channel requests and replacement-DOS bootstrap still need separate owned acceptance evidence.

## Evidence integrity

`native-link-7158.json` normalizes only machine workspace prefixes in actual command arrays to `${STAGE}`; system executable paths and all command arguments otherwise remain intact. It retains original source/export and patched-source hash maps, the source commit, exact seven artifact hashes, host checks and raw private-record digest. `host-postfix-7158.json` records the final producer's independent post-fix host run. `review-tests.json` binds final source/test hashes, the actual full `tests.log`, and the read-only recheck of the earlier seven native artifacts. No record claims the final producer performed the earlier link.
