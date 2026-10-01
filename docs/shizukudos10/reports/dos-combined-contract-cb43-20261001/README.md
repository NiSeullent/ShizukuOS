# Combined DOS compatibility source checkpoint, 2026-10-01

The complete kernel source compiled with both the CB43 DOS-internals patch and the primary DOSMGR contract patch, with `WIN31SUPPORT` explicitly enabled for **both C and NASM**. Fresh checks passed: **49 host assertions**, **327,673 exhaustive DOSMGR register frames**, **14 linked instance-layout checks**, and **9 linked DOSMGR table checks**. The real DOS compiler also accepted a compile-time assertion that the actual packed production CDS is 88 bytes.

A dedicated DOS-only diagnostic disk was constructed and all six payloads were read back; its FAT check exited 0. **This combined disk has not been executed in a guest at this checkpoint.** The earlier [17 native DOS checks](../dos-internals-cb43-20261001/README.md) used a kernel **without** the separate DOSMGR patch. They are not transferred to this combined binary. Windows 98 startup, Setup, replacement of MS-DOS under Windows 98, and native modern apps remain unverified. The target remains the final ShizukuOS 1.0 ISO; these are prerequisite source and build records.

Public files here are source, hashes and text receipts. The kernel, compiler, FreeCOM, diagnostic disk, VM data, Windows media and Windows keys are excluded. No main/shared source, existing frozen receipt, root-owned image or VM was modified.

| Check | Actual scope | Record |
|---|---|---|
| Complete combined kernel build | Fresh pristine kernel plus country/share; 4 patches; uncompressed 386/FAT32; exit 0 | [Source/build receipt](source-build-receipt.json), [build log](kernel-build.log) |
| Production C host checks | Existing 38 SFT/JFT/presence/startup assertions plus 11 combined assertions; actual Windows switch with its AH/BX guards and common carry clearing | [Fixture source](verify_combined_contract.py), [result](combined-contract-result.json), [output](host-results.txt) |
| Exhaustive DOSMGR frames | 65,536 CX=1 masks, 65,536 CX=3 selectors, 65,536 CX=4 masks, 65,535 other BX devices, 65,530 unknown CX functions | [Combined result](combined-contract-result.json) |
| Actual DOS CDS layout | Watcom compiles production `portab.h`/`cds.h` with small model and byte packing; `sizeof(struct cds)==88` assertion | [Combined result](combined-contract-result.json) |
| Actual linked kernel layout | MZ relocation and flattened-kernel instance-pointer checks; fixed SFT DS:00CC and full DOS instance extent | [14-check result](linked-layout.json) |
| Actual linked DOSMGR table | Driver/table data segment, actual symbol offsets, empty critical patch list, fixed SFT separation, flattened offset words | [9-check result](combined-contract-result.json) |
| Dedicated diagnostic construction | Real source-built kernel/template, frozen source-built FreeCOM, newly compiled CBDOSINT and SHZEXIT; six file readbacks; FAT exit 0 | [Image manifest](diagnostic-image-manifest.json), [static check](diagnostic-image-static.json) |
| Combined native DOS / Windows run | **NOT RUN / NOT VERIFIED** | VM execution belongs to the separate root-owned review/run stage |

The host adapter does not model segmented memory or a VMM. Production DOSMGR CX=5 device-size handling and the other Windows cases are compiled but are not exercised by this fixture. Native compile/link and table checks do not establish that Windows accepts or patches FreeDOS's layout.

## Contracts and frozen inputs

The pristine FreeDOS kernel is `5ffb5502d39a10a30f5b8a9e8beeba0bf30245d3`; country is `7f83e041d00f78b3912c761246930f3b437440f6` and share is `47f3d42527256fa46a00fe84cdb46d90f2e66f50`. All **287** pristine file preimages, all **288** patched/configured file hashes, archive hashes and patch order were recorded before compilation. The [toolchain receipt](toolchain-receipt.json) records actual executable hashes and distinguishes helper-tool hashes recorded after the build. The primary DOSMGR patch SHA-256 is `9ea1d25225664d41d0ba5be40e34455804932272b2f2f6808767e1bf14fc078d`; the CB43 patch is `a68f2a6bec6b378f69727bd32b386c097ed926323a98c5e34fb109ccdda10ce0`. Patch application uses zero fuzz; documented line offsets are retained in the receipt.

DOSMGR `AX=1607/BX=0015` CX=1 acknowledges the API but reports **BX=0 applied patches**. CX=3 supports only **DX=1** for CDS size; unsupported selectors return CX=0 while retaining other registers. CX=4 returns CX=DX=0 without a success signature. CX=0 reports actual `winInstanced`, independent of the presence-hiding flag. The host checks cover 1605 → 1607 → 1231 hide → 1606 → 1607 without calling that synthetic sequence a native Windows startup.

The actual linked patch-table words are `0006, 05EC, 05EA, 0321, 033E, 0315, 008C`, at DOS link segment `007A`, offset `00BC`; the driver symbol is offset `0048`. These describe the compiled FreeDOS implementation. They are not a claim of Microsoft kernel layout compatibility. Reporting zero implemented patch bits can cause Windows DOSMGR to try its own patching; that behavior remains a separate native compatibility gate.

The CB43 contracts retain correct major-byte-first startup record versions, offset-low/segment-high far pointers, actual startup chaining/veto behavior, genuine SFT/JFT traversal, and presence hiding without inventing Windows. **AX=1230 remains unsupported; AX=1231/DL=0 one-shot loading remains unsupported.** The primary authorities and original upstream preimages are preserved in the [earlier prerequisite checkpoint](../dos-internals-cb43-20261001/README.md), including [Ralf Brown's original corpus](https://www.cs.cmu.edu/~ralf/files.html) (`INTERRUP.K` and `INTERRUP.L`), Microsoft's [DDK Appendix D.2.1 preserved by PCjs](https://www.pcjs.org/documents/books/mspl13/win/w3ddkvxd/), and the [FreeDOS authors' Windows-hook review](https://sourceforge.net/p/freedos/mailman/freedos-devel/thread/a527e93966582aa438a51aad7d10f6a5@metalpunks.info/).

## Reproduce in a fresh source checkout

Use actual Git, Python 3, GNU make, patch, GCC, NASM, Open Watcom v2, mtools and dosfstools. The tool receipt identifies the executables actually used. The cached extracted Watcom tree has no archive-hash stamp, so its correspondence to a separately cached archive is **not assumed**; record your actual tools. Keep at least **17 GiB free disk** and **4 GiB host memory available** beyond the small single-job build/image budget. No download, installation, global configuration change or VM execution is performed by the verification fixture.

Set `WATCOM` to your installation, prepend its `binl64` to `PATH`, and set **`INCLUDE=$WATCOM/h`**. `WATCOM`/`PATH` alone were insufficient for the standard-library diagnostic on the used installation. [Diagnostic provenance](diagnostic-build-provenance.json) preserves the failed first compile with missing standard headers and the successful new output epoch after setting INCLUDE; the producer itself was unchanged.

From the repository root, obtain separate pristine sources:

```sh
git clone https://github.com/FDOS/kernel build/combined-dos/upstream-kernel
git -C build/combined-dos/upstream-kernel checkout 5ffb5502d39a10a30f5b8a9e8beeba0bf30245d3
git -C build/combined-dos/upstream-kernel submodule update --init --recursive
git -C build/combined-dos/upstream-kernel/country rev-parse HEAD
git -C build/combined-dos/upstream-kernel/share rev-parse HEAD
cp -a build/combined-dos/upstream-kernel build/combined-dos/kernel-win31
```

Confirm the two submodule hashes above. A top-level `git archive` alone omits country/share and cannot reproduce the build. In your separate `kernel-win31` copy, apply the repository patches in this order, using `patch --batch --fuzz=0 --no-backup-if-mismatch -p1 -i /absolute/path/to/patch`: `0001-shizukudos-branding.patch`, `0002-reproducible-build-date.patch`, `0003-cb43-win98-dos-internals.patch`, `0003-dosmgr-honest-contract.patch`. Do not apply them to the pristine source. Place this `config.mak` in the copied kernel root:

```make
XNASM=nasm
undefine XUPX
ALLCFLAGS=-DWIN31SUPPORT
NASMFLAGS=-DWIN31SUPPORT
```

Run `SOURCE_DATE_EPOCH=1785283200 make all XCPU=386 XFAT=32` in that copied tree. From the repository root:

```sh
python3 -B shizukudos/dos16/tests/verify_cb43_dos_layout.py \
  --kernel-tree build/combined-dos/kernel-win31 --output build/combined-dos/layout.json
python3 -B docs/shizukudos10/reports/dos-combined-contract-cb43-20261001/verify_combined_contract.py \
  --kernel-tree build/combined-dos/kernel-win31 --output build/combined-dos/host
```

The combined fixture checks exact production source hashes and fails when a future source revision differs. Freeze and review a new source epoch instead of bypassing those checks. Its fresh output directory contains generated C, the host binary, actual compile logs and a JSON receipt; only source/metadata should be committed.

For the private diagnostic, independently obtain FreeCOM at `04fc21a9f6792abe9048598e8f2d048b4f6cd0e5`, apply `freecom-0001-reproducible-build-stamp.patch` in a separate copy and run `bash build.sh` with the same Watcom environment. The reused frozen source-built FreeCOM input is identified by [its complete source preimages](../dos-internals-cb43-20261001/freecom-source-preimages.json) and SHA-256 `27c91c0c27d7aac140fd3dbeb4c20592ae6fae0555d4e310cf749e2102bd3e50`.

```sh
python3 -B shizukudos/dos16/tests/build_cb43_dos_diagnostic.py \
  --kernel-tree build/combined-dos/kernel-win31 \
  --freecom build/combined-dos/freecom/command.com --output build/combined-dos/diagnostic
```

The diagnostic builder creates a dedicated FAT16 image and manifest and reads every payload back. It never launches a VM. The checkpoint image is 33,546,240 bytes, SHA-256 `50d44ccf164e26fbcc06c4e3869031f6ca8353116e71f9218a5528596a39ab0a`; kernel SHA-256 is `c1c86626585c8332a8788a01ded40c8795fd449d1832c9428436038530bbe906`. It includes only DOS=LOW/FILES/BUFFERS/FreeCOM configuration, CBDOSINT and SHZEXIT, with no HIMEM, BILING or Microsoft/Windows inputs. A separately reviewed root-owned run may use a dedicated copy, 128 MiB, one TCG CPU actually advertised by the installed QEMU, no NIC and bounded execution; **no such run is included here**.

Only actual workspace/toolchain prefixes were replaced by `${STAGE}`, `${REPO}`, `${FROZEN_FREECOM_SOURCE}` and `${WATCOM}` in public text metadata. Commands and results were not invented or rerun for sanitization. Raw private record/log SHA-256 values preserve provenance; the build receipt and toolchain receipt separately identify the sanitized public log's hash. The [checkpoint manifest](checkpoint-manifest.json) hashes the complete new public allowlist; existing receipts remain unchanged.
