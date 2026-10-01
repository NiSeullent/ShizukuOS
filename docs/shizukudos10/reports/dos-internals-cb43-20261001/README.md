# DOS compatibility prerequisites: source checkpoint, 2026-10-01

The isolated source-built DOS kernel passed **17 real DOS guest checks**, **38 host checks of extracted production C bodies**, and **14 checks of actual linked/relocated kernel bytes**. Both complete kernel source profiles compile: the ordinary profile and the explicitly enabled experimental `WIN31SUPPORT` profile. This evidence does **not** verify Windows 98 startup, Setup, replacement of MS-DOS underneath Windows 98, or native modern applications. Those remain separate gates for the final ShizukuOS 1.0 ISO.

The patch is [0003-cb43-win98-dos-internals.patch](../../../../shizukudos/dos16/patches/0003-cb43-win98-dos-internals.patch). It preserves DOS-C/FreeDOS authorship and GPL-2.0-or-later licensing. Public evidence here contains source, hashes and text receipts; the diagnostic disk, kernel, FreeCOM, compiler binaries and Microsoft media are not included.

## Actual implementation and remaining contracts

`1231/DL=1,2` controls reporting of actual Windows state, using DL alone. Other registers do not select the operation. Enabling reporting never creates a Windows instance or an OS version. Unsupported selectors return carry and AX=1; `DL=0` remains explicitly unsupported because a verified one-shot-loader consumer is absent.

`1605` respects an existing CX veto and preserves the prior ES:BX startup-record chain. The startup record advertises supported format 3.0 or 4.0, with the major byte first; the caller's actual Windows version is stored separately for `1600`. The optional-instance pointer at record+0x12 is an actual zero DWORD. Instance-data pointers store offset first, segment second, including the GNU segment-relocation field. `1606` clears actual state and reporting state. These startup paths have host and linked-byte checks; the native DOS diagnostic deliberately does not synthesize Windows startup.

`1216` already performs genuine SFN-to-SFT traversal. `1220` returns a JFT-byte pointer and reports an out-of-range handle with **AL=6**, not a fabricated AX=6 contract. `1230` is a different Win95 operation: it searches a separate FCB filesystem table from an ES:DI SFT pointer and needs directory metadata. That table does not exist here, so `1230` remains unsupported. It is not aliased to `1216`.

The contract sources are [Ralf Brown's original interrupt corpus](https://www.cs.cmu.edu/~ralf/files.html), `INTERRUP.K` (1216/1220/1230/1231), `INTERRUP.L` (1605, tables 02631/02632), and Microsoft's [Windows 3.0 DDK Appendix D.2.1](https://www.pcjs.org/documents/books/mspl13/win/w3ddkvxd/), preserved by PCjs. Pointer word order follows the primary pointer contract and x86 far-pointer representation; actual MZ relocation and flattened-kernel checks validate the implementation. [Primary source receipts](primary-authorities.json) record these authorities. The [original FreeDOS authors' review](https://sourceforge.net/p/freedos/mailman/freedos-devel/thread/a527e93966582aa438a51aad7d10f6a5@metalpunks.info/) also describes the experimental nature of the Windows hooks.

## Evidence

| Scope | Actual result | Receipt |
|---|---|---|
| Complete ordinary kernel source build | PASS, exit 0 | [Full source preimages and build hashes](source-preimages.json) |
| Complete experimental Windows-hook kernel source build | PASS, exit 0 | [Full source preimages and build hashes](source-preimages.json) |
| Extracted production C bodies, with host far-pointer adapter | 38 PASS, 0 FAIL | [Host result](host-result.json), [checks](host-results.txt) |
| Actual MZ bytes, relocation entries and flattened kernel bytes | 14 PASS, 0 FAIL | [Linked layout](linked-layout.json) |
| Corrupted pointer/relocation/optional-pointer/fixed-SFT layouts | 4 rejected, 0 invalid accepted | [Negative checks](layout-negative-result.json) |
| Dedicated plain-DOS guest, actual JFT/SFT and presence calls | 17 PASS, 0 FAIL | [Guest result](native-dos-v2-result.json), [original guest-written report](native-dos-v2-results.txt) |
| Diagnostic image filesystem before boot | fsck exit 0 | [Static image receipt](diagnostic-image-static.json) |

The successful guest used 128 MiB RAM, one CPU, TCG, `qemu64`, no NIC and no Windows media. It ran 10.15 seconds and emitted `SHZ-EXIT:0`; the host then stopped its owned guest. The input disk stayed unchanged. The guest-written 710-byte report has SHA256 `f8419d5b465e7ba84dafa4265d446104aa4503916045e8b66e1dec440c525716`.

The first attempt failed before boot because the installed QEMU does not offer `qemu32`. It produced no guest report or exit marker. Its original receipt incorrectly marked DOS execution true; the original is preserved privately, and the public [corrected failure receipt](native-dos-v1-corrected-failure.json) explicitly records **no DOS execution**, the original receipt hash and the correction. A separate v2 epoch used advertised `qemu64` and a new owned disk. No failed receipt was converted into a successful test.

## Reproduce from source in another environment

Required real tools: Git, Python 3, GNU make, NASM, patch, a native C compiler for the host fixture, Open Watcom v2 (`wcc`, `wcl`, `wlink`, `wmake`), mtools and dosfstools. QEMU is required only for a separately reviewed native run. Keep at least 17 GiB free. Set `WATCOM` to your installation root and add its `binl64` directory to PATH. The [toolchain receipt](toolchain-receipt.json) freezes the executable hashes actually used. The used extracted tree lacks an archive-hash stamp; correspondence to the separately hashed cached archive is not assumed. Open Watcom's `Last-CI-build` URL is rolling, so record your actual compiler/archive hashes before comparing byte-identical builds.

Obtain FreeDOS at commit `5ffb5502d39a10a30f5b8a9e8beeba0bf30245d3` and initialize its submodules: country `7f83e041d00f78b3912c761246930f3b437440f6`, share `47f3d42527256fa46a00fe84cdb46d90f2e66f50`. Obtain FreeCOM at `04fc21a9f6792abe9048598e8f2d048b4f6cd0e5`; its complete [source preimages](freecom-source-preimages.json) are frozen. A top-level kernel `git archive` omits submodule content, including `country/kernel.tb1`, and will not compile by itself.

With the pristine kernel at `build/cb43/upstream-kernel`, from the repository root:

```sh
python3 -B shizukudos/dos16/tests/test_cb43_dos_internals.py \
  --upstream build/cb43/upstream-kernel --output build/cb43/host
```

For a complete kernel build, copy the kernel **including initialized submodules** to your own `build/cb43/kernel-win31`. Apply the existing branding/date patches and this checkpoint patch, each with `patch --batch --fuzz=0 -p1 -i /absolute/path/to/patch` in that copied source tree. Use this `config.mak` for the experimental profile:

```make
XNASM=nasm
undefine XUPX
ALLCFLAGS=-DWIN31SUPPORT
NASMFLAGS=-DWIN31SUPPORT
```

Run `make all XCPU=386 XFAT=32` in that tree. For the ordinary profile, use a separate fresh copy and omit both `WIN31SUPPORT` lines. These flags must agree between C and NASM. Compile FreeCOM in a separate pristine copy after applying `freecom-0001-reproducible-build-stamp.patch`, using `bash build.sh` with the same Open Watcom environment.

```sh
python3 -B shizukudos/dos16/tests/verify_cb43_dos_layout.py \
  --kernel-tree build/cb43/kernel-win31 --output build/cb43/layout.json
python3 -B shizukudos/dos16/tests/build_cb43_dos_diagnostic.py \
  --kernel-tree build/cb43/kernel-win31 \
  --freecom build/cb43/freecom/command.com --output build/cb43/diagnostic
```

The producer creates a dedicated FAT16 disk and manifest and reads every payload back. It starts no VM. Its [input manifest](diagnostic-image-manifest.json) records source hashes, exact payload hashes, construction commands and the resource budget. `SHZEXIT.COM` emits a COM1 marker and halts; a native harness must stop its own guest after that marker. Use an owned disk copy, bounded execution, no NIC and an actually advertised CPU model.

The separate primary `0003-dosmgr-honest-contract.patch` modifies different handler bodies. [Strict compatibility checks](dosmgr-patch-compatibility.json) show both patch orders apply with zero fuzz and produce identical combined handler bytes. This checkpoint's compiled kernels and native disk **exclude** that separate patch; a combined build and native run need fresh receipts. Existing DOSMGR capability and instancing behavior remains unverified for Windows 98, so these DOS checks cannot be presented as proof of complete Windows compatibility.
