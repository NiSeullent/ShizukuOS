# Pinned Wine graphics and shader prerequisite work

This directory preserves real Wine graphics source compilation, genuine
vkd3d-shader host tests, and an exact HLSL ownership repair for continuation on
another machine. **DirectX runtime support remains INCOMPLETE.** No loadable
D3D/DXGI/D2D DLL, device, presentation, or application acceptance result was
produced by this work.

The upstream pin is Wine `db11d0fe6a169c457e23d007e20404643d067aa8`, containing
vkd3d-shader 1.18. The originals were obtained from Git blobs in the local
read-only Wine checkout; their complete materialized hash ledger remains in
the private build receipt. Upstream LGPL notices are preserved in
`upstream-notices/`. The two changed upstream files retain LGPL-2.1-or-later;
the independent preparation and test recipes use GPL-2.0-only.

## Published checkpoint

| Work | Verified result |
| --- | --- |
| Wine graphics source units | 107 genuine AMD64 COFF objects compiled; DLL linking and runtime execution unverified |
| Genuine host shader compiler | 108 checks passed: HLSL to 468-byte DXBC, DXBC to 165-word SPIR-V, pinned 321-byte disassembly, malformed inputs, deterministic repetitions |
| Genuine DXBC container consumer | 975 normal host checks passed, including bounds, signatures, copies and ownership |
| Sanitizer continuation | **FAIL**: 725 bytes leaked in five allocations; failure was retained and not suppressed |
| HLSL ownership repair | Exact patch preparation passed; repaired compiler and sanitizer execution **UNVERIFIED** |
| AMD64 vkd3d-shader archive | **NOT BUILT**; the recipe's final success gate was never reached |

`evidence/publish-checkpoint.json` preserves a small source-side summary with
receipt, binary, log and patch hashes. Raw build receipts and logs remain
outside Git in ignored `build/`; a fresh checkout does not contain those
private inputs or compiled objects. The normal host checks were rerun for the
publication review with exit code 0 and identical output hashes. All 1,398
original files, 341 generated headers, one prepared IDL header and 107 graphics
objects were independently rehashed in that review.

## Prepare the repair on another machine

Use Python 3.9 or newer on Linux/WSL, an exact upstream Wine source tree, and
at least 20 GiB free disk after the operation. The helper requires the two
original file SHA-256 values in `patches/provenance.json`; it does not download
anything, alter the originals, install libraries, or start a guest.

From the repository root, replace the source path with your own read-only
tree. The output must be a fresh directory beneath this module's `build/`:

```sh
python3 -B ntwddm/win64/directx_wine_port/prepare_lifetime_cli.py \
  --wine /absolute/path/to/pinned-wine \
  --out ntwddm/win64/directx_wine_port/build/lifetime-prepared-new
```

The exact generated diff is already committed as
`patches/vkd3d-hlsl-lifetime.patch`, SHA-256
`e8b45f17167696adc7731cd880d6fe6b08c29663c3de70b7d9062d80752f3a57`.
The helper records hashes of both originals, prepared copies and its recipe.
Its PASS means source preparation only.

The repair initializes the cloned entry/patch bodies, cleans them and the
uniform block on each post-allocation return path, and supplies a Bison
destructor for discarded `<name>` values. `compiler_lifetime_host.c` adds
repeated positive HLSL compilation and four syntax/semantic failures, but has
not been compiled or run against the repaired source. The first next step is
an isolated repaired build with normal and unsuppressed sanitizer tests,
followed by byte-for-byte comparison of the three compiler outputs.

## Build recipes and limits

`build.py` records upstream source/header/license closure and compiles graphics
objects. `compiler_build.py` builds actual shader parser/compiler units and
then requires both normal and sanitizer host tests before attempting a MinGW
AMD64 archive. `compiler_resume.py` reuses only objects bound to the exact
resource-stopped historical v4 receipt. `contracts.py` requires that complete
shader gate before recording real unresolved COFF contracts against a sealed
runtime. `archive_failed.py` losslessly compacts only the specifically pinned
failed v1 source tree and checks every member; it is a historical maintenance
helper, not a general cleaner.

For the recorded base location, the normal fresh compiler invocation is:

```sh
python3 -B ntwddm/win64/directx_wine_port/compiler_build.py \
  --base ntwddm/win64/directx_wine_port/build/wine-graphics-object-v2 \
  --out ntwddm/win64/directx_wine_port/build/compiler-new
```

This existing recipe uses the **unmodified** originals. It does not apply the
repair automatically and is expected to retain the known sanitizer failure
on the recorded toolchain. Do not report its normal test PASS as the completed
recipe result. A repair-aware compilation driver is still needed.

The source materialization recipe currently expects the original local Wine
checkout at `/root/Win98-Modern-apps-cb43/build/upstream/wine`, the exact Git
pin, existing generated Wine headers and a genuine WIDL tool. On another
machine these must be supplied and the historical location adapted in a new
reviewed recipe. GCC, Clang with working ASan/UBSan runtimes, MinGW-w64 GCC/ar/nm,
Bison, Flex, m4, nm and readelf are also required; `contracts.py` needs
`pefile`. No recipe installs missing tools. The resume helper intentionally
rejects unrelated or recreated historical receipts.

All build helpers retain a 20 GiB disk floor, a 256 MiB aggregate owned build
budget, a 16 MiB aggregate log budget, serial compilation and bounded child
processes. The publication review used 224,313,344 allocated bytes in this
module's build directory. Keep the budget intact and use fresh receipts for
each continuation.

Full status, provenance and remaining runtime dependencies are in
[DIRECTX_WINE_PORT_6970.md](../../../docs/DIRECTX_WINE_PORT_6970.md).
