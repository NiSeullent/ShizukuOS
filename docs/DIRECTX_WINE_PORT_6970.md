# Wine graphics port checkpoint 6970

The Wine graphics source and genuine shader compiler prerequisites are
preserved for another development environment. **Full DirectX, Direct2D and
DirectWrite support remains incomplete.** This checkpoint does not satisfy
the modern-app or Office acceptance requirements.

## What has actually passed

The pinned upstream repository is
<https://github.com/wine-mirror/wine>, commit
`db11d0fe6a169c457e23d007e20404643d067aa8`. Its bundled vkd3d-shader version is
1.18. Source materialization reads immutable Git blobs and never edits the
peer checkout. Original source/license records, generated headers, tool
identities and exact compiler invocations remain in the private receipts.

All 107 selected C translation units compiled to real AMD64 COFF objects:

| Module | Compiled units |
| --- | ---: |
| D3D11 | 11 |
| DXGI | 8 |
| WineD3D | 32 |
| Direct2D | 15 |
| D3D9 | 12 |
| D3D10 | 7 |
| D3D10.1 | 1 |
| D3D10core | 1 |
| DirectDraw | 12 |
| D3D12 wrapper | 1 |
| d3dcompiler_43 | 7 |

These are compilation results, not API coverage or runtime behavior.
No DirectX DLL was linked or installed by these recipes.

The real vkd3d-shader normal host build passed 108 checks. It compiles HLSL
into 468-byte DXBC, compiles that DXBC into 165-word SPIR-V, and disassembles
the pinned Wine VS 4.1 fixture into 321 bytes of assembly. It checks malformed
HLSL, deterministic repeated conversion and output cleanup. The negative
checksum-correct DXBC mutation changes the declared SHDR token count at word
54; it proves rejection of that malformed length, not an unknown opcode.
SPIR-V was inspected structurally by the host test. Neither complete
`spirv-val` validation nor Vulkan execution was performed.

The real DXBC container consumer passed 975 normal host checks for extents,
signature semantics, malformed/truncated data, independent copies, and
release/ownership behavior. During publication review both existing normal
binaries ran again with exit code 0 and identical log and compiler-output
hashes. All 1,398 pinned originals, 341 generated headers, one prepared IDL
header and 107 compiled graphics objects were also rehashed.

## Failures and prepared repair

The preserved v3 compiler attempt failed while linking the GCC sanitizer
runtime because an expected installed ASan shared object was absent. A later
v4 attempt used Clang for sanitizer work but stopped at the unchanged 20 GiB
disk floor. Its receipt remains `INCOMPLETE`.

The object-reusing continuation completed the sanitizer link and then
**failed**: LeakSanitizer reported 725 bytes in five allocations. The malformed
HLSL case leaked a five-byte identifier, and the cloned entry-function IR
accounted for the remaining 720 bytes. The original failure log and receipt
were preserved; no leak suppression was introduced.

The exact proposed repair is committed in
`ntwddm/win64/directx_wine_port/patches/vkd3d-hlsl-lifetime.patch`. Its source
preparation passed, and independent review checked initialization and cleanup
of the three local IR blocks and the Bison discarded-token destructor.
**The repaired source has not been compiled or sanitizer-tested.**
`compiler_lifetime_host.c` preserves planned regression inputs: 16 repeated
positive HLSL compiles plus four syntax/semantic failures. Their execution is
unverified. No AMD64 vkd3d-shader archive was produced, and the final compiler
recipe success status was never reached.

| Identity | SHA-256 |
| --- | --- |
| Original `hlsl_codegen.c` | `f2594b5914565317ea167de6acf9edb86b5d79edd06b52b1f9db7fd8acd1b787` |
| Prepared `hlsl_codegen.c` | `3cd8f7f28efa2ad5c9059efd89752b359c47f7b155950cf4d53b6816543948c7` |
| Original `hlsl.y` | `b88f4a34a9e93f36e8c84e25bfd3a6268241df03b6a820cc3b261a8d19d09b50` |
| Prepared `hlsl.y` | `ecf4ed672cf2310ca11c00fc7f497b8e9e273802d3b5aa94d6ca039b6505899b` |
| Exact repair patch | `e8b45f17167696adc7731cd880d6fe6b08c29663c3de70b7d9062d80752f3a57` |

The modified upstream sources remain LGPL-2.1-or-later. The pinned Wine and
vkd3d notices and vkd3d authors are retained under the module's
`upstream-notices/`, with upstream Git blobs and hashes in
`patches/provenance.json`. The independently written build/preparation/test
recipes carry GPL-2.0-only identifiers.

## Evidence retained across publication

The small committed `evidence/publish-checkpoint.json` records the review,
exact historical receipt identities and truthful unverified flags. Full
receipts and compiler outputs are private ignored build artifacts. Their
presence is required to rerun the historical object-resume path; publishing
the source checkpoint does not put those artifacts into a fresh clone.

| Private receipt relative to the graphics module | Status | SHA-256 |
| --- | --- | --- |
| `build/wine-graphics-object-v2/result.json` | INCOMPLETE; all 107 graphics units compiled, container prerequisite compile failed | `e93d6496a79ace2209aeac727ba267dcb9dab964c091898dc93b52d489e5556a` |
| `build/genuine-shader-compiler-v4/result.json` | INCOMPLETE; resource floor stopped the sanitizer build | `09ddc931c44ca3f29f5fc7281b4cb1a830b2e2bfbbab45750cecee439384de44` |
| `build/genuine-shader-compiler-resume-v1/result.json` | INCOMPLETE; actual sanitizer test exited 1 with leaks | `7753c9b95b5738382ab6d5703ff40c6cbe200c3d087425a633c1f330454def06` |
| `build/publish-host-review-v1/audit.json` | Source/object and normal host review PASS; repair runtime unverified | `51bae21b7670fc8857c35bf70ce8907b3d27715d1dc970f6ef5c9bf1816563ac` |

The private read-only source materialization from the failed v1 attempt was
losslessly compacted separately, preserving all member hashes and modes.
That historical archive and its failure records were not substituted for a
successful compiler result.

## Continue on a new machine

The module [README](../ntwddm/win64/directx_wine_port/README.md) contains the
exact portable two-file preparation command and the existing unmodified
compiler invocation. Linux or WSL with Python 3.9+, installed GCC, Clang
ASan/UBSan, MinGW-w64, Bison, Flex, m4, nm and readelf is required. The source
materializer also requires a real WIDL tool and the recorded generated Wine
headers. The current materializer uses the original local peer path; adapt
that location in a new reviewed recipe or supply the same read-only layout.
The resume helper binds exact historical hashes and cannot resume from
unrelated receipts. No helper downloads or installs its prerequisites.

Before attempting a loadable graphics runtime:

1. Compile the prepared HLSL files and the lifetime regression harness in fresh
   isolated output, preserving the original failed receipts.
2. Require normal and unsuppressed ASan/UBSan tests to pass, with identical
   normal/sanitizer compiler outputs, then build the real AMD64 shader archive.
3. Resolve the genuine graphics dependencies and link real DLLs. DXGI and
   D3D12 require full vkd3d device/queue/resource and Vulkan support; the shader
   library alone is insufficient. WineD3D requires WGL/OpenGL and D3DKMT
   adapter/device/DC/video-memory services. Direct2D requires actual D3D10.1,
   shader compilation and supporting runtime services.
4. Run real device/resource/shader/readback/presentation tests through the
   exported Windows APIs, then rerun the required Office and messenger apps.

Retain the 20 GiB disk floor, 256 MiB aggregate owned-build budget, 16 MiB
aggregate logs and bounded serial child processes. The publication review
ended with 224,313,344 allocated bytes in this module's build directory and
22,726,721,536 free bytes on the host. A repair-aware continuation driver is
still required; neither the source-preparation helper nor the existing
unmodified compiler driver completes the repair testing automatically.

The separate private Mesa rendering and DirectWrite probes have their own
acceptance records. Their results do not grant the unlinked Wine graphics
objects DirectX runtime coverage. Win98 graphics execution, application
functionality and full DirectX support remain unverified here.
