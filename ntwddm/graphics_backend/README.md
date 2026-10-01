# Private Mesa resource foundation

This is original project resource ownership/state code plus a frozen genuine
Mesa **26.2.3** scalar TGSI interpreter and the reviewed 5abe triangle raster
adapter. It creates real RGBA8 and D32 allocations, retains bound resources,
rejects simultaneous maps, copies real pixels and shades actual triangles.
It exports **14 private `ntg_*` functions**, never `D3D11CreateDevice`, a DXGI
factory, Direct2D interfaces, feature levels or a hardware driver identity.

The supported profile has at most four devices, sixteen resources/device,
sixteen globally live Mesa shader contexts, 64×64 textures, one mip/layer/sample,
four affine varyings, depth comparisons and the existing byte-domain source-over
blend. Texture storage has a **2 MiB/device** cap; the separate shader-context
cap is 4 MiB/context and maximum draw scratch is 32 KiB. These do not amount to
a 2 MiB total device-memory claim. Resource creation with another format,
multisampling, mipmaps, arrays or extra flags fails before allocating memory.

Calls are serialized with a global nonblocking lock. Public operations and each
nested allocation/free/math callback use an AMD64 x87/MXCSR scope. The caller's
rounding, masks, status and saved register state are restored. Callback providers
must still allocate valid disjoint storage and compute the actual requested math
operation; a changed callback environment cannot leak into subsequent Mesa work.
Mapped pointers expire at unmap. Binding references survive external release;
device destruction refuses mapped objects and releases every remaining allocation.

`build.py` copies exact peer source bytes and retained per-file license notices
into a fresh ignored build, applies only explicit checked AMD64 FP/layout
preparation, runs normal and ASan/UBSan host tests, then builds `NTGSW.DLL` and a
fresh-nonce Windows ABI probe. The DLL is freestanding AMD64 PE32+ with zero
OS/CRT imports and actual DIR64 relocations. The probe resolves its transports
against the **actual frozen runtime archive**, including UCRT math exports.
Compiler dependencies, original/prepared sources, tool binaries, logs and
generated inputs are recorded in the immutable receipt. No peer script is run.

`trial.py` appends the exact private DLL to a verified private Modern archive,
preserving all existing member bytes/order. It uses the existing unchanged guest
runner with sealed boot/kernel/archive/QEMU/firmware, an own FAT image and QMP
socket, no NIC and the unchanged 20 GiB reserve, 256 MiB guest-write and 16 MiB
host-output guards. The evidence gate requires the actual child PID and nonce,
every mandatory pixel/lifetime assertion, external exit 0, successful
`proc_wait` return 0 and all 16,384 independent framebuffer pixels. A standalone
Kernel64 success is distinct from native Windows 98 or DirectX/app support.

Provenance: all new `backend.*`, `fp64.h`, `host.c`, `probe.c`, `build.py`,
`trial.py`, and `test_trial.py` are original GPL-2.0-only project code. The
reviewed peer glue also retains GPL-2.0-only. Mesa files keep their original
VMware/other MIT permission notices, Berkeley SoftFloat BSD notices and selected
BSL-1.0 license; do not relabel all selected files as one license. The official
Mesa archive SHA-256 is
`1628058a8d2c0615975de5a15ab7bbb9638c50000b5bed9456ff423ea034a81f`.
The frozen foundation receipts are shader-v2
`b2c21ccdbf876d310affac58202d4b3139c30f1d71db7b696d12980dfb81cac2`
and raster-v3
`26d7055953bb6e0915df675ea0c0797c07e0c5704b00ef16f077e1867da3164f`.
Their original 49 selected upstream files and seven prepared files are verified
before and after the build. This source closure and all license material stay
beside private generated artifacts, outside Git.

See [the graphics checkpoint](../../docs/DIRECTX_GRAPHICS_CONTINUATION_6970.md)
for current evidence and the full DirectX/Direct2D/DirectWrite acceptance boundary.

The corrected frozen v3 passed **1,714 assertions each** in normal and
ASan/UBSan host runs; **23** trial-gate regression tests passed. The actual
private Kernel64 trial passed **66** resource/pixel/lifetime checks, including
496 real shaded samples, 4,096 independent RGBA bytes, depth/padding, complete
heap cleanup and **16,384** independently checked QEMU framebuffer pixels.
The child exited normally with code 0 and raw `proc_wait` returned 0. QEMU's
separate host code 1 was verified against its ISA-debug-exit guest-zero encoding
and the actual `SHZ-EXIT:0` marker. KVM device/VM/vCPU file descriptors, no NIC
and original/sealed source preservation were recorded; the VM is stopped.

[handoff.json](handoff.json) pins the exact source, upstream, build, preparation
and guest receipts. Private evidence is in `build/graphics-mesa-run-v1` at the
repository root; no disk or generated binary is tracked. This is actual private
resource rendering; DirectX COM/device, DXGI, Direct2D, full DirectWrite, native
Windows 98 and Office acceptance remain false.
