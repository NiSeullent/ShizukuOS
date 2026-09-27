# NTWDDMWrapper9x

The independent software display foundation for **Windows 98 Shizuku's Second
Edition**. The implementation is original C11 and uses no KernelEx, Wine,
ReactOS, Direct3D, Windows SDK, or operating-system library. Its name describes
the intended graphics extension project; this component **does not implement
Microsoft's WDDM binary interface or run WDDM drivers**.

## Implemented behavior

- Versioned C ABI, explicit capability negotiation, and allocator ownership.
- Up to 64 live, reference-counted, zero-initialized software surfaces, with
  generation-tagged handles. Final release rejects mapped surfaces, stale
  handles fail, and a generation that would wrap retires its slot.
- Exclusive CPU mapping, rectangle fills, overlapping self-blits with snapshot
  semantics, cross-surface copies, and conversion between four pixel layouts.
- Binding and presenting to an already mapped linear framebuffer. Dimensions,
  pitch, mapped size, address wrap, source/destination bounds, and overlap with
  internal allocations are checked before writing. Failed binds preserve the
  previous binding. Successful bind/unbind invalidates prior fences.
- Synchronous completion fences issued after actual work. Present may invoke a
  platform completion hook before issuing its fence. A failed hook yields
  `NTWG_E_FLUSH` and no fence; the framebuffer writes already occurred and are
  not rolled back.

| Format | Byte order in memory | Alpha behavior |
| --- | --- | --- |
| `NTWG_PIXEL_XRGB8888` | B, G, R, X | Reads opaque; writes X = 255 |
| `NTWG_PIXEL_ARGB8888` | B, G, R, A | Alpha copied exactly, without blending |
| `NTWG_PIXEL_BGR888` | B, G, R | Reads opaque |
| `NTWG_PIXEL_XBGR8888` | R, G, B, X | Reads opaque; writes X = 255 |

Pixel encoding is independent of CPU byte order and uses byte accesses, so
unaligned addresses and padded rows work. Presentation touches only requested
pixels, preserving framebuffer padding and surrounding pixels. Rectangles must
be nonempty and completely in bounds; implicit clipping, scaling, blending,
stretching, rotations, and arbitrary bitmasks are not implemented.

## Port interface

Include `include/ntwddm.h` and compile `src/ntwddm.c` with
`-ffreestanding -fno-builtin -fno-stack-protector`. The object has no unresolved
runtime symbols on the tested x86-64 host and i386 freestanding target. Supply
aligned allocations and matching deallocations. Allocator regions must be
valid, writable, and disjoint; the core cannot validate whether arbitrary
addresses are mapped. All API calls and callbacks must be serialized, with no
callback reentry. There is no implicit lock, ISR integration, or protection
against a malicious caller sharing the same address space.

The ABI version is `NTWG_ABI_VERSION` (`0x00010000`). Descriptors contain a byte
size and exact ABI version. Their layouts use native pointer and `size_t`
widths: this is an in-process C interface, not an on-disk or cross-architecture
message format. Handles are scoped to a context. Fences are scoped to a live
context and its binding epoch; neither survives context destruction or may be
used with a new context that happens to reuse the same address.

The initialization sequence is:

1. `ntwg_create()` with allocator callbacks.
2. `ntwg_bind_framebuffer()` with a mapped address, mapped byte length, dimensions,
   pitch in bytes, and a supported pixel format.
3. `ntwg_surface_create()`, followed by `ntwg_fill()` / `ntwg_blit()`, or an exclusive
   `ntwg_surface_map()` / `ntwg_surface_unmap()` pair.
4. `ntwg_present()` to copy pixels to the bound framebuffer. Optionally query its
   returned fence with `ntwg_fence_query()`.
5. Release surface references and destroy the context. Destruction releases all
   remaining owned surfaces but never frees the caller-owned framebuffer.

For a UEFI GOP handoff, `PixelBlueGreenRedReserved8BitPerColor` maps to
`NTWG_PIXEL_XRGB8888`; `PixelRedGreenBlueReserved8BitPerColor` maps to
`NTWG_PIXEL_XBGR8888`. Validate `PixelsPerScanLine * 4` before constructing the
32-bit pitch. GOP `PixelBltOnly` and arbitrary mask modes cannot bind directly.
The caller owns physical-address mapping and the framebuffer's lifetime before
and after `ExitBootServices`. A boot demo may use a preallocated arena for the
context/surfaces; it does not require firmware allocation after that transition.

With no flush callback, a fence reports completion of CPU stores to the mapped
region. It does not report scanout, vblank, atomic frame presentation, GPU
completion, or correct hardware cache policy. A hardware port must supply the
needed memory attributes, ordering barriers, and posted-write completion. The
optional hook can report completion or failure; it cannot report pending work.
Sequences never wrap. Failed rendering creates no fence, and future or expired
fences are rejected. Existing completed fences remain valid after surface
release because no queued work retains the surface.

## Validation

From the repository root:

```sh
make -C ntwddm test
make -C ntwddm sanitize CC=clang
make -C ntwddm freestanding
make -C ntwddm freestanding32
```

All generated files are under ignored `ntwddm/build/`. The sanitizer compiler
must have working AddressSanitizer and UndefinedBehaviorSanitizer runtimes.
This server's GCC runtime libraries are missing, so Clang is used for that
check. No package installation is needed for the recorded run.

The 2026-09-27 host run passes **308,637 assertions**, including **50,960
exhaustive same-surface copies** covering every nonempty rectangle and valid
destination of a 7 × 6 surface in each format. The snapshot oracle checks full
allocation bytes, including untouched padding. Other tests cover all 16 format
pairs, unaligned framebuffers, real fill/present pixel values, allocator failure,
surface-slot exhaustion/reuse, reference/mapping lifetime, malformed descriptors,
overflowing bounds, stale handles, unsupported capabilities, cross-context
fences, rebind/unbind invalidation, and failed completion hooks. The same suite
passes Clang ASan/UBSan with leak detection. Compile-only host and i386 checks
require zero undefined symbols; they are not execution in Windows 98.

## Remaining platform work

This is a software rendering core, not a Windows 98 display driver. It has no
VxD entry point, VMM mapping/resource callbacks, GDI DIB-engine adapter, Win32
display-provider wiring, monitor modesetting, interrupt/DMA handling, GPU
command scheduler, pageable video memory manager, D3D runtime, or vendor
miniport driver. `ntwg_require_capabilities()` explicitly returns
`NTWG_E_UNSUPPORTED` for WDDM miniport, D3D, and GPU acceleration requests.
There are no success-shaped substitutes for those interfaces.

A Windows 98 port must first supply a real protected-mode mapping/allocation
backend and display-driver bridge, then demonstrate guest drawing and safe
mode changes. GPU driver support additionally requires a deliberately selected
device backend, register/DMA contracts, interrupt handling, and execution tests.
UEFI framebuffer rendering or host pixel tests alone cannot establish any of
those capabilities or Windows 10/11 application compatibility.
