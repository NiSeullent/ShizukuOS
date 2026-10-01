# DXGI unavailable-provider experiment

This module supplies **failure reporting only** for the three factory creation
entry points. Kernel64 currently has no DXGI Direct3D provider. Valid creation
requests return `DXGI_ERROR_UNSUPPORTED` and a NULL output; invalid output/IID
arguments and unknown factory2 flags return `DXGI_ERROR_INVALID_CALL`. No factory,
adapter, COM reference, driver identifier, device, swap chain, or rendering
success is advertised. The null-argument policy is this boundary's defensive
behavior; it has not been compared against a native Windows installation.

This is a loader/fallback experiment, not a DXGI implementation, graphics
functionality pass, full Windows API support claim, or Windows 98 execution
claim. A functional DXGI provider must replace this boundary when its real
backend exists.

## Actual trigger

The official Legcord 1.3.0 AMD64 executable, SHA-256
`cc77a1aa873ff55b4d9e5a532b356c557739dc0467c3dd54bc50b1d80a0b23b0`, has
one DXGI delay import: `CreateDXGIFactory1`, IAT RVA `0xd0b2390`.
Private `build/modern-apps/legcord-v7/serial.log` shows GPU PID216 missing
`dxgi.dll`, entering Electron's delay-load failure hook at `legcord.exe+5831fba`,
then exiting with `-2147483645`; PID308 repeats the failure. The main process
creates renderer PID372 but this does not prove that a window painted. Optional
DXCore probing and handled first-run configuration errors are separate.

The original log, publisher executable, frozen v7 runtime, kernel-v2 images,
and their existing build receipts were hashed before these files existed.
The immutable ignored receipt is
`build/app-inputs/productivity-01a0f3d0cb43/tools/legcord-dxgi-boundary/absent-before.json`.

## Contract and source review

This source is original GPL-2.0-only code; no upstream implementation is copied.
The negative provider result follows reviewed Wine 11.0 commit
`db11d0fe6a169c457e23d007e20404643d067aa8`,
[`dlls/dxgi/factory.c`](https://github.com/wine-mirror/wine/blob/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/dxgi/factory.c):
`dxgi_factory_init` calls `wined3d_create(0)` and returns
`DXGI_ERROR_UNSUPPORTED` when the backend cannot initialize.
[`dxgi_main.c`](https://github.com/wine-mirror/wine/blob/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/dxgi/dxgi_main.c)
routes all three creation entries into that factory implementation.

Microsoft documents failed factory creation as an HRESULT error and defines
[`DXGI_ERROR_UNSUPPORTED`](https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/dxgi-error)
for unsupported device/driver functionality. Only zero and
`DXGI_CREATE_FACTORY_DEBUG` are valid
[`CreateDXGIFactory2`](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_3/nf-dxgi1_3-createdxgifactory2)
flags. The publisher's Chromium information collector has a real
[`FAILED(CreateDXGIFactory1)` branch](https://github.com/chromium/chromium/blob/150.0.7871.129/gpu/config/gpu_info_collector_win.cc)
that returns false instead of accessing a factory. Whether Electron 43.2.0
actually reaches software rendering after that branch requires a fresh guest
application trial. Electron's tagged DEPS pins Chromium `150.0.7871.129`.

The pinned ReactOS revision
`9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8` has no DXGI module listed in
[`dll/directx/wine/CMakeLists.txt`](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/directx/wine/CMakeLists.txt);
the reviewed `dll/directx/wine/dxgi` and `dll/win32/dxgi` implementation paths
do not exist there. This is explicit source-availability debt.

## Real graphics prerequisites

Wine DXGI comprises adapter, device, factory, output, resource, swap-chain and
utility bodies. Its pinned Makefile imports `gdi32`, `user32`, `win32u`, `wined3d`
and GUID libraries; WineD3D imports `opengl32`, graphics libraries and optional
VKD3D/Vulkan providers. Neither complete backend is available in this runtime.
Kernel64's actual framebuffer/virtio GPU interfaces are different APIs and
cannot be presented as WineD3D/DXGI by renaming exports. Hardware rendering needs
that coherent device/backend port. A software path instead needs a working
Chromium raster/shared-memory presentation path and its actual packaged ANGLE
or SwiftShader dependencies, verified by visible frame capture and interaction.

## Verification

`tests/test_unavailable_host.c` executes the real production source with a
narrow Windows ABI fixture under ASan/UBSan: negative HRESULTs, cleared/bounded
outputs, invalid inputs and the caller's failure branch. Production DLL and
`win64/tests/t_dxgi_unavailable.c` must compile with normal strict AMD64 flags.
The guest contract loads the actual DLL, resolves all three entries, calls the
real static import and checks safe failure. A guest contract PASS proves this
failure boundary only. The subsequent real Legcord trial must independently
show whether GPU retries stop and actual rendering becomes possible.
