# ShizukuOS userland style

The genuine process-local theme engine now accepts ShizukuOS selector **3**.
OFF **0**, Classic **1** and Modern **2** retain their API values and original
resource bytes. Applications select through the existing `M98SetThemeStyle`
entrypoint, reopen invalidated theme handles, and paint with the existing
theme APIs. No extra exported symbol or global registration is required.

`src/uxtheme_shizukuos_style.h` embeds the exact bytes of
`src/uxtheme_shizukuos.ntth`. The existing `ntth_session_load` parser validates
that text; the existing `ntth_draw_background` software painter renders it.
There is no replacement painter, pre-rendered skin or unsupported-part success.

The distinct blue/cyan palette supplies all four push-button states, active
and inactive window captions, and the existing three frame parts. The active
caption runs horizontally from `102A43` to `167C9C` with white text. Button
normal/hot/pressed/disabled fills are `EDF5F9`, `DCEFF7`, `BEDFEA`, `E8EEF2`;
their borders are `3D7890`, `40A5C5`, `0E6680`, `A6B6C3`. Active button text
is `12283B`, disabled text is `526575`, and window frame fill is `F5F9FC`.

The new host fixture first failed against the unchanged production engine at
the actual style3 selection. It exercises genuine parsing/pixels, independent
literal gradient columns and palette expectations, 120 repeated selections,
stale-handle rejection with legal close, invalid-selector immutability,
clipping, row padding, surrounding byte guards, and allocation-failure cleanup.
Checks stay active with `NDEBUG`. Actual host results belong in the fresh
`build/shizukuos-style-agent-v1/`; the original `build/theme-engine/` is retained.

**Native execution and OS-wide themes remain unverified for this new style.**
This source does not supply the product appearance selector, persistence,
automatic common-control/nonclient hooks, the AMD64 provider's style3 default,
or a themed Kernel64 compositor. Those are separate mandatory integration and
native acceptance steps. A host pass cannot certify the self-installing ISO,
WDDM, modern apps or full web standards. The userland selector/build owner must
produce fresh source-bound PE/OEM/full-byte CPU evidence and genuine guest
input, painting, saved preference and restart evidence. Existing peer resources,
providers, probes, installed media and guest state are preserved.

Official product and ISO distribution remains **https://m98.nyase.kr**.
Only reviewed development files/patches may be public elsewhere; private
artifacts and local control credentials must remain private.
