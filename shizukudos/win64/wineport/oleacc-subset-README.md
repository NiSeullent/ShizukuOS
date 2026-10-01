# Isolated Wine 11 OLEACC feasibility port

`probe_oleacc.py` materializes OLEACC sources from pinned Wine commit
`db11d0fe6a169c457e23d007e20404643d067aa8`, generates IDL artifacts with the
already-prepared Wine `widl`, and invokes the existing module builder with a
separate output directory. It reads the prepared source/import libraries;
neither the prepared sparse checkout nor normal module caches/receipts change.

The default configuration attempts the complete upstream proxy layer. Its
actual link failure identifies missing RPC proxy/stub and COM user-marshaling
providers. `--local-default-objects` uses `oleacc-local-module.json` and retains
the actual upstream client/window accessible COM objects, child enumeration,
name/role/identity methods, resource strings and object lookup functions.
All five Chromium imports are present: `AccessibleChildren`,
`AccessibleObjectFromWindow`, `CreateStdAccessibleObject`, `LresultFromObject`
and `WindowFromAccessibleObject`.

The local adaptation explicitly excludes the absent RPC proxy factory and
registration. Their exports remain absent. Missing GUI-thread/class-name/atom
providers return documented failure values; no success token or placeholder
accessible object is manufactured. Cross-process accessibility and proxy
marshaling remain unsupported. The resulting 17 exports describe a bounded
module surface, not an accessibility compatibility percentage.

Adaptations are exact anchored replacements against the pinned source. The
receipt includes original file hashes, generated file/tool hashes, linker-input
hashes, the complete generated patch, output DLL hash and export classification.
It additionally closes a process handle after duplicate failure, propagates atom
deletion failure, returns `E_FAIL` after mapping failure, and validates null
window-object outputs and negative child ranges. The original upstream LGPL
notices are preserved in every materialized source.

Source lineage: [Wine11 OLEACC directory](https://github.com/wine-mirror/wine/tree/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/oleacc).
Upstream client/window/main/property-service source and resources carry
LGPL-2.1-or-later notices. The probe, configurations and guest contract are
original GPL-2.0-only project work.

The isolated local DLL links successfully for AMD64. `t_oleacc_local.c` compiles
with the runtime's strict flags and checks actual HWNDs, COM vtables, window text,
child hierarchy, identity, ownership and failing absent-provider paths. A guest
pass must be recorded separately before asserting behavior. No Chromium,
Legcord, Discord, Windows 98 GUI or full accessibility pass follows from linking.
