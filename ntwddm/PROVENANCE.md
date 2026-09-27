# NTWDDMWrapper9x source provenance

All tracked files in this directory were authored for this project on
2026-09-27. They are licensed under **GPL-2.0-only**, consistent with the
repository's `LICENSE` text. No Microsoft implementation, KernelEx, Wine,
ReactOS, Linux DRM, Mesa, vendor driver, or other third-party implementation was
copied or translated into this directory.

| File | Origin and role |
| --- | --- |
| `include/ntwddm.h` | Original project C interface and capability vocabulary |
| `src/ntwddm.c` | Original allocation ownership, bounds validation, pixel conversion, directed overlapping copy, and completion tracking |
| `tests/test_ntwddm.c` | Original contract tests with a separate snapshot-copy oracle and component-layout table |
| `Makefile` | Original host, sanitizer, and freestanding build checks |
| `README.md`, `PROVENANCE.md` | Original integration, limitations, validation, and provenance documentation |

Only standard compiler-provided integer/size declarations are required by the
core. Host tests use the host C runtime to allocate memory, report failures, and
construct their reference buffers; that runtime is not linked into the
freestanding core object. Common framebuffer component layouts, rectangle
copying, reference counts, and tagged handles are independently implemented
interface concepts, not imported source algorithms.

The `NTWDDMWrapper9x` name identifies the proposed graphics extension family.
It does not assert Microsoft's WDDM ABI compatibility, Direct3D support, vendor
driver compatibility, Windows 98 driver loading, or Windows 10/11 equivalence.
