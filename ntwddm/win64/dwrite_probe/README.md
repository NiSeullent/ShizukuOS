# Private AMD64 DirectWrite probe

`probe.c` calls the real `DWriteCreateFactory` export from the selected runtime
archive. It compares real font faces against independently parsed publisher
font tables, exercises Latin/Korean glyph analysis and text layout, and reads
back rendered pixels through GDI and the QEMU framebuffer. Font files remain
private to the trial; the probe does not install system fonts.

Build and execution are managed by `tools/win64_dwrite_probe_trial.py`. Fresh
preparation receipts bind the source, compiler inputs, runtime, font corpus,
executable and actual FAT payload bytes. The runner keeps a 20 GiB disk reserve,
256 MiB private write budget and 16 MiB output budget.

The current observer and PE regression suite passes 38 tests. The actual
`dwrite-run-v2` guest trial is **FAIL**: Korean glyph analysis produced an alpha
texture, and Latin text reached the real framebuffer, but Korean text layout
had two aggregate order/cmap errors and no Korean DIB ink. Its strict renderer
returned before the Korean bitmap draw call, so zero ink does not establish a
provider raster failure. The child then timed out before its final verdict and
normal exit. Full DirectWrite, native Windows 98, system
font fallback, Direct2D integration and application functionality remain
unverified.

The current source adds diagnostic records without changing the oracle or any
acceptance condition. `DW64 MISMATCH` identifies row (0 Latin, 1 Korean), UTF-16
position, expected/actual character, glyph and cluster, and the prior seen mask.
Its condition mask bits are 1 duplicate position, 2 cluster, 4 character and
8 glyph. Rejected callbacks retain their early error and emit `DW64 DRAW SKIPPED`;
valid callbacks emit `DW64 DRAW CALL` and `DW64 DRAW RETURN` with the actual
bitmap draw HRESULT. Layout-level draw success remains a separate record. These
new diagnostics are absent from the preserved v2 logs. A fresh compile of this
source produced an actual AMD64 executable with the same 33 imports, executable
entry and DIR64 relocations. The existing font oracle remained unchanged except
for a fresh nonce. The new executable has not been guest-tested; the v2 FAIL
and all acceptance conditions remain unchanged.

See [the evidence and reproduction guide](../../../docs/DIRECTWRITE_PROBE_6970.md)
for exact inputs, results and requirements for another development environment.
