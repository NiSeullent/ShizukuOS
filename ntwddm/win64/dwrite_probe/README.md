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
had two order/cmap errors and no Korean DIB ink. The child then timed out before
its final verdict and normal exit. Full DirectWrite, native Windows 98, system
font fallback, Direct2D integration and application functionality remain
unverified.

See [the evidence and reproduction guide](../../../docs/DIRECTWRITE_PROBE_6970.md)
for exact inputs, results and requirements for another development environment.
