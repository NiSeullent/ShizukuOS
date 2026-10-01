# Actual combined DOS guest checkpoint

The source-built combined CB43 + DOSMGR kernel was independently executed in a dedicated DOS-only guest. All **17 real DOS API checks passed**, no failures; the guest wrote its report and exit marker0. The FAT readback check exited0 and the complete frozen source disk was unchanged.

This new execution follows the earlier [combined source/build checkpoint](../dos-combined-contract-cb43-20261001/README.md), which truthfully recorded no guest run at its own freeze. Its frozen12 files are unchanged. The actual combined kernel SHA256 is `c1c86626585c8332a8788a01ded40c8795fd449d1832c9428436038530bbe906`; the frozen source image SHA256 is `50d44ccf164e26fbcc06c4e3869031f6ca8353116e71f9218a5528596a39ab0a`. Kernel bytes were independently read back before launch.

The VM used an owned copy, QEMU qemu64 TCG,128MiB,one CPU and no NIC/display/monitor. Root stopped only that owned VM after its actual SHZ-EXIT:0 marker. That host stop is not a Windows clean shutdown. The real DOS report is retained as [text](actual-native-results.txt), with complete scoped [receipt](actual-native-result.json). No disk, compiled binary, capture, installed Windows volume or Microsoft input is included here.

These17 checks exercise real SFT/JFT/open/close/reference-count and presence APIs. They do not exercise the327673 host DOSMGR frames in a guest, synthesize Windows startup, run a Windows VMM, or establish replacement of MS-DOS under actual Windows98. ShizukuDOS is intended to replace MS-DOS underneath Windows98; Kernel32 and Kernel64 remain components for that actual Windows98 system. Windows98 boot, native modern apps and final product ISO remain unverified.
