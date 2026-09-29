# Static TLS contract

This directory is a host-tested loader contract for a 32-bit
`IMAGE_TLS_DIRECTORY32` (24 bytes, the size in the pinned Chromium
156.0.8076.0 `chrome.exe` and `chrome_elf.dll`). It assigns indexes from zero,
writes `AddressOfIndex`, copies the template, applies `SizeOfZeroFill`, and
calls callbacks in registration order with a NULL reserved argument.

It does not remove a TLS data directory and it is not yet called by the
Windows 98 process loader. A passing host test is not a Chromium launch.

Provenance and the ReactOS zerofill difference are in [PROVENANCE.md](PROVENANCE.md).

```sh
python3 -B ntwin32/tls/test.py
```
