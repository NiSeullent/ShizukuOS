NCrypt provider absence boundary
================================

This module supplies a measured loader/fallback boundary. It implements no
software key storage, TPM, smart-card, persisted keys, signatures or attestation.
All thirteen exports are unsupported cryptographic functionality and must not
be counted as compatible cryptographic APIs. Host/native build results and
negative guest contracts do not prove Chromium or Steam works.

The current runtime has no registered CNG key-storage provider implementation.
`NCryptOpenStorageProvider` clears its pointer-sized handle output and reports
`NTE_PROV_DLL_NOT_FOUND`. A missing output is `NTE_INVALID_PARAMETER`; nonzero
flags are `NTE_BAD_FLAGS` because that API defines none. No provider object is
created, even for the default or Microsoft Software/Platform provider names.
The other exports cannot recognize any owned provider/key handle. They return
`NTE_INVALID_HANDLE` without reading arbitrary handle addresses; required NULL
output pointers return `NTE_INVALID_PARAMETER`. Typed key outputs and result
byte counts are cleared, while caller data/signature buffers are untouched.
No successful provider, algorithm, key, signature, export or cleanup is invented.
These documented failure categories are a bounded contract; the module does
not claim Windows' complete error-precedence behavior for malformed calls.

The existing `SHZ_K32TRACE=1` opt-in records at most sixteen provider-open
observations per process: the public provider alias (at most 96 UTF16 words),
flags and actual failure status. It preserves caller LastError. Each name word
is captured with the real process-memory API; an unreadable word is marked
without changing the API failure or reading beyond a terminating word. No key
material is logged.

Actual trigger: the official Chromium Win_x64 snapshot1708403 (157.0.8081.0)
`REVISIONS` pins source commit `fc75daa82260574dd02d7a1e66b58535389aca14`.
The V15 actual fatal frame at chrome.dll RVA`0x09fe041b` calls wrapper
`0x11093df0`, which jumps to delay IAT`0x135d9350`: `NCryptOpenStorageProvider`.
That function contains both Microsoft Software and Platform provider literals,
selected by `provider_type_`; the recorded serial alone does not establish
which one was selected. The pinned `UnexportableKeyProviderWin::SelectAlgorithm`
returns an empty optional when provider-open fails. A real software KSP and
asymmetric BCrypt implementation remain necessary if a product requires those
keys. Wine11's unconditional successful provider allocation is not used.

Primary contracts and pinned source:

- https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptopenstorageprovider
- https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreateclaim
- https://learn.microsoft.com/en-us/windows/win32/com/com-error-codes-4
- https://storage.googleapis.com/chromium-browser-snapshots/Win_x64/1708403/REVISIONS
- https://github.com/chromium/chromium/blob/fc75daa82260574dd02d7a1e66b58535389aca14/crypto/unexportable_key_win.cc

Validation uses real typed guard outputs, inaccessible handle addresses,
unchanged signature/property/export buffers and genuine static PE imports.
Actual publisher fallback and native Windows98 integration require separate
execution evidence.
