# Static TLS provenance

Local files `tls.c`, `tls.h`, `test_tls.c`, `test.py` and this note are
GPL-2.0-only project code. They are a behavioral derivative of the pinned
ReactOS loader, not a pasted copy of those functions.

| Source | Revision | What was read | License | Adaptation |
| --- | --- | --- | --- | --- |
| ReactOS `dll/ntdll/ldr/ldrinit.c` | `9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8` | `LdrpInitializeTls`, `LdrpAllocateTls`, `LdrpFreeTls`. File SHA-256 `4c278b6e97306cf105f3b541f8b26f38514668973b5f6ec68adf16fc0ee37231` | GPL-2.0 (root COPYING; authors Alex Ionescu, Aleksey Bragin) | Index publication and per-thread copy kept. `SizeOfZeroFill` is applied. The pinned ReactOS copy length is only `End-Start` and that omission is not followed. No PEB, TEB, or heap call is reused. |
| ReactOS `dll/ntdll/ldr/ldrutils.c` | same revision | `LdrpCallTlsInitializers`. File SHA-256 `889173186f4b86ba75968cc3841573977147f9e6d5ac323985f3707376ecd048` | GPL-2.0 | Callbacks run in listed order with `(module, reason, NULL)` until the NULL terminator. There is no SEH around the call. |
| Wine `dlls/ntdll/loader.c` | `df15af3652511150490934682202d45af892f887` | `alloc_tls_slot`, `alloc_thread_tls`, `call_tls_callbacks`. File SHA-256 `cd643f9bd17e1721f8ebe6f7bc3c2c192f7bc19cdbfa454c9d2836877c161aba` | LGPL-2.1-or-later | Compared only. No Wine source is copied. Empty directories (no template, no zerofill, no callbacks) are rejected, matching Wine's early return. Zerofill matches Wine and the PE contract. |
| One-Core-API-Source `dll/ntdll/ldr/ldrinit.c` | `9eb3c31de9460c1ccce3f6a10c9c4a704f032514` | HTTP 200 on the raw path | per-file; this tree is a ReactOS fork | The body was not copied. |

`Characteristics` must be zero in the on-disk directory. ReactOS stores the
index in its private copy of that field; this port writes only `*AddressOfIndex`.
Registration fails while a thread vector is live, so a new module cannot
silently miss an existing thread.
