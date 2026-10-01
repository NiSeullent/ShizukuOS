MPR guest/provider fixture
==========================

`t_mpr_provider.c` dynamically loads the unchanged pinned Wine MPR module and
resolves the seven real sal3.dll imports. It checks the runtime's independently
queried current identity, UTF16 buffer extent, actual local C: drive, and absent
registry ProviderOrder. Missing network providers stay unavailable and enum
outputs are cleared; no network connection/share or Office success is invented.
Pinned Wine currently inherits GetUserNameW's short-buffer status instead of
Windows WNet's documented ERROR_MORE_DATA. The test explicitly reports that
status gap and checks the real delegation; it does not claim full error parity.

The separately built `mprfix.dll` is **fixture only** and must never be added to
the product's provider configuration or compatible-API score. It supplies an
actually empty resource set. NPOpenEnum owns a genuine kernel event;
NPEnumResource returns zero resources; NPCloseEnum closes that actual event.
Counters prove the unchanged MPR registry loader and named-provider callback
dispatch happened. It offers no network type, connection, share, authentication,
credential, storage or product-health capability.

The guest refuses an existing ProviderOrder or dedicated fixture service. It
uses the native loaded DLL's actual path and terminated, type-correct REG_SZ
values, unloads MPR before each initialization, closes real enum/module/key
handles, removes only its created keys/value, and verifies missing-provider
behavior after cleanup. The helper DLL must be staged beside system DLLs as
`mprfix.dll`; it is built in a separate ignored test bundle, not discovered as
a production DLL by build.py. No product MPR source or ordinary Wine cache is
modified. Native compilation/host inspection do not prove guest execution.

Pinned Wine enum handles directly refer to internal heap structures. Tests
therefore never supply random or stale non-NULL enum handles. Its ProviderOrder
and provider metadata parsers also assume correctly terminated REG_SZ data;
malformed provider registry data remains an upstream boundary, not a claimed
validation capability. All test registry mutation belongs to a disposable
guest execution; the fixture performs no host/client configuration writes.

Primary inputs/contracts:

- Wine commit db11d0fe6a169c457e23d007e20404643d067aa8, dlls/mpr/wnet.c and mpr_main.c
- https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetgetuserw
- https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetgetconnectionw
- https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetopenenumw
