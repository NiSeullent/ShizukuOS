# chrome_elf NT registry provider (M98NTREG.DLL)

Chromium `chrome_elf.dll` is a load-time import of `chrome.exe`, and its
`nt_registry` code imports nine NTDLL names that the Windows 98 SE NTDLL in
`benchmarks/win98se-ko-oem-native-exports-v1.json` does not export:
`NtCreateKey`, `NtOpenKeyEx`, `NtQueryValueKey`, `NtSetValueKey`, `NtDeleteKey`,
`NtClose`, `RtlFormatCurrentUserKeyPath`, `RtlInitUnicodeString` and
`RtlFreeUnicodeString` (static audit of 156.0.8076.0 in
`docs/CHROMIUM_CURRENT_TARGET.json`). Without them `chrome_elf.dll`, and so
`chrome.exe`, cannot bind.

`nt_registry.c` implements these NT contracts on the real Win98 ANSI registry
through `nt_registry_native.c` (ADVAPI32 `Reg*A`, Kernel32 code-page and heap
services only). Original GPL-2.0-only code following the documented NT
interfaces; no ReactOS, Wine, Microsoft or Chromium code was copied.

Behaviour enforced over Win98 differences:

- `\Registry\Machine` -> HKLM, `\Registry\User` -> HKU, and the provider-local
  `\REGISTRY\USER\SHIZUKU-WIN98-CURRENT-USER` (returned by
  `RtlFormatCurrentUserKeyPath`) -> HKCU. It is not an NT SID. Other object
  namespaces fail with `STATUS_OBJECT_NAME_NOT_FOUND`.
- `NtCreateKey` creates one level only; a missing parent fails instead of
  using Win98's implicit intermediate creation.
- `NtDeleteKey` refuses keys with subkeys (`STATUS_CANNOT_DELETE`) instead of
  Win98's recursive delete; other handles to the deleted key report
  `STATUS_KEY_DELETED`.
- Names are split on UTF-16 before conversion, so DBCS trail bytes equal to
  `\` are never parsed as separators. Unmappable characters fail with
  `STATUS_UNMAPPABLE_CHARACTER`; nothing is written lossily.
- REG_SZ/EXPAND_SZ/MULTI_SZ are converted UTF-16 <-> ANSI; other types are raw.
- `KeyValueBasic/Full/PartialInformation` with NT
  `BUFFER_TOO_SMALL`/`BUFFER_OVERFLOW` sizing.
- Granted access is enforced per handle (query/set/DELETE). Handles are
  generation-bound slots (64); stale or foreign handles return
  `STATUS_INVALID_HANDLE`. `NtClose` owns only registry handles.
- Volatile/link/backup options, security descriptors, inheritable handles and
  key classes return `STATUS_NOT_SUPPORTED`.
- `RtlFreeUnicodeString` frees only buffers this provider allocated.

Build/check (host only, no VM):

```text
clang -std=c11 -fsanitize=address,undefined -pthread nt_registry.c nt_registry_host_test.c
i686-w64-mingw32-gcc -march=i486 -nostdlib -shared -Wl,--entry,_dll_entry@12 \
  nt_registry.c nt_registry_native.c nt_registry_native.def -lkernel32 -ladvapi32 -lgcc
```

Not yet done: routing chrome_elf's `ntdll.dll` imports to `M98NTREG.DLL`
requires the loader route table to authorize the exact preserved
`chrome_elf.dll` digest (as `api_contract.c` does for `chrome.exe`). No native
Win98 execution or Chromium startup is claimed.
