# OFFNLS: locale-name provider for LibreOffice SAL on Windows 98

LibreOffice 26.8.0.3 `sal/osl/w32/nlsupport.cxx` computes the process locale
and its text encoding with `GetUserDefaultLocaleName`, `GetLocaleInfoEx`
(ISO 639, ISO 3166, `LOCALE_IDEFAULTANSICODEPAGE | LOCALE_RETURN_NUMBER`)
and `ResolveLocaleName`. The Windows 98 SE KERNEL32 export manifest has none
of them, so an unmodified SAL build fails at import binding. The existing
`ntwin32/loader` resolver answers fixed en-US data, rejects the codepage query
and lacks `ResolveLocaleName`; it is a freestanding Chromium loader without
native-DLL access, so this provider is not wired into it.

`office_nls.c` maps BCP-47 `language[-REGION]` names to installed LCIDs using
only the running system's NLS data (`EnumSystemLocalesA(LCID_INSTALLED)`,
`GetLocaleInfoA` ISO codes, user/system default LCIDs). Ties prefer the user
LCID, the system LCID, `SUBLANG_DEFAULT`, then the lowest LCID. Strings are
converted with the locale's ANSI code page (or `CP_ACP` for
`LOCALE_USE_CP_ACP`). `LOCALE_RETURN_NUMBER` is computed by the provider for
an explicit list of decimal LCTYPEs plus hexadecimal `LOCALE_ILANGUAGE`.
Explicit failures: invariant locale `""` (no Win98 LCID) `ERROR_NOT_SUPPORTED`;
script/variant names in exact lookup, unknown names `ERROR_INVALID_PARAMETER`;
genitive names, unsupported number types and unknown LCTYPEs
`ERROR_INVALID_FLAGS`; short buffers `ERROR_INSUFFICIENT_BUFFER`; more than 512
installed locales `ERROR_NOT_ENOUGH_MEMORY`. `ResolveLocaleName` falls back
from `ll-RR` to the same language only.

`OFFNLS.DLL` exports undecorated stdcall `OfnGetUserDefaultLocaleName`,
`OfnGetLocaleInfoEx`, `OfnResolveLocaleName`, `OfnLocaleNameToLCID` and
`OfnLCIDToLocaleName`. The LibreOffice side is
`tools/modern_apps/office_win98_sal_nlsupport.patch` (pinned in
`office_win98_sal_nlsupport_pin.json`): under `LIBO_WIN98=1` the three SAL
calls bind to OFFNLS through the `dlltool -k` import library.

```text
python3 -B ntwin32/office_nls/build.py --out build/office-nls-NEW
```

runs 34 host logic controls (table backend; not Win98 evidence), builds i486
PE32 4.10 `OFFNLS.DLL`, the native probe `OFNLSPRB.EXE` (writes
`C:\VXDLAB\OFNLS.LOG`) and the link control `OFNLSLNK.EXE`, and refuses any
import absent from `benchmarks/win98se-ko-oem-native-exports-v1.json`.
No VM or application is launched. Native Windows 98 execution, a real SAL
build and Writer/Calc editing remain unverified.
