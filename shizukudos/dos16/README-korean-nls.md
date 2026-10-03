# Korean Windows DOS locale prerequisite

The installed Korean WIN.COM requests INT21 AX=6602 with BX=DX=949 when
AX=6601 returns a different active code page. An original DOS control reports
active/system 949 and country 82; the earlier ShizukuDOS kernel reports 437/1.
Replaying BILING.SYS alone does not change those DOS replies.

Patch 0005 keeps the resident CP437 package and adds a separate country82/CP949
package with its own byte tables, DBCS lead-byte ranges, and country record.
Independent original-DOS observations validate year-month-day dates, whole-won
currency amounts and 24-hour time; the kernel callback pointer is its own.
Explicit COUNTRY=82,949 without a filename selects the resident package in
CONFIG pass1 through the existing init-to-resident INT21 bridge, before device
loading in pass2. A supplied COUNTRY.SYS filename keeps the ordinary loader.
The explicit supported BX=DX selection activates the corresponding resident
package and system code page. Unsupported pages fail without changing state.
Uppercase operations preserve a DBCS lead/trail pair, including an ASCII-looking
trail byte, and preserve a truncated final lead byte.

The tables are source-written; no Microsoft COUNTRY.SYS, IO.SYS or BILING.SYS
bytes are included. Primary references are Microsoft's [code page identifiers](https://learn.microsoft.com/en-us/windows/win32/intl/code-page-identifiers),
the Unicode Consortium's [Microsoft CP949 mapping](https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP949.TXT),
and the pinned [FreeDOS NLS implementation](https://github.com/FDOS/kernel/blob/ke2046/kernel/nls.c).
The mapping identifies lead bytes 81–FE and single-byte ASCII; the patch does
not embed the mapping text or claim Unicode conversion support.

The profile request can explicitly select `initial_locale={"country":82,"codepage":949}`.
Its default is absent; the receipt labels it as unverified explicit configuration,
not an observed query or execution authority. An existing observed COUNTRY command
cannot be silently overridden.

The source-profile producer separately preserves a source-observed BILING
DEVICE/DEVICEHIGH invocation only when its exact rooted Windows path and actual
installed member are admitted. Other driver/startup commands remain backups.
This preparation does not prove that the Microsoft driver accepted DOS internals.

Build with the normal DOS16 builder, then run:

```
python3 -m unittest discover -s shizukudos/dos16/tests -p test_korean_nls.py
python3 -m unittest discover -s shizukudos/install/tests -p test_win98_source_profile_fada.py
```

An isolated build may select its patched source via SHIZUKUDOS_NLS_SOURCE.
The tests assemble the actual NLS package and execute actual patched C functions
with a host dependency harness and Clang address/undefined-behavior sanitizers.
They are component checks. A real Windows desktop on ShizukuDOS, BIOS/UEFI,
GOP and native x64 application execution require separate guest evidence.
Existing character-driver notification on runtime code-page changes still needs
its own compatibility validation; the package does not claim console-font setup.
