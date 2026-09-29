# NTW32 routing policy: Auto, Own, KernelEx, Native

Status: SOURCE, BUILT and HOST_TESTED only. **No Windows 98 guest ran this
code.** No KernelEx installation was observed. The evidence categories follow
[docs/shizukudos10/BASELINE.md](shizukudos10/BASELINE.md): `SOURCE`, `BUILT`,
`HOST_TESTED` (host models and mocks), `GUEST_RUN`, `HARDWARE`,
`USER_REPORTED` (a report not reproduced here).

| Claim | Category | Where |
| --- | --- | --- |
| Resolver, policy parser, provider order (built-in and configured), stub demotion | SOURCE, BUILT, HOST_TESTED | `ntwin32/routing.c`, `ntwin32/resolve.c`; `ntwin32/tests/routing_test.c` (1,422 checks, gcc and ASan/UBSan) |
| The linked `NTW32.DLL` applies every mode, override, configured order, INI and env path | BUILT, HOST_TESTED | `platform/abi32` executes the real PE32 code with mocked KERNEL32 services at two image bases (907 checks each) |
| Windows 98 SE `KERNEL32.DLL` lacks the SRW/InitOnce/tick/VEH names and exports the 14 imports | SOURCE (name manifest from the OEM ISO) | `benchmarks/win98se-ko-oem-native-exports-v1.json`; names only, not behaviour |
| KernelEx API libraries expose only `get_api_table`; KernelEx routes dynamic lookups by calling module | USER_REPORTED / earlier-session guest notes | `docs/KERNELEX_THREAD_LIFECYCLE.md`, `docs/NLS_EX_PORT.md`, `docs/PUBLIC_KERNELEX_VARIANTS.md` |
| `KERNELEX.DLL`, `KEXBASES.DLL`, `KEXBASEN.DLL` are the module names to probe | requirement-stated; `KEXBASES.DLL` also USER_REPORTED in the docs above | not verified against an installation here |
| Native `CompareStringW` is a stub on Windows 98 | USER_REPORTED (recorded guest observation, not re-run) | `docs/NLS_EX_PORT.md` |
| KernelEx `KERNEL32` stubs (12 names) | SOURCE (lexical triage of the pinned KernelEx tree) | `docs/KERNELEX_STUB_AUDIT.md`, `benchmarks/kernelex-source-body-audit-v1.json` |

## Terms

- **Import**: a request for a named export of `KERNEL32.DLL`, either a
  dynamic `GetProcAddress` call through the routed export or one of the
  seventeen static exports that `ntwin32/prepare.py` rebinds to `NTW32.DLL`.
- **Providers**:
  - `native`: the address the native loader (`KERNEL32!GetProcAddress`)
    returns, when that address is *not* attributed to KernelEx.
  - `own`: the implementation linked into `NTW32.DLL` for that name.
  - `kernelex`: the address the native loader returns when it lies inside a
    detected KernelEx API library image (see *KernelEx detection*).
- **Attribution** happens per lookup: one native lookup is made and its
  result is classified as `native` or `kernelex`. NTW32 never loads a
  library, never calls `get_api_table`, and never uses a fixed address.
- **Known stub**: an entry of `routes.json` `stubs` naming a module, a
  function and the provider whose implementation is known to be a stub.
- **Mode**: `auto` (default), `own`, `kernelex` or `native`, chosen per
  process and overridable per module and per function.
- **Order**: the providers mode `auto` tries, first to last. Built in per
  export by `routes.json`; configurable per process (`[routing] order=`) and
  per function (`[order]`).

## Semantics

For every import of `KERNEL32.DLL` by name (other modules and ordinal
imports reach the native loader unchanged in every mode):

1. **Effective mode** = the `[functions]` override for the name, else the
   `[modules]` override for `KERNEL32.DLL`, else the process `mode`.
2. **Mode `native`**: return the native loader's answer as is, with no
   attribution, no fallback and no diagnostic. A static export whose native
   counterpart exists forwards to it; otherwise the own implementation stays
   bound (this is logged when `log=1`).
3. Otherwise a **provider order** is tried:
   - `auto`: the first of
     1. the `[order]` entry for the name,
     2. the process-wide `[routing] order=`,
     3. the export's `order` in `routes.json`, and for names without an entry
        `default_order` = `native, own, kernelex`.

     Every own export that Windows 98 SE lacks uses that default.
     `GetProcAddress`, `MultiByteToWideChar` and `WideCharToMultiByte`, which
     Windows 98 does export, are `own, native, kernelex` in `routes.json` for
     the reasons recorded there (the router must stay in control of dynamic
     lookups; the UTF-8 exports delegate every other code page to native
     themselves). A configured order replaces these as well; an operator who
     wants them kept own-first while changing the rest adds `[order]` entries
     for them. A configured order may leave out providers; a left-out
     provider is never tried for that name.
   - `own`: `own, native`. KernelEx is never consulted; a native answer
     attributed to KernelEx is rejected.
   - `kernelex`: `kernelex, native, own`.
4. **Stub demotion** (all modes except `native`): a provider listed as a
   known stub for the name is skipped in the first pass and accepted only
   when no other provider answered. Using it is always logged
   (`... -> known-stub provider used as last resort: <provider>`).
5. The first provider that answers wins. A `native` or `kernelex` winner of a
   static export becomes that export's forward target; an `own` winner
   leaves the implementation bound. A winner whose address lies inside the
   `NTW32.DLL` image itself (a loader that answers with this provider's own
   export) is never used as a forward target, because the export would call
   itself without end; the own implementation stays bound and
   `NTW32: static export <name> resolved into NTW32.DLL itself; own
   implementation kept` is reported.
6. **Unresolved**: `GetProcAddress` returns `NULL`, sets
   `ERROR_PROC_NOT_FOUND` (127) and emits
   `NTW32: KERNEL32.DLL!<name> unresolved (mode <m>; native <state>; own
   <state>; kernelex <state>)` through `OutputDebugStringA`, so the failure
   names the module and the function. Static exports cannot be unresolved
   after load: the own implementation stays bound and
   `NTW32: static export <name> keeps the own implementation` follows the
   diagnostic (in mode `native` only with `log=1`).

A successful lookup restores the caller's last-error value even when a
native probe failed first. The dynamic router export (`GetProcAddress`) is
never forwarded; the policy is applied inside it, so a mode `native` lookup
is still a pure passthrough there. The policy is read once at
`DLL_PROCESS_ATTACH` and is immutable afterwards; every lookup is stateless.

Provider order in the resolver is evaluated lazily: in mode `own`, an own
implementation is returned without asking the native loader at all.

## Configuration

`NTW32.INI` is read from the directory of the loaded provider (the path
`GetModuleFileNameA` reports for `NTW32.DLL`; the file name is fixed even if
the DLL was renamed). An absent or unreadable file means defaults. The
environment variable `NTW32_ROUTING`, when set and non-empty, **replaces**
the file; it is meant for tests and uses the same grammar with `|` (as well
as a newline) ending a line.

```ini
; NTW32.INI — ASCII only, at most 4096 bytes, lines at most 127 bytes
[routing]
mode=auto        ; auto | own | kernelex | native (case-insensitive)
log=0            ; 1 traces every routing decision and prints the attach summary
order=native,own,kernelex   ; optional: the Auto order for every name

[modules]
KERNEL32.DLL=own ; per-module mode; only KERNEL32.DLL is routed today

[functions]
GetTickCount64=native   ; per-function mode; names are case-sensitive

[order]
MultiByteToWideChar=own,native   ; per-function Auto order
```

Grammar and limits (all enforced, none undefined):

- Lines are trimmed; empty lines and lines starting with `;` or `#` are
  comments. Section headers are `[routing]`, `[modules]`, `[functions]`,
  `[order]` (case-insensitive). Keys and values are separated by the first
  `=`; no inline comments.
- `[routing]` accepts `mode`, `log` (`0`/`1`) and `order`, each once; a
  second occurrence is reported and ignored even when the first was invalid.
- An order value is one to three distinct provider names (`native`, `own`,
  `kernelex`, case-insensitive) separated by commas, with optional blanks
  around each name. Empty names, repeats, unknown names, mode names such as
  `auto`, and more than three entries are rejected.
- `[modules]` keys match `[A-Za-z0-9_.-]{1,31}` and are stored upper-case;
  `[functions]` and `[order]` keys are C identifiers of at most 63
  characters, exact case. At most 32 `[modules]`, `[functions]` and
  `[order]` entries in total; a duplicate key within a section keeps the
  first entry.
- Configured orders apply only where the effective mode is `auto`; modes
  `own`, `kernelex` and `native` keep their fixed orders.
- Any byte outside printable ASCII, tab, CR and LF rejects the whole text;
  text longer than 4096 bytes is rejected whole; a line longer than 127
  bytes is skipped.
- Every rejected line or value is reported once as
  `NTW32: routing config line <n>: <reason> '<detail>'` (whole-text
  rejections omit the line) and the default for that item stays in place:
  mode `auto`, `log=0`, the `routes.json` order, no override.
- After parsing, entries that are valid but cannot take effect are reported
  as `NTW32: routing config: ...` warnings and left in place: a `[modules]`
  key other than `KERNEL32.DLL`, an `[order]` entry whose name has a
  non-Auto effective mode, and `[routing] order=` when neither the module
  mode nor any `[functions]` entry is `auto`.

With `log=1` the attach summary is
`NTW32: routing mode=<m> source=<default|NTW32.INI|NTW32_ROUTING>
overrides=<n> warnings=<n> kernelex=<not-detected|core-only|active>
order=<routes.json|provider list>` and each
successful route is traced as `NTW32: KERNEL32.DLL!<name> -> <provider>
(mode <m>)`. Warnings, stub use and unresolved imports are reported even
with `log=0`. All messages are bounded to 199 bytes; untrusted names are
truncated and non-printable bytes are shown as `?`.

## KernelEx detection

At attach, `GetModuleHandleA` is asked for the module files `KERNELEX.DLL`
(core), `KEXBASES.DLL` and `KEXBASEN.DLL` (API libraries). A mapped API
library counts when the resolver's native lookup (`GetProcAddress`) finds
its documented `get_api_table` export;
its PE32 headers (`e_lfanew`, `PE\0\0`, i386, PE32 magic, `SizeOfImage`
between 4 KiB and 256 MiB) give the image range used for attribution. State:

- `not-detected`: no API library qualifies and no core is mapped;
- `core-only`: `KERNELEX.DLL` is mapped but no API library qualifies;
- `active`: at least one API library qualifies (with or without a visible
  core; a missing core is logged).

Nothing is loaded and no address is hard-coded. The recorded KernelEx
behaviour this relies on is that a hooked process receives KernelEx code for
routed names through the ordinary loader (`docs/KERNELEX_THREAD_LIFECYCLE.md`
observed the EXE's static and dynamic `CreateThread` target inside
`KEXBASES.DLL`). Limits: if the API libraries are not enumerable by
`GetModuleHandleA` in a process, KernelEx-supplied pointers are
indistinguishable from native ones and count as `native`; mode `own` then
excludes only what can be attributed. `get_api_table` is not decoded, so
names that KernelEx provides only through its table and that the hooked
loader does not answer are not reachable through NTW32.

## `routes.json` schema v2

`ntwin32/routes.json` (schema id `ntwin32wrapper9x.routes.v2`) carries, per
export, the `order` of providers,
whether Windows 98 SE exports the name (`native_win98se`, checked against
the OEM manifest by `ntwin32/tests/test_routes.py`) and a `reason` when an
own-first order is used for a natively exported name. `stubs` lists known
stubs with module, name, provider, category and evidence. The `kernelex`
entries are derived from the audit JSON rows for `KERNEL32.DLL` in the
categories `explicit_unimplemented_macro`, `explicit_stub_body` and
`suspicious_stub_body` (the test enforces equality); the single `native`
entry is the recorded `CompareStringW` observation. Other modules are not
routed, so their audit rows are not carried.

`ntwin32/prepare.py` validates the file (`validate_routes`), exposes
`route_names` for the import rewriter and renders `build/platform/routes.inc`
(`NTW_ROUTE(name, NtwName, NTW_ORDERn(...))`, `NTW_STUB(module, name,
provider)`, `NTW_DEFAULT_ORDER`), which `ntwin32/runtime.c` turns into its
table, export index and forward slots. `platform/build.py` consumes the same
generator, so the list of exports, the order and the stub list have one
source.

## Tests

- `ntwin32/tests/routing_test.c` (`python3 platform/test.py`, gcc `-O2` and
  clang ASan/UBSan): text builder bounds, mode parsing, accepted INI
  grammar and precedence, every rejection message, exact size limits,
  override limit, provider order per mode, stub lookup, PE header reading,
  and the resolution matrix (native present/absent, own present/absent,
  KernelEx present/absent, attribution on/off, every mode, stub demotion,
  overrides through the resolver, legacy resolver without a policy,
  ordinal and foreign-module passthrough, bounded diagnostics), and the
  configured order (provider-list grammar and its bounds, `[routing]
  order=` and `[order]` precedence, fixed modes ignoring it, orders that
  leave out a provider, stub demotion inside a configured order, every
  order rejection message, and the post-parse no-effect warnings).
- `ntwin32/tests/test_routes.py` (same runner): schema v2 consistency with
  `exports.def`, the OEM manifest, the KernelEx audit, the generated include,
  the configuration names in this document, and 24 rejected malformations.
- `platform/tests/resolve_test.c`: the unchanged legacy contract (no policy
  means mode `own`, no diagnostics).
- `platform/abi32/harness.c` (`python3 platform/abi32/build.py`): the actual
  `NTW32.DLL` re-attached with mocked `NTW32.INI` contents, `NTW32_ROUTING`
  values and mocked KernelEx presence: defaults, `own`, `own` with KernelEx,
  `auto` with KernelEx, `kernelex` with and without KernelEx, `core-only`,
  `native` (dynamic passthrough, static forward to native
  `MultiByteToWideChar`, own SRW retained), INI overrides, nine malformed
  lines, oversized and non-ASCII INI, oversized variable, a loader that
  answers with an `NTW32.DLL` export (self-forward guard), a configured
  `kernelex,own,native` order with an `[order]` entry, an order without
  `own` (dynamic unresolved, static export kept), and malformed or
  ineffective order entries. The mock loader
  models the Windows 98 SE KERNEL32 export inventory for the names involved.

## Not verified

- No Windows 98 guest executed this provider or read an `NTW32.INI`.
- No KernelEx installation was probed; the module names, the presence of
  `get_api_table` as a PE export and the attribution of hooked pointers rest
  on the recorded observations cited above and on mocks.
- Forwarding a static export to a KernelEx pointer is exercised only by
  address comparison (the fake API library is data); forwarding to a native
  function is executed against a mock.
- The native stub list contains one entry with recorded evidence; it is not
  a survey of Windows 98 KERNEL32 stubs.
- The provider grew from 22,856 to 39,105 bytes; static-export forwarding
  adds one load-and-test per call.
- Whether a real KernelEx-hooked loader answers `KERNEL32` lookups made by
  `NTW32.DLL` itself (rather than by the application) with KernelEx code
  is not known; attribution depends on it, and so does the usefulness of a
  `kernelex`-first order.
