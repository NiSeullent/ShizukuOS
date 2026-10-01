# Trident modernization handoff — 2026-10-01

The user requires extending Trident toward modern HTML5, WebAssembly and 2026
JavaScript/web standards. A complete WebKit port is **not** a prerequisite.
Themes, current Legcord/Discord, Signal, open-source Office and OS TLS 1.3 remain
separate application/OS acceptance goals. This audit inspected source and saved
evidence only: no repository script, download, registration or VM operation.

The exact installed target is Windows 98 SE 4.10.2222, x86, classic mode,
Microsoft IE 5.00.2614.3500. Microsoft MSHTML/Trident implementation source is
not present in the inspected trees. Wine's MSHTML compatibility implementation
is a different project; its name does not establish Microsoft Trident internals.

## Available code and measured limits

| Area | Current inspected implementation/evidence | Next real behavior and native criterion |
| --- | --- | --- |
| Microsoft IE hosting | Independent `/home/almalinux/workspace/iewebkit` supplies COM DocObject, BHO, URLMon and request ownership code. Its normal provider is absent. | Keep actual MSHTML as document/layout owner for the Trident extension lane; execute a modern script that visibly changes the same genuine document. |
| Win98 browser ingress | Boot integration 83bd measured a real IE GET/URLMon handoff, but full page activation failed at `engine_missing`, exit 29. | Exact method/body/headers, committed URL, redirects, history, activation and teardown must complete in IE. Sending navigation is insufficient. |
| Original small renderer | `renderer/subset.cpp` has bounded UTF-8 parsing, simple tag/class/id selectors, cascade and GDI text/block painting. ME/IE5.5 local subset display passed; Win98 is separate. | No persistent DOM, scripts, forms, flex/grid or full HTML5 parser exists. Reusing its paint code requires implementing and testing real missing semantics; do not present it as Trident or HTML5 conformance. |
| Modern JavaScript | Pinned JSC source and Win9x port work exist externally; C_LOOP profile disables WASM. No inspected receipt certifies JavaScript execution in the installed Win98 MSHTML document. | Add a modern runtime/Active-Scripting bridge to the real document; pin language tests and publish failures, including host bindings and Promise job ordering. |
| Native JSC foundation | The newest saved 83bd trial `win98-iosys-gop-wtf-v5-83bd-20261001l` observes `WTFNAT.EXE` abnormal termination, with both stopped logs empty. WTF initialization and post-CRT child exit remain unverified. | If reusing JSC, resolve the peer-owned allocator/CRT lifecycle failure and obtain fresh startup/worker/timer/actual-exit evidence before claiming a usable runtime. |
| Shizuku Win64 “Trident” | `shizukudos/win64/trident/engine.h` defines a broad C DOM/style/event/script/view API. `build.py` references absent `engine/build_engine.py` and `xul/build_xul.py`; W2 records engine/mapping work not started. | This is a planned Wine-MSHTML/Gecko-adapter seam, not a working Trident engine. PE32+/Kernel64 modules do not load directly into the x86 Win98 IE process. |
| WASM and transport | No browser WASM runtime or JS bindings were found in these inspected modules. TLS component progress does not connect MSHTML navigation automatically. | Execute validated modules through actual `WebAssembly` bindings, then connect origin-bound fetch/subresources and verified TLS; preserve real certificate, origin and request checks. |

The independent `variants.json` declares IE5.5/ME and later variants, with empty
certifications; it has no Win98/IE5.0 profile. Its selector source explicitly
rejects a missing exact combination. This audit read the selector rather than
executing it. The boot builder's Win98/IE5.0 target is explicitly experimental;
an ME, IE6, Win64 or host result cannot certify it.

The independent provider ABI currently requires the specifically named
`IEWK_JAVASCRIPTCORE` capability as part of `IEWK_REQUIRED_CAPS=63`. A QuickJS
adapter must not set that bit to impersonate JSC. The proposed Active-Scripting
lane is separate; a future general-runtime provider would need a reviewed ABI
and capability-policy change by its owner.

## Concrete public extension seams

Active Scripting separates the language engine from its host. An engine can
implement `IActiveScript`/`IActiveScriptParse`, receive script text and resolve
host objects through its site. Microsoft documents `ParseScriptText` specifically
for HTML script evaluation, including state-dependent execution and exceptions.
This supports a modern language-engine adapter proposal; it does not prove our
IE5 build will select or safely host that adapter. See [Microsoft Active
Scripting architecture](https://learn.microsoft.com/en-us/archive/msdn-magazine/2000/june/visual-programmer-add-scripting-to-your-apps-with-microsoft-scriptcontrol)
and [ParseScriptText](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/windows-scripting/reference/iactivescriptparse-parsescripttext).

The browser's [language property](https://learn.microsoft.com/en-us/previous-versions/hh774286(v=vs.85))
and [IDispatchEx member resolution](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/windows-scripting/reference/idispatchex-getdispid)
provide candidate script selection and real Automation object binding seams.
[GetExternal](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/aa753256(v=vs.85))
exposes a host Automation object; it does not replace MSHTML's HTML/CSS parser,
layout or JavaScript engine. Likewise, the existing DocObject swaps a document
provider; calling it “Trident modification” would misdescribe that path.

URLMon [RegisterNameSpace](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/aa767759(v=vs.85))
is a transport seam, with replacement rather than automatic handler chaining.
Preserve original transport ownership, redirects and POST/header semantics;
the current bounded GET diagnostic is not a complete networking implementation.

## Smallest meaningful next implementation

Start a disjoint **x86 modern-script/real-MSHTML DOM bridge**, rather than a full
WebCore port. Proposed new files in this worktree are
`src/m98_trident_script.[ch]`, `src/m98_trident_active_script.cpp`,
`tests/m98_trident_script_host.c`, and `tests/m98_trident_script_guest.cpp`.
They are proposals, not files implemented by this audit. Leave the peer-owned
DocObject, navigation, allocator and provider ABI unchanged.

Use a pinned real interpreter. QuickJS is a small candidate with preliminary
MinGW support; its current upstream documentation describes most ES2025 support,
missing ECMA-402, tail calls and `Atomics.waitAsync`. It was not found, fetched,
built or tested here, and is not automatically an ES2026 or Win98 pass.
Alternatively reuse the existing JSC source once its native foundation passes.
Neither option requires all WebKit. See the [QuickJS manual](https://bellard.org/quickjs/quickjs.html).

Implement actual BSTR/UTF-16 and VARIANT conversions, COM identity/refcounts,
property/method calls against the genuine MSHTML document, script states,
exception reporting, bounded execution and a UI-thread Promise job queue.
First use a native test host with an actual MSHTML document and direct local
engine factory, avoiding global JScript replacement. Then separately verify
MSHTML-driven custom-language selection in the disposable IE target: a direct
test-host evaluation alone is not that browser integration pass. Default
`javascript` interception and ordinary-site script ordering are later explicit
integration gates.

The first native fixture must run modern syntax and Promise callbacks, call
real document element creation/mutation, display the resulting Korean text in
the same MSHTML view, handle a real input event, and release the document/runtime
on navigation. Require genuine HRESULT/COM results, exception and interruption
negative cases, rejected unsupported types, two-document isolation, no callbacks
after teardown, frozen source/binary hashes, fresh logs and observed child exit.
Do not substitute a painted mock DOM or a user-agent change for those results.
Audit the linked x86 PE and all dependencies against the exact installed Win98
exports first, then measure callable API behavior. COM apartment, native stack
bounds, script procedure/event interfaces and DLL unload require their own
actual-target checks; a MinGW cross-build does not establish them.

This first slice does not add HTML5 parsing, flex/grid or WASM. Public host
interfaces do not supply an arbitrary CSS/layout replacement hook. Deeper layout
work needs a separately evidenced engine seam or implementation; the open Wine
compatibility route is possible but has its own Gecko/backend and runtime gaps.
For WASM, implement a real validator/interpreter and JS Module/Instance/Memory,
imports/exports, traps and lifetime behavior. A WASI executable or a namespace
stub is insufficient under the [WebAssembly JS API](https://webassembly.github.io/spec/js-api/index.html).
Pin 2026 language requirements to the [ECMAScript 2026 specification](https://tc39.es/ecma262/2026/multipage/)
and a fixed [Test262](https://github.com/tc39/test262) revision; DOM/layout/network
conformance and actual Legcord/Signal/Office workflows remain additional gates.

## Ownership and provenance

The independent checkout is at commit
`dd93262508ecec2969d3267b9d6d831d66fcd489`, with existing dirty host and porting
changes. Its `.agents/coordination/01a0f1c7-733e.json` assigns host lifecycle and
port recovery to session 733e; that note is dated 2026-09-30 and is an ownership
record, not a live-process assertion. Boot `docs/IEWEBKIT_INTEGRATION.md` assigns
exact-target integration to 83bd. Neither owner's sources or guests were changed.
The user direction is also recorded in boot's `modern-apps-coordination-7707.md`.

Read-only source pins at this checkpoint:

| Independent checkout file | SHA-256 |
| --- | --- |
| `variants.json` | `9f5642b2eaf0d61f264c2f8fdddd7152df054812300de73cfb34897bda310855` |
| `include/engine.h` | `d80a8b1d2bced21b9c30fbfe6577b66e3e71719ded719e85e946c38fbee853e2` |
| `host/docobject.cpp` | `59ea59ffb4977a7560f39747cc440f04a69436c9b455870182106d67f1ecfccd` |
| `host/request_capture.cpp` | `91f5cdaffb7a6ba2d6dd99cebb3d36a2a65e1654b23df0ce615c16201de80029` |
| `renderer/subset.cpp` | `c0234ba6870f41f7d1496b30195b56425d8b76aed95f215d8098bbac61844d45` |

Latest native WTF classification receipt SHA-256:
`445937b5674c6e019794adcc876e47488b797eeb43b5fb0d4f0f2cf1b883eec3`;
its harness result SHA-256 is
`fd9c97a79b9f51962f19933fe057ad28b4abacac37f424d7911747ffe8b0e5f6`.
Only this new handoff document was written for the audit.
