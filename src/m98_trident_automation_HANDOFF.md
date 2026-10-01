# Genuine MSHTML Automation bridge

This original GPL-2.0-only component binds the peer-owned portable script ABI to
actual `IUnknown`/`IDispatch`/`IDispatchEx` objects. The native fixture creates the
installed Microsoft MSHTML document, hosts its own genuine OLE document view and
loads the explicit adjacent `M98QJS.DLL` runtime. It never replaces the global
JScript registration, installs a COM server, navigates an arbitrary website or
supplies a mock DOM as native evidence. A complete WebKit port is not required.

## Actual implementation

Four UI-thread contexts use process-unique, never recycled context/object
cookies. Canonical `QueryInterface(IID_IUnknown)` identities deduplicate aliases;
table references, output references and runtime proxy retains balance separately.
The first UI thread is established atomically; foreign calls are rejected before
reading UI-owned context slots. COM calls and releases use a reentry guard.

The adapter resolves current member names through `IDispatchEx::GetDispID` with
case-sensitive request, or legacy `GetIDsOfNames` otherwise. It does not cache
dynamic DISPIDs. Arguments are reversed into Automation order. Object/function
assignments select `PROPERTYPUT` or `PROPERTYPUTREF` from actual member metadata
or type information; no setter is retried after failure. This allows VARIANT
event properties to accept functions through their real value setter.
Scalar/string assignments use `PROPERTYPUT`, both with the named
`DISPID_PROPERTYPUT`. Actual HRESULTs, deferred EXCEPINFO,
bounded UTF-16 error descriptions and logical argument indices are retained.
InvokeEx has no argument-error-index output, so that diagnostic is unavailable.

Explicit UTF-16 BSTR conversion preserves embedded NUL and lone surrogates.
EMPTY/NULL/BOOL, signed and unsigned 8/16/32-bit numbers, R4/R8, BSTR and
dispatchable UNKNOWN/DISPATCH results are supported. Unsupported BYREF,
SAFEARRAY, DATE, CY, DECIMAL, ERROR, 64-bit integer and arbitrary COM interfaces
fail explicitly. No locale-sensitive coercion is invented. METHOD output is
returned only after genuine member metadata/type information proves callability
and the property-get result indicates a method rather than a property.
Type-information fallback scans only bounded local FUNCDESC entries; VARDESC
data members and inherited type information are not traversed in this slice.
Objects needing those routes may fail explicitly until their bindings are added.

**This is strict Automation binding.** A missing member is an actual HRESULT
exception. JavaScript website feature detection often expects missing DOM
properties to read as `undefined`; that requires a separately implemented and
tested browser DOM binding policy. These callbacks do not claim that policy,
arbitrary-site compatibility, ES2026 conformance, HTML5 layout or WebAssembly.

Context limits are 128 object identities, 128 owned strings (65536 UTF-16 units
each), 64 callback wrappers, 32 queued invocations, 32 positional arguments and
256-unit non-NUL member identifiers. Every input field is validated according to
the portable ABI. Untracked string pointers are rejected on result cleanup;
callers must not copy an ownership-bearing result or clear a borrowed input.
Pointer reuse cannot identify a caller's illicit stale copy as a separate lease.
Close also frees outstanding owned strings. Results become invalid at close.

## Callbacks and teardown

A real `IDispatchEx` function wrapper retains its native identity while in use.
Getting our own stored wrapper returns its original canonical JS function token.
Function tokens belong to one runtime context until that context closes, as
defined by `m98_trident_script.h`. Native Invoke/InvokeEx copies and queues
arguments; it never enters JavaScript on the COM call stack. The optional first
named `DISPID_THIS` receiver is preserved separately and dispatched through the
runtime's `m98_script_invoke_this`. Named arguments other than that receiver,
construction and synchronous event cancellation/return values are unsupported.
Callback invocations return VT_EMPTY. This initial queued event lane has an
explicit scheduling boundary; it is not complete synchronous DOM event semantics.

Only an explicit pump on the owning UI thread dispatches callbacks. A callback
can make normal document calls; recursive pump/close is rejected. Dispatch
failures consume that invocation once and preserve subsequent queued work.
Partial queue conversion cleans every acquired string/object reference. Nested
enqueue during conversion is rejected. Native AddRef/Release are atomic and may
occur on another thread, but foreign invocation is rejected before context access.

Detach document event bindings, close the adapter, close the script context,
then release the actual document/view. Adapter close invalidates generations,
discards queued callbacks and releases every owned COM reference. MSHTML-held
wrappers can survive close but return disconnected, including after a table slot
is reused. The fixture statically embeds the adapter, so native event-wrapper
vtables cannot outlive a separately unloaded adapter DLL. Integrators must retain
any module containing those vtables until the final wrapper reference is gone.
The reusable x86 object/archive is for static integration, not a registered server.

## Validation and native acceptance

`tools/build_trident_automation.py` builds the actual adapter against original
COM/OS doubles for normal and ASan/UBSan/leak checks, plus the native x86 object,
archive and `M98AUTPR.EXE`. The mock interfaces intentionally cover the exercised
calls, not the native vtable layout; the native compile uses actual MinGW Windows
headers. The PE gate checks original Win98 OEM import names, GUI PE32/4.10,
i486 compilation, relocation/entry/directory properties, 2MiB stack reserve and
512KiB commit. This is a static gate, not proof that original COM APIs work.

The genuine native fixture writes `AUT13.LOG` with CREATE_NEW beside its EXE,
records actual Win98 SE 4.10.2222/ACP949, EXE/runtime/MSHTML paths and all COM
results. It loads only the absolute EXE-adjacent runtime and verifies the returned
module path. The frozen harness must bind that actual DLL's bytes separately;
the module path is not a cryptographic measurement.

The fixture evaluates modern syntax and real Promise jobs against the genuine
document, then independently queries typed `IHTMLDocument3`/`IHTMLElement` for
the resulting Korean text. The tester must click the actual MSHTML input and
type keys. No key/event synthesis exists in the fixture. It requires both an
observed UI-thread key-up message and queued normal-function callback using its
real native `this.value`, followed by an independent typed IHTMLInputElement
value read. Empty input remains pending; the complete status BSTR must equal
the Korean prefix plus that exact nonempty input value. These
observations do not by themselves prove physical/QEMU GUI input; that requires
an independently reviewed input receipt. It keeps
the final view visible ten seconds for a separately trusted screenshot review.
Input is bounded to 180 seconds. View/runtime/document/site teardown must succeed.
It flushes and closes its fresh log, then exits zero only after all criteria.

A host test PASS or cross-build is not a native PASS. Acceptance requires a
frozen runtime/fixture/source manifest, a fresh complete native log, independently
observed child exit zero, reviewed exact painted screenshots, real input evidence
and full teardown. **No native trial has been performed by this implementation.**
IE-driven script selection, page script ordering, navigation, origins, network,
TLS, HTML5/CSS parsing/layout, WASM and Legcord/Signal/Office operation remain
separate unverified goals. Peer 733e host and 83bd native engine sources/guests
were preserved; no service, VM, registration or download was performed.

## Provenance and contracts

Adapter, fixture, doubles and builder are original GPL-2.0-only work under this
repository's license. The consumed portable script header is peer-owned original
GPL-2.0-only. QuickJS and its own notices are managed by that peer's pinned source
port and are not copied into this adapter. Microsoft proprietary Trident source
is absent. MinGW-w64 supplies build-time interface declarations under its supplied
notices; the binary does not redistribute Windows/MSHTML binaries.

Primary contracts used:
[canonical COM identity](https://learn.microsoft.com/en-us/windows/win32/com/rules-for-implementing-queryinterface),
[argument order/property puts](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/automat/accessing-members-through-idispatch),
[dynamic member resolution](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/windows-scripting/reference/idispatchex-getdispid),
and [InvokeEx/THIS receiver](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/windows-scripting/reference/idispatchex-invokeex).
