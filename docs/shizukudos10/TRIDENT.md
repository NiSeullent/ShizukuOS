# Trident+WebKit: Shizuku Internet Explorer

Owner: agent W2 (branch `wip/w2-trident`). Evidence and status are in `docs/shizukudos10/reports/W2.md`; this document
describes the design. Where a section says "planned", nothing of it is built yet.

## 1. Architecture

```
 iexplore.exe  (Wine programs/iexplore, rebranded "Shizuku Internet Explorer")
   -> ieframe.dll (Wine: IEFrame window, WebBrowser control CLSID_WebBrowser, DWebBrowserEvents2)
      shdocvw.dll (Wine: forwards to ieframe)
   -> mshtml.dll  (Wine, UNMODIFIED Trident behaviour code: HTMLDocument, IHTMLDocument2/3/..., IHTMLElement,
                   document.all, attachEvent/window.event, currentStyle, document modes, conditional comments,
                   IActiveScript hosting, events, navigation, urlmon binding)
        |  Gecko binding = the nsI* interfaces of dlls/mshtml/nsiface.idl + 21 xul.dll exports
   -> xul.dll     (trident/xul: "fake Gecko", every nsI* method mshtml calls implemented over engine.h)
        |  ShizukuTrident engine API (trident/engine.h, version 1)
   -> engine backend: shzwebkit.dll (W3's WebCore, when published; default)  |  shzlite.dll (trident/engine, fallback)
 urlmon.dll, wininet.dll (HTTP only), jscript.dll, msxml3.dll (XMLHTTP), oleacc.dll: Wine, through wineport
 tridentrt.dll (trident/comrt): COM pieces the Shizuku runtime does not have yet (registry activation, type
                libraries, streams, bind contexts, shlwapi URL functions); interim until ole32/oleaut32/shlwapi have them
```

Why a fake xul instead of editing mshtml: Wine's mshtml reaches Gecko only through widl-generated `nsIFoo_Method`
vtable macros (`nsiface.h`, MS x64 ABI) and 21 functions it looks up in `xul.dll`. Re-implementing that surface keeps the
100k lines of Wine's Trident COM code byte-for-byte upstream (no conflicts on a Wine bump) and confines the
engine-specific code to one adaptor. The adaptor is the only consumer of nsI*; `engine.h` is a plain C handle API that
a WebKit backend can implement too.

## 2. Engine API

`shizukudos/win64/trident/engine.h`. A backend DLL exports `ShzEngineGetInterface(api_version)` returning a
`shzeng_vtbl`. It covers: documents and incremental parsing, `load_string`, document modes, the DOM tree and
mutation, attributes, collections and selectors, form-control state, style/CSSOM and geometry, events (listener
registration, trusted-event delivery, synthetic dispatch), script evaluation (`script_eval`, only for backends with a
JavaScript engine), views (a child window in an HWND, painting into a DC, snapshot to a DIB), ranges, editing and
printing (optional). Selection: `shzwebkit.dll` if it loads and serves the API version, else `shzlite.dll`;
`HKCU\Software\Shizuku\Trident\Engine` or `SHZ_TRIDENT_ENGINE` (`webkit` | `lite`) override.

Scripts: `script_eval` is the engine's evaluation entry. The minimal engine has no JavaScript engine and returns
`E_NOTIMPL` (capability bit `SHZENG_CAP_SCRIPT` clear); the Trident layer then runs scripts the way IE does, through
an IActiveScript engine: Wine's jscript.dll. When W1's JavaScriptCore is available through a backend, that backend
sets `SHZENG_CAP_SCRIPT`.

## 3. Gecko (nsI*) to engine mapping

Planned; filled in as `trident/xul` implements each interface.

## 4. Trident compatibility layer

Planned. Document modes, X-UA-Compatible, conditional comments, `navigator.userAgent`/`appVersion` (Trident token plus
WebKit token), `document.all`, `attachEvent`/`detachEvent`, `window.event`, `currentStyle`, `innerText`, `createPopup`
and `ActiveXObject("Msxml2.XMLHTTP")` come from Wine's mshtml/jscript/msxml3 code; the exact UA string and the mode
table will be recorded here once they run.
