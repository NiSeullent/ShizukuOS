# Genuine MSHTML CSS variable consumer fixture

This fixture uses the real installed Microsoft MSHTML document/view and the
frozen `M98CSS.DLL`. It reads explicit custom-property and width-use values
from actual DOM fixture attributes, computes parent/child snapshots and resolves
`var()` through the actual DLL. These attributes carry a known already-cascaded
fixture map; there is no general selector/stylesheet/cascade implementation.

An original bounded property consumer accepts integer pixel lengths (0..1024)
and three/six-digit sRGB hash colors. It rejects unsupported valid modern forms
explicitly and does not reinterpret decoded token adjacency as a string value.
The consumer calls the owning DLL's actual token accessors. All root-owned
helpers use unchanged output-on-error contracts and are tested with the real
tokenizer normally and with ASan/UBSan/leak detection.

The native GUI requires Windows98SE4.10.2222, ACP949, exact adjacent component
path/all18exports, and genuine system MSHTML5.00.2614.3500 file-version data.
It initially shows two32px gray boxes, then sets genuine styles using resolved
values:168px width with blue parent and green child. Child width inherits its
parent's computed value. The child is a genuine DOM descendant; an independent
`parentElement` query must match the parent's canonical IUnknown identity before
the snapshot is supplied. The parent snapshot is released before child use.
Actual `IHTMLStyle.pixelWidth` and independent `IHTMLElement.offsetWidth` must
both match before and after mutation. A genuine UTF16 Korean text setter and
the original document/view cleanup paths are exercised.

The first actual offline Windows98SE/MSHTML5.00.2614.3500 trial,
`/root/Win98-Modern-boot/build/shizukudos/csm/run-win98-gop-css-mshtml-5abe-native-v1`,
failed the initial geometry check: both actual style pixel widths were32, but
parent/child offset widths were46/36. Gray background values were real VT_BSTR
and passed. The owned child PID4294888941 exited with the full DWORD value1;
its stdout was flushed and handles closed. Requested supervisor exit15 is a
separate observation and does not prove actual supervisor exit. Cleanup released
the client-site references, component and all core allocations. This failure did
not reach the modified geometry or Korean-text phases.

Both original boxes already specified zero border, margin and padding. The
unbreakable `Parent`/`Child` labels under16px Arial are a source-grounded possible
cause of the old layout engine's enlarged minimum width; that explanation remains
an inference pending a fresh guest trial. The corrected fixture uses single-glyph
`P`/`C` labels inside the same genuinely nested boxes, with their explanation
outside. The geometry oracles remain32px initially and168px after mutation for
both independent pixelWidth and offsetWidth queries. Typed gray/blue/green color
checks, complete Korean UTF16 setter/readback, parent identity, snapshot lifetime,
timers and cleanup are unchanged. The original frozen fixture-v8, stage-v2 and
failed guest logs remain preserved; a fresh build is not native confirmation.

Original `data-var-*`/`data-use-*` fixture attributes do not imply stock Trident
parses arbitrary modern CSS. Color setters alone do not prove painted colors;
width/style/geometry logs alone do not prove pixels. The visible10second initial
and12second modified phases require fresh independently reviewed frames. The
fixture rejects early window closure, guards against nested STA timer pumping,
and independently reads back the full Korean text. Each phase clock starts after
its verified state and synchronous paint request; that request itself is not
independent pixel evidence. It has a45second bound and
writes a fresh `CSS13.LOG`, but native acceptance
also needs an independently observed actual child exit/flush/close and the
canonical cold/noNIC/oneQA guest harness. A cross-build cannot supply that proof.

`tools/build_css_mshtml_fixture.py` requires a caller-approved core receipt SHA,
validates its complete current/frozen source and build/artifact closure, and
uses a fresh owned build directory. It builds the original property consumer
checks and GUI, and validates the latter's actual full i486 instruction stream,
PE32/GUI OS4.10, original OEM imports, no CRT/exports/modern loader directories,
relocations and2MiB/512KiB stack profile. It preserves failures and snapshots.
Both actual DLL and EXE receive a fail-closed per-line raw instruction scan,
with exact byte/address coverage of every declared executable section, explicit
i486/x87 opcode checks including prefixes, and real assembled modern-opcode
rejection controls. This supplements the core's historical scanner.
No VM, registration, network, installation or global configuration is changed.

Full CSS, modern layout, browser WPT, JavaScript/browserWASM/WebGPU/WebGL and
application functionality remain mandatory unfinished targets. Native load,
styles/geometry, visible paint and child completion remain unverified until a
fresh accepted installed-Windows trial provides its own evidence.
