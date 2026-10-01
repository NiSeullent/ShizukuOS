# ShizukuTrident Lite — engine design

`shzlite.dll` is the minimal HTML/CSS engine behind the Trident layer (`trident/engine.h`, API version 1). The WebBrowser
control, `iexplore.exe` and Wine's mshtml DOM layer run on it through `trident/xul` when the WebKit backend is absent.
This document fixes the internal architecture so that three agents can work on it in parallel:

| agent | scope |
|---|---|
| **core** (this phase) | architecture, all internal headers, HTML tokenizer + tree builder + charsets, DOM, selectors, serializer, ranges, URL, fetch plumbing, the engine.h glue, build + test scripts |
| **L1** | CSS (parser, sheets, CSSOM), cascade and computed style, layout, display list, GDI painting, fonts, geometry entries |
| **L2** | images (PNG/GIF/BMP), events and dispatch, the view window, forms (state, editing, submission), load lifecycle glue |

Everything that is "declared by core, owned by L1/L2" below already compiles: the glue calls it, weak stubs answer
`E_NOTIMPL` (section 11) until the owner implements it.

## 1. Architecture

```
 engine.h vtbl  ──  win/glue.c  (WCHAR/HRESULT/RECT <-> core types; handles ARE core structs)
                      │
   ┌──────────────────┼───────────────────────────────────────────────────────────────┐
   │ portable core (core/*.c, C99, no windows.h; host-testable with gcc + ASan/UBSan)   │
   │  base / names / url / charset / entities                                          │
   │  html_tokenizer + html_tree + html_parser  ──>  dom (+ dom_attr, dom_list,         │
   │  dom_text, range)  ──>  observe.h fan-out:  L1 shz_render_dom_changed             │
   │                                              L2 shz_interact_dom_changed          │
   │  selectors, serialize, fetch, font (interface + fixed 8x16 model)                 │
   │  L1: css*, style*, layout*, display_list          L2: events, forms, image*, loader │
   └──────────────────┬───────────────────────────────────────────────────────────────┘
                      │ platform.h (alloc, file read, time, trace)
   Windows layer (win/*.c, mingw -Werror):  main.c (DllMain, ShzEngineGetInterface), platform_win.c, crt_min.c,
   glue.c;  L1: paint_gdi.c, font_gdi.c [, font_dwrite.c];  L2: view.c
```

* The **handle types of engine.h are the core structures**: `struct shzeng_doc`, `shzeng_node`, `shzeng_list`
  (core/dom.h), `shzeng_range` (core/range.h), `shzeng_event` (core/events.h, L2), `shzeng_style`/`shzeng_sheet`
  (defined privately by L1), `shzeng_view` (defined privately by L2). Core code uses the typedefs `shz_doc`,
  `shz_node`, `shz_list`, `shz_event`, `shz_style`, `shz_sheet`, `shz_range`. No casts, no wrapper objects, so
  identity (`==`) is free.
* Text is UTF-16 everywhere (`shz_char` = `uint16_t`, same representation as `WCHAR`).
* Results are `shz_res`, numerically the engine.h HRESULTs; DOM exceptions use Gecko's `NS_ERROR_DOM_*` values
  (`SHZ_E_HIERARCHY` 0x80530003, `SHZ_E_NOT_FOUND` 0x80530008, `SHZ_E_SYNTAX` 0x8053000C, ...) so trident/xul can hand
  them to mshtml unchanged.
* Host callbacks: the glue adapts `shzeng_host` to `shz_doc_hooks` (core/dom.h, same members in core types). Host
  tests implement `shz_doc_hooks` directly.

## 2. Source tree and ownership

| file | owner | contents |
|---|---|---|
| `DESIGN.md`, `build_engine.py` | core | this document; the DLL build (section 3) |
| `core/base.h/.c` | core | results, memory prototypes, UTF-16 strings, `shz_buf`/`shz_bytes`/`shz_vec`, numbers, `shz_irect` |
| `core/platform.h` | core | what the platform provides (alloc, time, file read, trace) |
| `core/names.h/.c` | core | known tag / attribute names (`SHZ_TAG_*`, `SHZ_ATTR_*`, per-tag flags) |
| `core/dom.h`, `dom.c`, `dom_attr.c`, `dom_list.c`, `dom_text.c` | core | documents, nodes, lifetime, mutation, attributes + Attr nodes, live lists/collections, textContent/innerText, character data |
| `core/observe.h` | core | the change notifications to L1/L2 (section 5) |
| `core/range.h/.c` | core | ranges + selection, live boundary updates |
| `core/url.h/.c` | core | RFC 3986 resolution (+ WHATWG backslash rule), file: URL -> path |
| `core/charset.h/.c`, `core/entities.h/.c` | core | encodings (labels, BOM, prescan, decoders), named character references |
| `core/html_parser.h`, `html_int.h`, `html_parser.c`, `html_tokenizer.c`, `html_tree.c` | core | the HTML parser (section 8) |
| `core/selectors.h/.c` | core | selector parsing, specificity, matching, querySelector |
| `core/serialize.h/.c` | core | innerHTML/outerHTML (HTML) and XML serialization |
| `core/fetch.h/.c` | core | sub-resource fetch plumbing shared by L1 (sheets) and L2 (images) |
| `core/font.h` | **L1** (declared by core) | font-metrics interface (section 7) |
| `core/font_fixed.c` | core → L1 | the fixed 8x16 model of Shizuku gdi32 (host tests) |
| `core/css.h`, `core/style.h`, `core/layout.h`, `core/display_list.h` | **L1** (declared by core) | CSS/CSSOM, cascade, layout + geometry, display list |
| `core/events.h`, `core/forms.h`, `core/image.h`, `core/loader.h` | **L2** (declared by core) | events, forms, images, load lifecycle |
| `core/stubs_l1.c`, `win/stubs_l1_win.c` | **L1** deletes | temporary stubs of the L1 API |
| `core/stubs_l2.c`, `win/stubs_l2_win.c` | **L2** deletes | temporary stubs of the L2 API |
| `core/lodepng_glue.c` | core | allocator hooks for the vendored LodePNG (the PNG glue itself is L2's) |
| `win/winglue.h`, `glue.c`, `main.c`, `platform_win.c`, `crt_min.c` | core | engine.h glue, DLL entry + export, platform layer, memcpy & co |
| `win/paint.h` | **L1** (declared by core) | display list -> GDI, snapshot, GDI font backend |
| `win/view.h` | **L2** (declared by core) | the view window |
| `tests/run_host_tests.py`, `host_test.h`, `platform_host.c` | core | host test runner and helpers (L1/L2 add `tests/t_*.c`) |
| `tests/t_tree.c t_dom.c t_selectors.c t_serialize.c t_charset.c t_script.c t_url.c t_fetch.c t_fuzz.c t_fuzz_dom.c` | core | host tests of the core (the two fuzzers take `SHZ_FUZZ_ITER` / `SHZ_FUZZ_SEED` for longer local runs) |
| `tests/run_guest.py` | core | builds DLL + T_TRIDENT_ENGINE.EXE, adds them to a copy of WIN64.IMG, boots QEMU |
| `../../tests/t_trident_engine.c` | core, with **L1** / **L2** marker sections | the guest test (section 10) |
| `../../tests/data/TRIDENT_E*.*` | core (`E1`), **L1** (`TRIDENT_L1*`), **L2** (`TRIDENT_L2*`) | guest test pages and images |

Header rule after this phase: the owner of a header may add declarations and fields freely; changing or removing a
declaration that another module or `win/glue.c` uses is allowed only together with its callers, in the same change.
L1/L2 may edit the `glue.c` functions that forward to their own APIs; the rest of `glue.c` stays core's.

## 3. Build, memory and CRT

* `build_engine.py build(out_dir)` compiles `core/*.c` (`-std=c99`), `win/*.c` (`-std=gnu99`, `-DUNICODE`; NOT
  `WIN32_LEAN_AND_MEAN`: engine.h needs `VARIANT`) and `src/vendor/lodepng/lodepng.c` (zlib licence; built with
  `LODEPNG_NO_COMPILE_{ALLOCATORS,DISK,CPP,ENCODER,ERROR_TEXT}`) with `x86_64-w64-mingw32-gcc -O2 -Wall -Wextra
  -Werror -ffreestanding -fno-builtin -fno-stack-protector -fno-tree-loop-distribute-patterns -fno-strict-aliasing`,
  links `-shared -nostdlib -Wl,--entry,DllMain` at image base 0x7ffa80000000 (dynamic base) against
  `build/shizukudos/win64/lib{kernel32,user32,gdi32}.a` and `-lgcc`, exports `ShzEngineGetInterface` via a .def and
  makes `libshzlite.a` with dlltool. It returns `{"dll", "implib", "def", "exports", "objects", "imports",
  "stubs_overridden", "command"}`. `python3 build_engine.py --out DIR` does the same from the command line.
* **Memory/CRT: option (a), the process heap + own helpers.** `shz_alloc` (zero-filled) / `shz_realloc` / `shz_free`
  are `HeapAlloc`/`HeapReAlloc`/`HeapFree` on `GetProcessHeap()` (win/platform_win.c); `memcpy`/`memmove`/
  `memset`/`memcmp` come from win/crt_min.c; string, number and math helpers are in core/base.c. Reasons: (1) the
  same core source runs on the Linux host where the platform file maps to libc, so the core never depends on any CRT;
  (2) shzlite.dll then imports only kernel32/user32/gdi32 — nothing to initialize, `DllMain` is the entry, and it
  loads into any process (mshtml's, a test's) whatever CRT that process uses; (3) Shizuku ucrtbase (b) would add a
  dependency and CRT initialization for the dozen functions we need; wineport's static CRT (c) is built for Wine
  modules (its own headers/ABI conventions) and would pull musl into a Shizuku-original DLL. Strings handed to the
  engine.h caller are `shz_alloc`ed and freed by `str_free`/`bytes_free` (= `shz_free`), so both sides use one heap.
* Floating point is used in layout (float CSS px); no libm: `shz_floor/ceil/round` in base.c.

## 4. Data structures and lifetime

### Nodes (`core/dom.h`)

`struct shzeng_node` is the common header: `refs`, `type` (DOM value), `flags` (`SHZ_NF_IN_DOC` = connected,
`PARSER_INSERTED`/`STARTED` for scripts, ...), `doc`, the five tree links, `host_data` (engine.h
`node_set_host_data`, Wine's Get/SetMshtmlNode), `box` (L1) and `listeners` (L2). Subtypes embed it first:
`shz_element` (tag id, namespace, qualified/local name, attribute array, and the module pointers `style` (L1), `ctl`
and `img` (L2)), `shz_chardata` (text, comment, CDATA, PI), `shz_doctype`, `shz_attrnode`. The Document node is a
plain `shz_node` owned by its `shz_doc`.

**Lifetime rules**

1. `node->refs` counts every holder except the tree: engine.h handles, static lists, events, the parser's open-element
   stack, an Attr node's reference on its owner, interaction state (`doc->focus/hover/active`), ranges.
2. A node is alive while `refs > 0` **or** it has a parent. When the last reference of a parentless node is dropped
   the node is freed with every descendant that has no reference; a referenced descendant survives as the root of its
   own detached tree (iterative, deep trees are fine). Removing a node from its parent never frees it while the
   caller holds a reference (all DOM entry points take a temporary reference).
3. The document: `doc->refs` counts engine.h document handles plus holders that need it open (fetches in flight,
   views). When it reaches 0 the document is **closed**: the parser is destroyed, the selection released, and modules
   get `SHZ_CHG_DOC_CLOSED` to drop their node references. The memory (and the whole tree) is freed once the
   document is closed **and** `doc->pinned == 0` (number of its nodes with `refs > 0`). So any referenced node keeps
   its document alive and `node_doc()` never dangles; nodes moved to another document move their pin (adoption).
4. Identity is the pointer: the DOM never re-creates a node behind the host's back (the parser's formatting
   reconstruction creates new elements, as HTML specifies, but never replaces an existing node object).
5. Attr nodes (`elem_attr_node`): one per attribute while it exists (identity), holding a reference on the owner
   element; when the attribute is removed the Attr node keeps a copy of the last value and releases the owner.

### Lists (`struct shzeng_list`)

Kinds: static (querySelectorAll; references its nodes), children (childNodes), by tag / tag+ns / class / name, and
document collections (`SHZ_COLL_*`: all, forms, images, links = a/area with href, anchors = a with name, scripts,
applets = applet/object, embeds). Live lists cache their items and rebuild when `(root->doc, doc->version)` changed;
`doc->version` is bumped by every tree mutation, attribute change and `doc_set_mode` (quirks changes class matching).

### Other handles

* Ranges (`core/range.h`): reference their boundary nodes (not the document); dom.c reports removals, insertions,
  character-data changes and splitText so boundaries follow the DOM Standard's live-range rules.
* Events (`core/events.h`, L2): reference their target and `related` node; the host gets them in `event()` and may
  keep them with `event_addref`.
* Styles/sheets (L1): an inline style references its element; a computed style is a snapshot; a rule style keeps its
  sheet alive.
* Fetches (`core/fetch.h`): reference the document until `done` (the sink contract says it always comes).
* Views (L2): reference their document.

### Document (`struct shzeng_doc`)

URL, content type, charset, `is_html`, `mode` + `mode_set` (engine.h `doc_set_mode`) and `doctype_quirks` (from the
parser), `hooks`/`hooks_ctx` + `platform` (glue data), `parser`, `ready_state`, `fetch_pending`, `selection` +
`live_ranges`, interaction state (`focus`, `hover`, `active` — written by L2, read by selectors and L1), the viewport
(`viewport_w/h`, `scroll_x/y`, `zoom` — written by the view/snapshot, read by layout) and one private pointer per
module: `css`, `layout` (L1), `events`, `forms`, `images`, `load`, `views` (L2).

## 5. Change notifications (`core/observe.h`)

The DOM calls exactly two dispatchers, `shz_render_dom_changed` (L1, in its style.c) and `shz_interact_dom_changed`
(L2, in its events.c), with a `shz_chg_info`:

| what | when | node / other |
|---|---|---|
| `SHZ_CHG_INSERTED` | a node became connected (once per node, tree order; parser insertions too) | node |
| `SHZ_CHG_REMOVED` | a subtree root was disconnected (after unlinking) | node, other = old parent |
| `SHZ_CHG_CHILDREN` | a child list changed (any tree) | node = parent |
| `SHZ_CHG_ATTR` | an attribute was set/changed/removed (any tree) | node, attr_name, attr_id |
| `SHZ_CHG_TEXT` | character data changed (any tree) | node |
| `SHZ_CHG_ADOPTED` | a detached subtree moved to another document | node, old_doc |
| `SHZ_CHG_CLONED` | node was cloned | node, other = clone (copy form state, ...) |
| `SHZ_CHG_DESTROYED` | node is being freed: free `node->box`, `listeners`, `elem->style/ctl/img` | node |
| `SHZ_CHG_DOC_CLOSED` / `DOC_DESTROYED` | see section 4 | — |
| `SHZ_CHG_DOC_RESET` | the document was emptied for a new load / document.open | — |
| `SHZ_CHG_MODE` | doc_set_mode changed the mode | — |

Order for one mutation: tree update, `doc->version++`, then per affected node: L1 dispatcher, L2 dispatcher, host
callback (`node_inserted` / `node_removed`, per node in tree order). The host may mutate the tree from its callback
(mshtml replaces conditional comments there); the DOM re-checks connectedness before each notification. DOM
insertion of a connected `<script>` that is not "already started" (and has `src` or text) calls
`run_script(parser_inserted = FALSE)` after the notifications; fragment-parsed scripts are marked started.

## 6. Display list (`core/display_list.h`, L1)

Layout produces a `shz_display_list`: an array of `shz_dl_item` in painting order (CSS 2.1 Appendix E, simplified)
plus a text arena. Every item has `kind`, `flags`, `extra`, `r` (integer CSS px, **document space**), `color`
(0xAARRGGBB, straight alpha) and `node` (generator, no reference). Kinds:

* `FILL` (rectangle), `BORDER` (per side style `SHZ_BS_*`, width, color; inset/outset/groove/ridge drawn 2-tone like
  classic IE), `TEXT` (arena offset + length, `shz_font *`, x, baseline, decoration flags), `IMAGE` (`shz_image *`
  scaled into `r`, reference held), `CONTROL` (engine-drawn form control, `extra = SHZ_CTL_*`, state flags checked /
  disabled / focused / pressed, label/value text), `MARKER` (list marker `SHZ_LIST_*`), `CLIP_PUSH` / `CLIP_POP`
  (overflow clipping), `FOCUS_RING`, `CARET`.
* `canvas_color` is the canvas background (root/body background propagation); `width`/`height` the document size.

The painter (win/paint_gdi.c) translates by `-scroll`, clips to the destination and maps items to GDI: `FillRect`/
`PatBlt`, lines/rectangles for borders, `ExtTextOutW` (+ underline/line-through lines), `StretchDIBits` for opaque
images and `GdiAlphaBlend` from a DIB section for images with alpha. Snapshot and view_paint render into a 32-bpp DIB
section selected into a memory DC, so they work without a display.

## 7. Font-metrics interface (`core/font.h`, L1)

`shz_font_backend { get_font(desc) -> shz_font*; metrics(font) -> ascent, descent, line_height, x_height, avg_width;
text_width(font, text, n); advances(font, text, n, cumulative[]) }`. The process-wide backend is set at DLL load
(`shz_font_set_backend(shz_gdi_font_backend())`); layout only ever calls through `shz_font_get_backend()`.

* **fixed** (core/font_fixed.c): the exact metrics of Shizuku gdi32's single font (gdi_text.c / gdi_obj.c): scale =
  clamp((round(size) + 8) / 16, 1, 4), advance 8·scale per UTF-16 unit, ascent 13·scale, descent 3·scale, line
  height 16·scale. Host tests use it; expected layout numbers are computed by hand from these rules.
* **gdi** (L1): `CreateFontIndirectW` (lfHeight = −round(size), weight, italic), `GetTextMetricsW`,
  `GetTextExtentExPointW`; on Shizuku it reproduces the fixed model, so host and guest geometry agree.
* **dwrite** (optional, L1): Wine's DirectWrite with FreeType and the Noto/Tahoma fonts in `\SHZ\FONTS`, chosen at run
  time (e.g. an environment variable); never required by tests.

## 8. HTML parser

* **Tokenizer** (html_tokenizer.c): WHATWG states for data, RCDATA, RAWTEXT, script data (as RAWTEXT: the
  "script data escaped" states are not implemented), PLAINTEXT, tags and all attribute states, comments (a
  conditional comment `<!--[if IE]>...<![endif]-->` is one comment token by the grammar; the Trident layer evaluates
  it), bogus comments, DOCTYPE with public/system ids and force-quirks, CDATA in foreign content/XML, numeric
  references (C1 → windows-1252, invalid → U+FFFD) and named references (HTML 4.01 set + legacy no-semicolon names +
  a few HTML5 names; the attribute "`=`/alnum after a legacy name" rule). It is resumable at every position: a state
  needing lookahead stops and waits for more input (network chunks, document.write).
* **Tree builder** (html_tree.c): every insertion mode except "in template" (template is an ordinary element) and
  "in head noscript" (scripting is always on); element scopes, implied end tags, the active formatting list with
  reconstruction, Noah's Ark and the adoption agency algorithm, foster parenting, tables (implied tbody/tr/colgroup,
  captions), select, frameset, `<image>`→`<img>`, SVG/MathML subtrees in their namespaces with the break-out rule
  (tag/attribute case adjustment not implemented), DOCTYPE quirks detection (`doc->doctype_quirks`), the fragment case.
* **Input** (html_parser.c): bytes → BOM > channel charset (`parser_begin`) > `<meta>` prescan of the first 1024 bytes
  > UTF-8; labels per the Encoding Standard (iso-8859-1/us-ascii = windows-1252), decoders UTF-8 (maximal-subpart
  U+FFFD), windows-1252, ISO-8859-15, UTF-16LE/BE; CR LF normalization across chunks. A late `<meta charset>` does
  not re-decode.
* **Scripts**: at a parser-inserted `</script>` the tree builder calls `run_script(parser_inserted = TRUE)`
  synchronously; parsing is paused until it returns (re-entrant network data is appended and parsed later).
  `doc_write` during that call inserts at the insertion point (right after the `</script>`) and tokenizes the inserted
  text immediately, including nested scripts (depth 16). Outside a script, write implies `doc_open` (the document is
  replaced) and `doc_close` ends a script-created parser. `load_string` = begin + decoded feed + end.
* `parse_fragment(context)`: the HTML fragment algorithm (context element decides the insertion mode and tokenizer
  state; a Document context parses like `<body>`); the result is a detached DocumentFragment of the context's
  document, so nothing is reported to the host until it is inserted.
* XML documents (`parse_document` with an XML type): the same tokenizer without lower-casing, plain nesting,
  self-closing honoured, `xmlns` namespaces (prefixes ignored), CDATA as text, `<?target ...?>` PIs (`<?xml?>`
  dropped).
* Lifecycle: `shz_load_parser_started` / `shz_load_parser_finished` (loader.h, L2) — readyState, `parse_done`,
  DOMContentLoaded, and `load` once `doc->fetch_pending` is 0.

## 9. Modes, coordinates, threading

* `doc_set_mode` stores the Trident mode; `shz_doc_quirks(doc)` gives the rendering mode layout uses: QUIRKS/IE5 →
  quirks, IE7 → limited quirks, IE8+ → standards; until `doc_set_mode` is called the DOCTYPE decides (HTML rules: no
  doctype = quirks). Quirks mode also makes class and id selectors ASCII case-insensitive. L1 implements at least:
  body/html percentage heights resolve against the viewport (quirks), table cells do not inherit font size/weight/
  style/color from outside the table (quirks), and the line-height quirks of limited-quirks mode. (Wine's mshtml maps
  documentMode 5 → `BackCompat`, 7+ → `CSS1Compat` itself; the engine only needs the rendering mode.)
* Coordinates: CSS px = device px (96 DPI). Layout and the display list use document space; `SHZ_BOX_BORDER`, client
  rects and hit testing use viewport space (minus `doc->scroll_x/y`).
* Threading: a document and everything reachable from it is used from one thread (engine.h). Global state is
  read-only tables plus the font backend pointer set at DLL load.

## 10. Tests

* **Host**: `python3 shizukudos/win64/trident/engine/tests/run_host_tests.py` compiles `core/*.c` +
  `tests/platform_host.c` with `gcc -std=c99 -Wall -Wextra -Werror -fsanitize=address,undefined` (LeakSanitizer on)
  and links every `tests/t_*.c` into its own program; exit 0 = all pass. L1/L2 add `tests/t_<area>.c` files — no
  registry to edit. Expected values are derived by hand from the specifications (html5lib-style tree dumps for the
  parser, RFC 3986 examples, Selectors 3 specificity table, CSS 2.1 box model arithmetic with the fixed 8x16 font),
  never read back from the implementation.
* **Guest**: `shizukudos/win64/tests/t_trident_engine.c` → `T_TRIDENT_ENGINE.EXE` (built by win64/build.py
  build_apps like every `t_*.c`), loads `shzlite.dll` with `LoadLibraryW` + `GetProcAddress("ShzEngineGetInterface")`,
  uses `u_check.h`, exits 0 only if every check passed, needs no display. L1 and L2 own the code between their
  `/* ---- L1 begin */ ... /* ---- L1 end */` and `L2` markers. Data files: `tests/data/TRIDENT_E1.HTM` (core,
  windows-1252 reference page), `TRIDENT_L1*.*` (L1), `TRIDENT_L2*.*` (L2), packed as `\SHZ\TESTS\<NAME>`.
* `python3 shizukudos/win64/trident/engine/tests/run_guest.py [--out DIR]` builds shzlite.dll + T_TRIDENT_ENGINE.EXE
  into `build/shizukudos/trident-engine/guest`, copies `build/shizukudos/win64/WIN64.IMG` adding
  `\SHZ\SYS64\shzlite.dll`, `\SHZ\TESTS\T_TRIDENT_ENGINE.EXE` and the `TRIDENT*` data files (other entries kept), boots
  it with run_k64_standalone.py's QEMU command and prints the test's serial lines; exit 0 = the kernel reported exit 0
  without fault and no FAIL line appeared.

## 11. Stubs

`core/stubs_l1.c`, `core/stubs_l2.c` (portable) and `win/stubs_l1_win.c`, `win/stubs_l2_win.c` define every function of
the L1/L2 API that is not implemented yet. On ELF (host tests) they are `__attribute__((weak))`, so a real definition
simply wins. GNU ld for PE cannot resolve a weak definition from another object, so in the DLL build they are plain
definitions and `build_engine.py` makes every stub that a real object also defines local (`objcopy
--localize-symbol`); implementing a function never breaks either build. The owner deletes stubs as they are
replaced and removes the files when empty. The portable stubs give useful defaults where core needs them:
`shz_style_display`/`white_space` by tag (innerText), `shz_forms_is_checked` from attributes (`:checked`), and a
minimal loader (readyState, `parse_done`, `load_done`).

## 12. Work lists

### L1 — CSS, style, layout, paint, fonts

Owns: `core/css.h style.h layout.h display_list.h font.h font_fixed.c`, `win/paint.h`, new files `core/css_*.c`,
`core/style*.c`, `core/cssom.c`, `core/layout*.c`, `core/display_list.c`, `core/geometry.c` (+ private `*_int.h`),
`win/paint_gdi.c`, `win/font_gdi.c`, optional `win/font_dwrite.c`, `tests/t_css*.c t_style*.c t_layout*.c
t_paint*.c`, the L1 section of t_trident_engine.c, `tests/data/TRIDENT_L1*.*`; deletes `core/stubs_l1.c`,
`win/stubs_l1_win.c`.

1. CSS tokenizer/parser (CSS 2.1 + Syntax 3 error recovery): rules, `!important`, comments, `@media screen/all`
   (others dropped), `@import` best-effort through `shz_fetch_start`, selectors via `shz_selector_parse` on the
   prelude text.
2. Sheets: `<style>` (text children) and `<link rel=stylesheet href>` (fetch; `file:` read directly when the host has
   no fetch) tracked from `SHZ_CHG_INSERTED/REMOVED/TEXT/ATTR`, in tree order; the fetch counts toward `load`
   (`blocks_load` = 1). CSSOM: `shz_css_sheet_*`, rule text, rule style, insert/delete rule, href.
3. Declaration blocks: inline (`style=""`, written back with `shz_elem_set_attr`), computed (resolved values:
   `rgb(r, g, b)`, `Npx`, keywords), rule; get/set/remove/priority/cssText/length/item; `media_matches`.
4. Cascade: UA sheet (HTML4/CSS2-style, incl. form controls, lists, tables, headings, `center`, `b/i/u/s/big/small`),
   presentational attributes (bgcolor, text/link colors on body, `<font color face size>`, align, width/height on
   img/table/td, border/cellpadding/cellspacing, `hr` attributes, nowrap), author sheets, `style=""`, `!important`,
   specificity + order, inheritance; the properties listed in the task (display ... cursor). `shz_render_dom_changed`
   marks dirty state; `shz_style_display/white_space/cursor/visible`. Quirks per section 9.
5. Layout (`node->box`): block formatting with margin collapsing (siblings, parent/first/last child, empty blocks),
   inline formatting with line breaking at spaces and `<br>`, `white-space` modes, `text-align/indent/transform`,
   `vertical-align` approximations, inline-block and replaced elements (img with natural size from
   `shz_image_state`, form controls with intrinsic sizes from the fixed font: e.g. `size=20` text input),
   list items and markers, floats (left/right, shortened line boxes, clear), tables (auto layout: min/max content
   widths, colspan, basic rowspan, cellspacing/cellpadding, border attribute), `position: relative/absolute` (nearest
   positioned ancestor), `z-index` paint order, `overflow: hidden` clip, `visibility`.
6. Geometry entries: `shz_layout_elem_box` (OFFSET per CSSOM View offsetParent rules, CLIENT, SCROLL, BORDER in
   viewport space), `offset_parent`, `client_rects`, `set_scroll` (fires "scroll" via `shz_events_fire`),
   `scroll_into_view`, `hit_test`, `hit` (for the view), `content_size`, `caret_rect`, `ctl_offset_at`,
   `set_viewport`; call `shz_doc_invalidate` when the rendering changes.
7. Display list (section 6) including controls from `shz_forms_render_info` (fall back to attributes while L2's stub
   answers E_NOTIMPL), images from `shz_image_of`, focus ring and caret from `doc->focus`.
8. Painting (win/paint_gdi.c): `shz_paint_to_dc`, `shz_paint_snapshot` (DIB section, no display), GDI font backend
   (win/font_gdi.c) installed at attach (`shz_paint_process_attach`); optional DirectWrite backend.
9. Tests: host layout tests with hand-computed boxes (fixed font), cascade/specificity/inheritance/computed values,
   quirks vs standards; guest: computed style, geometry of a reference page, snapshot pixel colours at hand-computed
   positions, `doc_set_mode` effects.

### L2 — images, events, view, forms, load glue

Owns: `core/events.h forms.h image.h loader.h`, `win/view.h`, new files `core/events*.c` (with the
`shz_interact_dom_changed` dispatcher that fans out to forms/images/loader and keeps `doc->focus/hover/active` valid),
`core/forms*.c`, `core/image*.c` (image_png.c on LodePNG, image_gif.c, image_bmp.c), `core/loader.c`, `win/view.c`,
`tests/t_events*.c t_forms*.c t_image*.c t_loader*.c`, the L2 section of t_trident_engine.c,
`tests/data/TRIDENT_L2*.*`; deletes `core/stubs_l2.c`, `win/stubs_l2_win.c`.

1. Events: listeners per node / window (type, capture, cookie); `shz_events_dispatch` (capture → target → bubble,
   window last, stopPropagation / stopImmediatePropagation, preventDefault only when cancelable, `trusted` flag,
   `hooks->event` returning `SHZ_FALSE` = preventDefault); synthetic `dispatch_event`; event objects with mouse/key/
   progress data and refcounting; `shz_events_fire`; `click()`, `focus()`, `blur()` (+ focusin/focusout), active
   element.
2. Default actions: link activation → `hooks->navigate` (resolved href, target) unless prevented; status text on link
   hover; submit / reset buttons, implicit submission (Enter); checkbox/radio toggling; label activation.
3. Forms: control state in `elem->ctl` (value/dirty value, checkedness/dirty checkedness, selectedness,
   selectedIndex, caret/selection), `shz_forms_get/set_value/checked`, select index, `form_submission`
   (application/x-www-form-urlencoded, multipart/form-data with a boundary, GET builds action?query; successful
   controls per HTML), `form_reset`, typing (`edit_insert/delete`, "input" and "change" events), `render_info` for
   L1, `:checked` (`shz_forms_is_checked`), clone state on `SHZ_CHG_CLONED`.
4. Images: decoders (PNG via LodePNG — `lodepng_decode32` then premultiply; GIF first frame with its own LZW decoder,
   transparency; BMP 1/4/8/24/32 bpp; JPEG → `SHZ_E_NOT_SUPPORTED`), `<img>`/`<input type=image>` state from `src`
   changes and insertion (fetch with `blocks_load`), load / error events, `img_state` (complete, natural size),
   `shz_image_of`.
5. Loader: readyState transitions with readystatechange, `parse_done` + DOMContentLoaded at
   `shz_load_parser_finished`, window `load` + `load_done` when `fetch_pending` reaches 0 after parsing,
   `shz_doc_invalidate` (views: InvalidateRect; windowless: `hooks->invalidate`).
6. View (win/view.c): window class "ShizukuTridentView" registered at attach; `view_create` as WS_CHILD of the
   parent; double-buffered WM_PAINT through a DIB section + `shz_paint_to_dc`; own scroll bars (drawn by the engine,
   draggable), wheel/keys scrolling (`doc->scroll_x/y`), resize → `shz_layout_set_viewport`, focus, caret blink
   timer; mouse (move/over/out/down/up/click/dblclick/contextmenu/wheel) and keys (keydown/keypress/keyup) → trusted
   DOM events, cursor from `shz_style_cursor` (hand over links), `status_text`, `context_menu`.
7. Tests: host dispatch order / preventDefault / trusted flags / submission bytes / decoders with hand-made images;
   guest: event order with a host callback, form_submission bytes, PNG + GIF through `<img>` (natural size, complete,
   pixel check in a snapshot once L1 paints), load sequence.

## 13. Known limitations (v1)

Script data escaped states; SVG/MathML name case adjustment; `<template>` contents; re-decoding after a late
`<meta charset>`; frames are parsed but `frame_doc` answers S_FALSE; no editing or printing caps; selectors: no
`:nth-child(... of S)`, no namespaces in type selectors (prefix accepted and ignored).
