# Current CSS token and variable core

This original GPL-2.0-only component tokenizes explicit UTF16 and computes an
already-cascaded map of unregistered custom properties. It implements real token
substitution and immutable parent computed snapshots. `M98CSS.DLL` is an opt-in
8.3-name native build component with allocator callbacks and no imported OS APIs.
No native load, genuine MSHTML style mutation, layout, painting, browser WPT run,
full CSS, WebGL, WebGPU, WASM or application workflow has been established.

## Exact algorithm and oracle profile

The primary current drafts are [CSS Syntax3](https://drafts.csswg.org/css-syntax-3/),
[CSS Variables1](https://drafts.csswg.org/css-variables-1/) and
[CSS Values5 substitution](https://drafts.csswg.org/css-values-5/#substitution).
Their original Bikeshed sources are retained at csswg-drafts revision
`f505fd10877a9c915b5d4a4028c2ad83c76d006f`, with exact paths, URLs, sizes and
SHA256 in `benchmarks/css-standards-source-v1/source-pin.json`. Those are primary
algorithm references, not a downloaded engine or executable build dependency;
the [W3C document license 2023](https://www.w3.org/copyright/document-license-2023/)
applies to the retained reference documents. The accompanying
`benchmarks/css-standards-source-v1/NOTICE.md` retains each original W3C URI,
title, status, authors/editors and Copyright © 2026 World Wide Web Consortium.
That notice is included in the complete frozen build source closure; the raw
reference documents remain unchanged. No code was copied from them.

Current `var()` evaluation short circuits: unused fallback references do not
create a cycle. Active DFS tracks property replacement contexts; actual cycle
members remain invalid even when they themselves have a fallback. An outside
property can use a fallback for the invalid cycle. Computed first arguments such
as `var(var(--name))` are substituted and then parsed as a dashed identifier.
This intentionally differs from the older published 2022 all-fallback graph.

The official WPT selection is pinned to revision
`5cd8e3fa0a6c4ca11fa565f7c0956802c8e0045d` (2026-10-01T03:06:07Z).
`benchmarks/wpt-css-selected-v1/source-pin.json` binds seven original raw files,
including full upstream BSD-3-Clause LICENSE.md. The small original JSON oracle
transcribes token/variable expectations; its per-source hash map must match the
raw files before building. WPT HTML/JavaScript is never executed. No browser WPT
PASS or exact CSSOM author serialization is inferred from these core assertions.
WPT contributors retain copyright in their selected tests. Additional memory,
identity, lifetime, preprocessing and boundary tests are original GPL-2.0-only.

## ABI and lifetime

`m98_css_tokenize` returns owned opaque streams. UTF16 preprocessing collapses
CRLF/CR/FF to LF and replaces NUL/unpaired surrogates with U+FFFD; valid surrogate
pairs remain scalar values. Whitespace, identifiers/functions, at-keywords,
hash id/unrestricted flags, strings/bad strings, URLs/bad URLs, decimal number
representations/type, percentages/dimensions, CDO/CDC and punctuation are actual
tokens. Escapes, EOF, bad URL remnants, newline string recovery and comments
follow the pinned current algorithm. Numbers expose an exact decimal lexeme
and integer/number flag, not an eagerly rounded double; numeric value conversion
and property grammar/calculation remain the consuming style engine's work.

All calls must be serialized. Allocator callbacks must be valid and remain alive
until every related owned object is destroyed. Read views are borrowed; callers
must not mutate them, fabricate streams, or use views after teardown. A token
passed to `value`/`number` must come from `at` on that same live stream. Output
pointers are unchanged on API errors. Free functions clear the caller's pointer
before releasing storage and are idempotent for NULL; copying an owning pointer
does not create a second owner. `append` accepts distinct genuine live streams;
its capacity growth can invalidate borrowed array views even when the logical
append fails. Only EOF closing component tokens may be synthesized by `literal`.

`m98_css_compute` consumes unique winning declarations after selector/origin/
layer/importance cascade. It rejects invalid declaration syntax transactionally;
the caller must discard such a declaration before selecting a winner. It clones
parent **computed** tokens, so child overrides cannot re-evaluate the parent's
specified `var()` and the parent can be closed independently. Missing/initial
properties are guaranteed-invalid; a specified empty value remains valid empty.
`inherit` and `unset` copy the parent. A computed custom-property result consisting
only of a CSS-wide keyword acts as if specified originally, per current Values5:
`initial` is invalid and `inherit`/`unset` select the original parent snapshot.
The ordinary-property substitute API returns keyword tokens to its consuming
property grammar, which must apply that property's actual defaulting behavior.

`m98_css_substitute` evaluates using the computed snapshot. It reports invalid at
computed time separately from API failures and property-grammar validation.
Strings and URL tokens containing apparent `var` text remain literal. Empty
fallbacks, nested first arguments, comma-containing fallbacks and recovered EOF
function/block closers are represented as tokens. Per-argument declaration-value
grammar is checked on every specified var(), including nested references in an
unused fallback. A missing first argument or per-argument top-level `;`/`!`
returns transactional INVALID before winning-map compute/substitution. This
syntax-only pass creates no dependency edges or fallback evaluation. It applies
the current argument grammar structurally while preserving computed first names;
older static first-name-only grammar is not used. No string replacement shortcut
is used. The serializer inserts conservative empty comments at token boundaries,
except after a function opener/whitespace, and escapes names/strings/units; it
preserves token identity instead of accidentally turning NUMBER + IDENT into a
DIMENSION. It reports bad-token serialization as unsupported. Whitespace amount
may coalesce on reparsing. This is not original-author CSSOM serialization.

## Explicit bounds and unsupported lanes

Limits are 32,768 input UTF16 units, 4,096 tokens per stream/computed value,
131,072 pooled scalar units, 64 nested components/substitutions and 64 properties
including inherited entries. The final composed output is checked too, so a
shallow value cannot wrap a 64-deep inherited/computed value into depth65.
Allocation failure and excess expansion/depth have
explicit MEMORY/LIMIT errors; they never become a valid CSS value. Serialized
text can be larger than input because of escapes; callers must query capacity
and respect the tokenizer's input bound when reparsing. These are a bounded
engineering profile, not a claim that all documents fit.

`revert`/`revert-layer`/`revert-rule` require cascade metadata and return UNSUPPORTED.
`attr`, `env`, `if`, `inherit()`, `first-valid`, `random`, `ident`, `random-item`
and dashed custom-function invocations (`--name(...)`) are substitution functions
that are detected and return UNSUPPORTED, including inside unused fallback syntax.
Broader arbitrary substitutions, `@function`, registered `@property`, animation
taint, early spread syntax (`...var()` inside a var() argument), priority parsing,
selectors, at-rules, stylesheet parsing, relative-URL
resolution, property grammar, CSSOM, Flex/Grid, modern layout and paint are not
provided. Unknown ordinary functions are retained tokens for the later consuming
grammar; retention does not establish implementation of that function.

## Build and native integration handoff

`tools/build_css_core.py --build-dir build/css-core-v4` uses a fresh checkpoint.
It validates raw upstream hashes, generates bounded C data from the JSON oracle,
runs normal and ASan/UBSan/leak checks, builds the original i486 native component
and scans all linked machine instructions for post-i486 families/SIMD. Native
builds use the unchanged original freestanding memory primitives. PE32 DLL
headers target OS/subsystem4.10, exact 18 exports, no imports, relocations and
2MiB reserve/512KiB stack commit. The OEM export baseline is included in source
closure although this pure component requires zero OEM APIs. No registration,
global client changes, VM operations, service or network activity occurs.

Next integration must read genuine MSHTML style declarations, perform a real
selector/importance cascade into this ABI, supply parent computed snapshots,
validate resolved ordinary-property grammar and call genuine supported style
setters. Verify a directly hosted exact-IE5.00.2614.3500 Win98SE document with
Korean content using actual queried styles plus independently reviewed visible
paint. A later modern layout/composition implementation is still needed; neither
tokenization nor an opt-in DLL proves that stock Trident understands modern CSS.
