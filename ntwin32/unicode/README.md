# Original UTF conversion foundation

This directory implements independently authored UTF-8 ↔ UTF-16 conversion
for **Windows 98 Shizuku's Second Edition**. It advances the repository's
`unicode-nls` prerequisite family. The freestanding core is used by the
`CP_UTF8` implementations of `MultiByteToWideChar` and `WideCharToMultiByte`
in [the app-local provider](../README.md). Locale data, case mapping,
normalization, other code pages, and ANSI/OEM code-page selection are outside
this core; the provider delegates other code pages to native KERNEL32.

## Core contract

`utf.h` provides `ntwu_utf8_to_utf16` and `ntwu_utf16_to_utf8`. Lengths count
bytes for UTF-8 and `uint16_t` units for UTF-16. UTF-16 uses native-endian
integer values; it is not a byte-serialized UTF-16LE/BE interface. UTF-16
storage must be naturally aligned. The core has no allocation, OS calls,
global mutable state, lookup tables, or runtime library dependencies.

Both functions process exactly the supplied source length. Embedded NULs and
U+FEFF are ordinary data. They do not append a terminator or remove a BOM.
Empty input succeeds with length zero, and may use a NULL source. Destination
capacity zero performs a size query and ignores the destination pointer.

Flags zero enable replacement; `NTWU_STRICT` rejects malformed input. Unknown
flags fail. A validation/counting pass precedes output, so malformed input,
insufficient capacity, invalid ranges, and overlap errors leave destination
bytes untouched. `required` receives the exact full output length on success
or insufficient capacity; other errors preserve it. Its storage must be valid,
naturally aligned, and disjoint from the source and active destination.

Checked arithmetic covers unit-to-byte multiplication, pointer-range wrap,
output accumulation, and representability of the UTF-16 output byte size.
Source and destination declared ranges must not overlap, even when the
destination has extra unused capacity. Adjacent ranges are supported. The
caller guarantees accessible memory and an unchanged source throughout both
passes; the core cannot establish memory mapping or prevent concurrent writes.

## Encoding and malformed-input policy

Valid conversion follows Unicode's scalar-value and encoding-form definitions:
all values from U+0000 through U+10FFFF except surrogate code points are
representable, including noncharacters and unassigned values. Overlong UTF-8,
surrogate encodings, out-of-range values, and isolated UTF-16 surrogate units
are malformed. See [Unicode 17, Chapter 3, §§3.9.2–3.9.4](https://www.unicode.org/versions/Unicode17.0.0/core-spec/chapter-3/).

Replacement uses one U+FFFD per maximal ill-formed subpart. A truncated valid
prefix is consumed together; a disallowed next byte is reconsidered separately.
Thus `E1 80 41` becomes U+FFFD followed by `A`, while `ED A0 80` produces three
replacements. This policy never consumes a valid successor as part of an error.
It is the substitution practice described in
[Unicode §3.9.6](https://www.unicode.org/versions/Unicode17.0.0/core-spec/chapter-3/),
which explicitly distinguishes that practice from mandatory Unicode conformance.
Strict mode reports the first malformed input and writes nothing.

## Win32 adapter mapping

`../runtime.c` maps the portable results into the exported Win32 interface:

| Core result | Adapter result |
| --- | --- |
| `NTWU_OK` | Return the converted/required length after an `INT_MAX` check |
| `NTWU_MALFORMED` | `ERROR_NO_UNICODE_TRANSLATION` (1113) |
| `NTWU_INSUFFICIENT` | `ERROR_INSUFFICIENT_BUFFER` (122) |
| `NTWU_INVALID_FLAGS` | `ERROR_INVALID_FLAGS` (1004) |
| `NTWU_INVALID`, `NTWU_OVERLAP` | `ERROR_INVALID_PARAMETER` (87) |
| `NTWU_OVERFLOW` | `ERROR_INVALID_PARAMETER` (87); native edge unverified |

For [MultiByteToWideChar with CP_UTF8](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar),
accept only flags zero or `MB_ERR_INVALID_CHARS` (8), translating the latter
to `NTWU_STRICT`. The adapter rejects source length zero, distinguishes
positive byte counts from `-1`, and includes the terminator when scanning `-1`.
Output capacity is measured in UTF-16 units. A zero capacity is a query.

For [WideCharToMultiByte with CP_UTF8](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte),
accept only zero or `WC_ERR_INVALID_CHARS` (128), and require both default-
character parameters to be NULL. Source counts use UTF-16 units, output
capacity uses bytes, and `-1` includes the first terminator. Zero source length
and negative lengths other than `-1` are rejected by the adapter. The
Microsoft contracts identify an incorrectly NULL output buffer as insufficient
buffer; the adapter validates that separately from the core's generic
invalid-parameter result.

The adapter checks signed counts, scans `-1` until NUL inclusive within
representable address extent, dispatches code pages, and exposes the real Win32
calling convention and last-error handling. Result sizes above `INT_MAX` fail
with error 87. There is no arbitrary input-length cap. Per Microsoft remarks,
identical source and destination pointers fail even for size queries; unrelated
destination values are ignored for zero capacity. The core's strict alignment, full-range overlap
rejection, failure precedence, and untouched-output guarantee are explicit
project rules, not proven byte-for-byte Windows behavior. Native documentation
allows some partial output on errors; this core deliberately preflights instead.
Replacement grouping and exact last-error/invalid-pointer behavior require
native Windows differential tests. No Win98 guest compatibility is claimed.

## Reproduce validation

```sh
python3 ntwin32/unicode/test.py
```

The runner uses installed Clang, `nm`, and Python only. It installs/downloads
nothing and starts no guest processes. Every generated executable, object,
shared oracle module, and receipt remains under ignored `build/` in this
directory. The core source is compiled independently for i486; its object must
have zero undefined symbols. The host oracle module is also linked without a
C runtime and checked for undefined symbols.

The 2026-09-27 strict and ASan/UBSan runs each pass **15,578,938 assertions**,
including an exhaustive roundtrip of **1,112,064 Unicode scalar values** against
a separately written radix-arithmetic encoding oracle. Tests include truncated
prefixes, malformed UTF-8 categories, every isolated surrogate, surrogate-pair
boundaries, size queries, insufficient buffers, exact limits, overlap and
integer/address overflow, embedded NUL, Korean text, and BOM preservation.

The independent Python-codec comparison additionally passes **80,129 UTF-8
cases** and **4,826 UTF-16 cases** in strict and replacement modes. These include
every one-byte/two-byte UTF-8 input, constrained boundary leaders with every
second byte, mixed surrogate triples, and deterministic randomized strings.
Python is a host test oracle only; its source/data are not included in the core.
This comparison is not a native Windows conformance result.

`build/host-tests.json` binds the source hashes, exact assertion/scalar counts,
host-oracle results, and artifact hashes. A source change during validation
prevents receipt publication. This runner tests only the core; actual compiled
Win32 adapter calls are exercised by `platform/abi32`. Native Windows
differential and Win98 guest validation remain subsequent work.
