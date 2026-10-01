# Immutable PE32 resource prerequisite

This is an independently authored, freestanding i486 C resource reader for the
preserved original Chromium 157.0.8080.0 PE32 inputs. It is a host-validated
prerequisite; Chromium application success remains **false**. There are no Win32
exports, module registrations, loader admission changes or target entry/TLS
calls. The existing native loader still rejects both originals at
`EXECUTION_RUNTIME_DIRECTORY`.

`nr_parse` accepts a successful immutable `np_parse`/`np_parse_limited` result and
builds a caller-owned context. It validates a type/name/language tree, sorted
numeric or counted UTF16 keys, directory-relative metadata offsets, image-relative
payload RVAs, sizes and codepages. Its fixed bounds are 1,024 leaves, 4,096 metadata
regions and 262,144 total name code units. No allocation or operating system API
is used by the resource reader. The context includes its scratch storage, so a
future Win98 caller should reserve it outside a small stack frame.

`nr_lookup` requires exact type, name and WORD language. `nr_load` returns a
borrowed immutable pointer, size, RVA, codepage and language. `nr_sizeof` obtains
the size independently. An information handle must be an exact leaf identity in
the supplied live context; an arbitrary pointer is never dereferenced. Repeated
loads of a valid handle are allowed. Contexts and original files must stay alive
and immutable, and contexts must keep their addresses. The caller coordinates
lifetime/concurrency. Handles are not memory allocations, so no release or
double-free behavior is invented.
Context storage may be reused only after every borrowed handle is discarded;
pointer identity does not detect a stale handle after an address/slot is reused.

PE numeric keys preserve 31 bits. Counted names compare UTF16 code units without
case folding, conversion, assumed terminators or surrogate decoding. Shared and
partly overlapping immutable payloads are supported. Payloads may reside outside
the resource directory, in any file-backed image section or headers; the reader
does not apply executable-section permissions to opaque data. Zero-sized leaves,
including zero RVA, are supported. Writable outputs/error storage that overlap
the original, owner or query are refused before those objects are written.

Cycles, shared/overlapping metadata records, extra tree levels, named/non-WORD
languages and nonzero reserved fields are explicit unsupported profiles. A
refusal is not evidence that every such PE is invalid. File bounds, overflow,
zero-fill metadata/payload references, key-kind mismatches and duplicate or
descending keys are independently checked. The data directory bounds metadata,
not the placement of resource payloads.

The exact-language contract does not implement FindResourceExW thread/user/system
language fallback, MUI, ANSI conversion, `#decimal` strings, NULL/current HMODULE
or resource-specific image/string/message decoders. A future adapter must use the
actual native module database and prove those API semantics before exporting them.

Run the local tests into a fresh directory:

```text
python3 ntwin32/resources/test.py --out build/chromium-resources-validation-<unique>
```

The runner freezes the source tree and publisher/input metadata, hashes compiler
binaries and unchanged originals, maps the actual originals with read-only host
protection, and runs the same meaningful suite normally and
under Clang AddressSanitizer/UndefinedBehaviorSanitizer, and compiles an i486 COFF
object. An independent Python reader compares every original leaf and hashes its
payload. All failed runs retain their frozen sources, logs and failure receipt.
The runner reads existing files and writes only its new output directory. It
does not run target applications, launch a VM, download, install, start services
or change client configuration.

Layout and handle contracts were checked against Microsoft's public
[PE resource layout](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section),
[FindResourceExW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-findresourceexw),
[LoadResource](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadresource)
and [SizeofResource](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-sizeofresource).
