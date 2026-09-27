# UTF core provenance

All files in this directory were independently authored for this project on
2026-09-27 and are licensed under **GPL-2.0-only**, with the license text in the
repository root. No KernelEx, Wine, ReactOS, Microsoft implementation, ICU,
utf8proc, or other third-party Unicode implementation was copied or translated.
No Unicode Character Database tables are needed or imported.

| File | Original project contribution |
| --- | --- |
| `utf.h`, `utf.c` | Portable explicit-length API, bounds checks, two-pass conversion, UTF scalar decoders/encoders, and maximal-subpart replacement |
| `test_utf.c` | Exhaustive scalar/radix oracle and focused contract/malformed-input tests |
| `oracle.py` | Host-only comparison using Python's installed codecs through an original ctypes harness |
| `test.py` | Strict/sanitized host builds, freestanding i486 validation, oracle execution, and source-bound evidence receipt |
| `README.md`, `PROVENANCE.md` | API integration guidance, evidence limits, and attribution |

Primary interface/specification references consulted:

- [Unicode 17, Chapter 3: Conformance and Encoding Forms](https://www.unicode.org/versions/Unicode17.0.0/core-spec/chapter-3/)
- [Microsoft MultiByteToWideChar](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar)
- [Microsoft WideCharToMultiByte](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte)

The implementation was derived from public encoding/interface contracts,
not from an existing converter's source. Test byte sequences express format
boundaries and normative examples; they are not imported implementation tables.
Python's codecs are used only as an independent runtime oracle in development,
never linked or shipped as part of the freestanding core.
