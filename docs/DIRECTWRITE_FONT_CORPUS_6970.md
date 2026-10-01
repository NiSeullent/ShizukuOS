# Korean DirectWrite corpus — 6970

The actual 142-member Modern runtime contains Noto Sans, Noto Sans Mono, Noto
Serif and two Tahoma files. Independent cmap inspection finds zero Hangul
syllables in every file. DLL availability alone therefore cannot establish
Korean text support in this corpus. The archive and its original bytes remain
unchanged.

`tools/dwrite_font_corpus.py` acquired the unmodified official Noto Sans CJK KR
regular face from publisher commit `f8d157532fbfaeda587e826d4cd5b21a49186f7c`. Its exact
publisher Git blob identity and local SHA-256 hashes, SIL OFL 1.1 notice and
publisher README are retained in the new ignored
`build/dwrite-font-corpus-6970-v1`. The source pin and font profile are recorded
in `benchmarks/dwrite-font-corpus-6970.json`.

The real font is version 2.004, 16,433,112 bytes, with all 11,172 Hangul
syllables, Latin glyphs and 65,535 glyphs total. Independent font-table inspection
records glyph IDs, units/em, advance widths and bearings for the actual guest
probe oracle. These are font-table checks, not DWrite implementation or rendering
acceptance. The corpus tool installs/registers no fonts, starts no VM, and keeps
the 20-GiB reserve. The official font and notices remain outside Git.

The next private probe must load this exact face through real DWrite font-file
and COM interfaces, compare actual glyph/design metrics, exercise text layout
and rasterization, and separately validate native/window output and cleanup.
Global font fallback, native Windows 98 integration, full DirectWrite and
application functionality remain unverified.

Publisher: [official Noto CJK repository](https://github.com/notofonts/noto-cjk),
[exact OFL notice](https://github.com/notofonts/noto-cjk/blob/f8d157532fbfaeda587e826d4cd5b21a49186f7c/Sans/LICENSE).
