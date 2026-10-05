# ShizukuKRBitmap shell text

This Win32 helper draws Korean shell labels through real GDI brushes and filled
rectangles. The fixed 16×22 bitmap face covers ASCII, modern/archaic Hangul jamo,
compatibility jamo and every 11,172 precomposed Hangul syllable. Measurement and
drawing consume UTF-16 consistently; unsupported scalars use one question-mark
cell, including a surrogate pair. Invalid lengths, scales or coordinate overflow
fail before drawing. Brushes are released even if drawing fails.

Compile `shz_text.c` with the shell and include `shz_text.h`. Use
`ShzTextMeasureW` for the required extent and `ShzTextDrawW` for transparent text.
Painting respects the target DC's clipping. Callers choose scale 1–8 and must
provide room for the measured extent. The helper performs no wrapping, shaping,
IME input, font discovery or font installation; it does not replace Windows
`DrawTextW` or establish complete Unicode/Windows 10 text compatibility.

The generated bitmap data is **SIL OFL 1.1**, independently of the GPL helper.
Package `generated/OFL.txt` beside any shell artifact containing these glyphs.
The modified face is named ShizukuKRBitmap; Noto/Adobe are source attribution,
not product endorsement. The source font copyright and license are preserved.

Generation reads the installed Noto Sans CJK KR variable collection face 1 at
16 pixels, weight 500 and monochrome threshold 96. It checks every requested
glyph for coverage, clipping and unexpected empty output; the Hangul filler
characters U+115F/U+1160/U+3164 and space intentionally remain blank.
`generated/generation.json` records source/license hashes and settings. The font
source stays outside this repository; regenerated output can depend on Pillow
and FreeType versions. Regeneration must use a fresh directory:

```sh
python3 integration/shizuku-font/generate.py \
  --font /path/to/NotoSansCJK-VF.ttc \
  --license /path/to/OFL-license \
  --out /path/to/new-output
```

This component has been generated and compiled on the host. Shell linkage and
guest display must be verified separately.
