# Private DirectWrite acceptance — 6970

The private AMD64 probe now exercises the actual runtime `dwrite.dll` through
its COM interfaces. The latest actual guest trial is **FAIL**. Partial font,
glyph-analysis, Latin-rendering and framebuffer results are preserved below;
they do not establish working Korean text layout or full DirectWrite support.

## What is checked

`ntwddm/win64/dwrite_probe/probe.c` uses an isolated real DWrite factory and
checks COM identity, reference ownership, the five existing archive fonts,
explicit private Noto Sans CJK KR font-file references, custom font collection
enumeration, nine independently expected glyph IDs and design metrics, bounded
Korean alpha rasterization, Latin/Korean layout callbacks and real bitmap
rendering. It compares the complete 384 × 128 visible image through GDI and a
separate QEMU framebuffer capture, then checks cleanup and process exit.

The expected cmap, advances and bearings come from `tools/dwrite_font_corpus.py`
and the unmodified publisher font, not values reported by DWrite. Layout
callbacks must cover the exact UTF-16 positions and glyph order using the exact
private face, including spaces. The font is loaded privately from the trial
volume. There is no system font installation or registration.

`tools/win64_dwrite_probe_trial.py` freezes source and toolchain dependencies,
checks actual AMD64 PE imports and relocations, reads the FAT payload back,
requires a fresh nonce, records actual KVM descriptors, and requires both a
complete child verdict and independently observed normal child exit. A QEMU
framebuffer match alone cannot pass the trial.

## Recorded validation

The host regression command below passed **38 tests in 4.420 seconds**. These
cover observer rejection cases, framebuffer hashing, independent archive
relationships and actual compiled PE mutations. They do not execute DWrite.

```sh
DWRITE_TEST_OVERLAY=build/dwrite-theme-overlay-v3/theme-overlay.json \
  python3 -B -m unittest discover -s tests -p test_win64_dwrite_probe_trial.py
```

The sealed preparation was `build/dwrite-prep-v4b/prepared.json`, nonce
`74e25ce1b33640eda1ad92356a9da6b5`. Its 80,464-byte executable has SHA-256
`bb0f7df50bb0efa7ef99ec3b4e9dec3bcd557705a77904c4f0865b26112f76cb`,
with 33 imports resolved against the actual selected archive. The consumed
`dwrite.dll` is 1,857,013 bytes, SHA-256
`9e359934923f403097a048252c012e1d2b8f8c36c5233b4d6d37c563339cca28`.
This binds the tested binary; the preparation explicitly leaves reviewed-source
to binary identity unverified.

The actual trial `build/dwrite-run-v2` ran for 50.3 seconds using KVM, 1 GiB
guest RAM and no network. Its child was PID 60. The exact serial evidence shows:

| Operation | Actual result |
| --- | --- |
| Factory identity and reference balance | PASS |
| Five baseline fonts | Latin cmap/metrics PASS; all five have zero Hangul syllable coverage |
| Private CJK face | All nine glyph IDs, advances and bearings match independent font tables |
| Korean glyph-run analysis | PASS; alpha texture has 2,244 nonzero bytes out of 5,040, guards unchanged |
| Latin text layout and raster | PASS; callback order matches, 463 DIB ink pixels |
| Korean text layout | FAIL; covered positions 255/255, two aggregate callback cmap/order errors |
| Korean text raster | FAIL; zero Korean DIB ink pixels |
| Glyph face identity | No missing glyphs or wrong faces reported across two runs and ten glyphs |
| Visible GDI readback | PASS; all 49,152 pixels match the owned DWrite DIB |
| Separate QEMU framebuffer | Capture PASS; same 49,152 pixels, RGB hash `32a97c0e` |
| Final verdict, cleanup and normal child exit | Unverified; child timed out after 45 seconds |

The matching bound probe source rejects the Korean callback before calling
`IDWriteBitmapRenderTarget::DrawGlyphRun` when its shape-error count is nonzero.
The target is cleared white before each row and then copied/read back. The zero
Korean ink remains an observed FAIL; it does not prove that the provider's
bitmap raster call executed and failed. The v2 log does not identify which two
UTF-16 positions or comparison conditions failed. Its layout `Draw` HRESULT
was `S_OK`, which is distinct from the rejected renderer callback.

## Current source diagnostics, not yet executed

The current probe records `DW64 MISMATCH` for each failing position, with row
(0 Latin, 1 Korean), absolute/local UTF-16 position, callback text position,
expected/actual character, expected cmap/actual shaped glyph, expected/actual
cluster and the prior seen mask. Condition mask bits are 1 duplicate position,
2 cluster, 4 character and 8 glyph; several conditions can share one position.
The original one-error-per-position count and strict failure conditions remain.

Rejected runs still return early and now emit `DW64 DRAW SKIPPED` with a reason.
Valid runs emit `DW64 DRAW CALL` immediately before the actual bitmap call and
`DW64 DRAW RETURN` with its HRESULT. These diagnostic prefixes do not change the
existing assertion, `DW64 SHAPE`, raster, nonce, final-verdict or child-exit
records. No separate diagnostic draw is performed on rejected runs. The font,
expected oracle, locale/provider code and acceptance parser are unchanged.

These diagnostics have been compiled as described below, but not guest-tested. The
historical v2 source hashes and raw evidence above retain their original meaning;
new diagnostics require a fresh source-bound preparation and trial. A possible
locale-specific OpenType space substitution has not been established as the
cause of the two errors because the existing trace lacks per-position values.

## Recorded child termination

The furthest child marker is `DW64 GUI READY`. The next source operation is
`Sleep(4000)`. At timeout the thread report places the child in `ntdll.dll+9096`
through `kernel32.dll+3f07`. These observations localize the unfinished phase;
they do not prove the cause of the timeout. There is no subsequent window
destruction, final loader/factory cleanup, assertion total or final child
verdict in the serial log.

The kernel autorun result is `timeout exit=102 faulted=1 reaped=0`. Its later
kernel self-test `SHZ-EXIT:0` describes the kernel's own completion and cannot
replace the missing child exit. The acceptance parser correctly rejects the
trial with `unique complete fresh verdict required`.

The resource guard recorded 22,978,990,080 bytes minimum free space and
2,589,522 bytes peak private writes. The fixed floor is 21,474,836,480 bytes;
the private write and output limits remain 268,435,456 and 16,777,216 bytes.
Original and sealed inputs were preserved. No peer sources or global settings
were modified by this trial.

The local evidence remains under ignored `build/`; these paths identify
historical artifacts rather than files supplied by a Git clone.

| Local artifact | SHA-256 |
| --- | --- |
| `build/dwrite-prep-v4b/prepared.json` | `ce26eb89f7f4ca567be20bd4e5a070a107e834f9ed0a3f003cd94523d37f8606` |
| `build/dwrite-font-corpus-6970-v2/receipt.json` | `7dedada49e0b0616ca0f3f93db0205ea2b62293f72fe3acbe74b3648f682648c` |
| `build/dwrite-run-v2/result.json` | `5724368fd1fbf13d8252562893118e413f41f0d28991c8419d8255cfc2a005dd` |
| `build/dwrite-run-v2/serial.log` | `ba38b305c092dcc16ef670f7a3b86d15d181f27262821c0331e653e030c3f10c` |
| `build/dwrite-run-v2/dwrite-acceptance.json` | `d846de42676d1e6e0a08289a22f7e0ad20584e682459027fa731a76294dd9235` |

## Reproduce in another environment

The source tree and CLI use the checkout's own location rather than a hardcoded
`/root/Win98-Modern-theme-6970`. Select the runtime worktree, overlay, font corpus,
QEMU executable and firmware directories explicitly. All new trial outputs must
be fresh directories below that checkout's ignored `build/` directory.

Required local tools are Python 3.10 or newer with `pefile`, `fontTools` and
Pillow, `x86_64-w64-mingw32-gcc` and its tools/import libraries, `mkfs.vfat`,
`mcopy`, and a QEMU/KVM installation with accessible `/dev/kvm`. The runner
inspects Linux `/proc` for real hardware-virtualization evidence. These commands
therefore describe a Linux KVM environment, not a portable native Windows test.

The selected runtime worktree must supply its real `shizukudos/tests` and
`shizukudos/tools` helpers plus built `boot.elf`, `KERNEL64S.BIN` and `WIN64.IMG`
at the locations those helpers select. Its actual archive must include DWrite,
its dependencies, and the five baseline fonts. A valid theme-provider build
receipt and appended private runtime-overlay receipt are prerequisites; see
`ntwddm/win64/theme_provider/README.md` and
`tools/required_theme_runtime.py prepare --help`.

The current preparation freezes license notices from
`/usr/share/licenses/{mingw64-gcc,mingw64-headers,mingw64-crt,mingw-binutils-generic,cross-binutils-common}`.
This is an explicit host packaging assumption. A distribution with different
notice locations needs a reviewed recipe change and fresh receipts; the CLI
currently has no license-directory override. Executable/tool names are also
resolved from the local PATH. Historical receipts contain absolute paths and
hash bindings and are not relocatable. Generate fresh receipts after moving to
another host; do not rewrite old receipts or reuse a sealed trial after changing
its sources or compiler inputs.

The test suite's three historical corpus-binding cases look for
`build/dwrite-font-corpus-6970-v1/receipt.json` and skip when that retained local
fixture is absent. Its five actual PE cases require a compiler and the selected
`DWRITE_TEST_OVERLAY`. Check the test runner's skip count on a fresh checkout;
the recorded 38-test result above used the existing local evidence fixtures.

Run from the new checkout. The variables below are placeholders for real local
prerequisites and fresh output locations; `OVERLAY_RECEIPT` must already be
prepared for the chosen runtime on that host.

```sh
OVERLAY_RECEIPT="$PWD/build/private-theme-overlay/theme-overlay.json"
FONT_CORPUS_DIR="$PWD/build/private-dwrite-font-corpus"
DWRITE_PREP_DIR="$PWD/build/private-dwrite-preparation"
DWRITE_RUN_DIR="$PWD/build/private-dwrite-run"
DWRITE_QEMU_PATH="/absolute/path/to/qemu-system-x86_64"
DWRITE_FIRMWARE_DIR="/absolute/path/to/qemu-firmware"

# Downloads only the pinned public font and its notices; installs no fonts.
python3 -B tools/dwrite_font_corpus.py \
  --baseline-overlay "$OVERLAY_RECEIPT" --out "$FONT_CORPUS_DIR"

DWRITE_TEST_OVERLAY="$OVERLAY_RECEIPT" \
  python3 -B -m unittest discover -s tests -p test_win64_dwrite_probe_trial.py

python3 -B tools/win64_dwrite_probe_trial.py prepare \
  --overlay "$OVERLAY_RECEIPT" \
  --font-corpus "$FONT_CORPUS_DIR/receipt.json" --out "$DWRITE_PREP_DIR"

python3 -B tools/win64_dwrite_probe_trial.py run \
  --prepared "$DWRITE_PREP_DIR/prepared.json" --out "$DWRITE_RUN_DIR" \
  --qemu "$DWRITE_QEMU_PATH" --firmware-dir "$DWRITE_FIRMWARE_DIR" \
  --timeout 75
```

Repeat `--firmware-dir` when the local QEMU needs several firmware directories.
Preparation creates a private 64 MiB FAT32 image and read-only frozen copies;
execution uses a temporary private QEMU snapshot. There is no guest NIC. Keep
the 20 GiB reserve plus preparation/runtime headroom. Source changes require a
fresh preparation, output directory and nonce; the tool generates the nonce by
default. The 75-second host limit does not alter the bound 45-second child limit.

The official font and notices are pinned to Noto CJK commit
`f8d157532fbfaeda587e826d4cd5b21a49186f7c` under OFL 1.1. Their immutable Git
object identities are checked before accepting the corpus; see
[the font corpus guide](DIRECTWRITE_FONT_CORPUS_6970.md).

Full DirectWrite API coverage, system Korean font fallback, OS-wide integration,
Direct2D integration, native Windows 98 execution and modern application
functionality remain unverified. The next functional work must resolve the
Korean layout/raster failures and independently complete cleanup and normal
exit before this private subset can pass.

The diagnostic source was subsequently compiled into a fresh 81,521-byte AMD64
executable, SHA-256
`47e1a1f4c89a4e39c135711d3480c66912687b638c931d0771eedf6023db646f`.
The executable retains the same 33 imports as the recorded v4b probe, an
executable entry and actual DIR64 relocations. Its nonce is fresh; the font
oracle is byte-identical apart from that nonce. The compile/PE receipt SHA-256
is `1b2145433197c21925dbd13394a01aecfa735af4804f9ba3004e11e73a8b5796`.
This is a compile check, not a new guest trial or proof of reviewed DWrite
source-to-DLL identity. A functional retry still requires fresh preparation
with the actual runtime, font and compiler inputs. The previous v2 result
remains FAIL.
