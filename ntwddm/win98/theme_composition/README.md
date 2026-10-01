This is a separate diagnostic probe derived from the frozen redraw-fixed
`theme_probe/probe.c`. It does not change the original probe, provider, styles,
observer, automatic-start helper, or previous native evidence.

The client scene is composed in a private top-down 32-bit DIB. All seven caption
and button regions receive fixed independent background samples and complete
pixel comparisons against a separate native DrawTextA reference using the
Windows message font. Both reference and provider must contain actual text ink;
an HRESULT or an empty matching pair is insufficient. A completed scene is
transferred to the client DC once per paint. Destination GetPixel samples remain
separate from the memory result: clipping, unsupported readback, palette
quantization, and display artifacts cannot establish complete visible pixels.

Microsoft's CreateDIBSection documentation requires GdiFlush synchronization
before accessing DIB bits. Its GetPixel documentation specifies CLR_INVALID for
clipped points and notes that devices may not support readback:
https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-createdibsection
https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-getpixel
The modern pages do not establish Win98 support; the local OEM export gate and
the separately observed native Win98 run provide that evidence.

`build.py --frozen-theme-stage <v12-stage>` runs resource/pixel failure tests,
ASan/UBSan, parser tests, an i486 build, instruction checks and the OEM PE gate.
It copies the exact original provider and observer and emits a new immutable
artifact/source receipt. The existing guarded startup helper can then prepare a
fresh nonce and private COW trial. Parser results alone do not prove native
process exit or complete visible scanout. Keep original native strict lifecycle
verification and independent stopped-guest readbacks, then review actual PNGs.

V13 passed actual offscreen pixel and normal child lifecycle checks but failed
the existing strict verifier because its immutable build receipt used uppercase
`NOT-TESTED` instead of the required `not_tested`. Its original receipt and FAIL
remain sealed. Later builds validate the exact static receipt contract and all
frozen artifact hashes before preparation; this gate supplies no native exit.

The subsequent candidate makes one foreground request on initial show and each
style change, only after checking the probe handle belongs to its own process
and is visible. It records both the request return and the independently read
foreground handle. A refusal remains diagnostic, with no retry loop or changes
to other windows. Foreground state still cannot prove a complete visible scene.
Microsoft documents request restrictions and a possibly null foreground handle:
https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setforegroundwindow
https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getforegroundwindow
Win98 import support is checked against the unchanged local OEM export inventory.
