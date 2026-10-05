# ShizukuOS font policy

The user requires Noto Sans or Pretendard throughout the desktop. The chosen family is **Noto Sans**, with **Noto Sans KR** for Korean. Slade, Flute, Jade and custom themes must obey this policy. New application interfaces, installer text, dialog controls and window captions must use the same family.

## Implementation status

- Theme policy: source implementation enforces `Noto Sans KR`, including custom-theme parsing. Independent review and actual system execution are separate acceptance requirements.
- Existing shell renderer: `integration/shizuku-font/shz_text.c` still uses a one-bit, fixed-width Noto-derived bitmap. This does **not** satisfy the requested visual change.
- Existing GDI renderer: `shizukudos/win64/dlls/gdi32/gdi_text.c` still uses an ASCII VGA bitmap and ignores requested font faces. Requires refactoring.
- Reusable font infrastructure: pinned FreeType sources/module configuration, Wine font registration adaptation, WebKit directory-based font manager and FreeType guest check already exist. Extend them; do not introduce a parallel font engine.

## Required behavior

Use genuine Noto outlines where the existing font runtime is available. Text measurement and drawing must share the same glyph advances. Latin letters must keep proportional widths; Korean syllables must retain complete coverage. Antialiased coverage must blend with the actual destination background and respect clipping. Keep font-source hashes and original license text with generated or shipped data. Never advertise support solely because a face string is present.

The renderer must fail or explicitly report unavailable capabilities instead of silently claiming Noto while drawing the VGA face. Guest acceptance must include real shell text, menus, files, installer/dialog text and window captions. Host previews, compilation and face-name checks alone are insufficient.

Current installed ISO `9cacbe59590cd2bedbd63b156ebb8e38fd70ed87789054a81f0af6dcccd47ae1` predates this change. Its completed installation is not evidence of Noto rendering.
