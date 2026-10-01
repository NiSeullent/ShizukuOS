# Dead Screen: same-C design and game preview

**디자인·게임 미리보기 · 실제 OS 오류 화면이 아닙니다**

This WebAssembly module runs the exact held `dead_screen.c`, `render.c`, `dead_screen.h` and public-domain ASCII font from the private native source candidate. It shows a deliberately synthetic example traceback. It is not a guest capture, kernel crash, Win98/VMM hook or proof of native execution. The preview adapter replaces the native trace heading with **EXAMPLE TRACE - PREVIEW**, the item legend with **T shows example traceback**, and the lower native-halt legend with **design/game preview** in every graphical mode. It makes RGBA alpha opaque. Games, Korean stroke glyphs, item art and ASCII fallback use the real C implementation.

The source bundle contains the corresponding complete freestanding preview source and recipe, original glyph/art notices, GPL version 2 license, exact member hashes and the built WASM artifact. No Windows image, proprietary app, original OS icon, native kernel binary, browser dependency or package installation is included. The decorative Windows 10 checker is not a scannable QR code; all BSOD items are original game artwork.

Build with an installed Clang with wasm32 support, wasm-ld, Python 3 and Node:

```text
python3 shizukudos/dead_screen/wasm/build.py --out build/dead-screen-wasm-new
```

The recipe requires a new output beneath `build/`, copies/pins the exact source subset, builds without libc/WASI/imports/heap, executes bounded actual-WASM controls in Node, and freezes every command/log/source/compiler/module/source-ZIP hash. It changes no site, native kernel, VM, global setting or dependency installation. Clang/wasm-ld versions and SHA256 are recorded; another toolchain may produce another binary hash.

Exports are `memory` and:

| Export | Contract |
|---|---|
| `ds_preview_init()` | Reset the explicit example and game state; 640×480 Korean menu; returns 0 or -1. |
| `ds_preview_input(key)` | One actual C enum key; rejects values outside 0…11; ignored while preview text fallback is selected. |
| `ds_preview_tick()` | One bounded C simulation step; call at about 60 Hz; pauses in text fallback. |
| `ds_preview_render()` | Draw the same C renderer; returns 0 or -1. |
| `ds_preview_pixels()` | Stable byte pointer to the static RGBA8 array, alpha 255 after successful rendering. |
| `ds_preview_width()`, `ds_preview_height()` | Current dimensions; byte length is width × height × 4. |
| `ds_preview_trace()`, `ds_preview_trace_len()` | Stable counted English fallback/example text, not an observed OS traceback. |
| `ds_preview_mode()` | 0 menu, 1 Tetris, 2 Suika. |
| `ds_preview_score()` | Current game's score; 0 on menu. |
| `ds_preview_fallback(enable)` | Preview-only text-design toggle; call render afterwards. Native fallback halts and cannot resume. |
| `ds_preview_set_size(w,h)` | Optional 640×480 or 800×600; other modes return -1 without mutation. |

Keys: 0 none, 1 Tetris, 2 Suika, 3 left, 4 right, 5 rotate/up, 6 down, 7 drop, 8 menu/Escape, 9 restart, 10 KO/EN, 11 trace/items. Input buttons and the persistent Korean preview disclosure are the hosting page's responsibility. The module has no imports and exactly 4 MiB initial/maximum linear memory. It cannot call a host/OS service or read a native framebuffer.

For Canvas, use the successful render's width/height and `new Uint8ClampedArray(exports.memory.buffer, exports.ds_preview_pixels(), width * height * 4)` as `ImageData`. Decode exactly `ds_preview_trace_len()` UTF-8 bytes at `ds_preview_trace()`. The traceback remains immutable across both games, restart, language/item toggle, size changes and text-design toggle. Explicit `init()` starts the same example again.
