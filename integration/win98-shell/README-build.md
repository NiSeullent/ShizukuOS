# Selective Win98 shell component builder

`build_components.py` compiles/links the theme selector (`SHZTHEME.EXE`) and the
appearance app (`SHZAPPEAR.EXE`) using flag lists copied from
`ntwddm/win98/theme_selector/build.py` and `tools/build_theme_engine.py`, and
reuses `native_gate()` (selector), `pe_gate()` and `scan()` (i486) from them.
Output goes to a fresh `build/shell08-components/<run>/` (ignored, <16 MiB,
20 GiB free-space reserve) with `receipt.json` holding source/tool/artifact SHA-256.

    python3 integration/win98-shell/build_components.py --only selector
    python3 integration/win98-shell/build_components.py --only appearance --dry-run
    python3 integration/win98-shell/build_components.py --only appearance --appearance-source-frozen

Not run: host tests, sanitizers, M98THEME.DLL, installation, any execution.
Receipt status `PASS_STATIC_GATES_ONLY` means compile/link plus PE header,
OEM-import-inventory and i486 byte-scan gates only; no runtime claim. The flag
lists are duplicated, so re-check them if either upstream build script changes.
The appearance build is refused without `--appearance-source-frozen`.
