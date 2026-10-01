# VLC KernelEx configuration admission

The cold Windows 98 GOP trial
`build/shizukudos/csm/run-win98-gop-vlc-qt-v8-20261001T0137`
verified the installed Core and three provider hashes, but KernelEx still
reported `DCFG1`, with flags `0x80`, for the Qt plugin, Notepad++ and the newly
configured diagnostic. The diagnostic rejected this mismatch. It created no
Qt worker and established no native Qt load or VLC GUI acceptance.

The earlier review of `ApiConfiguration::merge` omitted its caller.
In the pinned KernelEx source `31cdfc3560fc116637ee8ed7be31b12f3aacf5d1`,
`ApiConfigurationManager::parse_overrides` converts the INI module name to
`module + ".DLL"` before calling `merge`. Both named and ordinal routes use
that transformation. Thus `KERNEL32.Function=provider.0` requires the exact
provider declaration `KERNEL32.DLL`. A normalized inventory entry does not prove
that the raw declaration matches.

Changing the new providers to bare names was an incorrect fix. The frozen
providers, Core, prior reviews and native failure remain preserved. The six
older NPP providers already declare complete DLL names. All three new VLC
providers, including the process provider, need complete DLL declarations in
the next candidate.

The independent selector finding remains valid. After finding a module,
`merge` uses `lower_bound` to find a symbol, then advances by the numeric suffix
to another declaration of that same symbol. The suffix does not select the
module table. A unique GDI32 or USER32 symbol therefore uses `.0`, even when its
module occupies table 1 or 2.

The current Core preparation gate validates complete raw DLL names and the
same-symbol variant. It also follows the real configuration enumeration: the
loader stops at its first missing numbered entry, and an inherited profile
must already have loaded under its exact name. Its 23 regression tests include
those failure cases. The additive correction receipt is
`build/root-vlc-kex-full-chain-correction-20261001T0153-v1/result.json`,
SHA-256 `fe7c9018a5b93c30a06cb4bc5467a7c10bf8743f195d41ab15694f6db699bfbf`.
It explicitly invalidates the prior bare-name admission model without altering
its original receipt.

The corrected candidate is now frozen in
`build/vlc-kex-fullchain-trial-20261001T0343-v4/manifest.json`, SHA-256
`872106f97ac0f5e032ebb1ad13c6c18ac995d9a0d10762ef3d027bf1c8f8226f`.
Compared with the failed bare-name trial, only the three provider DLLs and
their hash-bound installer changed; the other 43 staged files are identical.
In particular, Core remains byte-identical at `934b1652...`. The new evidence
is the complete caller protocol and all nine real compiled provider tables,
not a different Core hash or native configuration acceptance.

Root re-read the compiled tables, regenerated the exact merge, and verified the
47 assets and Qt bindings in 253 checks. An independent peer verified 677
source, original-package, import and protocol checks. The Qt v9 diagnostic
retains the entire v8 C implementation, its 653 imports, and its strict runtime
profile, NULL-handle, registry rollback and child OS-exit requirements. These
host reviews release the candidate for the native trials below; they establish
no Qt load or VLC GUI result.

The next native gate requires a fresh private installation of the corrected
three providers, all nine compiled provider table records, the resulting Core,
and a subsequent cold boot. KernelEx must report the exact `WINXP` profile and
flags `0x80`; registry type, value and length must remain exact. The diagnostic
must then observe a non-null native Qt load, inspect all 653 imports, release its
owned handles and report the real child's wait and OS exit. Even a successful
resolver diagnostic does not establish a usable VLC window, normal player exit
or audio playback. Previously observed native video and 94 direct API controls
remain separate evidence.
