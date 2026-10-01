# VLC 3.0.24 native compatibility checkpoint

The official 32-bit VLC archive is staged for a bounded GUI and local AVI/WAV
playback trial. Archive identity is SHA256
`8511356afd680817f3aea624c63032d0936f3d77b2175fb36c8fc16adf9744e8`.
The preparation receipt and original archive remain private under `build/`.
There is no VLC application or playback success claim before native execution.

Three new project providers address fourteen missing API names found against
actual Windows98 system exports and the compiled KernelEx providers:

| Provider | APIs and implemented scope |
| --- | --- |
| M98VLC | Real native system information and file seeking; explicit unsupported heap features and memory-font handles; real file-font removal with lossless Unicode conversion; real superclass-aware window class lookup |
| M98LOC | Factual geographical lookup, actual configured user geography, actual installed UI language and native NLS language-group decisions |
| M98CTX | Actual self-process ID and debugger query, real KernelEx thread opening, and assembly capture of original caller x86 context |

Arbitrary process handles remain unsupported on the installed KernelEx build
because its generic object/access/locking exports are absent. Geography is
never inferred from the Korean OS language. Heap features unsupported by Win98
are not reported as activated. Coordinates, timezone and localized geographical
names are not synthesized. Export presence is not proof that Qt or playback
accepts these bounded contracts.

M98LOC reads the existing user geography registry values without modifying
preferences. If no valid value exists it returns GEOID_NOT_AVAILABLE. UI
language uses the existing ResourceLocale value or unambiguous installed
USER.EXE version translations; it never defaults to US English. The native-NLS
fallback for language groups establishes native locale availability, not
installation of every font. Its portable parser/lookup/backend controls passed
52 checks under AddressSanitizer and UndefinedBehaviorSanitizer; actual
Win98 registry, UI and API probes have now passed in the separate direct
provider suite described below.

The 301 GEOID records are factual data extracted from the pinned Wine11
`tools/make_unicode` geoids array and pinned ISO3166 facts. Neither upstream
generator nor downloaded source is executed. The original Wine source carries
Alexandre Julliard's copyright and LGPL2.1-or-later attribution; only literal
IDs, classifications and country codes are extracted. Project implementation
and extraction code are GPL2.0-only. The production table is reproduced exactly
by the project generator:

```sh
python3 tools/generate_vlc_geo.py \
  --wine build/app-prerequisites-20260930/locale-source-wine11/make_unicode \
  --iso /usr/share/iso-codes/json/iso_3166-1.json \
  --output build/vlc-geo-reproduction-NEW/m98_vlc_geo.inc \
  --verify src/m98_vlc_geo.inc
```

The two input SHA256 values are
`f0284d8eee7f213cb5ff1db1264fd90d689fe3a36358451574a0511fa019e637`
and `f01b812b57fba9f31ff621bf33e7c7570a01964dbeb5be2167e94decf538c89f`;
the exact output is
`1c904784993be2bdbf92ee0cdd65f4a1f4da60957e28605ee90fec63504808e6`.
The verified reproduction receipt is
`build/vlc-geo-reproduction-20260930-v2/m98_vlc_geo.receipt.json`.

Native diagnostic probes directly load their exact providers from a private
VXDLAB directory. A suite records actual process creation, waits and exits.
These probes do not install providers, alter CORE.INI or claim VLC execution.

The actual Windows98 GOP suite passed33compatibility,26locale and35context
checks,94total. Its native supervisor independently observed all three child
waits and process exits0. Native UI language0412 and absent configured
geographyFFFFFFFF were read without preference changes. A genuine file seek
produced the exact13-byte file, and the temporary copied font was added,
removed and deleted, with absence checked before and after. The nineteen-gate
scoped review is
`build/shizukudos/csm/run-win98-gop-vlc-native-api-20260930T1830/native-vlc-api-review.json`,
SHA256 `e50eab7a4eac320778fd78490211451c1e9abd08bfbef8f8727fc6bc25b36bc7`.
The original runner status remains NEEDS-VISUAL-REVIEW. The suite executable
selects its own exit code in source, but that outer OS exit was not separately
observed; only the three actual child exit results are claimed. The app, CORE,
COM and original font files were independently checked unchanged.
Any timeout or forced cleanup remains a failure. VLC application setup and
real GUI, video frames, audio output and normal exit need their own trial.

The guarded CORE helper now permits nonzero API-library table indexes only
when exact compiled provider metadata proves the module and symbol at that
index. The original .0-only plans retain their behavior. Eighteen regression
controls and a real M98VLC binary merge verified KERNEL32 table0, GDI32 table1
and USER32 table2 without executing the DLL. Wrong-module/name/ordinal/index
and changed binary hashes fail before output. This prepares a configuration;
it does not establish guest installation or VLC application success.
