# c957 finite aging integration and preserved boundary failure

Reviewed canonical source `644c94ff17b45e28961135f76667188624c283da` was
consumed as the four exact arch.c, k64.h, sched.c and pma_tests.c files in
c957 commit `fcb36a0b3d9b025d8fd57018a4bed042ff828a7f`. The sampler guard
and independently reviewed d08e1cb empty-relocation DLL repair remain present.
Execution below is standalone UP component evidence. The full151-app regressions
use a pinned historical Win64 fixture; the current two-DLL API probe is separate.
These guests do not execute Windows98/VMM/VxD/Supervisor/SMP.

Four-profile build passed at2026-10-01T21:25:29Z in130.50 seconds with212
source identities and both build helpers stable. Receipt:
`build/pma-c957-kernels-aged-final/kernels-build-result.json`, SHA256
`8924ccade30db7cb74ae8d2d451bd661afc52dfa85b382e2214677b375abea50`.
Kernel64 SHA256
`ee92a58c07d1c29015507a1ca2eb7d877e4bb2f7d0b07c1d8dc91aa8e0476c1f`;
Kernel64 standalone SHA256
`745adc4cd4e079d25aaa41433f52d4dd1f9bcbe98027b2513ed4c9fe34073947`.
The previous loader-successor artifacts remain preserved separately.

Fresh focused KVM receipt `build/pma-c957-k64-pma-aged-final/result.json`
passes11 evaluator checks and35 scheduler assertions in1.46 seconds, QEMU
exit1. Fresh full receipt `build/pma-c957-pma-bridge-aged-final/result.json`
passes38/38 checks at2026-10-01T21:30:00Z in216.49 seconds, QEMU exit1,
without timeout. Result SHA256
`fb21dba77d3878ee8a54559d7edaa80a886ba8175380809d334a245d0d18cc06`;
serial SHA256
`819d6a73e5eae66445e5cdb4f0e47fefbc1675b71efa8b7b2d8bf4219335bec8`.
Independent review checked all212 sources,8 direct inputs,5 runtime helpers,
four profile artifacts and the complete serial. All151 archive-derived EXE
fixtures exit0/faulted0, including T_GUI_STATUS and archived WinMM. The35
scheduler assertions and48 total loopback checks pass. The latter are
**32 legacy Win64 plus16 PMA**, correcting older wording that double-counted
the PMA checks as additional to48 legacy checks.

ROOT useful-progress counts are865193/832296; refresh updates2410633,
first-ready residence32, useful loops2070564. The grant-arrival gate observes
wait4/remaining4. Aged workers begin at33/34/35 ticks and each run2048 loops.
Software interrupt controls remain explicitly software-only; this does not
establish an arbitrary interrupt-burst or SMP guarantee. The archive is the
unchanged historical component fixture SHA256
`a098a49fdf686973d5246f74e7f61d8257afced11ab28a11a7f4bd47c0dc7a7e`,
source epoch6d860bf, built18:39:22Z. No fresh Win64 runtime build is claimed.

## Historical canonical failure and reviewed successor

Canonical163f's fresh full guest at21:33:38Z has the identical212 source and
five helper identities but different compiled artifact identities. Its
`build/pma-integrated-native-successor-20261001/result.json` is FAIL:
151 apps pass,34 scheduler assertions pass, one fails, leading to three
consequential evaluator failures. Result SHA256
`6f0588032000a1a74bda1516e2a820825933f3ef7b517cae9b796a45c7f311d2`;
serial SHA256
`43bdb7c502aeea8d8dcda1921f22b008a223368639f3d01c45cee64484062ecd`.
Its actual arrival wait5 exceeds remaining4. Printed `terminal=0` is the
composite grant-arrival predicate, not worker termination.

The owner's production-C modeled-boundary control reproduces5/4 when the
coordinator stays READY and4/4 when it is BLOCKED; another aged thread can
interfere with this fixture. Diagnosis receipt SHA256
`8adc2d397b3bf6e1a7a68535cc2e0b367b2d74c5becc992964956c2abff183e5`.
This supports a possible mechanism but does not attribute or close the real
guest failure. Canonical163f retains correction/rebuild/acceptance ownership.
ROOT does not weaken thresholds, add a competing fix or erase either receipt.
All three earlier ROOT whole-guest failures remain unchanged.

The subsequently added, unused nt_sched_policy.h extends complete kbuild
declared source inventory to213. The212-source receipts above remain valid at their
frozen fcb36a0 epoch and are historical for future complete-tree builds. The
helper alone changes no runtime API, object or scheduler behavior.

Canonical now supplies a reviewed code-only successor `b5c49d873990bebdf7611fbccb03f3757dbbf874`. It changes only pma_tests.c and the owner's status note. The coordinator blocks on its completion semaphore while the real PIT dispatcher measures first selection. A bounded passive observer records coordinator state, remaining grant and low-thread charges. The original arrival<=remaining>0<=4 and40/80/useful-work thresholds remain unchanged.

The independent reviewer rehashed the actual full successor receipt
`/root/Win98-Modern-pma-20261002/build/pma-integrated-native-arrival-b5c49d8/result.json`: SHA256
`c72cc80a6135c67dcb0e323d89c0a5796c7fad97816cddb2b552b9ed42e1ecd2`.
It passes38/38 in210.27 seconds, QEMU exit1/SHZEXIT0, with151 apps exit0/faulted0,35 scheduler assertions and32 legacy+16 PMA loopback assertions. First selection is wait4/remaining4/low charged4, coordinator BLOCKED1/completed1/body delay0. Serial SHA256
`ee2239521342a0293188b0a82028a7505b490994c5a54c5390f3b5be515ff1a8`.
All212 source inputs, five runner helpers, four BIN/ELF profiles, two stubs and nine tool pins match the frozen producer/archive. Evidence archive SHA256
`f50c0b80767771085a18f4266834df88a7c85516675f42b9dfd3f90db96e911d`; build receipt SHA256
`b60125bca41dacdf5cbc466b385ccd5d2dad2d7f9e02889833d0e361e8f64080`.

This closes the successor's isolated UP arrival acceptance. It does not attribute the original natural PIT sequence or establish a global arrival bound, real Windows98/VMM, SMP, Supervisor, a fresh Win64 runtime or final ISO. All original natural/injected RED and ROOT failures remain preserved. ROOT imported only exact pma_tests.c in2d429dc, SHA256
`6761e4cd35de1672406e01dc356303fa84773baf71096fe3fd3a15391f9fed3b`, retained its stronger fresh-output guard, and produced the distinct214-source proof below with the separately reviewed NT API changes.

Before rebuilding, ROOT preserved the old fcb36a0 ten actual BIN/ELF/stub artifacts (3,592,806 bytes) in `build/pma-c957-kernels-aged-artifacts-frozen/`, with exact receipt and archive map SHA256
`8d5976b320edf59e54037c51edd2089589d7907f7beaac1c8df9465b55c596fc`. No previous receipt or serial was overwritten.

A later actually isolated213-file build exposed an inventory gap: pe_parse.h was omitted by kbuild.source_hashes despite real includes in ldr/ntdrv_ldr/pe_parse. Previous212/213 complete-source claims refer to the declared map and do not include that header. Raw old execution/artifact results remain retained, with this qualification; the independently reviewed899bf2e inventory correction and217-unit compiler-dependency regression precede the new frozen build below. NT249-header and targeted frontend320-input receipts already capture this header.


## Current214-source build and separate guest outcomes

Source899bf2e explicitly adds win64/pe_parse.h. Strongest closure receipt `build/pma-c957-kbuild-closure-green-v2/result.json` SHA256 `0cf4e116690312154aa05566c190b1b92d1366b05a46ebc127858d44b2412e4f` independently captures LIVE C selections, compares frozen selections and executes217 actual GCC -MM units across K32/K64/K64S/K32S and both boot stubs. All214 inventory entries,390 source pins,607 artifacts and compiler identities remain stable. Header-byte mutation changes exactly its inventory hash; an injected proc.c inventory omission is detected by both selection and compiler dependencies. Original213-map RED SHA256 `2aefc6dca7281347e373793296b7c7e23a9d915a3c56804ede8fefffd50effe1` remains unchanged. This proves C preprocessing/local dependency coverage, not assembly/link/runtime behavior.

Separate actual frozen four-profile compilation passes109.48 seconds. `build/pma-c957-kernels-nt-arrival-v2/verification-result.json` SHA256 `f48cc589bb501d0bbea4c9911bf6a3fd0aca5d9712d3cd1425c15e92f3bea41e` binds214 live/frozen sources, seven tools, driver and ten generated artifacts; build receipt SHA256 `ed3796a7ddc32cd0813b40a2cbe5b7aead7dd6e98adaeeb87432a607c1d5f47b`; source archive SHA256 `9ad5dbddc82b016b50d6a14008b78ec1897ff66d6ad76883984714965a1a72ff`. The snapshot was captured at2d429dc with the one inventory fix then uncommitted; its exact source bytes subsequently match899bf2e. Dirty-tree metadata is retained; commit labels do not replace source-map provenance.

| Profile | Bytes | SHA256 |
| --- | ---: | --- |
| K32 |24804|`58a6683fa05779ef3bef483298dd1b220be2bfb564294ea84b43fe1b2953888f`|
| K64 |750928|`4b55442f27502b3be637d8d9f3f9dbefc07004b8fb2296394c1776b0e4cbd91c`|
| K64S |849242|`091b58674f0d9f1ddf823f57c8a5b712450c1cef3ac61fc939c39e0c0a4b7e19`|
| K32S |27172|`205534bf0d72f347682c7051cc214d9b85d5a3065ad050a557921a33c1eb35a9`|

Only ROOT's ten standard kernel BIN/ELF/stub files and build receipt are promoted, with old copies preserved. Promotion map SHA256 `01b0c2423654ca50158173cc850aff54189198332689f390d2d813b666e7c197`. WIN64.IMG remains unchanged. K32 code semantics did not change, but absolute snapshot __FILE__ paths change its binary bytes.

Fresh focused KVM passes11 evaluator gates/35 PMA assertions; receipt `build/pma-c957-k64-pma-nt-arrival-v1/result.json` SHA256 `e5ab2f0087adec7811ec29225d36a025cc752e1306cc19ce101adfeb691a98c8`. Useful work625580/237577, arrival4/remaining4/low charged4/coordinator BLOCKED1/completed1. The first bare K32 KVM record passes nine checks, exit0/marker4b333221/44preemptions; receipt SHA256 `587d2fc7d4d8feff230f475f21725f945e1ce55842640f9b351770b2e6d9407f` has no per-run source/artifact guards. That gap prompted one separate frozen-artifact run: `build/pma-c957-k32-nt-arrival-guarded-v1/result.json` SHA256 `97f6b710cbb2426a2abb4efa21bd230d199caaae17d7e52c493c804eaf23bf21` passes nine raw checks and four outer provenance/exit gates in0.3 seconds/QEMU1. All214 live plus214 frozen sources and454 total producer/tool/artifact/runner/driver identities match before/after. Raw result and serial remain separate, unchanged evidence; no rebuild occurred.

Full fresh historical-archive regression `build/pma-c957-pma-bridge-nt-arrival-v1/result.json` SHA256 `cad0a54f053594d366cc144c23ef4504bc396c9465847f1fc8532a07c0e27723` passes **38/38**,226.46 seconds,QEMU1/no timeout,214 source/8 direct/5 helper inputs stable. Raw serial SHA256 `beec3efabf64ff0827f321d50b638b5890973e54fd20e8de48d971e65c58ffff`. All151 ordinary EXEs exit0/faulted0;35 PMA assertions and48 total loopback assertions (32 legacy W64+16 PMA) pass. Useful work737762/560851; arrival4/remaining4/low charged4/coordinator BLOCKED1/completed1/body delay0. The archived runtime remains source6d860bf and is not a current runtime rebuild.

The distinct four-member current-DLL priority probe executes321/0 API checks, but **its whole guest FAIL remains open**: first PMA low useful work361<1000, second148315, QEMU3. API receipt SHA256 `f0434fbdcbd4b31baa35ad41b470dd3ff1d426be248d52ab711088fd0c4ae63d`. The earlier PMA failure precedes user API calls; source/evaluator/artifact gates remain stable. A different fixture's passing full regression does not erase this failed run. Existing source/logs are under bounded independent diagnosis; no natural PIT/IRQ cause is established and no blind rerun or threshold change is authorized by these outcomes. See nt-runtime-priority-c957.md for actual API/archive scope.

One separately reviewed diagnostic-only clone captures602/605 records and320 paired IRQ/tick entries, but original first361 failure does not reproduce; later two useful-work predicates fail and remain preserved. Its capture PASS is explicitly not production acceptance. See [pma-spin-witness-c957.md](pma-spin-witness-c957.md) for exact source/receipt identities and the observed flat committed-loop grant. No production source or previous evidence changes.
