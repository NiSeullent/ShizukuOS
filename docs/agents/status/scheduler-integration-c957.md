# c957 finite aging integration and preserved boundary failure

Reviewed canonical source `644c94ff17b45e28961135f76667188624c283da` was
consumed as the four exact arch.c, k64.h, sched.c and pma_tests.c files in
c957 commit `fcb36a0b3d9b025d8fd57018a4bed042ff828a7f`. The sampler guard
and independently reviewed d08e1cb empty-relocation DLL repair remain present.
All execution below is standalone UP component evidence with the pinned
historical Win64 fixture. It does not execute Windows98/VMM/VxD/Supervisor/SMP.

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

## Independent canonical failure remains open

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
source inventory to213. The212-source receipts above remain valid at their
frozen fcb36a0 epoch and are historical for future complete-tree builds. The
helper alone changes no runtime API, object or scheduler behavior.
