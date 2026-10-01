# Actual native PE32 handoff for the Windows 98 owner

The selected hosted build at committed/pushed
`3c15e59ed0cf4e51c2b08cf178e11cc7579a7d75` retained project binaries and
their exact source/proof files. This proves build, ABI, instruction and
transfer properties. Windows 98 loading, credentials, TLS1.3, OS
registration, Kernel64 forwarding, modern applications and final ISO
acceptance remain unverified. Windows 98 is the product OS; ShizukuDOS
replaces MS-DOS. Existing DOS/VMM/SMP and sole main/site/ISO owners retain
their scopes. `native_loader --providers` stays disabled.

## Actual source and artifact

[Run36941495775](https://github.com/NiSeullent/Win98-Modern/actions/runs/36941495775)
/job110633810322 succeeded, including build, seal, upload and read-only
post-upload revalidation. Same-source nonretaining push run36941475511 was
deliberately cancelled and has no PASS claim. Historical run36938006092
at e4abae7b remains its own build proof with zero retained artifacts.

[Artifact11199849976](https://github.com/NiSeullent/Win98-Modern/actions/runs/36941495775/artifacts/11199849976)
is `native-provider-pe32-6970-36941495775-1`. API and actual RAM download
agree on441,427 B and SHA256
`27a76c77ad17ba2f64bd11da1c895fd4311589c64696b81d5f0649da202a2c29`.
API expiry is2026-10-08T23:34:34Z. The artifact URL requires GitHub login.
The7-day retention and immutable archive use the repository's pinned
[upload action](https://raw.githubusercontent.com/actions/upload-artifact/ea165f8d65b6e75b540449e92b4886f43607fa02/README.md).

The exact24 files comprise eight proof/project files and sixteen
source/licence files, relative to the checkout common ancestor. The first
eight reside under `build/native-provider-pe32-6970/actions-36941495775-1/`:
two PE32 files, closed `result.json`, four default/generated `.ld` scripts
and `native-handoff-6970.json`. The sixteen others are the unchanged14
build sources, `LICENSE` and new sealer. Two raw verbose linker captures
remain in the job log/closed receipt and are outside this archive allowlist.
No Windows media, VM image, prerequisite or application package is included.

| Actual file | Bytes | SHA256 |
| --- | ---: | --- |
| NTWPROV.DLL | 15,713 | 21c5272d74b79b7145364ea5d6ab2901985bf76de14a0da333a1a143451ed87c |
| NTWPRB.EXE | 11,639 | 870f25e5f95f728aaa7bb3cec5d00a93e49e0f3864d0ceeed262ac2c16ac0571 |
| result.json | 169,217 | 86bc4d375bd23b2293c1905448905dd5063c1996a1a6bff8f2e4c08807c92e0e |
| native-handoff-6970.json | 12,912 | 47b60774a8e0b7fcd4ec5ac099e56c2f7ea43600fb0924d96a571ae1d76f6c0e |

The new DLL digest belongs to this run and differs from the earlier
fourth-run DLL. No cross-run binary reproducibility claim is made.

## Actual verification and resource boundary

Root and independent reviewers matched38 actual capture digests
(139,531 B),19 zero/reaped/nonaborted commands, unchanged14 source and100
header pins, seven sealer rejection controls and17 recorded successful,
reaped Git queries. Symlink/hardlink cases are metadata-only models.
Individual Git command metadata was not retained; its compact summary is
reported as such. The sixteen committed source inputs total2,120,627 B.

The immutable closed receipt accounts585,882 B; adding12,912 B of new
manifest yields598,794 B. Build/sealer minimum observed free space was
91,840,344,064/91,838,160,896 B. Upload boundaries observed91,838,681,088 B
before and91,839,148,032 B after, giving net growth0 B. A free-space rise
is not cleanup credit. These checks establish no quota, continuous minimum,
transient peak or complete upload-action lifetime attestation.

Root and the independent consumer held/rehashed the ZIP before/after,
verified exact24 paths, contiguous local records/central directory,
bounded sizes and every CRC/SHA without extraction or execution. The
uncompressed total is2,372,882 B. Actual full PE hashes match this run;
root also matched executable VirtualSize bytes against its continuous
instruction proof (DLL3728/EXE1276). Independent consumer, resource and
focused instruction/script reviews are CLEAR. The focused reviewer
reconstructed both linker transformations from literal bytes, checked six
actual retained COFF symbols and readonly .rdata 8+8-byte tables, and
matched every captured objdump byte/address to the real executable sections.
No reviewer extracted/executed the binaries or reran the decoder.

Immutable RAM proof directory:
`/dev/shm/win98-hosted-provider-pe32-handoff-6970-36941495775`.
Raw613,593 B SHA256
`f347cad3093c7ec71b152a8013bcedb550e66ced337b1b7fb37f02f755650d78`;
preparation2519 B SHA256
`3c7971be46bf53bffaa7ffeb884d05940baa59aa711044158854b02dcc1fad85`.
The compiler-binary ZIP is excluded from the FADA6970 evidence-only NAS
lane. Earlier immutable RAM gates and NAS archive stay historical.

## Consumer and runtime contract

The native owner admits its own binary working space, verifies actual
API source/run/artifact identity, whole archive SHA, exact24 paths and
every inner size/SHA before adoption. Producer absolute paths/inodes
describe the hosted machine; a different machine compares content hashes
and its own file identities. Hosted-only `--verify-existing` is not a
cross-machine verifier.

The current probe creates fresh `C:\VXDLAB\NPVPRB.LOG`, loads
`C:\VXDLAB\NTWPROV.DLL`, resolves three stdcall exports and performs14
cases across five required legacy providers. The owner must independently
build/prove and supply all five providers. This probe does not invoke
SSPI credentials or TLS1.3. Existing `wait.c` was not built in this proof;
use a proven fullDWORD observer or separately build and gate it. Fresh
runtime/media identity, complete NPVPRB.LOG and NPVEXIT.LOG are required
for execution acceptance. Preserve the canonical owner's fresh ordinary
DOS producer/boot-profile gates and current loader policy.
