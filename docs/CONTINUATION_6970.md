# Theme, graphics, DirectWrite, TLS and apps: continuation checkpoint

This is a development checkpoint from 2026-10-01. Publication of the source
and a bootable development ISO is separate from completing Windows 98 Modern.
The required system themes, full DirectX/Direct2D/DirectWrite, modern Office,
Legcord/Discord, Signal and OS-wide TLS 1.3 remain active goals.

The user's original architecture, reaffirmed on 2026-10-01, is that
**ShizukuDOS replaces the MS-DOS foundation of Windows 98**. Kernel32 and
Kernel64, the firmware, wrappers and graphics components all serve that
Windows 98 system. An isolated boot or runtime test records an experimental
boundary; it does not establish completion of the DOS replacement or Windows
98 integration. Preserve that distinction without changing the product goal.

Use the repository-wide [official delivery guide](OFFICIAL_DISTRIBUTION.md)
and [new machine guide](CONTINUE_ON_ANOTHER_MACHINE.md) after integrated
`main` is supplied through the official website, https://m98.nyase.kr.
Record the actual source commit and start a new `codex/` branch. Old
`/root/.../build/` paths in receipts identify historical private artifacts;
they are not files supplied by a source archive or Git bundle.
Rebuild public sources and generate fresh source-bound receipts on the new host.
Never edit old hashes or weaken a verifier to reuse a relocated trial.

## Windows 98 installation USB

The requested deliverable combines ShizukuDOS, the extension components and
the original Windows 98 ISO inside an installation USB. The original ISO
should be copied unchanged into a writable USB volume. An integrated ISO is
an accepted alternative. The boot path must support the Windows 98 system
with ShizukuDOS replacing its DOS foundation. A Shizuku test workload,
an OEM MS-DOS control boot or copying probe files into an existing installation
does not demonstrate completion of that installation path.

The user supplied
`https://archive.org/download/X03-77968/Win98%20SE.iso`. The actual original
was acquired once, made read-only and verified against the archive's size,
SHA-1 and MD5, followed by complete on-disk SHA-256 readback:

- Bytes: `307714048`.
- SHA-256: `4c1b148bfd8aa9ffa702d6756ffa32064c49bb78c00d074225db5a0f302c0873`.
- SHA-1: `5ddad159382edf71521946085a8e9f78baa1cea9`.
- MD5: `c373a5f7f6fd567bedf3238d51bcb061`.

It matches the pinned Korean OEM source benchmark. The protected original
is `build/private-media/Win98-SE-X03-77968.iso` in the theme worktree;
the acquisition receipt SHA-256 is
`c36e973050edd7bb70937e5d7fbe1d092ebe73fe86230a1e01d5ce185f9311f9`.
These are input-integrity checks, not native installation acceptance.

The existing FAT32 raw-disk producer provides a writable BIOS/UEFI medium,
but the current installation flow still needs original-ISO copying and the
actual Windows 98 setup/integration path. The existing `--win98-media`
option extracts a private overlay; it does not launch Windows 98 Setup.
The OEM floppy inside the original ISO is a reference/control input:
offset `43008`, FAT12 BPB length `1474560` bytes. Use its validated BPB length
rather than xorriso's inferred hidden-image block count. Keep the original
unchanged and verify media copies, actual setup, first boot and component
installation separately. Do not mark the replacement complete from file
packaging alone.

## Component entry points

| Component | Source and evidence guide | Current boundary |
| --- | --- | --- |
| Native Win98 theme | [checkpoint](THEME_NATIVE_CHECKPOINT_6970.md), `ntwddm/win98/theme_composition` | Native v13 pixels/text/lifecycle observed, strict metadata gate FAIL; corrected v14 stopped at disk floor before desktop/child proof |
| AMD64 theme | `ntwddm/win64/theme_provider`, `ntwddm/win64/theme_probe` | Actual isolated Windows ABI and visible pixels verified; global Win98/app themes pending |
| Real Mesa resources | [graphics checkpoint](DIRECTX_GRAPHICS_CONTINUATION_6970.md), `ntwddm/graphics_backend` | Actual private resources/pixels and guest lifecycle verified; full DirectX COM/device APIs pending |
| Wine graphics/compiler | [port guide](DIRECTX_WINE_PORT_6970.md), `ntwddm/win64/directx_wine_port` | 107 genuine AMD64 objects and normal shader tests verified; memory-leak repair and linked/runtime API libraries pending |
| DirectWrite | [probe guide](DIRECTWRITE_PROBE_6970.md), `ntwddm/win64/dwrite_probe` | Real glyph analysis/Latin framebuffer progress; Korean layout/raster and normal exit FAIL/unverified |
| TLS/SSPI | [integration](TLS_SSPI_INTEGRATION_6970.md), `ntwin32/secure_transport` | Real host protocol/lifetime and i486/OEM PE checks; native communication and OS integration pending |
| Required modern apps | [runtime gaps](REQUIRED_APPS_RUNTIME_GAPS_6970.md), [loader comparison](MEMORY_RUNTIME_LOADER_AUDIT_6970.md) | Office requires genuine D3D11/DXGI; Signal has unresolved application startup failure |

Python 3, GCC and Clang with sanitizers, both MinGW toolchains, binutils,
Bison/Flex, FAT utilities, QEMU and matching firmware are component-specific
prerequisites. Follow each guide's explicit upstream commit/archive hash,
licenses and actual command arguments. The private runtime/font/native-media
prerequisites are different for each test. A checkout alone does not supply
licensed Windows installation files or app payloads.

A small source-only verifier can run immediately:

```sh
python3 -B -m unittest discover -s ntwddm/win98/theme_composition -p 'test_*.py'
```

The publication recheck passed all 14 of these builder/verifier tests. Host
and parser checks do not constitute a new Windows 98 trial. Read skip counts
in other suites: historical fixture or compiler-dependent cases may skip on
a fresh host, as documented in the DirectWrite guide.

## Private evidence and resource handling

Keep original VM/media and failed/successful receipts intact. Use a private COW
per native trial, a fresh output directory/nonce, no uncontrolled parallel VM
writes, and independently check KVM descriptors, final pixels, source hashes,
normal child exit and reaping. Keep the unchanged 20 GiB free-space floor,
256 MiB private write limit and 16 MiB host output limit. Budget additional
room for source closures, compiler outputs and ISO staging before allocation.

A separate disk optimizer recovered exact allocated blocks without deleting
originals, source/license trees or VM evidence. The latest bounded cache pass
reclaimed 50,470,912 bytes; it is not credited with unrelated global free-space
changes. Its historical checkpoint SHA-256 is
`9010e7368d7cec9fedaacb8a06c69288001340a24f1fc1db7dc35d9f396e1925`.
The separate four-pair 889,573,376-byte sharing plan was still a potential
estimate at the earlier checkpoint. Subsequent phase 5/6 receipts now verify
all four pairs: **889,573,376 bytes (848.363 MiB)** of actual kernel sharing.
Full logical contents, SHA-256, device/inode/size/mtime and existing final
receipts remained unchanged. The completion checkpoint SHA-256 is
`cb5644882a8ab93e9f60921a9306d9e99c49ce53922a0b0a735accce6a216f35`.
Later phase 7 read-only planning reclaimed zero bytes and did not approve
a new sharing operation. Recheck real free space before each media allocation;
concurrent writes consumed most of the transient additional headroom.

Before reporting a release, verify the exact remote main SHA, ISO source
receipt/member/license hashes, real boot results, published download checksum
and outside-host HTTPS homepage. Loopback success does not prove the public
edge. On 2026-10-01 public-DNS HTTPS requests with a normal browser User-Agent
returned the Korean/English homepages and redirected old VNC URLs to `/`,
but the actual automated Chrome browser and independent web fetch remained
Cloudflare-blocked. A later checker run using the normal Chrome 153 User-Agent
recorded the correct homepage in all four public HTTPS responses, while the
actual browser processes timed out.
Two offline data-URL controls also timed out with no DOM, isolating a local
CLI failure before website access; the exact cause is unresolved. Preserve
the historical Cloudflare block and the later local failure separately.
Outside-host browser and new USB/ISO installation/publication acceptance remain
pending. Preserve these results rather than calling the whole deployment PASS.
