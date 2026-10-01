# DOS Windows initialization build proposal

This is a source-only, one-path proposal for the existing DOS runtime builder at commit `8508c5e360fe8c24c659b719f1ed21831cbdbd4c`. ShizukuDOS is intended to replace MS-DOS under actual Windows 98. Kernel32, Kernel64 and Supervisor are components for that Windows 98 installation. These compiler fixtures do not complete that integration.

The existing builder writes only `XNASM=nasm` and `undefine XUPX`, so its patched Windows initialization/DOSMGR code is compiled out. The pinned FreeDOS parent makefile exports variables after including `config.mak`; Watcom derives CFLAGS from ALLCFLAGS and assembler rules use NASMFLAGS. Both definitions are required. The proposal adds these by default, preserving the current output location consumed by the installer/ISO builder:

```make
ALLCFLAGS=-DWIN31SUPPORT
NASMFLAGS=-DWIN31SUPPORT
```

The same patch records the exact configuration text, physical SHA256, and C/assembly definition lists in `build-result.json.kernel_make_config`. It refuses configuration changes during compilation. It adds no command-line option, output profile, ABI, image installer, or emulator behavior.

Only `shizukudos/dos16/build.py` changes. Its reviewed original SHA256 is `1ece1260ccfc5271a225331d70a8c91c31a28e5c413d15921edc1a293be875df`; the candidate is `bec1b7bd9433c0be86a1ca1b22d59ac220e71762d4b4c78c56f28a38caaee68b`. Patch SHA256: `a3b60e86f15341a0673c0721798353e5cd2eb806fdb583a3f66e5ca11cfe2ba8`. A changed builder needs a new reviewed rebase epoch. Do not refresh hashes to accept unrelated source.

Six actual-production-function tests pass. The immutable original builder produced four failures and two passes. The fixture executes the production `build_kernel` and `main` AST functions; full upstream copying/patching, full kernel linking, images, FreeCOM and external build boundaries are substituted. `main` really constructs the receipt; its test images/artifacts are explicitly fixture-only placeholders.

The independent compiler probe executes the genuine FreeDOS parent GNU makefile, its `export`/config inclusion, genuine Watcom make rules and actual Open Watcom/NASM tools. The C fixture includes the real `portab.h` and `win.h`, checking the 22-byte header structure and 14-byte patch table declaration. The assembler fixture compiles the exact WIN31SUPPORT-gated excerpt of `kernel.asm`. Actual positive outputs are two OMF objects (654-byte C, 357-byte assembly), recorded in evidence only; binaries are not included here. Removing the C flag fails real header compilation. Removing the assembly flag fails the actual assembler gate. These probes are tiny compile checks, not a kernel build or link.

The raw upstream assembly startup record and its C header have a Win95 optional-field difference. This proposal does not fix that layout. The separately reviewed combined CB43/DOSMGR patches and an actual Windows 98 test remain required. Enabling WIN31 hooks does not establish Windows 98 loader/VMM/GUI, MS-DOS replacement, or any modern application compatibility. No VM or private Windows media was used here.

An intermediate test-fixture revision appended its extra target to the parent makefile, then correctly failed three consumed-source-after checks. The final fixture uses a separate `-f shz-parent.mak`; all seven original FreeDOS files remain unchanged before/after. `fixture-failure.log` preserves the failed revision instead of relabeling it as a production failure. Baseline failures retain their original runner provenance in the evidence.

For a source-only rerun, obtain the project repository and a FreeDOS kernel Git checkout containing commit `5ffb5502d39a10a30f5b8a9e8beeba0bf30245d3`. Use an existing Open Watcom snapshot containing `binl64/wmake` and `binl64/wcc`; no dependency download or installation is performed by these tests. The actual tool hashes used are in `evidence.json`. Install GNU make and NASM at `/usr/bin/make` and `/usr/bin/nasm`. Keep at least 17 GiB plus 4 MiB free. Copy this report's payloads into a fresh owned directory outside source trees, then prepare only immutable source blobs:

```python
# Run from the fresh copied report directory. Set these explicit local inputs.
project = "/absolute/project-checkout"
freedos = "/absolute/freedos-kernel-checkout"
from pathlib import Path
import hashlib, json, subprocess
pins = json.loads(Path("inputs.json").read_text())
def export(repo, revision, relative, destination, digest):
    raw = subprocess.check_output(["git", "-C", repo, "show", revision + ":" + relative])
    assert hashlib.sha256(raw).hexdigest() == digest
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
export(project, pins["source_commit"], "shizukudos/dos16/build.py",
       "source/shizukudos/dos16/build.py", pins["builder_sha256"])
for relative, digest in pins["upstream_sha256"].items():
    export(freedos, pins["freedos_commit"], relative, "upstream/" + relative, digest)
subprocess.run(["patch", "--batch", "--fuzz=0", "--forward", "-p1", "-d", "source",
                "-i", str(Path("proposal.patch").resolve())], check=True)
assert hashlib.sha256(Path("source/shizukudos/dos16/build.py").read_bytes()).hexdigest() == pins["candidate_builder_sha256"]
```

```sh
SHZ_TEST_WATCOM=/absolute/open-watcom python3 test_win31_profile.py
```

The tests compile bounded fixtures under their own temporary output directories and remove those temporary files. They do not execute the full builder entrypoint, start an emulator, copy an installed disk, or publish anything. Future full DOS conformance/native Windows evidence must be recorded by the primary integration owner under the consumed final source epoch. The existing separately recorded 17 actual DOS guest checks are evidence for that earlier combined kernel; they have not been rerun for this source-only proposal.
