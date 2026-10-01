# Win98 script and actual-MSHTML child observers

The original GPL-2.0-only observer derives this project's reviewed single-child
TLS supervisor without changing that source. It creates one fixed native child,
records its actual DWORD exit through WaitForSingleObject/GetExitCodeProcess,
checks output flush/handle closure, and limits timeout termination to that exact
CreateProcess-owned handle. It requires actual Win98 SE platform1/4.10/build2222
and its exact own executable path. All output paths must initially be absent;
logs use CREATE_NEW. A raced/stale output prevents child execution.

| Profile | Observer | Child | Observer log | Child stdout | Child semantic log | Wait |
| --- | --- | --- | --- | --- | --- | --- |
| Runtime only | M98JSRUN.EXE | QJS13PR.EXE | JSRUN.LOG | JSOUT.LOG | QJS13.LOG | 60s |
| Genuine MSHTML host | M98AURUN.EXE | M98AUTPR.EXE | AURUN.LOG | AUOUT.LOG | AUT13.LOG | 240s |

Every path is below C:\\GOPLAB. Timeout reaping is bounded by another5s.
The Automation deadline accommodates the actual fixture's180s input wait and
display/cleanup interval. Each observer reserves2MiB and commits64KiB of stack;
the child/runtime's independently gated512KiB commit is a separate process
stack. Neither observer loads the script runtime or executes document code.

Build a fresh, preserved receipt with:

```sh
python3 tools/build_trident_guest_runner.py \
  --build-dir build/trident-observer-NEW \
  --nonce trident-UNIQUE-TRIAL
```

Frozen v2 is build/trident-observer-v2/result.json, SHA256
7b1e29758d8df087054e3ddf502b7282b2e01ed214eee946f8bddc70a8d54206.
The actual observer control flow passed3022 script and3031 Automation
OS-double assertions across18 fault scenarios per profile, normally and under
ASan/UBSan. The two native PE32 GUI4.10 artifacts pass original installed-OEM
import, relocation, stack and inspected i486 instruction gates. Five current
and frozen source digests, two artifacts and twelve step logs were independently
rechecked. Original v1 remains a separate historical receipt.

These are build/control-flow results. Native execution has not been measured.
An empty fresh stdout file is legitimate because both fixtures write their own
semantic log. The requested supervisor exit is logged before its final flush,
close and ExitProcess; its actual process exit requires an independent outer
observer. Child exit0 alone does not prove the semantic log's checks, trusted GUI
input, painted Korean text, browser navigation or full web standards.
The canonical cold-clone harness, exact stage manifest/source/artifact pins,
fresh semantic logs and independent GUI capture review remain separate gates.
No VM, global registration, provider installation or service change is performed
by this builder.
