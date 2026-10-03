# Fresh live Win98 baseline observer

`observer.c` builds an ANSI PE32 Win98 program, `BASEOBS.EXE`. It checks actual
GetVersionExA platform1/major4/minor10, reads only HKLM Enum Class/Driver for
Display devices, and writes a fresh CREATE_NEW `C:\BASEOBS.JSON`. It observes
raw build number rather than asserting Second Edition or license status from
version alone. It never reads a product key, full registry or system-file data,
installs a driver, edits the registry or overwrites a prior report.

Before registry access it opens `C:\BASENONC.BIN` with GENERIC_READ and only
FILE_SHARE_READ, requiring exactly32 bytes and a nonzero nonce. The same held
handle must supply the same bytes after observation. Version/platform/build
are queried again and must agree. Report contains lowercase64-digit nonce_hex,
observed version fields, Display Enum/Driver entries, observation_only=true,
source_approval=false and Windows98_on_ShizukuDOS=false. The latter flags are
scope declarations, never inputs to an authorization decision. A file holding a
nonce does not establish who issued it or whether this is a fresh owned boot.

Bounded traversal uses max16384 keys/depth8/path256 and60-second GetTickCount
checks. Report writes cap at4MiB and require exact WriteFile byte count. Failed
reads, stale/changed nonce, missing display, wrong registry type, truncation,
version drift, flush/close/write errors refuse. Owned partial report is deleted;
a deletion failure has distinct nonzero exit6. Existing report is never deleted
or overwritten. Exit0 is observation completion, not genuine-source approval.

`build.py --private-out /private/fresh-directory` uses the existing captured
MinGW convention. It retains original and captured source/header/import/tool
read leases through strict compile and full readback; captures actual GCC -M
header graph, builds captured headers with -nostdinc/-isystem, no CRT, i486,
PE32 OS/subsystem4.10 and deterministic zero timestamp. It does not claim a
complete dynamic toolchain/shared-library closure or execute a guest. Private
output, nonce, report and any baseline/media fingerprints remain outside Git.

Run `python3 shizukudos/install/live_baseline/test_observer.py`:7 test methods
execute actual observer C with modeled Win32 APIs across24 positive/negative
modes. The same24 modes pass Clang ASan/UBSan. These are not Windows execution.
`test_peer_credentials.py` additionally executes actual Linux owned children,
Unix stream connections, peer credentials and pidfds; its3 controls are IPC
feasibility only, not a production service or installed-source verifier.

## Concrete producer/service connection

The approved original installation/media lineage remains independently private.
An owner starts a new cold control in its own unit; there is no attaching an old
VM PID/socket, second QMP reader or promotion of a historical saved receipt.
It retains original0400 RDLK/full SHA, FICLONEs a fresh owned clone and verifies
that its report path is absent. Before launch it stages independently source/
tool-approved actual observer bytes and its fresh owner-generated nonce32B.
Only its actual QEMU process writes the clone. The same owner owns Popen/pidfd,
sole QMP and source-bound recipe, observes actual observer execution in cold
Windows, then reaps the owned unit. After reap, its source-pinned FAT reader
checks the fresh held clone report, nonce and observed version/Enum against the
independent live execution and original install/media lineage. Report JSON or
exit0 alone cannot provide that binding.

The current `ff061ee` source primitive is SOURCE_CUSTODY_ONLY; its generic
launch_control waits for a child and has no QMP observer pump. A separately
reviewed launch-own private service must integrate an internal fixed real QMP
control/observation state machine while retaining that source lifetime. It must
not mint Windows grade from a caller predicate/callback. The private verified
service then answers release admission challenges with live source/clone lease
and owner-exit guards through compilation. Existing policy refusal is unchanged.

For exact Linux peer ownership, the controller owns the new keeper's actual
Popen/pidfd and independent source/tool/recipe pins. The keeper connects **after
exec** to the controller's fresh AF_UNIX listener in an owned0700 directory.
SO_PEERCRED on that accepted connection must match its actual Popen PID and
expected UID/GID; pidfd must remain live, and owner-random challenge/one-shot
protocol/deadline must match. The expected identity and path come from this
independent launch context, never request JSON, private hash alone or same UID.
A socketpair created before fork has creator credentials; SO_PEERCRED does not
magically become child credentials after exec. Per-message SCM_CREDENTIALS is
an alternative requiring its own reviewed protocol. Correct peer credentials
remain insufficient for source approval; the private genuine lineage and live
Windows observation are still mandatory. Owner death/reuse/stale replies refuse.

The module does not yet implement that private service/client/production policy
connection, Win98 startup invocation, installed disk proof, default GOP, x64 app
execution or Windows running on ShizukuDOS. No VM was launched for these checks.
A fresh original-DOS Windows control is still a control result, not ShizukuDOS
foundation replacement. User product-key personalization is a separate final
installation operation, not part of this readonly version/Enum observation.

Primary API references:
- https://learn.microsoft.com/en-us/previous-versions/ms961286(v=msdn.10)
- https://man7.org/linux/man-pages/man7/unix.7.html
