# Local host validation

All commands ran from `/root/Win98-Modern-boot`. Output was isolated in
`build/steam-socket-c009/`; no download, install, socket connection, VM,
provider registration or service change occurred.

| Check | Result |
| --- | --- |
| GCC C99, `-Wall -Wextra -Werror -pedantic -O2`, authored host harness | 357 checks PASS |
| Clang C99, AddressSanitizer + UndefinedBehaviorSanitizer | 357 checks PASS; no sanitizer report |
| `x86_64-w64-mingw32-gcc`, freestanding, `-mno-red-zone`, decoder object | compile exit 0; `llvm-readobj` confirms AMD64 COFF |
| guarded allocation end, including zero-length remote region at inaccessible page | included in both host harness runs |

An independent read-only review by `chromium_blockers` found no reader bounds or
borrowed-lifetime fault. It requested clarity that validate-before-write is not
atomic publication to other threads. The README now requires caller
synchronization of concurrent result readers. No implementation change resulted.

The initial GCC sanitizer link failed because its configured libasan/libubsan
runtime files were absent. The installed Clang sanitizer runtime completed the
same checks without installing packages. The README therefore uses Clang for
that check.

Frozen source SHA-256:

```text
76345a32d4cf7e282abf658fcabe73662d75fa037b8ff881fa46b7eeb4aa6b2e  accept_buffer.c
455974b94289c9cc07f8a3327566d2a8f8f67cedf411a29ec410be96967033da  accept_buffer.h
89a210229da18eb908460f2897c15840f4af89a62bbb74f08bfe08ef295d58aa  host_test.c
```

Output SHA-256:

```text
2f1ad1aa2b4c5d417606b2225f4e5e5205295bf58d30e3e74960248fdac938c9  host_test
84543c9c3dc35adf4dc32e93248f8ac796960b939e37cf6bc8e7bfc5c84511a2  host_test_sanitized
e4fe074d743f35bb2ad980216775d134ba679cefdb4df05ab9721869d7d9fcf5  accept_buffer_win64.o
```

Commands and upstream links are in [README.md](README.md). This is a completed
host parser prerequisite. It does not provide a Windows API export or prove
Wine/Win98/Kernel64 socket integration, actual AcceptEx completion, or Steam
startup/functionality.
