# Resource integration in a separately patched native loader

This directory leaves held native.c, pe.c/h, build.py, reader and adapter v3
unchanged. `patch_loader.py` requires the exact native.c base hash and changes
only a generated frozen copy. Ordinary command modes continue using mode 2;
resource hooks remain blocked there. The compiled own probe alone calls private
mode 3, whose raw file hashes admit exactly RBAPP.EXE/RBROOT.DLL/RBDATA.DLL plus
original system Kernel32. All existing parsing, imports, relocations, runtime
profile, TLS ABI, protection, attach and thread-cessation gates still apply.

The bridge registers real state2 mapped module objects and their retained raw
PE images after graph protection and before any attach. Resource callbacks and
the existing GetProcAddress path share the same hook table and loader lock.
Lock helpers preserve actual thread LastError; trusted readability callbacks
save/restore it on every return. HMODULE NULL follows the actual NI root policy:
mapped EXE for application roots, native host process for DLL roots. Original
OEM exports handle known native-module resources; found/loaded native identities
are tracked before Load/Size/Lock/Free delegation, so foreign pointers are never
forwarded speculatively. Mapped resources use the accepted borrowed adapter.
The process host HMODULE is cached during preparation before target calls;
identity dispatch performs no API lookup that could clobber LastError. Fourteen
compiled native controls capture LastError before logging across recursive lock
entry/leave, both NULL-root identities, all resource hooks and selected native
host lookup failure. These controls have not yet been observed in a guest.

Existing FreeLibrary reference release retains mappings until graph cleanup.
The own DLL queries resources during real process attach/detach; registrations
survive detach and are removed under the lock before files/mappings are freed.
The exact diagnostic expects four successful detach resource calls and records
their result independently of DllMain's ignored detach return. After cleanup the
probe checks stale data pointers are refused with INVALID_HANDLE before another
graph starts. No pointer-generation/ABA protection or storage recycling while
borrowed is claimed.

The application tests NULL root, named A/W and decimal lookups, LastError,
actual GetProcAddress resource routing, DLL dependencies, retained data after
FreeLibrary, foreign information handles and repeated no-op FreeResource.
The host suite covers the portable registration/lifetime half; it does not
execute target code or simulate genuine Win98. Native artifacts are compiled
only. No VM launch/staging or Chromium entry occurs; application success remains
false and full language fallback/ACP/folding limitations remain unchanged.
