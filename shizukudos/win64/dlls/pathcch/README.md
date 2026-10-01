# PathCch lexical path family

This module ports all 22 `PathCch`/`PathAlloc`/`PathIsUNCEx` entry points from
Wine 11.0. `kernel32/k32_pathcch.c` supplies the same exports for the existing
`api-ms-win-core-path-l1-1-0` kernelbase host alias. Each wrapper loads the real
module from SYS64, calls its implementation, and releases the module reference.
Missing mandatory modules or exports return a failing HRESULT; Boolean calls
return `FALSE` with the loader error. The API-set contract table is unchanged.

The code operates on UTF-16 paths without filesystem access. Allocating calls
return actual `LocalAlloc` allocations that callers release with `LocalFree`.
Root handling, dot segments, extensions, length limits and option combinations
follow the pinned upstream algorithms. Export counts are not an API compatibility
percentage or application functionality result.

Source lineage and licenses:

- [Wine 11.0 kernelbase/path.c](https://github.com/wine-mirror/wine/blob/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/kernelbase/path.c),
  commit `db11d0fe6a169c457e23d007e20404643d067aa8`, SHA-256
  `5ab6715af29660476cabc10ead698e53b91bc9e6d757b73299c17fe6c4784c05`.
  Copyright Nikolay Sivov, Zhiyi Zhang and Zebediah Figura; LGPL-2.1-or-later.
- [Wine pathcch.h](https://github.com/wine-mirror/wine/blob/db11d0fe6a169c457e23d007e20404643d067aa8/include/pathcch.h):
  Copyright Michael Müller; LGPL-2.1-or-later. Original notices are retained.
- [ReactOS kernelbase/wine/path.c](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/kernelbase/wine/path.c),
  commit `9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8`, SHA-256
  `083e3e6ae50bfc74b6313cb7e15f08a11e5be5ca2c556bc9ee6d56342cd397a0`.
  Reviewed as a second implementation reference; this is the same Wine lineage.
- Integration wrappers and test scaffolding are original GPL-2.0-only code.

Adaptations remove Wine tracing and unrelated APIs, replace CRT character/string
helpers with local UTF-16 routines, check invalid output/capacity arguments,
remove the upstream `RemoveBackslashEx` read beyond an unterminated buffer,
and pass character capacity to `PathCchAddBackslash` instead of byte size.

Host verification builds `tests/test_pathcch_host.c` with `-fshort-wchar` and
Clang address/undefined-behavior sanitizers. Its 56 contract checks cover roots,
dot segments, long paths, flags, insufficient buffers, allocation failure and
ownership, extension operations, prefix stripping, and unterminated input.
The AMD64 module and API-set wrappers compile with the runtime's strict flags.
`win64/tests/t_pathcch.c` tests real DLL/API-set resolution and behavior in the
guest. Its source exists; a guest pass must be recorded separately.
