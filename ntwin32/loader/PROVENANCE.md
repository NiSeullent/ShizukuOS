# Loader guard provenance

`guard.c` and `guard.h` are original GPL-2.0-only code. They were written
after reading the public PE contract and the references below. No function
body from those trees was copied. VxKex was not used.

| Source | Revision | What was checked | Use here |
| --- | --- | --- | --- |
| Microsoft [IMAGE_LOAD_CONFIG_DIRECTORY32](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory32) | current documentation | Cookie at offset 60, GuardCF fields at 72/80/84/88 inside a structure whose Size is authoritative | 192-byte Chromium directories are accepted when those fields are inside the declared size and every CFG RVA is executable |
| Microsoft delay-load descriptor | PE/COFF | 32-byte RVA-based descriptors, attribute bit 0 | Non-RVA descriptors are rejected. A missing procedure rolls the IAT back |
| Wine `dlls/ntdll/loader.c` | `df15af3652511150490934682202d45af892f887` | Security-cookie initialization exists in the loader | Only the published MSVC x86 default cookie `0xBB40E64E` is special. Zero or identical entropy fails. A non-default cookie is left unchanged. No Wine code was copied |
| ReactOS `sdk/lib/rtl/vectoreh.c` | `9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8` | `RtlpAddVectoredHandler` / `RtlpRemoveVectoredHandler`. File SHA-256 `c0d2356dc5194151f11984402d4996a7c6cf2d32f9e05830f2732c20460ad4bf` | The Win32-shaped adapter is `ntwin32/exception/k32veh.c`. First-flag order follows this file. NULL callbacks are rejected, which this ReactOS function does not do |

CFG membership returns denied for RVA 0, an empty table, and any target that
is not an exact table entry. That is not a check which always succeeds.

## chrome_elf entry continuation

`critsec.c` checks flags the way ReactOS `RtlInitializeCriticalSectionEx`
does at `9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8`, including the Win7+ bits
`RESOURCE_TYPE` and `FORCE_DEBUG_INFO`, because Chromium 156 declares
subsystem 10. The existing `src/m98wrap.c` path only validates
`CRITICAL_SECTION_NO_DEBUG_INFO` and then calls the native Win98 initializer;
that call is not available in this freestanding loader. The 24-byte lock words,
recursive enter/leave, and the refusal to unlock a section owned by another
thread are new. Spin count is stored as zero on this one CPU. No ReactOS body
was copied.

`fls.c` follows the same index-0-reserved 128-slot limit and
`ERROR_NO_MORE_ITEMS` failure as `src/m98_fls.c`. A valid empty slot returns
NULL with error 0. `FlsFree` invokes a non-NULL callback for a non-NULL value.
Fiber switching is not implemented.

`LoadLibraryExW` / `LoadLibraryW` return a loader handle for `kernel32.dll`
and for `bcryptprimitives.dll`. Any other module returns 0 and last-error 126.
That is a missing-module result, not a successful load. `VirtualProtect` changes pages
inside the mapped image; `PAGE_GUARD` is rejected. `PAGE_WRITECOPY` is applied
as private read/write because this mapping is already private.

`fileio.c` implements synchronous `ReadFile`/`WriteFile` for the three handles
from `GetStdHandle`. The byte-count pointer is cleared before checks. A NULL
count or a non-NULL `OVERLAPPED` returns last-error 87. An unknown handle is 6.
Writing the input handle, or reading the output handles, is 5. Stdout is file
descriptor 1 and stderr is 2. This matches the failure shape checked in Wine
`dlls/kernel32/file.c` `WriteFile` at
`df15af3652511150490934682202d45af892f887`; the body was not copied.
`RtlCaptureStackBackTrace` walks saved frame pointers and stops when the frame
leaves the stack. `OpenProcess` succeeds only for this process id.

Chromium `base/rand_util_win.cc` loads `bcryptprimitives.dll` and resolves
`ProcessPrng`. The public contract is Microsoft
[ProcessPrng](https://learn.microsoft.com/en-us/windows/win32/seccng/processprng):
fill the buffer and return TRUE. This loader returns a handle for that DLL
only, and the export uses Linux `getrandom` (syscall 355) in 256-byte chunks.
A NULL buffer with a non-zero length fails. `src/bcrypt_shim.c` is the existing
Notepad++ SHA-256/MD5/HMAC path and is not used as ProcessPrng. No Chromium,
Wine, or ReactOS body was copied. `GetProcAddress` treats a name as an ordinal
only when the high 16 bits are zero; a pointer above 2GB is still a name.

SRW exclusive and shared locks call the existing `ntwin32/sync.c` word. A
condition variable is one generation. `SleepConditionVariableSRW` releases the
SRW, waits until that generation changes or the timeout elapses, then
reacquires. `WakeAllConditionVariable` increments the generation. There is no
second thread, so a wait is not reported as woken unless a wake happens.

`VirtualAlloc` records each reservation. Reserve-only memory is inaccessible.
`MEM_COMMIT` inside that reservation changes those pages with `mprotect`.
`MEM_DECOMMIT` makes them inaccessible again. `MEM_RELEASE` unmaps only the
base of a whole reservation and requires a zero size. An address that is not
the base fails. `PAGE_GUARD` and large-page requests are rejected.

Dynamic TLS has 1088 slots and index 0 is valid. `TlsGetValue` of an empty
live slot returns 0 with last-error 0. This is one thread; fiber switching is
not implemented. `IsWow64Process` writes FALSE for this 32-bit process.
`GetSystemInfo` reports one processor, 4096-byte pages and 65536-byte
granularity.

`GetVersionExW` and `VerifyVersionInfoW` answer Windows 10.0 build 19041,
workstation, platform 2, service pack 0 and suite mask 0, because the mapped
image declares subsystem 10.0. `VerSetConditionMask` stores each 3-bit
condition at bit index times 3. That answer is what this loader returns. It is
not a claim that the Linux host is Windows.

`GetACP` is 1252. `MultiByteToWideChar` and `WideCharToMultiByte` convert 1252
and well-formed UTF-8. Undefined 1252 bytes fail when the caller sets the
invalid-character flag. DBCS pages are named by `GetCPInfo` but conversion
returns last-error 87. `GetEnvironmentStringsW` copies the host environment
the process received, as UTF-16. Lookup is case-insensitive and a missing name
returns last-error 203. `FreeEnvironmentStringsW` accepts only that block.

`RtlFormatCurrentUserKeyPath` returns `STATUS_NO_TOKEN` (`0xC000007C`) and
leaves an empty `UNICODE_STRING`. No current-user SID is invented.

`chrome.exe` is a PE32 executable, so its entry is called with no arguments.
When that image imports `chrome_elf.dll`, the loader maps the sibling DLL,
binds its exports by name, registers both static TLS indexes, runs the DLL
callbacks and `DllMain`, then the executable callbacks and entry. Subsystem
10.0 is left unchanged. A large `MEM_RESERVE` with a null address is placed on
a 64 KiB or, at 2 MiB and above, a 2 MiB boundary by mapping extra pages and
unmapping the prefix and suffix. `MAP_FIXED` is used only for an address that
does not overlap an image, the heap, the environment block, or an existing
reservation. Critical-section debug records grow to 2048; after that the lock
is still initialized and `DebugInfo` is -1. Invalid flags still fail.

Fibers keep the parameter in the first word. `CreateFiberEx` maps a stack.
`SwitchToFiber` saves the current `esp`/`ebp` and resumes the target stack.
A fiber that has not run starts at its start routine. There is no floating-point
state switch. `SetCurrentDirectoryW` and `GetCurrentDirectoryW` use Linux
`chdir` and `getcwd`. `GetTempPathW` returns `/tmp/`. `GetFullPathNameW`
joins the host directory for a relative path and rejects a backslash.
`LoadLibraryExA` narrows to the existing wide loader and still returns
last-error 126 for a module this loader does not map.

`RaiseException` builds an `EXCEPTION_RECORD` and an x86 `CONTEXT`, runs
vectored handlers, then the `FS:[0]` SEH chain. A vectored handler returning
-1, or an SEH handler returning disposition 0, resumes the caller when the
exception is continuable. A noncontinuable exception that asks to resume
becomes `STATUS_NONCONTINUABLE_EXCEPTION` and terminates. If every handler
returns search and the top filter does not resume, the process exits with
the exception code. That is the unhandled-exception result, not a successful
return. `RtlUnwind` calls each frame with `EXCEPTION_UNWINDING` until the
target frame, stores that frame in `FS:[0]`, and jumps to the target address.
Handler calls use the cdecl convention observed in this `chrome.exe` build
(`ret`, not `ret 16`). Order follows ReactOS
`sdk/lib/rtl/i386/except.c` at
`cae3ca87209fd8ebabd96c8ea95d439c13e7fdf8`; the body was not copied. The
existing `ntwin32/exception/veh.c` registry remains the portable list and is
not the Win32 callback ABI used here.

A fiber switch also saves and restores `FS:[0]`. A new fiber starts with an
empty chain. `ADVAPI32.dll` resolves only the ACL and security-descriptor
exports implemented here. `InitializeAcl` rejects a short buffer and a
revision other than 2 or 4. `InitializeSecurityDescriptor` requires revision
1 and writes a 20-byte absolute descriptor. `SetSecurityDescriptorDacl`
rejects a present ACL that fails `IsValidAcl`. An unimplemented advapi export
returns last-error 127, so the delay-load helper raises `0xC06D007F` instead
of receiving a success stub. Registry functions return status 2 or 6 because
this loader has no registry hive.

`CreateFileMappingW` creates a pagefile section only for `INVALID_HANDLE_VALUE`.
Any other file handle is 6. A zero size, a non-zero high size, both
`SEC_COMMIT` and `SEC_RESERVE`, or a page protection outside the six mapping
values fails with 87. `MapViewOfFile` requires a 64 KiB-aligned offset that
fits the section. A write view of a read-only section fails with 5.
`UnmapViewOfFile` of a null address fails with 87 and an unknown address fails
with 487. A repeated name returns the existing handle and last-error 183 when
the page protection matches. `DuplicateHandle` adds another handle to that
section and can close the source. `VirtualQuery` reports those sections, the
two images, and the process heap. Other addresses are free for 64 KiB.
`GetFileVersionInfoSizeW`, `GetFileVersionInfoW`, and `VerQueryValueW`
read the RT_VERSION resource from the PE file named by an ASCII path.
A missing file or a PE without that resource returns 1812. A buffer smaller
than the resource returns 122 and copies nothing. `VerQueryValueW` walks the
public `VS_VERSIONINFO` tree. The path `\` returns the 52-byte
`VS_FIXEDFILEINFO` whose signature is `0xFEEF04BD`. A missing child returns
1812. No version text is invented.
The language ids returned here are `0x0409`, the language of this official
build's version resource. `GetLocalTime` and `GetSystemTime` are UTC from
`CLOCK_REALTIME`, because no timezone database is consulted. `PEB+0xA0` is
an unowned critical section so a loader-lock check does not see this thread
as the owner.

`ConvertStringSecurityDescriptorToSecurityDescriptorW` parses SDDL revision 1
into a self-relative descriptor allocated by `LocalAlloc`. The grammar and
ACE layout are the public security-descriptor contract. Wine
`ConvertStringSecurityDescriptorToSecurityDescriptor` (LGPL) and the ReactOS
advapi32 converter were not copied. A malformed string returns 87. An unknown
account alias returns 1332. The Chromium call logged here is
`D:(A;;GA;;;SY)(A;;GWGR;;;S-1-15-2-1)S:(ML;;;;;S-1-16-0)`.
`BuildExplicitAccessWithNameW` stores that name pointer and the access mode.
`BuildSecurityDescriptorW` adds a grant ACE only when the trustee is a SID this
loader can encode. `CURRENT_USER` has no token, so it returns 1332 and the
caller writes that text through `FormatMessageW`. Unknown message codes return
317. `FormatMessageW` does not substitute inserts.

`CreateFileW` opens an ASCII path. Backslashes become slashes. A missing
`OPEN_EXISTING` file returns 2. `CREATE_NEW` of an existing file returns 80.
`CREATE_ALWAYS` and `OPEN_ALWAYS` return a handle and last-error 183 when the
file already existed. A write-only handle rejects `ReadFile` with 5. A negative
`FILE_BEGIN` offset returns 131. `GetFileSizeEx` reads the seekable length.
Share mode is not enforced. Wine `dlls/kernel32/file.c` at
`df15af3652511150490934682202d45af892f887` was compared and not copied.
`CreateNamedPipeW` accepts only a `\\.\pipe\` name. A second live instance
returns 231. `ConnectNamedPipe` does not invent a client: nowait returns 536
and a waiting pipe returns 1460. A write before a client connects returns 233.
`CreateEventW` stores manual or auto state. A repeated name returns the same
handle and last-error 183. `WaitForSingleObject` on an unsignaled event returns
258 immediately; the millisecond argument is not slept.

A single leading backslash is the current drive root. This loader's root is
the `drive` directory under the process current directory, so `\Crashpad`
becomes `<cwd>/drive/Crashpad`. `CreateDirectoryW` and creating
`CreateFileW` dispositions create missing parent directories. `OPEN_EXISTING`
of a missing file still returns 2. A `C:` path and a UNC path return 3 and
create nothing. `\\.\pipe\` is a local pipe path, not the database.

`SHELL32.dll` and `api-ms-win-downlevel-shell32` resolve to this loader.
`CommandLineToArgvW` splits a quoted command line and fails with 87 on an empty
command. `SHGetFolderPathW` and `SHGetKnownFolderPath` return `0x80070002`
when the folder is absent and `0x80070057` for an unknown id. The create flag
makes that directory under the drive root. `src/m98shell.c` covers different
Shell entry points and was not copied. Wine shell32 was not copied.
The dbghelp delay imports return false with last-error 120.
`MiniDumpWriteDump` does not write a dump.

`CreateThread` uses Linux `clone` (syscall 120) so the start routine runs on
another thread in the same address space. `CREATE_SUSPENDED` waits for
`ResumeThread`. A null start routine returns 87. `GetExitCodeThread` returns
259 until the routine returns, then that code. `WaitForSingleObject` on the
thread handle waits for that completion. Wine `kernel32/thread.c` was not copied.

`TransactNamedPipe` writes the request and then reads the reply only when the
handle is a connected pipe. A listening socket that has not accepted a client,
and a pipe with no descriptor, return 233. An overlapped call returns 87.
`SetProcessShutdownParameters` stores the level and flags for this process and
`GetProcessShutdownParameters` reads them back. Levels above `0x4FF` and unknown
flags return 87. The stored values do not change the host process shutdown order.

`CreateIoCompletionPort`, `GetQueuedCompletionStatus`, and
`PostQueuedCompletionStatus` use a real queue. An unknown handle returns 6.
Creating a port with `INVALID_HANDLE_VALUE` and an existing port returns 87.
An empty wait returns 258 (`WAIT_TIMEOUT`). A posted completion returns with
the same byte count, completion key, and overlapped pointer. Wine
`kernel32/sync.c` completion helpers were compared and not copied.

`InitOnceExecuteOnce` calls the callback once. A callback that returns false
clears the cell so another call can try again. A null cell or null callback
returns 87. Wine `sync.c` was not copied.

`GetFileInformationByHandleEx` reads the i386 `stat64` result of Linux syscall
197. `FileBasicInfo` (class 0) and `FileStandardInfo` (class 1) return those
times, the byte size, and the directory bit. A short buffer returns 122. An
unknown class returns 87. Wine `file.c` was not copied.

`lstrcmpiA` folds only ASCII `A`–`Z`. Two null pointers compare equal and one
null pointer is less than a string. Bytes above 127 are not folded. Wine
`string.c` was not copied.

`K32GetProcessMemoryInfo` reads `/proc/<pid>/statm` or `/proc/self/statm`.
A buffer shorter than 40 bytes returns 122. An unknown process handle returns
6. `K32GetPerformanceInfo` reads `MemTotal`, `MemAvailable`, `Committed_AS`,
and `CommitLimit` from `/proc/meminfo`. A missing file returns 5 and an
unreadable field returns 31. Wine psapi was not copied.

`LockFileEx` and `UnlockFileEx` use Linux `fcntl` `F_SETLK64` (syscall 55,
commands 13 and 14). A null overlapped pointer or a reserved value returns 87.
A conflicting lock returns 33. Windows `0xFFFFFFFF,0xFFFFFFFF` byte counts mean
the rest of the 64-bit range; this loader records that as a Linux length of 0,
which locks or unlocks from the overlapped offset through EOF. That is a
recorded difference, not a success without a lock.

`SetEndOfFile` truncates at the current file pointer with i386 `ftruncate64`
(syscall 194). A bad handle returns 6. `GetLongPathNameW` returns the same
path when that path exists. This loader has no 8.3 short names. A missing path
returns 2. A short buffer returns the required character count, including the
null, and last-error 122. `DeleteFileW` unlinks the path. A path that a live
handle still has open returns 32. A missing path returns 2. A directory returns
5.

RaiseException code `0x406D1388` is the Visual C thread-name exception. If the
SEH chain does not resume, this loader continues after the call and logs
`thread name continued`. It does not treat that code as process termination.
`MiniDumpWriteDump` still returns false with last-error 120 and writes no dump.
`int 0x29` is Windows `__fastfail`. This loader logs the code from `ecx`, the
instruction address, and the return address on the stack, then restores the
default SIGSEGV action so the process still dies. It does not resume as
success. Code 2 is `FAST_FAIL_STACK_COOKIE_CHECK_FAILURE`. The failing frame
was the CRT startup function that calls `SwitchToFiber`. `SwitchToFiber` now
saves and restores `ebx`, `esi`, and `edi` with the stack pointer, frame
pointer, and SEH list. Wine's fiber switch was not copied.

`DeleteFileW` returns 32 when a live handle of that path was opened without
`FILE_SHARE_DELETE`. A handle opened with `FILE_SHARE_DELETE` does not block
the delete, and the open descriptor stays usable until close. MiniDumpWriteDump
still returns false and writes no dump.

`PEB+0x10` points at an `RTL_USER_PROCESS_PARAMETERS` block. Flags are 1, so
the high bit is clear, and the standard handles are the loader's console
handles. `api-ms-win-appmodel-runtime-l1-1-2` resolves here.
`AppPolicyGetProcessTerminationMethod` writes `ExitProcess` (0) and returns 0
for a desktop process. An unknown export of that module is logged and returns
127.

`ExitProcess` is not rewritten. The earlier code 2 was the return value of
fiber startup RVA `0x1000`. The browser process was reading
`child-cmdline.txt`, which still contained a previous
`--type=fallback-handler` command. It therefore ran as the handler and
returned 2. Only a process spawned with `ntw-depth-1` loads that file.
`GetModuleHandleW(L"mscoree.dll")` still fails with 126. The COM descriptor is
empty, so this loader does not invent a CLR host. `DeleteFileW` still returns
32 when the live handle lacks `FILE_SHARE_DELETE`. `MiniDumpWriteDump` still
returns false and writes no dump. The subsystem bytes stay 10.0.

`SetHandleInformation` stores `HANDLE_FLAG_INHERIT` and
`HANDLE_FLAG_PROTECT_FROM_CLOSE`. A mask outside those bits, or flag bits
outside the mask, returns 87. A protected handle then fails `CloseHandle`
with 6. `CreateSemaphoreW` rejects a non-positive maximum or an initial count
above it. Releasing past the maximum returns 298. `GetTokenInformation`
returns a documented SID for user, owner, primary group, and medium integrity,
and 122 when the buffer is short. Unknown token classes return 87.
`GetSecurityInfo` allocates one absolute security descriptor with
`LocalAlloc`. `FindFirstFileExW` fails a bad level with 87, a missing
directory with 3, and no match with 2. `SetProcessDEPPolicy` stores the first
value in 0..3 and returns 5 on a second call.

Official `chrome.dll` from the same chrome-win archive is mapped at its
preferred base `0x10000000`. Static TLS registration after threads exist uses
`ntwtls_register_late` and `ntwtls_thread_extend`. `ntwtls_register` still
returns busy while a thread is live.

The SIGSEGV at chrome.dll RVA `0x362290` was not a guard page or a null
pointer. Signal code 1 (`SEGV_MAPERR`) and fault address `0xa29fbf08` match
`test byte ptr [eax+eax*8], ah` (`84 24 C0`) with eax equal to a stack
pointer. The caller was the CRT cookie initializer's indirect call through
the `GetSystemTimeAsFileTime` import slot. `bind_imports` refused every IAT
whose RVA was above 8MiB, so chrome.dll's KERNEL32 imports stayed at their
placeholder VAs. The size check now uses `SizeOfImage`. `VirtualProtect`
accepts addresses inside chrome.dll. `CreateFileMappingW` of a live file
copies that file. `GetCurrentThread` (`0xfffffffe`) can be duplicated.
`icudtl.dat` from the same archive is mapped. `DllMain` returns 1.

`SHGetFolderPathW` and `SHGetKnownFolderPath` create the known folder,
including missing parents, under the synthetic `C:` root. A successful
`CSIDL_LOCAL_APPDATA` result is the Windows path `C:\AppData\Local`.
`CreateDirectoryW` creates missing parents of a relative path and returns 183
when the final directory already exists. A drive other than `C:` and a UNC
path still fail with error 3. Host `mkdir` returning `-13` (`EACCES`) stays
error 5 / `HRESULT` `0x80070005`. Microsoft documents
[SHGetFolderPathW](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetfolderpathw)
and [CreateDirectoryW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectoryw).
Wine and ReactOS were not copied.

`USER32.dll` is a loader module (`0x1006`). Delay-load exports such as
`CreateWindowExW` and `GetMessageW` are real functions. An unregistered class
returns last-error 1407. The earlier `0xC06D007E` self-terminate happened
because `LoadLibrary` of `USER32.dll` returned 0. No window exists.

Chromium's relative `--user-data-dir=tmp/Chromium/User Data` is created under
the loader working directory, including its parent `tmp/Chromium`. The check
in `chrome/app/chrome_main_delegate.cc` is past. The next stop is the
unresolved `KERNEL32` import `IsProcessInJob` (`ud2`, process exit 132).
Subsystem bytes stay 10.0. No window is created.
`browser_functionality_verified` stays false. `MiniDumpWriteDump` still
returns false and writes no dump. `ExitProcess` is not rewritten.

All of this loader code is GPL-2.0-only. Wine is LGPL-2.1-or-later at
`df15af3652511150490934682202d45af892f887` and was not copied.






`CreateProcessW` returns 2 when the image is missing and does not invent a pid.
A running image is `fork` plus `execve` of this loader. The public
`PROCESS_INFORMATION` receives the handle, a thread handle for that same child,
and the pid. `CREATE_SUSPENDED` returns 87 and starts nothing. A file that is
not a PE returns 193. Wine `dlls/kernel32/process.c` was not copied. Chromium's
logged command is `chrome.exe --type=crashpad-handler`. A child of that process
does not start another `chrome.exe`. `GetExitCodeProcess` returns 259 until the
child is reaped, then the exit code. `TerminateProcess` of the current process
calls the loader exit. On this run that code was `0xFFFF7001`.



