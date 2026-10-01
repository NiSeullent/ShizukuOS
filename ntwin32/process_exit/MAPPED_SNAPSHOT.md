# Own mapped notification diagnostic

This separate fixture maps one own zero-import PE DLL with actual MS-ABI static
TLS. It does not modify `native_loader/native.c`, its execution gates, the frozen
v5 manager or any modern application. The manager and native dependency observer
DLLs are byte-identical copies of the previously tested v5 artifacts.

Before termination, the native EXE maps/relocates/protects the own image,
initializes its real Win98 TLS plan, executes complete process attach and prepares
every eligible main/victim/caller thread's TLS. Native EXE BSS then holds the
sealed image/code/TLS ownership snapshot. Registering that snapshot with the
OS-loaded manager publishes it only after all preparation completed. Published
snapshots and borrowed mappings/TLS storage are never reused or freed.

The manager's callback reads the actual dispatcher thread ID and existing native
TLS slot. It requires exact ownership of that already-published TLS storage.
It invokes only the own mapped TLS callback with reserved zero, followed by the
own DLL entry with the actual native process-detach reserved pointer. The own
mapped DLL imports no native APIs; its callbacks only read real compiler TLS and
write the borrowed native EXE observation record. The dispatch path does not
wait, take a lock, create TLS, allocate/free storage or load/unload a native DLL.
It never substitutes the initiating caller's TLS for the dispatcher's TLS.

The main/worker controls retain their actual native TLS until process exit.
The victim holds a private lock, which dispatch never acquires. The missing-TLS
control deliberately removes the main thread's slot before termination and must
refuse dispatch before any mapped callback runs. The dependency control declares
an own native observer dependency, which must also refuse before mapped code if
that observer's actual detach flag is set. This is a declared dependency gate;
it is not evidence that arbitrary imported native DLL resources remain usable.

The outer suite waits for each actual child process and then reads its fresh
bounded report. A preselected child exit code alone cannot accept post-detach
callbacks. Positive controls need both real callback observations; negative
controls need the specific refusal and zero own mapped invocations. The suite's
own OS exit remains unobserved by this fixture.

The host controls exercise malformed code/image/snapshot ownership, absent TLS,
foreign thread/storage, duplicate owners and already-detached dependencies.
They do not simulate or establish Win98 execution. The native build verifies
classic GUI/i486 profiles, actual OEM imports and the own DLL's zero-import TLS
ABI. All native controls remain pending until a separately reviewed genuine
Win98 run. Physical cessation of other workers, production graph cleanup,
modern application mode and Chromium/Legcord/LibreOffice/Steam success remain
unproved.

The first frozen build failed because the outer 8 KiB automatic report buffer
required an unlinked stack helper. Its failure receipt is preserved. The v2
build uses a static parent-only buffer and passed the bounded host/build checks.
Further review corrections require a fresh frozen build and manifest.
