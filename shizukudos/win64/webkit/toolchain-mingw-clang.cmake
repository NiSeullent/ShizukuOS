# SPDX-License-Identifier: GPL-2.0-only
# CMake toolchain for WebKit (WTF/JavaScriptCore) on the ShizukuDOS Kernel64 Win64 runtime (docs/shizukudos10/WEBKIT.md):
# clang --target=x86_64-w64-windows-gnu, the mingw-w64 headers in UCRT mode, GCC 13's libstdc++ (win32 thread model,
# linked statically), and the Shizuku import libraries (build/shizukudos/win64/lib*.a) searched before mingw-w64's own,
# so every DLL import is one the Shizuku runtime exports (a missing one fails at link time, not in the guest).
# build.py passes SHZ_WIN64_LIBDIR (the Shizuku import libraries) and SHZ_ICU_PREFIX (the static Win64 ICU).
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR AMD64)
set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)
set(CMAKE_AR llvm-ar CACHE FILEPATH "")
set(CMAKE_RANLIB llvm-ranlib CACHE FILEPATH "")
set(CMAKE_C_COMPILER_TARGET x86_64-w64-windows-gnu)
set(CMAKE_CXX_COMPILER_TARGET x86_64-w64-windows-gnu)
set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32 ${SHZ_ICU_PREFIX})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
set(_shz_cflags "-D_UCRT -D__MSVCRT_VERSION__=0xE00 -D_WIN32_WINNT=0x0A00")
set(CMAKE_C_FLAGS_INIT "${_shz_cflags}")
set(CMAKE_CXX_FLAGS_INIT "${_shz_cflags}")
set(_shz_ldflags "-fuse-ld=lld -L${SHZ_WIN64_LIBDIR} -Wl,--no-insert-timestamp")
set(CMAKE_EXE_LINKER_FLAGS_INIT "${_shz_ldflags}")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "${_shz_ldflags}")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "${_shz_ldflags}")
