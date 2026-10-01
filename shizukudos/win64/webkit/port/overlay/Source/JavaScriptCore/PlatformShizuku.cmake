# ShizukuDOS "Shizuku" port (overlay, shizukudos/win64/webkit/port): JavaScriptCore is built exactly as for PORT=JSCOnly on
# Windows, the configuration agent W1 builds and runs jsc.exe with (docs/shizukudos10/WEBKIT.md).
include(${CMAKE_CURRENT_LIST_DIR}/PlatformJSCOnly.cmake)
