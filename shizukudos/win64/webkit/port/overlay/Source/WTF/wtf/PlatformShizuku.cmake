# ShizukuDOS "Shizuku" port (overlay, shizukudos/win64/webkit/port): WTF as for the Windows port, including its Win32
# message-pump RunLoop (RunLoopWin: a message-only window, PostMessage, SetTimer), which WebCore's OS(WINDOWS) code
# assumes. The user32 features it needs were checked in the guest first (port/tests/t_wk_msgloop.c).
include(${CMAKE_CURRENT_LIST_DIR}/PlatformWin.cmake)
