# Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
# Opt-in CMAKE_PROJECT_INCLUDE hook. Propagate the measured allocator's Win9x
# profile to its standalone C object, and track the genuine runtime object which
# must already be in executable linker flags.
include_guard(GLOBAL)

function(iewebkit_attach_runtime_dependency)
    if (NOT IEWEBKIT_WIN9X)
        return()
    endif ()
    if (PORT STREQUAL "JSCOnly")
        if (NOT TARGET mimalloc-obj)
            message(FATAL_ERROR "The opted-in Win9x allocator profile requires the actual mimalloc-obj target")
        endif ()
        target_compile_definitions(mimalloc-obj PRIVATE IEWEBKIT_WIN9X=1)
    endif ()
    if (NOT DEFINED IEWEBKIT_WIN9X_RUNTIME_OBJECT
            OR IEWEBKIT_WIN9X_RUNTIME_OBJECT STREQUAL "")
        return()
    endif ()
    if (NOT IS_ABSOLUTE "${IEWEBKIT_WIN9X_RUNTIME_OBJECT}"
            OR NOT EXISTS "${IEWEBKIT_WIN9X_RUNTIME_OBJECT}"
            OR IS_DIRECTORY "${IEWEBKIT_WIN9X_RUNTIME_OBJECT}"
            OR IS_SYMLINK "${IEWEBKIT_WIN9X_RUNTIME_OBJECT}")
        message(FATAL_ERROR "IEWEBKIT_WIN9X_RUNTIME_OBJECT must name an existing real absolute object file")
    endif ()
    if (NOT TARGET jsc)
        message(FATAL_ERROR "The opted-in Win9x runtime dependency requires the actual jsc target")
    endif ()
    get_target_property(_kind jsc TYPE)
    if (NOT _kind STREQUAL "EXECUTABLE")
        message(FATAL_ERROR "The Win9x runtime dependency requires an executable jsc target")
    endif ()
    get_filename_component(_object "${IEWEBKIT_WIN9X_RUNTIME_OBJECT}" REALPATH)
    get_target_property(_dependencies jsc LINK_DEPENDS)
    if (NOT _object IN_LIST _dependencies)
        set_property(TARGET jsc APPEND PROPERTY LINK_DEPENDS "${_object}")
    endif ()
endfunction()

# project() runs before add_subdirectory(Source). Defer to the top-level end so
# both real targets exist. C++ flags and source files are unchanged.
cmake_language(DEFER DIRECTORY "${CMAKE_SOURCE_DIR}"
               CALL iewebkit_attach_runtime_dependency)
