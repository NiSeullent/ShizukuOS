# ShizukuDOS "Shizuku" WebKit port (agent W3): the embedding layer and its programs. Added to the WebKit build by the
# overlay's Source/PlatformShizuku.cmake (add_subdirectory with SHIZUKU_PORT_DIR).

add_library(ShizukuWebKit STATIC
    shizuku/ShizukuPlatformStrategies.cpp
    shizuku/ShizukuWebKit.cpp
)
target_include_directories(ShizukuWebKit PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/shizuku"
    "${CMAKE_BINARY_DIR}"
    "${WTF_FRAMEWORK_HEADERS_DIR}"
    "${bmalloc_FRAMEWORK_HEADERS_DIR}"
    "${JavaScriptCore_FRAMEWORK_HEADERS_DIR}"
    "${JavaScriptCore_PRIVATE_FRAMEWORK_HEADERS_DIR}"
    "${PAL_FRAMEWORK_HEADERS_DIR}"
    "${WebCore_PRIVATE_FRAMEWORK_HEADERS_DIR}"
    "${Skia_FRAMEWORK_HEADERS_DIR}/top"
)
target_compile_definitions(ShizukuWebKit PUBLIC HAVE_CONFIG_H=1 BUILDING_WITH_CMAKE=1 STATICALLY_LINKED_WITH_WTF
    STATICALLY_LINKED_WITH_JavaScriptCore STATICALLY_LINKED_WITH_PAL STATICALLY_LINKED_WITH_WebCore)
target_link_libraries(ShizukuWebKit PUBLIC WebCore PAL JavaScriptCore WTF bmalloc Skia ShizukuEGL)
add_dependencies(ShizukuWebKit WebCore_CopyPrivateHeaders)
WEBKIT_ADD_TARGET_CXX_FLAGS(ShizukuWebKit -Wno-unused-parameter)

add_executable(T_WK_RENDER programs/TWkRender.cpp)
target_link_libraries(T_WK_RENDER PRIVATE ShizukuWebKit)
set_target_properties(T_WK_RENDER PROPERTIES OUTPUT_NAME T_WK_RENDER)
