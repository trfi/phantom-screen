cmake_minimum_required(VERSION 3.16)
project(phantom-screen
    VERSION 1.0.0
    DESCRIPTION "Screen capture bypass and protection research toolkit"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(PHANTOM_BUILD_EXAMPLES "Build example applications" ON)
option(PHANTOM_BUILD_TESTS "Build unit tests" ON)

# Windows-only project
if(NOT WIN32)
    message(FATAL_ERROR "phantom-screen is a Windows-only toolkit")
endif()

add_library(phantom STATIC)

target_include_directories(phantom
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(phantom
    PUBLIC
        d3d11
        dxgi
        dwmapi
        user32
        gdi32
        psapi
        advapi32
)

target_sources(phantom PRIVATE
    src/core/hooks.cpp
    src/core/memory.cpp
    src/core/process.cpp
    src/capture/detector.cpp
    src/capture/bitblt.cpp
    src/capture/dxgi.cpp
    src/capture/wgc.cpp
    src/display/overlay.cpp
    src/display/cloaker.cpp
    src/display/composition.cpp
    src/utils/logger.cpp
    src/utils/config.cpp
)

if(PHANTOM_BUILD_EXAMPLES)
    add_executable(basic_cloak examples/basic_cloak.cpp)
    target_link_libraries(basic_cloak PRIVATE phantom)

    add_executable(capture_detect examples/capture_detect.cpp)
    target_link_libraries(capture_detect PRIVATE phantom)
endif()

if(PHANTOM_BUILD_TESTS)
    enable_testing()

    add_executable(test_hooks tests/test_hooks.cpp)
    target_link_libraries(test_hooks PRIVATE phantom)
    add_test(NAME HookEngineTests COMMAND test_hooks)
endif()

install(TARGETS phantom ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
