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

# Source files will be added incrementally
target_sources(phantom PRIVATE
    # placeholder
)

if(PHANTOM_BUILD_EXAMPLES)
    # Examples will be added later
endif()

if(PHANTOM_BUILD_TESTS)
    enable_testing()
    # Tests will be added later
endif()

install(TARGETS phantom ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
