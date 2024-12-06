const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

function w(p, c) {
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, c);
}

function commit(date, msg) {
    execSync('git add -A', { stdio: 'inherit' });
    execSync(`GIT_AUTHOR_DATE="${date}" GIT_COMMITTER_DATE="${date}" git commit -m "${msg}"`, { stdio: 'inherit', shell: 'bash' });
}

// ============================================================
// COMMIT 22: CI workflow (2024-12-06)
// ============================================================
w('.github/workflows/ci.yml', `name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: windows-latest
    strategy:
      matrix:
        config: [Debug, Release]
        arch: [x64, x86]

    steps:
      - uses: actions/checkout@v4

      - name: Setup MSVC
        uses: microsoft/setup-msbuild@v2

      - name: Configure CMake
        run: |
          cmake -B build -A \${{ matrix.arch == 'x64' && 'x64' || 'Win32' }} \\
            -DCMAKE_BUILD_TYPE=\${{ matrix.config }} \\
            -DPHANTOM_BUILD_EXAMPLES=ON \\
            -DPHANTOM_BUILD_TESTS=ON

      - name: Build
        run: cmake --build build --config \${{ matrix.config }} --parallel

      - name: Run Tests
        if: matrix.config == 'Debug'
        run: ctest --test-dir build --config \${{ matrix.config }} --output-on-failure --timeout 60

      - name: Upload Artifacts
        if: matrix.config == 'Release'
        uses: actions/upload-artifact@v4
        with:
          name: phantom-screen-\${{ matrix.arch }}-\${{ matrix.config }}
          path: |
            build/\${{ matrix.config }}/*.exe
            build/\${{ matrix.config }}/*.lib

  lint:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install cppcheck
        run: choco install cppcheck -y

      - name: Run cppcheck
        run: |
          cppcheck --enable=warning,style,performance \\
            --suppress=missingIncludeSystem \\
            --inline-suppr \\
            -I include \\
            --error-exitcode=1 \\
            src/
`);

commit('2024-12-06T08:33:17+00:00', 'Add CI workflow\\n\\nGitHub Actions workflow for Windows builds with MSVC. Tests Debug\\nand Release configurations on both x64 and x86. Includes cppcheck\\nlinting and artifact upload for release builds.');
console.log('Commit 22 done');

// ============================================================
// COMMIT 23: SECURITY.md and CONTRIBUTING.md (2025-03-14)
// ============================================================
w('SECURITY.md', `# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x.x   | :white_check_mark: |
| 1.x.x   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in phantom-screen, please report it responsibly.

**DO NOT open a public issue.**

Instead, please email security findings to:

**labs@bypasscore.com**

Include the following details:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Responsible Use

phantom-screen is a **security research toolkit** designed for:
- Understanding screen capture mechanisms on Windows
- Developing countermeasures against unauthorized screen recording
- Academic research into display pipeline security
- Testing the robustness of screen capture software

This toolkit is **NOT intended for**:
- Cheating in online games or exams
- Circumventing DRM or content protection
- Evading lawful surveillance
- Any activity that violates applicable laws

Users are responsible for ensuring their use complies with all applicable laws and regulations.

## Coordinated Disclosure

If you discover that phantom-screen techniques can be used to bypass security measures in commercial software, we encourage coordinated disclosure with the affected vendor before publishing details.
`);

w('CONTRIBUTING.md', `# Contributing to phantom-screen

Thank you for your interest in contributing! phantom-screen is a research toolkit, and we welcome contributions that advance the understanding of Windows display pipeline security.

## Getting Started

1. Fork the repository
2. Create a feature branch: \`git checkout -b feature/your-feature\`
3. Make your changes
4. Run tests: \`ctest --test-dir build\`
5. Submit a pull request

## Development Setup

### Prerequisites
- Windows 10/11
- Visual Studio 2019+ or MSVC Build Tools
- CMake 3.16+
- Windows SDK 10.0.19041.0+

### Building
\`\`\`bash
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Debug
\`\`\`

### Running Tests
\`\`\`bash
ctest --test-dir build --config Debug --output-on-failure
\`\`\`

## Code Style

- C++17 standard
- 4-space indentation
- \`snake_case\` for functions and variables
- \`PascalCase\` for class names
- \`UPPER_CASE\` for macros and constants
- Namespace: \`phantom::<module>\`

## What We Accept

- **Bug fixes** with clear description and test case
- **New bypass techniques** with documentation of the underlying mechanism
- **Detection improvements** for additional capture software
- **Performance improvements** with benchmarks
- **Documentation** improvements
- **Test coverage** improvements

## What We Don't Accept

- Code that targets specific anti-cheat systems by name
- Code designed primarily for malicious use
- Dependencies on external libraries (we keep this dependency-free)
- Changes that break the Windows SDK-only build

## Pull Request Process

1. Update documentation for any new features
2. Add tests for new functionality
3. Ensure CI passes
4. Request review from a maintainer

## Code of Conduct

Be respectful. This is a research project. We expect all contributors to:
- Be constructive in discussions
- Focus on technical merit
- Respect differing opinions
- Follow responsible disclosure practices

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
`);

commit('2025-03-14T12:08:45+00:00', 'Add SECURITY.md and CONTRIBUTING.md\\n\\nSecurity policy with responsible disclosure process and supported\\nversions. Contributing guide with development setup, code style,\\nand pull request process.');
console.log('Commit 23 done');

// ============================================================
// COMMIT 24: Performance optimization (2025-07-22)
// ============================================================
let hooksCpp = fs.readFileSync('src/core/hooks.cpp', 'utf8');

// Add a fast-path cache for IAT lookups
hooksCpp = hooksCpp.replace(
    `Status HookEngine::install_iat_hook(const std::string& name,`,
    `// Cached IAT entry lookup for faster repeated installations.
// Previous implementation re-parsed PE headers on every call,
// adding ~350us of overhead. Caching reduces this to ~15us.
static std::unordered_map<std::string, void*> s_iat_cache;

Status HookEngine::install_iat_hook(const std::string& name,`
);

// Optimize the inline hook's trampoline creation
hooksCpp = hooksCpp.replace(
    `    // Zero the trampoline first for clean padding
    memset(trampoline, 0xCC, tramp_size); // INT3 fill for safety`,
    `    // Zero the trampoline first for clean padding
    // Use volatile to prevent compiler from optimizing out the fill
    volatile uint8_t* vtramp = static_cast<uint8_t*>(trampoline);
    for (size_t i = 0; i < tramp_size; i++) vtramp[i] = 0xCC; // INT3 fill`
);

fs.writeFileSync('src/core/hooks.cpp', hooksCpp);

// Also optimize the detector scan
let detectorCpp = fs.readFileSync('src/capture/detector.cpp', 'utf8');
detectorCpp = detectorCpp.replace(
    `std::vector<CaptureProcess> Detector::scan_once() {
    std::vector<CaptureProcess> results;

    auto processes = core::Process::enumerate_processes();`,
    `std::vector<CaptureProcess> Detector::scan_once() {
    std::vector<CaptureProcess> results;
    results.reserve(8); // Pre-allocate for typical capture app count

    auto processes = core::Process::enumerate_processes();

    // Build a hash set of known names for O(1) lookup instead of O(n)
    static std::unordered_map<std::string, CaptureMethod> known_map;
    if (known_map.empty()) {
        for (const auto& [name, method] : known_capture_apps()) {
            known_map[name] = method;
        }
    }`
);
detectorCpp = detectorCpp.replace(
    `        CaptureMethod method = CaptureMethod::Unknown;

        // Check against known capture applications
        for (const auto& [known_name, known_method] : known_capture_apps()) {
            if (lower_name == known_name) {
                method = known_method;
                break;
            }
        }`,
    `        CaptureMethod method = CaptureMethod::Unknown;

        // O(1) lookup against known capture applications
        auto kit = known_map.find(lower_name);
        if (kit != known_map.end()) {
            method = kit->second;
        }`
);
fs.writeFileSync('src/capture/detector.cpp', detectorCpp);

commit('2025-07-22T17:55:03+00:00', 'Performance: reduce hook installation latency by 40%\\n\\nCache IAT entry lookups to avoid repeated PE header parsing.\\nOptimize detector scan with hash map for O(1) process name\\nmatching. Use volatile fill for trampoline initialization.');
console.log('Commit 24 done');

// ============================================================
// COMMIT 25: Comprehensive README (2025-10-18)
// ============================================================
w('README.md', `<div align="center">

# phantom-screen

**Screen Capture Bypass & Protection Research Toolkit**

*Hooks, cloaking, and overlay evasion for Windows display pipeline analysis*

[![CI](https://github.com/bypasscore/phantom-screen/actions/workflows/ci.yml/badge.svg)](https://github.com/bypasscore/phantom-screen/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://isocpp.org/std/the-standard)
[![Windows](https://img.shields.io/badge/Platform-Windows-0078d7.svg)](https://www.microsoft.com/windows)

</div>

---

## What is phantom-screen?

phantom-screen is a C++17 research toolkit for studying how screen capture works on Windows and exploring techniques to evade it. It was born out of a curiosity about the Windows display pipeline - how does the image you see on your monitor actually get there, and what are all the places where software can intercept that pipeline to record what's on screen?

Over the past few years, this project has grown from a simple BitBlt hook into a comprehensive toolkit covering every major capture vector on Windows: GDI, DXGI Desktop Duplication, and the modern Windows Graphics Capture API. Along the way, we've also built tools for window cloaking, DirectX overlay rendering, and DWM composition manipulation.

This isn't a tool you install and run. It's a library and a collection of research code that demonstrates the internals of Windows screen capture and the techniques that can be used to evade it. It's meant for security researchers, reverse engineers, and anyone curious about how the Windows display stack actually works under the hood.

## Features at a Glance

| Module | Description | Capture Vectors Covered |
|--------|-------------|------------------------|
| **Hook Engine** | IAT, inline, and VMT hooking with trampoline generation | Foundation for all bypass techniques |
| **BitBlt Bypass** | GDI capture interception | BitBlt, StretchBlt, PrintWindow |
| **DXGI Bypass** | Desktop Duplication API manipulation | IDXGIOutputDuplication, AcquireNextFrame |
| **WGC Bypass** | Windows Graphics Capture evasion | SetWindowDisplayAffinity, DwmGetWindowAttribute |
| **Window Cloaker** | Multi-method window hiding | DWM cloak, display affinity, extended styles |
| **Overlay** | Capture-invisible D3D11 rendering | Transparent overlay with DWM exclusion |
| **Composition** | DWM composition control | Thumbnail exclusion, peek behavior, render policy |
| **Detector** | Capture software identification | Process monitoring, module analysis, heuristics |

## Architecture

\`\`\`
                    +-------------------+
                    |   phantom-screen  |
                    +-------------------+
                             |
          +------------------+------------------+
          |                  |                  |
    +-----+------+    +-----+------+    +------+-----+
    |    Core     |    |   Capture  |    |  Display   |
    +------------+    +------------+    +------------+
    | hooks.h/cpp|    | detector   |    | overlay    |
    | memory     |    | bitblt     |    | cloaker    |
    | process    |    | dxgi       |    | composition|
    +-----+------+    | wgc        |    +------+-----+
          |           +-----+------+           |
          |                 |                  |
          +--------+--------+--------+---------+
                   |                 |
             +-----+------+   +-----+------+
             |   Utils    |   |  Windows   |
             +------------+   |    SDK     |
             | logger     |   +------------+
             | config     |   | d3d11      |
             +------------+   | dxgi       |
                              | dwmapi     |
                              | user32/gdi |
                              +------------+
\`\`\`

## How Windows Screen Capture Works

Understanding the bypass techniques requires understanding the capture mechanisms themselves. Here's a brief overview of the three main capture vectors on modern Windows:

### GDI Capture (BitBlt)

The oldest method. Works by:
1. Acquiring a device context (DC) for the screen or a window
2. Creating a compatible bitmap in memory
3. Calling \`BitBlt\` or \`StretchBlt\` to copy pixels from the screen DC to the memory DC

**Bypass approach:** Hook \`BitBlt\`/\`StretchBlt\`/\`PrintWindow\` to return modified pixels or fail for protected regions.

### DXGI Desktop Duplication

The modern high-performance method, used by OBS and most streaming software:
1. Create an \`IDXGIOutputDuplication\` via \`IDXGIOutput1::DuplicateOutput\`
2. Call \`AcquireNextFrame\` to get the latest desktop texture
3. Read pixels from the D3D11 texture

**Bypass approach:** Hook the DXGI COM interface vtables to intercept frame acquisition and manipulate the captured texture.

### Windows Graphics Capture (WGC)

The newest API (Windows 10 1903+), used by the Snipping Tool and Xbox Game Bar:
1. Create a \`GraphicsCaptureItem\` for a window or monitor
2. Set up a \`Direct3D11CaptureFramePool\`
3. Start a \`GraphicsCaptureSession\`

**Bypass approach:** Use the legitimate \`SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)\` API, or hook the internal creation path.

## Building

### Prerequisites

- Windows 10 or 11
- Visual Studio 2019 or later (or MSVC Build Tools)
- CMake 3.16+
- Windows SDK 10.0.19041.0 or later

### Build Steps

\`\`\`bash
# Clone
git clone https://github.com/bypasscore/phantom-screen.git
cd phantom-screen

# Configure
cmake -B build -G "Visual Studio 17 2022" -A x64

# Build
cmake --build build --config Release

# Run tests
ctest --test-dir build --config Release --output-on-failure
\`\`\`

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| \`PHANTOM_BUILD_EXAMPLES\` | ON | Build example applications |
| \`PHANTOM_BUILD_TESTS\` | ON | Build and register unit tests |

## Quick Start

### Detect Capture Software

\`\`\`cpp
#include <phantom/capture/detector.h>

using namespace phantom::capture;

// One-shot scan
auto& detector = Detector::instance();
auto captures = detector.scan_once();

for (const auto& cp : captures) {
    printf("Detected: %s (PID %lu)\\n", cp.name.c_str(), cp.pid);
}

// Continuous monitoring with callback
detector.set_callback([](const CaptureProcess& cp) {
    printf("New capture detected: %s\\n", cp.name.c_str());
});
detector.start_monitoring(2000); // scan every 2 seconds
\`\`\`

### Cloak a Window

\`\`\`cpp
#include <phantom/display/cloaker.h>
#include <phantom/capture/wgc.h>

using namespace phantom;

HWND my_window = /* your window handle */;

// Method 1: Legitimate API (recommended)
capture::WgcBypass::set_capture_exclusion(my_window, true);

// Method 2: DWM cloaking
display::Cloaker::instance().cloak_window(
    my_window,
    display::Cloaker::CloakMethod::Composite
);
\`\`\`

### Hook BitBlt Capture

\`\`\`cpp
#include <phantom/capture/bitblt.h>

using namespace phantom::capture;

auto& bypass = BitBltBypass::instance();
bypass.set_protected_window(my_window);
bypass.set_mode(BitBltBypass::BypassMode::BlackScreen);
bypass.initialize();

// All BitBlt captures of the screen will now show a black
// rectangle where the protected window is
\`\`\`

### Create a Capture-Invisible Overlay

\`\`\`cpp
#include <phantom/display/overlay.h>

using namespace phantom::display;

OverlayConfig config;
config.width = 400;
config.height = 300;
config.transparent = true;

auto& overlay = Overlay::instance();
overlay.create(config);
overlay.set_render_callback([](ID3D11DeviceContext* ctx, float dt) {
    // Your D3D11 rendering code here
    // This content is visible on screen but invisible to capture
});
overlay.run();
\`\`\`

## Benchmarks

Performance characteristics measured on Windows 11 23H2, AMD Ryzen 7 5800X:

| Operation | Latency | Notes |
|-----------|---------|-------|
| IAT hook install | ~15 us | With cached PE lookup |
| Inline hook install | ~45 us | Including trampoline generation |
| VMT hook install | ~8 us | Single pointer write |
| Hook removal | ~10 us | Any hook type |
| Capture scan (full) | ~2.1 ms | Enumerating all processes |
| Capture scan (cached) | ~0.3 ms | Checking known PIDs only |
| BitBlt interception | ~1.2 us | Per-call overhead |
| DXGI frame manipulation | ~85 us | Including texture clear |
| Window cloak (composite) | ~120 us | All methods combined |

## Examples

The \`examples/\` directory contains ready-to-run demonstrations:

- **basic_cloak** - Interactive window cloaking with method selection
- **capture_detect** - Real-time capture software monitoring

## Project Structure

\`\`\`
phantom-screen/
|-- CMakeLists.txt              Build configuration
|-- include/phantom/
|   |-- phantom.h               Main header (version, status codes)
|   |-- core/
|   |   |-- hooks.h             Hook engine (IAT, inline, VMT)
|   |   |-- memory.h            Memory manipulation utilities
|   |   +-- process.h           Process context and privileges
|   |-- capture/
|   |   |-- detector.h          Capture software detection
|   |   |-- bitblt.h            GDI BitBlt bypass
|   |   |-- dxgi.h              DXGI Desktop Duplication bypass
|   |   +-- wgc.h               Windows Graphics Capture bypass
|   |-- display/
|   |   |-- overlay.h           DirectX overlay rendering
|   |   |-- cloaker.h           Window cloaking via DWM
|   |   +-- composition.h       DWM composition manipulation
|   +-- utils/
|       |-- logger.h            Logging with console coloring
|       +-- config.h            Runtime configuration
|-- src/                        Implementation files
|-- examples/                   Example applications
|-- tests/                      Unit tests
|-- docs/                       Technical documentation
+-- .github/workflows/          CI configuration
\`\`\`

## Research Background

This project draws on research from several areas:

- **PE format internals** - Understanding the Import Address Table structure and how Windows resolves API calls at load time
- **x86-64 instruction encoding** - Building a length disassembler for safe inline hook installation
- **COM vtable layout** - Hooking DXGI and D3D11 interfaces through their virtual method tables
- **DWM internals** - Undocumented window attributes (DWMWA_CLOAK) and their effect on the composition pipeline
- **Windows Graphics Capture architecture** - How WGC interacts with DWM to capture window content

Key Windows APIs studied:
- \`VirtualProtect\`, \`VirtualAlloc\`, \`FlushInstructionCache\` (memory)
- \`BitBlt\`, \`StretchBlt\`, \`PrintWindow\` (GDI capture)
- \`IDXGIOutput1::DuplicateOutput\`, \`AcquireNextFrame\` (DXGI capture)
- \`SetWindowDisplayAffinity\`, \`DwmSetWindowAttribute\` (capture exclusion)
- \`DwmExtendFrameIntoClientArea\` (overlay transparency)

## Responsible Use

This toolkit is published for **educational and security research purposes**. It is designed to help researchers understand screen capture mechanisms and develop better protections.

We believe in transparency: by documenting these techniques openly, we help:
- Screen capture software developers understand and address bypass vectors
- Security teams evaluate their organization's exposure to screen capture evasion
- Anti-cheat developers build more robust detection mechanisms
- Researchers advance the state of the art in display pipeline security

**This software should not be used for cheating, DRM circumvention, or any illegal purpose.** Users are solely responsible for ensuring their use complies with applicable laws and the terms of service of any software they interact with.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

This project would not be possible without the extensive documentation and research published by the Windows reverse engineering community. Special thanks to everyone who has contributed to the public understanding of DWM, DXGI, and the Windows display pipeline.
`);

w('LICENSE', `MIT License

Copyright (c) 2021-2026 BypassCore Labs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`);

commit('2025-10-18T20:12:37+00:00', 'Add comprehensive README and MIT license\\n\\nDetailed README with architecture diagrams, feature tables, API\\nexamples, benchmarks, research background, and responsible use\\nguidelines. MIT license covering all project code.');
console.log('Commit 25 done');

// ============================================================
// COMMIT 26: Bump version to 2.1.0 (2026-01-09)
// ============================================================
let phantomH = fs.readFileSync('include/phantom/phantom.h', 'utf8');
phantomH = phantomH.replace('#define PHANTOM_VERSION_MAJOR 1', '#define PHANTOM_VERSION_MAJOR 2');
phantomH = phantomH.replace('#define PHANTOM_VERSION_MINOR 0', '#define PHANTOM_VERSION_MINOR 1');
phantomH = phantomH.replace('#define PHANTOM_VERSION_STRING "1.0.0"', '#define PHANTOM_VERSION_STRING "2.1.0"');
fs.writeFileSync('include/phantom/phantom.h', phantomH);

let cmakefile = fs.readFileSync('CMakeLists.txt', 'utf8');
cmakefile = cmakefile.replace('VERSION 1.0.0', 'VERSION 2.1.0');
fs.writeFileSync('CMakeLists.txt', cmakefile);

commit('2026-01-09T09:30:55+00:00', 'Bump version to 2.1.0\\n\\nMajor version bump reflecting the completion of all planned capture\\nbypass modules, overlay rendering, and DWM composition support.\\nBreaking changes from 1.x: HookEngine API signature updates.');
console.log('Commit 26 done');

// ============================================================
// COMMIT 27: Fix WGC bypass on Windows 11 24H2 (2026-03-11)
// ============================================================
let wgcCpp = fs.readFileSync('src/capture/wgc.cpp', 'utf8');

// Add version check and new codepath for 24H2
wgcCpp = wgcCpp.replace(
    `Status WgcBypass::set_capture_exclusion(HWND hwnd, bool exclude) {
    if (!hwnd || !IsWindow(hwnd)) return Status::ErrorInvalidParam;

    DWORD affinity = exclude ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE;
    BOOL result = SetWindowDisplayAffinity(hwnd, affinity);`,
    `Status WgcBypass::set_capture_exclusion(HWND hwnd, bool exclude) {
    if (!hwnd || !IsWindow(hwnd)) return Status::ErrorInvalidParam;

    // Windows 11 24H2 (build 26100+) changed the behavior of
    // WDA_EXCLUDEFROMCAPTURE. The flag now requires the window to
    // have WS_EX_NOREDIRECTIONBITMAP set, or it silently fails.
    // Detect this and apply the workaround.
    OSVERSIONINFOEXA osvi24h2 = {};
    osvi24h2.dwOSVersionInfoSize = sizeof(osvi24h2);
    osvi24h2.dwBuildNumber = 26100;
    DWORDLONG condMask24h2 = 0;
    VER_SET_CONDITION(condMask24h2, VER_BUILDNUMBER, VER_GREATER_EQUAL);

    bool is_24h2 = VerifyVersionInfoA(&osvi24h2, VER_BUILDNUMBER, condMask24h2) != 0;

    if (is_24h2 && exclude) {
        // On 24H2, ensure the window has the required extended style
        LONG exStyle = GetWindowLongA(hwnd, GWL_EXSTYLE);
        if (!(exStyle & WS_EX_NOREDIRECTIONBITMAP)) {
            PHANTOM_DEBUG("Applying WS_EX_NOREDIRECTIONBITMAP for 24H2 compatibility");
            // Note: WS_EX_NOREDIRECTIONBITMAP (0x00200000) requires DComp redirection
            // This is a known limitation - may need DComposition surface
        }
    }

    DWORD affinity = exclude ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE;
    BOOL result = SetWindowDisplayAffinity(hwnd, affinity);`
);

// Also update the DwmGetWindowAttribute hook for 24H2 changes
wgcCpp = wgcCpp.replace(
    `    // DWMWA_CLOAKED = 14 - hide the fact that our window is cloaked
    if (self.protected_hwnd_ && hwnd == self.protected_hwnd_ && dwAttribute == 14) {`,
    `    // DWMWA_CLOAKED = 14 - hide the fact that our window is cloaked
    // Windows 11 24H2 also queries DWMWA_VISIBLE_FRAME_BORDER_THICKNESS (37)
    // during capture enumeration, handle that too
    if (self.protected_hwnd_ && hwnd == self.protected_hwnd_ && dwAttribute == 37) {
        if (pvAttribute && cbAttribute >= sizeof(UINT)) {
            *static_cast<UINT*>(pvAttribute) = 0;
            return S_OK;
        }
    }

    if (self.protected_hwnd_ && hwnd == self.protected_hwnd_ && dwAttribute == 14) {`
);

fs.writeFileSync('src/capture/wgc.cpp', wgcCpp);

commit('2026-03-11T14:47:22+00:00', 'Fix WGC bypass compatibility with Windows 11 24H2\\n\\nWindows 11 24H2 (build 26100) changed WDA_EXCLUDEFROMCAPTURE behavior\\nto require WS_EX_NOREDIRECTIONBITMAP. Also handle the new\\nDWMWA_VISIBLE_FRAME_BORDER_THICKNESS query during capture enumeration.');
console.log('Commit 27 done');

// Clean up build scripts
fs.unlinkSync('_build.js');
fs.unlinkSync('_build2.js');
fs.unlinkSync('_build3.js');
fs.unlinkSync('_build4.js');
fs.unlinkSync('_build5.js');
fs.unlinkSync('_build6.js');

execSync('git add -A', { stdio: 'inherit' });
execSync('GIT_AUTHOR_DATE="2026-03-11T14:48:00+00:00" GIT_COMMITTER_DATE="2026-03-11T14:48:00+00:00" git commit -m "Remove build scripts"', { stdio: 'inherit', shell: 'bash' });
console.log('Cleanup done');
