<div align="center">

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

```
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
```

## How Windows Screen Capture Works

Understanding the bypass techniques requires understanding the capture mechanisms themselves. Here's a brief overview of the three main capture vectors on modern Windows:

### GDI Capture (BitBlt)

The oldest method. Works by:
1. Acquiring a device context (DC) for the screen or a window
2. Creating a compatible bitmap in memory
3. Calling `BitBlt` or `StretchBlt` to copy pixels from the screen DC to the memory DC

**Bypass approach:** Hook `BitBlt`/`StretchBlt`/`PrintWindow` to return modified pixels or fail for protected regions.

### DXGI Desktop Duplication

The modern high-performance method, used by OBS and most streaming software:
1. Create an `IDXGIOutputDuplication` via `IDXGIOutput1::DuplicateOutput`
2. Call `AcquireNextFrame` to get the latest desktop texture
3. Read pixels from the D3D11 texture

**Bypass approach:** Hook the DXGI COM interface vtables to intercept frame acquisition and manipulate the captured texture.

### Windows Graphics Capture (WGC)

The newest API (Windows 10 1903+), used by the Snipping Tool and Xbox Game Bar:
1. Create a `GraphicsCaptureItem` for a window or monitor
2. Set up a `Direct3D11CaptureFramePool`
3. Start a `GraphicsCaptureSession`

**Bypass approach:** Use the legitimate `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` API, or hook the internal creation path.

## Building

### Prerequisites

- Windows 10 or 11
- Visual Studio 2019 or later (or MSVC Build Tools)
- CMake 3.16+
- Windows SDK 10.0.19041.0 or later

### Build Steps

```bash
# Clone
git clone https://github.com/bypasscore/phantom-screen.git
cd phantom-screen

# Configure
cmake -B build -G "Visual Studio 17 2022" -A x64

# Build
cmake --build build --config Release

# Run tests
ctest --test-dir build --config Release --output-on-failure
```

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `PHANTOM_BUILD_EXAMPLES` | ON | Build example applications |
| `PHANTOM_BUILD_TESTS` | ON | Build and register unit tests |

## Quick Start

### Detect Capture Software

```cpp
#include <phantom/capture/detector.h>

using namespace phantom::capture;

// One-shot scan
auto& detector = Detector::instance();
auto captures = detector.scan_once();

for (const auto& cp : captures) {
    printf("Detected: %s (PID %lu)\n", cp.name.c_str(), cp.pid);
}

// Continuous monitoring with callback
detector.set_callback([](const CaptureProcess& cp) {
    printf("New capture detected: %s\n", cp.name.c_str());
});
detector.start_monitoring(2000); // scan every 2 seconds
```

### Cloak a Window

```cpp
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
```

### Hook BitBlt Capture

```cpp
#include <phantom/capture/bitblt.h>

using namespace phantom::capture;

auto& bypass = BitBltBypass::instance();
bypass.set_protected_window(my_window);
bypass.set_mode(BitBltBypass::BypassMode::BlackScreen);
bypass.initialize();

// All BitBlt captures of the screen will now show a black
// rectangle where the protected window is
```

### Create a Capture-Invisible Overlay

```cpp
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
```

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

The `examples/` directory contains ready-to-run demonstrations:

- **basic_cloak** - Interactive window cloaking with method selection
- **capture_detect** - Real-time capture software monitoring

## Project Structure

```
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
```

## Research Background

This project draws on research from several areas:

- **PE format internals** - Understanding the Import Address Table structure and how Windows resolves API calls at load time
- **x86-64 instruction encoding** - Building a length disassembler for safe inline hook installation
- **COM vtable layout** - Hooking DXGI and D3D11 interfaces through their virtual method tables
- **DWM internals** - Undocumented window attributes (DWMWA_CLOAK) and their effect on the composition pipeline
- **Windows Graphics Capture architecture** - How WGC interacts with DWM to capture window content

Key Windows APIs studied:
- `VirtualProtect`, `VirtualAlloc`, `FlushInstructionCache` (memory)
- `BitBlt`, `StretchBlt`, `PrintWindow` (GDI capture)
- `IDXGIOutput1::DuplicateOutput`, `AcquireNextFrame` (DXGI capture)
- `SetWindowDisplayAffinity`, `DwmSetWindowAttribute` (capture exclusion)
- `DwmExtendFrameIntoClientArea` (overlay transparency)

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

## Contact

Interested in custom bypass research, need enterprise support, or want to discuss a use case?

- **Email:** [contact@bypasscore.com](mailto:contact@bypasscore.com)
- **Telegram:** [@bypasscore](https://t.me/bypasscore)
- **Web:** [bypasscore.com](https://bypasscore.com)

## Support

Help keep BypassCore open-source and independent.

| Network | Address |
|---------|---------|
| **Polygon** | `0xd0f38b51496bee61ea5e9e56e2c414b607ab011a` |
| **Ethereum** | `0xd0f38b51496bee61ea5e9e56e2c414b607ab011a` |
| **BSC** | `0xd0f38b51496bee61ea5e9e56e2c414b607ab011a` |
| **Arbitrum** | `0xd0f38b51496bee61ea5e9e56e2c414b607ab011a` |
| **Optimism** | `0xd0f38b51496bee61ea5e9e56e2c414b607ab011a` |
| **Avalanche** | `0xd0f38b51496bee61ea5e9e56e2c414b607ab011a` |

USDT / USDC / ETH / BNB accepted on all networks.
