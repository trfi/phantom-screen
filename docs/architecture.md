# phantom-screen Architecture

## Overview

phantom-screen is a modular C++17 toolkit for researching Windows screen capture mechanisms and evasion techniques. The architecture is designed around three main pillars: **hooking**, **capture bypass**, and **display manipulation**.

## Module Structure

```
phantom-screen/
+-- core/           Low-level primitives (hooks, memory, process)
+-- capture/        Capture detection and bypass modules
+-- display/        Window cloaking and overlay rendering
+-- utils/          Cross-cutting concerns (logging, config)
```

## Core Module

### Hook Engine (core/hooks)

The hook engine supports three hooking methods:

| Method | Mechanism | Best For |
|--------|-----------|----------|
| IAT    | Patch Import Address Table entries | API interception in current module |
| Inline | Overwrite function prologue with JMP | Any function, any module |
| VMT    | Patch virtual method table pointers | COM interfaces (DXGI, D3D) |

**Inline Hook Flow:**
1. Calculate minimum bytes to overwrite (length disassembly)
2. Allocate trampoline near target (within +/-2GB)
3. Copy original bytes to trampoline
4. Append JMP-back to trampoline
5. Write JMP-to-detour at target

### Memory (core/memory)

Provides safe memory operations with automatic protection management:
- RAII ProtectionGuard for scoped protection changes
- Pattern scanning with wildcard masks
- Nearby allocation for relative addressing
- Instruction cache flushing

### Process (core/process)

Process interaction utilities:
- Privilege elevation (SeDebugPrivilege)
- Process/thread enumeration and manipulation
- Remote DLL injection
- Module enumeration

## Capture Module

### Detector (capture/detector)

Identifies active screen capture software through:
1. Process name matching against known capture applications
2. Loaded module analysis (DXGI, WGC DLLs)
3. Window behavior heuristics

### BitBlt Bypass (capture/bitblt)

Hooks GDI capture functions:
- `BitBlt` - Primary GDI screen copy
- `StretchBlt` - Scaled screen copy
- `PrintWindow` - Window-specific capture

### DXGI Bypass (capture/dxgi)

Hooks DXGI Desktop Duplication:
- `IDXGIOutput1::DuplicateOutput` - Duplication creation
- `IDXGIOutputDuplication::AcquireNextFrame` - Frame acquisition
- Manipulates D3D11 textures to clear protected regions

### WGC Bypass (capture/wgc)

Combines legitimate and hook-based approaches:
- `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` - Official API
- Hooks `DwmGetWindowAttribute` to hide cloaking state
- Blocks capture item creation for protected windows

## Display Module

### Cloaker (display/cloaker)

Multiple cloaking strategies:
- **DWM Cloak**: Uses undocumented DWMWA_CLOAK attribute
- **Display Affinity**: WDA_EXCLUDEFROMCAPTURE flag
- **Extended Style**: WS_EX_TOOLWINDOW + WS_EX_LAYERED
- **Composite**: Combines all methods

### Overlay (display/overlay)

D3D11 overlay rendering:
- Transparent, click-through window
- Automatic capture exclusion
- DWM frame extension for per-pixel alpha
- Custom render callback support

### Composition (display/composition)

DWM composition control:
- Thumbnail exclusion
- Peek behavior manipulation
- Rendering policy modification
- Protected attribute enforcement via hooks

## Thread Safety

All singleton instances use std::mutex for thread safety. The hook engine serializes all hook operations to prevent race conditions during function patching.

## Build System

CMake 3.16+ with C++17. Windows-only (MSVC recommended).

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

## Dependencies

Windows SDK components only (no external dependencies):
- d3d11.lib, dxgi.lib (DirectX 11)
- dwmapi.lib (Desktop Window Manager)
- user32.lib, gdi32.lib (GDI/Window management)
- psapi.lib, advapi32.lib (Process/privilege APIs)
