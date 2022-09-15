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
// COMMIT 9: Screen capture detector (2022-09-15)
// ============================================================
w('include/phantom/capture/detector.h', `#pragma once
#ifndef PHANTOM_DETECTOR_H
#define PHANTOM_DETECTOR_H

#include <phantom/phantom.h>
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include <chrono>

namespace phantom { namespace capture {

enum class CaptureMethod : uint8_t {
    Unknown = 0,
    GDI_BitBlt,
    DXGI_Duplication,
    WindowsGraphicsCapture,
    PrintWindow,
    DirectShow,
    MediaFoundation
};

struct CaptureProcess {
    DWORD pid;
    std::string name;
    std::string window_title;
    CaptureMethod suspected_method;
    bool is_active;
    std::chrono::steady_clock::time_point detected_at;
};

using DetectionCallback = std::function<void(const CaptureProcess&)>;

/**
 * Detects active screen capture software by monitoring running processes,
 * loaded modules, and API usage patterns.
 */
class Detector {
public:
    static Detector& instance();

    Status start_monitoring(uint32_t interval_ms = 1000);
    void stop_monitoring();
    bool is_monitoring() const { return monitoring_.load(); }

    void set_callback(DetectionCallback cb) { callback_ = std::move(cb); }

    std::vector<CaptureProcess> scan_once();
    std::vector<CaptureProcess> get_detected() const;

    static bool is_capture_process(const std::string& process_name);
    static CaptureMethod detect_capture_method(DWORD pid);

private:
    Detector() = default;
    ~Detector() { stop_monitoring(); }
    Detector(const Detector&) = delete;
    Detector& operator=(const Detector&) = delete;

    void monitor_thread(uint32_t interval_ms);
    bool check_loaded_modules(DWORD pid, CaptureMethod& method);
    bool check_window_hooks(DWORD pid);

    std::atomic<bool> monitoring_{false};
    std::thread monitor_thread_;
    mutable std::mutex mutex_;
    std::vector<CaptureProcess> detected_;
    DetectionCallback callback_;

    static const std::vector<std::pair<std::string, CaptureMethod>>& known_capture_apps();
};

}} // namespace phantom::capture

#endif // PHANTOM_DETECTOR_H
`);

w('src/capture/detector.cpp', `#include <phantom/capture/detector.h>
#include <phantom/core/process.h>
#include <phantom/utils/logger.h>
#include <Psapi.h>
#include <algorithm>
#include <cctype>

namespace phantom { namespace capture {

Detector& Detector::instance() {
    static Detector inst;
    return inst;
}

const std::vector<std::pair<std::string, CaptureMethod>>& Detector::known_capture_apps() {
    static const std::vector<std::pair<std::string, CaptureMethod>> apps = {
        {"obs64.exe",              CaptureMethod::DXGI_Duplication},
        {"obs32.exe",              CaptureMethod::DXGI_Duplication},
        {"obs.exe",                CaptureMethod::DXGI_Duplication},
        {"streamlabs obs.exe",     CaptureMethod::DXGI_Duplication},
        {"sharex.exe",             CaptureMethod::GDI_BitBlt},
        {"greenshot.exe",          CaptureMethod::GDI_BitBlt},
        {"lightshot.exe",          CaptureMethod::GDI_BitBlt},
        {"snagit32.exe",           CaptureMethod::GDI_BitBlt},
        {"snagit.exe",             CaptureMethod::GDI_BitBlt},
        {"screenrec.exe",          CaptureMethod::WindowsGraphicsCapture},
        {"gamebarPresenceWriter.exe", CaptureMethod::WindowsGraphicsCapture},
        {"gamebar.exe",            CaptureMethod::WindowsGraphicsCapture},
        {"nvidia share.exe",       CaptureMethod::DXGI_Duplication},
        {"xsplit.core.exe",        CaptureMethod::DXGI_Duplication},
        {"xsplitbroadcaster.exe",  CaptureMethod::DXGI_Duplication},
        {"bandicam.exe",           CaptureMethod::DXGI_Duplication},
        {"fraps.exe",              CaptureMethod::DirectShow},
        {"action.exe",             CaptureMethod::DXGI_Duplication},
        {"camtasia.exe",           CaptureMethod::GDI_BitBlt},
        {"snippingtool.exe",       CaptureMethod::WindowsGraphicsCapture},
        {"screenclip.exe",         CaptureMethod::WindowsGraphicsCapture},
    };
    return apps;
}

bool Detector::is_capture_process(const std::string& process_name) {
    std::string lower_name = process_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    for (const auto& [name, method] : known_capture_apps()) {
        if (lower_name == name) return true;
    }
    return false;
}

CaptureMethod Detector::detect_capture_method(DWORD pid) {
    // Check which capture-related DLLs are loaded
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return CaptureMethod::Unknown;

    HMODULE modules[1024];
    DWORD needed;
    CaptureMethod method = CaptureMethod::Unknown;

    if (EnumProcessModules(hProcess, modules, sizeof(modules), &needed)) {
        DWORD count = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < count; i++) {
            char modName[MAX_PATH];
            if (GetModuleBaseNameA(hProcess, modules[i], modName, sizeof(modName))) {
                std::string name = modName;
                std::transform(name.begin(), name.end(), name.begin(),
                               [](unsigned char c) { return std::tolower(c); });

                if (name.find("dxgi") != std::string::npos ||
                    name.find("d3d11") != std::string::npos) {
                    method = CaptureMethod::DXGI_Duplication;
                }
                if (name.find("dwmapi") != std::string::npos && method == CaptureMethod::Unknown) {
                    method = CaptureMethod::GDI_BitBlt;
                }
                if (name.find("windows.graphics.capture") != std::string::npos) {
                    method = CaptureMethod::WindowsGraphicsCapture;
                    break; // High confidence
                }
            }
        }
    }

    CloseHandle(hProcess);
    return method;
}

bool Detector::check_loaded_modules(DWORD pid, CaptureMethod& method) {
    method = detect_capture_method(pid);
    return method != CaptureMethod::Unknown;
}

bool Detector::check_window_hooks(DWORD pid) {
    // Check if the process has installed any global hooks
    // that might be used for capture (WH_CBT, WH_GETMESSAGE, etc.)
    // This is a heuristic check
    HWND hwnd = nullptr;
    bool found = false;

    // Enumerate windows belonging to this process
    struct EnumData { DWORD pid; bool found; };
    EnumData data = { pid, false };

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* d = reinterpret_cast<EnumData*>(lParam);
        DWORD wndPid;
        GetWindowThreadProcessId(hwnd, &wndPid);
        if (wndPid == d->pid) {
            // Check if window has capture-related styles
            LONG exStyle = GetWindowLongA(hwnd, GWL_EXSTYLE);
            if (exStyle & WS_EX_LAYERED || exStyle & WS_EX_TRANSPARENT) {
                d->found = true;
            }
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&data));

    return data.found;
}

std::vector<CaptureProcess> Detector::scan_once() {
    std::vector<CaptureProcess> results;

    auto processes = core::Process::enumerate_processes();

    for (const auto& proc : processes) {
        std::string lower_name = proc.name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        CaptureMethod method = CaptureMethod::Unknown;

        // Check against known capture applications
        for (const auto& [known_name, known_method] : known_capture_apps()) {
            if (lower_name == known_name) {
                method = known_method;
                break;
            }
        }

        if (method == CaptureMethod::Unknown) {
            // Heuristic: check loaded modules
            CaptureMethod detected_method;
            if (check_loaded_modules(proc.pid, detected_method)) {
                // Only flag if it also has suspicious window behavior
                if (check_window_hooks(proc.pid)) {
                    method = detected_method;
                }
            }
        }

        if (method != CaptureMethod::Unknown) {
            CaptureProcess cp;
            cp.pid = proc.pid;
            cp.name = proc.name;
            cp.suspected_method = method;
            cp.is_active = true;
            cp.detected_at = std::chrono::steady_clock::now();

            // Try to get window title
            struct TitleData { DWORD pid; std::string title; };
            TitleData td = { proc.pid, "" };
            EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
                auto* d = reinterpret_cast<TitleData*>(lParam);
                DWORD wndPid;
                GetWindowThreadProcessId(hwnd, &wndPid);
                if (wndPid == d->pid && IsWindowVisible(hwnd)) {
                    char title[256];
                    GetWindowTextA(hwnd, title, sizeof(title));
                    if (strlen(title) > 0) {
                        d->title = title;
                        return FALSE;
                    }
                }
                return TRUE;
            }, reinterpret_cast<LPARAM>(&td));
            cp.window_title = td.title;

            results.push_back(cp);
        }
    }

    // Update detected list
    {
        std::lock_guard<std::mutex> lock(mutex_);
        detected_ = results;
    }

    return results;
}

std::vector<CaptureProcess> Detector::get_detected() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return detected_;
}

Status Detector::start_monitoring(uint32_t interval_ms) {
    if (monitoring_.load()) return Status::ErrorAlreadyInitialized;

    monitoring_.store(true);
    monitor_thread_ = std::thread(&Detector::monitor_thread, this, interval_ms);

    PHANTOM_INFO("Capture monitoring started (interval=" + std::to_string(interval_ms) + "ms)");
    return Status::Success;
}

void Detector::stop_monitoring() {
    if (!monitoring_.load()) return;
    monitoring_.store(false);
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
    PHANTOM_INFO("Capture monitoring stopped");
}

void Detector::monitor_thread(uint32_t interval_ms) {
    while (monitoring_.load()) {
        auto results = scan_once();

        if (!results.empty() && callback_) {
            for (const auto& cp : results) {
                callback_(cp);
            }
        }

        // Sleep in small increments for responsive shutdown
        auto end_time = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(interval_ms);
        while (monitoring_.load() && std::chrono::steady_clock::now() < end_time) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
}

}} // namespace phantom::capture
`);

commit('2022-09-15T08:55:41+00:00', 'Add screen capture detector\\n\\nImplement capture process detection by monitoring running processes\\nagainst a database of known capture software (OBS, ShareX, Game Bar,\\netc.). Includes heuristic detection via loaded module analysis and\\ncontinuous background monitoring with configurable callbacks.');
console.log('Commit 9 done');

// ============================================================
// COMMIT 10: GDI BitBlt bypass (2022-11-03)
// ============================================================
w('include/phantom/capture/bitblt.h', `#pragma once
#ifndef PHANTOM_BITBLT_H
#define PHANTOM_BITBLT_H

#include <phantom/phantom.h>
#include <phantom/core/hooks.h>
#include <functional>

namespace phantom { namespace capture {

/**
 * Bypass for GDI-based screen capture (BitBlt, StretchBlt, PrintWindow).
 *
 * GDI capture works by:
 * 1. Getting a device context for the screen/window (GetDC/GetWindowDC)
 * 2. Creating a compatible bitmap
 * 3. Using BitBlt/StretchBlt to copy pixels
 *
 * Bypass strategies:
 * - Hook BitBlt/StretchBlt to return a blank/modified image
 * - Hook GetDC to return a DC that excludes protected windows
 * - Hook PrintWindow to fail for protected windows
 */
class BitBltBypass {
public:
    static BitBltBypass& instance();

    Status initialize();
    void shutdown();
    bool is_active() const { return active_; }

    void set_protected_window(HWND hwnd) { protected_hwnd_ = hwnd; }
    HWND get_protected_window() const { return protected_hwnd_; }

    enum class BypassMode {
        BlackScreen,     // Return black pixels for protected region
        DesktopOnly,     // Return desktop wallpaper only
        CustomImage,     // Return user-specified image
        Passthrough      // Temporarily disable bypass
    };

    void set_mode(BypassMode mode) { mode_ = mode; }
    BypassMode get_mode() const { return mode_; }

private:
    BitBltBypass() = default;
    ~BitBltBypass() { shutdown(); }
    BitBltBypass(const BitBltBypass&) = delete;
    BitBltBypass& operator=(const BitBltBypass&) = delete;

    // Hook callbacks (static for C-style function pointer compatibility)
    static BOOL WINAPI hooked_BitBlt(HDC hdc, int x, int y, int cx, int cy,
                                      HDC hdcSrc, int x1, int y1, DWORD rop);
    static BOOL WINAPI hooked_StretchBlt(HDC hdcDest, int xDest, int yDest,
                                          int wDest, int hDest, HDC hdcSrc,
                                          int xSrc, int ySrc, int wSrc, int hSrc, DWORD rop);
    static BOOL WINAPI hooked_PrintWindow(HWND hwnd, HDC hdc, UINT flags);

    bool should_bypass(HDC hdcSrc);

    bool active_ = false;
    HWND protected_hwnd_ = nullptr;
    BypassMode mode_ = BypassMode::BlackScreen;

    // Original function pointers
    static decltype(&BitBlt) original_BitBlt_;
    static decltype(&StretchBlt) original_StretchBlt_;
    static decltype(&PrintWindow) original_PrintWindow_;
};

}} // namespace phantom::capture

#endif // PHANTOM_BITBLT_H
`);

w('src/capture/bitblt.cpp', `#include <phantom/capture/bitblt.h>
#include <phantom/utils/logger.h>

namespace phantom { namespace capture {

// Static member definitions
decltype(&BitBlt) BitBltBypass::original_BitBlt_ = nullptr;
decltype(&StretchBlt) BitBltBypass::original_StretchBlt_ = nullptr;
decltype(&PrintWindow) BitBltBypass::original_PrintWindow_ = nullptr;

BitBltBypass& BitBltBypass::instance() {
    static BitBltBypass inst;
    return inst;
}

Status BitBltBypass::initialize() {
    if (active_) return Status::ErrorAlreadyInitialized;

    auto& engine = core::HookEngine::instance();

    // Hook BitBlt
    Status result = engine.install_iat_hook(
        "BitBlt",
        "gdi32.dll",
        "BitBlt",
        reinterpret_cast<void*>(&hooked_BitBlt),
        reinterpret_cast<void**>(&original_BitBlt_)
    );

    if (result != Status::Success) {
        // Try inline hook as fallback
        void* bitblt_addr = (void*)GetProcAddress(GetModuleHandleA("gdi32.dll"), "BitBlt");
        if (bitblt_addr) {
            result = engine.install_inline_hook(
                "BitBlt",
                bitblt_addr,
                reinterpret_cast<void*>(&hooked_BitBlt),
                reinterpret_cast<void**>(&original_BitBlt_)
            );
        }
    }

    if (result != Status::Success) {
        PHANTOM_ERROR("Failed to hook BitBlt");
        return result;
    }

    // Hook StretchBlt
    result = engine.install_iat_hook(
        "StretchBlt",
        "gdi32.dll",
        "StretchBlt",
        reinterpret_cast<void*>(&hooked_StretchBlt),
        reinterpret_cast<void**>(&original_StretchBlt_)
    );

    if (result != Status::Success) {
        PHANTOM_WARN("Failed to hook StretchBlt (non-fatal)");
    }

    // Hook PrintWindow
    result = engine.install_iat_hook(
        "PrintWindow",
        "user32.dll",
        "PrintWindow",
        reinterpret_cast<void*>(&hooked_PrintWindow),
        reinterpret_cast<void**>(&original_PrintWindow_)
    );

    if (result != Status::Success) {
        PHANTOM_WARN("Failed to hook PrintWindow (non-fatal)");
    }

    active_ = true;
    PHANTOM_INFO("BitBlt bypass initialized");
    return Status::Success;
}

void BitBltBypass::shutdown() {
    if (!active_) return;

    auto& engine = core::HookEngine::instance();
    engine.remove_hook("BitBlt");
    engine.remove_hook("StretchBlt");
    engine.remove_hook("PrintWindow");

    original_BitBlt_ = nullptr;
    original_StretchBlt_ = nullptr;
    original_PrintWindow_ = nullptr;
    active_ = false;

    PHANTOM_INFO("BitBlt bypass shutdown");
}

bool BitBltBypass::should_bypass(HDC hdcSrc) {
    if (mode_ == BypassMode::Passthrough) return false;
    if (!protected_hwnd_) return false;

    // Check if the source DC belongs to the screen or our protected window
    HWND srcWnd = WindowFromDC(hdcSrc);

    // If source is the desktop DC or screen DC, bypass
    if (srcWnd == nullptr || srcWnd == GetDesktopWindow()) {
        return true;
    }

    // If source is our protected window
    if (srcWnd == instance().protected_hwnd_) {
        return true;
    }

    return false;
}

BOOL WINAPI BitBltBypass::hooked_BitBlt(HDC hdc, int x, int y, int cx, int cy,
                                         HDC hdcSrc, int x1, int y1, DWORD rop) {
    auto& self = instance();

    if (self.should_bypass(hdcSrc)) {
        PHANTOM_DEBUG("BitBlt capture intercepted - applying bypass");

        switch (self.mode_) {
            case BypassMode::BlackScreen: {
                // Fill with black instead of actual content
                RECT rc = { x, y, x + cx, y + cy };
                HBRUSH blackBrush = (HBRUSH)GetStockObject(BLACK_BRUSH);
                FillRect(hdc, &rc, blackBrush);
                return TRUE;
            }
            case BypassMode::DesktopOnly: {
                // Capture desktop wallpaper only (no windows)
                HDC desktopDC = GetDC(nullptr);
                // Temporarily hide our window
                HWND protectedWnd = self.protected_hwnd_;
                if (protectedWnd) {
                    ShowWindow(protectedWnd, SW_HIDE);
                }
                BOOL result = original_BitBlt_(hdc, x, y, cx, cy, desktopDC, x1, y1, rop);
                if (protectedWnd) {
                    ShowWindow(protectedWnd, SW_SHOW);
                }
                ReleaseDC(nullptr, desktopDC);
                return result;
            }
            default:
                break;
        }
    }

    return original_BitBlt_(hdc, x, y, cx, cy, hdcSrc, x1, y1, rop);
}

BOOL WINAPI BitBltBypass::hooked_StretchBlt(HDC hdcDest, int xDest, int yDest,
                                             int wDest, int hDest, HDC hdcSrc,
                                             int xSrc, int ySrc, int wSrc, int hSrc, DWORD rop) {
    auto& self = instance();

    if (self.should_bypass(hdcSrc)) {
        PHANTOM_DEBUG("StretchBlt capture intercepted - applying bypass");

        if (self.mode_ == BypassMode::BlackScreen) {
            RECT rc = { xDest, yDest, xDest + wDest, yDest + hDest };
            HBRUSH blackBrush = (HBRUSH)GetStockObject(BLACK_BRUSH);
            FillRect(hdcDest, &rc, blackBrush);
            return TRUE;
        }
    }

    return original_StretchBlt_(hdcDest, xDest, yDest, wDest, hDest,
                                 hdcSrc, xSrc, ySrc, wSrc, hSrc, rop);
}

BOOL WINAPI BitBltBypass::hooked_PrintWindow(HWND hwnd, HDC hdc, UINT flags) {
    auto& self = instance();

    if (self.protected_hwnd_ && hwnd == self.protected_hwnd_) {
        PHANTOM_DEBUG("PrintWindow capture intercepted for protected window");

        if (self.mode_ == BypassMode::BlackScreen) {
            RECT rc;
            GetClientRect(hwnd, &rc);
            HBRUSH blackBrush = (HBRUSH)GetStockObject(BLACK_BRUSH);
            FillRect(hdc, &rc, blackBrush);
            return TRUE;
        }

        // Return failure to make capture software think the call failed
        return FALSE;
    }

    return original_PrintWindow_(hwnd, hdc, flags);
}

}} // namespace phantom::capture
`);

commit('2022-11-03T12:18:29+00:00', 'Implement GDI BitBlt capture bypass\\n\\nHook BitBlt, StretchBlt, and PrintWindow to intercept GDI-based\\nscreen capture. Supports multiple bypass modes: black screen,\\ndesktop-only rendering, and custom image replacement.');
console.log('Commit 10 done');

// ============================================================
// COMMIT 11: DXGI duplication bypass (2023-01-20)
// ============================================================
w('include/phantom/capture/dxgi.h', `#pragma once
#ifndef PHANTOM_DXGI_H
#define PHANTOM_DXGI_H

#include <phantom/phantom.h>
#include <phantom/core/hooks.h>
#include <d3d11.h>
#include <dxgi1_2.h>

namespace phantom { namespace capture {

/**
 * Bypass for DXGI Desktop Duplication API.
 *
 * Modern capture software (OBS, etc.) uses IDXGIOutputDuplication
 * to capture the desktop compositor output. This module hooks the
 * DXGI interfaces to manipulate or block capture.
 *
 * Hook targets:
 * - IDXGIOutput1::DuplicateOutput (creation)
 * - IDXGIOutputDuplication::AcquireNextFrame
 * - IDXGIOutputDuplication::MapDesktopSurface
 */
class DxgiBypass {
public:
    static DxgiBypass& instance();

    Status initialize();
    void shutdown();
    bool is_active() const { return active_; }

    // Set a region to cloak (pixels in this region will be replaced)
    void set_cloak_region(RECT region) { cloak_region_ = region; }
    void set_cloak_hwnd(HWND hwnd) { cloak_hwnd_ = hwnd; }
    void set_enabled(bool enabled) { enabled_ = enabled; }

private:
    DxgiBypass() = default;
    ~DxgiBypass() { shutdown(); }
    DxgiBypass(const DxgiBypass&) = delete;
    DxgiBypass& operator=(const DxgiBypass&) = delete;

    static HRESULT STDMETHODCALLTYPE hooked_DuplicateOutput(
        IDXGIOutput1* pOutput,
        IUnknown* pDevice,
        IDXGIOutputDuplication** ppDuplication);

    static HRESULT STDMETHODCALLTYPE hooked_AcquireNextFrame(
        IDXGIOutputDuplication* pDuplication,
        UINT timeout,
        DXGI_OUTDUPL_FRAME_INFO* pFrameInfo,
        IDXGIResource** ppResource);

    bool manipulate_frame_texture(ID3D11Texture2D* texture);
    void clear_region_in_texture(ID3D11DeviceContext* ctx, ID3D11Texture2D* texture, RECT region);

    bool active_ = false;
    bool enabled_ = true;
    RECT cloak_region_ = {};
    HWND cloak_hwnd_ = nullptr;

    // Original vtable function pointers
    static void* original_DuplicateOutput_;
    static void* original_AcquireNextFrame_;

    // Cached D3D11 device/context
    ID3D11Device* device_ = nullptr;
    ID3D11DeviceContext* context_ = nullptr;
};

}} // namespace phantom::capture

#endif // PHANTOM_DXGI_H
`);

w('src/capture/dxgi.cpp', `#include <phantom/capture/dxgi.h>
#include <phantom/utils/logger.h>
#include <dxgi1_2.h>
#include <d3d11.h>
#include <cstring>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

namespace phantom { namespace capture {

void* DxgiBypass::original_DuplicateOutput_ = nullptr;
void* DxgiBypass::original_AcquireNextFrame_ = nullptr;

DxgiBypass& DxgiBypass::instance() {
    static DxgiBypass inst;
    return inst;
}

Status DxgiBypass::initialize() {
    if (active_) return Status::ErrorAlreadyInitialized;

    // Create a temporary D3D11 device to get the DXGI interfaces
    D3D_FEATURE_LEVEL featureLevel;
    ID3D11Device* device = nullptr;
    ID3D11DeviceContext* context = nullptr;
    IDXGIDevice* dxgiDevice = nullptr;
    IDXGIAdapter* adapter = nullptr;
    IDXGIOutput* output = nullptr;
    IDXGIOutput1* output1 = nullptr;

    HRESULT hr = D3D11CreateDevice(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        0, nullptr, 0, D3D11_SDK_VERSION,
        &device, &featureLevel, &context
    );

    if (FAILED(hr)) {
        PHANTOM_ERROR("Failed to create D3D11 device for DXGI bypass");
        return Status::ErrorNotSupported;
    }

    device_ = device;
    context_ = context;

    // Get DXGI interfaces to find vtable
    hr = device->QueryInterface(__uuidof(IDXGIDevice), (void**)&dxgiDevice);
    if (FAILED(hr)) {
        PHANTOM_ERROR("Failed to get IDXGIDevice");
        device->Release();
        context->Release();
        return Status::ErrorNotSupported;
    }

    hr = dxgiDevice->GetAdapter(&adapter);
    dxgiDevice->Release();
    if (FAILED(hr)) {
        PHANTOM_ERROR("Failed to get adapter");
        device->Release();
        context->Release();
        return Status::ErrorNotSupported;
    }

    hr = adapter->EnumOutputs(0, &output);
    adapter->Release();
    if (FAILED(hr)) {
        PHANTOM_WARN("No display output found (headless?)");
        device->Release();
        context->Release();
        return Status::ErrorNotSupported;
    }

    hr = output->QueryInterface(__uuidof(IDXGIOutput1), (void**)&output1);
    output->Release();
    if (FAILED(hr)) {
        PHANTOM_ERROR("IDXGIOutput1 not supported");
        device->Release();
        context->Release();
        return Status::ErrorNotSupported;
    }

    // Hook IDXGIOutput1::DuplicateOutput via VMT
    // DuplicateOutput is at vtable index 22 for IDXGIOutput1
    void** vtable = *reinterpret_cast<void***>(output1);
    auto& engine = core::HookEngine::instance();

    Status result = engine.install_vmt_hook(
        "DuplicateOutput",
        vtable, 22,
        reinterpret_cast<void*>(&hooked_DuplicateOutput),
        &original_DuplicateOutput_
    );

    if (result != Status::Success) {
        PHANTOM_ERROR("Failed to hook DuplicateOutput");
        output1->Release();
        device->Release();
        context->Release();
        return result;
    }

    output1->Release();
    active_ = true;
    PHANTOM_INFO("DXGI bypass initialized");
    return Status::Success;
}

void DxgiBypass::shutdown() {
    if (!active_) return;

    auto& engine = core::HookEngine::instance();
    engine.remove_hook("DuplicateOutput");
    engine.remove_hook("AcquireNextFrame");

    original_DuplicateOutput_ = nullptr;
    original_AcquireNextFrame_ = nullptr;

    if (context_) { context_->Release(); context_ = nullptr; }
    if (device_) { device_->Release(); device_ = nullptr; }

    active_ = false;
    PHANTOM_INFO("DXGI bypass shutdown");
}

HRESULT STDMETHODCALLTYPE DxgiBypass::hooked_DuplicateOutput(
    IDXGIOutput1* pOutput,
    IUnknown* pDevice,
    IDXGIOutputDuplication** ppDuplication) {

    PHANTOM_DEBUG("DuplicateOutput called - intercepted");

    // Call original
    typedef HRESULT(STDMETHODCALLTYPE* DuplicateOutput_t)(IDXGIOutput1*, IUnknown*, IDXGIOutputDuplication**);
    auto original = reinterpret_cast<DuplicateOutput_t>(original_DuplicateOutput_);
    HRESULT hr = original(pOutput, pDevice, ppDuplication);

    if (SUCCEEDED(hr) && ppDuplication && *ppDuplication) {
        // Now hook AcquireNextFrame on the returned duplication object
        void** duplication_vtable = *reinterpret_cast<void***>(*ppDuplication);
        auto& engine = core::HookEngine::instance();

        // AcquireNextFrame is at vtable index 8
        if (!engine.is_hooked("AcquireNextFrame")) {
            engine.install_vmt_hook(
                "AcquireNextFrame",
                duplication_vtable, 8,
                reinterpret_cast<void*>(&hooked_AcquireNextFrame),
                &original_AcquireNextFrame_
            );
        }
    }

    return hr;
}

HRESULT STDMETHODCALLTYPE DxgiBypass::hooked_AcquireNextFrame(
    IDXGIOutputDuplication* pDuplication,
    UINT timeout,
    DXGI_OUTDUPL_FRAME_INFO* pFrameInfo,
    IDXGIResource** ppResource) {

    auto& self = instance();

    typedef HRESULT(STDMETHODCALLTYPE* AcquireNextFrame_t)(
        IDXGIOutputDuplication*, UINT, DXGI_OUTDUPL_FRAME_INFO*, IDXGIResource**);
    auto original = reinterpret_cast<AcquireNextFrame_t>(original_AcquireNextFrame_);
    HRESULT hr = original(pDuplication, timeout, pFrameInfo, ppResource);

    if (SUCCEEDED(hr) && self.enabled_ && ppResource && *ppResource) {
        // Get the texture from the resource
        ID3D11Texture2D* texture = nullptr;
        hr = (*ppResource)->QueryInterface(__uuidof(ID3D11Texture2D), (void**)&texture);
        if (SUCCEEDED(hr) && texture) {
            self.manipulate_frame_texture(texture);
            texture->Release();
        }
    }

    return hr;
}

bool DxgiBypass::manipulate_frame_texture(ID3D11Texture2D* texture) {
    if (!context_ || !device_) return false;

    RECT region = cloak_region_;

    // If we have a window handle, get its screen rect
    if (cloak_hwnd_ && IsWindow(cloak_hwnd_)) {
        GetWindowRect(cloak_hwnd_, &region);
    }

    if (region.right <= region.left || region.bottom <= region.top) return false;

    clear_region_in_texture(context_, texture, region);
    return true;
}

void DxgiBypass::clear_region_in_texture(ID3D11DeviceContext* ctx,
                                          ID3D11Texture2D* texture,
                                          RECT region) {
    D3D11_TEXTURE2D_DESC desc;
    texture->GetDesc(&desc);

    // Clamp region to texture bounds
    if (region.left < 0) region.left = 0;
    if (region.top < 0) region.top = 0;
    if (region.right > (LONG)desc.Width) region.right = desc.Width;
    if (region.bottom > (LONG)desc.Height) region.bottom = desc.Height;

    // Create a staging texture for the cloaked region
    D3D11_TEXTURE2D_DESC stagingDesc = desc;
    stagingDesc.Width = region.right - region.left;
    stagingDesc.Height = region.bottom - region.top;
    stagingDesc.MipLevels = 1;
    stagingDesc.ArraySize = 1;
    stagingDesc.Usage = D3D11_USAGE_STAGING;
    stagingDesc.BindFlags = 0;
    stagingDesc.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;

    ID3D11Texture2D* staging = nullptr;
    HRESULT hr = device_->CreateTexture2D(&stagingDesc, nullptr, &staging);
    if (FAILED(hr)) return;

    // Map and fill with black
    D3D11_MAPPED_SUBRESOURCE mapped;
    hr = ctx->Map(staging, 0, D3D11_MAP_WRITE, 0, &mapped);
    if (SUCCEEDED(hr)) {
        for (UINT y = 0; y < stagingDesc.Height; y++) {
            memset(static_cast<uint8_t*>(mapped.pData) + y * mapped.RowPitch,
                   0, stagingDesc.Width * 4);
        }
        ctx->Unmap(staging, 0);

        // Copy the black region back to the captured texture
        D3D11_BOX srcBox = {};
        srcBox.left = 0;
        srcBox.top = 0;
        srcBox.front = 0;
        srcBox.right = stagingDesc.Width;
        srcBox.bottom = stagingDesc.Height;
        srcBox.back = 1;

        ctx->CopySubresourceRegion(texture, 0, region.left, region.top, 0,
                                    staging, 0, &srcBox);
    }

    staging->Release();
}

}} // namespace phantom::capture
`);

commit('2023-01-20T19:44:03+00:00', 'Add DXGI desktop duplication bypass\\n\\nHook IDXGIOutput1::DuplicateOutput and IDXGIOutputDuplication::AcquireNextFrame\\nvia VMT patching. Manipulates captured frames by clearing specified regions\\nin the D3D11 texture. Targets modern capture tools like OBS Studio.');
console.log('Commit 11 done');
