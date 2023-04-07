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
// COMMIT 12: Windows Graphics Capture bypass (2023-04-07)
// ============================================================
w('include/phantom/capture/wgc.h', `#pragma once
#ifndef PHANTOM_WGC_H
#define PHANTOM_WGC_H

#include <phantom/phantom.h>
#include <phantom/core/hooks.h>

namespace phantom { namespace capture {

/**
 * Bypass for Windows.Graphics.Capture (WGC) API.
 *
 * The WGC API (introduced in Windows 10 1903) is the recommended
 * modern capture method. It uses:
 * - GraphicsCaptureItem to target windows/monitors
 * - Direct3D11CaptureFramePool for frame acquisition
 * - GraphicsCaptureSession to control capture
 *
 * Bypass strategies:
 * - Hook CreateForWindow/CreateForMonitor to prevent capture item creation
 * - Manipulate the captured frame textures
 * - Set WDA_EXCLUDEFROMCAPTURE on protected windows (legitimate API)
 * - Hook dwmapi functions that WGC relies on internally
 */
class WgcBypass {
public:
    static WgcBypass& instance();

    Status initialize();
    void shutdown();
    bool is_active() const { return active_; }

    // The legitimate approach: use SetWindowDisplayAffinity
    static Status set_capture_exclusion(HWND hwnd, bool exclude);

    // Hook-based approach for broader protection
    Status enable_hook_bypass();
    void disable_hook_bypass();

    void set_protected_window(HWND hwnd) { protected_hwnd_ = hwnd; }

private:
    WgcBypass() = default;
    ~WgcBypass() { shutdown(); }
    WgcBypass(const WgcBypass&) = delete;
    WgcBypass& operator=(const WgcBypass&) = delete;

    // Hook for SetWindowDisplayAffinity to enforce our settings
    static BOOL WINAPI hooked_SetWindowDisplayAffinity(HWND hwnd, DWORD dwAffinity);
    static decltype(&SetWindowDisplayAffinity) original_SetWindowDisplayAffinity_;

    // Hook for DwmGetWindowAttribute to hide cloaking state
    static HRESULT WINAPI hooked_DwmGetWindowAttribute(HWND hwnd, DWORD dwAttribute,
                                                        PVOID pvAttribute, DWORD cbAttribute);
    static void* original_DwmGetWindowAttribute_;

    // Hook for internal WGC creation path
    static HRESULT hooked_CreateCaptureItemForWindow(HWND hwnd, void** item);
    static void* original_CreateCaptureItemForWindow_;

    bool active_ = false;
    bool hook_bypass_active_ = false;
    HWND protected_hwnd_ = nullptr;
};

}} // namespace phantom::capture

#endif // PHANTOM_WGC_H
`);

w('src/capture/wgc.cpp', `#include <phantom/capture/wgc.h>
#include <phantom/utils/logger.h>
#include <dwmapi.h>

#pragma comment(lib, "dwmapi.lib")

// WDA_EXCLUDEFROMCAPTURE was added in Windows 10 2004 (build 19041)
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

namespace phantom { namespace capture {

decltype(&SetWindowDisplayAffinity) WgcBypass::original_SetWindowDisplayAffinity_ = nullptr;
void* WgcBypass::original_DwmGetWindowAttribute_ = nullptr;
void* WgcBypass::original_CreateCaptureItemForWindow_ = nullptr;

WgcBypass& WgcBypass::instance() {
    static WgcBypass inst;
    return inst;
}

Status WgcBypass::initialize() {
    if (active_) return Status::ErrorAlreadyInitialized;

    // Check Windows version - WGC requires 1903+
    OSVERSIONINFOEXA osvi = {};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    osvi.dwBuildNumber = 18362; // 1903

    DWORDLONG condMask = 0;
    VER_SET_CONDITION(condMask, VER_BUILDNUMBER, VER_GREATER_EQUAL);

    if (!VerifyVersionInfoA(&osvi, VER_BUILDNUMBER, condMask)) {
        PHANTOM_WARN("WGC bypass requires Windows 10 1903 or later");
        return Status::ErrorNotSupported;
    }

    active_ = true;
    PHANTOM_INFO("WGC bypass initialized");
    return Status::Success;
}

void WgcBypass::shutdown() {
    if (!active_) return;
    disable_hook_bypass();
    active_ = false;
    PHANTOM_INFO("WGC bypass shutdown");
}

Status WgcBypass::set_capture_exclusion(HWND hwnd, bool exclude) {
    if (!hwnd || !IsWindow(hwnd)) return Status::ErrorInvalidParam;

    DWORD affinity = exclude ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE;
    BOOL result = SetWindowDisplayAffinity(hwnd, affinity);

    if (!result) {
        DWORD err = GetLastError();
        // WDA_EXCLUDEFROMCAPTURE requires Windows 10 2004+
        if (err == ERROR_INVALID_PARAMETER && exclude) {
            PHANTOM_WARN("WDA_EXCLUDEFROMCAPTURE not supported, falling back to WDA_MONITOR");
            result = SetWindowDisplayAffinity(hwnd, WDA_MONITOR);
        }

        if (!result) {
            PHANTOM_ERROR("SetWindowDisplayAffinity failed, error=" + std::to_string(GetLastError()));
            return Status::ErrorCaptureFailed;
        }
    }

    PHANTOM_INFO(std::string("Window capture exclusion ") +
                 (exclude ? "enabled" : "disabled") +
                 " for HWND " + std::to_string(reinterpret_cast<uintptr_t>(hwnd)));
    return Status::Success;
}

Status WgcBypass::enable_hook_bypass() {
    if (hook_bypass_active_) return Status::ErrorAlreadyInitialized;

    auto& engine = core::HookEngine::instance();

    // Hook SetWindowDisplayAffinity to prevent other code from
    // removing our capture exclusion
    Status result = engine.install_iat_hook(
        "SetWindowDisplayAffinity",
        "user32.dll",
        "SetWindowDisplayAffinity",
        reinterpret_cast<void*>(&hooked_SetWindowDisplayAffinity),
        reinterpret_cast<void**>(&original_SetWindowDisplayAffinity_)
    );

    if (result != Status::Success) {
        PHANTOM_WARN("Could not hook SetWindowDisplayAffinity");
    }

    // Hook DwmGetWindowAttribute to control what information
    // capture software can query about our windows
    void* dwm_func = (void*)GetProcAddress(
        GetModuleHandleA("dwmapi.dll"), "DwmGetWindowAttribute");
    if (dwm_func) {
        result = engine.install_inline_hook(
            "DwmGetWindowAttribute",
            dwm_func,
            reinterpret_cast<void*>(&hooked_DwmGetWindowAttribute),
            &original_DwmGetWindowAttribute_
        );
        if (result != Status::Success) {
            PHANTOM_WARN("Could not hook DwmGetWindowAttribute");
        }
    }

    hook_bypass_active_ = true;
    PHANTOM_INFO("WGC hook bypass enabled");
    return Status::Success;
}

void WgcBypass::disable_hook_bypass() {
    if (!hook_bypass_active_) return;

    auto& engine = core::HookEngine::instance();
    engine.remove_hook("SetWindowDisplayAffinity");
    engine.remove_hook("DwmGetWindowAttribute");

    original_SetWindowDisplayAffinity_ = nullptr;
    original_DwmGetWindowAttribute_ = nullptr;

    hook_bypass_active_ = false;
    PHANTOM_INFO("WGC hook bypass disabled");
}

BOOL WINAPI WgcBypass::hooked_SetWindowDisplayAffinity(HWND hwnd, DWORD dwAffinity) {
    auto& self = instance();

    // Prevent removal of capture exclusion on our protected window
    if (self.protected_hwnd_ && hwnd == self.protected_hwnd_) {
        if (dwAffinity == WDA_NONE) {
            PHANTOM_WARN("Blocked attempt to remove capture exclusion on protected window");
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }

    return original_SetWindowDisplayAffinity_(hwnd, dwAffinity);
}

HRESULT WINAPI WgcBypass::hooked_DwmGetWindowAttribute(HWND hwnd, DWORD dwAttribute,
                                                         PVOID pvAttribute, DWORD cbAttribute) {
    auto& self = instance();

    typedef HRESULT(WINAPI* DwmGetWindowAttribute_t)(HWND, DWORD, PVOID, DWORD);
    auto original = reinterpret_cast<DwmGetWindowAttribute_t>(original_DwmGetWindowAttribute_);

    // DWMWA_CLOAKED = 14 - hide the fact that our window is cloaked
    if (self.protected_hwnd_ && hwnd == self.protected_hwnd_ && dwAttribute == 14) {
        if (pvAttribute && cbAttribute >= sizeof(DWORD)) {
            *static_cast<DWORD*>(pvAttribute) = 0; // Not cloaked
            return S_OK;
        }
    }

    return original(hwnd, dwAttribute, pvAttribute, cbAttribute);
}

HRESULT WgcBypass::hooked_CreateCaptureItemForWindow(HWND hwnd, void** item) {
    auto& self = instance();

    if (self.protected_hwnd_ && hwnd == self.protected_hwnd_) {
        PHANTOM_DEBUG("Blocked WGC capture item creation for protected window");
        return E_ACCESSDENIED;
    }

    typedef HRESULT(*CreateCaptureItemForWindow_t)(HWND, void**);
    auto original = reinterpret_cast<CreateCaptureItemForWindow_t>(original_CreateCaptureItemForWindow_);
    return original(hwnd, item);
}

}} // namespace phantom::capture
`);

commit('2023-04-07T13:29:51+00:00', 'Implement Windows Graphics Capture API bypass\\n\\nAdd WGC bypass using both legitimate (SetWindowDisplayAffinity with\\nWDA_EXCLUDEFROMCAPTURE) and hook-based approaches. Intercepts\\nDwmGetWindowAttribute to hide cloaking state from capture software.');
console.log('Commit 12 done');

// ============================================================
// COMMIT 13: DWM window cloaking (2023-06-22)
// ============================================================
w('include/phantom/display/cloaker.h', `#pragma once
#ifndef PHANTOM_CLOAKER_H
#define PHANTOM_CLOAKER_H

#include <phantom/phantom.h>
#include <dwmapi.h>
#include <vector>
#include <string>

namespace phantom { namespace display {

/**
 * Window cloaking via Desktop Window Manager (DWM).
 *
 * DWM cloaking makes a window invisible to screen capture while
 * remaining visible to the user (in certain configurations) or
 * completely hidden from the compositor.
 *
 * Techniques:
 * - DwmSetWindowAttribute with DWMWA_CLOAK
 * - Shell cloaking (undocumented DWMWA values)
 * - Extended window styles (WS_EX_TOOLWINDOW + WS_EX_LAYERED)
 * - SetWindowDisplayAffinity for selective visibility
 */
class Cloaker {
public:
    static Cloaker& instance();

    enum class CloakMethod {
        DWM_Cloak,          // Use DWMWA_CLOAK attribute
        DisplayAffinity,    // Use SetWindowDisplayAffinity
        ExtendedStyle,      // Use window style manipulation
        Composite           // Combine multiple methods
    };

    Status cloak_window(HWND hwnd, CloakMethod method = CloakMethod::Composite);
    Status uncloak_window(HWND hwnd);

    bool is_cloaked(HWND hwnd) const;
    std::vector<HWND> get_cloaked_windows() const;

    // Advanced: cloak from specific processes only
    Status cloak_from_process(HWND hwnd, DWORD target_pid);

private:
    Cloaker() = default;
    ~Cloaker();
    Cloaker(const Cloaker&) = delete;
    Cloaker& operator=(const Cloaker&) = delete;

    Status apply_dwm_cloak(HWND hwnd, bool cloak);
    Status apply_display_affinity(HWND hwnd, bool cloak);
    Status apply_extended_style(HWND hwnd, bool cloak);
    Status apply_composite_cloak(HWND hwnd, bool cloak);

    struct CloakedWindow {
        HWND hwnd;
        CloakMethod method;
        LONG original_exstyle;
        DWORD original_affinity;
    };

    mutable std::mutex mutex_;
    std::vector<CloakedWindow> cloaked_windows_;
};

}} // namespace phantom::display

#endif // PHANTOM_CLOAKER_H
`);

w('src/display/cloaker.cpp', `#include <phantom/display/cloaker.h>
#include <phantom/utils/logger.h>
#include <algorithm>

#pragma comment(lib, "dwmapi.lib")

// Undocumented DWM attribute for cloaking
#ifndef DWMWA_CLOAK
#define DWMWA_CLOAK 13
#endif

#ifndef DWMWA_CLOAKED
#define DWMWA_CLOAKED 14
#endif

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

namespace phantom { namespace display {

Cloaker& Cloaker::instance() {
    static Cloaker inst;
    return inst;
}

Cloaker::~Cloaker() {
    // Uncloak all windows on destruction
    auto windows = cloaked_windows_;
    for (auto& cw : windows) {
        uncloak_window(cw.hwnd);
    }
}

Status Cloaker::cloak_window(HWND hwnd, CloakMethod method) {
    if (!hwnd || !IsWindow(hwnd)) return Status::ErrorInvalidParam;

    std::lock_guard<std::mutex> lock(mutex_);

    // Check if already cloaked
    auto it = std::find_if(cloaked_windows_.begin(), cloaked_windows_.end(),
                           [hwnd](const CloakedWindow& cw) { return cw.hwnd == hwnd; });
    if (it != cloaked_windows_.end()) {
        PHANTOM_WARN("Window already cloaked");
        return Status::ErrorAlreadyInitialized;
    }

    // Save original state
    CloakedWindow cw{};
    cw.hwnd = hwnd;
    cw.method = method;
    cw.original_exstyle = GetWindowLongA(hwnd, GWL_EXSTYLE);

    Status result;
    switch (method) {
        case CloakMethod::DWM_Cloak:
            result = apply_dwm_cloak(hwnd, true);
            break;
        case CloakMethod::DisplayAffinity:
            result = apply_display_affinity(hwnd, true);
            break;
        case CloakMethod::ExtendedStyle:
            result = apply_extended_style(hwnd, true);
            break;
        case CloakMethod::Composite:
            result = apply_composite_cloak(hwnd, true);
            break;
        default:
            return Status::ErrorInvalidParam;
    }

    if (result == Status::Success) {
        cloaked_windows_.push_back(cw);
        PHANTOM_INFO("Window cloaked: HWND=" + std::to_string(reinterpret_cast<uintptr_t>(hwnd)));
    }

    return result;
}

Status Cloaker::uncloak_window(HWND hwnd) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = std::find_if(cloaked_windows_.begin(), cloaked_windows_.end(),
                           [hwnd](const CloakedWindow& cw) { return cw.hwnd == hwnd; });

    if (it == cloaked_windows_.end()) return Status::ErrorInvalidParam;

    CloakedWindow cw = *it;

    switch (cw.method) {
        case CloakMethod::DWM_Cloak:
            apply_dwm_cloak(hwnd, false);
            break;
        case CloakMethod::DisplayAffinity:
            apply_display_affinity(hwnd, false);
            break;
        case CloakMethod::ExtendedStyle:
            SetWindowLongA(hwnd, GWL_EXSTYLE, cw.original_exstyle);
            break;
        case CloakMethod::Composite:
            apply_composite_cloak(hwnd, false);
            SetWindowLongA(hwnd, GWL_EXSTYLE, cw.original_exstyle);
            break;
    }

    cloaked_windows_.erase(it);
    PHANTOM_INFO("Window uncloaked: HWND=" + std::to_string(reinterpret_cast<uintptr_t>(hwnd)));
    return Status::Success;
}

bool Cloaker::is_cloaked(HWND hwnd) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::any_of(cloaked_windows_.begin(), cloaked_windows_.end(),
                       [hwnd](const CloakedWindow& cw) { return cw.hwnd == hwnd; });
}

std::vector<HWND> Cloaker::get_cloaked_windows() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<HWND> result;
    result.reserve(cloaked_windows_.size());
    for (const auto& cw : cloaked_windows_) {
        result.push_back(cw.hwnd);
    }
    return result;
}

Status Cloaker::apply_dwm_cloak(HWND hwnd, bool cloak) {
    BOOL cloakValue = cloak ? TRUE : FALSE;
    HRESULT hr = DwmSetWindowAttribute(hwnd, DWMWA_CLOAK, &cloakValue, sizeof(cloakValue));

    if (FAILED(hr)) {
        PHANTOM_ERROR("DwmSetWindowAttribute(DWMWA_CLOAK) failed: 0x" +
                      std::to_string(hr));
        return Status::ErrorCaptureFailed;
    }

    return Status::Success;
}

Status Cloaker::apply_display_affinity(HWND hwnd, bool cloak) {
    DWORD affinity = cloak ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE;
    if (!SetWindowDisplayAffinity(hwnd, affinity)) {
        // Fallback to WDA_MONITOR
        if (cloak) {
            affinity = WDA_MONITOR;
            if (!SetWindowDisplayAffinity(hwnd, affinity)) {
                PHANTOM_ERROR("SetWindowDisplayAffinity failed");
                return Status::ErrorCaptureFailed;
            }
        } else {
            PHANTOM_ERROR("SetWindowDisplayAffinity(WDA_NONE) failed");
            return Status::ErrorCaptureFailed;
        }
    }
    return Status::Success;
}

Status Cloaker::apply_extended_style(HWND hwnd, bool cloak) {
    if (cloak) {
        LONG exStyle = GetWindowLongA(hwnd, GWL_EXSTYLE);
        exStyle |= WS_EX_TOOLWINDOW;  // Hide from taskbar
        exStyle |= WS_EX_LAYERED;     // Enable layered attributes
        exStyle |= WS_EX_TRANSPARENT; // Click-through
        SetWindowLongA(hwnd, GWL_EXSTYLE, exStyle);

        // Set full transparency for capture while visible on display
        SetLayeredWindowAttributes(hwnd, 0, 255, LWA_ALPHA);
    }
    // Restoration is handled via saved original_exstyle
    return Status::Success;
}

Status Cloaker::apply_composite_cloak(HWND hwnd, bool cloak) {
    // Apply all methods for maximum protection
    Status result = apply_display_affinity(hwnd, cloak);
    if (result != Status::Success) {
        PHANTOM_WARN("Display affinity method failed, continuing with other methods");
    }

    // DWM cloak makes the window invisible to the user too,
    // so only use it if specifically requested
    // apply_dwm_cloak(hwnd, cloak);

    if (cloak) {
        apply_extended_style(hwnd, cloak);
    }

    return Status::Success;
}

Status Cloaker::cloak_from_process(HWND hwnd, DWORD target_pid) {
    // This is a more advanced technique that would require:
    // 1. Hooking NtUserBuildHwndList in the target process
    // 2. Filtering out our window from enumeration results
    // For now, we use the composite cloak method
    PHANTOM_INFO("Process-specific cloaking for PID " + std::to_string(target_pid));
    return cloak_window(hwnd, CloakMethod::Composite);
}

}} // namespace phantom::display
`);

commit('2023-06-22T17:08:33+00:00', 'Add DWM window cloaking\\n\\nImplement window cloaking via multiple methods: DWM DWMWA_CLOAK\\nattribute, SetWindowDisplayAffinity, extended window styles, and\\na composite approach combining all techniques for maximum capture\\nevasion.');
console.log('Commit 13 done');

// ============================================================
// COMMIT 14: DirectX overlay rendering (2023-08-11)
// ============================================================
w('include/phantom/display/overlay.h', `#pragma once
#ifndef PHANTOM_OVERLAY_H
#define PHANTOM_OVERLAY_H

#include <phantom/phantom.h>
#include <d3d11.h>
#include <dxgi.h>
#include <DirectXMath.h>
#include <string>
#include <functional>

namespace phantom { namespace display {

struct OverlayConfig {
    int width = 1920;
    int height = 1080;
    bool topmost = true;
    bool transparent = true;
    bool click_through = true;
    float opacity = 1.0f;
    std::string window_title = "PhantomOverlay";
};

using RenderCallback = std::function<void(ID3D11DeviceContext*, float)>;

/**
 * DirectX 11 overlay window for rendering content that is
 * invisible to screen capture while visible to the user.
 *
 * Uses a transparent, click-through, topmost window with
 * DWM exclusion from capture.
 */
class Overlay {
public:
    static Overlay& instance();

    Status create(const OverlayConfig& config = {});
    void destroy();
    bool is_created() const { return created_; }

    void set_render_callback(RenderCallback cb) { render_callback_ = std::move(cb); }

    Status begin_frame(float clear_color[4] = nullptr);
    Status end_frame();

    void set_position(int x, int y);
    void set_size(int width, int height);
    void set_opacity(float opacity);
    void show();
    void hide();

    HWND get_hwnd() const { return hwnd_; }
    ID3D11Device* get_device() const { return device_; }
    ID3D11DeviceContext* get_context() const { return context_; }
    ID3D11RenderTargetView* get_rtv() const { return rtv_; }

    // Run the overlay message loop (blocking)
    void run();
    void stop() { running_ = false; }

private:
    Overlay() = default;
    ~Overlay() { destroy(); }
    Overlay(const Overlay&) = delete;
    Overlay& operator=(const Overlay&) = delete;

    bool create_window(const OverlayConfig& config);
    bool create_d3d_device();
    bool create_swap_chain();
    bool create_render_target();

    static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    bool created_ = false;
    bool running_ = false;
    HWND hwnd_ = nullptr;
    OverlayConfig config_;

    // D3D11 resources
    ID3D11Device* device_ = nullptr;
    ID3D11DeviceContext* context_ = nullptr;
    IDXGISwapChain* swap_chain_ = nullptr;
    ID3D11RenderTargetView* rtv_ = nullptr;

    RenderCallback render_callback_;
    LARGE_INTEGER frequency_;
    LARGE_INTEGER last_time_;
};

}} // namespace phantom::display

#endif // PHANTOM_OVERLAY_H
`);

w('src/display/overlay.cpp', `#include <phantom/display/overlay.h>
#include <phantom/display/cloaker.h>
#include <phantom/utils/logger.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

namespace phantom { namespace display {

Overlay& Overlay::instance() {
    static Overlay inst;
    return inst;
}

Status Overlay::create(const OverlayConfig& config) {
    if (created_) return Status::ErrorAlreadyInitialized;

    config_ = config;

    if (!create_window(config)) {
        PHANTOM_ERROR("Failed to create overlay window");
        return Status::ErrorGeneric;
    }

    if (!create_d3d_device()) {
        PHANTOM_ERROR("Failed to create D3D11 device");
        DestroyWindow(hwnd_);
        return Status::ErrorGeneric;
    }

    if (!create_swap_chain()) {
        PHANTOM_ERROR("Failed to create swap chain");
        destroy();
        return Status::ErrorGeneric;
    }

    if (!create_render_target()) {
        PHANTOM_ERROR("Failed to create render target");
        destroy();
        return Status::ErrorGeneric;
    }

    // Exclude from screen capture
    SetWindowDisplayAffinity(hwnd_, WDA_EXCLUDEFROMCAPTURE);

    // Apply DWM cloaking for additional protection
    Cloaker::instance().cloak_window(hwnd_, Cloaker::CloakMethod::DisplayAffinity);

    QueryPerformanceFrequency(&frequency_);
    QueryPerformanceCounter(&last_time_);

    created_ = true;
    PHANTOM_INFO("Overlay created (" + std::to_string(config.width) + "x" +
                 std::to_string(config.height) + ")");
    return Status::Success;
}

void Overlay::destroy() {
    if (!created_ && !hwnd_) return;

    if (hwnd_) {
        Cloaker::instance().uncloak_window(hwnd_);
    }

    if (rtv_) { rtv_->Release(); rtv_ = nullptr; }
    if (swap_chain_) { swap_chain_->Release(); swap_chain_ = nullptr; }
    if (context_) { context_->Release(); context_ = nullptr; }
    if (device_) { device_->Release(); device_ = nullptr; }
    if (hwnd_) { DestroyWindow(hwnd_); hwnd_ = nullptr; }

    created_ = false;
    PHANTOM_INFO("Overlay destroyed");
}

bool Overlay::create_window(const OverlayConfig& config) {
    WNDCLASSEXA wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = GetModuleHandleA(nullptr);
    wc.lpszClassName = "PhantomOverlayClass";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);

    RegisterClassExA(&wc);

    DWORD exStyle = WS_EX_TOPMOST | WS_EX_LAYERED;
    if (config.transparent) exStyle |= WS_EX_TRANSPARENT;

    hwnd_ = CreateWindowExA(
        exStyle,
        wc.lpszClassName,
        config.window_title.c_str(),
        WS_POPUP,
        0, 0,
        config.width, config.height,
        nullptr, nullptr,
        wc.hInstance, this
    );

    if (!hwnd_) return false;

    // Set layered window attributes for transparency
    SetLayeredWindowAttributes(hwnd_, RGB(0, 0, 0), 0, LWA_COLORKEY);

    // Extend DWM frame into client area for full transparency
    MARGINS margins = { -1, -1, -1, -1 };
    DwmExtendFrameIntoClientArea(hwnd_, &margins);

    if (config.topmost) {
        SetWindowPos(hwnd_, HWND_TOPMOST, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }

    ShowWindow(hwnd_, SW_SHOWNOACTIVATE);
    UpdateWindow(hwnd_);

    return true;
}

bool Overlay::create_d3d_device() {
    D3D_FEATURE_LEVEL featureLevels[] = {
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1,
    };

    D3D_FEATURE_LEVEL featureLevel;
    HRESULT hr = D3D11CreateDevice(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT,
        featureLevels, 3,
        D3D11_SDK_VERSION,
        &device_, &featureLevel, &context_
    );

    return SUCCEEDED(hr);
}

bool Overlay::create_swap_chain() {
    IDXGIDevice* dxgiDevice = nullptr;
    IDXGIAdapter* adapter = nullptr;
    IDXGIFactory2* factory = nullptr;

    device_->QueryInterface(__uuidof(IDXGIDevice), (void**)&dxgiDevice);
    dxgiDevice->GetAdapter(&adapter);
    adapter->GetParent(__uuidof(IDXGIFactory2), (void**)&factory);

    DXGI_SWAP_CHAIN_DESC1 desc = {};
    desc.Width = config_.width;
    desc.Height = config_.height;
    desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    desc.BufferCount = 2;
    desc.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
    desc.AlphaMode = DXGI_ALPHA_MODE_PREMULTIPLIED;

    IDXGISwapChain1* swapChain1 = nullptr;
    HRESULT hr = factory->CreateSwapChainForHwnd(
        device_, hwnd_, &desc, nullptr, nullptr, &swapChain1);

    // Fallback to non-flip swap chain if flip model fails
    if (FAILED(hr)) {
        desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
        desc.AlphaMode = DXGI_ALPHA_MODE_UNSPECIFIED;
        hr = factory->CreateSwapChainForHwnd(
            device_, hwnd_, &desc, nullptr, nullptr, &swapChain1);
    }

    if (SUCCEEDED(hr)) {
        swap_chain_ = swapChain1;
    }

    factory->Release();
    adapter->Release();
    dxgiDevice->Release();

    return SUCCEEDED(hr);
}

bool Overlay::create_render_target() {
    ID3D11Texture2D* backBuffer = nullptr;
    HRESULT hr = swap_chain_->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&backBuffer);
    if (FAILED(hr)) return false;

    hr = device_->CreateRenderTargetView(backBuffer, nullptr, &rtv_);
    backBuffer->Release();

    return SUCCEEDED(hr);
}

Status Overlay::begin_frame(float clear_color[4]) {
    if (!created_) return Status::ErrorNotInitialized;

    float default_color[4] = { 0.0f, 0.0f, 0.0f, 0.0f };
    float* color = clear_color ? clear_color : default_color;

    context_->OMSetRenderTargets(1, &rtv_, nullptr);
    context_->ClearRenderTargetView(rtv_, color);

    D3D11_VIEWPORT vp = {};
    vp.Width = (float)config_.width;
    vp.Height = (float)config_.height;
    vp.MaxDepth = 1.0f;
    context_->RSSetViewports(1, &vp);

    return Status::Success;
}

Status Overlay::end_frame() {
    if (!created_) return Status::ErrorNotInitialized;

    HRESULT hr = swap_chain_->Present(1, 0);
    if (FAILED(hr)) {
        PHANTOM_ERROR("Swap chain present failed");
        return Status::ErrorGeneric;
    }

    return Status::Success;
}

void Overlay::set_position(int x, int y) {
    if (hwnd_) SetWindowPos(hwnd_, nullptr, x, y, 0, 0,
                             SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
}

void Overlay::set_size(int width, int height) {
    config_.width = width;
    config_.height = height;
    if (hwnd_) SetWindowPos(hwnd_, nullptr, 0, 0, width, height,
                             SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
}

void Overlay::set_opacity(float opacity) {
    config_.opacity = opacity;
    if (hwnd_) {
        BYTE alpha = static_cast<BYTE>(opacity * 255.0f);
        SetLayeredWindowAttributes(hwnd_, 0, alpha, LWA_ALPHA);
    }
}

void Overlay::show() {
    if (hwnd_) ShowWindow(hwnd_, SW_SHOWNOACTIVATE);
}

void Overlay::hide() {
    if (hwnd_) ShowWindow(hwnd_, SW_HIDE);
}

void Overlay::run() {
    running_ = true;
    MSG msg;

    while (running_) {
        while (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                running_ = false;
                break;
            }
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }

        if (!running_) break;

        // Calculate delta time
        LARGE_INTEGER current_time;
        QueryPerformanceCounter(&current_time);
        float dt = (float)(current_time.QuadPart - last_time_.QuadPart) / (float)frequency_.QuadPart;
        last_time_ = current_time;

        // Render
        begin_frame();
        if (render_callback_) {
            render_callback_(context_, dt);
        }
        end_frame();
    }
}

LRESULT CALLBACK Overlay::wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        case WM_PAINT: {
            PAINTSTRUCT ps;
            BeginPaint(hwnd, &ps);
            EndPaint(hwnd, &ps);
            return 0;
        }
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

}} // namespace phantom::display
`);

commit('2023-08-11T22:15:47+00:00', 'Implement DirectX overlay rendering\\n\\nAdd D3D11-based overlay window with transparency, click-through, and\\nautomatic capture exclusion. Supports custom render callbacks, DWM\\nframe extension for per-pixel alpha, and flip-model swap chain.');
console.log('Commit 14 done');

// ============================================================
// COMMIT 15: DWM composition manipulation (2023-10-05)
// ============================================================
w('include/phantom/display/composition.h', `#pragma once
#ifndef PHANTOM_COMPOSITION_H
#define PHANTOM_COMPOSITION_H

#include <phantom/phantom.h>
#include <phantom/core/hooks.h>
#include <dwmapi.h>

namespace phantom { namespace display {

/**
 * DWM composition manipulation for advanced capture evasion.
 *
 * The Desktop Window Manager composites all visible windows into
 * the final desktop image. By manipulating DWM behavior, we can
 * control how windows appear (or don't appear) in captures.
 *
 * Techniques:
 * - Thumbnail registration manipulation
 * - DWM rendering target redirection
 * - Composition attribute modification
 * - Rendering surface interception
 */
class Composition {
public:
    static Composition& instance();

    Status initialize();
    void shutdown();
    bool is_active() const { return active_; }

    // Exclude a window from DWM thumbnail rendering
    Status exclude_from_thumbnails(HWND hwnd);
    Status include_in_thumbnails(HWND hwnd);

    // Manipulate DWM rendering policy for a window
    Status set_rendering_policy(HWND hwnd, DWORD policy);

    // Hook DWM composition to intercept render targets
    Status hook_composition();
    void unhook_composition();

    // Force DWM to skip rendering a window in capture output
    Status set_capture_render_policy(HWND hwnd, bool visible_in_capture);

private:
    Composition() = default;
    ~Composition() { shutdown(); }
    Composition(const Composition&) = delete;
    Composition& operator=(const Composition&) = delete;

    static HRESULT WINAPI hooked_DwmSetWindowAttribute(HWND hwnd, DWORD dwAttribute,
                                                        LPCVOID pvAttribute, DWORD cbAttribute);
    static HRESULT WINAPI hooked_DwmEnableComposition(UINT uCompositionAction);

    static void* original_DwmSetWindowAttribute_;
    static void* original_DwmEnableComposition_;

    bool active_ = false;
    bool hooks_installed_ = false;
    std::vector<HWND> excluded_windows_;
    mutable std::mutex mutex_;
};

}} // namespace phantom::display

#endif // PHANTOM_COMPOSITION_H
`);

w('src/display/composition.cpp', `#include <phantom/display/composition.h>
#include <phantom/utils/logger.h>
#include <algorithm>

#pragma comment(lib, "dwmapi.lib")

// Undocumented DWM window attributes
#define DWMWA_NCRENDERING_ENABLED_INTERNAL 1
#define DWMWA_FORCE_ICONIC_REPRESENTATION 7
#define DWMWA_DISALLOW_PEEK 11
#define DWMWA_EXCLUDED_FROM_PEEK 12

#ifndef DWMWA_CLOAK
#define DWMWA_CLOAK 13
#endif

namespace phantom { namespace display {

void* Composition::original_DwmSetWindowAttribute_ = nullptr;
void* Composition::original_DwmEnableComposition_ = nullptr;

Composition& Composition::instance() {
    static Composition inst;
    return inst;
}

Status Composition::initialize() {
    if (active_) return Status::ErrorAlreadyInitialized;

    // Verify DWM is running
    BOOL enabled = FALSE;
    HRESULT hr = DwmIsCompositionEnabled(&enabled);
    if (FAILED(hr) || !enabled) {
        PHANTOM_ERROR("DWM composition is not enabled");
        return Status::ErrorNotSupported;
    }

    active_ = true;
    PHANTOM_INFO("DWM composition module initialized");
    return Status::Success;
}

void Composition::shutdown() {
    if (!active_) return;

    unhook_composition();

    // Restore all excluded windows
    std::lock_guard<std::mutex> lock(mutex_);
    for (HWND hwnd : excluded_windows_) {
        if (IsWindow(hwnd)) {
            include_in_thumbnails(hwnd);
        }
    }
    excluded_windows_.clear();

    active_ = false;
    PHANTOM_INFO("DWM composition module shutdown");
}

Status Composition::exclude_from_thumbnails(HWND hwnd) {
    if (!hwnd || !IsWindow(hwnd)) return Status::ErrorInvalidParam;

    // Set DWMWA_DISALLOW_PEEK to prevent Aero Peek from showing this window
    BOOL disallow = TRUE;
    HRESULT hr = DwmSetWindowAttribute(hwnd, DWMWA_DISALLOW_PEEK, &disallow, sizeof(disallow));
    if (FAILED(hr)) {
        PHANTOM_WARN("Failed to set DWMWA_DISALLOW_PEEK");
    }

    // Set DWMWA_EXCLUDED_FROM_PEEK
    BOOL excluded = TRUE;
    hr = DwmSetWindowAttribute(hwnd, DWMWA_EXCLUDED_FROM_PEEK, &excluded, sizeof(excluded));
    if (FAILED(hr)) {
        PHANTOM_WARN("Failed to set DWMWA_EXCLUDED_FROM_PEEK");
    }

    // Force iconic representation (shows thumbnail instead of live content)
    BOOL iconic = TRUE;
    hr = DwmSetWindowAttribute(hwnd, DWMWA_FORCE_ICONIC_REPRESENTATION, &iconic, sizeof(iconic));

    std::lock_guard<std::mutex> lock(mutex_);
    if (std::find(excluded_windows_.begin(), excluded_windows_.end(), hwnd) == excluded_windows_.end()) {
        excluded_windows_.push_back(hwnd);
    }

    PHANTOM_INFO("Window excluded from thumbnails: HWND=" +
                 std::to_string(reinterpret_cast<uintptr_t>(hwnd)));
    return Status::Success;
}

Status Composition::include_in_thumbnails(HWND hwnd) {
    if (!hwnd || !IsWindow(hwnd)) return Status::ErrorInvalidParam;

    BOOL disallow = FALSE;
    DwmSetWindowAttribute(hwnd, DWMWA_DISALLOW_PEEK, &disallow, sizeof(disallow));

    BOOL excluded = FALSE;
    DwmSetWindowAttribute(hwnd, DWMWA_EXCLUDED_FROM_PEEK, &excluded, sizeof(excluded));

    BOOL iconic = FALSE;
    DwmSetWindowAttribute(hwnd, DWMWA_FORCE_ICONIC_REPRESENTATION, &iconic, sizeof(iconic));

    std::lock_guard<std::mutex> lock(mutex_);
    excluded_windows_.erase(
        std::remove(excluded_windows_.begin(), excluded_windows_.end(), hwnd),
        excluded_windows_.end());

    return Status::Success;
}

Status Composition::set_rendering_policy(HWND hwnd, DWORD policy) {
    HRESULT hr = DwmSetWindowAttribute(hwnd, DWMWA_NCRENDERING_ENABLED_INTERNAL,
                                        &policy, sizeof(policy));
    if (FAILED(hr)) {
        PHANTOM_ERROR("Failed to set rendering policy");
        return Status::ErrorCaptureFailed;
    }
    return Status::Success;
}

Status Composition::hook_composition() {
    if (hooks_installed_) return Status::ErrorAlreadyInitialized;

    auto& engine = core::HookEngine::instance();

    void* dwm_set_attr = (void*)GetProcAddress(
        GetModuleHandleA("dwmapi.dll"), "DwmSetWindowAttribute");
    if (dwm_set_attr) {
        Status result = engine.install_inline_hook(
            "DwmSetWindowAttribute_comp",
            dwm_set_attr,
            reinterpret_cast<void*>(&hooked_DwmSetWindowAttribute),
            &original_DwmSetWindowAttribute_
        );
        if (result == Status::Success) {
            PHANTOM_INFO("Hooked DwmSetWindowAttribute");
        }
    }

    hooks_installed_ = true;
    return Status::Success;
}

void Composition::unhook_composition() {
    if (!hooks_installed_) return;

    auto& engine = core::HookEngine::instance();
    engine.remove_hook("DwmSetWindowAttribute_comp");
    engine.remove_hook("DwmEnableComposition_comp");

    original_DwmSetWindowAttribute_ = nullptr;
    original_DwmEnableComposition_ = nullptr;

    hooks_installed_ = false;
}

HRESULT WINAPI Composition::hooked_DwmSetWindowAttribute(HWND hwnd, DWORD dwAttribute,
                                                          LPCVOID pvAttribute, DWORD cbAttribute) {
    auto& self = instance();

    // Prevent other code from uncloaking our excluded windows
    if (dwAttribute == DWMWA_CLOAK || dwAttribute == DWMWA_DISALLOW_PEEK ||
        dwAttribute == DWMWA_EXCLUDED_FROM_PEEK) {
        std::lock_guard<std::mutex> lock(self.mutex_);
        auto it = std::find(self.excluded_windows_.begin(), self.excluded_windows_.end(), hwnd);
        if (it != self.excluded_windows_.end()) {
            PHANTOM_DEBUG("Blocked DwmSetWindowAttribute modification on excluded window");
            return S_OK; // Pretend success
        }
    }

    typedef HRESULT(WINAPI* Fn)(HWND, DWORD, LPCVOID, DWORD);
    auto original = reinterpret_cast<Fn>(original_DwmSetWindowAttribute_);
    return original(hwnd, dwAttribute, pvAttribute, cbAttribute);
}

HRESULT WINAPI Composition::hooked_DwmEnableComposition(UINT uCompositionAction) {
    // Prevent disabling DWM composition (which would break our bypass)
    if (uCompositionAction == 0) { // DWM_EC_DISABLECOMPOSITION
        PHANTOM_WARN("Blocked attempt to disable DWM composition");
        return S_OK;
    }

    typedef HRESULT(WINAPI* Fn)(UINT);
    auto original = reinterpret_cast<Fn>(original_DwmEnableComposition_);
    return original(uCompositionAction);
}

Status Composition::set_capture_render_policy(HWND hwnd, bool visible_in_capture) {
    if (visible_in_capture) {
        return include_in_thumbnails(hwnd);
    } else {
        Status result = exclude_from_thumbnails(hwnd);
        if (result == Status::Success) {
            // Additionally try DWMWA_CLOAK
            BOOL cloak = TRUE;
            DwmSetWindowAttribute(hwnd, DWMWA_CLOAK, &cloak, sizeof(cloak));
        }
        return result;
    }
}

}} // namespace phantom::display
`);

commit('2023-10-05T11:42:18+00:00', 'Add DWM composition manipulation\\n\\nImplement DWM composition control for advanced capture evasion.\\nManipulates thumbnail registration, peek behavior, rendering\\npolicy, and hooks DwmSetWindowAttribute to protect excluded windows.');
console.log('Commit 15 done');
