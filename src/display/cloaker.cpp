#include <phantom/display/cloaker.h>
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
