#include <phantom/display/composition.h>
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
