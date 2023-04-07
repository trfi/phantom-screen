#include <phantom/capture/wgc.h>
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
