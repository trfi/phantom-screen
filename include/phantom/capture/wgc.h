#pragma once
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
