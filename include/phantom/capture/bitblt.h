#pragma once
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
