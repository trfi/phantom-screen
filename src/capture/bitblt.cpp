#include <phantom/capture/bitblt.h>
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
