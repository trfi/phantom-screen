#pragma once
#ifndef PHANTOM_CLOAKER_H
#define PHANTOM_CLOAKER_H

#include <phantom/phantom.h>
#include <dwmapi.h>
#include <vector>
#include <string>
#include <mutex>

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
