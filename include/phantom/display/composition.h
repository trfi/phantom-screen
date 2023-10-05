#pragma once
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
