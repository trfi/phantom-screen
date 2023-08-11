#pragma once
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
