#pragma once
#ifndef PHANTOM_DXGI_H
#define PHANTOM_DXGI_H

#include <phantom/phantom.h>
#include <phantom/core/hooks.h>
#include <dxgi1_2.h>
#include <d3d11.h>

namespace phantom { namespace capture {

/**
 * Bypass for DXGI Desktop Duplication API.
 *
 * Modern capture software (OBS, etc.) uses IDXGIOutputDuplication
 * to capture the desktop compositor output. This module hooks the
 * DXGI interfaces to manipulate or block capture.
 *
 * Hook targets:
 * - IDXGIOutput1::DuplicateOutput (creation)
 * - IDXGIOutputDuplication::AcquireNextFrame
 * - IDXGIOutputDuplication::MapDesktopSurface
 */
class DxgiBypass {
public:
    static DxgiBypass& instance();

    Status initialize();
    void shutdown();
    bool is_active() const { return active_; }

    // Set a region to cloak (pixels in this region will be replaced)
    void set_cloak_region(RECT region) { cloak_region_ = region; }
    void set_cloak_hwnd(HWND hwnd) { cloak_hwnd_ = hwnd; }
    void set_enabled(bool enabled) { enabled_ = enabled; }

private:
    DxgiBypass() = default;
    ~DxgiBypass() { shutdown(); }
    DxgiBypass(const DxgiBypass&) = delete;
    DxgiBypass& operator=(const DxgiBypass&) = delete;

    static HRESULT STDMETHODCALLTYPE hooked_DuplicateOutput(
        IDXGIOutput1* pOutput,
        IUnknown* pDevice,
        IDXGIOutputDuplication** ppDuplication);

    static HRESULT STDMETHODCALLTYPE hooked_AcquireNextFrame(
        IDXGIOutputDuplication* pDuplication,
        UINT timeout,
        DXGI_OUTDUPL_FRAME_INFO* pFrameInfo,
        IDXGIResource** ppResource);

    bool manipulate_frame_texture(ID3D11Texture2D* texture);
    void clear_region_in_texture(ID3D11DeviceContext* ctx, ID3D11Texture2D* texture, RECT region);

    bool active_ = false;
    bool enabled_ = true;
    RECT cloak_region_ = {};
    HWND cloak_hwnd_ = nullptr;

    // Original vtable function pointers
    static void* original_DuplicateOutput_;
    static void* original_AcquireNextFrame_;

    // Cached D3D11 device/context
    ID3D11Device* device_ = nullptr;
    ID3D11DeviceContext* context_ = nullptr;
};

}} // namespace phantom::capture

#endif // PHANTOM_DXGI_H
