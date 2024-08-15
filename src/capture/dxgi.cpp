#include <phantom/capture/dxgi.h>
#include <phantom/utils/logger.h>
#include <dxgi1_2.h>
#include <d3d11.h>
#include <cstring>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

namespace phantom { namespace capture {

void* DxgiBypass::original_DuplicateOutput_ = nullptr;
void* DxgiBypass::original_AcquireNextFrame_ = nullptr;

DxgiBypass& DxgiBypass::instance() {
    static DxgiBypass inst;
    return inst;
}

Status DxgiBypass::initialize() {
    if (active_) return Status::ErrorAlreadyInitialized;

    // Create a temporary D3D11 device to get the DXGI interfaces
    D3D_FEATURE_LEVEL featureLevel;
    ID3D11Device* device = nullptr;
    ID3D11DeviceContext* context = nullptr;
    IDXGIDevice* dxgiDevice = nullptr;
    IDXGIAdapter* adapter = nullptr;
    IDXGIOutput* output = nullptr;
    IDXGIOutput1* output1 = nullptr;

    HRESULT hr = D3D11CreateDevice(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        0, nullptr, 0, D3D11_SDK_VERSION,
        &device, &featureLevel, &context
    );

    if (FAILED(hr)) {
        PHANTOM_ERROR("Failed to create D3D11 device for DXGI bypass");
        return Status::ErrorNotSupported;
    }

    device_ = device;
    context_ = context;

    // Get DXGI interfaces to find vtable
    hr = device->QueryInterface(__uuidof(IDXGIDevice), (void**)&dxgiDevice);
    if (FAILED(hr)) {
        PHANTOM_ERROR("Failed to get IDXGIDevice");
        device->Release();
        context->Release();
        return Status::ErrorNotSupported;
    }

    hr = dxgiDevice->GetAdapter(&adapter);
    dxgiDevice->Release();
    if (FAILED(hr)) {
        PHANTOM_ERROR("Failed to get adapter");
        device->Release();
        context->Release();
        return Status::ErrorNotSupported;
    }

    // Enumerate all outputs (multi-monitor support)
    // Previously only checked output 0 which crashed on multi-monitor
    // setups where the primary output index could differ
    std::vector<IDXGIOutput*> outputs;
    IDXGIOutput* tmpOutput = nullptr;
    for (UINT i = 0; adapter->EnumOutputs(i, &tmpOutput) != DXGI_ERROR_NOT_FOUND; i++) {
        outputs.push_back(tmpOutput);
    }
    adapter->Release();

    if (outputs.empty()) {
        PHANTOM_WARN("No display outputs found (headless?)");
        device->Release();
        context->Release();
        return Status::ErrorNotSupported;
    }

    // Use the first output; hook will apply to all duplications
    output = outputs[0];
    // Release extra outputs
    for (size_t i = 1; i < outputs.size(); i++) {
        outputs[i]->Release();
    }
    PHANTOM_INFO("Found " + std::to_string(outputs.size()) + " display output(s)");

    hr = output->QueryInterface(__uuidof(IDXGIOutput1), (void**)&output1);
    output->Release();
    if (FAILED(hr)) {
        PHANTOM_ERROR("IDXGIOutput1 not supported");
        device->Release();
        context->Release();
        return Status::ErrorNotSupported;
    }

    // Hook IDXGIOutput1::DuplicateOutput via VMT
    // DuplicateOutput is at vtable index 22 for IDXGIOutput1
    void** vtable = *reinterpret_cast<void***>(output1);
    auto& engine = core::HookEngine::instance();

    Status result = engine.install_vmt_hook(
        "DuplicateOutput",
        vtable, 22,
        reinterpret_cast<void*>(&hooked_DuplicateOutput),
        &original_DuplicateOutput_
    );

    if (result != Status::Success) {
        PHANTOM_ERROR("Failed to hook DuplicateOutput");
        output1->Release();
        device->Release();
        context->Release();
        return result;
    }

    output1->Release();
    active_ = true;
    PHANTOM_INFO("DXGI bypass initialized");
    return Status::Success;
}

void DxgiBypass::shutdown() {
    if (!active_) return;

    auto& engine = core::HookEngine::instance();
    engine.remove_hook("DuplicateOutput");
    engine.remove_hook("AcquireNextFrame");

    original_DuplicateOutput_ = nullptr;
    original_AcquireNextFrame_ = nullptr;

    if (context_) { context_->Release(); context_ = nullptr; }
    if (device_) { device_->Release(); device_ = nullptr; }

    active_ = false;
    PHANTOM_INFO("DXGI bypass shutdown");
}

HRESULT STDMETHODCALLTYPE DxgiBypass::hooked_DuplicateOutput(
    IDXGIOutput1* pOutput,
    IUnknown* pDevice,
    IDXGIOutputDuplication** ppDuplication) {

    PHANTOM_DEBUG("DuplicateOutput called - intercepted");

    // Call original
    typedef HRESULT(STDMETHODCALLTYPE* DuplicateOutput_t)(IDXGIOutput1*, IUnknown*, IDXGIOutputDuplication**);
    auto original = reinterpret_cast<DuplicateOutput_t>(original_DuplicateOutput_);
    HRESULT hr = original(pOutput, pDevice, ppDuplication);

    if (SUCCEEDED(hr) && ppDuplication && *ppDuplication) {
        // Now hook AcquireNextFrame on the returned duplication object
        void** duplication_vtable = *reinterpret_cast<void***>(*ppDuplication);
        auto& engine = core::HookEngine::instance();

        // AcquireNextFrame is at vtable index 8
        if (!engine.is_hooked("AcquireNextFrame")) {
            engine.install_vmt_hook(
                "AcquireNextFrame",
                duplication_vtable, 8,
                reinterpret_cast<void*>(&hooked_AcquireNextFrame),
                &original_AcquireNextFrame_
            );
        }
    }

    return hr;
}

HRESULT STDMETHODCALLTYPE DxgiBypass::hooked_AcquireNextFrame(
    IDXGIOutputDuplication* pDuplication,
    UINT timeout,
    DXGI_OUTDUPL_FRAME_INFO* pFrameInfo,
    IDXGIResource** ppResource) {

    auto& self = instance();

    typedef HRESULT(STDMETHODCALLTYPE* AcquireNextFrame_t)(
        IDXGIOutputDuplication*, UINT, DXGI_OUTDUPL_FRAME_INFO*, IDXGIResource**);
    auto original = reinterpret_cast<AcquireNextFrame_t>(original_AcquireNextFrame_);
    HRESULT hr = original(pDuplication, timeout, pFrameInfo, ppResource);

    if (SUCCEEDED(hr) && self.enabled_ && ppResource && *ppResource) {
        // Get the texture from the resource
        ID3D11Texture2D* texture = nullptr;
        hr = (*ppResource)->QueryInterface(__uuidof(ID3D11Texture2D), (void**)&texture);
        if (SUCCEEDED(hr) && texture) {
            self.manipulate_frame_texture(texture);
            texture->Release();
        }
    }

    return hr;
}

bool DxgiBypass::manipulate_frame_texture(ID3D11Texture2D* texture) {
    if (!context_ || !device_) return false;

    RECT region = cloak_region_;

    // If we have a window handle, get its screen rect
    if (cloak_hwnd_ && IsWindow(cloak_hwnd_)) {
        GetWindowRect(cloak_hwnd_, &region);
    }

    if (region.right <= region.left || region.bottom <= region.top) return false;

    clear_region_in_texture(context_, texture, region);
    return true;
}

void DxgiBypass::clear_region_in_texture(ID3D11DeviceContext* ctx,
                                          ID3D11Texture2D* texture,
                                          RECT region) {
    D3D11_TEXTURE2D_DESC desc;
    texture->GetDesc(&desc);

    // Clamp region to texture bounds
    if (region.left < 0) region.left = 0;
    if (region.top < 0) region.top = 0;
    if (region.right > (LONG)desc.Width) region.right = desc.Width;
    if (region.bottom > (LONG)desc.Height) region.bottom = desc.Height;

    // Create a staging texture for the cloaked region
    D3D11_TEXTURE2D_DESC stagingDesc = desc;
    stagingDesc.Width = region.right - region.left;
    stagingDesc.Height = region.bottom - region.top;
    stagingDesc.MipLevels = 1;
    stagingDesc.ArraySize = 1;
    stagingDesc.Usage = D3D11_USAGE_STAGING;
    stagingDesc.BindFlags = 0;
    stagingDesc.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;

    ID3D11Texture2D* staging = nullptr;
    HRESULT hr = device_->CreateTexture2D(&stagingDesc, nullptr, &staging);
    if (FAILED(hr)) return;

    // Map and fill with black
    D3D11_MAPPED_SUBRESOURCE mapped;
    hr = ctx->Map(staging, 0, D3D11_MAP_WRITE, 0, &mapped);
    if (SUCCEEDED(hr)) {
        for (UINT y = 0; y < stagingDesc.Height; y++) {
            memset(static_cast<uint8_t*>(mapped.pData) + y * mapped.RowPitch,
                   0, stagingDesc.Width * 4);
        }
        ctx->Unmap(staging, 0);

        // Copy the black region back to the captured texture
        D3D11_BOX srcBox = {};
        srcBox.left = 0;
        srcBox.top = 0;
        srcBox.front = 0;
        srcBox.right = stagingDesc.Width;
        srcBox.bottom = stagingDesc.Height;
        srcBox.back = 1;

        ctx->CopySubresourceRegion(texture, 0, region.left, region.top, 0,
                                    staging, 0, &srcBox);
    }

    staging->Release();
}

}} // namespace phantom::capture
