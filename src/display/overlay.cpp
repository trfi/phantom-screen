#include <phantom/display/overlay.h>
#include <phantom/display/cloaker.h>
#include <phantom/utils/logger.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

namespace phantom { namespace display {

Overlay& Overlay::instance() {
    static Overlay inst;
    return inst;
}

Status Overlay::create(const OverlayConfig& config) {
    if (created_) return Status::ErrorAlreadyInitialized;

    config_ = config;

    if (!create_window(config)) {
        PHANTOM_ERROR("Failed to create overlay window");
        return Status::ErrorGeneric;
    }

    if (!create_d3d_device()) {
        PHANTOM_ERROR("Failed to create D3D11 device");
        DestroyWindow(hwnd_);
        return Status::ErrorGeneric;
    }

    if (!create_swap_chain()) {
        PHANTOM_ERROR("Failed to create swap chain");
        destroy();
        return Status::ErrorGeneric;
    }

    if (!create_render_target()) {
        PHANTOM_ERROR("Failed to create render target");
        destroy();
        return Status::ErrorGeneric;
    }

    // Exclude from screen capture
    SetWindowDisplayAffinity(hwnd_, WDA_EXCLUDEFROMCAPTURE);

    // Apply DWM cloaking for additional protection
    Cloaker::instance().cloak_window(hwnd_, Cloaker::CloakMethod::DisplayAffinity);

    QueryPerformanceFrequency(&frequency_);
    QueryPerformanceCounter(&last_time_);

    created_ = true;
    PHANTOM_INFO("Overlay created (" + std::to_string(config.width) + "x" +
                 std::to_string(config.height) + ")");
    return Status::Success;
}

void Overlay::destroy() {
    if (!created_ && !hwnd_) return;

    if (hwnd_) {
        Cloaker::instance().uncloak_window(hwnd_);
    }

    if (rtv_) { rtv_->Release(); rtv_ = nullptr; }
    if (swap_chain_) { swap_chain_->Release(); swap_chain_ = nullptr; }
    if (context_) { context_->Release(); context_ = nullptr; }
    if (device_) { device_->Release(); device_ = nullptr; }
    if (hwnd_) { DestroyWindow(hwnd_); hwnd_ = nullptr; }

    created_ = false;
    PHANTOM_INFO("Overlay destroyed");
}

bool Overlay::create_window(const OverlayConfig& config) {
    WNDCLASSEXA wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = GetModuleHandleA(nullptr);
    wc.lpszClassName = "PhantomOverlayClass";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);

    RegisterClassExA(&wc);

    DWORD exStyle = WS_EX_TOPMOST | WS_EX_LAYERED;
    if (config.transparent) exStyle |= WS_EX_TRANSPARENT;

    hwnd_ = CreateWindowExA(
        exStyle,
        wc.lpszClassName,
        config.window_title.c_str(),
        WS_POPUP,
        0, 0,
        config.width, config.height,
        nullptr, nullptr,
        wc.hInstance, this
    );

    if (!hwnd_) return false;

    // Set layered window attributes for transparency
    SetLayeredWindowAttributes(hwnd_, RGB(0, 0, 0), 0, LWA_COLORKEY);

    // Extend DWM frame into client area for full transparency
    MARGINS margins = { -1, -1, -1, -1 };
    DwmExtendFrameIntoClientArea(hwnd_, &margins);

    if (config.topmost) {
        SetWindowPos(hwnd_, HWND_TOPMOST, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }

    ShowWindow(hwnd_, SW_SHOWNOACTIVATE);
    UpdateWindow(hwnd_);

    return true;
}

bool Overlay::create_d3d_device() {
    D3D_FEATURE_LEVEL featureLevels[] = {
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1,
    };

    D3D_FEATURE_LEVEL featureLevel;
    HRESULT hr = D3D11CreateDevice(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT,
        featureLevels, 3,
        D3D11_SDK_VERSION,
        &device_, &featureLevel, &context_
    );

    return SUCCEEDED(hr);
}

bool Overlay::create_swap_chain() {
    IDXGIDevice* dxgiDevice = nullptr;
    IDXGIAdapter* adapter = nullptr;
    IDXGIFactory2* factory = nullptr;

    device_->QueryInterface(__uuidof(IDXGIDevice), (void**)&dxgiDevice);
    dxgiDevice->GetAdapter(&adapter);
    adapter->GetParent(__uuidof(IDXGIFactory2), (void**)&factory);

    DXGI_SWAP_CHAIN_DESC1 desc = {};
    desc.Width = config_.width;
    desc.Height = config_.height;
    desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    desc.BufferCount = 2;
    desc.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
    desc.AlphaMode = DXGI_ALPHA_MODE_PREMULTIPLIED;

    IDXGISwapChain1* swapChain1 = nullptr;
    HRESULT hr = factory->CreateSwapChainForHwnd(
        device_, hwnd_, &desc, nullptr, nullptr, &swapChain1);

    // Fallback to non-flip swap chain if flip model fails
    if (FAILED(hr)) {
        desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
        desc.AlphaMode = DXGI_ALPHA_MODE_UNSPECIFIED;
        hr = factory->CreateSwapChainForHwnd(
            device_, hwnd_, &desc, nullptr, nullptr, &swapChain1);
    }

    if (SUCCEEDED(hr)) {
        swap_chain_ = swapChain1;
    }

    factory->Release();
    adapter->Release();
    dxgiDevice->Release();

    return SUCCEEDED(hr);
}

bool Overlay::create_render_target() {
    ID3D11Texture2D* backBuffer = nullptr;
    HRESULT hr = swap_chain_->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&backBuffer);
    if (FAILED(hr)) return false;

    hr = device_->CreateRenderTargetView(backBuffer, nullptr, &rtv_);
    backBuffer->Release();

    return SUCCEEDED(hr);
}

Status Overlay::begin_frame(float clear_color[4]) {
    if (!created_) return Status::ErrorNotInitialized;

    float default_color[4] = { 0.0f, 0.0f, 0.0f, 0.0f };
    float* color = clear_color ? clear_color : default_color;

    context_->OMSetRenderTargets(1, &rtv_, nullptr);
    context_->ClearRenderTargetView(rtv_, color);

    D3D11_VIEWPORT vp = {};
    vp.Width = (float)config_.width;
    vp.Height = (float)config_.height;
    vp.MaxDepth = 1.0f;
    context_->RSSetViewports(1, &vp);

    return Status::Success;
}

Status Overlay::end_frame() {
    if (!created_) return Status::ErrorNotInitialized;

    HRESULT hr = swap_chain_->Present(1, 0);
    if (FAILED(hr)) {
        PHANTOM_ERROR("Swap chain present failed");
        return Status::ErrorGeneric;
    }

    return Status::Success;
}

void Overlay::set_position(int x, int y) {
    if (hwnd_) SetWindowPos(hwnd_, nullptr, x, y, 0, 0,
                             SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
}

void Overlay::set_size(int width, int height) {
    config_.width = width;
    config_.height = height;
    if (hwnd_) SetWindowPos(hwnd_, nullptr, 0, 0, width, height,
                             SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
}

void Overlay::set_opacity(float opacity) {
    config_.opacity = opacity;
    if (hwnd_) {
        BYTE alpha = static_cast<BYTE>(opacity * 255.0f);
        SetLayeredWindowAttributes(hwnd_, 0, alpha, LWA_ALPHA);
    }
}

void Overlay::show() {
    if (hwnd_) ShowWindow(hwnd_, SW_SHOWNOACTIVATE);
}

void Overlay::hide() {
    if (hwnd_) ShowWindow(hwnd_, SW_HIDE);
}

void Overlay::run() {
    running_ = true;
    MSG msg;

    while (running_) {
        while (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                running_ = false;
                break;
            }
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }

        if (!running_) break;

        // Calculate delta time
        LARGE_INTEGER current_time;
        QueryPerformanceCounter(&current_time);
        float dt = (float)(current_time.QuadPart - last_time_.QuadPart) / (float)frequency_.QuadPart;
        last_time_ = current_time;

        // Render
        begin_frame();
        if (render_callback_) {
            render_callback_(context_, dt);
        }
        end_frame();
    }
}

LRESULT CALLBACK Overlay::wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        case WM_PAINT: {
            PAINTSTRUCT ps;
            BeginPaint(hwnd, &ps);
            EndPaint(hwnd, &ps);
            return 0;
        }
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

}} // namespace phantom::display
