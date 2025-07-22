#include <phantom/capture/detector.h>
#include <phantom/core/process.h>
#include <phantom/utils/logger.h>
#include <Psapi.h>
#include <algorithm>
#include <cctype>

namespace phantom { namespace capture {

Detector& Detector::instance() {
    static Detector inst;
    return inst;
}

const std::vector<std::pair<std::string, CaptureMethod>>& Detector::known_capture_apps() {
    static const std::vector<std::pair<std::string, CaptureMethod>> apps = {
        {"obs64.exe",              CaptureMethod::DXGI_Duplication},
        {"obs32.exe",              CaptureMethod::DXGI_Duplication},
        {"obs.exe",                CaptureMethod::DXGI_Duplication},
        {"streamlabs obs.exe",     CaptureMethod::DXGI_Duplication},
        {"sharex.exe",             CaptureMethod::GDI_BitBlt},
        {"greenshot.exe",          CaptureMethod::GDI_BitBlt},
        {"lightshot.exe",          CaptureMethod::GDI_BitBlt},
        {"snagit32.exe",           CaptureMethod::GDI_BitBlt},
        {"snagit.exe",             CaptureMethod::GDI_BitBlt},
        {"screenrec.exe",          CaptureMethod::WindowsGraphicsCapture},
        {"gamebarPresenceWriter.exe", CaptureMethod::WindowsGraphicsCapture},
        {"gamebar.exe",            CaptureMethod::WindowsGraphicsCapture},
        {"nvidia share.exe",       CaptureMethod::DXGI_Duplication},
        {"xsplit.core.exe",        CaptureMethod::DXGI_Duplication},
        {"xsplitbroadcaster.exe",  CaptureMethod::DXGI_Duplication},
        {"bandicam.exe",           CaptureMethod::DXGI_Duplication},
        {"fraps.exe",              CaptureMethod::DirectShow},
        {"action.exe",             CaptureMethod::DXGI_Duplication},
        {"camtasia.exe",           CaptureMethod::GDI_BitBlt},
        {"snippingtool.exe",       CaptureMethod::WindowsGraphicsCapture},
        {"screenclip.exe",         CaptureMethod::WindowsGraphicsCapture},
    };
    return apps;
}

bool Detector::is_capture_process(const std::string& process_name) {
    std::string lower_name = process_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    for (const auto& [name, method] : known_capture_apps()) {
        if (lower_name == name) return true;
    }
    return false;
}

CaptureMethod Detector::detect_capture_method(DWORD pid) {
    // Check which capture-related DLLs are loaded
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return CaptureMethod::Unknown;

    HMODULE modules[1024];
    DWORD needed;
    CaptureMethod method = CaptureMethod::Unknown;

    if (EnumProcessModules(hProcess, modules, sizeof(modules), &needed)) {
        DWORD count = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < count; i++) {
            char modName[MAX_PATH];
            if (GetModuleBaseNameA(hProcess, modules[i], modName, sizeof(modName))) {
                std::string name = modName;
                std::transform(name.begin(), name.end(), name.begin(),
                               [](unsigned char c) { return std::tolower(c); });

                if (name.find("dxgi") != std::string::npos ||
                    name.find("d3d11") != std::string::npos) {
                    method = CaptureMethod::DXGI_Duplication;
                }
                if (name.find("dwmapi") != std::string::npos && method == CaptureMethod::Unknown) {
                    method = CaptureMethod::GDI_BitBlt;
                }
                if (name.find("windows.graphics.capture") != std::string::npos) {
                    method = CaptureMethod::WindowsGraphicsCapture;
                    break; // High confidence
                }
            }
        }
    }

    CloseHandle(hProcess);
    return method;
}

bool Detector::check_loaded_modules(DWORD pid, CaptureMethod& method) {
    method = detect_capture_method(pid);
    return method != CaptureMethod::Unknown;
}

bool Detector::check_window_hooks(DWORD pid) {
    // Check if the process has installed any global hooks
    // that might be used for capture (WH_CBT, WH_GETMESSAGE, etc.)
    // This is a heuristic check
    HWND hwnd = nullptr;
    bool found = false;

    // Enumerate windows belonging to this process
    struct EnumData { DWORD pid; bool found; };
    EnumData data = { pid, false };

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* d = reinterpret_cast<EnumData*>(lParam);
        DWORD wndPid;
        GetWindowThreadProcessId(hwnd, &wndPid);
        if (wndPid == d->pid) {
            // Check if window has capture-related styles
            LONG exStyle = GetWindowLongA(hwnd, GWL_EXSTYLE);
            if (exStyle & WS_EX_LAYERED || exStyle & WS_EX_TRANSPARENT) {
                d->found = true;
            }
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&data));

    return data.found;
}

std::vector<CaptureProcess> Detector::scan_once() {
    std::vector<CaptureProcess> results;
    results.reserve(8); // Pre-allocate for typical capture app count

    auto processes = core::Process::enumerate_processes();

    // Build a hash set of known names for O(1) lookup instead of O(n)
    static std::unordered_map<std::string, CaptureMethod> known_map;
    if (known_map.empty()) {
        for (const auto& [name, method] : known_capture_apps()) {
            known_map[name] = method;
        }
    }

    for (const auto& proc : processes) {
        std::string lower_name = proc.name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        CaptureMethod method = CaptureMethod::Unknown;

        // O(1) lookup against known capture applications
        auto kit = known_map.find(lower_name);
        if (kit != known_map.end()) {
            method = kit->second;
        }

        if (method == CaptureMethod::Unknown) {
            // Heuristic: check loaded modules
            CaptureMethod detected_method;
            if (check_loaded_modules(proc.pid, detected_method)) {
                // Only flag if it also has suspicious window behavior
                if (check_window_hooks(proc.pid)) {
                    method = detected_method;
                }
            }
        }

        if (method != CaptureMethod::Unknown) {
            CaptureProcess cp;
            cp.pid = proc.pid;
            cp.name = proc.name;
            cp.suspected_method = method;
            cp.is_active = true;
            cp.detected_at = std::chrono::steady_clock::now();

            // Try to get window title
            struct TitleData { DWORD pid; std::string title; };
            TitleData td = { proc.pid, "" };
            EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
                auto* d = reinterpret_cast<TitleData*>(lParam);
                DWORD wndPid;
                GetWindowThreadProcessId(hwnd, &wndPid);
                if (wndPid == d->pid && IsWindowVisible(hwnd)) {
                    char title[256];
                    GetWindowTextA(hwnd, title, sizeof(title));
                    if (strlen(title) > 0) {
                        d->title = title;
                        return FALSE;
                    }
                }
                return TRUE;
            }, reinterpret_cast<LPARAM>(&td));
            cp.window_title = td.title;

            results.push_back(cp);
        }
    }

    // Update detected list
    {
        std::lock_guard<std::mutex> lock(mutex_);
        detected_ = results;
    }

    return results;
}

std::vector<CaptureProcess> Detector::get_detected() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return detected_;
}

Status Detector::start_monitoring(uint32_t interval_ms) {
    if (monitoring_.load()) return Status::ErrorAlreadyInitialized;

    monitoring_.store(true);
    monitor_thread_ = std::thread(&Detector::monitor_thread, this, interval_ms);

    PHANTOM_INFO("Capture monitoring started (interval=" + std::to_string(interval_ms) + "ms)");
    return Status::Success;
}

void Detector::stop_monitoring() {
    if (!monitoring_.load()) return;
    monitoring_.store(false);
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
    PHANTOM_INFO("Capture monitoring stopped");
}

void Detector::monitor_thread(uint32_t interval_ms) {
    while (monitoring_.load()) {
        auto results = scan_once();

        if (!results.empty() && callback_) {
            for (const auto& cp : results) {
                callback_(cp);
            }
        }

        // Sleep in small increments for responsive shutdown
        auto end_time = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(interval_ms);
        while (monitoring_.load() && std::chrono::steady_clock::now() < end_time) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
}

}} // namespace phantom::capture
