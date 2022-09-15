#pragma once
#ifndef PHANTOM_DETECTOR_H
#define PHANTOM_DETECTOR_H

#include <phantom/phantom.h>
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include <chrono>

namespace phantom { namespace capture {

enum class CaptureMethod : uint8_t {
    Unknown = 0,
    GDI_BitBlt,
    DXGI_Duplication,
    WindowsGraphicsCapture,
    PrintWindow,
    DirectShow,
    MediaFoundation
};

struct CaptureProcess {
    DWORD pid;
    std::string name;
    std::string window_title;
    CaptureMethod suspected_method;
    bool is_active;
    std::chrono::steady_clock::time_point detected_at;
};

using DetectionCallback = std::function<void(const CaptureProcess&)>;

/**
 * Detects active screen capture software by monitoring running processes,
 * loaded modules, and API usage patterns.
 */
class Detector {
public:
    static Detector& instance();

    Status start_monitoring(uint32_t interval_ms = 1000);
    void stop_monitoring();
    bool is_monitoring() const { return monitoring_.load(); }

    void set_callback(DetectionCallback cb) { callback_ = std::move(cb); }

    std::vector<CaptureProcess> scan_once();
    std::vector<CaptureProcess> get_detected() const;

    static bool is_capture_process(const std::string& process_name);
    static CaptureMethod detect_capture_method(DWORD pid);

private:
    Detector() = default;
    ~Detector() { stop_monitoring(); }
    Detector(const Detector&) = delete;
    Detector& operator=(const Detector&) = delete;

    void monitor_thread(uint32_t interval_ms);
    bool check_loaded_modules(DWORD pid, CaptureMethod& method);
    bool check_window_hooks(DWORD pid);

    std::atomic<bool> monitoring_{false};
    std::thread monitor_thread_;
    mutable std::mutex mutex_;
    std::vector<CaptureProcess> detected_;
    DetectionCallback callback_;

    static const std::vector<std::pair<std::string, CaptureMethod>>& known_capture_apps();
};

}} // namespace phantom::capture

#endif // PHANTOM_DETECTOR_H
