/**
 * capture_detect.cpp - Capture Detection Example
 *
 * Monitors the system for active screen capture software and
 * reports detections in real-time.
 *
 * Usage: capture_detect.exe [--interval <ms>] [--auto-bypass]
 *
 * This is part of phantom-screen, a security research toolkit.
 */

#include <phantom/phantom.h>
#include <phantom/capture/detector.h>
#include <phantom/capture/bitblt.h>
#include <phantom/capture/dxgi.h>
#include <phantom/capture/wgc.h>
#include <phantom/utils/logger.h>
#include <iostream>
#include <string>
#include <csignal>
#include <iomanip>
#include <chrono>
#include <ctime>

using namespace phantom;

static volatile bool g_running = true;

void signal_handler(int sig) {
    (void)sig;
    g_running = false;
}

const char* method_to_string(capture::CaptureMethod method) {
    switch (method) {
        case capture::CaptureMethod::GDI_BitBlt:               return "GDI BitBlt";
        case capture::CaptureMethod::DXGI_Duplication:          return "DXGI Duplication";
        case capture::CaptureMethod::WindowsGraphicsCapture:    return "Windows Graphics Capture";
        case capture::CaptureMethod::PrintWindow:               return "PrintWindow";
        case capture::CaptureMethod::DirectShow:                return "DirectShow";
        case capture::CaptureMethod::MediaFoundation:           return "Media Foundation";
        default:                                                return "Unknown";
    }
}

void print_detection(const capture::CaptureProcess& cp) {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
    localtime_s(&tm_buf, &time);

    std::cout << std::put_time(&tm_buf, "[%H:%M:%S] ");
    std::cout << "DETECTED: " << cp.name
              << " (PID " << cp.pid << ")"
              << " | Method: " << method_to_string(cp.suspected_method);
    if (!cp.window_title.empty()) {
        std::cout << " | Window: \"" << cp.window_title << "\"";
    }
    std::cout << "\n";
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);

    utils::Logger::instance().set_level(utils::LogLevel::Info);
    utils::Logger::instance().set_console(true);

    uint32_t interval_ms = 2000;
    bool auto_bypass = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--interval" && i + 1 < argc) {
            interval_ms = std::stoul(argv[++i]);
        } else if (arg == "--auto-bypass") {
            auto_bypass = true;
        } else if (arg == "--help") {
            std::cout << "Usage: capture_detect.exe [--interval <ms>] [--auto-bypass]\n";
            return 0;
        }
    }

    std::cout << "=== phantom-screen: Capture Detection Monitor ===\n\n";
    std::cout << "Scan interval: " << interval_ms << " ms\n";
    std::cout << "Auto-bypass:   " << (auto_bypass ? "enabled" : "disabled") << "\n";
    std::cout << "\nMonitoring for screen capture software...\n";
    std::cout << "(Press Ctrl+C to stop)\n\n";

    if (auto_bypass) {
        std::cout << "Auto-bypass enabled. Initializing bypass modules...\n";
        auto& bitblt = capture::BitBltBypass::instance();
        bitblt.initialize();

        auto& dxgi = capture::DxgiBypass::instance();
        dxgi.initialize();

        auto& wgc = capture::WgcBypass::instance();
        wgc.initialize();
        wgc.enable_hook_bypass();

        std::cout << "Bypass modules initialized.\n\n";
    }

    auto& detector = capture::Detector::instance();
    detector.set_callback([](const capture::CaptureProcess& cp) {
        print_detection(cp);
    });

    Status result = detector.start_monitoring(interval_ms);
    if (result != Status::Success) {
        std::cerr << "Failed to start monitoring: " << status_to_string(result) << "\n";
        return 1;
    }

    // Initial scan
    auto initial = detector.scan_once();
    if (initial.empty()) {
        std::cout << "No capture software currently detected.\n";
    } else {
        std::cout << "Initial scan found " << initial.size() << " capture process(es):\n";
        for (const auto& cp : initial) {
            print_detection(cp);
        }
    }
    std::cout << "\n";

    // Main loop
    while (g_running) {
        Sleep(100);
    }

    std::cout << "\nShutting down...\n";
    detector.stop_monitoring();

    if (auto_bypass) {
        capture::BitBltBypass::instance().shutdown();
        capture::DxgiBypass::instance().shutdown();
        capture::WgcBypass::instance().shutdown();
    }

    std::cout << "Done.\n";
    return 0;
}
