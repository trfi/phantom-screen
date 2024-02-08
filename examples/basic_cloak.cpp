/**
 * basic_cloak.cpp - Window Cloaking Example
 *
 * Demonstrates how to cloak a window from screen capture using
 * multiple methods: DWM cloaking, display affinity, and the
 * composite approach.
 *
 * Usage: basic_cloak.exe [window_title]
 *
 * This is part of phantom-screen, a security research toolkit.
 */

#include <phantom/phantom.h>
#include <phantom/display/cloaker.h>
#include <phantom/display/composition.h>
#include <phantom/capture/wgc.h>
#include <phantom/utils/logger.h>
#include <phantom/utils/config.h>
#include <iostream>
#include <string>

using namespace phantom;

HWND find_window_by_title(const std::string& title) {
    struct SearchData {
        std::string title;
        HWND result;
    };

    SearchData data = { title, nullptr };

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* d = reinterpret_cast<SearchData*>(lParam);
        char windowTitle[256];
        GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle));

        std::string wt = windowTitle;
        if (wt.find(d->title) != std::string::npos) {
            d->result = hwnd;
            return FALSE;
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&data));

    return data.result;
}

void print_usage() {
    std::cout << "phantom-screen: Basic Window Cloaking Example\n\n";
    std::cout << "Usage: basic_cloak.exe [window_title]\n\n";
    std::cout << "Methods available:\n";
    std::cout << "  1. DWM Cloak (DWMWA_CLOAK attribute)\n";
    std::cout << "  2. Display Affinity (WDA_EXCLUDEFROMCAPTURE)\n";
    std::cout << "  3. Extended Style manipulation\n";
    std::cout << "  4. Composite (all methods combined)\n\n";
}

int main(int argc, char* argv[]) {
    utils::Logger::instance().set_level(utils::LogLevel::Debug);
    utils::Logger::instance().set_console(true);

    print_usage();

    std::string target_title;
    if (argc > 1) {
        target_title = argv[1];
    } else {
        std::cout << "Enter window title to cloak: ";
        std::getline(std::cin, target_title);
    }

    if (target_title.empty()) {
        std::cerr << "No window title provided.\n";
        return 1;
    }

    HWND hwnd = find_window_by_title(target_title);
    if (!hwnd) {
        std::cerr << "Window not found: " << target_title << "\n";
        return 1;
    }

    char actualTitle[256];
    GetWindowTextA(hwnd, actualTitle, sizeof(actualTitle));
    std::cout << "Found window: \"" << actualTitle << "\"\n";
    std::cout << "  HWND: 0x" << std::hex << reinterpret_cast<uintptr_t>(hwnd) << std::dec << "\n\n";

    // Initialize DWM composition
    auto& composition = display::Composition::instance();
    composition.initialize();

    // Method selection
    std::cout << "Select cloaking method:\n";
    std::cout << "  1. DWM Cloak\n";
    std::cout << "  2. Display Affinity (recommended)\n";
    std::cout << "  3. Extended Style\n";
    std::cout << "  4. Composite\n";
    std::cout << "Choice [2]: ";

    std::string choice_str;
    std::getline(std::cin, choice_str);
    int choice = choice_str.empty() ? 2 : std::stoi(choice_str);

    display::Cloaker::CloakMethod method;
    switch (choice) {
        case 1: method = display::Cloaker::CloakMethod::DWM_Cloak; break;
        case 3: method = display::Cloaker::CloakMethod::ExtendedStyle; break;
        case 4: method = display::Cloaker::CloakMethod::Composite; break;
        default: method = display::Cloaker::CloakMethod::DisplayAffinity; break;
    }

    auto& cloaker = display::Cloaker::instance();
    Status result = cloaker.cloak_window(hwnd, method);

    if (result == Status::Success) {
        std::cout << "\nWindow cloaked successfully!\n";
        std::cout << "The window should now be invisible to screen capture software.\n";
        std::cout << "\nAlso applying WGC exclusion...\n";

        // Also apply WGC exclusion
        capture::WgcBypass::set_capture_exclusion(hwnd, true);

        // Also exclude from DWM thumbnails
        composition.exclude_from_thumbnails(hwnd);

        std::cout << "\nPress Enter to uncloak and exit...\n";
        std::cin.get();

        cloaker.uncloak_window(hwnd);
        capture::WgcBypass::set_capture_exclusion(hwnd, false);
        composition.include_in_thumbnails(hwnd);

        std::cout << "Window uncloaked.\n";
    } else {
        std::cerr << "Failed to cloak window: " << status_to_string(result) << "\n";
        return 1;
    }

    return 0;
}
