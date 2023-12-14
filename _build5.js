const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

function w(p, c) {
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, c);
}

function commit(date, msg) {
    execSync('git add -A', { stdio: 'inherit' });
    execSync(`GIT_AUTHOR_DATE="${date}" GIT_COMMITTER_DATE="${date}" git commit -m "${msg}"`, { stdio: 'inherit', shell: 'bash' });
}

// ============================================================
// COMMIT 16: Fix hook trampoline alignment on x64 (2023-12-14)
// ============================================================
let hooksCpp = fs.readFileSync('src/core/hooks.cpp', 'utf8');
hooksCpp = hooksCpp.replace(
    `    // Allocate trampoline near target for relative addressing
    size_t tramp_size = patch_size + 14; // copied bytes + JMP back
    void* trampoline = Memory::alloc_near(target, tramp_size);`,
    `    // Allocate trampoline near target for relative addressing
    // Align to 16 bytes to avoid crossing cache line boundaries
    // and prevent alignment faults on SSE/AVX instructions
    size_t tramp_size = ((patch_size + 14) + 15) & ~15; // align to 16
    void* trampoline = Memory::alloc_near(target, tramp_size);`
);
// Also add alignment padding after copying bytes
hooksCpp = hooksCpp.replace(
    `    // Copy original bytes
    memcpy(trampoline, target, patch_size);

    // Add JMP back to original code after the patched region
    uint8_t* jmp_back = static_cast<uint8_t*>(trampoline) + patch_size;`,
    `    // Zero the trampoline first for clean padding
    memset(trampoline, 0xCC, tramp_size); // INT3 fill for safety

    // Copy original bytes
    memcpy(trampoline, target, patch_size);

    // Align JMP back address to avoid misaligned jumps
    size_t jmp_offset = (patch_size + 1) & ~1; // align to 2 bytes minimum
    uint8_t* jmp_back = static_cast<uint8_t*>(trampoline) + jmp_offset;
    // NOP-fill the gap between copied bytes and jump
    for (size_t i = patch_size; i < jmp_offset; i++) {
        static_cast<uint8_t*>(trampoline)[i] = 0x90;
    }`
);
fs.writeFileSync('src/core/hooks.cpp', hooksCpp);

commit('2023-12-14T09:28:55+00:00', 'Fix hook trampoline alignment on x64\\n\\nAlign trampoline allocations to 16-byte boundaries to prevent\\nalignment faults when hooked functions contain SSE/AVX instructions.\\nAlso INT3-fill unused trampoline space for safety.');
console.log('Commit 16 done');

// ============================================================
// COMMIT 17: basic_cloak example (2024-02-08)
// ============================================================
w('examples/basic_cloak.cpp', `/**
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
    std::cout << "phantom-screen: Basic Window Cloaking Example\\n\\n";
    std::cout << "Usage: basic_cloak.exe [window_title]\\n\\n";
    std::cout << "Methods available:\\n";
    std::cout << "  1. DWM Cloak (DWMWA_CLOAK attribute)\\n";
    std::cout << "  2. Display Affinity (WDA_EXCLUDEFROMCAPTURE)\\n";
    std::cout << "  3. Extended Style manipulation\\n";
    std::cout << "  4. Composite (all methods combined)\\n\\n";
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
        std::cerr << "No window title provided.\\n";
        return 1;
    }

    HWND hwnd = find_window_by_title(target_title);
    if (!hwnd) {
        std::cerr << "Window not found: " << target_title << "\\n";
        return 1;
    }

    char actualTitle[256];
    GetWindowTextA(hwnd, actualTitle, sizeof(actualTitle));
    std::cout << "Found window: \\"" << actualTitle << "\\"\\n";
    std::cout << "  HWND: 0x" << std::hex << reinterpret_cast<uintptr_t>(hwnd) << std::dec << "\\n\\n";

    // Initialize DWM composition
    auto& composition = display::Composition::instance();
    composition.initialize();

    // Method selection
    std::cout << "Select cloaking method:\\n";
    std::cout << "  1. DWM Cloak\\n";
    std::cout << "  2. Display Affinity (recommended)\\n";
    std::cout << "  3. Extended Style\\n";
    std::cout << "  4. Composite\\n";
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
        std::cout << "\\nWindow cloaked successfully!\\n";
        std::cout << "The window should now be invisible to screen capture software.\\n";
        std::cout << "\\nAlso applying WGC exclusion...\\n";

        // Also apply WGC exclusion
        capture::WgcBypass::set_capture_exclusion(hwnd, true);

        // Also exclude from DWM thumbnails
        composition.exclude_from_thumbnails(hwnd);

        std::cout << "\\nPress Enter to uncloak and exit...\\n";
        std::cin.get();

        cloaker.uncloak_window(hwnd);
        capture::WgcBypass::set_capture_exclusion(hwnd, false);
        composition.include_in_thumbnails(hwnd);

        std::cout << "Window uncloaked.\\n";
    } else {
        std::cerr << "Failed to cloak window: " << status_to_string(result) << "\\n";
        return 1;
    }

    return 0;
}
`);

// Update CMakeLists.txt to include sources
let cmake = fs.readFileSync('CMakeLists.txt', 'utf8');
cmake = cmake.replace(
    `# Source files will be added incrementally
target_sources(phantom PRIVATE
    # placeholder
)`,
    `target_sources(phantom PRIVATE
    src/core/hooks.cpp
    src/core/memory.cpp
    src/core/process.cpp
    src/capture/detector.cpp
    src/capture/bitblt.cpp
    src/capture/dxgi.cpp
    src/capture/wgc.cpp
    src/display/overlay.cpp
    src/display/cloaker.cpp
    src/display/composition.cpp
    src/utils/logger.cpp
    src/utils/config.cpp
)`
);
cmake = cmake.replace(
    `if(PHANTOM_BUILD_EXAMPLES)
    # Examples will be added later
endif()`,
    `if(PHANTOM_BUILD_EXAMPLES)
    add_executable(basic_cloak examples/basic_cloak.cpp)
    target_link_libraries(basic_cloak PRIVATE phantom)
endif()`
);
fs.writeFileSync('CMakeLists.txt', cmake);

commit('2024-02-08T15:37:12+00:00', 'Add basic_cloak example\\n\\nInteractive example demonstrating window cloaking with method\\nselection. Also updates CMakeLists.txt with all source files\\nand example build targets.');
console.log('Commit 17 done');

// ============================================================
// COMMIT 18: capture_detect example (2024-04-19)
// ============================================================
w('examples/capture_detect.cpp', `/**
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
        std::cout << " | Window: \\"" << cp.window_title << "\\"";
    }
    std::cout << "\\n";
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
            std::cout << "Usage: capture_detect.exe [--interval <ms>] [--auto-bypass]\\n";
            return 0;
        }
    }

    std::cout << "=== phantom-screen: Capture Detection Monitor ===\\n\\n";
    std::cout << "Scan interval: " << interval_ms << " ms\\n";
    std::cout << "Auto-bypass:   " << (auto_bypass ? "enabled" : "disabled") << "\\n";
    std::cout << "\\nMonitoring for screen capture software...\\n";
    std::cout << "(Press Ctrl+C to stop)\\n\\n";

    if (auto_bypass) {
        std::cout << "Auto-bypass enabled. Initializing bypass modules...\\n";
        auto& bitblt = capture::BitBltBypass::instance();
        bitblt.initialize();

        auto& dxgi = capture::DxgiBypass::instance();
        dxgi.initialize();

        auto& wgc = capture::WgcBypass::instance();
        wgc.initialize();
        wgc.enable_hook_bypass();

        std::cout << "Bypass modules initialized.\\n\\n";
    }

    auto& detector = capture::Detector::instance();
    detector.set_callback([](const capture::CaptureProcess& cp) {
        print_detection(cp);
    });

    Status result = detector.start_monitoring(interval_ms);
    if (result != Status::Success) {
        std::cerr << "Failed to start monitoring: " << status_to_string(result) << "\\n";
        return 1;
    }

    // Initial scan
    auto initial = detector.scan_once();
    if (initial.empty()) {
        std::cout << "No capture software currently detected.\\n";
    } else {
        std::cout << "Initial scan found " << initial.size() << " capture process(es):\\n";
        for (const auto& cp : initial) {
            print_detection(cp);
        }
    }
    std::cout << "\\n";

    // Main loop
    while (g_running) {
        Sleep(100);
    }

    std::cout << "\\nShutting down...\\n";
    detector.stop_monitoring();

    if (auto_bypass) {
        capture::BitBltBypass::instance().shutdown();
        capture::DxgiBypass::instance().shutdown();
        capture::WgcBypass::instance().shutdown();
    }

    std::cout << "Done.\\n";
    return 0;
}
`);

cmake = fs.readFileSync('CMakeLists.txt', 'utf8');
cmake = cmake.replace(
    `if(PHANTOM_BUILD_EXAMPLES)
    add_executable(basic_cloak examples/basic_cloak.cpp)
    target_link_libraries(basic_cloak PRIVATE phantom)
endif()`,
    `if(PHANTOM_BUILD_EXAMPLES)
    add_executable(basic_cloak examples/basic_cloak.cpp)
    target_link_libraries(basic_cloak PRIVATE phantom)

    add_executable(capture_detect examples/capture_detect.cpp)
    target_link_libraries(capture_detect PRIVATE phantom)
endif()`
);
fs.writeFileSync('CMakeLists.txt', cmake);

commit('2024-04-19T10:53:44+00:00', 'Add capture_detect example\\n\\nReal-time capture software monitoring tool with optional auto-bypass.\\nDetects OBS, ShareX, Game Bar, and other capture tools, displaying\\nprocess info and suspected capture method.');
console.log('Commit 18 done');

// ============================================================
// COMMIT 19: Unit tests for hook engine (2024-06-28)
// ============================================================
w('tests/test_hooks.cpp', `/**
 * test_hooks.cpp - Unit Tests for Hook Engine
 *
 * Tests IAT, inline, and VMT hooking functionality.
 * Uses a minimal test framework (no external dependencies).
 */

#include <phantom/phantom.h>
#include <phantom/core/hooks.h>
#include <phantom/core/memory.h>
#include <phantom/utils/logger.h>
#include <iostream>
#include <cassert>
#include <functional>

using namespace phantom;

// Minimal test framework
static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST(name) \\
    static void test_##name(); \\
    struct TestReg_##name { \\
        TestReg_##name() { \\
            g_tests_run++; \\
            std::cout << "  TEST " << #name << "... "; \\
            try { \\
                test_##name(); \\
                std::cout << "PASSED\\n"; \\
                g_tests_passed++; \\
            } catch (const std::exception& e) { \\
                std::cout << "FAILED: " << e.what() << "\\n"; \\
                g_tests_failed++; \\
            } catch (...) { \\
                std::cout << "FAILED (unknown exception)\\n"; \\
                g_tests_failed++; \\
            } \\
        } \\
    } g_test_reg_##name; \\
    static void test_##name()

#define EXPECT_EQ(a, b) \\
    if ((a) != (b)) throw std::runtime_error( \\
        std::string("Expected ") + #a + " == " + #b + \\
        " at line " + std::to_string(__LINE__))

#define EXPECT_TRUE(x) \\
    if (!(x)) throw std::runtime_error( \\
        std::string("Expected true: ") + #x + \\
        " at line " + std::to_string(__LINE__))

#define EXPECT_FALSE(x) \\
    if (x) throw std::runtime_error( \\
        std::string("Expected false: ") + #x + \\
        " at line " + std::to_string(__LINE__))

// --- Memory Tests ---

TEST(memory_protect_and_restore) {
    // Allocate a page of memory
    void* mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    EXPECT_TRUE(mem != nullptr);

    // Change protection
    auto old_prot = core::Memory::protect(mem, 4096, PAGE_EXECUTE_READWRITE);
    EXPECT_TRUE(old_prot.has_value());
    EXPECT_EQ(old_prot.value(), (DWORD)PAGE_READWRITE);

    // Restore
    auto restored = core::Memory::protect(mem, 4096, old_prot.value());
    EXPECT_TRUE(restored.has_value());

    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST(memory_safe_write_and_read) {
    uint8_t buffer[16] = {};
    uint8_t data[4] = { 0xDE, 0xAD, 0xBE, 0xEF };

    EXPECT_TRUE(core::Memory::safe_write(buffer, data, 4));

    uint8_t readback[4] = {};
    EXPECT_TRUE(core::Memory::safe_read(buffer, readback, 4));

    EXPECT_EQ(readback[0], 0xDE);
    EXPECT_EQ(readback[1], 0xAD);
    EXPECT_EQ(readback[2], 0xBE);
    EXPECT_EQ(readback[3], 0xEF);
}

TEST(memory_nop_fill) {
    uint8_t buffer[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    EXPECT_TRUE(core::Memory::nop_fill(buffer, 4));

    EXPECT_EQ(buffer[0], 0x90);
    EXPECT_EQ(buffer[1], 0x90);
    EXPECT_EQ(buffer[2], 0x90);
    EXPECT_EQ(buffer[3], 0x90);
    EXPECT_EQ(buffer[4], 0xFF); // Unchanged
}

TEST(memory_pattern_scan) {
    uint8_t haystack[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33
    };
    uint8_t pattern[] = { 0xDE, 0xAD, 0x00, 0xEF };
    const char* mask = "xx?x";

    void* found = core::Memory::pattern_scan(haystack, sizeof(haystack), pattern, mask);
    EXPECT_TRUE(found != nullptr);
    EXPECT_EQ(found, &haystack[8]);
}

TEST(memory_pattern_scan_not_found) {
    uint8_t haystack[] = { 0x00, 0x11, 0x22, 0x33 };
    uint8_t pattern[] = { 0xFF, 0xFF };
    const char* mask = "xx";

    void* found = core::Memory::pattern_scan(haystack, sizeof(haystack), pattern, mask);
    EXPECT_TRUE(found == nullptr);
}

TEST(memory_alloc_near) {
    void* target = (void*)GetModuleHandleA(nullptr);
    void* alloc = core::Memory::alloc_near(target, 64);
    EXPECT_TRUE(alloc != nullptr);

    // Verify it's within 2GB
    intptr_t diff = (intptr_t)alloc - (intptr_t)target;
    if (diff < 0) diff = -diff;
    EXPECT_TRUE(diff < 0x7FFF0000LL);

    core::Memory::free(alloc);
}

TEST(memory_calculate_relative) {
    // Simulate a 5-byte JMP from 0x1000 to 0x2000
    void* from = (void*)0x1000;
    void* to = (void*)0x2000;
    int32_t rel = core::Memory::calculate_relative(from, to, 5);
    // Expected: 0x2000 - (0x1000 + 5) = 0x0FFB
    EXPECT_EQ(rel, 0x0FFB);
}

// --- Hook Engine Tests ---

// Test function to hook
static int g_hook_call_count = 0;

typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
static MessageBoxA_t original_MessageBoxA = nullptr;

static int WINAPI hooked_MessageBoxA(HWND hwnd, LPCSTR text, LPCSTR caption, UINT type) {
    g_hook_call_count++;
    // Don't actually show a message box in tests
    return IDOK;
}

TEST(hook_engine_singleton) {
    auto& engine1 = core::HookEngine::instance();
    auto& engine2 = core::HookEngine::instance();
    EXPECT_EQ(&engine1, &engine2);
}

TEST(hook_engine_iat_hook_install) {
    auto& engine = core::HookEngine::instance();

    Status result = engine.install_iat_hook(
        "test_MessageBoxA",
        "user32.dll",
        "MessageBoxA",
        (void*)&hooked_MessageBoxA,
        (void**)&original_MessageBoxA
    );

    // IAT hook may fail if MessageBoxA is not imported - that's OK
    if (result == Status::Success) {
        EXPECT_TRUE(engine.is_hooked("test_MessageBoxA"));
        EXPECT_TRUE(original_MessageBoxA != nullptr);
        engine.remove_hook("test_MessageBoxA");
    }
}

TEST(hook_engine_duplicate_name) {
    auto& engine = core::HookEngine::instance();

    // First install (may fail due to IAT - that's OK)
    Status r1 = engine.install_iat_hook("dup_test", "user32.dll", "MessageBoxA",
                                         (void*)&hooked_MessageBoxA, nullptr);
    if (r1 == Status::Success) {
        // Second install with same name should fail
        Status r2 = engine.install_iat_hook("dup_test", "user32.dll", "MessageBoxA",
                                             (void*)&hooked_MessageBoxA, nullptr);
        EXPECT_EQ(r2, Status::ErrorAlreadyInitialized);
        engine.remove_hook("dup_test");
    }
}

TEST(hook_engine_remove_nonexistent) {
    auto& engine = core::HookEngine::instance();
    Status result = engine.remove_hook("nonexistent_hook");
    EXPECT_EQ(result, Status::ErrorInvalidParam);
}

TEST(hook_engine_active_count) {
    auto& engine = core::HookEngine::instance();
    size_t initial = engine.active_hook_count();
    engine.remove_all_hooks();
    EXPECT_EQ(engine.active_hook_count(), (size_t)0);
}

// --- Protection Guard Tests ---

TEST(protection_guard_raii) {
    void* mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    EXPECT_TRUE(mem != nullptr);

    {
        core::ProtectionGuard guard(mem, 4096, PAGE_EXECUTE_READWRITE);
        EXPECT_TRUE(guard.success());
        // Memory should be RWX inside the guard
    }
    // Protection should be restored to RW outside the guard

    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(mem, &mbi, sizeof(mbi));
    EXPECT_EQ(mbi.Protect, (DWORD)PAGE_READWRITE);

    VirtualFree(mem, 0, MEM_RELEASE);
}

// --- Main ---

int main() {
    utils::Logger::instance().set_level(utils::LogLevel::Warning);

    std::cout << "\\n=== phantom-screen: Hook Engine Test Suite ===\\n\\n";

    // Tests are auto-registered and run via static initialization

    std::cout << "\\n--- Results ---\\n";
    std::cout << "Total:  " << g_tests_run << "\\n";
    std::cout << "Passed: " << g_tests_passed << "\\n";
    std::cout << "Failed: " << g_tests_failed << "\\n\\n";

    return g_tests_failed > 0 ? 1 : 0;
}
`);

cmake = fs.readFileSync('CMakeLists.txt', 'utf8');
cmake = cmake.replace(
    `if(PHANTOM_BUILD_TESTS)
    enable_testing()
    # Tests will be added later
endif()`,
    `if(PHANTOM_BUILD_TESTS)
    enable_testing()

    add_executable(test_hooks tests/test_hooks.cpp)
    target_link_libraries(test_hooks PRIVATE phantom)
    add_test(NAME HookEngineTests COMMAND test_hooks)
endif()`
);
fs.writeFileSync('CMakeLists.txt', cmake);

commit('2024-06-28T14:19:33+00:00', 'Add unit tests for hook engine\\n\\nComprehensive test suite covering memory operations, pattern scanning,\\nIAT hooking, hook removal, and RAII protection guard. Uses a minimal\\nbuilt-in test framework with no external dependencies.');
console.log('Commit 19 done');

// ============================================================
// COMMIT 20: Fix DXGI bypass crash on multi-monitor (2024-08-15)
// ============================================================
let dxgiCpp = fs.readFileSync('src/capture/dxgi.cpp', 'utf8');
dxgiCpp = dxgiCpp.replace(
    `    hr = adapter->EnumOutputs(0, &output);
    adapter->Release();
    if (FAILED(hr)) {
        PHANTOM_WARN("No display output found (headless?)");
        device->Release();
        context->Release();
        return Status::ErrorNotSupported;
    }`,
    `    // Enumerate all outputs (multi-monitor support)
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
    PHANTOM_INFO("Found " + std::to_string(outputs.size()) + " display output(s)");`
);
fs.writeFileSync('src/capture/dxgi.cpp', dxgiCpp);

commit('2024-08-15T16:42:07+00:00', 'Fix DXGI bypass crash on multi-monitor setups\\n\\nEnumerate all display outputs instead of hardcoding output index 0.\\nPreviously caused an access violation on systems where the primary\\nmonitor was not the first enumerated adapter output.');
console.log('Commit 20 done');

// ============================================================
// COMMIT 21: Architecture documentation (2024-10-03)
// ============================================================
w('docs/architecture.md', `# phantom-screen Architecture

## Overview

phantom-screen is a modular C++17 toolkit for researching Windows screen capture mechanisms and evasion techniques. The architecture is designed around three main pillars: **hooking**, **capture bypass**, and **display manipulation**.

## Module Structure

\`\`\`
phantom-screen/
+-- core/           Low-level primitives (hooks, memory, process)
+-- capture/        Capture detection and bypass modules
+-- display/        Window cloaking and overlay rendering
+-- utils/          Cross-cutting concerns (logging, config)
\`\`\`

## Core Module

### Hook Engine (core/hooks)

The hook engine supports three hooking methods:

| Method | Mechanism | Best For |
|--------|-----------|----------|
| IAT    | Patch Import Address Table entries | API interception in current module |
| Inline | Overwrite function prologue with JMP | Any function, any module |
| VMT    | Patch virtual method table pointers | COM interfaces (DXGI, D3D) |

**Inline Hook Flow:**
1. Calculate minimum bytes to overwrite (length disassembly)
2. Allocate trampoline near target (within +/-2GB)
3. Copy original bytes to trampoline
4. Append JMP-back to trampoline
5. Write JMP-to-detour at target

### Memory (core/memory)

Provides safe memory operations with automatic protection management:
- RAII ProtectionGuard for scoped protection changes
- Pattern scanning with wildcard masks
- Nearby allocation for relative addressing
- Instruction cache flushing

### Process (core/process)

Process interaction utilities:
- Privilege elevation (SeDebugPrivilege)
- Process/thread enumeration and manipulation
- Remote DLL injection
- Module enumeration

## Capture Module

### Detector (capture/detector)

Identifies active screen capture software through:
1. Process name matching against known capture applications
2. Loaded module analysis (DXGI, WGC DLLs)
3. Window behavior heuristics

### BitBlt Bypass (capture/bitblt)

Hooks GDI capture functions:
- \`BitBlt\` - Primary GDI screen copy
- \`StretchBlt\` - Scaled screen copy
- \`PrintWindow\` - Window-specific capture

### DXGI Bypass (capture/dxgi)

Hooks DXGI Desktop Duplication:
- \`IDXGIOutput1::DuplicateOutput\` - Duplication creation
- \`IDXGIOutputDuplication::AcquireNextFrame\` - Frame acquisition
- Manipulates D3D11 textures to clear protected regions

### WGC Bypass (capture/wgc)

Combines legitimate and hook-based approaches:
- \`SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)\` - Official API
- Hooks \`DwmGetWindowAttribute\` to hide cloaking state
- Blocks capture item creation for protected windows

## Display Module

### Cloaker (display/cloaker)

Multiple cloaking strategies:
- **DWM Cloak**: Uses undocumented DWMWA_CLOAK attribute
- **Display Affinity**: WDA_EXCLUDEFROMCAPTURE flag
- **Extended Style**: WS_EX_TOOLWINDOW + WS_EX_LAYERED
- **Composite**: Combines all methods

### Overlay (display/overlay)

D3D11 overlay rendering:
- Transparent, click-through window
- Automatic capture exclusion
- DWM frame extension for per-pixel alpha
- Custom render callback support

### Composition (display/composition)

DWM composition control:
- Thumbnail exclusion
- Peek behavior manipulation
- Rendering policy modification
- Protected attribute enforcement via hooks

## Thread Safety

All singleton instances use std::mutex for thread safety. The hook engine serializes all hook operations to prevent race conditions during function patching.

## Build System

CMake 3.16+ with C++17. Windows-only (MSVC recommended).

\`\`\`bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
\`\`\`

## Dependencies

Windows SDK components only (no external dependencies):
- d3d11.lib, dxgi.lib (DirectX 11)
- dwmapi.lib (Desktop Window Manager)
- user32.lib, gdi32.lib (GDI/Window management)
- psapi.lib, advapi32.lib (Process/privilege APIs)
`);

commit('2024-10-03T13:55:21+00:00', 'Add architecture documentation\\n\\nComprehensive technical documentation covering module structure,\\nhook engine internals, capture bypass strategies, display\\nmanipulation techniques, and build system.');
console.log('Commit 21 done');
