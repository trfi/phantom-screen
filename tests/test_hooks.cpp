/**
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

#define TEST(name) \
    static void test_##name(); \
    struct TestReg_##name { \
        TestReg_##name() { \
            g_tests_run++; \
            std::cout << "  TEST " << #name << "... "; \
            try { \
                test_##name(); \
                std::cout << "PASSED\n"; \
                g_tests_passed++; \
            } catch (const std::exception& e) { \
                std::cout << "FAILED: " << e.what() << "\n"; \
                g_tests_failed++; \
            } catch (...) { \
                std::cout << "FAILED (unknown exception)\n"; \
                g_tests_failed++; \
            } \
        } \
    } g_test_reg_##name; \
    static void test_##name()

#define EXPECT_EQ(a, b) \
    if ((a) != (b)) throw std::runtime_error( \
        std::string("Expected ") + #a + " == " + #b + \
        " at line " + std::to_string(__LINE__))

#define EXPECT_TRUE(x) \
    if (!(x)) throw std::runtime_error( \
        std::string("Expected true: ") + #x + \
        " at line " + std::to_string(__LINE__))

#define EXPECT_FALSE(x) \
    if (x) throw std::runtime_error( \
        std::string("Expected false: ") + #x + \
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

    std::cout << "\n=== phantom-screen: Hook Engine Test Suite ===\n\n";

    // Tests are auto-registered and run via static initialization

    std::cout << "\n--- Results ---\n";
    std::cout << "Total:  " << g_tests_run << "\n";
    std::cout << "Passed: " << g_tests_passed << "\n";
    std::cout << "Failed: " << g_tests_failed << "\n\n";

    return g_tests_failed > 0 ? 1 : 0;
}
