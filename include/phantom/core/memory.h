#pragma once
#ifndef PHANTOM_MEMORY_H
#define PHANTOM_MEMORY_H

#include <phantom/phantom.h>
#include <cstdint>
#include <vector>
#include <optional>

namespace phantom { namespace core {

struct MemoryProtection {
    DWORD old_protect = 0;
    void* address = nullptr;
    size_t size = 0;
};

/**
 * Memory manipulation utilities for hook installation and code patching.
 * Provides safe read/write/protect operations with RAII-style protection guard.
 */
class Memory {
public:
    static std::optional<DWORD> protect(void* address, size_t size, DWORD new_protect);
    static bool safe_read(const void* address, void* buffer, size_t size);
    static bool safe_write(void* address, const void* data, size_t size);
    static bool nop_fill(void* address, size_t size);
    static void* alloc_near(void* target, size_t size, DWORD protect = PAGE_EXECUTE_READWRITE);
    static bool free(void* address);
    static void* pattern_scan(void* start, size_t size, const uint8_t* pattern, const char* mask);
    static void* pattern_scan_module(const char* module_name, const uint8_t* pattern, const char* mask);
    static bool get_module_info(const char* module_name, void*& base, size_t& size);
    static int32_t calculate_relative(void* from, void* to, size_t instruction_size = 5);
    static bool flush_cache(void* address, size_t size);
};

class ProtectionGuard {
public:
    ProtectionGuard(void* address, size_t size, DWORD new_protect);
    ~ProtectionGuard();
    bool success() const { return success_; }
    ProtectionGuard(const ProtectionGuard&) = delete;
    ProtectionGuard& operator=(const ProtectionGuard&) = delete;
private:
    void* address_;
    size_t size_;
    DWORD old_protect_;
    bool success_;
};

}} // namespace phantom::core

#endif // PHANTOM_MEMORY_H
