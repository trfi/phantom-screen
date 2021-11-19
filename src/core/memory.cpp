#include <phantom/core/memory.h>
#include <phantom/utils/logger.h>
#include <Psapi.h>
#include <algorithm>
#include <cstring>

namespace phantom { namespace core {

std::optional<DWORD> Memory::protect(void* address, size_t size, DWORD new_protect) {
    DWORD old_protect = 0;
    if (!VirtualProtect(address, size, new_protect, &old_protect)) {
        PHANTOM_ERROR("VirtualProtect failed at " +
                      std::to_string(reinterpret_cast<uintptr_t>(address)) +
                      " error=" + std::to_string(GetLastError()));
        return std::nullopt;
    }
    return old_protect;
}

bool Memory::safe_read(const void* address, void* buffer, size_t size) {
    SIZE_T bytes_read = 0;
    HANDLE process = GetCurrentProcess();
    if (!ReadProcessMemory(process, address, buffer, size, &bytes_read)) {
        DWORD old_prot;
        if (!VirtualProtect(const_cast<void*>(address), size, PAGE_EXECUTE_READ, &old_prot)) {
            PHANTOM_ERROR("safe_read: failed to change protection");
            return false;
        }
        memcpy(buffer, address, size);
        VirtualProtect(const_cast<void*>(address), size, old_prot, &old_prot);
        return true;
    }
    return bytes_read == size;
}

bool Memory::safe_write(void* address, const void* data, size_t size) {
    ProtectionGuard guard(address, size, PAGE_EXECUTE_READWRITE);
    if (!guard.success()) {
        PHANTOM_ERROR("safe_write: failed to unprotect target region");
        return false;
    }
    memcpy(address, data, size);
    flush_cache(address, size);
    return true;
}

bool Memory::nop_fill(void* address, size_t size) {
    std::vector<uint8_t> nops(size, 0x90);
    return safe_write(address, nops.data(), size);
}

void* Memory::alloc_near(void* target, size_t size, DWORD prot) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    uintptr_t target_addr = reinterpret_cast<uintptr_t>(target);
    uintptr_t alloc_granularity = si.dwAllocationGranularity;

    uintptr_t min_addr = (target_addr > 0x7FFF0000ULL)
        ? target_addr - 0x7FFF0000ULL : 0;
    uintptr_t max_addr = target_addr + 0x7FFF0000ULL;

    min_addr = (std::max)(min_addr, reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress));
    max_addr = (std::min)(max_addr, reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress));

    uintptr_t addr = target_addr;
    addr = (addr + alloc_granularity - 1) & ~(alloc_granularity - 1);

    while (addr < max_addr) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<void*>(addr), &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_FREE && mbi.RegionSize >= size) {
            void* result = VirtualAlloc(reinterpret_cast<void*>(addr), size,
                                        MEM_COMMIT | MEM_RESERVE, prot);
            if (result) return result;
        }
        addr += mbi.RegionSize;
        addr = (addr + alloc_granularity - 1) & ~(alloc_granularity - 1);
    }

    addr = target_addr - size;
    addr &= ~(alloc_granularity - 1);
    while (addr > min_addr) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<void*>(addr), &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_FREE && mbi.RegionSize >= size) {
            void* result = VirtualAlloc(reinterpret_cast<void*>(addr), size,
                                        MEM_COMMIT | MEM_RESERVE, prot);
            if (result) return result;
        }
        if (addr < alloc_granularity) break;
        addr -= alloc_granularity;
    }

    PHANTOM_WARN("alloc_near: no suitable region found, using standard allocation");
    return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, prot);
}

bool Memory::free(void* address) {
    if (!address) return false;
    return VirtualFree(address, 0, MEM_RELEASE) != 0;
}

void* Memory::pattern_scan(void* start, size_t region_size,
                           const uint8_t* pattern, const char* mask) {
    size_t pattern_len = strlen(mask);
    if (pattern_len == 0 || pattern_len > region_size) return nullptr;

    const uint8_t* region = static_cast<const uint8_t*>(start);
    size_t scan_end = region_size - pattern_len;

    for (size_t i = 0; i <= scan_end; ++i) {
        bool found = true;
        for (size_t j = 0; j < pattern_len; ++j) {
            if (mask[j] == 'x' && region[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) return const_cast<uint8_t*>(region + i);
    }
    return nullptr;
}

void* Memory::pattern_scan_module(const char* module_name,
                                  const uint8_t* pattern, const char* mask) {
    void* base = nullptr;
    size_t mod_size = 0;
    if (!get_module_info(module_name, base, mod_size)) {
        PHANTOM_ERROR("pattern_scan_module: failed to get info for " + std::string(module_name));
        return nullptr;
    }
    return pattern_scan(base, mod_size, pattern, mask);
}

bool Memory::get_module_info(const char* module_name, void*& base, size_t& size) {
    HMODULE hModule = GetModuleHandleA(module_name);
    if (!hModule) return false;
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &mi, sizeof(mi))) return false;
    base = mi.lpBaseOfDll;
    size = mi.SizeOfImage;
    return true;
}

int32_t Memory::calculate_relative(void* from, void* to, size_t instruction_size) {
    uintptr_t from_addr = reinterpret_cast<uintptr_t>(from) + instruction_size;
    uintptr_t to_addr = reinterpret_cast<uintptr_t>(to);
    return static_cast<int32_t>(to_addr - from_addr);
}

bool Memory::flush_cache(void* address, size_t size) {
    return FlushInstructionCache(GetCurrentProcess(), address, size) != 0;
}

ProtectionGuard::ProtectionGuard(void* address, size_t size, DWORD new_protect)
    : address_(address), size_(size), old_protect_(0), success_(false) {
    success_ = VirtualProtect(address, size, new_protect, &old_protect_) != 0;
}

ProtectionGuard::~ProtectionGuard() {
    if (success_) {
        DWORD dummy;
        VirtualProtect(address_, size_, old_protect_, &dummy);
    }
}

}} // namespace phantom::core
