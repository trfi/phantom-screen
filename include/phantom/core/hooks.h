#pragma once
#ifndef PHANTOM_HOOKS_H
#define PHANTOM_HOOKS_H

#include <phantom/phantom.h>
#include <phantom/core/memory.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

namespace phantom { namespace core {

enum class HookType : uint8_t {
    IAT = 0,     // Import Address Table hooking
    Inline,      // Inline/detour hooking
    VMT          // Virtual Method Table hooking
};

struct HookContext {
    std::string name;
    HookType type;
    void* target;           // Original function address
    void* detour;           // Our replacement function
    void* trampoline;       // Trampoline to call original
    void* original_bytes;   // Backup of overwritten bytes
    size_t patch_size;      // Number of bytes patched
    bool active;
    HMODULE target_module;
};

/**
 * Hook engine supporting IAT, inline, and VMT hooking.
 * Thread-safe with automatic trampoline generation.
 */
class HookEngine {
public:
    static HookEngine& instance();

    // IAT Hooking
    Status install_iat_hook(const std::string& name,
                            const char* target_module,
                            const char* target_function,
                            void* detour,
                            void** original_out = nullptr);

    // Inline Hooking (added in later commit)
    Status install_inline_hook(const std::string& name,
                               void* target,
                               void* detour,
                               void** original_out = nullptr);

    // VMT Hooking (added in later commit)
    Status install_vmt_hook(const std::string& name,
                            void** vtable,
                            size_t index,
                            void* detour,
                            void** original_out = nullptr);

    Status remove_hook(const std::string& name);
    Status remove_all_hooks();

    bool is_hooked(const std::string& name) const;
    const HookContext* get_context(const std::string& name) const;

    size_t active_hook_count() const;

private:
    HookEngine() = default;
    ~HookEngine() { remove_all_hooks(); }
    HookEngine(const HookEngine&) = delete;
    HookEngine& operator=(const HookEngine&) = delete;

    void* find_iat_entry(HMODULE module, const char* target_module, const char* target_function);
    size_t calculate_trampoline_size(void* target);
    void* create_trampoline(void* target, size_t patch_size);

    mutable std::mutex mutex_;
    std::unordered_map<std::string, HookContext> hooks_;
};

}} // namespace phantom::core

#endif // PHANTOM_HOOKS_H
