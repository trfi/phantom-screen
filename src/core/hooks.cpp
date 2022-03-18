#include <phantom/core/hooks.h>
#include <phantom/utils/logger.h>
#include <DbgHelp.h>
#include <cstring>

namespace phantom { namespace core {

HookEngine& HookEngine::instance() {
    static HookEngine engine;
    return engine;
}

// ---- IAT Hooking Implementation ----

void* HookEngine::find_iat_entry(HMODULE module, const char* target_module, const char* target_function) {
    if (!module) module = GetModuleHandleA(nullptr);

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uint8_t*>(module) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.Size == 0) return nullptr;

    auto import_desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        reinterpret_cast<uint8_t*>(module) + import_dir.VirtualAddress);

    for (; import_desc->Name != 0; ++import_desc) {
        auto mod_name = reinterpret_cast<const char*>(
            reinterpret_cast<uint8_t*>(module) + import_desc->Name);

        if (_stricmp(mod_name, target_module) != 0) continue;

        auto orig_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
            reinterpret_cast<uint8_t*>(module) + import_desc->OriginalFirstThunk);
        auto first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
            reinterpret_cast<uint8_t*>(module) + import_desc->FirstThunk);

        for (; orig_thunk->u1.AddressOfData != 0; ++orig_thunk, ++first_thunk) {
            if (IMAGE_SNAP_BY_ORDINAL(orig_thunk->u1.Ordinal)) continue;

            auto import_by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                reinterpret_cast<uint8_t*>(module) + orig_thunk->u1.AddressOfData);

            if (strcmp(import_by_name->Name, target_function) == 0) {
                return &first_thunk->u1.Function;
            }
        }
    }

    return nullptr;
}

Status HookEngine::install_iat_hook(const std::string& name,
                                     const char* target_module,
                                     const char* target_function,
                                     void* detour,
                                     void** original_out) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (hooks_.find(name) != hooks_.end()) {
        PHANTOM_WARN("Hook already exists: " + name);
        return Status::ErrorAlreadyInitialized;
    }

    HMODULE exe_module = GetModuleHandleA(nullptr);
    void* iat_entry = find_iat_entry(exe_module, target_module, target_function);

    if (!iat_entry) {
        PHANTOM_ERROR("IAT entry not found for " + std::string(target_module) +
                      "!" + std::string(target_function));
        return Status::ErrorHookFailed;
    }

    // Read the current (original) function pointer
    void* original = nullptr;
    Memory::safe_read(iat_entry, &original, sizeof(void*));

    if (original_out) *original_out = original;

    // Overwrite IAT entry with our detour
    if (!Memory::safe_write(iat_entry, &detour, sizeof(void*))) {
        PHANTOM_ERROR("Failed to write IAT entry for " + name);
        return Status::ErrorHookFailed;
    }

    HookContext ctx{};
    ctx.name = name;
    ctx.type = HookType::IAT;
    ctx.target = iat_entry;
    ctx.detour = detour;
    ctx.trampoline = original;
    ctx.original_bytes = nullptr;
    ctx.patch_size = sizeof(void*);
    ctx.active = true;
    ctx.target_module = exe_module;

    hooks_[name] = ctx;

    PHANTOM_INFO("IAT hook installed: " + name + " (" +
                 std::string(target_module) + "!" + std::string(target_function) + ")");
    return Status::Success;
}

Status HookEngine::remove_hook(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = hooks_.find(name);
    if (it == hooks_.end()) return Status::ErrorInvalidParam;

    auto& ctx = it->second;
    if (!ctx.active) {
        hooks_.erase(it);
        return Status::Success;
    }

    switch (ctx.type) {
        case HookType::IAT: {
            void* original = ctx.trampoline;
            Memory::safe_write(ctx.target, &original, sizeof(void*));
            break;
        }
        case HookType::Inline: {
            if (ctx.original_bytes) {
                Memory::safe_write(ctx.target, ctx.original_bytes, ctx.patch_size);
                Memory::free(ctx.original_bytes);
            }
            if (ctx.trampoline) {
                Memory::free(ctx.trampoline);
            }
            break;
        }
        case HookType::VMT: {
            void* original = ctx.trampoline;
            Memory::safe_write(ctx.target, &original, sizeof(void*));
            break;
        }
    }

    ctx.active = false;
    PHANTOM_INFO("Hook removed: " + name);
    hooks_.erase(it);
    return Status::Success;
}

Status HookEngine::remove_all_hooks() {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& [name, ctx] : hooks_) {
        if (!ctx.active) continue;

        switch (ctx.type) {
            case HookType::IAT:
            case HookType::VMT: {
                void* original = ctx.trampoline;
                Memory::safe_write(ctx.target, &original, sizeof(void*));
                break;
            }
            case HookType::Inline: {
                if (ctx.original_bytes) {
                    Memory::safe_write(ctx.target, ctx.original_bytes, ctx.patch_size);
                    Memory::free(ctx.original_bytes);
                }
                if (ctx.trampoline) Memory::free(ctx.trampoline);
                break;
            }
        }
        ctx.active = false;
    }

    hooks_.clear();
    PHANTOM_INFO("All hooks removed");
    return Status::Success;
}

bool HookEngine::is_hooked(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = hooks_.find(name);
    return it != hooks_.end() && it->second.active;
}

const HookContext* HookEngine::get_context(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = hooks_.find(name);
    return (it != hooks_.end()) ? &it->second : nullptr;
}

size_t HookEngine::active_hook_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [_, ctx] : hooks_) {
        if (ctx.active) count++;
    }
    return count;
}

// Stub implementations for inline/VMT (will be filled in later commits)
size_t HookEngine::calculate_trampoline_size(void* target) {
    // Basic implementation: minimum 5 bytes for a JMP rel32
    // A proper implementation needs a length disassembler
    (void)target;
    return 5;
}

void* HookEngine::create_trampoline(void* target, size_t patch_size) {
    (void)target;
    (void)patch_size;
    return nullptr; // Implemented in inline hook commit
}

Status HookEngine::install_inline_hook(const std::string& name, void* target,
                                        void* detour, void** original_out) {
    (void)name; (void)target; (void)detour; (void)original_out;
    return Status::ErrorNotSupported; // Implemented later
}

Status HookEngine::install_vmt_hook(const std::string& name, void** vtable,
                                     size_t index, void* detour, void** original_out) {
    (void)name; (void)vtable; (void)index; (void)detour; (void)original_out;
    return Status::ErrorNotSupported; // Implemented later
}

}} // namespace phantom::core
