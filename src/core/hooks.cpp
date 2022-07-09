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
// ---- Inline Length Disassembler (simplified) ----
// Returns instruction length at the given address.
// This is a simplified x86-64 length disassembler covering common
// instruction prefixes and encodings. A production implementation
// would use a full disassembler like Zydis or Capstone.
static size_t get_instruction_length(const uint8_t* code) {
    size_t len = 0;
    bool has_rex = false;
    bool has_prefix66 = false;

    // Skip prefixes
    while (true) {
        uint8_t b = code[len];
        if (b == 0x66) { has_prefix66 = true; len++; continue; }
        if (b == 0x67 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65) { len++; continue; }
        // REX prefix (0x40-0x4F)
        if ((b & 0xF0) == 0x40) { has_rex = true; len++; continue; }
        break;
    }

    uint8_t opcode = code[len++];

    // Common single-byte instructions
    if (opcode == 0x90) return len; // NOP
    if (opcode == 0xC3 || opcode == 0xCB) return len; // RET
    if (opcode == 0xCC) return len; // INT3

    // PUSH/POP register (0x50-0x5F)
    if (opcode >= 0x50 && opcode <= 0x5F) return len;

    // MOV reg, imm32/imm64 (0xB8-0xBF)
    if (opcode >= 0xB8 && opcode <= 0xBF) {
        return len + (has_rex ? 8 : 4);
    }

    // Short JMP rel8
    if (opcode == 0xEB) return len + 1;

    // Near JMP rel32
    if (opcode == 0xE9) return len + 4;

    // CALL rel32
    if (opcode == 0xE8) return len + 4;

    // Jcc rel8 (0x70-0x7F)
    if (opcode >= 0x70 && opcode <= 0x7F) return len + 1;

    // SUB RSP, imm8 pattern
    if (opcode == 0x83) {
        len++; // ModR/M
        return len + 1; // imm8
    }

    // MOV with ModR/M
    if (opcode == 0x89 || opcode == 0x8B || opcode == 0x8D) {
        uint8_t modrm = code[len++];
        uint8_t mod = (modrm >> 6) & 3;
        uint8_t rm = modrm & 7;
        if (mod == 0 && rm == 5) return len + 4; // RIP-relative
        if (mod == 0 && rm == 4) len++; // SIB
        if (mod == 1) { if (rm == 4) len++; return len + 1; }
        if (mod == 2) { if (rm == 4) len++; return len + 4; }
        return len;
    }

    // Two-byte opcode (0x0F prefix)
    if (opcode == 0x0F) {
        uint8_t op2 = code[len++];
        // Jcc rel32 (0x80-0x8F)
        if (op2 >= 0x80 && op2 <= 0x8F) return len + 4;
        // MOVAPS, MOVDQA etc with ModR/M
        uint8_t modrm = code[len++];
        uint8_t mod = (modrm >> 6) & 3;
        uint8_t rm = modrm & 7;
        if (mod == 0 && rm == 5) return len + 4;
        if (mod == 0 && rm == 4) len++;
        if (mod == 1) { if (rm == 4) len++; return len + 1; }
        if (mod == 2) { if (rm == 4) len++; return len + 4; }
        return len;
    }

    // Fallback: assume 1 byte
    return len;
}

size_t HookEngine::calculate_trampoline_size(void* target) {
    const uint8_t* code = static_cast<const uint8_t*>(target);
    size_t total = 0;
    // Need at least 5 bytes for a JMP rel32 (or 14 for absolute JMP on x64)
#ifdef _WIN64
    const size_t min_size = 14; // JMP [RIP+0]; DQ addr
#else
    const size_t min_size = 5;  // JMP rel32
#endif
    while (total < min_size) {
        size_t inst_len = get_instruction_length(code + total);
        if (inst_len == 0) return 0; // Disassembly failure
        total += inst_len;
    }
    return total;
}

void* HookEngine::create_trampoline(void* target, size_t patch_size) {
    // Allocate trampoline near target for relative addressing
    size_t tramp_size = patch_size + 14; // copied bytes + JMP back
    void* trampoline = Memory::alloc_near(target, tramp_size);
    if (!trampoline) return nullptr;

    // Copy original bytes
    memcpy(trampoline, target, patch_size);

    // Add JMP back to original code after the patched region
    uint8_t* jmp_back = static_cast<uint8_t*>(trampoline) + patch_size;
    void* continue_addr = static_cast<uint8_t*>(target) + patch_size;

#ifdef _WIN64
    // Absolute JMP: FF 25 00 00 00 00 [8-byte addr]
    jmp_back[0] = 0xFF;
    jmp_back[1] = 0x25;
    *reinterpret_cast<uint32_t*>(jmp_back + 2) = 0;
    *reinterpret_cast<uint64_t*>(jmp_back + 6) = reinterpret_cast<uint64_t>(continue_addr);
#else
    // Relative JMP: E9 [4-byte offset]
    jmp_back[0] = 0xE9;
    *reinterpret_cast<int32_t*>(jmp_back + 1) = Memory::calculate_relative(jmp_back, continue_addr);
#endif

    Memory::flush_cache(trampoline, tramp_size);
    return trampoline;
}

Status HookEngine::install_inline_hook(const std::string& name, void* target,
                                        void* detour, void** original_out) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (hooks_.find(name) != hooks_.end()) {
        return Status::ErrorAlreadyInitialized;
    }

    if (!target || !detour) return Status::ErrorInvalidParam;

    // Calculate how many bytes we need to overwrite
    size_t patch_size = calculate_trampoline_size(target);
    if (patch_size == 0) {
        PHANTOM_ERROR("Failed to calculate trampoline size for " + name);
        return Status::ErrorHookFailed;
    }

    // Create trampoline (copy original bytes + JMP back)
    void* trampoline = create_trampoline(target, patch_size);
    if (!trampoline) {
        PHANTOM_ERROR("Failed to create trampoline for " + name);
        return Status::ErrorMemoryAlloc;
    }

    if (original_out) *original_out = trampoline;

    // Backup original bytes
    void* backup = Memory::alloc_near(target, patch_size);
    if (backup) {
        memcpy(backup, target, patch_size);
    }

    // Write the detour JMP at the target
    uint8_t jmp_patch[14] = {};
#ifdef _WIN64
    // FF 25 00 00 00 00 [8-byte addr]
    jmp_patch[0] = 0xFF;
    jmp_patch[1] = 0x25;
    *reinterpret_cast<uint32_t*>(jmp_patch + 2) = 0;
    *reinterpret_cast<uint64_t*>(jmp_patch + 6) = reinterpret_cast<uint64_t>(detour);

    // NOP remaining bytes
    if (!Memory::safe_write(target, jmp_patch, 14)) {
        Memory::free(trampoline);
        Memory::free(backup);
        return Status::ErrorHookFailed;
    }
    if (patch_size > 14) {
        Memory::nop_fill(static_cast<uint8_t*>(target) + 14, patch_size - 14);
    }
#else
    jmp_patch[0] = 0xE9;
    *reinterpret_cast<int32_t*>(jmp_patch + 1) = Memory::calculate_relative(target, detour);

    if (!Memory::safe_write(target, jmp_patch, 5)) {
        Memory::free(trampoline);
        Memory::free(backup);
        return Status::ErrorHookFailed;
    }
    if (patch_size > 5) {
        Memory::nop_fill(static_cast<uint8_t*>(target) + 5, patch_size - 5);
    }
#endif

    HookContext ctx{};
    ctx.name = name;
    ctx.type = HookType::Inline;
    ctx.target = target;
    ctx.detour = detour;
    ctx.trampoline = trampoline;
    ctx.original_bytes = backup;
    ctx.patch_size = patch_size;
    ctx.active = true;

    hooks_[name] = ctx;

    PHANTOM_INFO("Inline hook installed: " + name + " (patched " +
                 std::to_string(patch_size) + " bytes)");
    return Status::Success;
}

Status HookEngine::install_vmt_hook(const std::string& name, void** vtable,
                                     size_t index, void* detour, void** original_out) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (hooks_.find(name) != hooks_.end()) {
        return Status::ErrorAlreadyInitialized;
    }

    if (!vtable || !detour) return Status::ErrorInvalidParam;

    // The vtable entry to patch
    void** entry = &vtable[index];
    void* original = vtable[index];

    if (original_out) *original_out = original;

    // Overwrite the vtable entry
    if (!Memory::safe_write(entry, &detour, sizeof(void*))) {
        PHANTOM_ERROR("Failed to patch VMT entry for " + name);
        return Status::ErrorHookFailed;
    }

    HookContext ctx{};
    ctx.name = name;
    ctx.type = HookType::VMT;
    ctx.target = entry;
    ctx.detour = detour;
    ctx.trampoline = original;
    ctx.original_bytes = nullptr;
    ctx.patch_size = sizeof(void*);
    ctx.active = true;

    hooks_[name] = ctx;

    PHANTOM_INFO("VMT hook installed: " + name + " (vtable index " +
                 std::to_string(index) + ")");
    return Status::Success;
}

}} // namespace phantom::core
