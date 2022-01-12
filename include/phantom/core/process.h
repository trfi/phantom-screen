#pragma once
#ifndef PHANTOM_PROCESS_H
#define PHANTOM_PROCESS_H

#include <phantom/phantom.h>
#include <string>
#include <vector>
#include <TlHelp32.h>

namespace phantom { namespace core {

struct ProcessInfo {
    DWORD pid;
    DWORD parent_pid;
    std::string name;
    std::string path;
    HANDLE handle;
};

class Process {
public:
    static DWORD get_current_pid();
    static std::string get_current_path();
    static bool enable_debug_privilege();
    static bool is_elevated();
    static std::vector<ProcessInfo> enumerate_processes();
    static std::vector<ProcessInfo> find_by_name(const std::string& name);
    static HANDLE open_process(DWORD pid, DWORD access = PROCESS_ALL_ACCESS);
    static bool is_process_running(DWORD pid);
    static bool is_wow64(HANDLE process = nullptr);
    static std::vector<HMODULE> get_loaded_modules(HANDLE process = nullptr);
    static void* get_remote_proc_address(HANDLE process, const char* module_name, const char* proc_name);
    static bool inject_dll(DWORD pid, const std::string& dll_path);
    static bool suspend_threads(DWORD pid, DWORD exclude_tid = 0);
    static bool resume_threads(DWORD pid);
};

}} // namespace phantom::core

#endif // PHANTOM_PROCESS_H
