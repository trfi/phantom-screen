#include <phantom/core/process.h>
#include <phantom/utils/logger.h>
#include <Psapi.h>
#include <sstream>
#include <algorithm>

namespace phantom { namespace core {

DWORD Process::get_current_pid() {
    return GetCurrentProcessId();
}

std::string Process::get_current_path() {
    char buf[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    return std::string(buf);
}

bool Process::enable_debug_privilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        PHANTOM_ERROR("Failed to open process token");
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        PHANTOM_ERROR("Failed to lookup SeDebugPrivilege");
        return false;
    }

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr) != 0;
    DWORD err = GetLastError();
    CloseHandle(hToken);

    if (!result || err == ERROR_NOT_ALL_ASSIGNED) {
        PHANTOM_WARN("Could not enable SeDebugPrivilege (run as admin?)");
        return false;
    }

    PHANTOM_INFO("SeDebugPrivilege enabled successfully");
    return true;
}

bool Process::is_elevated() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return false;

    TOKEN_ELEVATION elevation = {};
    DWORD size = sizeof(elevation);
    bool elevated = false;

    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
        elevated = elevation.TokenIsElevated != 0;
    }

    CloseHandle(hToken);
    return elevated;
}

std::vector<ProcessInfo> Process::enumerate_processes() {
    std::vector<ProcessInfo> result;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return result;

    PROCESSENTRY32 pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32First(snap, &pe)) {
        do {
            ProcessInfo info;
            info.pid = pe.th32ProcessID;
            info.parent_pid = pe.th32ParentProcessID;
            info.name = pe.szExeFile;
            info.handle = nullptr;
            result.push_back(info);
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return result;
}

std::vector<ProcessInfo> Process::find_by_name(const std::string& name) {
    auto all = enumerate_processes();
    std::vector<ProcessInfo> matches;
    for (auto& p : all) {
        std::string pname = p.name;
        std::string target = name;
        std::transform(pname.begin(), pname.end(), pname.begin(), ::tolower);
        std::transform(target.begin(), target.end(), target.begin(), ::tolower);
        if (pname.find(target) != std::string::npos) {
            matches.push_back(p);
        }
    }
    return matches;
}

HANDLE Process::open_process(DWORD pid, DWORD access) {
    HANDLE h = OpenProcess(access, FALSE, pid);
    if (!h) {
        PHANTOM_WARN("OpenProcess failed for PID " + std::to_string(pid) +
                     " error=" + std::to_string(GetLastError()));
    }
    return h;
}

bool Process::is_process_running(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    DWORD exitCode = 0;
    bool running = GetExitCodeProcess(h, &exitCode) && exitCode == STILL_ACTIVE;
    CloseHandle(h);
    return running;
}

bool Process::is_wow64(HANDLE process) {
    BOOL wow64 = FALSE;
    HANDLE h = process ? process : GetCurrentProcess();
    IsWow64Process(h, &wow64);
    return wow64 != FALSE;
}

std::vector<HMODULE> Process::get_loaded_modules(HANDLE process) {
    HANDLE h = process ? process : GetCurrentProcess();
    std::vector<HMODULE> modules(1024);
    DWORD needed = 0;

    if (!EnumProcessModules(h, modules.data(), (DWORD)(modules.size() * sizeof(HMODULE)), &needed)) {
        return {};
    }

    modules.resize(needed / sizeof(HMODULE));
    return modules;
}

void* Process::get_remote_proc_address(HANDLE process, const char* module_name, const char* proc_name) {
    HMODULE local_mod = GetModuleHandleA(module_name);
    if (!local_mod) return nullptr;
    void* local_proc = (void*)GetProcAddress(local_mod, proc_name);
    if (!local_proc) return nullptr;
    return local_proc;
}

bool Process::inject_dll(DWORD pid, const std::string& dll_path) {
    PHANTOM_INFO("Injecting DLL into PID " + std::to_string(pid) + ": " + dll_path);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        PHANTOM_ERROR("inject_dll: OpenProcess failed");
        return false;
    }

    size_t path_size = dll_path.size() + 1;
    void* remote_buf = VirtualAllocEx(hProcess, nullptr, path_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_buf) {
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, remote_buf, dll_path.c_str(), path_size, nullptr)) {
        VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),
        remote_buf, 0, nullptr);

    if (!hThread) {
        VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, 5000);
    VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    PHANTOM_INFO("DLL injection completed");
    return true;
}

bool Process::suspend_threads(DWORD pid, DWORD exclude_tid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    int count = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid && te.th32ThreadID != exclude_tid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) { SuspendThread(hThread); CloseHandle(hThread); count++; }
            }
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return count > 0;
}

bool Process::resume_threads(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    int count = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) { ResumeThread(hThread); CloseHandle(hThread); count++; }
            }
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return count > 0;
}

}} // namespace phantom::core
