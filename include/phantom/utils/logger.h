#pragma once
#ifndef PHANTOM_LOGGER_H
#define PHANTOM_LOGGER_H

#include <phantom/phantom.h>
#include <string>
#include <fstream>
#include <mutex>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <iostream>

namespace phantom { namespace utils {

enum class LogLevel : uint8_t {
    Trace = 0,
    Debug,
    Info,
    Warning,
    Error,
    Fatal,
    Off
};

inline const char* log_level_str(LogLevel level) {
    switch (level) {
        case LogLevel::Trace:   return "TRACE";
        case LogLevel::Debug:   return "DEBUG";
        case LogLevel::Info:    return "INFO ";
        case LogLevel::Warning: return "WARN ";
        case LogLevel::Error:   return "ERROR";
        case LogLevel::Fatal:   return "FATAL";
        default:                return "?????";
    }
}

class Logger {
public:
    static Logger& instance() {
        static Logger inst;
        return inst;
    }

    void set_level(LogLevel level) { min_level_ = level; }
    LogLevel get_level() const { return min_level_; }

    void set_file(const std::string& path) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (file_.is_open()) file_.close();
        file_.open(path, std::ios::app);
        file_enabled_ = file_.is_open();
    }

    void set_console(bool enabled) { console_enabled_ = enabled; }

    void log(LogLevel level, const char* file, int line, const std::string& message) {
        if (level < min_level_) return;

        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        std::tm tm_buf{};
        localtime_s(&tm_buf, &time_t);

        std::ostringstream oss;
        oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
            << '.' << std::setfill('0') << std::setw(3) << ms.count()
            << " [" << log_level_str(level) << "] "
            << extract_filename(file) << ":" << line
            << " | " << message;

        std::string formatted = oss.str();

        std::lock_guard<std::mutex> lock(mutex_);
        if (console_enabled_) {
            HANDLE hConsole = GetStdHandle(STD_ERROR_HANDLE);
            WORD color = get_color(level);
            SetConsoleTextAttribute(hConsole, color);
            std::cerr << formatted << std::endl;
            SetConsoleTextAttribute(hConsole, 0x07); // reset
        }
        if (file_enabled_ && file_.is_open()) {
            file_ << formatted << std::endl;
        }
    }

private:
    Logger() : min_level_(LogLevel::Info), console_enabled_(true), file_enabled_(false) {}
    ~Logger() { if (file_.is_open()) file_.close(); }
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    static const char* extract_filename(const char* path) {
        const char* file = path;
        for (const char* p = path; *p; ++p) {
            if (*p == '\\' || *p == '/') file = p + 1;
        }
        return file;
    }

    static WORD get_color(LogLevel level) {
        switch (level) {
            case LogLevel::Trace:   return 0x08; // dark gray
            case LogLevel::Debug:   return 0x07; // gray
            case LogLevel::Info:    return 0x0A; // green
            case LogLevel::Warning: return 0x0E; // yellow
            case LogLevel::Error:   return 0x0C; // red
            case LogLevel::Fatal:   return 0xCF; // white on red
            default:                return 0x07;
        }
    }

    LogLevel min_level_;
    bool console_enabled_;
    bool file_enabled_;
    std::ofstream file_;
    std::mutex mutex_;
};

}} // namespace phantom::utils

#define PHANTOM_LOG(level, msg) \
    phantom::utils::Logger::instance().log(level, __FILE__, __LINE__, msg)

#define PHANTOM_TRACE(msg)   PHANTOM_LOG(phantom::utils::LogLevel::Trace, msg)
#define PHANTOM_DEBUG(msg)   PHANTOM_LOG(phantom::utils::LogLevel::Debug, msg)
#define PHANTOM_INFO(msg)    PHANTOM_LOG(phantom::utils::LogLevel::Info, msg)
#define PHANTOM_WARN(msg)    PHANTOM_LOG(phantom::utils::LogLevel::Warning, msg)
#define PHANTOM_ERROR(msg)   PHANTOM_LOG(phantom::utils::LogLevel::Error, msg)
#define PHANTOM_FATAL(msg)   PHANTOM_LOG(phantom::utils::LogLevel::Fatal, msg)

#endif // PHANTOM_LOGGER_H
