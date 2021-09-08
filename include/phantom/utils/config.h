#pragma once
#ifndef PHANTOM_CONFIG_H
#define PHANTOM_CONFIG_H

#include <phantom/phantom.h>
#include <string>
#include <unordered_map>
#include <mutex>
#include <fstream>
#include <sstream>
#include <algorithm>

namespace phantom { namespace utils {

/**
 * Runtime configuration manager.
 * Supports loading from INI-style files and programmatic overrides.
 * Thread-safe for concurrent read/write access.
 */
class Config {
public:
    static Config& instance() {
        static Config inst;
        return inst;
    }

    Status load_file(const std::string& path) {
        std::ifstream file(path);
        if (!file.is_open()) return Status::ErrorGeneric;

        std::lock_guard<std::mutex> lock(mutex_);
        std::string line, current_section;

        while (std::getline(file, line)) {
            line = trim(line);
            if (line.empty() || line[0] == '#' || line[0] == ';') continue;

            if (line.front() == '[' && line.back() == ']') {
                current_section = line.substr(1, line.size() - 2);
                continue;
            }

            auto eq_pos = line.find('=');
            if (eq_pos == std::string::npos) continue;

            std::string key = trim(line.substr(0, eq_pos));
            std::string value = trim(line.substr(eq_pos + 1));

            if (!current_section.empty()) {
                key = current_section + "." + key;
            }

            values_[key] = value;
        }

        loaded_ = true;
        return Status::Success;
    }

    void set(const std::string& key, const std::string& value) {
        std::lock_guard<std::mutex> lock(mutex_);
        values_[key] = value;
    }

    std::string get_string(const std::string& key, const std::string& default_val = "") const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = values_.find(key);
        return (it != values_.end()) ? it->second : default_val;
    }

    int get_int(const std::string& key, int default_val = 0) const {
        std::string val = get_string(key);
        if (val.empty()) return default_val;
        try { return std::stoi(val); }
        catch (...) { return default_val; }
    }

    bool get_bool(const std::string& key, bool default_val = false) const {
        std::string val = get_string(key);
        if (val.empty()) return default_val;
        std::transform(val.begin(), val.end(), val.begin(), ::tolower);
        return val == "true" || val == "1" || val == "yes";
    }

    double get_double(const std::string& key, double default_val = 0.0) const {
        std::string val = get_string(key);
        if (val.empty()) return default_val;
        try { return std::stod(val); }
        catch (...) { return default_val; }
    }

    bool has(const std::string& key) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return values_.find(key) != values_.end();
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        values_.clear();
        loaded_ = false;
    }

    bool is_loaded() const { return loaded_; }

    /** Dump all config entries (for debugging) */
    std::string dump() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ostringstream oss;
        for (const auto& kv : values_) {
            oss << kv.first << " = " << kv.second << "\n";
        }
        return oss.str();
    }

private:
    Config() : loaded_(false) {}
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;

    static std::string trim(const std::string& s) {
        auto start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        auto end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }

    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::string> values_;
    bool loaded_;
};

}} // namespace phantom::utils

#endif // PHANTOM_CONFIG_H
