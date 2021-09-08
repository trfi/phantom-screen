#include <phantom/utils/config.h>
#include <phantom/utils/logger.h>

namespace phantom { namespace utils {

Status load_config(const std::string& path) {
    PHANTOM_INFO("Loading configuration from: " + path);
    Status result = Config::instance().load_file(path);
    if (result == Status::Success) {
        PHANTOM_INFO("Configuration loaded successfully");
        PHANTOM_DEBUG("Config dump:\n" + Config::instance().dump());
    } else {
        PHANTOM_ERROR("Failed to load configuration from: " + path);
    }
    return result;
}

void apply_default_config() {
    auto& cfg = Config::instance();

    // Core defaults
    cfg.set("core.hook_method", "iat");
    cfg.set("core.trampoline_size", "64");
    cfg.set("core.enable_watchdog", "true");

    // Capture defaults
    cfg.set("capture.scan_interval_ms", "1000");
    cfg.set("capture.auto_bypass", "false");
    cfg.set("capture.target_processes", "obs64.exe,obs32.exe,ShareX.exe");

    // Display defaults
    cfg.set("display.overlay_enabled", "false");
    cfg.set("display.cloak_method", "dwm");
    cfg.set("display.composition_bypass", "true");

    // Logging defaults
    cfg.set("logging.level", "info");
    cfg.set("logging.file", "");
    cfg.set("logging.console", "true");

    PHANTOM_DEBUG("Default configuration applied");
}

}} // namespace phantom::utils
