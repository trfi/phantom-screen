#include <phantom/utils/logger.h>

namespace phantom { namespace utils {

// Logger is header-only with inline singleton, but we provide
// explicit template instantiation and any non-inline helpers here.

void init_logging(LogLevel level, const std::string& log_file) {
    Logger::instance().set_level(level);
    Logger::instance().set_console(true);
    if (!log_file.empty()) {
        Logger::instance().set_file(log_file);
    }
    PHANTOM_INFO("phantom-screen logging initialized (level=" +
                 std::string(log_level_str(level)) + ")");
}

void shutdown_logging() {
    PHANTOM_INFO("phantom-screen logging shutting down");
    Logger::instance().set_level(LogLevel::Off);
}

}} // namespace phantom::utils
