#pragma once

/**
 * phantom-screen — Screen Capture Bypass & Protection Research Toolkit
 *
 * This toolkit is designed for security research purposes to study
 * screen capture mechanisms on Windows and methods to evade them.
 *
 * Copyright (c) 2021 BypassCore Labs
 * Licensed under the MIT License
 */

#ifndef PHANTOM_SCREEN_H
#define PHANTOM_SCREEN_H

#define PHANTOM_VERSION_MAJOR 1
#define PHANTOM_VERSION_MINOR 0
#define PHANTOM_VERSION_PATCH 0
#define PHANTOM_VERSION_STRING "1.0.0"

#ifdef PHANTOM_EXPORTS
    #define PHANTOM_API __declspec(dllexport)
#else
    #define PHANTOM_API __declspec(dllimport)
#endif

#include <Windows.h>
#include <cstdint>
#include <string>
#include <functional>
#include <memory>
#include <vector>

namespace phantom {

enum class Status : uint32_t {
    Success = 0,
    ErrorGeneric,
    ErrorInvalidParam,
    ErrorNotInitialized,
    ErrorAlreadyInitialized,
    ErrorHookFailed,
    ErrorMemoryAlloc,
    ErrorPrivilege,
    ErrorNotSupported,
    ErrorCaptureFailed,
};

inline const char* status_to_string(Status s) {
    switch (s) {
        case Status::Success:                return "Success";
        case Status::ErrorGeneric:           return "Generic error";
        case Status::ErrorInvalidParam:      return "Invalid parameter";
        case Status::ErrorNotInitialized:    return "Not initialized";
        case Status::ErrorAlreadyInitialized:return "Already initialized";
        case Status::ErrorHookFailed:        return "Hook installation failed";
        case Status::ErrorMemoryAlloc:       return "Memory allocation failed";
        case Status::ErrorPrivilege:         return "Insufficient privileges";
        case Status::ErrorNotSupported:      return "Operation not supported";
        case Status::ErrorCaptureFailed:     return "Capture operation failed";
        default:                             return "Unknown error";
    }
}

} // namespace phantom

#endif // PHANTOM_SCREEN_H
