#pragma once

#include <windows.h>
#include <string>

struct DownloadProgress {
    unsigned long long totalBytes = 0;
    unsigned long long downloadedBytes = 0;
    double bytesPerSecond = 0.0;
    int percent = 0;
};

using DownloadProgressCallback = void(*)(const DownloadProgress& progress, void* userData);
using DownloadProgressTextCallback = void(*)(const std::wstring& text, void* userData);

// Synchronous download. Reports progress (percent + speed) via callback.
// Returns true on success.
bool DownloadFileWithProgressWinHttp(
    const std::wstring& url,
    const std::wstring& destinationPath,
    DownloadProgressCallback progressCallback,
    void* userData,
    std::wstring* outError);

// Same as above, but also reports a pre-formatted progress text suitable for LogMessage.
bool DownloadFileWithProgressWinHttp(
    const std::wstring& url,
    const std::wstring& destinationPath,
    DownloadProgressCallback progressCallback,
    DownloadProgressTextCallback progressTextCallback,
    void* userData,
    std::wstring* outError);
