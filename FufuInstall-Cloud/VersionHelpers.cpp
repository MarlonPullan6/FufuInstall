#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include "FufuInstall.h"

std::wstring GetCurrentVersion() {
    if (!g_selectedVersion.empty()) return g_selectedVersion;
    for (const auto& v : g_versions) {
        if (_wcsicmp(v.channel.c_str(), L"Release") == 0 && !v.version.empty()) {
            return v.version;
        }
    }
    if (!g_versions.empty()) {
        return g_versions.front().version;
    }
    return kFallbackVersion;
}
