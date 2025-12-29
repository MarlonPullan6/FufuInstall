#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include "Downloader.h"

#include <winhttp.h>
#include <vector>

#pragma comment(lib, "winhttp.lib")

static void ReportProgress(DownloadProgressCallback cb, void* user, const DownloadProgress& p) {
    if (cb) {
        cb(p, user);
    }
}

static std::wstring CrackHostAndPath(const std::wstring& url, std::wstring& host, std::wstring& path, INTERNET_SCHEME& scheme, INTERNET_PORT& port) {
    URL_COMPONENTS comp{};
    comp.dwStructSize = sizeof(comp);
    comp.dwSchemeLength = (DWORD)-1;
    comp.dwHostNameLength = (DWORD)-1;
    comp.dwUrlPathLength = (DWORD)-1;
    comp.dwExtraInfoLength = (DWORD)-1;

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &comp)) {
        return L"WinHttpCrackUrl failed";
    }

    scheme = (INTERNET_SCHEME)comp.nScheme;
    port = comp.nPort;

    host.assign(comp.lpszHostName, comp.dwHostNameLength);
    std::wstring urlPath(comp.lpszUrlPath ? comp.lpszUrlPath : L"", comp.dwUrlPathLength);
    std::wstring extra(comp.lpszExtraInfo ? comp.lpszExtraInfo : L"", comp.dwExtraInfoLength);
    path = urlPath + extra;

    return L"";
}

static bool QueryContentLength(HINTERNET hRequest, unsigned long long& outLen) {
    outLen = 0;
    DWORD size = sizeof(outLen);
    DWORD idx = WINHTTP_NO_HEADER_INDEX;
    if (WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &outLen,
        &size,
        &idx)) {
        return true;
    }
    return false;
}

static std::wstring FormatSpeedText(double bytesPerSec) {
    if (bytesPerSec <= 0.0) return L"0 B/s";
    double v = bytesPerSec;
    const wchar_t* units[] = { L"B/s", L"KB/s", L"MB/s", L"GB/s" };
    int idx = 0;
    while (v >= 1024.0 && idx < 3) {
        v /= 1024.0;
        ++idx;
    }
    wchar_t buf[64];
    swprintf_s(buf, L"%.2f %s", v, units[idx]);
    return buf;
}

static std::wstring FormatBytesText(unsigned long long bytes) {
    double v = (double)bytes;
    const wchar_t* units[] = { L"B", L"KB", L"MB", L"GB" };
    int idx = 0;
    while (v >= 1024.0 && idx < 3) {
        v /= 1024.0;
        ++idx;
    }
    wchar_t buf[64];
    swprintf_s(buf, L"%.2f %s", v, units[idx]);
    return buf;
}

static std::wstring MakeProgressBar(int percent, int width = 30) {
    if (percent < 0) percent = 0;
    if (percent > 100) percent = 100;

    int filled = (percent * width) / 100;
    if (filled < 0) filled = 0;
    if (filled > width) filled = width;

    std::wstring bar;
    bar.reserve((size_t)width);
    for (int i = 0; i < width; ++i) {
        bar.push_back(i < filled ? L'#' : L'.');
    }
    return bar;
}

static void EmitProgressText(DownloadProgressTextCallback cb, void* userData, const DownloadProgress& p) {
    if (!cb) return;

    std::wstring text = L"[" + MakeProgressBar(p.percent, 30) + L"] " + std::to_wstring(p.percent) + L"%";
    if (p.totalBytes > 0) {
        text += L" (" + FormatBytesText(p.downloadedBytes) + L" / " + FormatBytesText(p.totalBytes) + L")";
    }
    text += L"  " + FormatSpeedText(p.bytesPerSecond);

    cb(text, userData);
}

static std::wstring LastErrorToText(DWORD err) {
    if (err == 0) return L"0";
    wchar_t* msg = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD len = FormatMessageW(flags, nullptr, err, 0, (LPWSTR)&msg, 0, nullptr);
    std::wstring text = std::to_wstring(err);
    if (len && msg) {
        std::wstring m(msg, len);
        while (!m.empty() && (m.back() == L'\r' || m.back() == L'\n')) m.pop_back();
        text += L" (" + m + L")";
    }
    if (msg) LocalFree(msg);
    return text;
}

static void SetErr(std::wstring* outError, const std::wstring& msg) {
    if (outError) *outError = msg;
}

bool DownloadFileWithProgressWinHttp(
    const std::wstring& url,
    const std::wstring& destinationPath,
    DownloadProgressCallback progressCallback,
    void* userData,
    std::wstring* outError) {
    return DownloadFileWithProgressWinHttp(url, destinationPath, progressCallback, nullptr, userData, outError);
}

bool DownloadFileWithProgressWinHttp(
    const std::wstring& url,
    const std::wstring& destinationPath,
    DownloadProgressCallback progressCallback,
    DownloadProgressTextCallback progressTextCallback,
    void* userData,
    std::wstring* outError) {

    if (outError) *outError = L"";

    std::wstring host, path;
    INTERNET_SCHEME scheme = INTERNET_SCHEME_HTTP;
    INTERNET_PORT port = 0;
    if (const auto err = CrackHostAndPath(url, host, path, scheme, port); !err.empty()) {
        if (outError) *outError = err;
        return false;
    }

    HINTERNET hSession = WinHttpOpen(L"FufuInstaller/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        SetErr(outError, L"WinHttpOpen failed, GetLastError=" + LastErrorToText(GetLastError()));
        return false;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        SetErr(outError, L"WinHttpConnect failed, GetLastError=" + LastErrorToText(GetLastError()));
        return false;
    }

    DWORD flags = (scheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        SetErr(outError, L"WinHttpOpenRequest failed, GetLastError=" + LastErrorToText(GetLastError()));
        return false;
    }

    HANDLE hFile = INVALID_HANDLE_VALUE;
    bool ok = false;

    auto cleanup = [&]() {
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
        }
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        if (!ok) {
            DeleteFileW(destinationPath.c_str());
        }
    };

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, nullptr)) {
        SetErr(outError, L"WinHttpSendRequest/WinHttpReceiveResponse failed, GetLastError=" + LastErrorToText(GetLastError()));
        cleanup();
        return false;
    }

    unsigned long long totalLen = 0;
    QueryContentLength(hRequest, totalLen);

    hFile = CreateFileW(destinationPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        SetErr(outError, L"CreateFile failed, GetLastError=" + LastErrorToText(GetLastError()));
        cleanup();
        return false;
    }

    const DWORD kBufSize = 64 * 1024;
    std::vector<unsigned char> buffer(kBufSize);

    DownloadProgress prog{};
    prog.totalBytes = totalLen;

    ULONGLONG startTick = GetTickCount64();
    ULONGLONG lastReportTick = startTick;
    unsigned long long lastBytes = 0;

    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) {
            SetErr(outError, L"WinHttpQueryDataAvailable failed, GetLastError=" + LastErrorToText(GetLastError()));
            cleanup();
            return false;
        }
        if (avail == 0) {
            ok = true;
            break;
        }

        while (avail > 0) {
            DWORD toRead = (avail > kBufSize) ? kBufSize : avail;
            DWORD read = 0;
            if (!WinHttpReadData(hRequest, buffer.data(), toRead, &read)) {
                SetErr(outError, L"WinHttpReadData failed, GetLastError=" + LastErrorToText(GetLastError()));
                cleanup();
                return false;
            }
            if (read == 0) {
                ok = true;
                break;
            }

            DWORD written = 0;
            if (!WriteFile(hFile, buffer.data(), read, &written, nullptr) || written != read) {
                SetErr(outError, L"WriteFile failed, GetLastError=" + LastErrorToText(GetLastError()));
                cleanup();
                return false;
            }

            prog.downloadedBytes += written;
            if (prog.totalBytes > 0) {
                prog.percent = (int)((prog.downloadedBytes * 100ULL) / prog.totalBytes);
                if (prog.percent > 100) prog.percent = 100;
            }

            ULONGLONG nowTick = GetTickCount64();
            ULONGLONG sinceLastMs = nowTick - lastReportTick;
            if (sinceLastMs >= 250) {
                double dt = (double)sinceLastMs / 1000.0;
                unsigned long long dBytes = prog.downloadedBytes - lastBytes;
                prog.bytesPerSecond = dt > 0.0 ? (double)dBytes / dt : 0.0;

                lastReportTick = nowTick;
                lastBytes = prog.downloadedBytes;

                ReportProgress(progressCallback, userData, prog);
                EmitProgressText(progressTextCallback, userData, prog);
            }

            avail -= read;
        }
    }

    // final report
    {
        ULONGLONG nowTick = GetTickCount64();
        double totalTime = (double)(nowTick - startTick) / 1000.0;
        prog.bytesPerSecond = totalTime > 0.0 ? (double)prog.downloadedBytes / totalTime : prog.bytesPerSecond;
        prog.percent = (prog.totalBytes > 0) ? 100 : prog.percent;
        ReportProgress(progressCallback, userData, prog);
        EmitProgressText(progressTextCallback, userData, prog);
    }

    cleanup();
    return ok;
}
