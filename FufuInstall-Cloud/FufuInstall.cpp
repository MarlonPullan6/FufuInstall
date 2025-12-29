#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <shobjidl.h>
#include <urlmon.h>
#include <winhttp.h>
#include <cwchar>
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <cctype>
#include "Globals.h"
#include "resource.h"
#include "FufuInstall.h"
#include "EnvChecks.h"
#include "uninstaller.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ============================================================================
// 版本/下载辅助函数实现
// ============================================================================

bool RunCommandCapture(const std::wstring& commandLine, std::string& output, DWORD* exitCode) {

    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        return false;
    }
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {};
    std::wstring cmd = L"cmd.exe /c " + commandLine;
    BOOL created = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(hWrite);

    if (!created) {
        CloseHandle(hRead);
        return false;
    }

    char buf[512];
    DWORD read = 0;
    while (ReadFile(hRead, buf, sizeof(buf) - 1, &read, nullptr) && read > 0) {
        buf[read] = '\0';
        output.append(buf, buf + read);
    }
    CloseHandle(hRead);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    if (exitCode) {
        *exitCode = code;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

static std::wstring ToWide(const std::string& input) {
    UINT codePage = CP_UTF8;
    int len = MultiByteToWideChar(codePage, 0, input.c_str(), -1, nullptr, 0);
    if (len <= 0) {
        codePage = CP_ACP;
        len = MultiByteToWideChar(codePage, 0, input.c_str(), -1, nullptr, 0);
    }
    if (len <= 0) return L"";

    std::wstring result(len, 0);
    MultiByteToWideChar(codePage, 0, input.c_str(), -1, &result[0], len);
    if (!result.empty() && result.back() == L'\0') result.pop_back();
    return result;
}

static std::string TrimString(const std::string& s) {
    auto start = std::find_if_not(s.begin(), s.end(), [](unsigned char c) { return std::isspace(c); });
    auto end = std::find_if_not(s.rbegin(), s.rend(), [](unsigned char c) { return std::isspace(c); }).base();
    if (start >= end) return "";
    return std::string(start, end);
}

static std::string ExtractJsonString(const std::string& json, const std::string& key, size_t startPos) {
    std::string token = "\"" + key + "\"";
    size_t keyPos = json.find(token, startPos);
    if (keyPos == std::string::npos) return "";
    size_t colon = json.find(':', keyPos + token.size());
    if (colon == std::string::npos) return "";
    size_t firstQuote = json.find('"', colon + 1);
    if (firstQuote == std::string::npos) return "";
    size_t secondQuote = json.find('"', firstQuote + 1);
    if (secondQuote == std::string::npos || secondQuote <= firstQuote + 1) return "";
    return json.substr(firstQuote + 1, secondQuote - firstQuote - 1);
}

bool HttpGet(const std::wstring& url, std::string& response) {
    response.clear();

    URL_COMPONENTS comp{};
    comp.dwStructSize = sizeof(comp);
    comp.dwSchemeLength = (DWORD)-1;
    comp.dwHostNameLength = (DWORD)-1;
    comp.dwUrlPathLength = (DWORD)-1;
    comp.dwExtraInfoLength = (DWORD)-1;

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &comp)) {
        LogMessage(L"无法解析URL: " + url);
        return false;
    }

    std::wstring host(comp.lpszHostName, comp.dwHostNameLength);
    std::wstring path(comp.lpszUrlPath ? comp.lpszUrlPath : L"", comp.dwUrlPathLength);
    std::wstring extra(comp.lpszExtraInfo ? comp.lpszExtraInfo : L"", comp.dwExtraInfoLength);
    std::wstring fullPath = path + extra;

    HINTERNET hSession = WinHttpOpen(L"FufuInstaller/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), comp.nPort, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD flags = (comp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", fullPath.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    bool ok = false;
    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD size = 0;
        ok = true;
        do {
            if (!WinHttpQueryDataAvailable(hRequest, &size)) {
                ok = false;
                break;
            }
            if (size == 0) break;
            std::vector<char> buffer(size);
            DWORD downloaded = 0;
            if (!WinHttpReadData(hRequest, buffer.data(), size, &downloaded)) {
                ok = false;
                break;
            }
            response.append(buffer.data(), buffer.data() + downloaded);
        } while (size > 0);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return ok;
}

bool ParseVersionJson(const std::string& json, std::vector<VersionEntry>& outVersions) {
    outVersions.clear();

    size_t releasePos = json.find("\"Release\"");
    if (releasePos != std::string::npos) {
        std::string version = ExtractJsonString(json, "version", releasePos);
        std::string download = ExtractJsonString(json, "Download", releasePos);
        if (!version.empty() && !download.empty()) {
            outVersions.push_back({ L"Release", ToWide(version), ToWide(download), L"", false });
        }
    }

    size_t previewPos = json.find("\"Preview\"");
    if (previewPos != std::string::npos) {
        size_t arrayStart = json.find('[', previewPos);
        size_t arrayEnd = json.find(']', arrayStart == std::string::npos ? previewPos : arrayStart);
        size_t pos = arrayStart;
        while (pos != std::string::npos && (arrayEnd == std::string::npos || pos < arrayEnd)) {
            size_t verKey = json.find("\"version\"", pos);
            if (verKey == std::string::npos || (arrayEnd != std::string::npos && verKey > arrayEnd)) break;
            std::string version = ExtractJsonString(json, "version", verKey);
            size_t dlKey = json.find("\"Download\"", verKey);
            if (dlKey == std::string::npos || (arrayEnd != std::string::npos && dlKey > arrayEnd)) break;
            std::string download = ExtractJsonString(json, "Download", dlKey);
            if (!version.empty() && !download.empty()) {
                outVersions.push_back({ L"Preview", ToWide(version), ToWide(download), L"", false });
            }
            pos = dlKey + 1;
        }
    }

    return !outVersions.empty();
}

bool LoadVersionList() {
    if (g_versionsLoaded) {
        return true;
    }

    g_versions.clear();
    std::string json;
    if (!HttpGet(kVersionApiUrl, json)) {
        LogMessage(L"无法获取版本列表: 网络请求失败");
        return false;
    }

    std::vector<VersionEntry> parsed;
    if (!ParseVersionJson(json, parsed)) {
        LogMessage(L"解析版本列表失败");
        return false;
    }

    g_versions = parsed;
    g_versionsLoaded = true;

    // 预先获取所有版本的文件信息（只调用一次curl）
    for (auto& v : g_versions) {
        std::wstring fileInfo;
        if (FetchFileInfo(v.downloadUrl, fileInfo)) {
            v.fileInfo = fileInfo;
            v.fileInfoFetched = true;
        }
    }

    PopulateVersionTabs();
    return true;
}

void PopulateVersionTabs() {
    if (!g_hVersionTab) return;

    // 清除现有选项卡
    SendMessageW(g_hVersionTab, LB_RESETCONTENT, 0, 0);

    // 按频道分组添加选项卡
    std::vector<std::wstring> channels;
    for (const auto& v : g_versions) {
        bool found = false;
        for (const auto& ch : channels) {
            if (_wcsicmp(ch.c_str(), v.channel.c_str()) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            channels.push_back(v.channel);
        }
    }

    // 为每个频道创建选项卡，显示频道名和版本号
    for (const auto& channel : channels) {
        // 查找该频道的第一个版本
        for (size_t i = 0; i < g_versions.size(); ++i) {
            const auto& v = g_versions[i];
            if (_wcsicmp(v.channel.c_str(), channel.c_str()) == 0) {
                std::wstring tabText = channel + L" " + v.version;

                int index = (int)SendMessageW(g_hVersionTab, LB_ADDSTRING, 0, (LPARAM)tabText.c_str());
                SendMessageW(g_hVersionTab, LB_SETITEMDATA, index, (LPARAM)i);

                break; // 每个频道只添加一个选项卡（第一个版本）
            }
        }
    }

    // 选中第一个选项卡
    if (SendMessageW(g_hVersionTab, LB_GETCOUNT, 0, 0) > 0) {
        SendMessageW(g_hVersionTab, LB_SETCURSEL, 0, 0);
        OnVersionTabSelected();
    }
}

void OnVersionTabSelected() {
    if (!g_hVersionTab) return;

    int sel = (int)SendMessageW(g_hVersionTab, LB_GETCURSEL, 0, 0);
    if (sel == LB_ERR) return;

    size_t idx = (size_t)SendMessageW(g_hVersionTab, LB_GETITEMDATA, sel, 0);
    if (idx >= g_versions.size()) return;

    auto& v = g_versions[idx];
    g_selectedVersion = v.version;
    g_selectedDownloadUrl = v.downloadUrl;
    g_selectedChannel = v.channel;

    std::wstring info = L"将安装版本: " + v.channel + L" " + v.version;

    // 使用缓存的文件信息，不再重复调用curl
    if (!v.fileInfo.empty()) {
        info += L"\r\n" + v.fileInfo;
    }
    SetWindowTextW(g_hFileInfoLabel, info.c_str());

    ApplyInstallPath(GetInstallRoot(g_installPath), true);
}

bool FetchFileInfo(const std::wstring& url, std::wstring& outInfo) {
    outInfo.clear();
    std::wstring cmd = L"curl.exe -I \"" + url + L"\"";
    std::string output;
    DWORD exitCode = 0;
    if (!RunCommandCapture(cmd, output, &exitCode) || exitCode != 0) {
        LogMessage(L"获取文件信息失败");
        return false;
    }

    std::string lower = output;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return (char)std::tolower(c); });

    auto extractHeader = [&](const std::string& header) {
        std::string headerLower = header;
        std::transform(headerLower.begin(), headerLower.end(), headerLower.begin(), [](unsigned char c) { return (char)std::tolower(c); });
        size_t pos = lower.find(headerLower + ":");
        if (pos == std::string::npos) return std::string();
        size_t start = pos + headerLower.size() + 1;
        size_t end = output.find('\n', start);
        std::string raw = output.substr(start, end == std::string::npos ? std::string::npos : end - start);
        return TrimString(raw);
        };

    std::string lengthStr = extractHeader("Content-Length");
    std::string lastModified = extractHeader("Last-Modified");
    std::string acceptRanges = extractHeader("Accept-Ranges");

    std::wstring sizeText = lengthStr.empty() ? L"未知大小" : FormatSizeFromLength(ToWide(lengthStr));
    std::wstring lastText = lastModified.empty() ? L"未知" : ToWide(lastModified);
    std::wstring acceptWide = ToWide(acceptRanges);
    std::wstring resumeText = (!acceptRanges.empty() && _wcsicmp(acceptWide.c_str(), L"bytes") == 0) ? L"支持" : L"不确定";

    outInfo = L"文件大小: " + sizeText +
        L"\r\n最后修改时间: " + lastText +
        L"\r\n断点续传: " + resumeText;
    LogMessage(outInfo);
    return true;
}

std::wstring FormatSizeFromLength(const std::wstring& lengthStr) {
    wchar_t* endPtr = nullptr;
    unsigned long long size = wcstoull(lengthStr.c_str(), &endPtr, 10);

    if (size == 0) return L"未知大小";

    double value = static_cast<double>(size);
    const wchar_t* units[] = { L"B", L"KB", L"MB", L"GB" };
    int unitIdx = 0;
    while (value >= 1024.0 && unitIdx < 3) {
        value /= 1024.0;
        ++unitIdx;
    }

    wchar_t buf[64];
    swprintf_s(buf, L"%.2f %s", value, units[unitIdx]);
    return buf;
}

bool ExecutePowerShellWithLog(const std::wstring& command) {
    LogMessage(L"执行 PowerShell: " + command);

    SECURITY_ATTRIBUTES sa{ sizeof(sa) };
    HANDLE hRead = nullptr;
    HANDLE hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        LogMessage(L"无法创建管道以捕获 PowerShell 输出。错误码: " + std::to_wstring(GetLastError()));
        return false;
    }

    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{ sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};
    std::wstring pwshCmd = L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"& {" + command + L"}\"";

    BOOL created = CreateProcessW(nullptr, pwshCmd.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);

    CloseHandle(hWrite);

    if (!created) {
        DWORD errCode = GetLastError();
        CloseHandle(hRead);
        LogMessage(L"启动 PowerShell 失败: " + std::to_wstring(errCode));
        return false;
    }

    std::string output;
    char buffer[256];
    DWORD bytesRead = 0;
    while (ReadFile(hRead, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
        output.append(buffer, bytesRead);
    }

    CloseHandle(hRead);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    std::wstring outputWide = ToWide(output);
    if (!outputWide.empty()) {
        LogMessage(L"PowerShell 输出:\n" + outputWide);
    }

    if (exitCode != 0) {
        LogMessage(L"PowerShell 命令退出代码: " + std::to_wstring(exitCode));
    }

    return exitCode == 0;
}

bool DownloadSelectedVersion(std::wstring& outFilePath) {
    if (g_selectedDownloadUrl.empty()) {
        LogMessage(L"未选择下载地址");
        return false;
    }

    std::wstring fileName = ExtractFileNameFromUrl(g_selectedDownloadUrl);
    if (fileName.empty()) {
        LogMessage(L"无法解析下载文件名");
        return false;
    }

    CreateDirectoryW(kDownloadBaseDir.c_str(), nullptr);
    std::wstring dest = kDownloadBaseDir + L"\\" + fileName;
    HRESULT hr = URLDownloadToFileW(nullptr, g_selectedDownloadUrl.c_str(), dest.c_str(), 0, nullptr);
    if (FAILED(hr)) {
        LogMessage(L"下载失败，HRESULT=" + std::to_wstring(hr));
        return false;
    }

    LogMessage(L"下载完成: " + dest);
    outFilePath = dest;
    return true;
}

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

std::wstring ExtractFileNameFromUrl(const std::wstring& url) {
    if (url.empty()) return L"";
    size_t lastSlash = url.find_last_of(L"/\\");
    if (lastSlash == std::wstring::npos) return url;
    std::wstring fileName = url.substr(lastSlash + 1);
    // Remove query string if present
    size_t queryPos = fileName.find(L'?');
    if (queryPos != std::wstring::npos) {
        fileName = fileName.substr(0, queryPos);
    }
    return fileName;
}

// ============================================================================
// 辅助函数实现 - 日志相关
// ============================================================================

// 写入日志消息到UI和日志文件
void LogMessage(const std::wstring& message) {
    // 获取当前时间戳
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t timeStamp[64];
    swprintf_s(timeStamp, L"[%04d-%02d-%02d %02d:%02d:%02d] ",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    std::wstring fullMessage = timeStamp + message + L"\r\n";

    // 追加到日志编辑框
    if (g_hLogEdit != nullptr) {
        int len = GetWindowTextLengthW(g_hLogEdit);
        SendMessageW(g_hLogEdit, EM_SETSEL, len, len);
        SendMessageW(g_hLogEdit, EM_REPLACESEL, FALSE, (LPARAM)fullMessage.c_str());
        SendMessageW(g_hLogEdit, EM_SCROLLCARET, 0, 0);
    }
}

// ============================================================================
// 辅助函数实现 - 资源释放
// ============================================================================

bool DeleteFileIfExists(const std::wstring& path) {
    if (path.empty()) return true;

    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return true; // 文件不存在，无需处理
    }

    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        return true; // 非本函数的职责，略过目录
    }

    if (DeleteFileW(path.c_str())) {
        LogMessage(L"已删除文件: " + path);
        return true;
    }

    DWORD err = GetLastError();
    LogMessage(L"删除文件失败: " + path + L"，错误码=" + std::to_wstring(err));
    return false;
}

void CleanupTemporaryFiles() {
    LogMessage(L"清理临时文件俸...");

    // 清理释放的 7z 工具
    DeleteFileIfExists(g_tempPath + L"\\7z.exe");
    DeleteFileIfExists(g_tempPath + L"\\7z.dll");

    // 清理已下载的安装包
    if (!g_downloadedFilePath.empty()) {
        DeleteFileIfExists(g_downloadedFilePath);
    }
}

// 从EXE资源段释放文件到磁盘
bool ExtractResourceToFile(UINT resourceId, LPCWSTR resourceType, const std::wstring& filePath) {
    HRSRC hRes = FindResourceW(g_hInstance, MAKEINTRESOURCEW(resourceId), resourceType);
    if (!hRes) {
        LogMessage(L"错误: 无法找到资源 ID=" + std::to_wstring(resourceId));
        return false;
    }

    HGLOBAL hResData = LoadResource(g_hInstance, hRes);
    if (!hResData) {
        LogMessage(L"错误: 无法加载资源 ID=" + std::to_wstring(resourceId));
        return false;
    }

    LPVOID pData = LockResource(hResData);
    DWORD size = SizeofResource(g_hInstance, hRes);

    if (!pData || size == 0) {
        LogMessage(L"错误: 资源数据无效 ID=" + std::to_wstring(resourceId));
        return false;
    }

    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        LogMessage(L"错误: 无法创建文件 " + filePath);
        return false;
    }

    DWORD written;
    BOOL result = WriteFile(hFile, pData, size, &written, nullptr);
    CloseHandle(hFile);

    if (!result || written != size) {
        LogMessage(L"错误: 写入文件失败 " + filePath);
        return false;
    }

    LogMessage(L"已释放资源到: " + filePath);
    return true;
}

// ============================================================================
// 辅助函数实现 - 7z解压
// ============================================================================

// 调用7z.exe解压压缩包
bool Extract7zArchive(const std::wstring& archivePath, const std::wstring& destPath) {
    // 构建7z.exe路径
    std::wstring exe7z = g_tempPath + L"\\7z.exe";

    // 检查7z.exe是否存在
    if (GetFileAttributesW(exe7z.c_str()) == INVALID_FILE_ATTRIBUTES) {
        LogMessage(L"错误: 7z.exe不存在于 " + exe7z);
        return false;
    }

    // 构建命令行参数: x "archivePath" -o"destPath" -y
    std::wstring params = L"x \"" + archivePath + L"\" -o\"" + destPath + L"\" -y";

    LogMessage(L"开始解压: " + archivePath);
    LogMessage(L"目标目录: " + destPath);

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sei.hwnd = g_hMainWnd;
    sei.lpVerb = L"open";
    sei.lpFile = exe7z.c_str();
    sei.lpParameters = params.c_str();
    sei.lpDirectory = g_tempPath.c_str();
    sei.nShow = SW_HIDE;

    if (!ShellExecuteExW(&sei)) {
        LogMessage(L"错误: 无法启动7z.exe");
        return false;
    }

    // 等待解压完成
    WaitForSingleObject(sei.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(sei.hProcess, &exitCode);
    CloseHandle(sei.hProcess);

    if (exitCode != 0) {
        LogMessage(L"错误: 7z.exe返回错误代码 " + std::to_wstring(exitCode));
        return false;
    }

    LogMessage(L"解压完成");
    return true;
}

// ============================================================================
// 辅助函数实现 - VC++ 14 runtime check/install
// ============================================================================

bool CheckVCRuntime() {
    LogMessage(L"检查 VC++14 运行时...");

    // 使用 winget install 检查/安装 VC++ 运行时（如果未安装会开始安装）
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE hReadPipe = nullptr, hWritePipe = nullptr;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        LogMessage(L"错误: 创建管道失败，无法使用 winget 检测 VC++ 运行时");
        return false;
    }

    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {};
    // 使用 cmd.exe /c 来调用 winget install；加上非交互参数以避免提示
    wchar_t cmdLine[] = L"cmd.exe /c winget install --id Microsoft.VCRedist.2015+.x64 --source winget --accept-source-agreements --accept-package-agreements --silent";

    BOOL created = CreateProcessW(nullptr, cmdLine, nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);

    // 关闭写端句柄以便读取输出
    CloseHandle(hWritePipe);

    if (!created) {
        CloseHandle(hReadPipe);
        LogMessage(L"winget 调用失败或未安装。");
        return false;
    }

    // 读取输出
    std::string output;
    char buffer[512];
    DWORD bytesRead = 0;
    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        output += buffer;
    }

    CloseHandle(hReadPipe);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // 将输出转为宽字符串以记录日志并用于中文匹配
    auto ConvertToWide = [&](UINT codePage) {
        int len = MultiByteToWideChar(codePage, 0, output.c_str(), -1, nullptr, 0);
        if (len <= 0) return std::wstring();
        std::wstring tmp(len, 0);
        MultiByteToWideChar(codePage, 0, output.c_str(), -1, &tmp[0], len);
        return tmp;
        };

    // winget 输出通常为 UTF-8，失败时回退到控制台代码页
    std::wstring wout = ConvertToWide(CP_UTF8);
    if (wout.empty()) {
        wout = ConvertToWide(CP_OEMCP);
    }

    LogMessage(L"winget 输出: " + wout);

    // 如果 exitCode==0 则判断为成功
    if (exitCode == 0) {
        LogMessage(L"检测到或成功安装 VC++ 运行时 (winget 返回 0)");
        return true;
    }

    // 即使 exitCode 非零，也解析输出内容判断是否表示已安装或已是最新
    // 检查中文提示
    if (wout.find(L"找到已安装的现有包") != std::wstring::npos ||
        wout.find(L"正在尝试升级已安装的包") != std::wstring::npos ||
        wout.find(L"找不到可用的升级") != std::wstring::npos ||
        wout.find(L"没有可用的较新的包版本") != std::wstring::npos ||
        wout.find(L"已安装") != std::wstring::npos) {
        LogMessage(L"winget 输出表明包已安装或为最新，视为已安装");
        return true;
    }

    // 检查英文提示（小写比较)
    std::string outLower = output;
    for (auto& c : outLower) c = (char)tolower((unsigned char)c);

    if (outLower.find("already installed") != std::string::npos ||
        outLower.find("no applicable upgrade") != std::string::npos ||
        outLower.find("no available upgrade") != std::string::npos ||
        outLower.find("no newer package versions") != std::string::npos ||
        outLower.find("installed") != std::string::npos) {
        LogMessage(L"winget 输出（英文）表明包已安装或为最新，视为已安装");
        return true;
    }

    LogMessage(L"未检测到 VC++ 运行时 (winget 返回非零 且 未在输出中识别到已安装/最新提示)");
    return false;
}

bool InstallVCRuntime() {
    int result = MessageBoxW(g_hMainWnd,
        L"未检测到 Visual C++ 2015-2022 (VC++14) 运行时，是否自动使用 winget 安装？\n\n点击[是]将使用 winget 自动安装\n点击[否]将显示手动安装说明",
        L"缺少依赖项", MB_YESNO | MB_ICONQUESTION);

    if (result == IDYES) {
        LogMessage(L"正在通过 winget 安装 VC++ 运行时...");
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.hwnd = g_hMainWnd;
        sei.lpVerb = L"runas";
        sei.lpFile = L"cmd.exe";
        sei.lpParameters = L"/c winget install --id Microsoft.VCRedist.2015+.x64 --source winget --interactive";
        sei.nShow = SW_SHOW;

        if (ShellExecuteExW(&sei)) {
            WaitForSingleObject(sei.hProcess, INFINITE);
            DWORD exitCode = 0;
            GetExitCodeProcess(sei.hProcess, &exitCode);
            CloseHandle(sei.hProcess);
            LogMessage(L"winget 安装 VC++ 运行时完成，退出代码: " + std::to_wstring(exitCode));

            // 如果安装成功，标记需要重启（但不要立刻弹窗），将在所有安装完成后提示
            if (exitCode == 0) {
                g_needsReboot = true;
                LogMessage(L"VC++ 运行时安装成功，标记为需要重启");
                return true;
            }
        }
        else {
            LogMessage(L"错误: 无法启动 winget 安装 VC++ 运行时");
            return false;
        }
    }
    else {
        MessageBoxW(g_hMainWnd,
            L"请在管理员命令提示符中运行以下命令安装 Visual C++ 2015-2022 运行时:\n\nwinget install --id Microsoft.VCRedist.2015+.x64 --interactive",
            L"手动安装说明", MB_OK | MB_ICONINFORMATION);
        return false;
    }
}

// ============================================================================
// 辅助函数实现 - 安装路径处理
// ============================================================================

std::wstring TrimTrailingSeparators(const std::wstring& path) {
    std::wstring result = path;
    while (!result.empty() && (result.back() == L'\\' || result.back() == L'/')) {
        result.pop_back();
    }
    return result;
}

bool EndsWithInsensitive(const std::wstring& value, const std::wstring& suffix) {
    if (value.length() < suffix.length()) {
        return false;
    }
    return _wcsnicmp(value.c_str() + value.length() - suffix.length(), suffix.c_str(), suffix.length()) == 0;
}

std::wstring EnsureInstallPathFormat(const std::wstring& basePath) {
    std::wstring cleanedBase = TrimTrailingSeparators(basePath.empty() ? g_defaultBasePath : basePath);

    if (cleanedBase.find(L"\\" + kAppFolderName) == std::wstring::npos &&
        cleanedBase.find(L"/" + kAppFolderName) == std::wstring::npos) {
        cleanedBase += L"\\" + kAppFolderName;
    }

    std::wstring versionSuffix = L"\\" + GetCurrentVersion();
    if (!EndsWithInsensitive(cleanedBase, versionSuffix)) {
        cleanedBase += versionSuffix;
    }

    return cleanedBase;
}

std::wstring GetInstallRoot(const std::wstring& installPath) {
    std::wstring trimmed = TrimTrailingSeparators(installPath);
    size_t pos = trimmed.find_last_of(L"\\/");

    if (pos == std::wstring::npos) {
        return trimmed;
    }

    return trimmed.substr(0, pos);
}

void ApplyInstallPath(const std::wstring& basePath, bool updateEditControl) {
    g_installPath = EnsureInstallPathFormat(basePath);
    g_tempPath = GetInstallRoot(g_installPath);

    if (updateEditControl && g_hPathEdit) {
        SetWindowTextW(g_hPathEdit, g_installPath.c_str());
    }
}

// ============================================================================
// 辅助函数实现 - 创建桌面快捷方式
// ============================================================================

bool CreateDesktopShortcut() {
    if (g_installPath.empty()) {
        LogMessage(L"错误: 安装路径为空，无法创建快捷方式");
        return false;
    }

    std::wstring targetPath = TrimTrailingSeparators(g_installPath) + L"\\FufuLauncher.exe";
    if (GetFileAttributesW(targetPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        LogMessage(L"错误: 未找到目标可执行文件 " + targetPath);
        return false;
    }

    PWSTR desktopPath = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_Desktop, 0, nullptr, &desktopPath))) {
        LogMessage(L"错误: 无法获取桌面目录，无法创建快捷方式");
        return false;
    }

    std::wstring shortcutPath = desktopPath;
    CoTaskMemFree(desktopPath);

    if (shortcutPath.empty()) {
        LogMessage(L"错误: 桌面目录路径为空");
        return false;
    }

    if (shortcutPath.back() != L'\\' && shortcutPath.back() != L'/') {
        shortcutPath += L"\\";
    }
    shortcutPath += L"芙芙启动器.lnk";

    LogMessage(L"创建桌面快捷方式: " + shortcutPath);

    IShellLinkW* shellLink = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&shellLink);
    if (FAILED(hr) || shellLink == nullptr) {
        LogMessage(L"错误: 无法创建 ShellLink 实例");
        return false;
    }

    shellLink->SetPath(targetPath.c_str());
    shellLink->SetWorkingDirectory(g_installPath.c_str());
    shellLink->SetDescription(L"芙芙启动器");

    IPersistFile* persistFile = nullptr;
    hr = shellLink->QueryInterface(IID_IPersistFile, (void**)&persistFile);
    if (FAILED(hr) || persistFile == nullptr) {
        LogMessage(L"错误: 无法获取 IPersistFile 接口以保存快捷方式");
        shellLink->Release();
        return false;
    }

    hr = persistFile->Save(shortcutPath.c_str(), TRUE);
    persistFile->Release();
    shellLink->Release();

    if (FAILED(hr)) {
        LogMessage(L"错误: 保存快捷方式失败");
        return false;
    }

    LogMessage(L"已在桌面创建快捷方式: " + shortcutPath);
    return true;
}

// ============================================================================
// UI相关函数
// ============================================================================

void UpdateProgress(int percent) {
    int curPos = SendMessageW(g_hProgressBar, PBM_GETPOS, 0, 0);
    if (curPos == percent) return; // 仅在进度变化时更新

    if (g_hProgressBar) {
        SendMessageW(g_hProgressBar, PBM_SETPOS, percent, 0);
    }
    PostMessageW(g_hMainWnd, WM_UPDATE_PROGRESS, percent, 0);
}

// 更新导航按钮状态
void UpdateNavigationButtons() {
    switch (g_currentPage) {
    case PAGE_WELCOME:
        EnableWindow(g_hBackButton, FALSE);
        EnableWindow(g_hNextButton, TRUE);
        SetWindowTextW(g_hNextButton, L"下一步 >");
        ShowWindow(g_hCancelButton, SW_SHOW);
        break;
    case PAGE_LICENSE:
        EnableWindow(g_hBackButton, TRUE);
        EnableWindow(g_hNextButton, g_agreedToLicense);
        SetWindowTextW(g_hNextButton, L"下一步 >");
        ShowWindow(g_hCancelButton, SW_SHOW);
        break;
    case PAGE_LOCATION:
        EnableWindow(g_hBackButton, TRUE);
        EnableWindow(g_hNextButton, TRUE);
        SetWindowTextW(g_hNextButton, L"安装");
        ShowWindow(g_hCancelButton, SW_SHOW);
        break;
    case PAGE_PROGRESS:
        EnableWindow(g_hBackButton, FALSE);
        EnableWindow(g_hNextButton, FALSE);
        SetWindowTextW(g_hNextButton, L"安装中...");
        ShowWindow(g_hCancelButton, SW_HIDE);
        break;
    case PAGE_COMPLETE:
        EnableWindow(g_hBackButton, FALSE);
        EnableWindow(g_hNextButton, TRUE);
        SetWindowTextW(g_hNextButton, L"完成");
        ShowWindow(g_hCancelButton, SW_HIDE);
        break;
    }
}

// 显示指定页面
void ShowPage(int page) {
    g_currentPage = page;

    // 隐藏所有控件
    ShowWindow(g_hLicenseLink, SW_HIDE);
    ShowWindow(g_hLicenseCheck, SW_HIDE);
    ShowWindow(g_hPathEdit, SW_HIDE);
    ShowWindow(g_hBrowseButton, SW_HIDE);
    ShowWindow(g_hProgressBar, SW_HIDE);
    ShowWindow(g_hLogEdit, SW_HIDE);
    ShowWindow(g_hVersionLabel, SW_HIDE);
    ShowWindow(g_hVersionTab, SW_HIDE);
    ShowWindow(g_hFileInfoLabel, SW_HIDE);

    switch (page) {
    case PAGE_WELCOME:
        SetWindowTextW(g_hTitleLabel, L"欢迎使用 Fufu 安装向导");
        // 副标题文本在这里设置：要修改文本内容请在此处更改字符串；要修改副标题大小请参见 WM_CREATE 中 g_hNormalFont 的 CreateFontW 参数。
        SetWindowTextW(g_hSubtitleLabel, L"此向导将引导您完成 Fufu 的安装过程。\n\n请点击[下一步]继续。");
        break;
    case PAGE_LICENSE:
        SetWindowTextW(g_hTitleLabel, L"许可协议");
        SetWindowTextW(g_hSubtitleLabel, L"请阅读并同意以下许可协议以继续安装。");
        ShowWindow(g_hLicenseLink, SW_SHOW);
        ShowWindow(g_hLicenseCheck, SW_SHOW);
        break;
    case PAGE_LOCATION:
        SetWindowTextW(g_hTitleLabel, L"选择安装位置");
        SetWindowTextW(g_hSubtitleLabel, L"请选择要安装的版本，并指定安装目录:");
        ShowWindow(g_hVersionLabel, SW_SHOW);
        ShowWindow(g_hVersionTab, SW_SHOW);
        ShowWindow(g_hFileInfoLabel, SW_SHOW);
        ShowWindow(g_hPathEdit, SW_SHOW);
        ShowWindow(g_hBrowseButton, SW_SHOW);
        if (!g_versionsLoaded) {
            if (!LoadVersionList()) {
                SetWindowTextW(g_hFileInfoLabel, L"无法获取版本列表，请检查网络。\r\n");
            }
        }
        else {
            OnVersionTabSelected();
        }
        break;
    case PAGE_PROGRESS:
        SetWindowTextW(g_hTitleLabel, L"正在安装");
        SetWindowTextW(g_hSubtitleLabel, L"请稍候，正在配置和安装 Fufu...");
        ShowWindow(g_hProgressBar, SW_SHOW);
        ShowWindow(g_hLogEdit, SW_SHOW);
        SendMessageW(g_hProgressBar, PBM_SETPOS, 0, 0);
        SetWindowTextW(g_hLogEdit, L"");
        break;
    case PAGE_COMPLETE:
        if (g_installSuccess) {
            SetWindowTextW(g_hTitleLabel, L"安装完成");
            SetWindowTextW(g_hSubtitleLabel, L"Fufu 已成功安装！\n您可以在安装目录中启动程序。");
        }
        else {
            SetWindowTextW(g_hTitleLabel, L"安装失败");
            SetWindowTextW(g_hSubtitleLabel, L"安装过程中发生错误。\n请查看安装日志获取详细信息。");
        }
        ShowWindow(g_hLogEdit, SW_SHOW);

        if (g_hProgressBar) {
            ShowWindow(g_hProgressBar, SW_SHOW);
            SendMessageW(g_hProgressBar, PBM_SETPOS, 100, 0);
            InvalidateRect(g_hProgressBar, nullptr, TRUE);
            UpdateWindow(g_hProgressBar);
        }
        break;
    }

    // 重新布局导航按钮：完成页时靠右对齐，否则恢复默认位置
    RECT rcClient = {};
    if (g_hMainWnd) {
        GetClientRect(g_hMainWnd, &rcClient);

        if (page == PAGE_COMPLETE) {
            int xNext = rcClient.right - BUTTON_RIGHT_MARGIN - NEXT_WIDTH;
            int xBack = xNext - BUTTON_SPACING - BACK_WIDTH;

            MoveWindow(g_hBackButton, xBack, BUTTON_Y, BACK_WIDTH, BUTTON_HEIGHT, TRUE);
            MoveWindow(g_hNextButton, xNext, BUTTON_Y, NEXT_WIDTH, BUTTON_HEIGHT, TRUE);
            MoveWindow(g_hCancelButton, rcClient.right + 10, BUTTON_Y, CANCEL_WIDTH, BUTTON_HEIGHT, TRUE);
        }
        else if (page == PAGE_PROGRESS) {
            // 在安装进度页时也将“上一步”和“安装中...”按钮右对齐，以便与完成页保持一致
            int xNext = rcClient.right - BUTTON_RIGHT_MARGIN - NEXT_WIDTH;
            int xBack = xNext - BUTTON_SPACING - BACK_WIDTH;

            MoveWindow(g_hBackButton, xBack, BUTTON_Y, BACK_WIDTH, BUTTON_HEIGHT, TRUE);
            MoveWindow(g_hNextButton, xNext, BUTTON_Y, NEXT_WIDTH, BUTTON_HEIGHT, TRUE);
            // 隐藏取消按钮（放到窗口外）
            MoveWindow(g_hCancelButton, rcClient.right + 10, BUTTON_Y, CANCEL_WIDTH, BUTTON_HEIGHT, TRUE);
        }
        else {
            MoveWindow(g_hBackButton, BUTTON_DEFAULT_BACK_X, BUTTON_Y, BACK_WIDTH, BUTTON_HEIGHT, TRUE);
            MoveWindow(g_hNextButton, BUTTON_DEFAULT_NEXT_X, BUTTON_Y, NEXT_WIDTH, BUTTON_HEIGHT, TRUE);
            MoveWindow(g_hCancelButton, BUTTON_DEFAULT_CANCEL_X, BUTTON_Y, CANCEL_WIDTH, BUTTON_HEIGHT, TRUE);
        }
    }

    UpdateNavigationButtons();
    InvalidateRect(g_hMainWnd, nullptr, TRUE);
}

// ============================================================================
// 安装核心逻辑
// ============================================================================

// 准备安装目录
bool PrepareInstallDirectory() {
    LogMessage(L"准备安装目录...");

    // 获取用户选择的安装路径并补全目录结构
    wchar_t pathBuffer[MAX_PATH];
    GetWindowTextW(g_hPathEdit, pathBuffer, MAX_PATH);
    ApplyInstallPath(pathBuffer, true);

    if (g_installPath.empty()) {
        ApplyInstallPath(g_defaultBasePath, true);
    }

    LogMessage(L"安装路径: " + g_installPath);

    // 在准备安装前删除上一版本的安装目录
    if (!RemovePreviousInstall(g_installPath)) {
        LogMessage(L"错误: 无法删除之前的安装目录");
        return false;
    }

    // 创建基础目录和安装目录
    CreateDirectoryW(g_tempPath.c_str(), nullptr);
    if (!CreateDirectoryW(g_installPath.c_str(), nullptr)) {
        DWORD err = GetLastError();
        if (err != ERROR_ALREADY_EXISTS) {
            LogMessage(L"错误: 无法创建安装目录");
            return false;
        }
    }

    // 检查并清理旧的AppX目录
    std::wstring installDir = g_installPath + L"\\AppX";
    if (GetFileAttributesW(installDir.c_str()) != INVALID_FILE_ATTRIBUTES) {
        LogMessage(L"清理旧的安装文件...");

        std::wstring cmd = L"/c rd /s /q \"" + installDir + L"\"";

        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
        sei.lpVerb = L"open";
        sei.lpFile = L"cmd.exe";
        sei.lpParameters = cmd.c_str();
        sei.nShow = SW_HIDE;

        if (ShellExecuteExW(&sei)) {
            WaitForSingleObject(sei.hProcess, INFINITE);
            CloseHandle(sei.hProcess);
        }
    }

    return true;
}

// 后台安装线程
DWORD WINAPI PerformConfigurationThread(LPVOID lpParam) {
    bool success = true;
    std::wstring downloadedPath;

    // 阶段1: 准备安装目录 (10%)
    UpdateProgress(5);
    LogMessage(L"========== 开始安装 ==========");

    if (!PrepareInstallDirectory()) {
        success = false;
        goto cleanup;
    }
    UpdateProgress(10);

    // 阶段2: 下载并解压所选版本 (35%)
    LogMessage(L"准备下载所选版本...");

    // 释放 7z 工具
    ExtractResourceToFile(IDR_7ZEXE, L"BINARY", g_tempPath + L"\\7z.exe");
    ExtractResourceToFile(IDR_7ZDLL, L"BINARY", g_tempPath + L"\\7z.dll");

    if (!DownloadSelectedVersion(downloadedPath)) {
        success = false;
        goto cleanup;
    }
    g_downloadedFilePath = downloadedPath;
    UpdateProgress(25);

    LogMessage(L"开始解压下载的包...");
    if (!Extract7zArchive(downloadedPath, g_installPath)) {
        success = false;
        goto cleanup;
    }
    UpdateProgress(35);

    // 阶段3: 检查.NET 8 SDK (45%)
    LogMessage(L"检查.NET 8 SDK...");
    if (!CheckDotNet8SDK()) {
        if (!InstallDotNet8SDK()) {
            LogMessage(L"警告: .NET 8 SDK未安装，应用可能无法正常运行");
        }
    }
    UpdateProgress(45);

    // 新增阶段: 检查 VC++ 运行时 (55%)
    LogMessage(L"检查 VC++ 运行时...");
    if (!CheckVCRuntime()) {
        if (!InstallVCRuntime()) {
            LogMessage(L"警告: VC++ 运行时未安装，应用可能无法正常运行");
        }
    }
    UpdateProgress(55);

    // 阶段4: 安装WebView2 (65%)
    LogMessage(L"安装WebView2运行时...");
    if (!IsWebView2Installed()) {
        InstallWebview2();
    }
    else {
        LogMessage(L"跳过 WebView2 安装，已检测到运行时");
    }
    UpdateProgress(65);

     // 阶段6: 配置PowerShell执行策略 (82%)
     LogMessage(L"配置PowerShell执行策略...");
     ExecutePowerShellWithLog(L"Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned -Force");
     ExecutePowerShellWithLog(L"Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force");
     UpdateProgress(82);

     // 阶段8: 创建桌面快捷方式 (98%)
     CreateDesktopShortcut();
     UpdateProgress(98);

    if (success) {
        RecordInstallLocation(g_installPath);
    }

    LogMessage(L"========== 安装完成 ==========");
    UpdateProgress(100);

cleanup:
    g_installSuccess = success;

    // 清理临时文件
    CleanupTemporaryFiles();

    // 发送完成消息，wParam low bit = success, bit 8 = needs reboot
    WPARAM completionParam = (g_installSuccess ? 1 : 0) | (g_needsReboot ? (1 << 8) : 0);
    PostMessageW(g_hMainWnd, WM_CONFIGURATION_COMPLETE, completionParam, 0);

    return 0;
}

// ============================================================================
// 窗口过程函数
// ============================================================================

LRESULT CALLBACK WindowProcedure(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        // 创建字体
        // 标题字体：如需修改标题大小，请调整下面 CreateFontW 的第一个参数（高度），当前为24。
        g_hTitleFont = CreateFontW(28, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"微软雅黑");

        // 普通字体 / 副标题字体：副标题和大部分界面文字使用此字体。要修改这些文字的大小，请更改下面 CreateFontW 的第一个参数（高度），当前为14。
        g_hNormalFont = CreateFontW(18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"微软雅黑");

        // 创建标题标签
        g_hTitleLabel = CreateWindowExW(0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            20, 15, 520, 35, hwnd, (HMENU)IDC_TITLE_LABEL, g_hInstance, nullptr);
        SendMessageW(g_hTitleLabel, WM_SETFONT, (WPARAM)g_hTitleFont, TRUE);

        // 创建副标题标签
        g_hSubtitleLabel = CreateWindowExW(0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            20, 55, 520, 60, hwnd, (HMENU)IDC_SUBTITLE_LABEL, g_hInstance, nullptr);
        SendMessageW(g_hSubtitleLabel, WM_SETFONT, (WPARAM)g_hNormalFont, TRUE);

        // 创建许可协议链接
        g_hLicenseLink = CreateWindowExW(0, L"STATIC", L"<点击查看许可协议>",
            WS_CHILD | SS_NOTIFY | SS_LEFT,
            20, 125, 300, 25, hwnd, (HMENU)IDC_LICENSE_LINK, g_hInstance, nullptr);
        SendMessageW(g_hLicenseLink, WM_SETFONT, (WPARAM)g_hNormalFont, TRUE);

        // 创建许可协议复选框
        g_hLicenseCheck = CreateWindowExW(0, L"BUTTON", L"我已阅读并同意许可协议",
            WS_CHILD | BS_AUTOCHECKBOX,
            20, 155, 300, 25, hwnd, (HMENU)IDC_LICENSE_CHECK, g_hInstance, nullptr);
        SendMessageW(g_hLicenseCheck, WM_SETFONT, (WPARAM)g_hNormalFont, TRUE);

        // 创建安装路径编辑框
        g_hPathEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", g_installPath.c_str(),
            WS_CHILD | ES_AUTOHSCROLL,
            20, 285, 450, 25, hwnd, (HMENU)IDC_PATH_EDIT, g_hInstance, nullptr);
        SendMessageW(g_hPathEdit, WM_SETFONT, (WPARAM)g_hNormalFont, TRUE);

        // 创建浏览按钮
        g_hBrowseButton = CreateWindowExW(0, L"BUTTON", L"浏览...",
            WS_CHILD | BS_PUSHBUTTON,
            480, 285, 70, 28, hwnd, (HMENU)IDC_BROWSE_BUTTON, g_hInstance, nullptr);
        SendMessageW(g_hBrowseButton, WM_SETFONT, (WPARAM)g_hNormalFont, TRUE);

        // 创建版本列表框 (原版本选项卡控件)
        g_hVersionTab = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT,
            20, 115, 160, 120, hwnd, (HMENU)IDC_VERSION_TAB, g_hInstance, nullptr);
        SendMessageW(g_hVersionTab, WM_SETFONT, (WPARAM)g_hNormalFont, TRUE);

        // 创建文件信息标签（放在列表框右侧）
        g_hFileInfoLabel = CreateWindowExW(0, L"STATIC", L"",
            WS_CHILD | SS_LEFT,
            190, 115, 360, 120, hwnd, (HMENU)IDC_FILEINFO_LABEL, g_hInstance, nullptr);
        SendMessageW(g_hFileInfoLabel, WM_SETFONT, (WPARAM)g_hNormalFont, TRUE);

        // 创建进度条
        g_hProgressBar = CreateWindowExW(0, PROGRESS_CLASSW, L"",
            WS_CHILD | PBS_SMOOTH,
            20, 100, 530, 22, hwnd, (HMENU)IDC_PROGRESS_BAR, g_hInstance, nullptr);
        SendMessageW(g_hProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));

        // 创建日志编辑框
        g_hLogEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            20, 130, 530, 180, hwnd, (HMENU)IDC_LOG_EDIT, g_hInstance, nullptr);
        SendMessageW(g_hLogEdit, WM_SETFONT, (WPARAM)g_hNormalFont, TRUE);

        // 创建导航按钮
        g_hBackButton = CreateWindowExW(0, L"BUTTON", L"< 上一步",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            BUTTON_DEFAULT_BACK_X, BUTTON_Y, BACK_WIDTH, BUTTON_HEIGHT, hwnd, (HMENU)IDC_BACK_BUTTON, g_hInstance, nullptr);
        SendMessageW(g_hBackButton, WM_SETFONT, (WPARAM)g_hNormalFont, TRUE);

        g_hNextButton = CreateWindowExW(0, L"BUTTON", L"下一步 >",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            BUTTON_DEFAULT_NEXT_X, BUTTON_Y, NEXT_WIDTH, BUTTON_HEIGHT, hwnd, (HMENU)IDC_NEXT_BUTTON, g_hInstance, nullptr);
        SendMessageW(g_hNextButton, WM_SETFONT, (WPARAM)g_hNormalFont, TRUE);

        g_hCancelButton = CreateWindowExW(0, L"BUTTON", L"取消",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            BUTTON_DEFAULT_CANCEL_X, BUTTON_Y, CANCEL_WIDTH, BUTTON_HEIGHT, hwnd, (HMENU)IDC_CANCEL_BUTTON, g_hInstance, nullptr);
        SendMessageW(g_hCancelButton, WM_SETFONT, (WPARAM)g_hNormalFont, TRUE);

        // 显示欢迎页
        ShowPage(PAGE_WELCOME);
        return 0;
    }

    case WM_COMMAND: {
        int wmId = LOWORD(wParam);
        int wmEvent = HIWORD(wParam);

        switch (wmId) {
        case IDC_BACK_BUTTON: {
            // 上一步按钮点击
            if (g_currentPage == PAGE_LICENSE) {
                ShowPage(PAGE_WELCOME);
            }
            else if (g_currentPage == PAGE_LOCATION) {
                ShowPage(PAGE_LICENSE);
            }
            break;
        }

        case IDC_NEXT_BUTTON: {
            // 下一步按钮点击
            if (g_currentPage == PAGE_WELCOME) {
                ShowPage(PAGE_LICENSE);
            }
            else if (g_currentPage == PAGE_LICENSE) {
                ShowPage(PAGE_LOCATION);
            }
            else if (g_currentPage == PAGE_LOCATION) {
                if (!g_versionsLoaded && !LoadVersionList()) {
                    MessageBoxW(hwnd, L"无法获取版本列表，请检查网络后重试。", L"错误", MB_OK | MB_ICONERROR);
                    break;
                }
                if (g_selectedDownloadUrl.empty()) {
                    MessageBoxW(hwnd, L"请选择要安装的版本。", L"提示", MB_OK | MB_ICONINFORMATION);
                    break;
                }
                ShowPage(PAGE_PROGRESS);
                // 创建后台安装线程
                HANDLE hThread = CreateThread(nullptr, 0, PerformConfigurationThread, nullptr, 0, nullptr);
                if (hThread) {
                    CloseHandle(hThread);
                }
            }
            else if (g_currentPage == PAGE_COMPLETE) {
                PostQuitMessage(0);
            }
            break;
        }

        case IDC_CANCEL_BUTTON: {
            // 取消按钮点击
            if (g_currentPage != PAGE_PROGRESS) {
                if (MessageBoxW(hwnd, L"确定要取消安装吗？", L"取消安装",
                    MB_YESNO | MB_ICONQUESTION) == IDYES) {
                    PostQuitMessage(0);
                }
            }
            break;
        }

        case IDC_LICENSE_LINK: {
            // 许可协议链接点击
            if (wmEvent == STN_CLICKED) {
                ShellExecuteW(hwnd, L"open", L"https://philia093.cyou/",
                    nullptr, nullptr, SW_SHOWNORMAL);
            }
            break;
        }

        case IDC_LICENSE_CHECK: {
            // 许可协议复选框点击
            g_agreedToLicense = (SendMessageW(g_hLicenseCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
            UpdateNavigationButtons();
            break;
        }

        case IDC_BROWSE_BUTTON: {
            // 浏览按钮点击 - 使用文件夹选择对话框
            CoInitialize(nullptr);

            IFileOpenDialog* pFileOpen = nullptr;
            HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_ALL,
                IID_IFileOpenDialog, reinterpret_cast<void**>(&pFileOpen));

            if (SUCCEEDED(hr)) {
                DWORD dwOptions;
                pFileOpen->GetOptions(&dwOptions);
                pFileOpen->SetOptions(dwOptions | FOS_PICKFOLDERS);
                pFileOpen->SetTitle(L"选择安装目录");

                hr = pFileOpen->Show(hwnd);
                if (SUCCEEDED(hr)) {
                    IShellItem* pItem = nullptr;
                    hr = pFileOpen->GetResult(&pItem);
                    if (SUCCEEDED(hr)) {
                        PWSTR pszPath = nullptr;
                        hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszPath);
                        if (SUCCEEDED(hr)) {
                            ApplyInstallPath(pszPath, true);
                            CoTaskMemFree(pszPath);
                        }
                        pItem->Release();
                    }
                }
                pFileOpen->Release();
            }

            CoUninitialize();
            break;
        }

        case IDC_VERSION_TAB: {
            if (HIWORD(wParam) == LBN_SELCHANGE) {
                OnVersionTabSelected();
            }
            break;
        }
        }
        return 0;
    }

    case WM_NOTIFY: {
        return 0;
    }

    case WM_UPDATE_PROGRESS: {
        // 进度更新消息
        SendMessageW(g_hProgressBar, PBM_SETPOS, (int)wParam, 0);
        return 0;
    }

    case WM_CONFIGURATION_COMPLETE: {
        // 安装完成消息
        // wParam low bit = success, bit 8 = needs reboot
        g_installSuccess = ((wParam & 0x1) == 1);
        bool needsReboot = ((wParam & (1 << 8)) != 0);

        // 确保进度条显示完成状态并显示完成页面
        if (g_hProgressBar) {
            SendMessageW(g_hProgressBar, PBM_SETPOS, 100, 0);
            ShowWindow(g_hProgressBar, SW_SHOW);
        }
        ShowPage(PAGE_COMPLETE);

        // 如果需要重启，弹窗提示用户是否立即重启
        if (needsReboot) {
            int rebootChoice = MessageBoxW(g_hMainWnd,
                L"安装过程中需要重启电脑以完成某些组件的安装，您可以选择立即重启或稍后手动重启。",
                L"重启提示", MB_YESNO | MB_ICONQUESTION);

            if (rebootChoice == IDYES) {
                LogMessage(L"用户选择立即重启，正在执行重启...");
                SHELLEXECUTEINFOW seiShutdown = { sizeof(seiShutdown) };
                seiShutdown.fMask = SEE_MASK_NOCLOSEPROCESS;
                seiShutdown.hwnd = g_hMainWnd;
                seiShutdown.lpVerb = L"runas";
                seiShutdown.lpFile = L"shutdown.exe";
                seiShutdown.lpParameters = L"/r /t 0";
                seiShutdown.nShow = SW_SHOW;

                if (ShellExecuteExW(&seiShutdown)) {
                    WaitForSingleObject(seiShutdown.hProcess, 5000);
                    DWORD scExit = 0;
                    if (GetExitCodeProcess(seiShutdown.hProcess, &scExit)) {
                        LogMessage(L"shutdown.exe 返回代码: " + std::to_wstring(scExit));
                    }
                    CloseHandle(seiShutdown.hProcess);
                }
                else {
                    LogMessage(L"错误: 无法启动 shutdown.exe 来重启系统");
                }
            }
            else {
                LogMessage(L"用户选择稍后重启");
            }
        }

        return 0;
    }

    case WM_CTLCOLORSTATIC: {
        // 设置静态控件背景色
        HDC hdc = (HDC)wParam;
        SetBkMode(hdc, TRANSPARENT);

        // 许可协议链接设置为蓝色
        if ((HWND)lParam == g_hLicenseLink) {
            SetTextColor(hdc, RGB(0, 102, 204));
        }

        return (LRESULT)GetStockObject(WHITE_BRUSH);
    }

    case WM_DESTROY: {
        // 清理资源
        if (g_hTitleFont) DeleteObject(g_hTitleFont);
        if (g_hNormalFont) DeleteObject(g_hNormalFont);
        PostQuitMessage(0);
        return 0;
    }

    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    return 0;
}

// ============================================================================
// 程序入口点
// ============================================================================

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    g_hInstance = hInstance;

    // 隐藏控制台窗口
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    // 阶段1: 权限检查
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation{};
        DWORD size = sizeof(elevation);

        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            if (!elevation.TokenIsElevated) {
                CloseHandle(hToken);
                MessageBoxW(nullptr,
                    L"此安装程序需要管理员权限运行。\n\n请右键点击程序，选择[以管理员身份运行]。",
                    L"权限不足", MB_OK | MB_ICONERROR);
                return 1;
            }
        }
        CloseHandle(hToken);
    }

    // 阶段2: 初始化通用控件
    INITCOMMONCONTROLSEX icex{};
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES | ICC_TAB_CLASSES;
    InitCommonControlsEx(&icex);

    // 初始化COM
    CoInitialize(nullptr);

    // 阶段3: 设置默认安装路径（C:\FufuToolbox\版本号）
    g_defaultBasePath = TrimTrailingSeparators(L"C:\\FufuToolbox");

    g_documentsPath = g_defaultBasePath;
    ApplyInstallPath(g_defaultBasePath, false);
    CreateDirectoryW(g_tempPath.c_str(), nullptr);

    // 阶段5: 注册窗口类
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WindowProcedure;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(IDR_MAINICON));
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"MSIInstallerClass";
    wc.hIconSm = LoadIconW(hInstance, MAKEINTRESOURCEW(IDR_MAINICON));

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(nullptr, L"窗口类注册失败", L"错误", MB_OK | MB_ICONERROR);
        return 1;
    }

    // 阶段6: 创建主窗口
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int windowWidth = 580;
    int windowHeight = 400;
    int x = (screenWidth - windowWidth) / 2;
    int y = (screenHeight - windowHeight) / 2;

    g_hMainWnd = CreateWindowExW(
        0, L"MSIInstallerClass", L"Fufu 安装程序",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        x, y, windowWidth, windowHeight,
        nullptr, nullptr, hInstance, nullptr);

    if (!g_hMainWnd) {
        MessageBoxW(nullptr, L"窗口创建失败", L"错误", MB_OK | MB_ICONERROR);
        return 1;
    }

    // 显示窗口并进入消息循环
    ShowWindow(g_hMainWnd, nCmdShow);
    UpdateWindow(g_hMainWnd);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // 清理工作
    CoUninitialize();

    return (int)msg.wParam;
}
