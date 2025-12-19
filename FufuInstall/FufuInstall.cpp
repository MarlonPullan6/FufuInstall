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
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>
#include "resource.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ============================================================================
// 页面常量定义
// ============================================================================
constexpr int PAGE_WELCOME = 0;  // 欢迎页
constexpr int PAGE_LICENSE = 1;  // 许可协议页
constexpr int PAGE_LOCATION = 2;  // 安装路径选择页
constexpr int PAGE_PROGRESS = 3;  // 安装进度页
constexpr int PAGE_COMPLETE = 4;  // 安装完成页

// ============================================================================
// 自定义消息
// ============================================================================
constexpr UINT WM_UPDATE_PROGRESS = WM_USER + 1;        // 更新进度条
constexpr UINT WM_CONFIGURATION_COMPLETE = WM_USER + 2; // 安装完成

// ============================================================================
// 控件ID
// ============================================================================
constexpr int IDC_TITLE_LABEL = 1001;  // 标题标签
constexpr int IDC_SUBTITLE_LABEL = 1002;  // 副标题标签
constexpr int IDC_BACK_BUTTON = 1003;  // 上一步按钮
constexpr int IDC_NEXT_BUTTON = 1004;  // 下一步按钮
constexpr int IDC_CANCEL_BUTTON = 1005;  // 取消按钮
constexpr int IDC_PROGRESS_BAR = 1006;  // 进度条
constexpr int IDC_LOG_EDIT = 1007;  // 日志编辑框
constexpr int IDC_LICENSE_LINK = 1008;  // 许可协议链接
constexpr int IDC_LICENSE_CHECK = 1009;  // 许可协议复选框
constexpr int IDC_PATH_EDIT = 1010;  // 安装路径编辑框
constexpr int IDC_BROWSE_BUTTON = 1011;  // 浏览按钮

// ============================================================================
// 布局常量（按钮位置/大小）
// =========================================================================///
constexpr int BUTTON_Y = 320;
constexpr int BUTTON_HEIGHT = 28;
constexpr int BACK_WIDTH = 85;
constexpr int NEXT_WIDTH = 85;
constexpr int CANCEL_WIDTH = 65;
constexpr int BUTTON_SPACING = 10;
constexpr int BUTTON_RIGHT_MARGIN = 20;
constexpr int BUTTON_DEFAULT_BACK_X = 290;
constexpr int BUTTON_DEFAULT_NEXT_X = 385;
constexpr int BUTTON_DEFAULT_CANCEL_X = 480;

// ============================================================================
// 全局变量
// ============================================================================
HINSTANCE g_hInstance = nullptr;          // 程序实例句柄
HWND g_hMainWnd = nullptr;                // 主窗口句柄
HWND g_hTitleLabel = nullptr;             // 标题标签句柄
HWND g_hSubtitleLabel = nullptr;          // 副标题标签句柄
HWND g_hBackButton = nullptr;             // 上一步按钮句柄
HWND g_hNextButton = nullptr;             // 下一步按钮句柄
HWND g_hCancelButton = nullptr;           // 取消按钮句柄
HWND g_hProgressBar = nullptr;            // 进度条句柄
HWND g_hLogEdit = nullptr;                // 日志编辑框句柄
HWND g_hLicenseLink = nullptr;            // 许可协议链接句柄
HWND g_hLicenseCheck = nullptr;           // 许可协议复选框句柄
HWND g_hPathEdit = nullptr;               // 安装路径编辑框句柄
HWND g_hBrowseButton = nullptr;           // 浏览按钮句柄

HFONT g_hTitleFont = nullptr;             // 标题字体
HFONT g_hNormalFont = nullptr;            // 普通字体

HANDLE g_hLogFile = INVALID_HANDLE_VALUE; // 日志文件句柄

int g_currentPage = PAGE_WELCOME;         // 当前页面
bool g_agreedToLicense = false;           // 是否同意许可协议
bool g_installSuccess = false;            // 安装是否成功

std::wstring g_documentsPath;             // 文档路径
std::wstring g_installPath;               // 安装路径
std::wstring g_tempPath;                  // 临时文件路径

// 注册表备份值
DWORD g_originalAllowDev = 0;             // AllowDevelopmentWithoutDevLicense 原始值
DWORD g_originalAllowTrust = 0;           // AllowAllTrustedApps 原始值
bool g_regBackedUp = false;               // 是否已备份注册表

// 新增全局重启标志
bool g_needsReboot = false; // 是否需要重启

// ============================================================================
// 函数前向声明
// ============================================================================
LRESULT CALLBACK WindowProcedure(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
void LogMessage(const std::wstring& message);
bool ExtractResourceToFile(UINT resourceId, LPCWSTR resourceType, const std::wstring& filePath);
bool Extract7zArchive(const std::wstring& archivePath, const std::wstring& destPath);
DWORD ReadRegDWORD(HKEY hKeyRoot, LPCWSTR subKey, LPCWSTR valueName, DWORD defaultValue);
bool SetRegDWORDWithLog(HKEY hKeyRoot, LPCWSTR subKey, LPCWSTR valueName, DWORD value);
bool ExecutePowerShellWithLog(const std::wstring& command);
bool FindManifestRecursive(const std::wstring& dir, std::wstring& outPath);
std::wstring GetPackageNameFromManifest(const std::wstring& manifestPath);
bool IsPackageInstalled(const std::wstring& packageName);
bool UninstallAppxPackage(const std::wstring& packageName);
bool InstallAppxPackage(const std::wstring& manifestPath);
bool CheckDotNet8SDK();
bool InstallDotNet8SDK();
bool InstallWebview2();
bool CheckVCRuntime();
bool InstallVCRuntime();
bool IsWebView2Installed();

void ShowPage(int page);
void UpdateNavigationButtons();
void UpdateProgress(int percent);
bool PrepareInstallDirectory();
DWORD WINAPI PerformConfigurationThread(LPVOID lpParam);
void RestoreRegistry();

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

    // 写入日志文件
    if (g_hLogFile != INVALID_HANDLE_VALUE) {
        // 转换为UTF-8
        int utf8Len = WideCharToMultiByte(CP_UTF8, 0, fullMessage.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (utf8Len > 0) {
            std::vector<char> utf8Buf(utf8Len);
            WideCharToMultiByte(CP_UTF8, 0, fullMessage.c_str(), -1, utf8Buf.data(), utf8Len, nullptr, nullptr);
            DWORD written;
            WriteFile(g_hLogFile, utf8Buf.data(), utf8Len - 1, &written, nullptr);
        }
    }
}

// ============================================================================
// 辅助函数实现 - 资源释放
// ============================================================================

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
// 辅助函数实现 - 注册表操作
// ============================================================================

// 读取注册表DWORD值
DWORD ReadRegDWORD(HKEY hKeyRoot, LPCWSTR subKey, LPCWSTR valueName, DWORD defaultValue) {
    HKEY hKey;
    DWORD value = defaultValue;
    DWORD size = sizeof(DWORD);

    if (RegOpenKeyExW(hKeyRoot, subKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExW(hKey, valueName, nullptr, nullptr, (LPBYTE)&value, &size);
        RegCloseKey(hKey);
    }

    return value;
}

// 设置注册表DWORD值并记录日志
bool SetRegDWORDWithLog(HKEY hKeyRoot, LPCWSTR subKey, LPCWSTR valueName, DWORD value) {
    HKEY hKey;
    LONG result = RegOpenKeyExW(hKeyRoot, subKey, 0, KEY_SET_VALUE, &hKey);

    if (result != ERROR_SUCCESS) {
        // 尝试创建键
        result = RegCreateKeyExW(hKeyRoot, subKey, 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    }

    if (result != ERROR_SUCCESS) {
        LogMessage(L"错误: 无法打开/创建注册表键 " + std::wstring(subKey));
        return false;
    }

    result = RegSetValueExW(hKey, valueName, 0, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        LogMessage(L"错误: 无法设置注册表值 " + std::wstring(valueName));
        return false;
    }

    LogMessage(L"已设置注册表: " + std::wstring(subKey) + L"\\" + valueName + L" = " + std::to_wstring(value));
    return true;
}

// ============================================================================
// 辅助函数实现 - PowerShell执行
// ============================================================================

// 执行PowerShell命令并记录日志
bool ExecutePowerShellWithLog(const std::wstring& command) {
    LogMessage(L"执行PowerShell: " + command);

    std::wstring params = L"-NoProfile -ExecutionPolicy Bypass -Command \"" + command + L"\"";

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sei.hwnd = g_hMainWnd;
    sei.lpVerb = L"runas";
    sei.lpFile = L"powershell.exe";
    sei.lpParameters = params.c_str();
    sei.nShow = SW_HIDE;

    if (!ShellExecuteExW(&sei)) {
        LogMessage(L"错误: 无法启动PowerShell");
        return false;
    }

    // 等待执行完成
    WaitForSingleObject(sei.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(sei.hProcess, &exitCode);
    CloseHandle(sei.hProcess);

    LogMessage(L"PowerShell执行完成，退出代码: " + std::to_wstring(exitCode));
    return true;
}

// ============================================================================
// 辅助函数实现 - VC++ 14 runtime check/install
// ============================================================================

bool CheckVCRuntime() {
    LogMessage(L"检查 Visual C++ 2015-2019 (VC++14) 运行时...");

    // 尝试使用 winget 查询包信息
    LogMessage(L"使用 winget 检查 VC++ 运行时...");

    bool foundByWinget = false;

    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE hReadPipe = nullptr, hWritePipe = nullptr;
    if (CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOW si = {};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.hStdOutput = hWritePipe;
        si.hStdError = hWritePipe;
        si.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION pi = {};
        // 使用 cmd.exe /c 来调用 winget
        wchar_t cmdLine[] = L"cmd.exe /c winget show --id Microsoft.VCRedist.2015+.x64";

        BOOL created = CreateProcessW(nullptr, cmdLine, nullptr, nullptr, TRUE,
            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);

        // 关闭写端句柄以便读取输出
        CloseHandle(hWritePipe);

        if (created) {
            // 读取输出
            std::string output;
            char buffer[256];
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

            // 将输出转为宽字符串以记录日志
            int wlen = MultiByteToWideChar(CP_OEMCP, 0, output.c_str(), -1, nullptr, 0);
            std::wstring wout;
            if (wlen > 0) {
                wout.resize(wlen);
                MultiByteToWideChar(CP_OEMCP, 0, output.c_str(), -1, &wout[0], wlen);
            }

            LogMessage(L"winget 输出: " + wout);

            if (exitCode == 0 && (output.find("Id:") != std::string::npos || output.find("Name:") != std::string::npos || output.find("Microsoft.VCRedist") != std::string::npos || output.find("Visual C++") != std::string::npos)) {
                LogMessage(L"检测到 VC++ 运行时 (winget)");
                foundByWinget = true;
            }
            else {
                LogMessage(L"未通过 winget 检测到 VC++ 运行时");
            }
        }
        else {
            // 无法创建进程，记录并继续注册表检测
            CloseHandle(hReadPipe);
            LogMessage(L"winget 调用失败或未安装，回退到注册表检测");
        }
    }
    else {
        LogMessage(L"错误: 创建管道失败，回退到注册表检测");
    }

    if (foundByWinget) {
        return true;
    }

    // 回退到原有的注册表检测实现
    LogMessage(L"使用注册表检测 VC++ 运行时...");
    HKEY hKey = nullptr;
    const wchar_t* arpKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

    // 检查 64 位分支
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, arpKey, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        wchar_t name[256];
        DWORD nameLen = sizeof(name) / sizeof(name[0]);
        FILETIME ft;
        while (RegEnumKeyExW(hKey, index, name, &nameLen, nullptr, nullptr, nullptr, &ft) == ERROR_SUCCESS) {
            HKEY hSub = nullptr;
            if (RegOpenKeyExW(hKey, name, 0, KEY_READ | KEY_WOW64_64KEY, &hSub) == ERROR_SUCCESS) {
                wchar_t displayName[512] = { 0 };
                DWORD sz = sizeof(displayName);
                if (RegQueryValueExW(hSub, L"DisplayName", nullptr, nullptr, (LPBYTE)displayName, &sz) == ERROR_SUCCESS) {
                    if ((wcsstr(displayName, L"Visual C++") && (wcsstr(displayName, L"2015") || wcsstr(displayName, L"2017") || wcsstr(displayName, L"2019") || wcsstr(displayName, L"2015-2019"))) || wcsstr(displayName, L"Microsoft Visual C++ 2015-2022")) {
                        RegCloseKey(hSub);
                        RegCloseKey(hKey);
                        LogMessage(L"检测到 VC++ 运行时: " + std::wstring(displayName));
                        return true;
                    }
                }
                RegCloseKey(hSub);
            }
            index++;
            nameLen = sizeof(name) / sizeof(name[0]);
        }
        RegCloseKey(hKey);
    }

    // 检查 32 位分支
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, arpKey, 0, KEY_READ | KEY_WOW64_32KEY, &hKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        wchar_t name[256];
        DWORD nameLen = sizeof(name) / sizeof(name[0]);
        FILETIME ft;
        while (RegEnumKeyExW(hKey, index, name, &nameLen, nullptr, nullptr, nullptr, &ft) == ERROR_SUCCESS) {
            HKEY hSub = nullptr;
            if (RegOpenKeyExW(hKey, name, 0, KEY_READ | KEY_WOW64_32KEY, &hSub) == ERROR_SUCCESS) {
                wchar_t displayName[512] = { 0 };
                DWORD sz = sizeof(displayName);
                if (RegQueryValueExW(hSub, L"DisplayName", nullptr, nullptr, (LPBYTE)displayName, &sz) == ERROR_SUCCESS) {
                    if ((wcsstr(displayName, L"Visual C++") && (wcsstr(displayName, L"2015") || wcsstr(displayName, L"2017") || wcsstr(displayName, L"2019") || wcsstr(displayName, L"2015-2019"))) || wcsstr(displayName, L"Microsoft Visual C++ 2015-2022")) {
                        RegCloseKey(hSub);
                        RegCloseKey(hKey);
                        LogMessage(L"检测到 VC++ 运行时: " + std::wstring(displayName));
                        return true;
                    }
                }
                RegCloseKey(hSub);
            }
            index++;
            nameLen = sizeof(name) / sizeof(name[0]);
        }
        RegCloseKey(hKey);
    }

    LogMessage(L"未检测到 VC++14 运行时");
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
        sei.lpParameters = L"/c winget install --id Microsoft.VCRedist.2015+.x64 --interactive";
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
// 辅助函数实现 - Appx包管理
// ============================================================================

// 递归查找AppxManifest.xml
bool FindManifestRecursive(const std::wstring& dir, std::wstring& outPath) {
    WIN32_FIND_DATAW fd;
    std::wstring searchPath = dir + L"\\*";

    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        return false;
    }

    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) {
            continue;
        }

        std::wstring fullPath = dir + L"\\" + fd.cFileName;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // 递归搜索子目录
            if (FindManifestRecursive(fullPath, outPath)) {
                FindClose(hFind);
                return true;
            }
        }
        else {
            // 检查是否为AppxManifest.xml
            if (_wcsicmp(fd.cFileName, L"AppxManifest.xml") == 0) {
                outPath = fullPath;
                FindClose(hFind);
                return true;
            }
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
    return false;
}

// 从AppxManifest.xml中解析包名
std::wstring GetPackageNameFromManifest(const std::wstring& manifestPath) {
    // 读取文件内容
    HANDLE hFile = CreateFileW(manifestPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        LogMessage(L"错误: 无法打开Manifest文件");
        return L"";
    }

    DWORD fileSize = GetFileSize(hFile, nullptr);
    std::vector<char> buffer(fileSize + 1, 0);
    DWORD bytesRead;
    ReadFile(hFile, buffer.data(), fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);

    // 转换为宽字符
    int wlen = MultiByteToWideChar(CP_UTF8, 0, buffer.data(), -1, nullptr, 0);
    std::wstring content(wlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, buffer.data(), -1, &content[0], wlen);

    // 简单解析 Identity Name="..." 
    // 查找 <Identity
    size_t identityPos = content.find(L"<Identity");
    if (identityPos == std::wstring::npos) {
        LogMessage(L"错误: Manifest中未找到Identity元素");
        return L"";
    }

    // 查找 Name="..."
    size_t namePos = content.find(L"Name=\"", identityPos);
    if (namePos == std::wstring::npos) {
        LogMessage(L"错误: Manifest中未找到Name属性");
        return L"";
    }

    namePos += 6; // 跳过 Name="
    size_t nameEnd = content.find(L"\"", namePos);
    if (nameEnd == std::wstring::npos) {
        return L"";
    }

    std::wstring packageName = content.substr(namePos, nameEnd - namePos);
    LogMessage(L"解析到包名: " + packageName);
    return packageName;
}

// 检查Appx包是否已安装
bool IsPackageInstalled(const std::wstring& packageName) {
    // 使用PowerShell检查
    std::wstring checkCmd = L"if (Get-AppxPackage -Name '" + packageName + L"') { exit 0 } else { exit 1 }";

    std::wstring params = L"-NoProfile -ExecutionPolicy Bypass -Command \"" + checkCmd + L"\"";

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sei.lpVerb = L"open";
    sei.lpFile = L"powershell.exe";
    sei.lpParameters = params.c_str();
    sei.nShow = SW_HIDE;

    if (!ShellExecuteExW(&sei)) {
        return false;
    }

    WaitForSingleObject(sei.hProcess, INFINITE);

    DWORD exitCode = 1;
    GetExitCodeProcess(sei.hProcess, &exitCode);
    CloseHandle(sei.hProcess);

    return exitCode == 0;
}

// 卸载Appx包
bool UninstallAppxPackage(const std::wstring& packageName) {
    LogMessage(L"卸载现有包: " + packageName);

    std::wstring cmd = L"Get-AppxPackage -Name '" + packageName + L"' | Remove-AppxPackage";
    return ExecutePowerShellWithLog(cmd);
}

// 安装Appx包
bool InstallAppxPackage(const std::wstring& manifestPath) {
    LogMessage(L"安装Appx包: " + manifestPath);

    std::wstring cmd = L"Add-AppxPackage -Register '" + manifestPath + L"'";
    return ExecutePowerShellWithLog(cmd);
}

// 获取Appx Manifest路径
std::wstring GetAppxManifestPath() {
    std::wstring installDir = g_installPath;
    std::wstring manifestPath;

    if (FindManifestRecursive(installDir, manifestPath)) {
        LogMessage(L"找到Manifest: " + manifestPath);
        return manifestPath;
    }

    LogMessage(L"错误: 未找到AppxManifest.xml");
    return L"";
}

// ============================================================================
// 辅助函数实现 - 环境依赖检查
// ============================================================================

// 检查是否安装了.NET 8 SDK
bool CheckDotNet8SDK() {
    LogMessage(L"检查.NET 8 SDK...");

    // 创建管道读取dotnet命令输出
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE hReadPipe, hWritePipe;

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return false;
    }

    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {};
    wchar_t cmdLine[] = L"dotnet --list-sdks";

    if (!CreateProcessW(nullptr, cmdLine, nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        LogMessage(L".NET SDK未安装");
        return false;
    }

    CloseHandle(hWritePipe);

    // 读取输出
    std::string output;
    char buffer[256];
    DWORD bytesRead;

    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
        buffer[bytesRead] = 0;
        output += buffer;
    }

    CloseHandle(hReadPipe);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // 检查输出中是否包含 "8."
    bool found = output.find("8.") != std::string::npos;

    if (found) {
        LogMessage(L".NET 8 SDK已安装");
    }
    else {
        LogMessage(L".NET 8 SDK未检测到");
    }

    return found;
}

// 安装.NET 8 SDK
bool InstallDotNet8SDK() {
    int result = MessageBoxW(g_hMainWnd,
        L"未检测到 .NET 8 SDK，是否自动安装？\n\n"
        L"点击[是]将使用 winget 自动安装\n"
        L"点击[否]将显示手动安装命令",
        L"缺少依赖项", MB_YESNO | MB_ICONQUESTION);

    if (result == IDYES) {
        LogMessage(L"正在通过winget安装.NET 8 SDK...");

        // 使用cmd运行winget
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.hwnd = g_hMainWnd;
        sei.lpVerb = L"runas";
        sei.lpFile = L"cmd.exe";
        sei.lpParameters = L"/c winget install Microsoft.DotNet.SDK.8 --accept-source-agreements --accept-package-agreements";
        sei.nShow = SW_SHOW;

        if (ShellExecuteExW(&sei)) {
            WaitForSingleObject(sei.hProcess, INFINITE);
            CloseHandle(sei.hProcess);
            LogMessage(L".NET 8 SDK安装完成");
            return true;
        }
        else {
            LogMessage(L"错误: 无法启动winget安装");
            return false;
        }
    }
    else {
        MessageBoxW(g_hMainWnd,
            L"请在管理员命令提示符中运行以下命令安装 .NET 8 SDK:\n\n"
            L"winget install Microsoft.DotNet.SDK.8",
            L"手动安装说明", MB_OK | MB_ICONINFORMATION);
        return false;
    }
}

// 安装WebView2运行时
bool InstallWebview2() {
    int result = MessageBoxW(g_hMainWnd,
        L"未检测到 WebView2 运行时，是否使用 winget 自动安装？\n\n"
        L"点击[是]将使用 winget 自动安装 WebView2 运行时\n"
        L"点击[否]将显示手动安装命令",
        L"缺少依赖项", MB_YESNO | MB_ICONQUESTION);

    if (result == IDYES) {
        LogMessage(L"正在通过 winget 安装 WebView2 运行时...");

        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.hwnd = g_hMainWnd;
        sei.lpVerb = L"runas";
        sei.lpFile = L"cmd.exe";
        // 使用 winget 安装 Edge WebView2 Runtime
        sei.lpParameters = L"/c winget install --id Microsoft.EdgeWebView2Runtime -e --accept-source-agreements --accept-package-agreements";
        sei.nShow = SW_SHOW;

        if (ShellExecuteExW(&sei)) {
            WaitForSingleObject(sei.hProcess, INFINITE);
            DWORD exitCode = 0;
            GetExitCodeProcess(sei.hProcess, &exitCode);
            CloseHandle(sei.hProcess);
            LogMessage(L"winget 安装 WebView2 完成，退出代码: " + std::to_wstring(exitCode));
            return exitCode == 0;
        }
        else {
            LogMessage(L"错误: 无法启动 winget 安装 WebView2");
            return false;
        }
    }
    else {
        MessageBoxW(g_hMainWnd,
            L"请在管理员命令提示符中运行以下命令安装 WebView2 运行时:\n\n"
            L"winget install --id Microsoft.EdgeWebView2Runtime -e --accept-source-agreements --accept-package-agreements",
            L"手动安装说明", MB_OK | MB_ICONINFORMATION);
        return false;
    }
}

// 检查 WebView2 运行时是否已安装（通过 ARP 注册表中的 DisplayName 检查）
bool IsWebView2Installed() {
    LogMessage(L"检测 WebView2 运行时是否已安装...");
    const wchar_t* arpKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    HKEY hKey = nullptr;

    // 检查 64 位分支
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, arpKey, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        wchar_t name[256];
        DWORD nameLen = sizeof(name) / sizeof(name[0]);
        FILETIME ft;
        while (RegEnumKeyExW(hKey, index, name, &nameLen, nullptr, nullptr, nullptr, &ft) == ERROR_SUCCESS) {
            HKEY hSub = nullptr;
            if (RegOpenKeyExW(hKey, name, 0, KEY_READ | KEY_WOW64_64KEY, &hSub) == ERROR_SUCCESS) {
                wchar_t displayName[512] = { 0 };
                DWORD sz = sizeof(displayName);
                if (RegQueryValueExW(hSub, L"DisplayName", nullptr, nullptr, (LPBYTE)displayName, &sz) == ERROR_SUCCESS) {
                    if (wcsstr(displayName, L"WebView2") || wcsstr(displayName, L"Edge WebView2") || wcsstr(displayName, L"Microsoft Edge WebView2 Runtime") || wcsstr(displayName, L"WebView2 Runtime")) {
                        RegCloseKey(hSub);
                        RegCloseKey(hKey);
                        LogMessage(L"检测到 WebView2 运行时: " + std::wstring(displayName));
                        return true;
                    }
                }
                RegCloseKey(hSub);
            }
            index++;
            nameLen = sizeof(name) / sizeof(name[0]);
        }
        RegCloseKey(hKey);
    }

    // 检查 32 位分支
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, arpKey, 0, KEY_READ | KEY_WOW64_32KEY, &hKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        wchar_t name[256];
        DWORD nameLen = sizeof(name) / sizeof(name[0]);
        FILETIME ft;
        while (RegEnumKeyExW(hKey, index, name, &nameLen, nullptr, nullptr, nullptr, &ft) == ERROR_SUCCESS) {
            HKEY hSub = nullptr;
            if (RegOpenKeyExW(hKey, name, 0, KEY_READ | KEY_WOW64_32KEY, &hSub) == ERROR_SUCCESS) {
                wchar_t displayName[512] = { 0 };
                DWORD sz = sizeof(displayName);
                if (RegQueryValueExW(hSub, L"DisplayName", nullptr, nullptr, (LPBYTE)displayName, &sz) == ERROR_SUCCESS) {
                    if (wcsstr(displayName, L"WebView2") || wcsstr(displayName, L"Edge WebView2") || wcsstr(displayName, L"Microsoft Edge WebView2 Runtime") || wcsstr(displayName, L"WebView2 Runtime")) {
                        RegCloseKey(hSub);
                        RegCloseKey(hKey);
                        LogMessage(L"检测到 WebView2 运行时: " + std::wstring(displayName));
                        return true;
                    }
                }
                RegCloseKey(hSub);
            }
            index++;
            nameLen = sizeof(name) / sizeof(name[0]);
        }
        RegCloseKey(hKey);
    }

    LogMessage(L"未检测到 WebView2 运行时");
    return false;
}

// ============================================================================
// 辅助函数实现 - 注册表恢复
// ============================================================================

// 恢复注册表设置
void RestoreRegistry() {
    if (!g_regBackedUp) {
        return;
    }

    LogMessage(L"恢复注册表设置...");

    LPCWSTR subKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock";

    SetRegDWORDWithLog(HKEY_LOCAL_MACHINE, subKey, L"AllowDevelopmentWithoutDevLicense", g_originalAllowDev);
    SetRegDWORDWithLog(HKEY_LOCAL_MACHINE, subKey, L"AllowAllTrustedApps", g_originalAllowTrust);

    LogMessage(L"注册表设置已恢复");
}

// ============================================================================
// UI相关函数
// ============================================================================

// 更新进度条
void UpdateProgress(int percent) {
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
        SetWindowTextW(g_hSubtitleLabel, L"选择 Fufu 的安装目录:");
        ShowWindow(g_hPathEdit, SW_SHOW);
        ShowWindow(g_hBrowseButton, SW_SHOW);
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
            SetWindowTextW(g_hSubtitleLabel, L"Fufu 已成功安装！\n您可以通过桌面快捷方式启动程序。");
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

    // 获取用户选择的安装路径
    wchar_t pathBuffer[MAX_PATH];
    GetWindowTextW(g_hPathEdit, pathBuffer, MAX_PATH);
    g_installPath = pathBuffer;

    if (g_installPath.empty()) {
        g_installPath = g_documentsPath + L"\\fufu\\Install";
    }

    LogMessage(L"安装路径: " + g_installPath);

    // 创建安装目录
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

    // 阶段1: 准备安装目录 (10%)
    UpdateProgress(5);
    LogMessage(L"========== 开始安装 ==========");

    if (!PrepareInstallDirectory()) {
        success = false;
        goto cleanup;
    }
    UpdateProgress(10);

    // 阶段2: 释放安装包并解压 (20%)
    LogMessage(L"释放安装文件...");
    {
        std::wstring archivePath = g_tempPath + L"\\Install_temp.7z";

        // 释放7z压缩包
        if (!ExtractResourceToFile(IDR_INSTALL7Z, L"BINARY", archivePath)) {
            LogMessage(L"错误: 无法释放安装包");
            success = false;
            goto cleanup;
        }

        UpdateProgress(15);

        // 解压到安装目录
        if (!Extract7zArchive(archivePath, g_installPath)) {
            LogMessage(L"错误: 解压失败");
            success = false;
            goto cleanup;
        }

        // 删除临时压缩包
        DeleteFileW(archivePath.c_str());
    }
    UpdateProgress(20);

    // 阶段3: 检查.NET 8 SDK (30%)
    LogMessage(L"检查.NET 8 SDK...");
    if (!CheckDotNet8SDK()) {
        if (!InstallDotNet8SDK()) {
            LogMessage(L"警告: .NET 8 SDK未安装，应用可能无法正常运行");
        }
    }
    UpdateProgress(30);

    // 新增阶段: 检查 VC++ 运行时 (40%)
    LogMessage(L"检查 VC++ 运行时...");
    if (!CheckVCRuntime()) {
        if (!InstallVCRuntime()) {
            LogMessage(L"警告: VC++ 运行时未安装，应用可能无法正常运行");
        }
    }
    UpdateProgress(40);

    // 阶段4: 安装WebView2 (55%)
    LogMessage(L"安装WebView2运行时...");
    if (!IsWebView2Installed()) {
        InstallWebview2();
    }
    else {
        LogMessage(L"跳过 WebView2 安装，已检测到运行时");
    }
    UpdateProgress(55);

    // 阶段5: 配置开发者模式 (65%)
    LogMessage(L"配置开发者模式...");
    {
        LPCWSTR subKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock";

        // 备份原始值
        g_originalAllowDev = ReadRegDWORD(HKEY_LOCAL_MACHINE, subKey, L"AllowDevelopmentWithoutDevLicense", 0);
        g_originalAllowTrust = ReadRegDWORD(HKEY_LOCAL_MACHINE, subKey, L"AllowAllTrustedApps", 0);
        g_regBackedUp = true;

        LogMessage(L"备份注册表原始值: AllowDev=" + std::to_wstring(g_originalAllowDev) +
            L", AllowTrust=" + std::to_wstring(g_originalAllowTrust));

        // 设置开发者模式
        SetRegDWORDWithLog(HKEY_LOCAL_MACHINE, subKey, L"AllowDevelopmentWithoutDevLicense", 1);
        SetRegDWORDWithLog(HKEY_LOCAL_MACHINE, subKey, L"AllowAllTrustedApps", 1);
    }
    UpdateProgress(65);

    // 阶段6: 配置PowerShell执行策略 (75%)
    LogMessage(L"配置PowerShell执行策略...");
    ExecutePowerShellWithLog(L"Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned -Force");
    ExecutePowerShellWithLog(L"Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force");
    UpdateProgress(75);

    // 阶段7: 安装Appx包 (90%)
    LogMessage(L"安装应用包...");
    {
        std::wstring manifestPath = GetAppxManifestPath();
        if (manifestPath.empty()) {
            LogMessage(L"错误: 未找到AppxManifest.xml");
            success = false;
            goto cleanup;
        }

        UpdateProgress(80);

        // 获取包名并检查是否已安装
        std::wstring packageName = GetPackageNameFromManifest(manifestPath);
        if (!packageName.empty() && IsPackageInstalled(packageName)) {
            LogMessage(L"检测到已安装的版本，正在卸载...");
            UninstallAppxPackage(packageName);
        }

        UpdateProgress(85);

        // 安装新包
        if (!InstallAppxPackage(manifestPath)) {
            LogMessage(L"错误: Appx包安装失败");
            success = false;
            goto cleanup;
        }
    }
    UpdateProgress(90);

    // 阶段8: 恢复注册表 (95%)
    LogMessage(L"恢复系统设置...");
    RestoreRegistry();
    UpdateProgress(95);

    // 阶段9: 创建快捷方式 (99%)
    LogMessage(L"创建桌面快捷方式...");
    {
        // 复制图标到文档目录
        std::wstring icoDst = g_documentsPath + L"\\fufu\\app.ico";
        ExtractResourceToFile(IDR_APP_ICO, L"BINARY", icoDst);

        // 获取桌面路径
        PWSTR desktopPath = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Desktop, 0, nullptr, &desktopPath))) {
            std::wstring lnkPath = std::wstring(desktopPath) + L"\\芙芙启动器.lnk";

            // 释放快捷方式文件
            ExtractResourceToFile(IDR_LNK, L"BINARY", lnkPath);

            CoTaskMemFree(desktopPath);
            LogMessage(L"已创建桌面快捷方式");
        }
    }
    UpdateProgress(99);

    LogMessage(L"========== 安装完成 ==========");
    UpdateProgress(100);

cleanup:
    g_installSuccess = success;

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
            20, 125, 450, 25, hwnd, (HMENU)IDC_PATH_EDIT, g_hInstance, nullptr);
        SendMessageW(g_hPathEdit, WM_SETFONT, (WPARAM)g_hNormalFont, TRUE);

        // 创建浏览按钮
        g_hBrowseButton = CreateWindowExW(0, L"BUTTON", L"浏览...",
            WS_CHILD | BS_PUSHBUTTON,
            480, 123, 70, 28, hwnd, (HMENU)IDC_BROWSE_BUTTON, g_hInstance, nullptr);
        SendMessageW(g_hBrowseButton, WM_SETFONT, (WPARAM)g_hNormalFont, TRUE);

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
                            SetWindowTextW(g_hPathEdit, pszPath);
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
        }
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

    // ========================================================================
    // 隐藏控制台窗口
    // ========================================================================
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    // ========================================================================
    // 阶段1: 权限检查
    // ========================================================================
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
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

    // ========================================================================
    // 阶段2: 初始化通用控件
    // ========================================================================
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icex);

    // 初始化COM
    CoInitialize(nullptr);

    // ========================================================================
    // 阶段3: 获取文档路径并创建工作目录
    // ========================================================================
    PWSTR documentsPath = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Documents, 0, nullptr, &documentsPath))) {
        g_documentsPath = documentsPath;
        CoTaskMemFree(documentsPath);
    }
    else {
        MessageBoxW(nullptr, L"无法获取文档路径", L"错误", MB_OK | MB_ICONERROR);
        return 1;
    }

    // 创建fufu目录
    g_tempPath = g_documentsPath + L"\\fufu";
    CreateDirectoryW(g_tempPath.c_str(), nullptr);

    // 设置默认安装路径
    g_installPath = g_tempPath + L"\\Install";

    // ========================================================================
    // 阶段4: 创建日志文件
    // ========================================================================
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t logFileName[256];
    swprintf_s(logFileName, L"\\安装日志_%04d-%02d-%02d_%02d-%02d-%02d.txt",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    std::wstring logFilePath = g_tempPath + logFileName;
    g_hLogFile = CreateFileW(logFilePath.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (g_hLogFile != INVALID_HANDLE_VALUE) {
        // 写入UTF-8 BOM
        BYTE bom[] = { 0xEF, 0xBB, 0xBF };
        DWORD written;
        WriteFile(g_hLogFile, bom, sizeof(bom), &written, nullptr);

        // 写入日志头
        const char* header = "========== Fufu 安装日志 ==========\r\n\r\n";
        WriteFile(g_hLogFile, header, (DWORD)strlen(header), &written, nullptr);
    }

    // ========================================================================
    // 阶段5: 注册窗口类
    // ========================================================================
    WNDCLASSEXW wc = {};
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

    // ========================================================================
    // 阶段6: 创建主窗口
    // ========================================================================
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

    // ========================================================================
    // 阶段7: 资源预处理 - 释放7z工具和WebView2安装程序
    // ========================================================================
    {
        // 清理可能存在的旧Install目录
        std::wstring installDir = g_tempPath + L"\\Install";
        if (GetFileAttributesW(installDir.c_str()) != INVALID_FILE_ATTRIBUTES) {
            std::wstring cmd = L"/c rd /s /q \"" + installDir + L"\"";

            SHELLEXECUTEINFOW sei = { sizeof(sei) };
            sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
            sei.lpVerb = L"open";
            sei.lpFile = L"cmd.exe";
            sei.lpParameters = cmd.c_str();
            sei.nShow = SW_HIDE;

            if (ShellExecuteExW(&sei)) {
                WaitForSingleObject(sei.hProcess, 10000);
                CloseHandle(sei.hProcess);
            }
        }

        // 释放7z.exe
        std::wstring exe7z = g_tempPath + L"\\7z.exe";
        if (!ExtractResourceToFile(IDR_7ZEXE, L"BINARY", exe7z)) {
            MessageBoxW(nullptr, L"无法释放7z.exe", L"错误", MB_OK | MB_ICONERROR);
            return 1;
        }

        // 释放7z.dll
        std::wstring dll7z = g_tempPath + L"\\7z.dll";
        if (!ExtractResourceToFile(IDR_7ZDLL, L"BINARY", dll7z)) {
            MessageBoxW(nullptr, L"无法释放7z.dll", L"错误", MB_OK | MB_ICONERROR);
            return 1;
        }

        // 不再从资源释放 WebView2 安装程序，使用 winget 安装
    }

    // ========================================================================
    // 阶段8: 显示窗口并进入消息循环
    // ========================================================================
    ShowWindow(g_hMainWnd, nCmdShow);
    UpdateWindow(g_hMainWnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // ========================================================================
    // 阶段9: 清理临时文件
    // ========================================================================
    DeleteFileW((g_tempPath + L"\\7z.exe").c_str());
    DeleteFileW((g_tempPath + L"\\7z.dll").c_str());
    // 不再删除 Webview2Setup.exe，因为未创建该文件

    // 关闭日志文件
    if (g_hLogFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hLogFile);
    }

    CoUninitialize();

    return (int)msg.wParam;
}