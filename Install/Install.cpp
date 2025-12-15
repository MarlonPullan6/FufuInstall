#include <windows.h>
#include <shellapi.h>
#include <commctrl.h>
#include <string>
#include <shlwapi.h>
#include <shlobj.h>
#include <time.h>
#include <stdio.h>  
#include "resource.h"
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#define WM_CONFIGURATION_COMPLETE (WM_USER + 1)
#define WM_UPDATE_PROGRESS (WM_USER + 2)


#define PAGE_WELCOME 0
#define PAGE_LICENSE 1
#define PAGE_PROGRESS 2
#define PAGE_COMPLETE 3

const int WINDOW_WIDTH = 580; // 窗口宽度
const int WINDOW_HEIGHT = 400; // 窗口高度
const int BUTTON_WIDTH = 85; // 按钮宽度
const int BUTTON_HEIGHT = 25; // 按钮高度
const int BUTTON_GAP = 10; // 按钮之间的间隙
const int BUTTON_RIGHT_MARGIN = 20; // 按钮右边距
const int BUTTON_BOTTOM_MARGIN = 12; // 按钮底边距
const int CONTENT_LEFT = 40; // 内容区域左边距
const int CONTENT_WIDTH = 500; // 内容区域宽度
const COLORREF WINDOW_BACKGROUND_COLOR = RGB(240, 240, 240); // 窗口背景颜色
const int HEADER_TOP = 30; // 标题顶部位置
const int SUBHEADER_TOP = 70; // 副标题顶部位置
const int LICENSE_TEXT_TOP = 130; // 许可证文本顶部位置
const int LICENSE_LINK_TOP = 170; // 许可证链接顶部位置
const int LICENSE_CHECK_TOP = 240; // 许可证复选框顶部位置
const int PROGRESS_BAR_TOP = 180; // 进度条顶部位置
const int LOG_TOP = 100; // 日志显示区域顶部位置
const int LOG_HEIGHT = 240; // 日志显示区域高度
const int COMPLETE_TITLE_TOP = 160; // 完成页面标题顶部位置
const int COMPLETE_TEXT_TOP = 220; // 完成页面文本顶部位置

HWND g_hMainWnd = NULL;
HWND g_hBtnBack = NULL;
HWND g_hBtnNext = NULL;
HWND g_hBtnCancel = NULL;
HWND g_hProgressBar = NULL;
HWND g_hStaticHeader = NULL;
HWND g_hStaticSubHeader = NULL;
HWND g_hEditLog = NULL;
HANDLE g_hLogFile = INVALID_HANDLE_VALUE;


HWND g_pageWelcome[3] = { 0 };
HWND g_pageLicense[3] = { 0 };
HWND g_pageProgress[2] = { 0 };
HWND g_pageComplete[2] = { 0 };

HBRUSH g_hBackgroundBrush = NULL;

int g_currentPage = PAGE_WELCOME;
bool g_installSuccess = false;
bool g_agreedToLicense = false;


DWORD g_originalAllowDevelopment = 0;
DWORD g_originalAllowAllTrusted = 0;
bool g_devValueExists = false;
bool g_allTrustedValueExists = false;
std::wstring g_installFolderPath;
std::wstring g_packageName;
std::wstring g_appId;


void LogMessage(const wchar_t* message);
void ShowPage(int page);
void UpdateNavigationButtons();
void OnNextClicked();
void OnBackClicked();
bool CheckDotNet8SDK();
bool InstallDotNet8SDK();
bool InstallWebview2();
bool ExtractResourceToFile(int resourceId, const std::wstring& outputPath);
bool Extract7zArchive(const std::wstring& archivePath, const std::wstring& destDir);
bool PrepareInstallDirectory();
bool ReadRegDWORD(HKEY hRoot, const wchar_t* subKey, const wchar_t* valueName, DWORD& data, bool& valueExists);
bool SetRegDWORDWithLog(HKEY hRoot, const wchar_t* subKey, const wchar_t* valueName, DWORD data,
    DWORD& originalData, bool& valueExists, bool deleteIfNotExists);
bool ExecutePowerShellWithLog(const wchar_t* scope);
std::wstring FindManifestRecursive(const std::wstring& directory);
std::wstring GetAppxManifestPath();
std::wstring GetPackageNameFromManifest();
bool IsPackageInstalled(const std::wstring& packageName);
bool UninstallAppxPackage(const std::wstring& packageName);
bool InstallAppxPackage();
std::wstring GetAppxManifestPath();
void RestoreRegistry();
DWORD WINAPI PerformConfigurationThread(LPVOID lpParam);


void LogMessage(const wchar_t* message) {

    if (g_hEditLog) {
        int len = GetWindowTextLengthW(g_hEditLog);
        SendMessageW(g_hEditLog, EM_SETSEL, len, len);
        SendMessageW(g_hEditLog, EM_REPLACESEL, FALSE, (LPARAM)message);
        SendMessageW(g_hEditLog, EM_REPLACESEL, FALSE, (LPARAM)L"\r\n");
        SendMessageW(g_hEditLog, EM_SCROLLCARET, 0, 0);
    }


    if (g_hLogFile != INVALID_HANDLE_VALUE) {

        time_t now = time(NULL);
        struct tm timeinfo;
        localtime_s(&timeinfo, &now);

        char timeStr[100];
        sprintf_s(timeStr, "[%02d:%02d:%02d] ",
            timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);


        int wideLen = (int)wcslen(message);
        int utf8Len = WideCharToMultiByte(CP_UTF8, 0, message, wideLen, NULL, 0, NULL, NULL);
        if (utf8Len > 0) {
            char* utf8Buffer = new char[utf8Len + 1];
            WideCharToMultiByte(CP_UTF8, 0, message, wideLen, utf8Buffer, utf8Len, NULL, NULL);
            utf8Buffer[utf8Len] = '\0';

            DWORD written;
            WriteFile(g_hLogFile, timeStr, (DWORD)strlen(timeStr), &written, NULL);
            WriteFile(g_hLogFile, utf8Buffer, (DWORD)strlen(utf8Buffer), &written, NULL);
            WriteFile(g_hLogFile, "\r\n", 2, &written, NULL);

            delete[] utf8Buffer;
        }
    }
}


bool CheckDotNet8SDK() {
    LogMessage(L"===== 检测.NET 8 SDK环境 =====");
    LogMessage(L"");

    wchar_t params[] = L"-NoProfile -WindowStyle Hidden -Command \"$sdks = dotnet --list-sdks 2>&1; if ($sdks -match '8\\.') { exit 0 } else { exit 1 }\"";

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"open";
    sei.lpFile = L"powershell.exe";
    sei.lpParameters = params;
    sei.nShow = SW_HIDE;

    if (ShellExecuteExW(&sei) && sei.hProcess != NULL) {
        WaitForSingleObject(sei.hProcess, 30000);
        DWORD exitCode;
        GetExitCodeProcess(sei.hProcess, &exitCode);
        CloseHandle(sei.hProcess);

        if (exitCode == 0) {
            LogMessage(L"✓ 检测到已安装.NET 8 SDK");
            LogMessage(L"");
            return true;
        }
    }

    LogMessage(L"✗ 未检测到.NET 8 SDK");
    LogMessage(L"");
    return false;
}

bool InstallDotNet8SDK() {

    int result = MessageBoxW(g_hMainWnd,
        L"未检测到.NET 8 SDK\n\n请选择安装方式：\n\n"
        L"是：自动安装（推荐）\n"
        L"否：手动安装并继续（不影响安装流程）\n\n"
        L"提示：即使选择手动安装，本程序也会继续执行后续步骤。",
        L".NET 8 SDK 未安装", MB_YESNOCANCEL | MB_ICONQUESTION);

    if (result == IDCANCEL) {
        LogMessage(L"用户取消安装");
        return false;
    }

    if (result == IDYES) {
        LogMessage(L"用户选择自动安装.NET 8 SDK");
        LogMessage(L"===== 开始安装.NET 8 SDK =====");
        LogMessage(L"");
        LogMessage(L"正在通过winget安装Microsoft.DotNet.SDK.8...");
        LogMessage(L"(此过程可能需要几分钟，请耐心等待)");

        wchar_t params[] = L"install Microsoft.DotNet.SDK.8 --silent --accept-source-agreements --accept-package-agreements";

        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = L"open";
        sei.lpFile = L"winget";
        sei.lpParameters = params;
        sei.nShow = SW_HIDE;

        if (ShellExecuteExW(&sei) && sei.hProcess != NULL) {
            DWORD waitResult = WaitForSingleObject(sei.hProcess, 600000);
            DWORD exitCode;
            GetExitCodeProcess(sei.hProcess, &exitCode);
            CloseHandle(sei.hProcess);

            if (waitResult == WAIT_OBJECT_0 && exitCode == 0) {
                LogMessage(L"✓ .NET 8 SDK安装成功");
                LogMessage(L"");
                return true;
            }

            wchar_t errorMsg[256];
            swprintf_s(errorMsg, L"✗ .NET 8 SDK安装失败 (退出码: %d)", exitCode);
            LogMessage(errorMsg);
        }
        else {
            LogMessage(L"✗ 无法启动winget进行安装");
            LogMessage(L"请确保系统已安装winget (Windows Package Manager)");
        }
        LogMessage(L"");


        int continueResult = MessageBoxW(g_hMainWnd,
            L".NET 8 SDK自动安装失败\n\n程序可以继续安装，但某些功能可能无法正常使用\n\n是否继续？",
            L"警告", MB_YESNO | MB_ICONWARNING);

        return (continueResult == IDYES);
    }

    LogMessage(L"用户选择手动安装.NET 8 SDK");
    LogMessage(L"安装将继续进行，手动安装.NET不会影响后续步骤...");

    MessageBoxW(g_hMainWnd,
        L"您选择了手动安装.NET 8 SDK\n\n"
        L"安装方法：\n"
        L"1. 以管理员身份运行PowerShell\n"
        L"2. 输入命令: winget install Microsoft.DotNet.SDK.8\n\n"
        L"提示：这不会影响本安装程序的执行，您可以继续继续下一步。",
        L"手动安装指南", MB_OK | MB_ICONINFORMATION);

    return true;
}


bool InstallWebview2() {
    LogMessage(L"===== 安装 WebView2 Runtime =====");
    LogMessage(L"");

    std::wstring setupPath = g_installFolderPath;
    size_t lastSlash = setupPath.find_last_of(L'\\');
    if (lastSlash != std::wstring::npos) {
        setupPath = setupPath.substr(0, lastSlash);
    }
    setupPath += L"\\Webview2Setup.exe";

    if (GetFileAttributesW(setupPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        LogMessage(L"✗ 找不到 Webview2Setup.exe");
        return false;
    }

    LogMessage(L"正在运行 WebView2 安装程序...");

    wchar_t params[] = L"/silent /install";

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"open";
    sei.lpFile = setupPath.c_str();
    sei.lpParameters = params;
    sei.nShow = SW_HIDE;

    if (ShellExecuteExW(&sei) && sei.hProcess != NULL) {
        WaitForSingleObject(sei.hProcess, INFINITE);
        DWORD exitCode;
        GetExitCodeProcess(sei.hProcess, &exitCode);
        CloseHandle(sei.hProcess);

        LogMessage(L"✓ WebView2 安装程序执行完成");
    }
    else {
        LogMessage(L"✗ 无法启动 WebView2 安装程序");
    }

    LogMessage(L"");
    return true;
}


bool ExtractResourceToFile(int resourceId, const std::wstring& outputPath) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hRes = FindResourceW(hModule, MAKEINTRESOURCEW(resourceId), RT_RCDATA);
    if (!hRes) {
        wchar_t msg[64];
        swprintf_s(msg, L"✗ 找不到资源 ID: %d", resourceId);
        LogMessage(msg);
        return false;
    }

    HGLOBAL hData = LoadResource(hModule, hRes);
    if (!hData) {
        LogMessage(L"✗ 无法加载资源");
        return false;
    }

    DWORD dataSize = SizeofResource(hModule, hRes);
    void* pData = LockResource(hData);
    if (!pData || dataSize == 0) {
        LogMessage(L"✗ 无法锁定资源");
        return false;
    }

    HANDLE hFile = CreateFileW(outputPath.c_str(), GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LogMessage(L"✗ 无法创建文件");
        return false;
    }

    DWORD bytesWritten;
    BOOL result = WriteFile(hFile, pData, dataSize, &bytesWritten, NULL);
    CloseHandle(hFile);

    if (!result || bytesWritten != dataSize) {
        LogMessage(L"✗ 写入文件失败");
        return false;
    }

    return true;
}

bool Extract7zArchive(const std::wstring& archivePath, const std::wstring& destDir) {
    wchar_t logMsg[512];
    swprintf_s(logMsg, L"正在解压到: %s", destDir.c_str());
    LogMessage(logMsg);

    CreateDirectoryW(destDir.c_str(), NULL);

    wchar_t params[1024];

    std::wstring sevenZipPath;

    // Check for bundled 7z.exe in the parent directory of install folder
    std::wstring bundled7zPath = g_installFolderPath;
    size_t lastSlash = bundled7zPath.find_last_of(L'\\');
    if (lastSlash != std::wstring::npos) {
        bundled7zPath = bundled7zPath.substr(0, lastSlash);
    }
    bundled7zPath += L"\\7z.exe";

    if (GetFileAttributesW(bundled7zPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        sevenZipPath = bundled7zPath;
    } else {
        const wchar_t* possiblePaths[] = {
            L"C:\\Program Files\\7-Zip\\7z.exe",
            L"C:\\Program Files (x86)\\7-Zip\\7z.exe"
        };

        for (const auto& path : possiblePaths) {
            if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) {
                sevenZipPath = path;
                break;
            }
        }
    }

    if (sevenZipPath.empty()) {
        sevenZipPath = L"7z.exe";
    }

    swprintf_s(params, L"x \"%s\" -o\"%s\" -y", archivePath.c_str(), destDir.c_str());

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"open";
    sei.lpFile = sevenZipPath.c_str();
    sei.lpParameters = params;
    sei.nShow = SW_HIDE;

    if (ShellExecuteExW(&sei) && sei.hProcess != NULL) {
        WaitForSingleObject(sei.hProcess, 120000);
        DWORD exitCode;
        GetExitCodeProcess(sei.hProcess, &exitCode);
        CloseHandle(sei.hProcess);

        if (exitCode == 0) {
            LogMessage(L"✓ 解压完成");
            return true;
        }
        wchar_t errorMsg[256];
        swprintf_s(errorMsg, L"✗ 解压失败 (退出码: %d)", exitCode);
        LogMessage(errorMsg);
    }
    else {
        LogMessage(L"✗ 無法启动7z进行解压，请确保已安装7-Zip");
    }

    return false;
}

bool PrepareInstallDirectory() {
    LogMessage(L"===== 准备安装目录 =====");
    LogMessage(L"");

    PWSTR documentsPath = NULL;
    HRESULT hr = SHGetKnownFolderPath(FOLDERID_Documents, 0, NULL, &documentsPath);
    if (FAILED(hr)) {
        LogMessage(L"✗ 無法获取文档文件夹路径");
        return false;
    }

    std::wstring fufuDir = documentsPath;
    fufuDir += L"\\fufu";
    CreateDirectoryW(fufuDir.c_str(), NULL);

    g_installFolderPath = fufuDir + L"\\Install";

    wchar_t logMsg[512];
    swprintf_s(logMsg, L"安装目录: %s", g_installFolderPath.c_str());
    LogMessage(logMsg);

    if (GetFileAttributesW(g_installFolderPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        LogMessage(L"检测到已存在的Install目录，正在清理...");
        wchar_t cmdParams[512];
        swprintf_s(cmdParams, L"/c rd /s /q \"%s\"", g_installFolderPath.c_str());
        SHELLEXECUTEINFOW seiDel = { sizeof(seiDel) };
        seiDel.fMask = SEE_MASK_NOCLOSEPROCESS;
        seiDel.lpVerb = L"open";
        seiDel.lpFile = L"cmd.exe";
        seiDel.lpParameters = cmdParams;
        seiDel.nShow = SW_HIDE;
        if (ShellExecuteExW(&seiDel) && seiDel.hProcess != NULL) {
            WaitForSingleObject(seiDel.hProcess, 30000);
            CloseHandle(seiDel.hProcess);
        }
    }

    std::wstring temp7zPath = fufuDir + L"\\Install_temp.7z";

    if (!ExtractResourceToFile(IDR_INSTALL7Z, temp7zPath)) {
        CoTaskMemFree(documentsPath);
        return false;
    }

    bool result = Extract7zArchive(temp7zPath, g_installFolderPath);

    DeleteFileW(temp7zPath.c_str());

    CoTaskMemFree(documentsPath);

    if (result) {
        LogMessage(L"");
        LogMessage(L"===== 安装目录准备完成 =====");
        LogMessage(L"");
    }

    return result;
}


bool ReadRegDWORD(HKEY hRoot, const wchar_t* subKey, const wchar_t* valueName, DWORD& data, bool& valueExists) {
    HKEY hKey;
    valueExists = false;

    long result = RegOpenKeyExW(hRoot, subKey, 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
    if (result != ERROR_SUCCESS) return false;

    DWORD size = sizeof(DWORD);
    result = RegQueryValueExW(hKey, valueName, NULL, NULL, (LPBYTE)&data, &size);
    RegCloseKey(hKey);

    if (result == ERROR_SUCCESS) {
        valueExists = true;
        return true;
    }
    return false;
}

bool SetRegDWORDWithLog(HKEY hRoot, const wchar_t* subKey, const wchar_t* valueName, DWORD data,
    DWORD& originalData, bool& valueExists, bool deleteIfNotExists) {
    wchar_t logMsg[512];

    ReadRegDWORD(hRoot, subKey, valueName, originalData, valueExists);

    if (valueExists) {
        swprintf_s(logMsg, L"设置注册表: %s\\%s = %d (原始值: %d)", subKey, valueName, data, originalData);
    }
    else {
        swprintf_s(logMsg, L"设置注册表: %s\\%s = %d (原始不存在)", subKey, valueName, data);
    }
    LogMessage(logMsg);

    HKEY hKey;
    long result = RegCreateKeyExW(hRoot, subKey, 0, NULL, REG_OPTION_NON_VOLATILE,
        KEY_WRITE | KEY_WOW64_64KEY, NULL, &hKey, NULL);
    if (result != ERROR_SUCCESS) {
        LogMessage(L"✗ 无法打开注册表项");
        return false;
    }

    if (deleteIfNotExists && !valueExists) {
        result = RegDeleteValueW(hKey, valueName);
        RegCloseKey(hKey);
        if (result == ERROR_SUCCESS) {
            LogMessage(L"✓ 注册表值已删除");
            return true;
        }
    }
    else {
        result = RegSetValueExW(hKey, valueName, 0, REG_DWORD, (const BYTE*)&data, sizeof(data));
        RegCloseKey(hKey);
        if (result == ERROR_SUCCESS) {
            LogMessage(L"✓ 注册表设置成功");
            return true;
        }
    }

    LogMessage(L"✗ 注册表操作失败");
    return false;
}


bool ExecutePowerShellWithLog(const wchar_t* scope) {
    wchar_t logMsg[256];
    swprintf_s(logMsg, L"设置PowerShell执行策略: %s", scope);
    LogMessage(logMsg);

    wchar_t params[256];
    swprintf_s(params, L"-NoProfile -WindowStyle Hidden -Command \"Set-ExecutionPolicy RemoteSigned -Scope %s -Force\"", scope);

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"open";
    sei.lpFile = L"powershell.exe";
    sei.lpParameters = params;
    sei.nShow = SW_HIDE;

    if (ShellExecuteExW(&sei) && sei.hProcess != NULL) {
        WaitForSingleObject(sei.hProcess, 20000);
        DWORD exitCode;
        GetExitCodeProcess(sei.hProcess, &exitCode);
        CloseHandle(sei.hProcess);

        if (exitCode == 0) {
            LogMessage(L"✓ PowerShell执行策略设置成功");
            return true;
        }
    }

    LogMessage(L"✗ PowerShell执行策略设置失败");
    return false;
}

std::wstring FindManifestRecursive(const std::wstring& directory) {
    std::wstring targetFile = directory + L"\\AppxManifest.xml";
    if (GetFileAttributesW(targetFile.c_str()) != INVALID_FILE_ATTRIBUTES) {
        return targetFile;
    }

    std::wstring searchPattern = directory + L"\\*";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return L"";
    }

    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (wcscmp(findData.cFileName, L".") != 0 && wcscmp(findData.cFileName, L"..") != 0) {
                std::wstring subDir = directory + L"\\" + findData.cFileName;
                std::wstring result = FindManifestRecursive(subDir);
                if (!result.empty()) {
                    FindClose(hFind);
                    return result;
                }
            }
        }
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
    return L"";
}

std::wstring GetAppxManifestPath() {
    return FindManifestRecursive(g_installFolderPath);
}

std::wstring GetPackageNameFromManifest() {
    std::wstring manifestPathStr = GetAppxManifestPath();
    if (manifestPathStr.empty()) {
        return L"";
    }

    HANDLE hFile = CreateFileW(manifestPathStr.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return L"";
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        return L"";
    }

    char* buffer = new char[fileSize + 1];
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
        delete[] buffer;
        CloseHandle(hFile);
        return L"";
    }
    buffer[bytesRead] = '\0';
    CloseHandle(hFile);

    int wideLen = MultiByteToWideChar(CP_UTF8, 0, buffer, -1, NULL, 0);
    wchar_t* wideBuffer = new wchar_t[wideLen];
    MultiByteToWideChar(CP_UTF8, 0, buffer, -1, wideBuffer, wideLen);
    delete[] buffer;

    std::wstring content(wideBuffer);
    delete[] wideBuffer;

    const wchar_t* identityTag = L"<Identity";
    const wchar_t* nameAttr = L"Name=\"";

    size_t identityPos = content.find(identityTag);
    if (identityPos == std::wstring::npos) {
        return L"";
    }

    size_t tagEnd = content.find(L">", identityPos);
    if (tagEnd == std::wstring::npos) {
        return L"";
    }
    size_t namePos = content.find(nameAttr, identityPos);
    if (namePos == std::wstring::npos || namePos > tagEnd) {
        return L"";
    }

    size_t valueStart = namePos + wcslen(nameAttr);
    size_t valueEnd = content.find(L"\"", valueStart);
    if (valueEnd == std::wstring::npos || valueEnd > tagEnd) {
        return L"";
    }

    std::wstring packageName = content.substr(valueStart, valueEnd - valueStart);

    const wchar_t* appTag = L"<Application";
    const wchar_t* idAttr = L"Id=\"";

    size_t appPos = content.find(appTag);
    if (appPos != std::wstring::npos) {
        size_t idPos = content.find(idAttr, appPos);
        if (idPos != std::wstring::npos) {
            size_t idValueStart = idPos + wcslen(idAttr);
            size_t idValueEnd = content.find(L"\"", idValueStart);
            if (idValueEnd != std::wstring::npos) {
                g_appId = content.substr(idValueStart, idValueEnd - idValueStart);
            }
        }
    }

    return packageName;
}

bool IsPackageInstalled(const std::wstring& packageName) {
    if (packageName.empty()) {
        return false;
    }

    wchar_t logMsg[512];
    swprintf_s(logMsg, L"检查包是否已安装: %s", packageName.c_str());
    LogMessage(logMsg);

    wchar_t params[512];
    swprintf_s(params, L"-NoProfile -WindowStyle Hidden -Command \"if (Get-AppxPackage -Name '%s') { exit 0 } else { exit 1 }\"", packageName.c_str());

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"open";
    sei.lpFile = L"powershell.exe";
    sei.lpParameters = params;
    sei.nShow = SW_HIDE;

    if (ShellExecuteExW(&sei) && sei.hProcess != NULL) {
        WaitForSingleObject(sei.hProcess, 30000);
        DWORD exitCode;
        GetExitCodeProcess(sei.hProcess, &exitCode);
        CloseHandle(sei.hProcess);

        if (exitCode == 0) {
            LogMessage(L"✓ 检测到已安装此包");
            return true;
        }
    }

    LogMessage(L"✓ 未检测到已安装此包");
    return false;
}

bool UninstallAppxPackage(const std::wstring& packageName) {
    if (packageName.empty()) {
        return false;
    }

    wchar_t logMsg[512];
    swprintf_s(logMsg, L"正在卸载已安装的包: %s", packageName.c_str());
    LogMessage(logMsg);

    wchar_t params[512];
    swprintf_s(params, L"-NoProfile -WindowStyle Hidden -Command \"Get-AppxPackage -Name '%s' | Remove-AppxPackage\"", packageName.c_str());

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"open";
    sei.lpFile = L"powershell.exe";
    sei.lpParameters = params;
    sei.nShow = SW_HIDE;

    if (ShellExecuteExW(&sei) && sei.hProcess != NULL) {
        WaitForSingleObject(sei.hProcess, 60000);
        DWORD exitCode;
        GetExitCodeProcess(sei.hProcess, &exitCode);
        CloseHandle(sei.hProcess);

        if (exitCode == 0) {
            LogMessage(L"✓ 包卸载成功");
            return true;
        }
        wchar_t errorMsg[256];
        swprintf_s(errorMsg, L"✗ 包卸载失败 (退出码: %d)", exitCode);
        LogMessage(errorMsg);
    }
    else {
        LogMessage(L"✗ 无法启动PowerShell进行卸载");
    }

    return false;
}

bool InstallAppxPackage() {
    LogMessage(L"===== 开始安装AppxPackage =====");
    LogMessage(L"");
    
    std::wstring manifestPath = GetAppxManifestPath();

    if (manifestPath.empty()) {
        LogMessage(L"✗ 未找到AppxManifest.xml文件");
        return false;
    }

    g_packageName = GetPackageNameFromManifest();
    if (g_packageName.empty()) {
        LogMessage(L"✗ 无法从AppxManifest.xml获取包名，跳过卸载检查");
    }
    else {
        wchar_t logMsg[512];
        swprintf_s(logMsg, L"获取到包名: %s", g_packageName.c_str());
        LogMessage(logMsg);

        if (IsPackageInstalled(g_packageName)) {
            LogMessage(L"");
            LogMessage(L"检测到已安装，开始卸载...");
            if (!UninstallAppxPackage(g_packageName)) {
                LogMessage(L"✗ 卸载失败，继续尝试安装...");
            }
            LogMessage(L"");
        }
    }

    LogMessage(L"找到AppxManifest.xml，开始安装...");

    wchar_t params[512];
    swprintf_s(params, L"-NoProfile -WindowStyle Hidden -Command \"Add-AppxPackage -Register '%s'\"", manifestPath.c_str());

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"open";
    sei.lpFile = L"powershell.exe";
    sei.lpParameters = params;
    sei.nShow = SW_HIDE;

    if (ShellExecuteExW(&sei) && sei.hProcess != NULL) {
        WaitForSingleObject(sei.hProcess, 60000);
        DWORD exitCode;
        GetExitCodeProcess(sei.hProcess, &exitCode);
        CloseHandle(sei.hProcess);

        if (exitCode == 0) {
            LogMessage(L"✓ AppxPackage安装成功");
            LogMessage(L"");
            return true;
        }
        wchar_t errorMsg[256];
        swprintf_s(errorMsg, L"✗ AppxPackage安装失败 (退出码: %d)", exitCode);
        LogMessage(errorMsg);
    }
    else {
        LogMessage(L"✗ 无法启动PowerShell进行安装");
    }

    LogMessage(L"");
    return false;
}

void RestoreRegistry() {
    LogMessage(L"===== 恢复注册表设置 =====");
    LogMessage(L"");

    const wchar_t* devPath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock";

    SetRegDWORDWithLog(HKEY_LOCAL_MACHINE, devPath, L"AllowDevelopmentWithoutDevLicense",
        g_originalAllowDevelopment, g_originalAllowDevelopment, g_devValueExists, true);
    LogMessage(L"");

    SetRegDWORDWithLog(HKEY_LOCAL_MACHINE, devPath, L"AllowAllTrustedApps",
        g_originalAllowAllTrusted, g_originalAllowAllTrusted, g_allTrustedValueExists, true);
    LogMessage(L"");

    LogMessage(L"===== 注册表恢复完成 =====");
}


void ShowPage(int page) {
    g_currentPage = page;


    for (int i = 0; i < 3; i++) {
        if (g_pageWelcome[i]) ShowWindow(g_pageWelcome[i], SW_HIDE);
        if (g_pageLicense[i]) ShowWindow(g_pageLicense[i], SW_HIDE);
    }
    for (int i = 0; i < 2; i++) {
        if (g_pageProgress[i]) ShowWindow(g_pageProgress[i], SW_HIDE);
        if (g_pageComplete[i]) ShowWindow(g_pageComplete[i], SW_HIDE);
    }


    switch (page) {
    case PAGE_WELCOME:
        for (int i = 0; i < 3; i++)
            if (g_pageWelcome[i]) ShowWindow(g_pageWelcome[i], SW_SHOW);
        SetWindowTextW(g_hStaticHeader, L"欢迎使用芙芙启动器安装向导");
        SetWindowTextW(g_hStaticSubHeader, L"此向导将引导您完成芙芙启动器的安装");
        break;

    case PAGE_LICENSE:
        for (int i = 0; i < 3; i++)
            if (g_pageLicense[i]) ShowWindow(g_pageLicense[i], SW_SHOW);
        SetWindowTextW(g_hStaticHeader, L"许可协议");
        SetWindowTextW(g_hStaticSubHeader, L"请阅读以下许可协议并同意条款后继续安装");
        break;

    case PAGE_PROGRESS:
        for (int i = 0; i < 2; i++)
            if (g_pageProgress[i]) ShowWindow(g_pageProgress[i], SW_SHOW);
        SetWindowTextW(g_hStaticHeader, L"正在安装");
        SetWindowTextW(g_hStaticSubHeader, L"正在安装芙芙启动器，请稍候...");
        break;

    case PAGE_COMPLETE:
        for (int i = 0; i < 2; i++)
            if (g_pageComplete[i]) ShowWindow(g_pageComplete[i], SW_SHOW);
        SetWindowTextW(g_hStaticHeader, g_installSuccess ? L"安装完成" : L"安装失败");
        SetWindowTextW(g_hStaticSubHeader, g_installSuccess ?
            L"芙芙启动器已成功安装到您的计算机" : L"安装过程中出现错误");
        break;
    }

    UpdateNavigationButtons();
    InvalidateRect(g_hMainWnd, NULL, TRUE);
}

void UpdateNavigationButtons() {
    switch (g_currentPage) {
    case PAGE_WELCOME:
        EnableWindow(g_hBtnBack, FALSE);
        EnableWindow(g_hBtnNext, TRUE);
        SetWindowTextW(g_hBtnNext, L"下一步");
        break;
    case PAGE_LICENSE:
        EnableWindow(g_hBtnBack, TRUE);
        EnableWindow(g_hBtnNext, g_agreedToLicense);
        SetWindowTextW(g_hBtnNext, L"下一步");
        break;
    case PAGE_PROGRESS:
        EnableWindow(g_hBtnBack, FALSE);
        EnableWindow(g_hBtnNext, FALSE);
        SetWindowTextW(g_hBtnNext, L"下一步");
        break;
    case PAGE_COMPLETE:
        EnableWindow(g_hBtnBack, FALSE);
        EnableWindow(g_hBtnNext, TRUE);
        SetWindowTextW(g_hBtnNext, L"完成");
        break;
    }
}

void OnNextClicked() {
    if (g_currentPage == PAGE_COMPLETE) {
        PostQuitMessage(0);
        return;
    }

    if (g_currentPage == PAGE_WELCOME) {
        ShowPage(PAGE_LICENSE);
    }
    else if (g_currentPage == PAGE_LICENSE) {
        ShowPage(PAGE_PROGRESS);

        HANDLE hThread = CreateThread(NULL, 0, PerformConfigurationThread, NULL, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);
        }
    }
}

void OnBackClicked() {
    if (g_currentPage == PAGE_LICENSE) {
        ShowPage(PAGE_WELCOME);
    }
}


DWORD WINAPI PerformConfigurationThread(LPVOID lpParam) {

    auto UpdateProgress = [](int percent) {
        PostMessageW(g_hMainWnd, WM_UPDATE_PROGRESS, percent, 0);
        };

    UpdateProgress(10);


    if (!PrepareInstallDirectory()) {
        PostMessage(g_hMainWnd, WM_CONFIGURATION_COMPLETE, 0, 0);
        return 0;
    }

    if (!CheckDotNet8SDK()) {
        if (!InstallDotNet8SDK()) {

            PostMessage(g_hMainWnd, WM_CONFIGURATION_COMPLETE, 0, 0);
            return 0;
        }
    }

    UpdateProgress(30);

    InstallWebview2();

    LogMessage(L"===== 开始配置开发者模式 =====");
    const wchar_t* devPath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock";
    SetRegDWORDWithLog(HKEY_LOCAL_MACHINE, devPath, L"AllowDevelopmentWithoutDevLicense",
        1, g_originalAllowDevelopment, g_devValueExists, false);

    UpdateProgress(40);

    SetRegDWORDWithLog(HKEY_LOCAL_MACHINE, devPath, L"AllowAllTrustedApps",
        1, g_originalAllowAllTrusted, g_allTrustedValueExists, false);

    UpdateProgress(50);

    ExecutePowerShellWithLog(L"LocalMachine");
    ExecutePowerShellWithLog(L"CurrentUser");

    UpdateProgress(60);

    bool installSuccess = InstallAppxPackage();

    UpdateProgress(80);

    RestoreRegistry();

    UpdateProgress(90);

    if (installSuccess) {
        LogMessage(L"安装流程全部完成！");


        PWSTR documentsPath = NULL;
        HRESULT hr = SHGetKnownFolderPath(FOLDERID_Documents, 0, NULL, &documentsPath);
        if (SUCCEEDED(hr)) {
            std::wstring destDir = documentsPath;
            destDir += L"\\fufu";
            CreateDirectoryW(destDir.c_str(), NULL);

            std::wstring destPath = destDir + L"\\app.ico";
            std::wstring sourcePath = g_installFolderPath + L"\\app.ico";
            if (CopyFileW(sourcePath.c_str(), destPath.c_str(), FALSE)) {
                PWSTR desktopPath = NULL;
                HRESULT hr2 = SHGetKnownFolderPath(FOLDERID_Desktop, 0, NULL, &desktopPath);
                if (SUCCEEDED(hr2)) {
                    std::wstring desktopDest = desktopPath;
                    desktopDest += L"\\芙芙启动器.lnk";
                    std::wstring lnkSource = g_installFolderPath + L"\\芙芙启动器.lnk";
                    if (CopyFileW(lnkSource.c_str(), desktopDest.c_str(), FALSE)) {
                        LogMessage(L"✓ 桌面快捷方式创建成功");
                    }
                    else {
                        LogMessage(L"✗ 桌面快捷方式创建失败");
                    }
                    CoTaskMemFree(desktopPath);
                }
                CoTaskMemFree(documentsPath);
            }
        }
    }

    UpdateProgress(100);

    PostMessage(g_hMainWnd, WM_CONFIGURATION_COMPLETE, installSuccess ? 1 : 0, 0);
    return 0;
}


LRESULT CALLBACK WindowProcedure(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {

        int btnY = WINDOW_HEIGHT - BUTTON_HEIGHT - BUTTON_BOTTOM_MARGIN;
        int xCancel = WINDOW_WIDTH - BUTTON_RIGHT_MARGIN - BUTTON_WIDTH;
        int xNext = xCancel - BUTTON_GAP - BUTTON_WIDTH;
        int xBack = xNext - BUTTON_GAP - BUTTON_WIDTH;

        g_hStaticHeader = CreateWindowW(L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            CONTENT_LEFT, HEADER_TOP, CONTENT_WIDTH, 35, hwnd, NULL, GetModuleHandle(NULL), NULL);

        g_hStaticSubHeader = CreateWindowW(L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            CONTENT_LEFT, SUBHEADER_TOP, CONTENT_WIDTH, 45, hwnd, NULL, GetModuleHandle(NULL), NULL);

        HFONT hTitleFont = CreateFontW(24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"微软雅黑");
        SendMessageW(g_hStaticHeader, WM_SETFONT, (WPARAM)hTitleFont, TRUE);

        HFONT hSubFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"微软雅黑");
        SendMessageW(g_hStaticSubHeader, WM_SETFONT, (WPARAM)hSubFont, TRUE);

        g_hBtnBack = CreateWindowW(L"BUTTON", L"上一步",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
            xBack, btnY, BUTTON_WIDTH, BUTTON_HEIGHT, hwnd, (HMENU)100, GetModuleHandle(NULL), NULL);

        g_hBtnNext = CreateWindowW(L"BUTTON", L"下一步",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            xNext, btnY, BUTTON_WIDTH, BUTTON_HEIGHT, hwnd, (HMENU)101, GetModuleHandle(NULL), NULL);

        g_hBtnCancel = CreateWindowW(L"BUTTON", L"取消",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
            xCancel, btnY, BUTTON_WIDTH, BUTTON_HEIGHT, hwnd, (HMENU)102, GetModuleHandle(NULL), NULL);

        HFONT hButtonFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"微软雅黑");
        SendMessageW(g_hBtnBack, WM_SETFONT, (WPARAM)hButtonFont, TRUE);
        SendMessageW(g_hBtnNext, WM_SETFONT, (WPARAM)hButtonFont, TRUE);
        SendMessageW(g_hBtnCancel, WM_SETFONT, (WPARAM)hButtonFont, TRUE);

        g_pageWelcome[0] = CreateWindowW(L"STATIC", L"芙芙启动器",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            CONTENT_LEFT, 150, CONTENT_WIDTH, 50, hwnd, NULL, GetModuleHandle(NULL), NULL);
        SendMessageW(g_pageWelcome[0], WM_SETFONT, (WPARAM)hTitleFont, TRUE);

        g_pageWelcome[1] = CreateWindowW(L"STATIC",
            L"\n点击\"下一步\"继续安装",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            CONTENT_LEFT, 220, CONTENT_WIDTH, 120, hwnd, NULL, GetModuleHandle(NULL), NULL);
        SendMessageW(g_pageWelcome[1], WM_SETFONT, (WPARAM)hSubFont, TRUE);

        g_pageLicense[0] = CreateWindowW(L"STATIC",
            L"请访问以下链接查看许可协议：",
            WS_CHILD | SS_LEFT,
            CONTENT_LEFT, LICENSE_TEXT_TOP, CONTENT_WIDTH, 35, hwnd, NULL, GetModuleHandle(NULL), NULL);
        SendMessageW(g_pageLicense[0], WM_SETFONT, (WPARAM)hSubFont, TRUE);

        g_pageLicense[1] = CreateWindowW(L"STATIC", L"https://philia093.cyou/",
            WS_CHILD | SS_LEFT | SS_NOTIFY,
            CONTENT_LEFT, LICENSE_LINK_TOP, CONTENT_WIDTH, 35, hwnd, (HMENU)201, GetModuleHandle(NULL), NULL);
        SendMessageW(g_pageLicense[1], WM_SETFONT, (WPARAM)hSubFont, TRUE);

        g_pageLicense[2] = CreateWindowW(L"BUTTON", L"我已阅读并同意许可协议",
            WS_CHILD | BS_AUTOCHECKBOX,
            CONTENT_LEFT, LICENSE_CHECK_TOP, CONTENT_WIDTH, 40, hwnd, (HMENU)202, GetModuleHandle(NULL), NULL);
        SendMessageW(g_pageLicense[2], WM_SETFONT, (WPARAM)hSubFont, TRUE);

        g_hProgressBar = CreateWindowExW(0, PROGRESS_CLASSW, NULL,
            WS_CHILD | PBS_SMOOTH,
            CONTENT_LEFT, PROGRESS_BAR_TOP, CONTENT_WIDTH, 25, hwnd, NULL, GetModuleHandle(NULL), NULL);
        SendMessageW(g_hProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));

        g_pageProgress[0] = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            CONTENT_LEFT, LOG_TOP, CONTENT_WIDTH, LOG_HEIGHT, hwnd, NULL, GetModuleHandle(NULL), NULL);
        SendMessageW(g_pageProgress[0], WM_SETFONT, (WPARAM)hSubFont, TRUE);
        g_hEditLog = g_pageProgress[0];

        g_pageComplete[0] = CreateWindowW(L"STATIC", L"",
            WS_CHILD | SS_CENTER,
            CONTENT_LEFT, COMPLETE_TITLE_TOP, CONTENT_WIDTH, 40, hwnd, NULL, GetModuleHandle(NULL), NULL);
        SendMessageW(g_pageComplete[0], WM_SETFONT, (WPARAM)hTitleFont, TRUE);

        g_pageComplete[1] = CreateWindowW(L"STATIC", L"",
            WS_CHILD | SS_CENTER,
            CONTENT_LEFT, COMPLETE_TEXT_TOP, CONTENT_WIDTH, 130, hwnd, NULL, GetModuleHandle(NULL), NULL);
        SendMessageW(g_pageComplete[1], WM_SETFONT, (WPARAM)hSubFont, TRUE);

        ShowPage(PAGE_WELCOME);
        break;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case 100:
            OnBackClicked();
            break;
        case 101:
            OnNextClicked();
            break;
        case 102:
            if (g_currentPage == PAGE_PROGRESS) {
                MessageBoxW(hwnd, L"安装正在进行中，无法取消！", L"提示", MB_ICONINFORMATION);
            }
            else {
                PostQuitMessage(0);
            }
            break;
        case 201:
        {
            SHELLEXECUTEINFOW sei = { sizeof(sei) };
            sei.lpVerb = L"open";
            sei.lpFile = L"https://philia093.cyou/";
            sei.nShow = SW_SHOW;
            ShellExecuteExW(&sei);
        }
        break;
        case 202:
        {
            g_agreedToLicense = (SendMessageW(g_pageLicense[2], BM_GETCHECK, 0, 0) == BST_CHECKED);
            UpdateNavigationButtons();
        }
        break;
        }
        break;

    case WM_ERASEBKGND: {
        RECT rc;
        GetClientRect(hwnd, &rc);
        HBRUSH hBrush = g_hBackgroundBrush ? g_hBackgroundBrush : (HBRUSH)(COLOR_WINDOW + 1);
        FillRect((HDC)wParam, &rc, hBrush);
        return 1;
    }

    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = (HDC)wParam;
        HWND hStatic = (HWND)lParam;
        HBRUSH hBrush = g_hBackgroundBrush ? g_hBackgroundBrush : (HBRUSH)(COLOR_WINDOW + 1);

        if (hStatic == g_pageLicense[1]) {
            SetTextColor(hdc, RGB(0, 102, 204));
        }
        SetBkColor(hdc, WINDOW_BACKGROUND_COLOR);
        SetBkMode(hdc, OPAQUE);
        return (INT_PTR)hBrush;
    }

    case WM_CTLCOLORBTN:
    case WM_CTLCOLOREDIT:
    {
        HDC hdc = (HDC)wParam;
        HBRUSH hBrush = g_hBackgroundBrush ? g_hBackgroundBrush : (HBRUSH)(COLOR_WINDOW + 1);
        SetBkColor(hdc, WINDOW_BACKGROUND_COLOR);
        SetBkMode(hdc, OPAQUE);
        return (INT_PTR)hBrush;
    }
    break;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        RECT rcClient;
        GetClientRect(hwnd, &rcClient);

        HBRUSH hBrushBg = g_hBackgroundBrush ? g_hBackgroundBrush : (HBRUSH)(COLOR_WINDOW + 1);
        FillRect(hdc, &rcClient, hBrushBg);

        int lineY = rcClient.bottom - 46;
        HPEN hPenLine = CreatePen(PS_SOLID, 1, RGB(160, 160, 160));
        HPEN hOldPen = (HPEN)SelectObject(hdc, hPenLine);

        MoveToEx(hdc, 20, lineY, NULL);
        LineTo(hdc, rcClient.right - 20, lineY);

        SelectObject(hdc, hOldPen);
        DeleteObject(hPenLine);

        EndPaint(hwnd, &ps);
        break;
    }

    case WM_UPDATE_PROGRESS:
        SendMessageW(g_hProgressBar, PBM_SETPOS, wParam, 0);
        break;

    case WM_CONFIGURATION_COMPLETE:
        g_installSuccess = (wParam == 1);
        ShowPage(PAGE_COMPLETE);

        if (g_installSuccess) {
            SetWindowTextW(g_pageComplete[0], L"✓ 安装成功");
            SetWindowTextW(g_pageComplete[1],
                L"芙芙启动器已成功安装到您的计算机\n\n"
                L"桌面快捷方式已创建\n"
                L"您可以从桌面快捷方式启动程序");
        }
        else {
            SetWindowTextW(g_pageComplete[0], L"✗ 安装失败");
            SetWindowTextW(g_pageComplete[1],
                L"安装过程中出现错误\n\n"
                L"请查看日志信息并尝试重新安装\n"
                L"或联系技术支持获取帮助");
        }
        break;

    case WM_DESTROY:

        if (g_hLogFile != INVALID_HANDLE_VALUE) {
            CloseHandle(g_hLogFile);
            g_hLogFile = INVALID_HANDLE_VALUE;
        }
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}


int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE, _In_ LPWSTR, _In_ int nCmdShow) {

    BOOL isAdmin = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(elevation);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, size, &size)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    if (!isAdmin) {
        MessageBoxW(NULL,
            L"此程序需要以管理员权限运行！\n\n请右键点击程序，选择\"以管理员身份运行\"。",
            L"权限不足", MB_ICONWARNING);
        return 1;
    }


    INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_WIN95_CLASSES | ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icex);


    PWSTR documentsPath = NULL;
    HRESULT hr = SHGetKnownFolderPath(FOLDERID_Documents, 0, NULL, &documentsPath);
    if (SUCCEEDED(hr)) {
        std::wstring fufuDir = documentsPath;
        fufuDir += L"\\fufu";
        CreateDirectoryW(fufuDir.c_str(), NULL);


        time_t now = time(NULL);
        struct tm timeinfo;
        localtime_s(&timeinfo, &now);

        wchar_t fileName[256];
        swprintf_s(fileName, L"%s\\安装日志_%04d-%02d-%02d_%02d-%02d-%02d.txt",
            fufuDir.c_str(),
            timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
            timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);

        g_hLogFile = CreateFileW(fileName, GENERIC_WRITE, FILE_SHARE_READ, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

        if (g_hLogFile != INVALID_HANDLE_VALUE) {

            BYTE bom[] = { 0xEF, 0xBB, 0xBF };
            DWORD written;
            WriteFile(g_hLogFile, bom, 3, &written, NULL);


            char header[256];
            sprintf_s(header, "芙芙启动器安装日志 - %04d-%02d-%02d %02d:%02d:%02d\r\n",
                timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
            WriteFile(g_hLogFile, header, (DWORD)strlen(header), &written, NULL);
        }

        CoTaskMemFree(documentsPath);
    }


    g_hBackgroundBrush = CreateSolidBrush(WINDOW_BACKGROUND_COLOR);

    WNDCLASSEXW wc = { sizeof(WNDCLASSEXW) };
    wc.lpfnWndProc = WindowProcedure;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"MSIInstallerClass";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = g_hBackgroundBrush ? g_hBackgroundBrush : (HBRUSH)(COLOR_WINDOW + 1);
    wc.hIcon = wc.hIconSm = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDR_MAINICON));

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(NULL, L"窗口类注册失败", L"错误", MB_ICONERROR);
        if (g_hLogFile != INVALID_HANDLE_VALUE) CloseHandle(g_hLogFile);
        return 1;
    }

    RECT rcClient = { 0, 0, WINDOW_WIDTH, WINDOW_HEIGHT };
    AdjustWindowRect(&rcClient, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE);

    g_hMainWnd = CreateWindowExW(
        0, L"MSIInstallerClass", L"芙芙启动器安装向导",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, rcClient.right - rcClient.left, rcClient.bottom - rcClient.top, NULL, NULL, hInstance, NULL
    );

    if (!g_hMainWnd) {
        MessageBoxW(NULL, L"窗口创建失败", L"错误", MB_ICONERROR);
        if (g_hLogFile != INVALID_HANDLE_VALUE) CloseHandle(g_hLogFile);
        return 1;
    }


    RECT rc;
    GetWindowRect(g_hMainWnd, &rc);
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    SetWindowPos(g_hMainWnd, NULL,
        (screenWidth - (rc.right - rc.left)) / 2,
        (screenHeight - (rc.bottom - rc.top)) / 2,
        0, 0, SWP_NOZORDER | SWP_NOSIZE);
    ShowWindow(g_hMainWnd, SW_HIDE);
    documentsPath = NULL;
    hr = SHGetKnownFolderPath(FOLDERID_Documents, 0, NULL, &documentsPath);
    if (FAILED(hr)) {
        MessageBoxW(NULL, L"无法获取文档文件夹路径", L"错误", MB_ICONERROR);
        if (g_hLogFile != INVALID_HANDLE_VALUE) CloseHandle(g_hLogFile);
        return 1;
    }

    std::wstring fufuDir = documentsPath;
    fufuDir += L"\\fufu";
    CreateDirectoryW(fufuDir.c_str(), NULL);
    g_installFolderPath = fufuDir + L"\\Install";

    if (GetFileAttributesW(g_installFolderPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        wchar_t cmdParams[512];
        swprintf_s(cmdParams, L"/c rd /s /q \"%s\"", g_installFolderPath.c_str());
        SHELLEXECUTEINFOW seiDel = { sizeof(seiDel) };
        seiDel.fMask = SEE_MASK_NOCLOSEPROCESS;
        seiDel.lpVerb = L"open";
        seiDel.lpFile = L"cmd.exe";
        seiDel.lpParameters = cmdParams;
        seiDel.nShow = SW_HIDE;
        if (ShellExecuteExW(&seiDel) && seiDel.hProcess != NULL) {
            WaitForSingleObject(seiDel.hProcess, 30000);
            CloseHandle(seiDel.hProcess);
        }
    }


    auto ExtractResource = [](UINT resourceId, const std::wstring& outputPath) -> bool {
        HMODULE hModule = GetModuleHandle(NULL);
        HRSRC hRes = FindResourceW(hModule, MAKEINTRESOURCEW(resourceId), RT_RCDATA);
        if (!hRes) return false;

        HGLOBAL hData = LoadResource(hModule, hRes);
        if (!hData) return false;

        DWORD dataSize = SizeofResource(hModule, hRes);
        void* pData = LockResource(hData);
        if (!pData || dataSize == 0) return false;

        HANDLE hFile = CreateFileW(outputPath.c_str(), GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        DWORD bytesWritten;
        BOOL result = WriteFile(hFile, pData, dataSize, &bytesWritten, NULL);
        CloseHandle(hFile);

        return (result && bytesWritten == dataSize);
        };

    std::wstring sevenZipExePath = fufuDir + L"\\7z.exe";
    std::wstring sevenZipDllPath = fufuDir + L"\\7z.dll";
    std::wstring temp7zPath = fufuDir + L"\\Install_temp.7z";
    std::wstring webview2SetupPath = fufuDir + L"\\Webview2Setup.exe";

    bool extractSuccess = true;
    if (!ExtractResource(IDR_7ZEXE, sevenZipExePath)) extractSuccess = false;
    if (!ExtractResource(IDR_7ZDLL, sevenZipDllPath)) extractSuccess = false;
    if (!ExtractResource(IDR_INSTALL7Z, temp7zPath)) extractSuccess = false;
    if (!ExtractResource(IDR_WEBVIEW2SETUP, webview2SetupPath)) extractSuccess = false;

    if (!extractSuccess) {
        CoTaskMemFree(documentsPath);
        MessageBoxW(NULL, L"无法提取安装资源", L"错误", MB_ICONERROR);
        if (g_hLogFile != INVALID_HANDLE_VALUE) CloseHandle(g_hLogFile);
        return 1;
    }


    CreateDirectoryW(g_installFolderPath.c_str(), NULL);
    wchar_t params[1024];
    swprintf_s(params, L"x \"%s\" -o\"%s\" -y", temp7zPath.c_str(), g_installFolderPath.c_str());

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"open";
    sei.lpFile = sevenZipExePath.c_str();
    sei.lpParameters = params;
    sei.nShow = SW_HIDE;

    if (ShellExecuteExW(&sei) && sei.hProcess != NULL) {
        WaitForSingleObject(sei.hProcess, 120000);
        DWORD exitCode;
        GetExitCodeProcess(sei.hProcess, &exitCode);
        CloseHandle(sei.hProcess);
        extractSuccess = (exitCode == 0);
    }


    DeleteFileW(temp7zPath.c_str());
    CoTaskMemFree(documentsPath);

    if (!extractSuccess) {
        DeleteFileW(sevenZipExePath.c_str());
        DeleteFileW(sevenZipDllPath.c_str());
        DeleteFileW(webview2SetupPath.c_str());
        MessageBoxW(NULL, L"解压Install.7z失败", L"错误", MB_ICONERROR);
        if (g_hLogFile != INVALID_HANDLE_VALUE) CloseHandle(g_hLogFile);
        return 1;
    }


    ShowWindow(g_hMainWnd, nCmdShow);
    UpdateWindow(g_hMainWnd);


    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    DeleteFileW(sevenZipExePath.c_str());
    DeleteFileW(sevenZipDllPath.c_str());
    DeleteFileW(webview2SetupPath.c_str());

    if (g_hBackgroundBrush) {
        DeleteObject(g_hBackgroundBrush);
        g_hBackgroundBrush = NULL;
    }

    return (int)msg.wParam;
}