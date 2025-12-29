#include <windows.h>
#include <string>
#include <vector>
#include <cwchar>
#include "Globals.h"
#include "EnvChecks.h"
#include "FufuInstall.h"

bool CheckDotNet8SDK() {
    LogMessage(L"检查.NET 8 SDK...");

    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE }; // 允许继承的匿名管道用于读取子进程输出
    HANDLE hReadPipe, hWritePipe;

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        LogMessage(L"CreatePipe 失败，错误代码: " + std::to_wstring(GetLastError()));
        return false;
    }

    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0); // 仅子进程继承写端

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;   // 重定向 stdout
    si.hStdError = hWritePipe;    // 重定向 stderr
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {};
    wchar_t cmdLine[] = L"dotnet --list-sdks"; // 列出已安装 SDK

    LogMessage(L"启动命令: dotnet --list-sdks");
    if (!CreateProcessW(nullptr, cmdLine, nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        LogMessage(L"CreateProcessW 失败，错误代码: " + std::to_wstring(GetLastError()));
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        LogMessage(L".NET SDK未安装");
        return false;
    }

    CloseHandle(hWritePipe);

    std::string output;
    char buffer[256];
    DWORD bytesRead;
    DWORD totalBytes = 0;

    while (true) {
        BOOL readOk = ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr);
        if (!readOk) {
            DWORD err = GetLastError();
            if (err != ERROR_BROKEN_PIPE) {
                LogMessage(L"读取 dotnet 输出失败，错误代码: " + std::to_wstring(err));
            }
            break;
        }
        if (bytesRead == 0) break;
        buffer[bytesRead] = 0;
        totalBytes += bytesRead;
        output += buffer; // 收集输出文本
    }

    CloseHandle(hReadPipe);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    std::wstring outputWide(output.begin(), output.end());
    LogMessage(L"dotnet --list-sdks 进程退出代码: " + std::to_wstring(exitCode));
    LogMessage(L"dotnet --list-sdks 输出字节数: " + std::to_wstring(totalBytes));
    if (outputWide.empty()) {
        LogMessage(L"dotnet --list-sdks 无输出");
    } else {
        LogMessage(L"dotnet --list-sdks 输出:\n" + outputWide);
    }

    bool found = output.find("8.") != std::string::npos; // 查找 8.x SDK

    if (found) {
        LogMessage(L".NET 8 SDK已安装");
    }
    else {
        LogMessage(L".NET 8 SDK未检测到");
    }

    return found;
}

bool InstallDotNet8SDK() {
    int result = MessageBoxW(g_hMainWnd,
        L"未检测到 .NET 8 SDK，是否自动安装？\n\n"
        L"点击[是]将使用 winget 自动安装\n"
        L"点击[否]将显示手动安装命令",
        L"缺少依赖项", MB_YESNO | MB_ICONQUESTION);

    LogMessage(result == IDYES ? L"用户选择自动安装 .NET 8 SDK" : L"用户选择手动安装 .NET 8 SDK");

    if (result == IDYES) {
        LogMessage(L"正在通过winget安装.NET 8 SDK...");
        LogMessage(L"安装命令: cmd /c winget install Microsoft.DotNet.SDK.8 --accept-source-agreements --accept-package-agreements");

        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.fMask = SEE_MASK_NOCLOSEPROCESS; // 需等待安装完成
        sei.hwnd = g_hMainWnd;
        sei.lpVerb = L"runas"; // 以管理员权限运行
        sei.lpFile = L"cmd.exe";
        sei.lpParameters = L"/c winget install Microsoft.DotNet.SDK.8 --accept-source-agreements --accept-package-agreements";
        sei.nShow = SW_SHOW;

        if (ShellExecuteExW(&sei)) {
            WaitForSingleObject(sei.hProcess, INFINITE);
            DWORD exitCode = 0;
            GetExitCodeProcess(sei.hProcess, &exitCode);
            CloseHandle(sei.hProcess);
            LogMessage(L"winget 安装 .NET 8 SDK 完成，退出代码: " + std::to_wstring(exitCode));
            return exitCode == 0;
        }
        else {
            LogMessage(L"错误: 无法启动winget安装，错误代码: " + std::to_wstring(GetLastError()));
            return false;
        }
    }
    else {
        MessageBoxW(g_hMainWnd,
            L"请在管理员命令提示符中运行以下命令安装 .NET 8 SDK:\n\n"
            L"winget install Microsoft.DotNet.SDK.8",
            L"手动安装说明", MB_OK | MB_ICONINFORMATION);
        LogMessage(L"已显示 .NET 8 SDK 手动安装命令");
        return false;
    }
}

bool InstallWebview2() {
    int result = MessageBoxW(g_hMainWnd,
        L"未检测到 WebView2 运行时，是否使用 winget 自动安装？\n\n"
        L"点击[是]将使用 winget 自动安装 WebView2 运行时\n"
        L"点击[否]将显示手动安装命令",
        L"缺少依赖项", MB_YESNO | MB_ICONQUESTION);

    LogMessage(result == IDYES ? L"用户选择自动安装 WebView2" : L"用户选择手动安装 WebView2");

    if (result == IDYES) {
        LogMessage(L"正在通过 winget 安装 WebView2 运行时...");
        LogMessage(L"安装命令: cmd /c winget install --id Microsoft.EdgeWebView2Runtime -e --accept-source-agreements --accept-package-agreements");

        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.hwnd = g_hMainWnd;
        sei.lpVerb = L"runas";
        sei.lpFile = L"cmd.exe";
        sei.lpParameters = L"/c winget install --id Microsoft.EdgeWebView2Runtime -e --accept-source-agreements --accept-package-agreements";
        sei.nShow = SW_SHOW;

        if (ShellExecuteExW(&sei)) {
            WaitForSingleObject(sei.hProcess, INFINITE);
            DWORD exitCode = 0;
            GetExitCodeProcess(sei.hProcess, &exitCode); // 读取安装退出码
            CloseHandle(sei.hProcess);
            LogMessage(L"winget 安装 WebView2 完成，退出代码: " + std::to_wstring(exitCode));
            return exitCode == 0;
        }
        else {
            LogMessage(L"错误: 无法启动 winget 安装 WebView2，错误代码: " + std::to_wstring(GetLastError()));
            return false;
        }
    }
    else {
        MessageBoxW(g_hMainWnd,
            L"请在管理员命令提示符中运行以下命令安装 WebView2 运行时:\n\n"
            L"winget install --id Microsoft.EdgeWebView2Runtime -e --accept-source-agreements --accept-package-agreements",
            L"手动安装说明", MB_OK | MB_ICONINFORMATION);
        LogMessage(L"已显示 WebView2 手动安装命令");
        return false;
    }
}

bool IsWebView2Installed() {
    LogMessage(L"检测 WebView2 运行时是否已安装...");
    const wchar_t* arpKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    HKEY hKey = nullptr;

    auto checkBranch = [&](REGSAM wowFlag) -> bool {
        LogMessage(std::wstring(L"检查注册表分支 (" ) + (wowFlag == KEY_WOW64_64KEY ? L"64" : L"32") + L" 位)...");
        DWORD matchCount = 0;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, arpKey, 0, KEY_READ | wowFlag, &hKey) == ERROR_SUCCESS) {
            DWORD index = 0;
            wchar_t name[256];
            DWORD nameLen = sizeof(name) / sizeof(name[0]);
            FILETIME ft;
            while (RegEnumKeyExW(hKey, index, name, &nameLen, nullptr, nullptr, nullptr, &ft) == ERROR_SUCCESS) {
                HKEY hSub = nullptr;
                if (RegOpenKeyExW(hKey, name, 0, KEY_READ | wowFlag, &hSub) == ERROR_SUCCESS) {
                    wchar_t displayName[512] = { 0 };
                    DWORD sz = sizeof(displayName);
                    if (RegQueryValueExW(hSub, L"DisplayName", nullptr, nullptr, (LPBYTE)displayName, &sz) == ERROR_SUCCESS) {
                        // 通过 DisplayName 包含关键字判断是否存在 WebView2 运行时
                        if (wcsstr(displayName, L"WebView2") || wcsstr(displayName, L"Edge WebView2") || wcsstr(displayName, L"Microsoft Edge WebView2 Runtime") || wcsstr(displayName, L"WebView2 Runtime")) {
                            matchCount++;
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
            LogMessage(L"遍历完毕，匹配次数: " + std::to_wstring(matchCount));
            RegCloseKey(hKey);
        }
        else {
            LogMessage(L"无法打开注册表分支，错误代码: " + std::to_wstring(GetLastError()));
        }
        return false;
    };

    if (checkBranch(KEY_WOW64_64KEY)) return true; // 先查 64 位卸载键
    if (checkBranch(KEY_WOW64_32KEY)) return true; // 再查 32 位卸载键

    LogMessage(L"未检测到 WebView2 运行时");
    return false;
}
