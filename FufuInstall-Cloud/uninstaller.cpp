#include "uninstaller.h"
#include "Globals.h"
#include "FufuInstall.h"

#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>

namespace {
    std::wstring GetRecordFilePath() {
        return kDownloadBaseDir + L"\\install_path.txt";
    }

    bool LoadRecordedInstallPath(std::wstring& outPath) {
        outPath.clear();
        std::wstring recordPath = GetRecordFilePath();

        HANDLE hFile = CreateFileW(recordPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }

        DWORD size = GetFileSize(hFile, nullptr);
        if (size == INVALID_FILE_SIZE || size == 0 || size > 4096) {
            CloseHandle(hFile);
            return false;
        }

        std::wstring buffer;
        buffer.resize(size / sizeof(wchar_t) + 2, L'\0');

        DWORD bytesRead = 0;
        if (!ReadFile(hFile, buffer.data(), size, &bytesRead, nullptr)) {
            CloseHandle(hFile);
            return false;
        }
        CloseHandle(hFile);

        buffer.resize(bytesRead / sizeof(wchar_t));
        // 去掉可能的结尾换行符
        while (!buffer.empty() && (buffer.back() == L'\r' || buffer.back() == L'\n' || buffer.back() == L'\0')) {
            buffer.pop_back();
        }

        outPath = buffer;
        return !outPath.empty();
    }

    bool WriteRecordedInstallPath(const std::wstring& installPath) {
        if (installPath.empty()) return false;

        HANDLE hFile = CreateFileW(GetRecordFilePath().c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }

        DWORD toWrite = static_cast<DWORD>(installPath.size() * sizeof(wchar_t));
        DWORD written = 0;
        BOOL ok = WriteFile(hFile, installPath.c_str(), toWrite, &written, nullptr);
        CloseHandle(hFile);
        return ok && written == toWrite;
    }

    bool DeleteDirectoryRecursive(const std::wstring& path) {
        if (path.empty()) return false;

        wchar_t target[MAX_PATH + 2] = {};
        wcsncpy_s(target, path.c_str(), MAX_PATH);
        target[wcslen(target) + 1] = L'\0'; // double-null terminate

        SHFILEOPSTRUCTW op{};
        op.wFunc = FO_DELETE;
        op.pFrom = target;
        op.fFlags = FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI;

        return SHFileOperationW(&op) == 0;
    }
}

bool RemovePreviousInstall(const std::wstring& currentInstallPath) {
    std::wstring recordedPath;
    bool hasRecord = LoadRecordedInstallPath(recordedPath);

    if (!hasRecord || recordedPath.empty()) {
        LogMessage(L"未找到历史安装记录，跳过旧版本清理");
        return true;
    }

    // 避免误删系统目录：必须包含应用文件夹名
    if (recordedPath.find(kAppFolderName) == std::wstring::npos) {
        LogMessage(L"跳过删除：记录的路径不包含应用目录名: " + recordedPath);
        return true;
    }

    if (GetFileAttributesW(recordedPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        LogMessage(L"旧安装目录不存在，跳过删除: " + recordedPath);
        return true;
    }

    LogMessage(L"删除之前的安装目录: " + recordedPath);
    if (!DeleteDirectoryRecursive(recordedPath)) {
        LogMessage(L"删除旧安装目录失败: " + recordedPath);
        return false;
    }

    LogMessage(L"旧安装目录删除成功: " + recordedPath);

    // 若旧记录路径与当前不同，清理记录文件，避免重复清理
    if (!currentInstallPath.empty() && _wcsicmp(recordedPath.c_str(), currentInstallPath.c_str()) != 0) {
        std::wstring recordFile = GetRecordFilePath();
        if (DeleteFileW(recordFile.c_str())) {
            LogMessage(L"已删除旧安装记录文件: " + recordFile);
        }
        else {
            DWORD err = GetLastError();
            if (err != ERROR_FILE_NOT_FOUND) {
                LogMessage(L"警告: 删除旧安装记录文件失败: " + recordFile + L"，错误码=" + std::to_wstring(err));
            }
        }
    }

    return true;
}

bool RecordInstallLocation(const std::wstring& installPath) {
    if (installPath.empty()) return false;

    LogMessage(L"记录安装路径到文件: " + installPath);

    // 确保记录目录存在
    CreateDirectoryW(kDownloadBaseDir.c_str(), nullptr);

    if (!WriteRecordedInstallPath(installPath)) {
        LogMessage(L"无法写入安装记录文件");
        return false;
    }

    LogMessage(L"已记录安装路径: " + installPath);
    return true;
}