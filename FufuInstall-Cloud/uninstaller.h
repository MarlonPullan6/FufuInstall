#pragma once

#include <string>

bool RemovePreviousInstall(const std::wstring& currentInstallPath); // 删除记录的旧安装目录
bool RecordInstallLocation(const std::wstring& installPath);         // 记录当前安装目录
