#pragma once

#include <string>

bool CheckDotNet8SDK();   // 检查是否已安装 .NET 8 SDK
bool InstallDotNet8SDK(); // 触发安装 .NET 8 SDK（winget 或手动提示）
bool InstallWebview2();   // 触发安装 WebView2 运行时（winget 或手动提示）
bool IsWebView2Installed(); // 检查 WebView2 运行时是否已安装
