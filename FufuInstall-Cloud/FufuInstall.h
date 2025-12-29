#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include "Globals.h"

bool DeleteFileIfExists(const std::wstring& path);                                   // 若存在则删除文件
void CleanupTemporaryFiles();                                                        // 清理临时文件
LRESULT CALLBACK WindowProcedure(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); // 主窗口消息处理
void LogMessage(const std::wstring& message);                                        // 写入日志并显示
bool ExtractResourceToFile(UINT resourceId, LPCWSTR resourceType, const std::wstring& filePath); // 从资源解压到文件
bool Extract7zArchive(const std::wstring& archivePath, const std::wstring& destPath); // 解压 7z 压缩包
DWORD ReadRegDWORD(HKEY hKeyRoot, LPCWSTR subKey, LPCWSTR valueName, DWORD defaultValue);       // 读取 DWORD 注册表值
bool SetRegDWORDWithLog(HKEY hKeyRoot, LPCWSTR subKey, LPCWSTR valueName, DWORD value);         // 写入 DWORD 注册表值并记录日志
bool ExecutePowerShellWithLog(const std::wstring& command);                           // 执行 PowerShell 命令并记录日志
bool FindManifestRecursive(const std::wstring& dir, std::wstring& outPath);           // 递归查找 AppX 清单文件
std::wstring GetPackageNameFromManifest(const std::wstring& manifestPath);            // 从清单解析包名
bool IsPackageInstalled(const std::wstring& packageName);                              // 检查包是否已安装
bool UninstallAppxPackage(const std::wstring& packageName);                          // 卸载指定 AppX 包
bool InstallAppxPackage(const std::wstring& manifestPath);                             // 安装指定清单的 AppX 包
bool CheckDotNet8SDK();                                                                // 检查 .NET 8 SDK
bool InstallDotNet8SDK();                                                              // 安装 .NET 8 SDK（提示/winget）
bool InstallWebview2();                                                                // 安装 WebView2 运行时（提示/winget）
bool CheckVCRuntime();                                                                 // 检查 VC 运行时
bool InstallVCRuntime();                                                               // 安装 VC 运行时
bool IsWebView2Installed();                                                            // 检查 WebView2 是否已安装
std::wstring TrimTrailingSeparators(const std::wstring& path);                        // 去除路径末尾分隔符
bool EndsWithInsensitive(const std::wstring& value, const std::wstring& suffix);       // 不区分大小写判断后缀
std::wstring EnsureInstallPathFormat(const std::wstring& basePath);                    // 规范化安装路径格式
std::wstring GetInstallRoot(const std::wstring& installPath);                          // 获取安装根路径
void ApplyInstallPath(const std::wstring& basePath, bool updateEditControl);           // 应用并可更新 UI 中的路径
bool RunCommandCapture(const std::wstring& commandLine, std::string& output, DWORD* exitCode = nullptr); // 运行命令并捕获输出
bool HttpGet(const std::wstring& url, std::string& response);                          // 简单 HTTP GET
bool ParseVersionJson(const std::string& json, std::vector<VersionEntry>& outVersions); // 解析版本列表 JSON
bool LoadVersionList();                                                                  // 加载版本列表
void PopulateVersionTabs();                                                            // 填充版本选项卡
void OnVersionTabSelected();                                                           // 响应版本标签选择
bool FetchFileInfo(const std::wstring& url, std::wstring& outInfo);                    // 获取文件信息（Content-Length 等）
bool DownloadSelectedVersion(std::wstring& outFilePath);                               // 下载选定版本
std::wstring ExtractFileNameFromUrl(const std::wstring& url);                          // 从 URL 提取文件名
std::wstring FormatSizeFromLength(const std::wstring& lengthStr);                      // 将长度字符串格式化为可读大小
std::wstring GetCurrentVersion();                                                      // 获取当前已安装版本
bool CreateDesktopShortcut();                                                            // 创建桌面快捷方式
void UpdateProgress(int percent);                                                      // 更新进度条显示
void UpdateNavigationButtons();                                                        // 更新导航按钮状态
void ShowPage(int page);                                                               // 切换显示页面
bool PrepareInstallDirectory();                                                          // 准备安装目录（创建/清空）
DWORD WINAPI PerformConfigurationThread(LPVOID lpParam);                               // 执行安装/配置线程
std::wstring GetAppxManifestPath();                                                    // 获取当前包清单路径
void RestoreRegistry();                                                                  // 恢复注册表备份
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow); // 入口函数
