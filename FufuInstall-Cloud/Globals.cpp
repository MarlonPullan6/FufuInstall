#include "Globals.h"
#include "resource.h"

// Global handles
HINSTANCE g_hInstance = nullptr;                 // 应用实例句柄
HWND g_hMainWnd = nullptr;                       // 主窗口句柄
HWND g_hTitleLabel = nullptr;                    // 标题文本控件
HWND g_hSubtitleLabel = nullptr;                 // 副标题文本控件
HWND g_hBackButton = nullptr;                    // 返回按钮
HWND g_hNextButton = nullptr;                    // 下一步按钮
HWND g_hCancelButton = nullptr;                  // 取消按钮
HWND g_hProgressBar = nullptr;                   // 进度条
HWND g_hLogEdit = nullptr;                       // 日志输出编辑框
HWND g_hLicenseLink = nullptr;                   // 许可证链接控件
HWND g_hLicenseCheck = nullptr;                  // 同意许可复选框
HWND g_hPathEdit = nullptr;                      // 安装路径输入框
HWND g_hBrowseButton = nullptr;                  // 浏览路径按钮
HWND g_hVersionLabel = nullptr;                  // 版本显示标签
HWND g_hVersionTab = nullptr;                    // 版本选择标签页控件
HWND g_hFileInfoLabel = nullptr;                 // 文件信息标签
HWND g_hProgressText = nullptr;                  // 进度文本标签

HFONT g_hTitleFont = nullptr;                    // 标题字体
HFONT g_hNormalFont = nullptr;                   // 正文字体

int g_currentPage = PAGE_WELCOME;                // 当前向导页索引
bool g_agreedToLicense = false;                  // 是否已同意许可
bool g_installSuccess = false;                   // 安装是否成功

std::wstring g_documentsPath;                    // 用户文档路径
std::wstring g_installPath;                      // 选定的安装路径
std::wstring g_tempPath;                         // 临时目录
std::wstring g_defaultBasePath;                  // 默认基础安装目录

DWORD g_originalAllowDev = 0;                    // 更改原始开发者模式注册表值
DWORD g_originalAllowTrust = 0;                  // 更改原始允许信任的注册表值
bool g_regBackedUp = false;                      // 注册表是否已备份标记

bool g_needsReboot = false;                      // 是否需要重启标记

const std::wstring kAppFolderName = L"FufuToolbox";            // 应用安装文件夹名
const std::wstring kFallbackVersion = L"latest";               // 默认回退版本
const std::wstring kDownloadBaseDir = L"C:\\FufuToolbox"; // 默认下载/安装目录
const std::wstring kVersionApiUrl = L"https://seikan.lat/api/Version.json"; // 版本信息接口

std::vector<VersionEntry> g_versions;            // 可用版本列表
bool g_versionsLoaded = false;                   // 版本列表是否已加载
std::wstring g_selectedVersion;                  // 选择的版本号
std::wstring g_selectedDownloadUrl;              // 选择的下载链接
std::wstring g_selectedChannel;                  // 选择的更新通道
std::wstring g_downloadedFilePath;               // 已下载安装包路径
