#pragma once

#include <windows.h>
#include <string>
#include <vector>

inline constexpr int PAGE_WELCOME = 0;    // 欢迎页
inline constexpr int PAGE_LICENSE = 1;    // 许可协议页
inline constexpr int PAGE_LOCATION = 2;   // 选择安装路径页
inline constexpr int PAGE_PROGRESS = 3;   // 安装进度页
inline constexpr int PAGE_COMPLETE = 4;   // 完成页

inline constexpr UINT WM_UPDATE_PROGRESS = WM_USER + 1;         // 更新进度的自定义消息
inline constexpr UINT WM_CONFIGURATION_COMPLETE = WM_USER + 2;  // 配置完成的自定义消息

inline constexpr int IDC_TITLE_LABEL = 1001;      // 标题文本控件ID
inline constexpr int IDC_SUBTITLE_LABEL = 1002;   // 副标题文本控件ID
inline constexpr int IDC_BACK_BUTTON = 1003;      // 返回按钮ID
inline constexpr int IDC_NEXT_BUTTON = 1004;      // 下一步按钮ID
inline constexpr int IDC_CANCEL_BUTTON = 1005;    // 取消按钮ID
inline constexpr int IDC_PROGRESS_BAR = 1006;     // 进度条ID
inline constexpr int IDC_LOG_EDIT = 1007;         // 日志输出编辑框ID
inline constexpr int IDC_LICENSE_LINK = 1008;     // 许可证链接控件ID
inline constexpr int IDC_LICENSE_CHECK = 1009;    // 同意许可复选框ID
inline constexpr int IDC_PATH_EDIT = 1010;        // 安装路径输入框ID
inline constexpr int IDC_BROWSE_BUTTON = 1011;    // 浏览路径按钮ID
inline constexpr int IDC_VERSION_LABEL = 1012;    // 版本显示标签ID
inline constexpr int IDC_FILEINFO_LABEL = 1014;   // 文件信息标签ID
inline constexpr int IDC_VERSION_TAB = 1015;      // 版本选择标签页控件ID

inline constexpr int BUTTON_Y = 320;               // 底部按钮Y坐标
inline constexpr int BUTTON_HEIGHT = 28;           // 按钮高度
inline constexpr int BACK_WIDTH = 85;              // 返回按钮宽度
inline constexpr int NEXT_WIDTH = 85;              // 下一步按钮宽度
inline constexpr int CANCEL_WIDTH = 65;            // 取消按钮宽度
inline constexpr int BUTTON_SPACING = 10;          // 按钮之间间距
inline constexpr int BUTTON_RIGHT_MARGIN = 20;     // 按钮区域右侧边距
inline constexpr int BUTTON_DEFAULT_BACK_X = 290;  // 返回按钮默认X坐标
inline constexpr int BUTTON_DEFAULT_NEXT_X = 385;  // 下一步按钮默认X坐标
inline constexpr int BUTTON_DEFAULT_CANCEL_X = 480;// 取消按钮默认X坐标

struct VersionEntry {
    std::wstring channel;       // 发布/预览通道
    std::wstring version;       // 版本号字符串
    std::wstring downloadUrl;   // 下载地址
    std::wstring fileInfo;      // 缓存的文件信息
    bool fileInfoFetched;       // 是否已获取文件信息
};

extern HINSTANCE g_hInstance;              // 应用实例句柄
extern HWND g_hMainWnd;                    // 主窗口句柄
extern HWND g_hTitleLabel;                 // 标题文本控件
extern HWND g_hSubtitleLabel;              // 副标题文本控件
extern HWND g_hBackButton;                 // 返回按钮
extern HWND g_hNextButton;                 // 下一步按钮
extern HWND g_hCancelButton;               // 取消按钮
extern HWND g_hProgressBar;                // 进度条
extern HWND g_hLogEdit;                    // 日志输出编辑框
extern HWND g_hLicenseLink;                // 许可证链接控件
extern HWND g_hLicenseCheck;               // 同意许可复选框
extern HWND g_hPathEdit;                   // 安装路径输入框
extern HWND g_hBrowseButton;               // 浏览路径按钮
extern HWND g_hVersionLabel;               // 版本显示标签
extern HWND g_hVersionTab;                 // 版本选择标签页控件
extern HWND g_hFileInfoLabel;              // 文件信息标签

extern HFONT g_hTitleFont;                 // 标题字体
extern HFONT g_hNormalFont;                // 正文字体

extern int g_currentPage;                  // 当前向导页索引
extern bool g_agreedToLicense;             // 是否已同意许可
extern bool g_installSuccess;              // 安装是否成功

extern std::wstring g_documentsPath;       // 用户文档路径
extern std::wstring g_installPath;         // 选定的安装路径
extern std::wstring g_tempPath;            // 临时目录路径
extern std::wstring g_defaultBasePath;     // 默认基础安装目录

extern bool g_needsReboot;                 // 是否需要重启标记

extern const std::wstring kAppFolderName;  // 应用安装文件夹名
extern const std::wstring kFallbackVersion;// 默认回退版本
extern const std::wstring kDownloadBaseDir;// 默认下载/安装目录
extern const std::wstring kVersionApiUrl;  // 版本信息接口

extern std::vector<VersionEntry> g_versions;       // 可用版本列表
extern bool g_versionsLoaded;                      // 版本列表是否已加载
extern std::wstring g_selectedVersion;             // 选择的版本号
extern std::wstring g_selectedDownloadUrl;         // 选择的下载链接
extern std::wstring g_selectedChannel;             // 选择的更新通道
extern std::wstring g_downloadedFilePath;          // 已下载安装包路径
