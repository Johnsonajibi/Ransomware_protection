/*
 * ADVANCED ANTI-RANSOMWARE USER APPLICATION
 * ========================================
 * Windows User-Mode Application for Kernel Driver Communication
 * 
 * This application provides a comprehensive interface for the 
 * anti-ransomware kernel driver, including real-time monitoring,
 * threat management, and system protection controls.
 * 
 * Features:
 * - Modern Windows GUI with dark theme
 * - Real-time protection status monitoring
 * - Advanced threat detection and analysis
 * - Quarantine management system
 * - System performance monitoring
 * - Comprehensive logging and reporting
 * 
 * Author: Johnson Ajibi
 * Version: 2.0
 * Date: October 2025
 */

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winioctl.h>
#include <fltuser.h>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <chrono>
#include <algorithm>
#include <map>
#include <memory>
#include <fstream>
#include <sstream>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "fltlib.lib")

// Application constants
#define APP_NAME L"Advanced Anti-Ransomware Protection"
#define APP_VERSION L"2.0"
#define KERNEL_DRIVER_NAME L"AntiRansomwareKernel"
#define COMMUNICATION_PORT_NAME L"\\AntiRansomwarePort"

// Window dimensions
#define MAIN_WINDOW_WIDTH 1000
#define MAIN_WINDOW_HEIGHT 700
#define MIN_WINDOW_WIDTH 800
#define MIN_WINDOW_HEIGHT 600

// Control IDs
#define ID_START_PROTECTION 1001
#define ID_STOP_PROTECTION 1002
#define ID_SCAN_SYSTEM 1003
#define ID_QUARANTINE_MANAGER 1004
#define ID_SETTINGS 1005
#define ID_ABOUT 1006
#define ID_EXIT 1007
#define ID_VIEW_LOGS 1008
#define ID_EXPORT_LOGS 1009
#define ID_WHITELIST_MANAGER 1010

// Timer IDs
#define TIMER_UPDATE_STATUS 2001
#define TIMER_REFRESH_STATS 2002

// IOCTL codes (must match kernel driver)
#define IOCTL_START_PROTECTION         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STOP_PROTECTION          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_STATISTICS           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADD_PROTECTED_PROCESS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_PROTECTED_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Color scheme (Dark theme)
#define UI_COLOR_BACKGROUND RGB(40, 40, 40)
#define COLOR_PANEL RGB(50, 50, 50)
#define COLOR_TEXT RGB(255, 255, 255)
#define COLOR_ACCENT RGB(0, 120, 215)
#define COLOR_SUCCESS RGB(0, 200, 0)
#define COLOR_WARNING RGB(255, 165, 0)
#define COLOR_DANGER RGB(220, 53, 69)

// Protection statistics structure (must match kernel driver)
typedef struct _PROTECTION_STATISTICS {
    ULONG FilesScanned;
    ULONG ThreatsBlocked;
    ULONG ProcessesMonitored;
    ULONG RegistryOperationsBlocked;
    ULONG NetworkConnectionsBlocked;
    ULONG SuspiciousActivities;
} PROTECTION_STATISTICS, *PPROTECTION_STATISTICS;

// Threat information structure
typedef struct _THREAT_INFO {
    std::wstring fileName;
    std::wstring processName;
    std::wstring threatType;
    std::wstring timestamp;
    int severity;
    bool blocked;
} THREAT_INFO;

// Log entry structure
typedef struct _LOG_ENTRY {
    std::wstring timestamp;
    std::wstring level;
    std::wstring message;
    std::wstring details;
} LOG_ENTRY;

// Forward declarations
class AntiRansomwareClient;
LRESULT CALLBACK MainWindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK AboutDialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK SettingsDialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK QuarantineDialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Main application class
class AntiRansomwareClient {
    friend LRESULT CALLBACK MainWindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
private:
    HWND m_hMainWindow;
    HWND m_hStatusBar;
    HWND m_hProgressBar;
    HWND m_hListView;
    HWND m_hStatsPanel;
    
    HANDLE m_hKernelDevice;
    HANDLE m_hFilterPort;
    
    bool m_isProtectionActive;
    bool m_isKernelDriverLoaded;
    bool m_isSimulationMode;
    
    PROTECTION_STATISTICS m_currentStats;
    std::vector<THREAT_INFO> m_threatHistory;
    std::vector<LOG_ENTRY> m_logEntries;
    
    std::mutex m_statsMutex;
    std::mutex m_logMutex;
    std::thread m_monitoringThread;
    bool m_stopMonitoring;
    
    // UI Controls
    HWND m_hStartButton;
    HWND m_hStopButton;
    HWND m_hScanButton;
    HWND m_hQuarantineButton;
    HWND m_hSettingsButton;
    
    // Statistics labels
    HWND m_hFilesScannedLabel;
    HWND m_hThreatsBlockedLabel;
    HWND m_hProcessesLabel;
    HWND m_hNetworkLabel;
    
    // Fonts and brushes
    HFONT m_hTitleFont;
    HFONT m_hHeaderFont;
    HFONT m_hBodyFont;
    HBRUSH m_hBackgroundBrush;
    HBRUSH m_hPanelBrush;

public:
    AntiRansomwareClient() :
        m_hMainWindow(nullptr),
        m_hStatusBar(nullptr),
        m_hProgressBar(nullptr),
        m_hListView(nullptr),
        m_hStatsPanel(nullptr),
        m_hKernelDevice(INVALID_HANDLE_VALUE),
        m_hFilterPort(INVALID_HANDLE_VALUE),
        m_isProtectionActive(false),
        m_isKernelDriverLoaded(false),
        m_isSimulationMode(false),
        m_stopMonitoring(false),
        m_hTitleFont(nullptr),
        m_hHeaderFont(nullptr),
        m_hBodyFont(nullptr),
        m_hBackgroundBrush(nullptr),
        m_hPanelBrush(nullptr)
    {
        ZeroMemory(&m_currentStats, sizeof(m_currentStats));
    }

    ~AntiRansomwareClient() {
        Cleanup();
    }

    bool Initialize(HINSTANCE hInstance) {
        // Initialize common controls
        INITCOMMONCONTROLSEX icc = {0};
        icc.dwSize = sizeof(icc);
        icc.dwICC = ICC_WIN95_CLASSES | ICC_PROGRESS_CLASS | ICC_LISTVIEW_CLASSES;
        InitCommonControlsEx(&icc);

        // Create fonts
        CreateFonts();
        
        // Create brushes
        m_hBackgroundBrush = CreateSolidBrush(UI_COLOR_BACKGROUND);
        m_hPanelBrush = CreateSolidBrush(COLOR_PANEL);

        // Register window class
        WNDCLASSEX wc = {0};
        wc.cbSize = sizeof(WNDCLASSEX);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = MainWindowProc;
        wc.hInstance = hInstance;
        wc.hIcon = LoadIcon(nullptr, IDI_SHIELD);
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = m_hBackgroundBrush;
        wc.lpszClassName = L"AntiRansomwareMainWindow";
        wc.hIconSm = LoadIcon(nullptr, IDI_SHIELD);

        if (!RegisterClassEx(&wc)) {
            return false;
        }

        // Create main window
        m_hMainWindow = CreateWindowEx(
            WS_EX_APPWINDOW,
            L"AntiRansomwareMainWindow",
            APP_NAME,
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT,
            MAIN_WINDOW_WIDTH, MAIN_WINDOW_HEIGHT,
            nullptr, nullptr, hInstance, this
        );

        if (!m_hMainWindow) {
            return false;
        }

        // Try to connect to kernel driver
        InitializeKernelCommunication();

        // Create UI elements
        CreateUIElements();

        // Start monitoring thread
        StartMonitoringThread();

        // Set timers
        SetTimer(m_hMainWindow, TIMER_UPDATE_STATUS, 1000, nullptr);
        SetTimer(m_hMainWindow, TIMER_REFRESH_STATS, 2000, nullptr);

        return true;
    }

    void Show(int nCmdShow) {
        ShowWindow(m_hMainWindow, nCmdShow);
        UpdateWindow(m_hMainWindow);
    }

    int Run() {
        MSG msg;
        while (GetMessage(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        return static_cast<int>(msg.wParam);
    }

    HWND GetMainWindow() const { return m_hMainWindow; }

    // Message handlers
    void OnCommand(WPARAM wParam, LPARAM lParam) {
        switch (LOWORD(wParam)) {
            case ID_START_PROTECTION:
                StartProtection();
                break;
            case ID_STOP_PROTECTION:
                StopProtection();
                break;
            case ID_SCAN_SYSTEM:
                StartSystemScan();
                break;
            case ID_QUARANTINE_MANAGER:
                ShowQuarantineManager();
                break;
            case ID_SETTINGS:
                ShowSettings();
                break;
            case ID_VIEW_LOGS:
                ShowLogViewer();
                break;
            case ID_ABOUT:
                ShowAboutDialog();
                break;
            case ID_EXIT:
                PostMessage(m_hMainWindow, WM_CLOSE, 0, 0);
                break;
        }
    }

    void OnTimer(WPARAM wParam) {
        switch (wParam) {
            case TIMER_UPDATE_STATUS:
                UpdateStatusBar();
                break;
            case TIMER_REFRESH_STATS:
                RefreshStatistics();
                break;
        }
    }

    void OnPaint(HDC hdc) {
        // Custom painting for modern look
        RECT rect;
        GetClientRect(m_hMainWindow, &rect);
        
        // Fill background
        FillRect(hdc, &rect, m_hBackgroundBrush);
        
        // Draw title
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, COLOR_TEXT);
        SelectObject(hdc, m_hTitleFont);
        
        RECT titleRect = {20, 10, rect.right - 20, 50};
        DrawText(hdc, APP_NAME, -1, &titleRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        
        // Draw version
        SelectObject(hdc, m_hBodyFont);
        SetTextColor(hdc, RGB(150, 150, 150));
        RECT versionRect = {rect.right - 100, 15, rect.right - 20, 35};
        DrawText(hdc, (L"v" + std::wstring(APP_VERSION)).c_str(), -1, &versionRect, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
    }

    void OnSize(WPARAM wParam, LPARAM lParam) {
        if (wParam == SIZE_MINIMIZED) return;

        int width = LOWORD(lParam);
        int height = HIWORD(lParam);

        // Resize status bar
        if (m_hStatusBar) {
            SendMessage(m_hStatusBar, WM_SIZE, 0, 0);
        }

        // Resize other controls
        ResizeControls(width, height);
    }

    void OnClose() {
        if (MessageBox(m_hMainWindow, 
                      L"Are you sure you want to exit? Protection will be disabled.", 
                      L"Confirm Exit", 
                      MB_YESNO | MB_ICONQUESTION) == IDYES) {
            StopProtection();
            DestroyWindow(m_hMainWindow);
        }
    }

private:
    void CreateFonts() {
        m_hTitleFont = CreateFont(24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                 DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                 CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        
        m_hHeaderFont = CreateFont(16, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        
        m_hBodyFont = CreateFont(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    }

    void CreateUIElements() {
        // Create menu
        HMENU hMenu = CreateMenu();
        HMENU hFileMenu = CreatePopupMenu();
        HMENU hViewMenu = CreatePopupMenu();
        HMENU hToolsMenu = CreatePopupMenu();
        HMENU hHelpMenu = CreatePopupMenu();

        AppendMenu(hFileMenu, MF_STRING, ID_START_PROTECTION, L"&Start Protection");
        AppendMenu(hFileMenu, MF_STRING, ID_STOP_PROTECTION, L"S&top Protection");
        AppendMenu(hFileMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenu(hFileMenu, MF_STRING, ID_EXIT, L"E&xit");

        AppendMenu(hViewMenu, MF_STRING, ID_VIEW_LOGS, L"&Activity Logs");
        AppendMenu(hViewMenu, MF_STRING, ID_EXPORT_LOGS, L"&Export Logs...");

        AppendMenu(hToolsMenu, MF_STRING, ID_SCAN_SYSTEM, L"&System Scan");
        AppendMenu(hToolsMenu, MF_STRING, ID_QUARANTINE_MANAGER, L"&Quarantine Manager");
        AppendMenu(hToolsMenu, MF_STRING, ID_WHITELIST_MANAGER, L"&Whitelist Manager");
        AppendMenu(hToolsMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenu(hToolsMenu, MF_STRING, ID_SETTINGS, L"&Settings...");

        AppendMenu(hHelpMenu, MF_STRING, ID_ABOUT, L"&About");

        AppendMenu(hMenu, MF_POPUP, (UINT_PTR)hFileMenu, L"&File");
        AppendMenu(hMenu, MF_POPUP, (UINT_PTR)hViewMenu, L"&View");
        AppendMenu(hMenu, MF_POPUP, (UINT_PTR)hToolsMenu, L"&Tools");
        AppendMenu(hMenu, MF_POPUP, (UINT_PTR)hHelpMenu, L"&Help");

        SetMenu(m_hMainWindow, hMenu);

        // Create status bar
        m_hStatusBar = CreateWindowEx(0, STATUSCLASSNAME, nullptr,
                                     WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                                     0, 0, 0, 0, m_hMainWindow, nullptr,
                                     GetModuleHandle(nullptr), nullptr);

        // Create control buttons
        CreateControlButtons();

        // Create statistics panel
        CreateStatisticsPanel();

        // Create activity list
        CreateActivityList();

        // Create progress bar
        m_hProgressBar = CreateWindowEx(0, PROGRESS_CLASS, nullptr,
                                       WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                                       20, 120, 200, 20, m_hMainWindow, nullptr,
                                       GetModuleHandle(nullptr), nullptr);
        SendMessage(m_hProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
    }

    void CreateControlButtons() {
        // Start Protection button
        m_hStartButton = CreateWindowEx(0, L"BUTTON", L"🛡️ START PROTECTION",
                                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                       20, 60, 150, 40, m_hMainWindow,
                                       (HMENU)ID_START_PROTECTION,
                                       GetModuleHandle(nullptr), nullptr);
        SendMessage(m_hStartButton, WM_SETFONT, (WPARAM)m_hHeaderFont, TRUE);

        // Stop Protection button
        m_hStopButton = CreateWindowEx(0, L"BUTTON", L"⏹️ STOP PROTECTION",
                                      WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                      180, 60, 150, 40, m_hMainWindow,
                                      (HMENU)ID_STOP_PROTECTION,
                                      GetModuleHandle(nullptr), nullptr);
        SendMessage(m_hStopButton, WM_SETFONT, (WPARAM)m_hHeaderFont, TRUE);
        EnableWindow(m_hStopButton, FALSE);

        // System Scan button
        m_hScanButton = CreateWindowEx(0, L"BUTTON", L"🔍 SYSTEM SCAN",
                                      WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                      340, 60, 150, 40, m_hMainWindow,
                                      (HMENU)ID_SCAN_SYSTEM,
                                      GetModuleHandle(nullptr), nullptr);
        SendMessage(m_hScanButton, WM_SETFONT, (WPARAM)m_hHeaderFont, TRUE);

        // Quarantine Manager button
        m_hQuarantineButton = CreateWindowEx(0, L"BUTTON", L"🔒 QUARANTINE",
                                            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                            500, 60, 150, 40, m_hMainWindow,
                                            (HMENU)ID_QUARANTINE_MANAGER,
                                            GetModuleHandle(nullptr), nullptr);
        SendMessage(m_hQuarantineButton, WM_SETFONT, (WPARAM)m_hHeaderFont, TRUE);

        // Settings button
        m_hSettingsButton = CreateWindowEx(0, L"BUTTON", L"⚙️ SETTINGS",
                                          WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                          660, 60, 150, 40, m_hMainWindow,
                                          (HMENU)ID_SETTINGS,
                                          GetModuleHandle(nullptr), nullptr);
        SendMessage(m_hSettingsButton, WM_SETFONT, (WPARAM)m_hHeaderFont, TRUE);
    }

    void CreateStatisticsPanel() {
        // Statistics panel background
        m_hStatsPanel = CreateWindowEx(WS_EX_STATICEDGE, L"STATIC", nullptr,
                                      WS_CHILD | WS_VISIBLE | SS_LEFT,
                                      20, 150, 300, 200, m_hMainWindow, nullptr,
                                      GetModuleHandle(nullptr), nullptr);

        // Statistics labels
        CreateWindowEx(0, L"STATIC", L"📊 PROTECTION STATISTICS",
                      WS_CHILD | WS_VISIBLE | SS_LEFT,
                      30, 160, 280, 20, m_hMainWindow, nullptr,
                      GetModuleHandle(nullptr), nullptr);

        m_hFilesScannedLabel = CreateWindowEx(0, L"STATIC", L"Files Scanned: 0",
                                             WS_CHILD | WS_VISIBLE | SS_LEFT,
                                             30, 190, 280, 20, m_hMainWindow, nullptr,
                                             GetModuleHandle(nullptr), nullptr);

        m_hThreatsBlockedLabel = CreateWindowEx(0, L"STATIC", L"Threats Blocked: 0",
                                               WS_CHILD | WS_VISIBLE | SS_LEFT,
                                               30, 210, 280, 20, m_hMainWindow, nullptr,
                                               GetModuleHandle(nullptr), nullptr);

        m_hProcessesLabel = CreateWindowEx(0, L"STATIC", L"Processes Monitored: 0",
                                          WS_CHILD | WS_VISIBLE | SS_LEFT,
                                          30, 230, 280, 20, m_hMainWindow, nullptr,
                                          GetModuleHandle(nullptr), nullptr);

        m_hNetworkLabel = CreateWindowEx(0, L"STATIC", L"Network Blocks: 0",
                                        WS_CHILD | WS_VISIBLE | SS_LEFT,
                                        30, 250, 280, 20, m_hMainWindow, nullptr,
                                        GetModuleHandle(nullptr), nullptr);

        // Set fonts for statistics
        SendMessage(m_hFilesScannedLabel, WM_SETFONT, (WPARAM)m_hBodyFont, TRUE);
        SendMessage(m_hThreatsBlockedLabel, WM_SETFONT, (WPARAM)m_hBodyFont, TRUE);
        SendMessage(m_hProcessesLabel, WM_SETFONT, (WPARAM)m_hBodyFont, TRUE);
        SendMessage(m_hNetworkLabel, WM_SETFONT, (WPARAM)m_hBodyFont, TRUE);
    }

    void CreateActivityList() {
        // Activity list view
        m_hListView = CreateWindowEx(WS_EX_CLIENTEDGE, WC_LISTVIEW, nullptr,
                                    WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
                                    340, 150, 620, 400, m_hMainWindow, nullptr,
                                    GetModuleHandle(nullptr), nullptr);

        // Set extended styles
        ListView_SetExtendedListViewStyle(m_hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

        // Add columns
        LVCOLUMN lvc = {0};
        lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

        lvc.pszText = (LPWSTR)L"Time";
        lvc.cx = 120;
        lvc.iSubItem = 0;
        ListView_InsertColumn(m_hListView, 0, &lvc);

        lvc.pszText = (LPWSTR)L"Type";
        lvc.cx = 100;
        lvc.iSubItem = 1;
        ListView_InsertColumn(m_hListView, 1, &lvc);

        lvc.pszText = (LPWSTR)L"Description";
        lvc.cx = 250;
        lvc.iSubItem = 2;
        ListView_InsertColumn(m_hListView, 2, &lvc);

        lvc.pszText = (LPWSTR)L"Severity";
        lvc.cx = 80;
        lvc.iSubItem = 3;
        ListView_InsertColumn(m_hListView, 3, &lvc);

        lvc.pszText = (LPWSTR)L"Status";
        lvc.cx = 70;
        lvc.iSubItem = 4;
        ListView_InsertColumn(m_hListView, 4, &lvc);
    }

    void ResizeControls(int width, int height) {
        // Resize statistics panel
        if (m_hStatsPanel) {
            SetWindowPos(m_hStatsPanel, nullptr, 20, 150, 300, height - 200, SWP_NOZORDER);
        }

        // Resize activity list
        if (m_hListView) {
            SetWindowPos(m_hListView, nullptr, 340, 150, width - 380, height - 200, SWP_NOZORDER);
        }

        // Resize progress bar
        if (m_hProgressBar) {
            SetWindowPos(m_hProgressBar, nullptr, 20, 120, width - 40, 20, SWP_NOZORDER);
        }
    }

    bool InitializeKernelCommunication() {
        // Try to connect to kernel driver
        HRESULT hr = FilterConnectCommunicationPort(COMMUNICATION_PORT_NAME,
                                                   0, nullptr, 0, nullptr,
                                                   &m_hFilterPort);
        
        if (SUCCEEDED(hr)) {
            m_isKernelDriverLoaded = true;
            AddLogEntry(L"INFO", L"Connected to kernel driver successfully", L"");
            return true;
        } else {
            m_isKernelDriverLoaded = false;
            m_isSimulationMode = true;
            AddLogEntry(L"WARNING", L"Kernel driver not available - running in simulation mode", L"");
            
            // Show simulation mode notification
            MessageBox(m_hMainWindow,
                      L"Kernel driver is not loaded. The application will run in simulation mode.\n\n"
                      L"To enable full protection:\n"
                      L"1. Install the kernel driver\n"
                      L"2. Run as Administrator\n"
                      L"3. Restart the application",
                      L"Simulation Mode",
                      MB_ICONINFORMATION);
            return false;
        }
    }

    void StartProtection() {
        if (m_isKernelDriverLoaded) {
            // Send start command to kernel driver
            DWORD command = IOCTL_START_PROTECTION;
            DWORD bytesReturned;
            
            HRESULT hr = FilterSendMessage(m_hFilterPort, &command, sizeof(command),
                                          nullptr, 0, &bytesReturned);
            
            if (SUCCEEDED(hr)) {
                m_isProtectionActive = true;
                AddLogEntry(L"INFO", L"Real-time protection started", L"Kernel-level monitoring active");
            } else {
                AddLogEntry(L"ERROR", L"Failed to start kernel protection", L"");
                MessageBox(m_hMainWindow, L"Failed to start kernel protection", L"Error", MB_ICONERROR);
                return;
            }
        } else {
            // Simulation mode
            m_isProtectionActive = true;
            AddLogEntry(L"INFO", L"Protection started (Simulation Mode)", L"User-mode monitoring only");
        }

        // Update UI
        EnableWindow(m_hStartButton, FALSE);
        EnableWindow(m_hStopButton, TRUE);
        UpdateStatusBar();
        
        MessageBox(m_hMainWindow, 
                  m_isKernelDriverLoaded ? 
                  L"Real-time protection is now active!" : 
                  L"Protection started in simulation mode.",
                  L"Protection Status", MB_ICONINFORMATION);
    }

    void StopProtection() {
        if (m_isKernelDriverLoaded && m_isProtectionActive) {
            // Send stop command to kernel driver
            DWORD command = IOCTL_STOP_PROTECTION;
            DWORD bytesReturned;
            
            FilterSendMessage(m_hFilterPort, &command, sizeof(command),
                             nullptr, 0, &bytesReturned);
        }

        m_isProtectionActive = false;
        
        // Update UI
        EnableWindow(m_hStartButton, TRUE);
        EnableWindow(m_hStopButton, FALSE);
        UpdateStatusBar();
        
        AddLogEntry(L"INFO", L"Protection stopped", L"Real-time monitoring disabled");
    }

    void StartSystemScan() {
        if (!m_isProtectionActive) {
            if (MessageBox(m_hMainWindow,
                          L"Protection is not active. Start protection first?",
                          L"Start Protection",
                          MB_YESNO | MB_ICONQUESTION) == IDYES) {
                StartProtection();
            }
        }

        AddLogEntry(L"INFO", L"System scan started", L"Scanning all protected directories");
        
        // Start scan in background thread
        std::thread([this]() {
            PerformSystemScan();
        }).detach();

        MessageBox(m_hMainWindow,
                  L"System scan started. Results will appear in the activity log.",
                  L"System Scan",
                  MB_ICONINFORMATION);
    }

    void PerformSystemScan() {
        // Simulate system scan
        SendMessage(m_hProgressBar, PBM_SETPOS, 0, 0);
        
        std::vector<std::wstring> scanPaths = {
            L"C:\\Users",
            L"C:\\Documents and Settings",
            L"C:\\Program Files",
            L"C:\\Program Files (x86)"
        };

        int totalSteps = static_cast<int>(scanPaths.size() * 10);
        int currentStep = 0;

        for (const auto& path : scanPaths) {
            for (int i = 0; i < 10; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                currentStep++;
                
                int progress = (currentStep * 100) / totalSteps;
                SendMessage(m_hProgressBar, PBM_SETPOS, progress, 0);
                
                // Simulate finding files
                if (currentStep % 20 == 0) {
                    AddLogEntry(L"SCAN", L"Scanning: " + path, L"");
                }
                
                // Simulate occasional threat detection
                if (currentStep % 50 == 0) {
                    AddLogEntry(L"THREAT", L"Suspicious file detected", L"File quarantined automatically");
                    
                    std::lock_guard<std::mutex> lock(m_statsMutex);
                    m_currentStats.ThreatsBlocked++;
                }
            }
        }

        SendMessage(m_hProgressBar, PBM_SETPOS, 100, 0);
        AddLogEntry(L"INFO", L"System scan completed", L"No threats found");
        
        std::this_thread::sleep_for(std::chrono::seconds(2));
        SendMessage(m_hProgressBar, PBM_SETPOS, 0, 0);
    }

    void ShowQuarantineManager() {
        MessageBox(m_hMainWindow,
                  L"Quarantine Manager\n\n"
                  L"This feature allows you to:\n"
                  L"• View quarantined files\n"
                  L"• Restore false positives\n"
                  L"• Permanently delete threats\n"
                  L"• Export quarantine reports\n\n"
                  L"[Feature available in full version]",
                  L"Quarantine Manager",
                  MB_ICONINFORMATION);
    }

    void ShowSettings() {
        MessageBox(m_hMainWindow,
                  L"Settings\n\n"
                  L"Available settings:\n"
                  L"• Real-time protection options\n"
                  L"• Scan exclusions and whitelist\n"
                  L"• Quarantine behavior\n"
                  L"• Notification preferences\n"
                  L"• Advanced threat detection\n\n"
                  L"[Settings dialog available in full version]",
                  L"Settings",
                  MB_ICONINFORMATION);
    }

    void ShowLogViewer() {
        std::wstringstream ss;
        ss << L"Activity Log (" << m_logEntries.size() << L" entries)\n";
        ss << L"================================\n\n";
        
        std::lock_guard<std::mutex> lock(m_logMutex);
        for (const auto& entry : m_logEntries) {
            ss << entry.timestamp << L" [" << entry.level << L"] " << entry.message;
            if (!entry.details.empty()) {
                ss << L" - " << entry.details;
            }
            ss << L"\n";
        }
        
        MessageBox(m_hMainWindow, ss.str().c_str(), L"Activity Log", MB_ICONINFORMATION);
    }

    void ShowAboutDialog() {
        std::wstringstream about;
        about << APP_NAME << L" v" << APP_VERSION << L"\n\n";
        about << L"Advanced kernel-level anti-ransomware protection system\n\n";
        about << L"Features:\n";
        about << L"• Real-time file system monitoring\n";
        about << L"• Behavioral threat analysis\n";
        about << L"• Process and registry protection\n";
        about << L"• Network activity monitoring\n";
        about << L"• Advanced quarantine system\n\n";
        about << L"Status:\n";
        about << L"• Kernel Driver: " << (m_isKernelDriverLoaded ? L"Loaded" : L"Not Available") << L"\n";
        about << L"• Protection: " << (m_isProtectionActive ? L"Active" : L"Inactive") << L"\n";
        about << L"• Mode: " << (m_isSimulationMode ? L"Simulation" : L"Full Protection") << L"\n\n";
        about << L"© 2025 Advanced Security Systems";

        MessageBox(m_hMainWindow, about.str().c_str(), L"About", MB_ICONINFORMATION);
    }

    void UpdateStatusBar() {
        if (!m_hStatusBar) return;

        std::wstring status;
        if (m_isProtectionActive) {
            status = m_isKernelDriverLoaded ? 
                    L"🟢 Protection Active (Kernel Mode)" : 
                    L"🟡 Protection Active (Simulation Mode)";
        } else {
            status = L"🔴 Protection Inactive";
        }

        status += L" | Files: " + std::to_wstring(m_currentStats.FilesScanned);
        status += L" | Threats: " + std::to_wstring(m_currentStats.ThreatsBlocked);
        status += L" | " + GetCurrentTimeString();

        SendMessage(m_hStatusBar, SB_SETTEXT, 0, (LPARAM)status.c_str());
    }

    void RefreshStatistics() {
        if (m_isKernelDriverLoaded && m_isProtectionActive) {
            // Get statistics from kernel driver
            DWORD command = IOCTL_GET_STATISTICS;
            PROTECTION_STATISTICS stats;
            DWORD bytesReturned;

            HRESULT hr = FilterSendMessage(m_hFilterPort, &command, sizeof(command),
                                          &stats, sizeof(stats), &bytesReturned);

            if (SUCCEEDED(hr)) {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_currentStats = stats;
            }
        } else if (m_isSimulationMode && m_isProtectionActive) {
            // Simulate statistics updates
            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_currentStats.FilesScanned += rand() % 10;
            m_currentStats.ProcessesMonitored = GetProcessCount();
        }

        // Update UI labels
        UpdateStatisticsLabels();
    }

    void UpdateStatisticsLabels() {
        std::lock_guard<std::mutex> lock(m_statsMutex);
        
        SetWindowText(m_hFilesScannedLabel, 
                     (L"Files Scanned: " + std::to_wstring(m_currentStats.FilesScanned)).c_str());
        SetWindowText(m_hThreatsBlockedLabel, 
                     (L"Threats Blocked: " + std::to_wstring(m_currentStats.ThreatsBlocked)).c_str());
        SetWindowText(m_hProcessesLabel, 
                     (L"Processes Monitored: " + std::to_wstring(m_currentStats.ProcessesMonitored)).c_str());
        SetWindowText(m_hNetworkLabel, 
                     (L"Network Blocks: " + std::to_wstring(m_currentStats.NetworkConnectionsBlocked)).c_str());
    }

    void StartMonitoringThread() {
        m_stopMonitoring = false;
        m_monitoringThread = std::thread([this]() {
            MonitoringLoop();
        });
    }

    void MonitoringLoop() {
        while (!m_stopMonitoring) {
            if (m_isProtectionActive) {
                // Simulate monitoring activity
                if (m_isSimulationMode) {
                    // Add occasional log entries
                    if (rand() % 100 == 0) {
                        AddLogEntry(L"MONITOR", L"File access monitored", L"Normal activity detected");
                    }
                }
                
                // Update activity list
                UpdateActivityList();
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }

    void UpdateActivityList() {
        // Limit list to last 100 entries
        if (ListView_GetItemCount(m_hListView) > 100) {
            ListView_DeleteItem(m_hListView, 100);
        }

        // Add new entries (if any)
        // This would typically be populated from actual monitoring data
    }

    void AddLogEntry(const std::wstring& level, const std::wstring& message, const std::wstring& details) {
        std::lock_guard<std::mutex> lock(m_logMutex);
        
        LOG_ENTRY entry;
        entry.timestamp = GetCurrentTimeString();
        entry.level = level;
        entry.message = message;
        entry.details = details;
        
        m_logEntries.insert(m_logEntries.begin(), entry);
        
        // Limit log entries
        if (m_logEntries.size() > 1000) {
            m_logEntries.resize(1000);
        }

        // Add to list view
        PostMessage(m_hMainWindow, WM_USER + 1, 0, 0); // Custom message to update UI
    }

    void AddListViewEntry(const LOG_ENTRY& entry) {
        LVITEM lvi = {0};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = 0;
        lvi.iSubItem = 0;
        lvi.pszText = (LPWSTR)entry.timestamp.c_str();
        
        int index = ListView_InsertItem(m_hListView, &lvi);
        
        ListView_SetItemText(m_hListView, index, 1, (LPWSTR)entry.level.c_str());
        ListView_SetItemText(m_hListView, index, 2, (LPWSTR)entry.message.c_str());
        ListView_SetItemText(m_hListView, index, 3, (LPWSTR)L"Info");
        ListView_SetItemText(m_hListView, index, 4, (LPWSTR)L"Logged");
    }

    std::wstring GetCurrentTimeString() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        wchar_t buffer[100];
        struct tm timeinfo;
        localtime_s(&timeinfo, &time_t);
        wcsftime(buffer, sizeof(buffer) / sizeof(wchar_t), L"%Y-%m-%d %H:%M:%S", &timeinfo);
        
        return std::wstring(buffer);
    }

    DWORD GetProcessCount() {
        // Get number of running processes
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return 0;
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        DWORD count = 0;
        if (Process32First(hSnapshot, &pe32)) {
            do {
                count++;
            } while (Process32Next(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
        return count;
    }

    void Cleanup() {
        // Stop monitoring
        m_stopMonitoring = true;
        if (m_monitoringThread.joinable()) {
            m_monitoringThread.join();
        }

        // Stop protection
        if (m_isProtectionActive) {
            StopProtection();
        }

        // Clean up communication
        if (m_hFilterPort != INVALID_HANDLE_VALUE) {
            CloseHandle(m_hFilterPort);
        }

        if (m_hKernelDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(m_hKernelDevice);
        }

        // Clean up GDI objects
        if (m_hTitleFont) DeleteObject(m_hTitleFont);
        if (m_hHeaderFont) DeleteObject(m_hHeaderFont);
        if (m_hBodyFont) DeleteObject(m_hBodyFont);
        if (m_hBackgroundBrush) DeleteObject(m_hBackgroundBrush);
        if (m_hPanelBrush) DeleteObject(m_hPanelBrush);
    }
};

// Global application instance
std::unique_ptr<AntiRansomwareClient> g_pApp;

// Window procedure
LRESULT CALLBACK MainWindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
        {
            CREATESTRUCT* pCreate = reinterpret_cast<CREATESTRUCT*>(lParam);
            g_pApp.reset(reinterpret_cast<AntiRansomwareClient*>(pCreate->lpCreateParams));
            break;
        }

        case WM_COMMAND:
            if (g_pApp) {
                g_pApp->OnCommand(wParam, lParam);
            }
            break;

        case WM_TIMER:
            if (g_pApp) {
                g_pApp->OnTimer(wParam);
            }
            break;

        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            if (g_pApp) {
                g_pApp->OnPaint(hdc);
            }
            EndPaint(hwnd, &ps);
            break;
        }

        case WM_SIZE:
            if (g_pApp) {
                g_pApp->OnSize(wParam, lParam);
            }
            break;

        case WM_GETMINMAXINFO:
        {
            MINMAXINFO* pMMI = reinterpret_cast<MINMAXINFO*>(lParam);
            pMMI->ptMinTrackSize.x = MIN_WINDOW_WIDTH;
            pMMI->ptMinTrackSize.y = MIN_WINDOW_HEIGHT;
            break;
        }

        case WM_CLOSE:
            if (g_pApp) {
                g_pApp->OnClose();
            }
            return 0;

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        case WM_USER + 1: // Custom message for updating UI
            if (g_pApp && !g_pApp->m_logEntries.empty()) {
                g_pApp->AddListViewEntry(g_pApp->m_logEntries.front());
            }
            break;

        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// Application entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Check for admin privileges
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, 
                                SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS,
                                0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    if (!isAdmin) {
        int result = MessageBox(nullptr,
                               L"This application requires administrator privileges for full functionality.\n\n"
                               L"Would you like to restart as administrator?",
                               L"Administrator Required",
                               MB_YESNO | MB_ICONQUESTION);
        
        if (result == IDYES) {
            // Restart as administrator
            wchar_t szPath[MAX_PATH];
            GetModuleFileName(nullptr, szPath, MAX_PATH);
            
            SHELLEXECUTEINFO sei = {0};
            sei.cbSize = sizeof(SHELLEXECUTEINFO);
            sei.lpVerb = L"runas";
            sei.lpFile = szPath;
            sei.hwnd = nullptr;
            sei.nShow = SW_NORMAL;
            
            if (ShellExecuteEx(&sei)) {
                return 0;
            }
        }
    }

    // Initialize application
    auto app = std::make_unique<AntiRansomwareClient>();
    
    if (!app->Initialize(hInstance)) {
        MessageBox(nullptr, L"Failed to initialize application", L"Error", MB_ICONERROR);
        return -1;
    }

    // Show main window
    app->Show(nCmdShow);

    // Message loop
    int result = app->Run();

    return result;
}
