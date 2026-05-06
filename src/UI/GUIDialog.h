#pragma once

#include <Windows.h>
#include <commdlg.h>
#include <string>
#include <vector>
#include "Core/SecureFolderManager.h"

namespace SecureFolder {

// Password input dialog
class PasswordDialog {
public:
    // Show password input dialog for unlock
    // openAfterUnlock: set to true if user clicked "Unlock and Open"
    static bool Show(HWND parent, const std::wstring& folderPath, std::wstring& outPassword, bool& openAfterUnlock);

    // Show password input dialog for lock (with confirm password)
    static bool ShowForLock(HWND parent, const std::wstring& folderPath, std::wstring& outPassword);

    // Show success message
    static void ShowSuccess(HWND parent, const std::wstring& message);

    // Show error message
    static void ShowError(HWND parent, const std::wstring& message);

private:
    static std::wstring s_folderPath;
    static std::wstring s_password;
    static bool s_result;
    static bool s_isLockMode;  // true for lock, false for unlock
};

// Main window GUI
class MainWindow {
public:
    MainWindow();
    ~MainWindow();

    // Create and show main window
    bool Create(HINSTANCE hInstance);

    // Message loop
    int Run();

private:
    HWND m_hWnd = nullptr;
    HINSTANCE m_hInstance = nullptr;
    SecureFolderManager m_manager;

    // Control IDs
    enum ControlID {
        IDC_FOLDER_PATH = 1001,
        IDC_BROWSE_BTN = 1002,
        IDC_PASSWORD = 1003,
        IDC_MODE_QUICK = 1004,
        IDC_MODE_FULL = 1005,
        IDC_MODE_CRYPTO = 1006,
        IDC_LOCK_BTN = 1007,
        IDC_UNLOCK_BTN = 1008,
        IDC_STATUS_BTN = 1009,
        IDC_PROGRESS = 1010,
        IDC_LOG = 1011,
    };

    static LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
    void OnCreate();
    void OnLock();
    void OnUnlock();
    void OnBrowse();
    void OnStatus();
    void UpdateLog(const std::wstring& text);
    void SetProgress(int percent);
};

// Initialize GUI module
void InitGUI(HINSTANCE hInstance);

// Show password input dialog (for Shell extension - unlock)
// openAfterUnlock: set to true if user wants to open folder after unlock
bool RequestPassword(const std::wstring& folderPath, std::wstring& password, bool& openAfterUnlock);

// Show password input dialog for lock (with confirm)
bool RequestPasswordForLock(const std::wstring& folderPath, std::wstring& password);

// Perform unlock operation (for Shell extension)
bool PerformUnlock(const std::wstring& folderPath, const std::wstring& password);

} // namespace SecureFolder