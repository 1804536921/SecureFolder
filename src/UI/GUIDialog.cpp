#include "GUIDialog.h"
#include "Common/Utils.h"
#include <CommCtrl.h>
#include <shlobj.h>
#include <shellapi.h>

// Icon resource ID
#define IDI_APP_ICON 101

#pragma comment(lib, "comctl32.lib")

namespace SecureFolder {

// Static members
std::wstring PasswordDialog::s_folderPath;
std::wstring PasswordDialog::s_password;
bool PasswordDialog::s_result = false;
bool PasswordDialog::s_isLockMode = false;

// Dialog context for window procedure
struct DialogContext {
    HWND hPwdEdit;
    HWND hPwdEdit2;  // For lock dialog (confirm password)
    std::wstring folderPath;
    bool isLockMode;
    bool* result;
    std::wstring* password;
    bool running;
};

static HWND g_hPwdEdit = nullptr;
static HWND g_hPwdEdit2 = nullptr;
static std::wstring g_folderPath;
static bool g_isLockMode = false;
static bool* g_result = nullptr;
static std::wstring* g_password = nullptr;
static bool g_running = true;
static bool g_openAfterUnlock = false;
static bool* g_openAfterUnlockPtr = nullptr;

// Global variables
static MainWindow* g_mainWindow = nullptr;
static HINSTANCE g_hInstance = nullptr;

// Dialog window procedure
static LRESULT CALLBACK DialogWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_COMMAND:
        {
            int cmd = LOWORD(wParam);

            if (cmd == IDOK) {
                // Get password
                wchar_t buffer[256] = {0};
                GetWindowTextW(g_hPwdEdit, buffer, 256);
                std::wstring pwd = buffer;

                if (pwd.empty()) {
                    MessageBoxW(hWnd, L"Please enter password", L"Warning", MB_ICONWARNING);
                    SetFocus(g_hPwdEdit);
                    return 0;
                }

                if (g_isLockMode) {
                    // Lock mode: check confirm password
                    wchar_t buffer2[256] = {0};
                    GetWindowTextW(g_hPwdEdit2, buffer2, 256);
                    std::wstring pwd2 = buffer2;

                    if (pwd != pwd2) {
                        MessageBoxW(hWnd, L"Passwords do not match", L"Warning", MB_ICONWARNING);
                        SetWindowTextW(g_hPwdEdit2, L"");
                        SetFocus(g_hPwdEdit2);
                        return 0;
                    }

                    *g_password = pwd;
                    *g_result = true;
                    g_running = false;
                    DestroyWindow(hWnd);
                } else {
                    // Unlock mode: just return password, don't unlock here
                    // The caller will handle the unlock operation
                    *g_password = pwd;
                    *g_result = true;
                    g_running = false;
                    DestroyWindow(hWnd);
                }
                return 0;
            } else if (cmd == 1003) {
                // Unlock and Open button: set openAfterUnlock flag
                wchar_t buffer[256] = {0};
                GetWindowTextW(g_hPwdEdit, buffer, 256);
                std::wstring pwd = buffer;

                if (pwd.empty()) {
                    MessageBoxW(hWnd, L"Please enter password", L"Warning", MB_ICONWARNING);
                    SetFocus(g_hPwdEdit);
                    return 0;
                }

                *g_password = pwd;
                *g_result = true;
                g_openAfterUnlock = true;
                if (g_openAfterUnlockPtr) *g_openAfterUnlockPtr = true;
                g_running = false;
                DestroyWindow(hWnd);
                return 0;
            } else if (cmd == IDCANCEL) {
                g_running = false;
                DestroyWindow(hWnd);
                return 0;
            }
            break;
        }

        case WM_CLOSE:
            g_running = false;
            DestroyWindow(hWnd);
            return 0;

        default:
            return DefWindowProcW(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Register dialog window class
static void RegisterDialogClass(HINSTANCE hInstance) {
    WNDCLASSEXW wcex = {0};
    wcex.cbSize = sizeof(WNDCLASSEXW);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = DialogWndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APP_ICON));
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wcex.lpszMenuName = nullptr;
    wcex.lpszClassName = L"SecureFolderDialog";
    wcex.hIconSm = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APP_ICON));

    RegisterClassExW(&wcex);
}

void InitGUI(HINSTANCE hInstance) {
    g_hInstance = hInstance;
    InitCommonControls();
    RegisterDialogClass(hInstance);
}

bool RequestPassword(const std::wstring& folderPath, std::wstring& password, bool& openAfterUnlock) {
    return PasswordDialog::Show(nullptr, folderPath, password, openAfterUnlock);
}

bool RequestPasswordForLock(const std::wstring& folderPath, std::wstring& password) {
    return PasswordDialog::ShowForLock(nullptr, folderPath, password);
}

bool PerformUnlock(const std::wstring& folderPath, const std::wstring& password) {
    SecureFolderManager manager;
    Result result = manager.UnlockFolder(folderPath, password, nullptr);
    return result.success;
}

// ==================== Password Dialog ====================

bool PasswordDialog::Show(HWND parent, const std::wstring& folderPath, std::wstring& outPassword, bool& openAfterUnlock) {
    // Set global context
    g_folderPath = folderPath;
    g_password = &outPassword;
    g_result = &s_result;
    g_isLockMode = false;
    g_running = true;
    g_hPwdEdit2 = nullptr;
    g_openAfterUnlock = false;
    g_openAfterUnlockPtr = &openAfterUnlock;
    openAfterUnlock = false;  // Initialize to false

    // Ensure g_hInstance is set
    if (!g_hInstance) {
        MessageBoxW(nullptr, L"GUI not initialized", L"Error", MB_ICONERROR);
        return false;
    }

    HWND hDlg = CreateWindowExW(
        WS_EX_DLGMODALFRAME | WS_EX_TOPMOST | WS_EX_CONTROLPARENT,
        L"SecureFolderDialog",  // Custom dialog class
        L"SecureFolder - Unlock Folder",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT,
        320, 180,
        parent, nullptr, g_hInstance, nullptr
    );

    if (!hDlg) {
        MessageBoxW(nullptr, L"Cannot create dialog window", L"Error", MB_ICONERROR);
        outPassword.clear();
        return false;
    }

    // Create controls
    CreateWindowW(L"STATIC", L"Encrypted folder:", WS_VISIBLE | WS_CHILD,
                  10, 10, 300, 20, hDlg, nullptr, g_hInstance, nullptr);

    std::wstring displayPath = folderPath;
    if (Utils::IsCLSIDFolder(folderPath)) {
        displayPath = Utils::ExtractOriginalName(folderPath) + L" (locked)";
    }

    CreateWindowW(L"STATIC", displayPath.c_str(), WS_VISIBLE | WS_CHILD | SS_SUNKEN,
                  10, 35, 300, 25, hDlg, nullptr, g_hInstance, nullptr);

    CreateWindowW(L"STATIC", L"Enter password:", WS_VISIBLE | WS_CHILD,
                  10, 70, 100, 20, hDlg, nullptr, g_hInstance, nullptr);

    g_hPwdEdit = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL,
                               110, 70, 200, 25, hDlg, (HMENU)1002, g_hInstance, nullptr);

    CreateWindowW(L"BUTTON", L"Unlock", WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | WS_TABSTOP,
                  50, 110, 80, 30, hDlg, (HMENU)IDOK, g_hInstance, nullptr);

    CreateWindowW(L"BUTTON", L"Unlock & Open", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP,
                  140, 110, 100, 30, hDlg, (HMENU)1003, g_hInstance, nullptr);

    CreateWindowW(L"BUTTON", L"Cancel", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP,
                  250, 110, 60, 30, hDlg, (HMENU)IDCANCEL, g_hInstance, nullptr);

    CreateWindowW(L"STATIC", L"Tip: Correct password will unlock and restore folder.",
                  WS_VISIBLE | WS_CHILD, 10, 145, 300, 20, hDlg, nullptr, g_hInstance, nullptr);

    // Center window
    RECT rcOwner, rcDlg;
    GetWindowRect(parent ? parent : GetDesktopWindow(), &rcOwner);
    GetWindowRect(hDlg, &rcDlg);
    int x = rcOwner.left + (rcOwner.right - rcOwner.left - rcDlg.right + rcDlg.left) / 2;
    int y = rcOwner.top + (rcOwner.bottom - rcOwner.top - rcDlg.bottom + rcDlg.top) / 2;
    SetWindowPos(hDlg, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

    ShowWindow(hDlg, SW_SHOW);
    SetFocus(g_hPwdEdit);

    // Message loop - simple dispatch loop
    MSG msg;
    while (g_running && GetMessageW(&msg, nullptr, 0, 0)) {
        if (IsDialogMessageW(hDlg, &msg)) {
            continue;  // Handle keyboard navigation
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return s_result;
}

bool PasswordDialog::ShowForLock(HWND parent, const std::wstring& folderPath, std::wstring& outPassword) {
    // Set global context
    g_folderPath = folderPath;
    g_password = &outPassword;
    g_result = &s_result;
    g_isLockMode = true;
    g_running = true;

    // Ensure g_hInstance is set
    if (!g_hInstance) {
        MessageBoxW(nullptr, L"GUI not initialized", L"Error", MB_ICONERROR);
        return false;
    }

    HWND hDlg = CreateWindowExW(
        WS_EX_DLGMODALFRAME | WS_EX_TOPMOST | WS_EX_CONTROLPARENT,
        L"SecureFolderDialog",  // Custom dialog class
        L"SecureFolder - Lock Folder",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT,
        320, 220,
        parent, nullptr, g_hInstance, nullptr
    );

    if (!hDlg) {
        MessageBoxW(nullptr, L"Cannot create lock dialog window", L"Error", MB_ICONERROR);
        outPassword.clear();
        return false;
    }

    // Create controls
    CreateWindowW(L"STATIC", L"Folder to lock:", WS_VISIBLE | WS_CHILD,
                  10, 10, 300, 20, hDlg, nullptr, g_hInstance, nullptr);

    CreateWindowW(L"STATIC", folderPath.c_str(), WS_VISIBLE | WS_CHILD | SS_SUNKEN,
                  10, 35, 300, 25, hDlg, nullptr, g_hInstance, nullptr);

    CreateWindowW(L"STATIC", L"Password:", WS_VISIBLE | WS_CHILD,
                  10, 70, 100, 20, hDlg, nullptr, g_hInstance, nullptr);

    g_hPwdEdit = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL,
                               110, 70, 200, 25, hDlg, (HMENU)1002, g_hInstance, nullptr);

    CreateWindowW(L"STATIC", L"Confirm:", WS_VISIBLE | WS_CHILD,
                  10, 100, 100, 20, hDlg, nullptr, g_hInstance, nullptr);

    g_hPwdEdit2 = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL,
                                110, 100, 200, 25, hDlg, (HMENU)1004, g_hInstance, nullptr);

    CreateWindowW(L"BUTTON", L"Lock", WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | WS_TABSTOP,
                  100, 140, 80, 30, hDlg, (HMENU)IDOK, g_hInstance, nullptr);

    CreateWindowW(L"BUTTON", L"Cancel", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP,
                  190, 140, 60, 30, hDlg, (HMENU)IDCANCEL, g_hInstance, nullptr);

    CreateWindowW(L"STATIC", L"Tip: Password will be required to unlock.",
                  WS_VISIBLE | WS_CHILD, 10, 180, 300, 20, hDlg, nullptr, g_hInstance, nullptr);

    // Center window
    RECT rcOwner, rcDlg;
    GetWindowRect(parent ? parent : GetDesktopWindow(), &rcOwner);
    GetWindowRect(hDlg, &rcDlg);
    int x = rcOwner.left + (rcOwner.right - rcOwner.left - rcDlg.right + rcDlg.left) / 2;
    int y = rcOwner.top + (rcOwner.bottom - rcOwner.top - rcDlg.bottom + rcDlg.top) / 2;
    SetWindowPos(hDlg, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

    ShowWindow(hDlg, SW_SHOW);
    SetFocus(g_hPwdEdit);

    // Message loop - simple dispatch loop
    MSG msg;
    while (g_running && GetMessageW(&msg, nullptr, 0, 0)) {
        if (IsDialogMessageW(hDlg, &msg)) {
            continue;  // Handle keyboard navigation
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    s_isLockMode = false;
    return s_result;
}

void PasswordDialog::ShowSuccess(HWND parent, const std::wstring& message) {
    MessageBoxW(parent, message.c_str(), L"Success", MB_ICONINFORMATION);
}

void PasswordDialog::ShowError(HWND parent, const std::wstring& message) {
    MessageBoxW(parent, message.c_str(), L"Error", MB_ICONERROR);
}

// ==================== Main Window ====================

MainWindow::MainWindow() {
    g_mainWindow = this;
}

MainWindow::~MainWindow() {
    g_mainWindow = nullptr;
}

bool MainWindow::Create(HINSTANCE hInstance) {
    m_hInstance = hInstance;

    WNDCLASSEXW wcex = {0};
    wcex.cbSize = sizeof(WNDCLASSEXW);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = sizeof(MainWindow*);
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APP_ICON));
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = nullptr;
    wcex.lpszClassName = L"SecureFolderMainWindow";
    wcex.hIconSm = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APP_ICON));

    if (!RegisterClassExW(&wcex)) {
        return false;
    }

    m_hWnd = CreateWindowW(
        L"SecureFolderMainWindow",
        L"SecureFolder - Folder Encryption Tool",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        600, 450,
        nullptr, nullptr,
        hInstance, this
    );

    if (!m_hWnd) {
        return false;
    }

    ShowWindow(m_hWnd, SW_SHOW);
    UpdateWindow(m_hWnd);

    return true;
}

int MainWindow::Run() {
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}

LRESULT CALLBACK MainWindow::WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    MainWindow* pThis = nullptr;

    if (message == WM_CREATE) {
        pThis = (MainWindow*)((CREATESTRUCT*)lParam)->lpCreateParams;
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pThis);
        pThis->m_hWnd = hWnd;
        pThis->OnCreate();
    } else {
        pThis = (MainWindow*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    }

    if (!pThis) {
        return DefWindowProc(hWnd, message, wParam, lParam);
    }

    switch (message) {
        case WM_COMMAND:
        {
            switch (LOWORD(wParam)) {
                case IDC_BROWSE_BTN:
                    pThis->OnBrowse();
                    break;
                case IDC_LOCK_BTN:
                    pThis->OnLock();
                    break;
                case IDC_UNLOCK_BTN:
                    pThis->OnUnlock();
                    break;
                case IDC_STATUS_BTN:
                    pThis->OnStatus();
                    break;
            }
            break;
        }

        case WM_DESTROY:
        {
            PostQuitMessage(0);
            break;
        }

        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
    }

    return 0;
}

void MainWindow::OnCreate() {
    // Folder path label
    CreateWindowW(L"STATIC", L"Folder path:", WS_VISIBLE | WS_CHILD,
                  20, 20, 100, 20, m_hWnd, nullptr, m_hInstance, nullptr);

    // Folder path input
    CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
                  120, 20, 350, 25, m_hWnd, (HMENU)IDC_FOLDER_PATH, m_hInstance, nullptr);

    // Browse button
    CreateWindowW(L"BUTTON", L"Browse...", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                  480, 20, 80, 25, m_hWnd, (HMENU)IDC_BROWSE_BTN, m_hInstance, nullptr);

    // Password label
    CreateWindowW(L"STATIC", L"Password:", WS_VISIBLE | WS_CHILD,
                  20, 55, 100, 20, m_hWnd, nullptr, m_hInstance, nullptr);

    // Password input
    CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL,
                  120, 55, 350, 25, m_hWnd, (HMENU)IDC_PASSWORD, m_hInstance, nullptr);

    // Mode label
    CreateWindowW(L"STATIC", L"Encrypt mode:", WS_VISIBLE | WS_CHILD,
                  20, 90, 100, 20, m_hWnd, nullptr, m_hInstance, nullptr);

    // Quick mode radio
    CreateWindowW(L"BUTTON", L"Quick disguise (fast)", WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON | WS_GROUP,
                  120, 90, 180, 20, m_hWnd, (HMENU)IDC_MODE_QUICK, m_hInstance, nullptr);

    // Full mode radio (default)
    HWND hFullRadio = CreateWindowW(L"BUTTON", L"Full encryption (disguise+AES)", WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON,
                                    120, 115, 220, 20, m_hWnd, (HMENU)IDC_MODE_FULL, m_hInstance, nullptr);
    SendMessage(hFullRadio, BM_SETCHECK, BST_CHECKED, 0);

    // Crypto only radio
    CreateWindowW(L"BUTTON", L"Crypto only (no disguise)", WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON,
                  120, 140, 180, 20, m_hWnd, (HMENU)IDC_MODE_CRYPTO, m_hInstance, nullptr);

    // Lock button
    CreateWindowW(L"BUTTON", L"Lock", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                  120, 180, 100, 35, m_hWnd, (HMENU)IDC_LOCK_BTN, m_hInstance, nullptr);

    // Unlock button
    CreateWindowW(L"BUTTON", L"Unlock", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                  230, 180, 100, 35, m_hWnd, (HMENU)IDC_UNLOCK_BTN, m_hInstance, nullptr);

    // Status button
    CreateWindowW(L"BUTTON", L"Status", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                  340, 180, 100, 35, m_hWnd, (HMENU)IDC_STATUS_BTN, m_hInstance, nullptr);

    // Progress bar
    CreateWindowW(PROGRESS_CLASSW, L"", WS_VISIBLE | WS_CHILD,
                  20, 230, 540, 25, m_hWnd, (HMENU)IDC_PROGRESS, m_hInstance, nullptr);

    // Log output
    CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
                  20, 270, 540, 130, m_hWnd, (HMENU)IDC_LOG, m_hInstance, nullptr);
}

void MainWindow::OnBrowse() {
    // Use GetOpenFileName for .securefolder files or BROWSEINFO for folders
    // First, ask user what they want to select
    int choice = MessageBoxW(m_hWnd,
        L"Do you want to select:\n\n"
        L"[Yes] - A folder to encrypt\n"
        L"[No] - A .securefolder file to decrypt\n"
        L"[Cancel] - Cancel selection",
        L"Select Item Type",
        MB_YESNOCANCEL | MB_ICONQUESTION);

    if (choice == IDYES) {
        // Select folder to encrypt
        wchar_t path[MAX_PATH] = {0};

        BROWSEINFOW bi = {0};
        bi.hwndOwner = m_hWnd;
        bi.lpszTitle = L"Select folder to encrypt";
        bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

        LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
        if (pidl) {
            SHGetPathFromIDListW(pidl, path);
            SetDlgItemTextW(m_hWnd, IDC_FOLDER_PATH, path);
            CoTaskMemFree(pidl);
        }
    } else if (choice == IDNO) {
        // Select .securefolder file to decrypt
        OPENFILENAMEW ofn = {0};
        wchar_t path[MAX_PATH] = {0};

        ofn.lStructSize = sizeof(OPENFILENAMEW);
        ofn.hwndOwner = m_hWnd;
        ofn.lpstrFilter = L"SecureFolder Files (*.securefolder)\0*.securefolder\0All Files (*.*)\0*.*\0";
        ofn.lpstrFile = path;
        ofn.nMaxFile = MAX_PATH;
        ofn.lpstrTitle = L"Select encrypted file to decrypt";
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

        if (GetOpenFileNameW(&ofn)) {
            SetDlgItemTextW(m_hWnd, IDC_FOLDER_PATH, path);
        }
    }
}

void MainWindow::OnLock() {
    wchar_t path[MAX_PATH] = {0};
    GetDlgItemTextW(m_hWnd, IDC_FOLDER_PATH, path, MAX_PATH);
    std::wstring folderPath = path;

    if (folderPath.empty()) {
        MessageBoxW(m_hWnd, L"Please select a folder", L"Warning", MB_ICONWARNING);
        return;
    }

    wchar_t pwd[256] = {0};
    GetDlgItemTextW(m_hWnd, IDC_PASSWORD, pwd, 256);
    std::wstring password = pwd;

    if (password.empty()) {
        MessageBoxW(m_hWnd, L"Please enter password", L"Warning", MB_ICONWARNING);
        return;
    }

    EncryptMode mode = EncryptMode::FullEncrypt;
    if (IsDlgButtonChecked(m_hWnd, IDC_MODE_QUICK) == BST_CHECKED) {
        mode = EncryptMode::QuickLock;
    } else if (IsDlgButtonChecked(m_hWnd, IDC_MODE_CRYPTO) == BST_CHECKED) {
        mode = EncryptMode::CryptoOnly;
    }

    UpdateLog(L"Starting encryption: " + folderPath);
    SetProgress(0);

    EncryptConfig config;
    config.mode = mode;

    class SimpleProgress : public IProgressCallback {
    public:
        HWND m_hWnd;
        void OnProgress(int current, int total, const std::wstring& file) override {
            int percent = total > 0 ? current * 100 / total : 0;
            SendDlgItemMessage(m_hWnd, IDC_PROGRESS, PBM_SETPOS, percent, 0);
        }
        void OnError(const std::wstring& error) override {}
    };

    SimpleProgress progress;
    progress.m_hWnd = m_hWnd;

    Result result = m_manager.LockFolder(folderPath, password, mode, config, &progress);

    SetProgress(100);

    if (result.success) {
        UpdateLog(L"Encryption successful!");
        MessageBoxW(m_hWnd, result.message.c_str(), L"Success", MB_ICONINFORMATION);
    } else {
        UpdateLog(L"Encryption failed: " + result.message);
        MessageBoxW(m_hWnd, result.message.c_str(), L"Error", MB_ICONERROR);
    }
}

void MainWindow::OnUnlock() {
    wchar_t path[MAX_PATH] = {0};
    GetDlgItemTextW(m_hWnd, IDC_FOLDER_PATH, path, MAX_PATH);
    std::wstring folderPath = path;

    if (folderPath.empty()) {
        MessageBoxW(m_hWnd, L"Please select a folder", L"Warning", MB_ICONWARNING);
        return;
    }

    wchar_t pwd[256] = {0};
    GetDlgItemTextW(m_hWnd, IDC_PASSWORD, pwd, 256);
    std::wstring password = pwd;

    if (password.empty()) {
        MessageBoxW(m_hWnd, L"Please enter password", L"Warning", MB_ICONWARNING);
        return;
    }

    UpdateLog(L"Starting decryption: " + folderPath);
    SetProgress(0);

    Result result = m_manager.UnlockFolder(folderPath, password, nullptr);

    SetProgress(100);

    if (result.success) {
        UpdateLog(L"Decryption successful!");
        MessageBoxW(m_hWnd, result.message.c_str(), L"Success", MB_ICONINFORMATION);
    } else {
        UpdateLog(L"Decryption failed: " + result.message);
        MessageBoxW(m_hWnd, result.message.c_str(), L"Error", MB_ICONERROR);
    }
}

void MainWindow::OnStatus() {
    wchar_t path[MAX_PATH] = {0};
    GetDlgItemTextW(m_hWnd, IDC_FOLDER_PATH, path, MAX_PATH);
    std::wstring folderPath = path;

    if (folderPath.empty()) {
        MessageBoxW(m_hWnd, L"Please select a folder", L"Warning", MB_ICONWARNING);
        return;
    }

    auto status = m_manager.GetFolderStatus(folderPath);

    std::wstring info;
    info += L"Folder Status:\n";
    info += L"Locked: " + (status.isLocked ? std::wstring(L"Yes") : std::wstring(L"No")) + L"\n";
    info += L"Disguised: " + (status.isDisguised ? std::wstring(L"Yes") : std::wstring(L"No")) + L"\n";
    info += L"Encrypted: " + (status.isEncrypted ? std::wstring(L"Yes") : std::wstring(L"No")) + L"\n";

    if (status.isLocked) {
        info += L"Mode: ";
        switch (status.mode) {
            case EncryptMode::QuickLock: info += L"Quick disguise\n"; break;
            case EncryptMode::FullEncrypt: info += L"Full encryption\n"; break;
            case EncryptMode::CryptoOnly: info += L"Crypto only\n"; break;
        }
        info += L"Original: " + status.originalPath + L"\n";
    }

    UpdateLog(info);
    MessageBoxW(m_hWnd, info.c_str(), L"Folder Status", MB_ICONINFORMATION);
}

void MainWindow::UpdateLog(const std::wstring& text) {
    HWND hLog = GetDlgItem(m_hWnd, IDC_LOG);
    int len = GetWindowTextLengthW(hLog);
    SendMessageW(hLog, EM_SETSEL, len, len);
    SendMessageW(hLog, EM_REPLACESEL, FALSE, (LPARAM)(text + L"\n").c_str());
}

void MainWindow::SetProgress(int percent) {
    SendDlgItemMessage(m_hWnd, IDC_PROGRESS, PBM_SETPOS, percent, 0);
}

} // namespace SecureFolder