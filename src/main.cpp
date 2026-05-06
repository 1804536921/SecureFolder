// SecureFolder - Windows Folder Encryption Tool
// Main entry point (GUI and CLI modes)

#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>
#include <shellapi.h>
#include <fcntl.h>
#include <io.h>
#include "Core/SecureFolderManager.h"
#include "Common/Utils.h"
#include "UI/GUIDialog.h"

using namespace SecureFolder;

// Console progress callback
class ConsoleProgressCallback : public IProgressCallback {
public:
    void OnProgress(int current, int total, const std::wstring& currentFile) override {
        int percent = (total > 0) ? (current * 100 / total) : 0;
        std::wcout << L"\rProgress: " << percent << L"% - " << currentFile.substr(0, 50);
        if (currentFile.size() > 50) std::wcout << L"...";
        std::wcout << std::flush;
    }

    void OnError(const std::wstring& error) override {
        std::wcout << L"\nError: " << error << std::endl;
    }

    bool ShouldCancel() override { return false; }
};

// Print help
void PrintHelp() {
    std::wcout << L"\n";
    std::wcout << L"SecureFolder - Windows Folder Encryption Tool\n";
    std::wcout << L"========================================\n";
    std::wcout << L"\n";
    std::wcout << L"Usage:\n";
    std::wcout << L"  SecureFolder                   Open GUI\n";
    std::wcout << L"  SecureFolder <command> [opts]  CLI mode\n";
    std::wcout << L"\n";
    std::wcout << L"Commands:\n";
    std::wcout << L"  lock <path> [password]     Lock folder\n";
    std::wcout << L"  unlock <path> [password]   Unlock folder\n";
    std::wcout << L"  status <path>              View folder status\n";
    std::wcout << L"  scan <path>                Scan locked folders\n";
    std::wcout << L"  gui                        Open GUI\n";
    std::wcout << L"  help                       Show help\n";
    std::wcout << L"\n";
    std::wcout << L"Options:\n";
    std::wcout << L"  -m <mode>     Mode: quick/full/crypto\n";
    std::wcout << L"  -p <password> Specify password\n";
    std::wcout << L"  -i <count>    PBKDF2 iterations (default 100000)\n";
    std::wcout << L"  -n            No secure delete\n";
    std::wcout << L"\n";
}

// Remove quotes from path if present
std::wstring CleanPath(const std::wstring& path) {
    if (path.size() >= 2 && path.front() == L'"' && path.back() == L'"') {
        return path.substr(1, path.size() - 2);
    }
    return path;
}

// Get password input (hidden)
std::wstring GetPasswordInput(const std::wstring& prompt) {
    std::wcout << prompt;

    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);

    std::wstring password;
    std::wcin >> password;

    SetConsoleMode(hStdin, mode);
    std::wcout << L"\n";

    return password;
}

// Parse encrypt mode
EncryptMode ParseEncryptMode(const std::wstring& modeStr) {
    if (modeStr == L"quick" || modeStr == L"0") return EncryptMode::QuickLock;
    if (modeStr == L"crypto" || modeStr == L"2") return EncryptMode::CryptoOnly;
    return EncryptMode::FullEncrypt;
}

// Lock command
int CmdLock(const std::vector<std::wstring>& args) {
    if (args.size() < 2) {
        std::wcout << L"Error: Need folder path\n";
        std::wcout << L"Usage: SecureFolder lock \"folder_path\"\n";
        return 1;
    }

    std::wstring folderPath = CleanPath(args[1]);
    std::wstring password;
    EncryptConfig config;
    config.mode = EncryptMode::FullEncrypt;

    for (size_t i = 2; i < args.size(); i++) {
        if (args[i] == L"-m" && i + 1 < args.size()) {
            config.mode = ParseEncryptMode(args[i + 1]);
            i++;
        } else if (args[i] == L"-p" && i + 1 < args.size()) {
            password = args[i + 1];
            i++;
        } else if (args[i] == L"-i" && i + 1 < args.size()) {
            config.pbkdf2Iterations = std::stoi(args[i + 1]);
            i++;
        } else if (args[i] == L"-n") {
            config.secureDelete = false;
        }
    }

    if (password.empty()) {
        password = GetPasswordInput(L"Enter encryption password: ");
        if (password.empty()) {
            std::wcout << L"Error: Password cannot be empty\n";
            return 1;
        }

        std::wstring confirm = GetPasswordInput(L"Confirm password: ");
        if (password != confirm) {
            std::wcout << L"Error: Passwords do not match\n";
            return 1;
        }
    }

    if (!Utils::FolderExists(folderPath)) {
        std::wcout << L"Error: Folder not found: " << folderPath << std::endl;
        return 1;
    }

    SecureFolderManager manager;
    manager.SetConfig(config);

    ConsoleProgressCallback callback;
    std::wcout << L"\nEncrypting folder...\n";

    Result result = manager.LockFolder(folderPath, password, config.mode, config, &callback);

    std::wcout << L"\n\n";

    if (result.success) {
        std::wcout << L"Success: " << result.message << std::endl;
        std::wcout << L"\nFolder now appears as Control Panel icon\n";
        std::wcout << L"Double-click or right-click to unlock\n";
    } else {
        std::wcout << L"Failed: " << result.message << std::endl;
        return 1;
    }

    return 0;
}

// Unlock command
int CmdUnlock(const std::vector<std::wstring>& args) {
    if (args.size() < 2) {
        std::wcout << L"Error: Need folder path\n";
        std::wcout << L"Usage: SecureFolder unlock \"folder_path\"\n";
        return 1;
    }

    std::wstring folderPath = CleanPath(args[1]);
    std::wstring password;

    for (size_t i = 2; i < args.size(); i++) {
        if (args[i] == L"-p" && i + 1 < args.size()) {
            password = args[i + 1];
            i++;
        }
    }

    if (password.empty()) {
        password = GetPasswordInput(L"Enter decryption password: ");
    }

    DWORD attr = GetFileAttributesW(folderPath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        std::wcout << L"Error: Folder not found or inaccessible\n";
        std::wcout << L"Tip: Encrypted folder appears as Control Panel icon\n";
        return 1;
    }

    SecureFolderManager manager;
    ConsoleProgressCallback callback;
    std::wcout << L"\nDecrypting folder...\n";

    Result result = manager.UnlockFolder(folderPath, password, &callback);

    std::wcout << L"\n\n";

    if (result.success) {
        std::wcout << L"Success: " << result.message << std::endl;
    } else {
        std::wcout << L"Failed: " << result.message << std::endl;
        return 1;
    }

    return 0;
}

// Status command
int CmdStatus(const std::vector<std::wstring>& args) {
    if (args.size() < 2) {
        std::wcout << L"Error: Need folder path\n";
        return 1;
    }

    std::wstring folderPath = CleanPath(args[1]);

    SecureFolderManager manager;
    auto status = manager.GetFolderStatus(folderPath);

    std::wcout << L"\nFolder Status:\n";
    std::wcout << L"--------------------------------\n";
    std::wcout << L"Path: " << folderPath << std::endl;
    std::wcout << L"Locked: " << (status.isLocked ? L"Yes" : L"No") << std::endl;
    std::wcout << L"Disguised: " << (status.isDisguised ? L"Yes" : L"No") << std::endl;
    std::wcout << L"Encrypted: " << (status.isEncrypted ? L"Yes" : L"No") << std::endl;
    std::wcout << L"Lock file: " << (status.hasLockFile ? L"Yes" : L"No") << std::endl;

    if (status.isLocked) {
        std::wcout << L"Mode: ";
        switch (status.mode) {
            case EncryptMode::QuickLock: std::wcout << L"Quick disguise"; break;
            case EncryptMode::FullEncrypt: std::wcout << L"Full encryption"; break;
            case EncryptMode::CryptoOnly: std::wcout << L"Crypto only"; break;
        }
        std::wcout << std::endl;
        std::wcout << L"Original name: " << status.originalPath << std::endl;
    }
    std::wcout << L"--------------------------------\n";

    return 0;
}

// Scan command
int CmdScan(const std::vector<std::wstring>& args) {
    std::wstring scanPath = (args.size() >= 2) ? args[1] : L"D:\\";

    SecureFolderManager manager;
    auto lockedFolders = manager.ScanLockedFolders(scanPath);

    std::wcout << L"\nScan Results:\n";
    std::wcout << L"Scan path: " << scanPath << std::endl;
    std::wcout << L"Found " << lockedFolders.size() << L" locked folders\n\n";

    for (const auto& folder : lockedFolders) {
        auto status = manager.GetFolderStatus(folder);
        std::wcout << L"  " << folder << std::endl;
        std::wcout << L"    Original: " << status.originalPath << std::endl;
        std::wcout << L"    Mode: ";
        switch (status.mode) {
            case EncryptMode::QuickLock: std::wcout << L"Quick disguise"; break;
            case EncryptMode::FullEncrypt: std::wcout << L"Full encryption"; break;
            case EncryptMode::CryptoOnly: std::wcout << L"Crypto only"; break;
        }
        std::wcout << L"\n\n";
    }

    return 0;
}

// GUI Lock command (for shell extension)
int CmdLockGUI(const std::wstring& folderPath) {
    if (folderPath.empty()) {
        MessageBoxW(nullptr, L"No folder path specified", L"Error", MB_ICONERROR);
        return 1;
    }

    std::wstring cleanPath = CleanPath(folderPath);
    if (!Utils::FolderExists(cleanPath)) {
        std::wstring errMsg = L"Folder not found:\n" + cleanPath;
        MessageBoxW(nullptr, errMsg.c_str(), L"Error", MB_ICONERROR);
        return 1;
    }

    std::wstring password;
    if (!RequestPasswordForLock(cleanPath, password)) {
        return 1;  // User cancelled
    }

    EncryptConfig config;
    config.mode = EncryptMode::FullEncrypt;

    SecureFolderManager manager;
    Result result = manager.LockFolder(cleanPath, password, config.mode, config, nullptr);

    if (result.success) {
        MessageBoxW(nullptr, result.message.c_str(), L"Success", MB_ICONINFORMATION);
        return 0;
    } else {
        MessageBoxW(nullptr, result.message.c_str(), L"Error", MB_ICONERROR);
        return 1;
    }
}

// Helper: Find the actual locked folder path
std::wstring FindLockedFolder(const std::wstring& inputPath) {
    std::wstring cleanPath = CleanPath(inputPath);

    // If path already has .securefolder suffix, use it directly
    if (cleanPath.find(LOCKED_FOLDER_SUFFIX) != std::wstring::npos) {
        if (Utils::FolderExists(cleanPath)) {
            return cleanPath;
        }
    }

    // Check if .securefolder version exists
    std::wstring lockedPath = cleanPath + LOCKED_FOLDER_SUFFIX;
    if (Utils::FolderExists(lockedPath)) {
        return lockedPath;
    }

    // Check if original path has lock file (backward compatibility)
    std::wstring lockFile = cleanPath + L"\\" + LOCK_FILE_NAME;
    if (Utils::FileExists(lockFile)) {
        return cleanPath;
    }

    // Not found
    return L"";
}

// GUI Unlock command (for shell extension)
int CmdUnlockGUI(const std::wstring& folderPath) {
    if (folderPath.empty()) {
        MessageBoxW(nullptr, L"No folder path specified", L"Error", MB_ICONERROR);
        return 1;
    }

    // Find actual locked folder
    std::wstring lockedPath = FindLockedFolder(folderPath);
    if (lockedPath.empty()) {
        std::wstring msg = L"Cannot find locked folder:\n" + folderPath;
        if (folderPath.find(LOCKED_FOLDER_SUFFIX) == std::wstring::npos) {
            msg += L"\n(Try: " + folderPath + LOCKED_FOLDER_SUFFIX + L")";
        }
        MessageBoxW(nullptr, msg.c_str(), L"Error", MB_ICONERROR);
        return 1;
    }

    std::wstring password;
    if (!RequestPassword(lockedPath, password)) {
        return 1;  // User cancelled
    }

    SecureFolderManager manager;
    Result result = manager.UnlockFolder(lockedPath, password, nullptr);

    if (result.success) {
        MessageBoxW(nullptr, result.message.c_str(), L"Success", MB_ICONINFORMATION);
        // Optionally open the unlocked folder
        std::wstring openPath = lockedPath;
        size_t pos = openPath.find(LOCKED_FOLDER_SUFFIX);
        if (pos != std::wstring::npos) {
            openPath = openPath.substr(0, pos);  // Use restored name
        }
        ShellExecuteW(nullptr, L"open", openPath.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        return 0;
    } else {
        MessageBoxW(nullptr, result.message.c_str(), L"Error", MB_ICONERROR);
        return 1;
    }
}

// Double-click handler: intercept folder open
int CmdOpenFolder(const std::wstring& folderPath) {
    if (folderPath.empty()) {
        // Just open explorer
        ShellExecuteW(nullptr, L"open", L"expler.exe", nullptr, nullptr, SW_SHOWNORMAL);
        return 0;
    }

    std::wstring cleanPath = CleanPath(folderPath);

    // Check if folder is encrypted/locked
    SecureFolderManager manager;
    auto status = manager.GetFolderStatus(cleanPath);

    if (status.isLocked) {
        // Folder is locked - show password dialog
        std::wstring password;
        if (!RequestPassword(cleanPath, password)) {
            // User cancelled - don't open folder
            return 1;
        }

        // Try to unlock
        Result result = manager.UnlockFolder(cleanPath, password, nullptr);

        if (result.success) {
            // Unlock successful - open folder
            ShellExecuteW(nullptr, L"open", cleanPath.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            return 0;
        } else {
            // Wrong password or error
            MessageBoxW(nullptr, result.message.c_str(), L"Error", MB_ICONERROR);
            return 1;
        }
    } else {
        // Folder is not locked - open normally
        ShellExecuteW(nullptr, L"open", cleanPath.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        return 0;
    }
}

// GUI mode
int RunGUI(HINSTANCE hInstance) {
    InitGUI(hInstance);

    MainWindow mainWindow;
    if (!mainWindow.Create(hInstance)) {
        MessageBoxW(nullptr, L"Cannot create main window", L"Error", MB_ICONERROR);
        return 1;
    }

    return mainWindow.Run();
}

// Main function
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    InitGUI(hInstance);

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    if (argc <= 1 || (argc > 1 && std::wstring(argv[1]) == L"gui")) {
        LocalFree(argv);
        return RunGUI(hInstance);
    }

    std::wstring command = argv[1];

    // Handle GUI mode commands first (no console needed)
    if (command == L"lock-gui") {
        std::wstring folderPath = (argc >= 3) ? CleanPath(argv[2]) : L"";
        LocalFree(argv);
        return CmdLockGUI(folderPath);
    } else if (command == L"unlock-gui") {
        std::wstring folderPath = (argc >= 3) ? CleanPath(argv[2]) : L"";
        LocalFree(argv);
        return CmdUnlockGUI(folderPath);
    } else if (command == L"open-folder") {
        // Double-click handler: check if encrypted, show password dialog if needed
        std::wstring folderPath = (argc >= 3) ? CleanPath(argv[2]) : L"";
        LocalFree(argv);
        return CmdOpenFolder(folderPath);
    }

    // Console mode for other commands
    AllocConsole();
    SetConsoleTitleW(L"SecureFolder CLI");
    SetConsoleOutputCP(CP_UTF8);
    _setmode(_fileno(stdout), _O_WTEXT);
    _setmode(_fileno(stdin), _O_WTEXT);

    std::vector<std::wstring> args;
    args.push_back(command);  // First arg is the command
    for (int i = 2; i < argc; i++) {
        args.push_back(argv[i]);
    }
    LocalFree(argv);

    int result = 0;
    if (command == L"lock") {
        result = CmdLock(args);
    } else if (command == L"unlock") {
        result = CmdUnlock(args);
    } else if (command == L"status") {
        result = CmdStatus(args);
    } else if (command == L"scan") {
        result = CmdScan(args);
    } else if (command == L"help" || command == L"-h" || command == L"--help") {
        PrintHelp();
    } else {
        std::wcout << L"Unknown command: " << command << std::endl;
        PrintHelp();
        result = 1;
    }

    std::wcout << L"\nPress any key to close...";
    _getwch();
    FreeConsole();

    return result;
}