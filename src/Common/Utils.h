#pragma once

// Utility functions for SecureFolder

#include "Types.h"
#include <filesystem>

namespace SecureFolder {
namespace Utils {

// Get file size
inline uint64_t GetFileSize(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA attr;
    if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attr)) {
        return (static_cast<uint64_t>(attr.nFileSizeHigh) << 32) | attr.nFileSizeLow;
    }
    return 0;
}

// Get file time
inline bool GetFileTime(const std::wstring& path, FILETIME* creation, FILETIME* lastAccess, FILETIME* lastWrite) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    bool result = ::GetFileTime(hFile, creation, lastAccess, lastWrite);
    CloseHandle(hFile);
    return result;
}

// Set file time
inline bool SetFileTime(const std::wstring& path, const FILETIME* creation, const FILETIME* lastAccess, const FILETIME* lastWrite) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    bool result = ::SetFileTime(hFile, creation, lastAccess, lastWrite);
    CloseHandle(hFile);
    return result;
}

// Get all files in folder
inline std::vector<FileInfo> GetAllFiles(const std::wstring& folderPath, const std::vector<std::wstring>& excludeExt = {}) {
    std::vector<FileInfo> files;
    std::filesystem::path root(folderPath);

    for (auto& entry : std::filesystem::recursive_directory_iterator(root)) {
        if (!entry.is_directory()) {
            std::wstring path = entry.path().wstring();
            std::wstring ext = entry.path().extension().wstring();

            bool excluded = false;
            for (const auto& e : excludeExt) {
                if (ext == e) { excluded = true; break; }
            }
            if (excluded) continue;

            if (entry.path().filename() == LOCK_FILE_NAME) continue;

            FileInfo info;
            info.path = path;
            info.relativePath = entry.path().lexically_relative(root).wstring();
            info.size = entry.file_size();
            info.isDirectory = false;
            files.push_back(info);
        }
    }
    return files;
}

// Check if folder exists
inline bool FolderExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES) && (attr & FILE_ATTRIBUTE_DIRECTORY);
}

// Check if file exists
inline bool FileExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES) && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

// Create directory
inline bool CreateDir(const std::wstring& path) {
    return CreateDirectoryW(path.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS;
}

// Delete file safely
inline bool DeleteFileSafe(const std::wstring& path) {
    return DeleteFileW(path.c_str());
}

// Rename folder
inline bool RenameFolder(const std::wstring& oldPath, const std::wstring& newPath) {
    return MoveFileW(oldPath.c_str(), newPath.c_str());
}

// Check if CLSID disguised folder
inline bool IsCLSIDFolder(const std::wstring& path) {
    size_t pos = path.find(L".{");
    return pos != std::wstring::npos && path.back() == L'}';
}

// Extract original folder name (remove CLSID or .securefolder extension)
inline std::wstring ExtractOriginalName(const std::wstring& path) {
    // First check for CLSID format: path.{CLSID}
    size_t pos = path.find(L".{");
    if (pos != std::wstring::npos) {
        return path.substr(0, pos);
    }

    // Then check for .securefolder package file extension
    size_t extPos = path.find(PACKAGE_FILE_EXTENSION);
    if (extPos != std::wstring::npos) {
        return path.substr(0, extPos);
    }

    return path;
}

// Generate random string
inline std::wstring GenerateRandomString(size_t length) {
    static const wchar_t chars[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::wstring result;
    HCRYPTPROV hProv = 0;

    if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        for (size_t i = 0; i < length; i++) {
            BYTE b;
            CryptGenRandom(hProv, 1, &b);
            result += chars[b % (sizeof(chars)/sizeof(wchar_t) - 1)];
        }
        CryptReleaseContext(hProv, 0);
    }
    return result;
}

// Hex encode
inline std::wstring HexEncode(const std::vector<uint8_t>& data) {
    static const wchar_t hex[] = L"0123456789ABCDEF";
    std::wstring result;
    result.reserve(data.size() * 2);
    for (uint8_t b : data) {
        result += hex[(b >> 4) & 0xF];
        result += hex[b & 0xF];
    }
    return result;
}

// Hex decode
inline std::vector<uint8_t> HexDecode(const std::wstring& hexStr) {
    std::vector<uint8_t> result;
    if (hexStr.size() % 2 != 0) return result;

    result.reserve(hexStr.size() / 2);
    for (size_t i = 0; i < hexStr.size(); i += 2) {
        uint8_t b = 0;
        wchar_t c1 = hexStr[i], c2 = hexStr[i + 1];

        if (c1 >= L'0' && c1 <= L'9') b = (uint8_t)((c1 - L'0') << 4);
        else if (c1 >= L'A' && c1 <= L'F') b = (uint8_t)((c1 - L'A' + 10) << 4);
        else if (c1 >= L'a' && c1 <= L'f') b = (uint8_t)((c1 - L'a' + 10) << 4);

        if (c2 >= L'0' && c2 <= L'9') b |= (uint8_t)(c2 - L'0');
        else if (c2 >= L'A' && c2 <= L'F') b |= (uint8_t)(c2 - L'A' + 10);
        else if (c2 >= L'a' && c2 <= L'f') b |= (uint8_t)(c2 - L'a' + 10);

        result.push_back(b);
    }
    return result;
}

// Wide string to UTF8
inline std::string WideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(len - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, result.data(), len, nullptr, nullptr);
    return result;
}

// UTF8 to wide string
inline std::wstring Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    std::wstring result(len - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, result.data(), len);
    return result;
}

// Check if path is a SecureFolder package file (new format)
inline bool IsSecureFolderPackage(const std::wstring& path) {
    // Must be a file (not directory)
    DWORD attr = GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return false;
    if (attr & FILE_ATTRIBUTE_DIRECTORY) return false;

    // Check extension
    std::filesystem::path p(path);
    if (p.extension().wstring() != PACKAGE_FILE_EXTENSION) return false;

    // Verify magic number
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    char magic[4] = {0};
    DWORD bytesRead = 0;
    bool result = ReadFile(hFile, magic, 4, &bytesRead, nullptr) &&
                  bytesRead == 4 &&
                  magic[0] == 'S' && magic[1] == 'F' && magic[2] == 'P' && magic[3] == 'K';
    CloseHandle(hFile);
    return result;
}

// Get total folder size (all files combined)
inline uint64_t GetFolderSize(const std::wstring& folderPath) {
    uint64_t total = 0;
    try {
        std::filesystem::path root(folderPath);
        for (auto& entry : std::filesystem::recursive_directory_iterator(root)) {
            if (!entry.is_directory()) {
                total += entry.file_size();
            }
        }
    } catch (...) {
        // Handle permission errors
    }
    return total;
}

// Ensure parent directory exists for output path
inline bool EnsureParentDirectory(const std::wstring& filePath) {
    try {
        std::filesystem::path p(filePath);
        std::filesystem::path parent = p.parent_path();
        if (!std::filesystem::exists(parent)) {
            return std::filesystem::create_directories(parent);
        }
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace Utils
} // namespace SecureFolder