#include "SecureDelete.h"
#include "Common/Utils.h"
#include <filesystem>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

namespace SecureFolder {

std::wstring SecureDelete::s_lastError;

bool SecureDelete::OverwriteFileContent(HANDLE hFile, uint64_t fileSize, int passes) {
    const size_t bufferSize = 1024 * 1024;
    std::vector<uint8_t> buffer(bufferSize);

    for (int pass = 0; pass < passes; pass++) {
        NTSTATUS status = BCryptGenRandom(nullptr, buffer.data(), (ULONG)bufferSize, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status != 0) {
            s_lastError = L"Failed to generate random data";
            return false;
        }

        LARGE_INTEGER zero = {0};
        SetFilePointerEx(hFile, zero, nullptr, FILE_BEGIN);

        uint64_t written = 0;
        while (written < fileSize) {
            DWORD toWrite = (DWORD)min(bufferSize, fileSize - written);
            DWORD bytesWritten = 0;

            if (!WriteFile(hFile, buffer.data(), toWrite, &bytesWritten, nullptr)) {
                s_lastError = L"Failed to write file";
                return false;
            }

            written += bytesWritten;
        }

        FlushFileBuffers(hFile);
    }

    return true;
}

bool SecureDelete::OverwriteFile(const std::wstring& filePath, int passes) {
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        s_lastError = L"Cannot open file: " + filePath;
        return false;
    }

    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);

    bool result = OverwriteFileContent(hFile, fileSize.QuadPart, passes);
    CloseHandle(hFile);

    return result;
}

bool SecureDelete::DeleteFileSecure(const std::wstring& filePath, int overwritePasses) {
    if (!Utils::FileExists(filePath)) {
        s_lastError = L"File not found: " + filePath;
        return false;
    }

    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        if (overwritePasses > 0) {
            s_lastError = L"Cannot open file for secure wipe, will try direct delete";
        }
        return DeleteFileW(filePath.c_str()) != 0;
    }

    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);

    if (overwritePasses > 0 && fileSize.QuadPart > 0) {
        OverwriteFileContent(hFile, fileSize.QuadPart, overwritePasses);
    }

    CloseHandle(hFile);

    std::wstring tempName = filePath + L"." + Utils::GenerateRandomString(8);
    MoveFileW(filePath.c_str(), tempName.c_str());

    bool deleted = DeleteFileW(tempName.c_str()) != 0;
    if (!deleted) {
        deleted = DeleteFileW(filePath.c_str()) != 0;
    }

    if (!deleted) {
        s_lastError = L"Failed to delete file: " + filePath;
    }

    return deleted;
}

bool SecureDelete::DeleteFolderSecure(const std::wstring& folderPath, int overwritePasses) {
    if (!Utils::FolderExists(folderPath)) {
        s_lastError = L"Folder not found: " + folderPath;
        return false;
    }

    std::filesystem::path root(folderPath);
    bool allSuccess = true;

    for (auto& entry : std::filesystem::recursive_directory_iterator(root)) {
        if (!entry.is_directory()) {
            std::wstring filePath = entry.path().wstring();

            if (entry.path().filename() == LOCK_FILE_NAME) continue;

            if (!DeleteFileSecure(filePath, overwritePasses)) {
                allSuccess = false;
            }
        }
    }

    for (auto it = std::filesystem::recursive_directory_iterator(root);
         it != std::filesystem::recursive_directory_iterator();) {
        if (it->is_directory()) {
            std::wstring dirPath = it->path().wstring();
            RemoveDirectoryW(dirPath.c_str());
        }
        ++it;
    }

    RemoveDirectoryW(folderPath.c_str());

    return allSuccess;
}

} // namespace SecureFolder