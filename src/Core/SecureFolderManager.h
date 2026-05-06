#pragma once

#include <string>
#include <vector>
#include <functional>
#include <Windows.h>
#include <bcrypt.h>
#include "Types.h"
#include "CryptoEngine.h"
#include "FolderDisguise.h"
#include "SecureDelete.h"

namespace SecureFolder {

// Main controller - Combined encryption manager
class SecureFolderManager {
public:
    SecureFolderManager();
    ~SecureFolderManager();

    // Lock folder (combined mode)
    Result LockFolder(const std::wstring& folderPath,
                      const std::wstring& password,
                      EncryptMode mode = EncryptMode::FullEncrypt,
                      EncryptConfig config = {},
                      IProgressCallback* callback = nullptr);

    // Unlock folder
    Result UnlockFolder(const std::wstring& folderPath,
                        const std::wstring& password,
                        IProgressCallback* callback = nullptr);

    // Check if folder is locked
    bool IsLocked(const std::wstring& folderPath);

    // Get folder status info
    struct FolderStatus {
        bool isLocked = false;
        bool isDisguised = false;
        bool isEncrypted = false;
        bool hasLockFile = false;
        std::wstring originalPath;
        EncryptMode mode = EncryptMode::FullEncrypt;
    };
    FolderStatus GetFolderStatus(const std::wstring& folderPath);

    // Verify password (without unlocking)
    bool VerifyPassword(const std::wstring& folderPath, const std::wstring& password);

    // Get list of locked folders (scan)
    std::vector<std::wstring> ScanLockedFolders(const std::wstring& scanPath);

    // Set config
    void SetConfig(const EncryptConfig& config) { m_config = config; }
    EncryptConfig GetConfig() const { return m_config; }

    // Get last error
    std::wstring GetLastError() const { return m_lastError; }

private:
    CryptoEngine m_cryptoEngine;
    FolderDisguise m_disguise;
    EncryptConfig m_config;
    std::wstring m_lastError;

    // Package file helpers (new format)
    bool CreatePackageFile(const std::wstring& folderPath,
                           const std::wstring& outputPath,
                           const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& salt,
                           IProgressCallback* callback);

    bool ExtractPackageFile(const std::wstring& packagePath,
                            const std::wstring& outputFolder,
                            const std::vector<uint8_t>& key,
                            IProgressCallback* callback);

    bool ReadPackageHeader(HANDLE hFile,
                           SecurePackageHeader& header,
                           std::vector<uint8_t>& salt,
                           std::vector<uint8_t>& verifyHash,
                           std::wstring& originalFolderName,
                           std::vector<uint8_t>& indexIV,
                           std::vector<uint8_t>& indexCipher,
                           std::vector<uint8_t>& indexTag);

    bool BuildEncryptedIndex(const std::vector<FileInfo>& files,
                             const std::vector<uint8_t>& key,
                             std::vector<uint8_t>& iv,
                             std::vector<uint8_t>& cipher,
                             std::vector<uint8_t>& tag);

    bool ParseEncryptedIndex(const std::vector<uint8_t>& cipher,
                             const std::vector<uint8_t>& key,
                             const std::vector<uint8_t>& iv,
                             const std::vector<uint8_t>& tag,
                             std::vector<FileInfo>& files);

    // Legacy helpers (deprecated, for backward compatibility)
    bool EncryptAllFiles(const std::wstring& folderPath,
                         const std::vector<uint8_t>& key,
                         std::vector<FileInfo>& encryptedFiles,
                         IProgressCallback* callback);

    bool DecryptAllFiles(const std::wstring& folderPath,
                         const std::vector<uint8_t>& key,
                         IProgressCallback* callback);

    bool CreateIndexFile(const std::wstring& folderPath,
                         const std::vector<FileInfo>& files,
                         const std::vector<uint8_t>& key);

    bool ReadIndexFile(const std::wstring& folderPath,
                       std::vector<FileInfo>& files,
                       const std::vector<uint8_t>& key);

    std::wstring GetIndexPath(const std::wstring& folderPath);

    // Compute password verify hash (for lock file)
    std::vector<uint8_t> ComputePasswordVerifyHash(const std::vector<uint8_t>& key);

    // Check if path is a package file (new format)
    bool IsPackageFile(const std::wstring& path);

    // Check if path is legacy locked folder (old format)
    bool IsLegacyLockedFolder(const std::wstring& path);

    // Legacy unlock method (backward compatibility)
    Result UnlockFolderLegacy(const std::wstring& folderPath,
                              const std::wstring& password,
                              IProgressCallback* callback);
};

} // namespace SecureFolder