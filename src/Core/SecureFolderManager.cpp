#include "SecureFolderManager.h"
#include "Utils.h"
#include <filesystem>
#include <fstream>

namespace SecureFolder {

SecureFolderManager::SecureFolderManager() {
}

SecureFolderManager::~SecureFolderManager() {
}

Result SecureFolderManager::LockFolder(const std::wstring& folderPath,
                                        const std::wstring& password,
                                        EncryptMode mode,
                                        EncryptConfig config,
                                        IProgressCallback* callback) {
    Result result;
    m_config = config;

    // Check CryptoEngine initialization
    if (!m_cryptoEngine.IsInitialized()) {
        result.message = L"CryptoEngine not initialized: " + m_cryptoEngine.GetLastError();
        return result;
    }

    if (!Utils::FolderExists(folderPath)) {
        result.message = L"Folder does not exist: " + folderPath;
        result.errorCode = ERROR_PATH_NOT_FOUND;
        return result;
    }

    if (IsLocked(folderPath)) {
        result.message = L"Folder is already locked";
        result.errorCode = 0;
        return result;
    }

    std::vector<uint8_t> salt, key;
    if (!m_cryptoEngine.GenerateSalt(salt, SALT_SIZE)) {
        result.message = m_cryptoEngine.GetLastError();
        return result;
    }

    if (!m_cryptoEngine.DeriveKeyFromPassword(password, salt, key, config.pbkdf2Iterations)) {
        result.message = m_cryptoEngine.GetLastError();
        return result;
    }

    // New logic: Rename folder to add .securefolder suffix
    // Like .zip files, double-click will trigger our handler
    std::wstring lockedPath = folderPath + LOCKED_FOLDER_SUFFIX;

    // Check if locked path already exists
    if (Utils::FolderExists(lockedPath)) {
        m_cryptoEngine.SecureClear(key);
        result.message = L"A locked folder already exists at: " + lockedPath;
        result.errorCode = ERROR_ALREADY_EXISTS;
        return result;
    }

    // Rename folder first
    if (!MoveFileW(folderPath.c_str(), lockedPath.c_str())) {
        DWORD err = ::GetLastError();
        m_cryptoEngine.SecureClear(key);
        result.message = L"Cannot rename folder: " + std::to_wstring(err);
        result.errorCode = err;
        return result;
    }

    // Set hidden attribute on the locked folder during encryption
    SetFileAttributesW(lockedPath.c_str(), FILE_ATTRIBUTE_HIDDEN);

    std::vector<FileInfo> encryptedFiles;
    if (mode != EncryptMode::QuickLock) {
        if (callback) callback->OnProgress(0, 100, L"Encrypting files...");

        auto files = Utils::GetAllFiles(lockedPath, config.excludeExtensions);
        if (!files.empty()) {
            if (!EncryptAllFiles(lockedPath, key, encryptedFiles, callback)) {
                m_cryptoEngine.SecureClear(key);
                // Restore folder name on failure
                MoveFileW(lockedPath.c_str(), folderPath.c_str());
                SetFileAttributesW(folderPath.c_str(), FILE_ATTRIBUTE_NORMAL);
                result.message = m_lastError;
                return result;
            }

            if (!CreateIndexFile(lockedPath, encryptedFiles, key)) {
                m_cryptoEngine.SecureClear(key);
                MoveFileW(lockedPath.c_str(), folderPath.c_str());
                SetFileAttributesW(folderPath.c_str(), FILE_ATTRIBUTE_NORMAL);
                result.message = L"Failed to create index file";
                return result;
            }
        }
    }

    auto verifyHash = ComputePasswordVerifyHash(key);
    std::wstring lockFilePath = lockedPath + L"\\" + LOCK_FILE_NAME;

    HANDLE hLock = CreateFileW(lockFilePath.c_str(), GENERIC_WRITE, 0,
                               nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, nullptr);
    if (hLock != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        uint32_t magic = 0x534C434B;
        uint32_t version = 1;
        uint32_t lockMode = (uint32_t)mode;
        uint32_t saltLen = (uint32_t)salt.size();
        uint32_t hashLen = (uint32_t)verifyHash.size();

        WriteFile(hLock, &magic, sizeof(magic), &written, nullptr);
        WriteFile(hLock, &version, sizeof(version), &written, nullptr);
        WriteFile(hLock, &lockMode, sizeof(lockMode), &written, nullptr);
        WriteFile(hLock, &saltLen, sizeof(saltLen), &written, nullptr);
        WriteFile(hLock, salt.data(), saltLen, &written, nullptr);
        WriteFile(hLock, &hashLen, sizeof(hashLen), &written, nullptr);
        WriteFile(hLock, verifyHash.data(), hashLen, &written, nullptr);

        // Store original folder name (without .securefolder suffix)
        std::wstring folderName = std::filesystem::path(folderPath).filename().wstring();
        std::string nameBytes = Utils::WideToUtf8(folderName);
        uint32_t nameLen = (uint32_t)nameBytes.size();
        WriteFile(hLock, &nameLen, sizeof(nameLen), &written, nullptr);
        WriteFile(hLock, nameBytes.data(), nameLen, &written, nullptr);

        CloseHandle(hLock);
    }

    // Make folder visible (no special icon, just the suffix name)
    SetFileAttributesW(lockedPath.c_str(), FILE_ATTRIBUTE_NORMAL);

    m_cryptoEngine.SecureClear(key);
    m_cryptoEngine.SecureClear(verifyHash);

    if (callback) callback->OnProgress(100, 100, L"Encryption complete");

    result.success = true;
    result.message = L"Folder locked: " + lockedPath + L"\nDouble-click to unlock.";
    return result;
}

Result SecureFolderManager::UnlockFolder(const std::wstring& folderPath,
                                          const std::wstring& password,
                                          IProgressCallback* callback) {
    Result result;

    // Determine the actual locked folder path
    std::wstring lockedPath = folderPath;

    // Check if input already has .securefolder suffix
    bool hasSuffix = (folderPath.find(LOCKED_FOLDER_SUFFIX) != std::wstring::npos);

    if (hasSuffix) {
        // User passed .securefolder path directly
        if (!Utils::FolderExists(folderPath)) {
            result.message = L"Locked folder does not exist: " + folderPath;
            result.errorCode = ERROR_PATH_NOT_FOUND;
            return result;
        }
        lockedPath = folderPath;
    } else {
        // User passed original name, check if .securefolder version exists
        std::wstring suffixedPath = folderPath + LOCKED_FOLDER_SUFFIX;
        if (Utils::FolderExists(suffixedPath)) {
            lockedPath = suffixedPath;
        } else if (Utils::FolderExists(folderPath)) {
            // Check if original path has lock file (backward compatibility)
            std::wstring lockFile = folderPath + L"\\" + LOCK_FILE_NAME;
            if (Utils::FileExists(lockFile)) {
                lockedPath = folderPath;  // Use original path
            } else {
                result.message = L"Folder is not locked: " + folderPath;
                result.errorCode = 0;
                return result;
            }
        } else {
            result.message = L"Folder does not exist: " + folderPath;
            result.errorCode = ERROR_PATH_NOT_FOUND;
            return result;
        }
    }

    // Now check lock file in lockedPath
    std::wstring lockFilePath = lockedPath + L"\\" + LOCK_FILE_NAME;
    if (!Utils::FileExists(lockFilePath)) {
        result.message = L"Lock file not found: " + lockFilePath;
        result.errorCode = ERROR_FILE_NOT_FOUND;
        return result;
    }

    HANDLE hLock = CreateFileW(lockFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hLock == INVALID_HANDLE_VALUE) {
        result.message = L"Cannot open lock file: " + lockFilePath;
        result.errorCode = ::GetLastError();
        return result;
    }

    DWORD bytesRead = 0;
    uint32_t magic = 0, version = 0, lockMode = 0, saltLen = 0, hashLen = 0;

    ReadFile(hLock, &magic, sizeof(magic), &bytesRead, nullptr);
    ReadFile(hLock, &version, sizeof(version), &bytesRead, nullptr);
    ReadFile(hLock, &lockMode, sizeof(lockMode), &bytesRead, nullptr);
    ReadFile(hLock, &saltLen, sizeof(saltLen), &bytesRead, nullptr);

    std::vector<uint8_t> salt(saltLen);
    ReadFile(hLock, salt.data(), saltLen, &bytesRead, nullptr);

    ReadFile(hLock, &hashLen, sizeof(hashLen), &bytesRead, nullptr);
    std::vector<uint8_t> storedHash(hashLen);
    ReadFile(hLock, storedHash.data(), hashLen, &bytesRead, nullptr);

    uint32_t nameLen = 0;
    ReadFile(hLock, &nameLen, sizeof(nameLen), &bytesRead, nullptr);
    std::vector<char> nameBuf(nameLen);
    ReadFile(hLock, nameBuf.data(), nameLen, &bytesRead, nullptr);

    CloseHandle(hLock);

    if (magic != 0x534C434B) {
        result.message = L"Invalid lock file";
        return result;
    }

    EncryptMode mode = (EncryptMode)lockMode;

    std::vector<uint8_t> key;
    if (!m_cryptoEngine.DeriveKeyFromPassword(password, salt, key, m_config.pbkdf2Iterations)) {
        result.message = m_cryptoEngine.GetLastError();
        return result;
    }

    auto verifyHash = ComputePasswordVerifyHash(key);
    bool passwordValid = (verifyHash.size() == storedHash.size());
    for (size_t i = 0; i < verifyHash.size() && passwordValid; i++) {
        if (verifyHash[i] != storedHash[i]) passwordValid = false;
    }

    if (!passwordValid) {
        m_cryptoEngine.SecureClear(key);
        m_cryptoEngine.SecureClear(verifyHash);
        result.message = L"Wrong password";
        result.errorCode = ERROR_ACCESS_DENIED;
        return result;
    }

    m_cryptoEngine.SecureClear(verifyHash);

    // Decrypt files
    if (mode != EncryptMode::QuickLock) {
        if (callback) callback->OnProgress(10, 100, L"Decrypting files...");

        if (!DecryptAllFiles(lockedPath, key, callback)) {
            m_cryptoEngine.SecureClear(key);
            result.message = m_lastError;
            return result;
        }
    }

    // Delete lock and index files
    std::wstring lockFile = lockedPath + L"\\" + LOCK_FILE_NAME;
    std::wstring indexFile = GetIndexPath(lockedPath);

    if (m_config.secureDelete) {
        SecureDelete::DeleteFileSecure(lockFile);
        SecureDelete::DeleteFileSecure(indexFile);
    } else {
        DeleteFileW(lockFile.c_str());
        DeleteFileW(indexFile.c_str());
    }

    // Restore original folder name (remove .securefolder suffix)
    std::wstring originalPath = lockedPath;
    size_t suffixPos = lockedPath.find(LOCKED_FOLDER_SUFFIX);
    if (suffixPos != std::wstring::npos) {
        originalPath = lockedPath.substr(0, suffixPos);
    }

    // Rename folder back to original name
    if (!MoveFileW(lockedPath.c_str(), originalPath.c_str())) {
        DWORD err = ::GetLastError();
        m_cryptoEngine.SecureClear(key);
        result.message = L"Cannot restore folder name: " + std::to_wstring(err);
        result.errorCode = err;
        return result;
    }

    m_cryptoEngine.SecureClear(key);

    if (callback) callback->OnProgress(100, 100, L"Decryption complete");

    result.success = true;
    result.message = L"Folder unlocked successfully: " + originalPath;
    return result;
}

bool SecureFolderManager::IsLocked(const std::wstring& folderPath) {
    auto status = GetFolderStatus(folderPath);
    return status.isLocked;
}

SecureFolderManager::FolderStatus SecureFolderManager::GetFolderStatus(const std::wstring& folderPath) {
    FolderStatus status;

    // Check for CLSID disguise (backward compatibility)
    status.isDisguised = Utils::IsCLSIDFolder(folderPath);

    // Check for .securefolder suffix
    bool hasSuffix = (folderPath.find(LOCKED_FOLDER_SUFFIX) != std::wstring::npos);

    std::wstring checkPath = folderPath;
    if (!hasSuffix && !status.isDisguised) {
        // Also check if .securefolder version exists
        std::wstring lockedPath = folderPath + LOCKED_FOLDER_SUFFIX;
        if (Utils::FolderExists(lockedPath)) {
            checkPath = lockedPath;
            hasSuffix = true;
        }
    }

    // Check for lock file
    std::wstring lockFilePath = checkPath + L"\\" + LOCK_FILE_NAME;
    status.hasLockFile = Utils::FileExists(lockFilePath);

    if (status.hasLockFile || hasSuffix) {
        status.isLocked = true;

        HANDLE hLock = CreateFileW(lockFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hLock != INVALID_HANDLE_VALUE) {
            DWORD bytesRead = 0;
            uint32_t magic = 0, version = 0, lockMode = 0;

            ReadFile(hLock, &magic, sizeof(magic), &bytesRead, nullptr);
            ReadFile(hLock, &version, sizeof(version), &bytesRead, nullptr);
            ReadFile(hLock, &lockMode, sizeof(lockMode), &bytesRead, nullptr);

            if (magic == 0x534C434B) {
                status.mode = (EncryptMode)lockMode;
                status.isEncrypted = (lockMode != 0);
            }

            CloseHandle(hLock);
        }
    }

    std::wstring indexPath = GetIndexPath(checkPath);
    status.isEncrypted = Utils::FileExists(indexPath);

    status.originalPath = Utils::ExtractOriginalName(folderPath);

    return status;
}

bool SecureFolderManager::VerifyPassword(const std::wstring& folderPath, const std::wstring& password) {
    auto status = GetFolderStatus(folderPath);
    if (!status.isLocked) return false;

    std::wstring lockFilePath = folderPath + L"\\" + LOCK_FILE_NAME;

    HANDLE hLock = CreateFileW(lockFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hLock == INVALID_HANDLE_VALUE) return false;

    DWORD bytesRead = 0;
    uint32_t magic, version, lockMode, saltLen, hashLen;

    ReadFile(hLock, &magic, sizeof(magic), &bytesRead, nullptr);
    ReadFile(hLock, &version, sizeof(version), &bytesRead, nullptr);
    ReadFile(hLock, &lockMode, sizeof(lockMode), &bytesRead, nullptr);
    ReadFile(hLock, &saltLen, sizeof(saltLen), &bytesRead, nullptr);

    std::vector<uint8_t> salt(saltLen);
    ReadFile(hLock, salt.data(), saltLen, &bytesRead, nullptr);

    ReadFile(hLock, &hashLen, sizeof(hashLen), &bytesRead, nullptr);
    std::vector<uint8_t> storedHash(hashLen);
    ReadFile(hLock, storedHash.data(), hashLen, &bytesRead, nullptr);

    CloseHandle(hLock);

    if (magic != 0x534C434B) return false;

    std::vector<uint8_t> key;
    if (!m_cryptoEngine.DeriveKeyFromPassword(password, salt, key, m_config.pbkdf2Iterations)) {
        return false;
    }

    auto verifyHash = ComputePasswordVerifyHash(key);
    m_cryptoEngine.SecureClear(key);

    bool valid = (verifyHash.size() == storedHash.size());
    for (size_t i = 0; i < verifyHash.size() && valid; i++) {
        if (verifyHash[i] != storedHash[i]) valid = false;
    }

    m_cryptoEngine.SecureClear(verifyHash);
    return valid;
}

std::vector<std::wstring> SecureFolderManager::ScanLockedFolders(const std::wstring& scanPath) {
    std::vector<std::wstring> lockedFolders;
    std::filesystem::path root(scanPath);

    for (auto& entry : std::filesystem::recursive_directory_iterator(root)) {
        std::wstring path = entry.path().wstring();

        if (IsLocked(path)) {
            lockedFolders.push_back(path);
        }
    }

    return lockedFolders;
}

bool SecureFolderManager::EncryptAllFiles(const std::wstring& folderPath,
                                           const std::vector<uint8_t>& key,
                                           std::vector<FileInfo>& encryptedFiles,
                                           IProgressCallback* callback) {
    auto files = Utils::GetAllFiles(folderPath, m_config.excludeExtensions);
    int total = (int)files.size();
    int current = 0;

    for (const auto& file : files) {
        if (callback && callback->ShouldCancel()) {
            m_lastError = L"User cancelled operation";
            return false;
        }

        if (file.path.find(LOCK_FILE_NAME) != std::wstring::npos) continue;

        std::wstring outputPath = file.path + ENCRYPTED_EXTENSION;

        if (!m_cryptoEngine.EncryptFile(file.path, outputPath, key, callback)) {
            m_lastError = L"Failed to encrypt file: " + file.path + L"\n" + m_cryptoEngine.GetLastError();
            return false;
        }

        FileInfo encryptedInfo;
        encryptedInfo.path = outputPath;
        encryptedInfo.relativePath = file.relativePath;
        encryptedInfo.size = Utils::GetFileSize(outputPath);
        encryptedInfo.isDirectory = false;
        encryptedFiles.push_back(encryptedInfo);

        if (m_config.secureDelete) {
            SecureDelete::DeleteFileSecure(file.path);
        } else {
            DeleteFileW(file.path.c_str());
        }

        current++;
        if (callback) {
            callback->OnProgress(current, total, file.path);
        }
    }

    return true;
}

bool SecureFolderManager::DecryptAllFiles(const std::wstring& folderPath,
                                           const std::vector<uint8_t>& key,
                                           IProgressCallback* callback) {
    std::vector<FileInfo> files;

    // First try to read from index file
    bool indexRead = ReadIndexFile(folderPath, files, key);

    // Debug: Log the folder path we're searching
    m_lastError = L"Searching in: " + folderPath;

    if (!indexRead || files.empty()) {
        // Scan folder for .encf files using Win32 API
        files.clear();

        WIN32_FIND_DATAW findData;
        std::wstring searchPath = folderPath + L"\\*" + ENCRYPTED_EXTENSION;

        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE) {
            DWORD err = ::GetLastError();
            m_lastError = L"Cannot find encrypted files in: " + folderPath + L"\nSearch pattern: " + searchPath + L"\nError code: " + std::to_wstring(err);
            // Try alternative: direct path check for known files
            return true;  // Continue anyway, might have files
        }

        do {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                FileInfo info;
                info.path = folderPath + L"\\";
                info.path += findData.cFileName;
                info.relativePath = findData.cFileName;
                info.size = ((uint64_t)findData.nFileSizeHigh << 32) | findData.nFileSizeLow;
                info.isDirectory = false;
                files.push_back(info);
            }
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }

    if (files.empty()) {
        m_lastError = L"No encrypted files found in: " + folderPath;
        return true;  // Not an error, just no files to decrypt
    }

    int total = (int)files.size();
    int current = 0;

    for (const auto& file : files) {
        if (callback && callback->ShouldCancel()) {
            m_lastError = L"User cancelled operation";
            return false;
        }

        std::wstring outputPath = file.path;
        size_t pos = outputPath.find(ENCRYPTED_EXTENSION);
        if (pos != std::wstring::npos) {
            outputPath = outputPath.substr(0, pos);
        }

        // Check file exists with detailed error
        DWORD attr = GetFileAttributesW(file.path.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) {
            DWORD err = ::GetLastError();
            m_lastError = L"File not found: " + file.path + L"\nError: " + std::to_wstring(err);
            return false;
        }

        if (!m_cryptoEngine.DecryptFile(file.path, outputPath, key)) {
            m_lastError = L"Failed to decrypt: " + file.path + L"\n" + m_cryptoEngine.GetLastError();
            return false;
        }

        if (m_config.secureDelete) {
            SecureDelete::DeleteFileSecure(file.path);
        } else {
            DeleteFileW(file.path.c_str());
        }

        current++;
        if (callback) {
            callback->OnProgress(current, total, outputPath);
        }
    }

    return true;
}

std::wstring SecureFolderManager::GetIndexPath(const std::wstring& folderPath) {
    return folderPath + L"\\" + LOCK_FILE_NAME + L".idx";
}

bool SecureFolderManager::CreateIndexFile(const std::wstring& folderPath,
                                           const std::vector<FileInfo>& files,
                                           const std::vector<uint8_t>& key) {
    std::wstring indexPath = GetIndexPath(folderPath);

    std::string indexData;
    for (const auto& file : files) {
        std::string relPath = Utils::WideToUtf8(file.relativePath);
        indexData += relPath + "|" + std::to_string(file.size) + "\n";
    }

    std::vector<uint8_t> iv, tag, cipher;
    m_cryptoEngine.GenerateIV(iv);
    std::vector<uint8_t> plainData(indexData.begin(), indexData.end());

    if (!m_cryptoEngine.Encrypt(plainData, key, iv, cipher, tag)) {
        return false;
    }

    HANDLE hFile = CreateFileW(indexPath.c_str(), GENERIC_WRITE, 0,
                               nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_HIDDEN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD written = 0;
    uint32_t magic = 0x494E4458;
    uint32_t version = 1;
    uint32_t ivLen = (uint32_t)iv.size();
    uint32_t cipherLen = (uint32_t)cipher.size();
    uint32_t tagLen = (uint32_t)tag.size();

    WriteFile(hFile, &magic, sizeof(magic), &written, nullptr);
    WriteFile(hFile, &version, sizeof(version), &written, nullptr);
    WriteFile(hFile, &ivLen, sizeof(ivLen), &written, nullptr);
    WriteFile(hFile, iv.data(), ivLen, &written, nullptr);
    WriteFile(hFile, &cipherLen, sizeof(cipherLen), &written, nullptr);
    WriteFile(hFile, cipher.data(), cipherLen, &written, nullptr);
    WriteFile(hFile, &tagLen, sizeof(tagLen), &written, nullptr);
    WriteFile(hFile, tag.data(), tagLen, &written, nullptr);

    CloseHandle(hFile);

    m_cryptoEngine.SecureClear(iv);
    m_cryptoEngine.SecureClear(cipher);
    m_cryptoEngine.SecureClear(tag);
    m_cryptoEngine.SecureClear(plainData);

    return true;
}

bool SecureFolderManager::ReadIndexFile(const std::wstring& folderPath,
                                         std::vector<FileInfo>& files,
                                         const std::vector<uint8_t>& key) {
    std::wstring indexPath = GetIndexPath(folderPath);

    if (!Utils::FileExists(indexPath)) return false;

    HANDLE hFile = CreateFileW(indexPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD bytesRead = 0;
    uint32_t magic = 0, version = 0, ivLen = 0, cipherLen = 0, tagLen = 0;

    ReadFile(hFile, &magic, sizeof(magic), &bytesRead, nullptr);
    ReadFile(hFile, &version, sizeof(version), &bytesRead, nullptr);

    if (magic != 0x494E4458) {
        CloseHandle(hFile);
        return false;
    }

    ReadFile(hFile, &ivLen, sizeof(ivLen), &bytesRead, nullptr);
    std::vector<uint8_t> iv(ivLen);
    ReadFile(hFile, iv.data(), ivLen, &bytesRead, nullptr);

    ReadFile(hFile, &cipherLen, sizeof(cipherLen), &bytesRead, nullptr);
    std::vector<uint8_t> cipher(cipherLen);
    ReadFile(hFile, cipher.data(), cipherLen, &bytesRead, nullptr);

    ReadFile(hFile, &tagLen, sizeof(tagLen), &bytesRead, nullptr);
    std::vector<uint8_t> tag(tagLen);
    ReadFile(hFile, tag.data(), tagLen, &bytesRead, nullptr);

    CloseHandle(hFile);

    std::vector<uint8_t> plainData;
    if (!m_cryptoEngine.Decrypt(cipher, key, iv, tag, plainData)) {
        return false;
    }

    std::string indexStr(plainData.begin(), plainData.end());
    size_t pos = 0, end = 0;

    while ((end = indexStr.find('\n', pos)) != std::string::npos) {
        std::string line = indexStr.substr(pos, end - pos);
        pos = end + 1;

        size_t sep = line.find('|');
        if (sep != std::string::npos) {
            FileInfo info;
            info.relativePath = Utils::Utf8ToWide(line.substr(0, sep));
            info.size = std::stoull(line.substr(sep + 1));
            info.isDirectory = false;
            // Build full path: folderPath + relativePath + .encf extension
            info.path = folderPath + L"\\";
            info.path += info.relativePath;
            info.path += ENCRYPTED_EXTENSION;  // Add encrypted file extension
            files.push_back(info);
        }
    }

    m_cryptoEngine.SecureClear(iv);
    m_cryptoEngine.SecureClear(cipher);
    m_cryptoEngine.SecureClear(tag);
    m_cryptoEngine.SecureClear(plainData);

    return true;
}

std::vector<uint8_t> SecureFolderManager::ComputePasswordVerifyHash(const std::vector<uint8_t>& key) {
    std::vector<uint8_t> verifyHash(32);

    BCRYPT_ALG_HANDLE hShaAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hShaAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);

    if (status == 0) {
        BCRYPT_HASH_HANDLE hHash = nullptr;
        status = BCryptCreateHash(hShaAlg, &hHash, nullptr, 0, nullptr, 0, 0);

        if (status == 0) {
            // Make a copy since BCryptHashData requires non-const pointer
            std::vector<uint8_t> keyCopy = key;
            BCryptHashData(hHash, keyCopy.data(), (ULONG)keyCopy.size(), 0);
            BCryptFinishHash(hHash, verifyHash.data(), 32, 0);
            BCryptDestroyHash(hHash);
            m_cryptoEngine.SecureClear(keyCopy);
        }

        BCryptCloseAlgorithmProvider(hShaAlg, 0);
    }

    return verifyHash;
}

} // namespace SecureFolder