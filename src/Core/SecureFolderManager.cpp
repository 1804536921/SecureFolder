#include "SecureFolderManager.h"
#include "Utils.h"
#include <filesystem>
#include <fstream>
#include <algorithm>

namespace SecureFolder {

SecureFolderManager::SecureFolderManager() {
}

SecureFolderManager::~SecureFolderManager() {
}

// Check if path is a package file (new format)
bool SecureFolderManager::IsPackageFile(const std::wstring& path) {
    // Check if it's a file (not directory) with .securefolder extension
    DWORD attr = GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return false;
    if (attr & FILE_ATTRIBUTE_DIRECTORY) return false;  // Must be a file

    // Check extension
    std::filesystem::path p(path);
    std::wstring ext = p.extension().wstring();
    if (ext != PACKAGE_FILE_EXTENSION) return false;

    // Verify magic number in header
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    char magic[4] = {0};
    DWORD bytesRead = 0;
    ReadFile(hFile, magic, 4, &bytesRead, nullptr);
    CloseHandle(hFile);

    return (bytesRead == 4 && magic[0] == 'S' && magic[1] == 'F' && magic[2] == 'P' && magic[3] == 'K');
}

// Check if path is legacy locked folder (old format with .securefolder suffix)
bool SecureFolderManager::IsLegacyLockedFolder(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return false;
    if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) return false;  // Must be a directory

    // Check for lock file inside
    std::wstring lockFile = path + L"\\";
    lockFile += LOCK_FILE_NAME;
    return Utils::FileExists(lockFile);
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

    // Generate salt and derive key
    std::vector<uint8_t> salt, key;
    if (!m_cryptoEngine.GenerateSalt(salt, SALT_SIZE)) {
        result.message = m_cryptoEngine.GetLastError();
        return result;
    }

    if (!m_cryptoEngine.DeriveKeyFromPassword(password, salt, key, config.pbkdf2Iterations)) {
        result.message = m_cryptoEngine.GetLastError();
        return result;
    }

    // Create package file path: folderPath + .securefolder extension
    std::wstring packagePath = folderPath + PACKAGE_FILE_EXTENSION;

    // Check if package file already exists
    if (Utils::FileExists(packagePath)) {
        m_cryptoEngine.SecureClear(key);
        result.message = L"Package file already exists: " + packagePath;
        result.errorCode = ERROR_ALREADY_EXISTS;
        return result;
    }

    // Create the package file
    if (!CreatePackageFile(folderPath, packagePath, key, salt, callback)) {
        m_cryptoEngine.SecureClear(key);
        // Clean up partial package file
        DeleteFileW(packagePath.c_str());
        result.message = m_lastError;
        return result;
    }

    m_cryptoEngine.SecureClear(key);

    // Delete original folder (secure delete if configured)
    bool deleteSuccess = true;
    std::wstring deleteError;
    std::filesystem::path root(folderPath);

    if (config.secureDelete) {
        // Recursively secure delete folder contents
        std::vector<std::filesystem::path> filesToDelete;

        // Collect all files first (to avoid iterator issues during deletion)
        try {
            for (auto& entry : std::filesystem::recursive_directory_iterator(root)) {
                if (!entry.is_directory()) {
                    filesToDelete.push_back(entry.path());
                }
            }
        } catch (const std::filesystem::filesystem_error& e) {
            deleteError = Utils::Utf8ToWide(e.what());
            deleteSuccess = false;
        }

        // Delete each file
        for (const auto& filePath : filesToDelete) {
            if (!SecureDelete::DeleteFileSecure(filePath.wstring())) {
                deleteSuccess = false;
                deleteError = SecureDelete::GetLastError();
                // Continue trying other files
            }
        }
    }

    // Remove folder structure
    if (deleteSuccess) {
        try {
            // Remove empty directories first (reverse order)
            std::vector<std::filesystem::path> dirsToRemove;
            for (auto& entry : std::filesystem::recursive_directory_iterator(root)) {
                if (entry.is_directory()) {
                    dirsToRemove.push_back(entry.path());
                }
            }
            // Sort in reverse order (deepest first)
            std::sort(dirsToRemove.begin(), dirsToRemove.end(), [](const auto& a, const auto& b) {
                return a.native().size() > b.native().size();
            });
            for (const auto& dir : dirsToRemove) {
                std::filesystem::remove(dir);
            }
            // Finally remove the root folder
            std::filesystem::remove(folderPath);
        } catch (const std::filesystem::filesystem_error& e) {
            deleteError = Utils::Utf8ToWide(e.what());
            // Try force delete
            if (!DeleteFileW(folderPath.c_str()) && !RemoveDirectoryW(folderPath.c_str())) {
                deleteSuccess = false;
            }
        }
    }

    if (!deleteSuccess && !deleteError.empty()) {
        result.success = true;  // Encryption succeeded
        result.message = L"Folder locked: " + packagePath +
                         L"\nWarning: Some files could not be deleted:\n" + deleteError;
    } else {
        result.success = true;
        result.message = L"Folder locked: " + packagePath + L"\nDouble-click to unlock.";
    }

    if (callback) callback->OnProgress(100, 100, L"Encryption complete");
    return result;
}

Result SecureFolderManager::UnlockFolder(const std::wstring& packagePath,
                                          const std::wstring& password,
                                          IProgressCallback* callback) {
    Result result;

    // Determine the actual package file path
    std::wstring actualPath = packagePath;
    bool isPackage = false;

    // Check if input is a package file
    if (IsPackageFile(packagePath)) {
        isPackage = true;
        actualPath = packagePath;
    } else if (Utils::FileExists(packagePath + PACKAGE_FILE_EXTENSION)) {
        // Try adding extension
        isPackage = true;
        actualPath = packagePath + PACKAGE_FILE_EXTENSION;
    } else if (IsLegacyLockedFolder(packagePath)) {
        // Legacy format: folder with .securefolder suffix and lock file inside
        // Fall back to legacy unlock logic
        isPackage = false;
        actualPath = packagePath;
    } else {
        result.message = L"Package file not found: " + packagePath;
        result.errorCode = ERROR_FILE_NOT_FOUND;
        return result;
    }

    if (isPackage) {
        // New format: extract from package file
        HANDLE hFile = CreateFileW(actualPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            result.message = L"Cannot open package file: " + actualPath;
            result.errorCode = ::GetLastError();
            return result;
        }

        // Read header
        SecurePackageHeader header;
        std::vector<uint8_t> salt, verifyHash, indexIV, indexCipher, indexTag;
        std::wstring originalFolderName;

        if (!ReadPackageHeader(hFile, header, salt, verifyHash, originalFolderName, indexIV, indexCipher, indexTag)) {
            CloseHandle(hFile);
            result.message = L"Invalid package file header";
            result.errorCode = 0;
            return result;
        }

        // Derive key from password
        std::vector<uint8_t> key;
        if (!m_cryptoEngine.DeriveKeyFromPassword(password, salt, key, m_config.pbkdf2Iterations)) {
            CloseHandle(hFile);
            result.message = m_cryptoEngine.GetLastError();
            return result;
        }

        // Verify password
        auto computedHash = ComputePasswordVerifyHash(key);
        bool passwordValid = (computedHash.size() == verifyHash.size());
        for (size_t i = 0; i < computedHash.size() && passwordValid; i++) {
            if (computedHash[i] != verifyHash[i]) passwordValid = false;
        }

        if (!passwordValid) {
            CloseHandle(hFile);
            m_cryptoEngine.SecureClear(key);
            m_cryptoEngine.SecureClear(computedHash);
            result.message = L"Wrong password";
            result.errorCode = ERROR_ACCESS_DENIED;
            return result;
        }

        m_cryptoEngine.SecureClear(computedHash);
        CloseHandle(hFile);

        // Determine output folder path
        std::filesystem::path pkgPath(actualPath);
        std::wstring outputFolder = pkgPath.parent_path().wstring() + L"\\";
        if (!originalFolderName.empty()) {
            outputFolder += originalFolderName;
        } else {
            // Remove .securefolder extension from package filename
            std::wstring fileName = pkgPath.stem().wstring();
            outputFolder += fileName;
        }

        // Check if output folder already exists
        if (Utils::FolderExists(outputFolder)) {
            m_cryptoEngine.SecureClear(key);
            result.message = L"Output folder already exists: " + outputFolder;
            result.errorCode = ERROR_ALREADY_EXISTS;
            return result;
        }

        // Extract package
        if (!ExtractPackageFile(actualPath, outputFolder, key, callback)) {
            m_cryptoEngine.SecureClear(key);
            result.message = m_lastError;
            return result;
        }

        m_cryptoEngine.SecureClear(key);

        // Delete package file after successful extraction
        DeleteFileW(actualPath.c_str());

        if (callback) callback->OnProgress(100, 100, L"Decryption complete");

        result.success = true;
        result.message = L"Folder unlocked: " + outputFolder;
        return result;
    } else {
        // Legacy format unlock (backward compatibility)
        return UnlockFolderLegacy(actualPath, password, callback);
    }
}

// Legacy unlock for old format folders
Result SecureFolderManager::UnlockFolderLegacy(const std::wstring& folderPath,
                                                 const std::wstring& password,
                                                 IProgressCallback* callback) {
    Result result;

    std::wstring lockFilePath = folderPath + L"\\";
    lockFilePath += LOCK_FILE_NAME;
    if (!Utils::FileExists(lockFilePath)) {
        result.message = L"Lock file not found: " + lockFilePath;
        result.errorCode = ERROR_FILE_NOT_FOUND;
        return result;
    }

    HANDLE hLock = CreateFileW(lockFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hLock == INVALID_HANDLE_VALUE) {
        result.message = L"Cannot open lock file";
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

    if (mode != EncryptMode::QuickLock) {
        if (callback) callback->OnProgress(10, 100, L"Decrypting files...");

        if (!DecryptAllFiles(folderPath, key, callback)) {
            m_cryptoEngine.SecureClear(key);
            result.message = m_lastError;
            return result;
        }
    }

    // Delete lock and index files
    std::wstring lockFile = folderPath + L"\\";
    lockFile += LOCK_FILE_NAME;
    std::wstring indexFile = GetIndexPath(folderPath);

    if (m_config.secureDelete) {
        SecureDelete::DeleteFileSecure(lockFile);
        SecureDelete::DeleteFileSecure(indexFile);
    } else {
        DeleteFileW(lockFile.c_str());
        DeleteFileW(indexFile.c_str());
    }

    // Restore original folder name
    std::wstring originalPath = folderPath;
    size_t suffixPos = folderPath.find(LOCKED_FOLDER_SUFFIX);
    if (suffixPos != std::wstring::npos) {
        originalPath = folderPath.substr(0, suffixPos);
    }

    if (!MoveFileW(folderPath.c_str(), originalPath.c_str())) {
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

bool SecureFolderManager::IsLocked(const std::wstring& path) {
    // Check for new package file format
    if (IsPackageFile(path)) return true;

    // Check if .securefolder package file exists for this folder name
    std::wstring packagePath = path + PACKAGE_FILE_EXTENSION;
    if (IsPackageFile(packagePath)) return true;

    // Check for legacy locked folder
    if (IsLegacyLockedFolder(path)) return true;

    // Check if path has .securefolder suffix and is a legacy folder
    if (path.find(LOCKED_FOLDER_SUFFIX) != std::wstring::npos) {
        if (IsLegacyLockedFolder(path)) return true;
    }

    return false;
}

SecureFolderManager::FolderStatus SecureFolderManager::GetFolderStatus(const std::wstring& path) {
    FolderStatus status;

    // Check for new package file
    if (IsPackageFile(path)) {
        status.isLocked = true;
        status.isEncrypted = true;

        // Read header for more info
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            SecurePackageHeader header;
            std::vector<uint8_t> salt, verifyHash, indexIV, indexCipher, indexTag;
            std::wstring originalName;
            if (ReadPackageHeader(hFile, header, salt, verifyHash, originalName, indexIV, indexCipher, indexTag)) {
                status.originalPath = originalName;
            }
            CloseHandle(hFile);
        }
        return status;
    }

    // Check for package file with same base name
    std::wstring packagePath = path + PACKAGE_FILE_EXTENSION;
    if (IsPackageFile(packagePath)) {
        status.isLocked = true;
        status.isEncrypted = true;
        return status;
    }

    // Check for legacy format
    status.isDisguised = Utils::IsCLSIDFolder(path);

    bool hasSuffix = (path.find(LOCKED_FOLDER_SUFFIX) != std::wstring::npos);
    std::wstring checkPath = path;

    if (!hasSuffix && !status.isDisguised) {
        std::wstring lockedPath = path + LOCKED_FOLDER_SUFFIX;
        if (Utils::FolderExists(lockedPath)) {
            checkPath = lockedPath;
            hasSuffix = true;
        }
    }

    std::wstring lockFilePath = checkPath + L"\\";
    lockFilePath += LOCK_FILE_NAME;
    status.hasLockFile = Utils::FileExists(lockFilePath);

    if (status.hasLockFile || hasSuffix || status.isDisguised) {
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

    status.originalPath = Utils::ExtractOriginalName(path);

    return status;
}

bool SecureFolderManager::VerifyPassword(const std::wstring& path, const std::wstring& password) {
    auto status = GetFolderStatus(path);
    if (!status.isLocked) return false;

    std::wstring actualPath = path;

    // Handle package file
    if (IsPackageFile(path)) {
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        SecurePackageHeader header;
        std::vector<uint8_t> salt, verifyHash, indexIV, indexCipher, indexTag;
        std::wstring originalName;
        if (!ReadPackageHeader(hFile, header, salt, verifyHash, originalName, indexIV, indexCipher, indexTag)) {
            CloseHandle(hFile);
            return false;
        }
        CloseHandle(hFile);

        std::vector<uint8_t> key;
        if (!m_cryptoEngine.DeriveKeyFromPassword(password, salt, key, m_config.pbkdf2Iterations)) {
            return false;
        }

        auto computedHash = ComputePasswordVerifyHash(key);
        m_cryptoEngine.SecureClear(key);

        bool valid = (computedHash.size() == verifyHash.size());
        for (size_t i = 0; i < computedHash.size() && valid; i++) {
            if (computedHash[i] != verifyHash[i]) valid = false;
        }

        m_cryptoEngine.SecureClear(computedHash);
        return valid;
    }

    // Legacy format
    std::wstring lockFilePath = actualPath + L"\\";
    lockFilePath += LOCK_FILE_NAME;

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
    std::vector<std::wstring> lockedItems;
    std::filesystem::path root(scanPath);

    try {
        for (auto& entry : std::filesystem::recursive_directory_iterator(root)) {
            std::wstring path = entry.path().wstring();
            if (IsLocked(path)) {
                lockedItems.push_back(path);
            }
        }
    } catch (...) {
        // Handle permission errors
    }

    return lockedItems;
}

// ==================== Package File Methods ====================

bool SecureFolderManager::CreatePackageFile(const std::wstring& folderPath,
                                             const std::wstring& outputPath,
                                             const std::vector<uint8_t>& key,
                                             const std::vector<uint8_t>& salt,
                                             IProgressCallback* callback) {
    // Get all files in folder
    auto files = Utils::GetAllFiles(folderPath, m_config.excludeExtensions);
    if (files.empty()) {
        m_lastError = L"Folder is empty or contains no files";
        return false;
    }

    // Get original folder name
    std::filesystem::path fp(folderPath);
    std::wstring folderName = fp.filename().wstring();
    std::string folderNameUtf8 = Utils::WideToUtf8(folderName);

    // Build encrypted index
    std::vector<uint8_t> indexIV, indexCipher, indexTag;
    if (!BuildEncryptedIndex(files, key, indexIV, indexCipher, indexTag)) {
        m_lastError = L"Failed to build encrypted index";
        return false;
    }

    // Compute password verify hash
    auto verifyHash = ComputePasswordVerifyHash(key);

    // Create package file
    HANDLE hOutput = CreateFileW(outputPath.c_str(), GENERIC_WRITE, 0,
                                 nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hOutput == INVALID_HANDLE_VALUE) {
        m_cryptoEngine.SecureClear(indexIV);
        m_cryptoEngine.SecureClear(indexCipher);
        m_cryptoEngine.SecureClear(indexTag);
        m_cryptoEngine.SecureClear(verifyHash);
        m_lastError = L"Cannot create package file: " + outputPath;
        return false;
    }

    // Write header
    SecurePackageHeader header;
    header.originalFolderNameLen = (uint32_t)folderNameUtf8.size();
    header.originalFileCount = (uint32_t)files.size();
    header.indexCipherLen = (uint32_t)indexCipher.size();

    DWORD written = 0;

    // Write magic and version
    WriteFile(hOutput, header.magic, 4, &written, nullptr);
    WriteFile(hOutput, &header.version, sizeof(header.version), &written, nullptr);
    WriteFile(hOutput, &header.flags, sizeof(header.flags), &written, nullptr);

    // Write folder name length and name
    WriteFile(hOutput, &header.originalFolderNameLen, sizeof(header.originalFolderNameLen), &written, nullptr);
    WriteFile(hOutput, folderNameUtf8.data(), header.originalFolderNameLen, &written, nullptr);

    // Write file count
    WriteFile(hOutput, &header.originalFileCount, sizeof(header.originalFileCount), &written, nullptr);

    // Write salt
    WriteFile(hOutput, &header.saltLen, sizeof(header.saltLen), &written, nullptr);
    WriteFile(hOutput, salt.data(), header.saltLen, &written, nullptr);

    // Write verify hash
    WriteFile(hOutput, &header.verifyHashLen, sizeof(header.verifyHashLen), &written, nullptr);
    WriteFile(hOutput, verifyHash.data(), header.verifyHashLen, &written, nullptr);

    // Write index IV, cipher, tag
    WriteFile(hOutput, &header.indexIVLen, sizeof(header.indexIVLen), &written, nullptr);
    WriteFile(hOutput, indexIV.data(), header.indexIVLen, &written, nullptr);
    WriteFile(hOutput, &header.indexCipherLen, sizeof(header.indexCipherLen), &written, nullptr);
    WriteFile(hOutput, indexCipher.data(), header.indexCipherLen, &written, nullptr);
    WriteFile(hOutput, &header.indexTagLen, sizeof(header.indexTagLen), &written, nullptr);
    WriteFile(hOutput, indexTag.data(), header.indexTagLen, &written, nullptr);

    m_cryptoEngine.SecureClear(indexIV);
    m_cryptoEngine.SecureClear(indexCipher);
    m_cryptoEngine.SecureClear(indexTag);
    m_cryptoEngine.SecureClear(verifyHash);

    // Calculate total size for progress
    uint64_t totalSize = 0;
    for (const auto& file : files) {
        totalSize += file.size;
    }

    uint64_t processedSize = 0;
    int currentFileIndex = 0;

    // Write each file with streaming encryption
    for (const auto& file : files) {
        if (callback && callback->ShouldCancel()) {
            CloseHandle(hOutput);
            m_lastError = L"User cancelled";
            return false;
        }

        // Open input file with relaxed sharing mode (allow other processes to read/write)
        HANDLE hInput = CreateFileW(file.path.c_str(), GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hInput == INVALID_HANDLE_VALUE) {
            DWORD err = ::GetLastError();
            CloseHandle(hOutput);

            // Provide more helpful error message
            if (err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION) {
                m_lastError = L"File is in use by another program: " + file.path +
                              L"\n\nPlease close the program using this file and try again.";
            } else if (err == ERROR_ACCESS_DENIED) {
                m_lastError = L"Access denied to file: " + file.path +
                              L"\n\nThe file may be protected or in use.";
            } else {
                m_lastError = L"Cannot open file: " + file.path +
                              L"\nError code: " + std::to_wstring(err);
            }
            return false;
        }

        // Get file size
        LARGE_INTEGER fileSize;
        GetFileSizeEx(hInput, &fileSize);
        uint64_t fileSize64 = fileSize.QuadPart;

        // Write file entry header
        std::string relPathUtf8 = Utils::WideToUtf8(file.relativePath);
        uint32_t pathLen = (uint32_t)relPathUtf8.size();

        WriteFile(hOutput, &pathLen, sizeof(pathLen), &written, nullptr);
        WriteFile(hOutput, relPathUtf8.data(), pathLen, &written, nullptr);
        WriteFile(hOutput, &fileSize64, sizeof(fileSize64), &written, nullptr);

        // Generate file IV for chunk authentication
        std::vector<uint8_t> fileIV;
        m_cryptoEngine.GenerateIV(fileIV);

        // Encrypt file in chunks
        std::vector<uint8_t> buffer(CHUNK_SIZE);
        std::vector<uint8_t> cipherBuffer;
        std::vector<uint8_t> chunkIV;
        std::vector<uint8_t> authTag;

        uint64_t remaining = fileSize64;
        uint32_t chunkCount = 0;

        while (remaining > 0) {
            uint32_t readSize = (uint32_t)min((uint64_t)CHUNK_SIZE, remaining);
            DWORD bytesRead = 0;

            if (!ReadFile(hInput, buffer.data(), readSize, &bytesRead, nullptr) || bytesRead != readSize) {
                CloseHandle(hInput);
                CloseHandle(hOutput);
                m_lastError = L"Read error on file: " + file.path;
                return false;
            }

            // Resize buffer to actual read size
            buffer.resize(bytesRead);

            // Generate chunk IV
            m_cryptoEngine.GenerateIV(chunkIV);

            // Encrypt chunk
            if (!m_cryptoEngine.Encrypt(buffer, key, chunkIV, cipherBuffer, authTag)) {
                CloseHandle(hInput);
                CloseHandle(hOutput);
                m_lastError = L"Encryption error: " + m_cryptoEngine.GetLastError();
                return false;
            }

            // Write chunk: IV + cipherLen + cipherData + tag
            uint32_t cipherLen = (uint32_t)cipherBuffer.size();
            WriteFile(hOutput, chunkIV.data(), AES_IV_SIZE, &written, nullptr);
            WriteFile(hOutput, &cipherLen, sizeof(cipherLen), &written, nullptr);
            WriteFile(hOutput, cipherBuffer.data(), cipherLen, &written, nullptr);
            WriteFile(hOutput, authTag.data(), AES_TAG_SIZE, &written, nullptr);

            m_cryptoEngine.SecureClear(buffer);
            m_cryptoEngine.SecureClear(chunkIV);
            m_cryptoEngine.SecureClear(cipherBuffer);
            m_cryptoEngine.SecureClear(authTag);

            remaining -= bytesRead;
            processedSize += bytesRead;
            chunkCount++;

            // Report progress
            if (callback) {
                int percent = (int)(processedSize * 100 / totalSize);
                callback->OnProgress(currentFileIndex + 1, (int)files.size(), file.relativePath);
            }
        }

        // Write chunk count for this file
        WriteFile(hOutput, &chunkCount, sizeof(chunkCount), &written, nullptr);

        CloseHandle(hInput);
        currentFileIndex++;
    }

    CloseHandle(hOutput);
    return true;
}

bool SecureFolderManager::ExtractPackageFile(const std::wstring& packagePath,
                                              const std::wstring& outputFolder,
                                              const std::vector<uint8_t>& key,
                                              IProgressCallback* callback) {
    HANDLE hInput = CreateFileW(packagePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hInput == INVALID_HANDLE_VALUE) {
        m_lastError = L"Cannot open package file";
        return false;
    }

    // Read header (including index data)
    SecurePackageHeader header;
    std::vector<uint8_t> salt, verifyHash, indexIV, indexCipher, indexTag;
    std::wstring originalFolderName;

    if (!ReadPackageHeader(hInput, header, salt, verifyHash, originalFolderName, indexIV, indexCipher, indexTag)) {
        CloseHandle(hInput);
        m_lastError = L"Invalid package header";
        return false;
    }

    // Decrypt index (index data already read by ReadPackageHeader)
    std::vector<FileInfo> files;
    if (!ParseEncryptedIndex(indexCipher, key, indexIV, indexTag, files)) {
        CloseHandle(hInput);
        m_cryptoEngine.SecureClear(indexIV);
        m_cryptoEngine.SecureClear(indexCipher);
        m_cryptoEngine.SecureClear(indexTag);
        m_lastError = L"Failed to decrypt index (wrong password or corrupted file)";
        return false;
    }

    m_cryptoEngine.SecureClear(indexIV);
    m_cryptoEngine.SecureClear(indexCipher);
    m_cryptoEngine.SecureClear(indexTag);

    // Create output folder
    if (!CreateDirectoryW(outputFolder.c_str(), nullptr)) {
        DWORD err = ::GetLastError();
        if (err != ERROR_ALREADY_EXISTS) {
            CloseHandle(hInput);
            m_lastError = L"Cannot create output folder: " + std::to_wstring(err);
            return false;
        }
    }

    // Calculate total size for progress
    uint64_t totalSize = 0;
    for (const auto& file : files) {
        totalSize += file.size;
    }

    uint64_t processedSize = 0;
    int currentFileIndex = 0;
    DWORD bytesRead = 0;

    // Extract each file
    for (const auto& fileInfo : files) {
        if (callback && callback->ShouldCancel()) {
            CloseHandle(hInput);
            m_lastError = L"User cancelled";
            return false;
        }

        // Read file entry header
        uint32_t pathLen = 0;
        uint64_t fileSize64 = 0;

        ReadFile(hInput, &pathLen, sizeof(pathLen), &bytesRead, nullptr);
        std::vector<char> pathBuf(pathLen);
        ReadFile(hInput, pathBuf.data(), pathLen, &bytesRead, nullptr);
        ReadFile(hInput, &fileSize64, sizeof(fileSize64), &bytesRead, nullptr);

        std::wstring relativePath = Utils::Utf8ToWide(std::string(pathBuf.begin(), pathBuf.end()));

        // Build output path
        std::wstring outputPath = outputFolder + L"\\";
        outputPath += relativePath;

        // Ensure parent directory exists
        std::filesystem::path op(outputPath);
        std::filesystem::path parentDir = op.parent_path();
        if (!std::filesystem::exists(parentDir)) {
            std::filesystem::create_directories(parentDir);
        }

        // Create output file
        HANDLE hOutput = CreateFileW(outputPath.c_str(), GENERIC_WRITE, 0,
                                     nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hOutput == INVALID_HANDLE_VALUE) {
            CloseHandle(hInput);
            m_lastError = L"Cannot create output file: " + outputPath;
            return false;
        }

        // Decrypt chunks
        std::vector<uint8_t> chunkIV(AES_IV_SIZE);
        std::vector<uint8_t> cipherBuffer;
        std::vector<uint8_t> authTag(AES_TAG_SIZE);
        std::vector<uint8_t> plainBuffer;

        uint64_t remaining = fileSize64;

        while (remaining > 0) {
            // Read chunk header
            uint32_t cipherLen = 0;

            // Resize buffers before each iteration (they were cleared in previous iteration)
            chunkIV.resize(AES_IV_SIZE);
            authTag.resize(AES_TAG_SIZE);

            ReadFile(hInput, chunkIV.data(), AES_IV_SIZE, &bytesRead, nullptr);
            ReadFile(hInput, &cipherLen, sizeof(cipherLen), &bytesRead, nullptr);

            cipherBuffer.resize(cipherLen);
            ReadFile(hInput, cipherBuffer.data(), cipherLen, &bytesRead, nullptr);
            ReadFile(hInput, authTag.data(), AES_TAG_SIZE, &bytesRead, nullptr);

            // Decrypt chunk
            if (!m_cryptoEngine.Decrypt(cipherBuffer, key, chunkIV, authTag, plainBuffer)) {
                CloseHandle(hOutput);
                CloseHandle(hInput);
                m_lastError = L"Decryption error: " + m_cryptoEngine.GetLastError();
                return false;
            }

            // Write decrypted data
            DWORD written = 0;
            WriteFile(hOutput, plainBuffer.data(), (DWORD)plainBuffer.size(), &written, nullptr);

            remaining -= plainBuffer.size();
            processedSize += plainBuffer.size();

            m_cryptoEngine.SecureClear(chunkIV);
            m_cryptoEngine.SecureClear(cipherBuffer);
            m_cryptoEngine.SecureClear(authTag);
            m_cryptoEngine.SecureClear(plainBuffer);

            // Report progress
            if (callback) {
                int percent = (int)(processedSize * 100 / totalSize);
                callback->OnProgress(currentFileIndex + 1, (int)files.size(), relativePath);
            }
        }

        // Read chunk count (for file integrity check)
        uint32_t chunkCount = 0;
        ReadFile(hInput, &chunkCount, sizeof(chunkCount), &bytesRead, nullptr);

        CloseHandle(hOutput);
        currentFileIndex++;

        // Preserve timestamp if configured
        if (m_config.preserveTimestamp) {
            // Use current time for now (original timestamps stored in index could be restored)
        }
    }

    CloseHandle(hInput);
    return true;
}

bool SecureFolderManager::ReadPackageHeader(HANDLE hFile,
                                             SecurePackageHeader& header,
                                             std::vector<uint8_t>& salt,
                                             std::vector<uint8_t>& verifyHash,
                                             std::wstring& originalFolderName,
                                             std::vector<uint8_t>& indexIV,
                                             std::vector<uint8_t>& indexCipher,
                                             std::vector<uint8_t>& indexTag) {
    DWORD bytesRead = 0;

    // Read magic
    ReadFile(hFile, header.magic, 4, &bytesRead, nullptr);
    if (bytesRead != 4 || header.magic[0] != 'S' || header.magic[1] != 'F' ||
        header.magic[2] != 'P' || header.magic[3] != 'K') {
        return false;
    }

    // Read version, flags
    ReadFile(hFile, &header.version, sizeof(header.version), &bytesRead, nullptr);
    ReadFile(hFile, &header.flags, sizeof(header.flags), &bytesRead, nullptr);

    // Read folder name
    ReadFile(hFile, &header.originalFolderNameLen, sizeof(header.originalFolderNameLen), &bytesRead, nullptr);
    std::vector<char> nameBuf(header.originalFolderNameLen);
    ReadFile(hFile, nameBuf.data(), header.originalFolderNameLen, &bytesRead, nullptr);
    originalFolderName = Utils::Utf8ToWide(std::string(nameBuf.begin(), nameBuf.end()));

    // Read file count
    ReadFile(hFile, &header.originalFileCount, sizeof(header.originalFileCount), &bytesRead, nullptr);

    // Read salt
    ReadFile(hFile, &header.saltLen, sizeof(header.saltLen), &bytesRead, nullptr);
    salt.resize(header.saltLen);
    ReadFile(hFile, salt.data(), header.saltLen, &bytesRead, nullptr);

    // Read verify hash
    ReadFile(hFile, &header.verifyHashLen, sizeof(header.verifyHashLen), &bytesRead, nullptr);
    verifyHash.resize(header.verifyHashLen);
    ReadFile(hFile, verifyHash.data(), header.verifyHashLen, &bytesRead, nullptr);

    // Read index IV length and data
    ReadFile(hFile, &header.indexIVLen, sizeof(header.indexIVLen), &bytesRead, nullptr);
    indexIV.resize(header.indexIVLen);
    ReadFile(hFile, indexIV.data(), header.indexIVLen, &bytesRead, nullptr);

    // Read index cipher length and data
    ReadFile(hFile, &header.indexCipherLen, sizeof(header.indexCipherLen), &bytesRead, nullptr);
    indexCipher.resize(header.indexCipherLen);
    ReadFile(hFile, indexCipher.data(), header.indexCipherLen, &bytesRead, nullptr);

    // Read index tag length and data
    ReadFile(hFile, &header.indexTagLen, sizeof(header.indexTagLen), &bytesRead, nullptr);
    indexTag.resize(header.indexTagLen);
    ReadFile(hFile, indexTag.data(), header.indexTagLen, &bytesRead, nullptr);

    return true;
}

bool SecureFolderManager::BuildEncryptedIndex(const std::vector<FileInfo>& files,
                                               const std::vector<uint8_t>& key,
                                               std::vector<uint8_t>& iv,
                                               std::vector<uint8_t>& cipher,
                                               std::vector<uint8_t>& tag) {
    // Build plaintext index
    std::string indexData;
    for (const auto& file : files) {
        std::string relPath = Utils::WideToUtf8(file.relativePath);
        indexData += relPath + "|" + std::to_string(file.size) + "|0\n";  // 0 = not directory
    }

    std::vector<uint8_t> plainData(indexData.begin(), indexData.end());

    // Generate IV
    m_cryptoEngine.GenerateIV(iv);

    // Encrypt
    if (!m_cryptoEngine.Encrypt(plainData, key, iv, cipher, tag)) {
        m_cryptoEngine.SecureClear(plainData);
        return false;
    }

    m_cryptoEngine.SecureClear(plainData);
    return true;
}

bool SecureFolderManager::ParseEncryptedIndex(const std::vector<uint8_t>& cipher,
                                               const std::vector<uint8_t>& key,
                                               const std::vector<uint8_t>& iv,
                                               const std::vector<uint8_t>& tag,
                                               std::vector<FileInfo>& files) {
    std::vector<uint8_t> plainData;
    if (!m_cryptoEngine.Decrypt(cipher, key, iv, tag, plainData)) {
        return false;
    }

    std::string indexStr(plainData.begin(), plainData.end());
    m_cryptoEngine.SecureClear(plainData);

    size_t pos = 0, end = 0;
    while ((end = indexStr.find('\n', pos)) != std::string::npos) {
        std::string line = indexStr.substr(pos, end - pos);
        pos = end + 1;

        size_t sep1 = line.find('|');
        size_t sep2 = line.find('|', sep1 + 1);
        if (sep1 != std::string::npos && sep2 != std::string::npos) {
            FileInfo info;
            info.relativePath = Utils::Utf8ToWide(line.substr(0, sep1));
            info.size = std::stoull(line.substr(sep1 + 1, sep2 - sep1 - 1));
            info.isDirectory = (line.substr(sep2 + 1) == "1");
            files.push_back(info);
        }
    }

    return true;
}

// ==================== Legacy Methods (Backward Compatibility) ====================

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
    bool indexRead = ReadIndexFile(folderPath, files, key);

    if (!indexRead || files.empty()) {
        files.clear();

        WIN32_FIND_DATAW findData;
        std::wstring searchPath = folderPath + L"\\*" + ENCRYPTED_EXTENSION;

        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE) {
            return true;  // No files to decrypt
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
        return true;
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
    return folderPath + L"\\";
}

bool SecureFolderManager::CreateIndexFile(const std::wstring& folderPath,
                                           const std::vector<FileInfo>& files,
                                           const std::vector<uint8_t>& key) {
    std::wstring indexPath = GetIndexPath(folderPath) + LOCK_FILE_NAME + L".idx";

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
    std::wstring indexPath = GetIndexPath(folderPath) + LOCK_FILE_NAME + L".idx";

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
            info.path = folderPath + L"\\";
            info.path += info.relativePath;
            info.path += ENCRYPTED_EXTENSION;
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