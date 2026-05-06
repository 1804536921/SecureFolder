#pragma once

// Common Types and Constants for SecureFolder

#include <string>
#include <vector>
#include <cstdint>
#include <functional>

// Windows headers must be included first
#include <Windows.h>
#include <wincrypt.h>

// Then standard library headers that depend on Windows types
#include <filesystem>

namespace SecureFolder {

// Encrypt mode
enum class EncryptMode {
    QuickLock,      // Quick mode: only CLSID disguise
    FullEncrypt,    // Full mode: disguise + AES encryption
    CryptoOnly      // Crypto only: no disguise
};

// Encrypt config
struct EncryptConfig {
    EncryptMode mode = EncryptMode::FullEncrypt;
    int pbkdf2Iterations = 100000;
    bool secureDelete = true;
    bool preserveTimestamp = true;
    std::vector<std::wstring> excludeExtensions;
};

// Progress callback interface
class IProgressCallback {
public:
    virtual ~IProgressCallback() = default;
    virtual void OnProgress(int current, int total, const std::wstring& currentFile) = 0;
    virtual void OnError(const std::wstring& error) = 0;
    virtual bool ShouldCancel() { return false; }
};

// Operation result
struct Result {
    bool success = false;
    std::wstring message;
    int errorCode = 0;
};

// File info
struct FileInfo {
    std::wstring path;
    std::wstring relativePath;
    uint64_t size;
    bool isDirectory;
};

// Encrypted file header format
#pragma pack(push, 1)
struct EncryptedFileHeader {
    char magic[4] = {'E', 'N', 'C', 'F'};
    uint32_t version = 1;
    uint32_t flags = 0;
    uint64_t originalSize = 0;
    uint32_t originalNameLen = 0;
};
#pragma pack(pop)

// Constants
constexpr uint32_t AES_KEY_SIZE = 32;       // 256 bits
constexpr uint32_t AES_IV_SIZE = 12;        // GCM IV (12 bytes recommended)
constexpr uint32_t AES_TAG_SIZE = 16;       // GCM Auth Tag
constexpr uint32_t SALT_SIZE = 32;          // PBKDF2 Salt
constexpr uint32_t CHUNK_SIZE = 1024 * 1024; // 1MB chunks

// CLSID list for disguise
const std::vector<std::wstring> CLSID_LIST = {
    L"{21EC2020-3AEA-1069-A2DD-08002B30309D}", // Control Panel
    L"{2559A1F4-21D7-11D4-BDAF-00C04F60B9D0}", // Windows Security
    L"{645FF040-5081-101B-9F08-00AA002F954E}", // Recycle Bin
    L"{20D04FE0-3AEA-1069-A2DD-08002B30309D}", // My Computer
    L"{F02C5A5E-21D7-11D4-BDAF-00C04F60B9D0}", // Network
    L"{450D8FBA-AD25-11D0-98A8-0800361B1103}", // My Documents
};

// Lock file name
const std::wstring LOCK_FILE_NAME = L".securelock";
const std::wstring ENCRYPTED_EXTENSION = L".encf";
const std::wstring LOCKED_FOLDER_SUFFIX = L".securefolder";  // Encrypted folder suffix (deprecated)
const std::wstring PACKAGE_FILE_EXTENSION = L".securefolder"; // Package file extension (new format)

// Package file magic number
constexpr uint32_t PACKAGE_MAGIC = 0x5346504B;  // "SFPK" - SecureFolder Package

// Package file header (new format for single-file encryption)
#pragma pack(push, 1)
struct SecurePackageHeader {
    char magic[4] = {'S', 'F', 'P', 'K'};  // Magic number
    uint32_t version = 1;                   // Format version
    uint32_t flags = 0;                     // Reserved flags
    uint32_t originalFolderNameLen = 0;    // Original folder name length
    uint32_t originalFileCount = 0;        // Number of files in package
    uint32_t saltLen = SALT_SIZE;          // Salt length (32 bytes)
    uint32_t verifyHashLen = 32;           // Password verify hash length
    uint32_t indexIVLen = AES_IV_SIZE;     // Index encryption IV length (12 bytes)
    uint32_t indexCipherLen = 0;           // Encrypted index data length
    uint32_t indexTagLen = AES_TAG_SIZE;   // Index auth tag length (16 bytes)
};

// File entry header in package (per file)
struct FileEntryHeader {
    uint32_t relativePathLen = 0;          // Relative path length
    uint64_t originalSize = 0;             // Original file size
    uint32_t chunkCount = 0;               // Number of chunks
};
#pragma pack(pop)

} // namespace SecureFolder