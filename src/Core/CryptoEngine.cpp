#include "CryptoEngine.h"
#include "Utils.h"
#include <stdexcept>

namespace SecureFolder {

CryptoEngine::CryptoEngine() : m_hAesAlg(nullptr), m_hShaAlg(nullptr) {
    if (!InitializeAlgorithms()) {
        // Log error but don't throw - will fail on first operation
    }
}

CryptoEngine::~CryptoEngine() {
    if (m_hAesAlg) BCryptCloseAlgorithmProvider(m_hAesAlg, 0);
    if (m_hShaAlg) BCryptCloseAlgorithmProvider(m_hShaAlg, 0);
}

bool CryptoEngine::InitializeAlgorithms() {
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&m_hAesAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status != 0) {
        m_lastError = L"Cannot open AES algorithm provider, status: " + std::to_wstring(status);
        return false;
    }

    status = BCryptSetProperty(m_hAesAlg, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status != 0) {
        m_lastError = L"Cannot set GCM mode, status: " + std::to_wstring(status);
        BCryptCloseAlgorithmProvider(m_hAesAlg, 0);
        m_hAesAlg = nullptr;
        return false;
    }

    status = BCryptOpenAlgorithmProvider(&m_hShaAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status != 0) {
        m_lastError = L"Cannot open SHA256 algorithm provider (HMAC), status: " + std::to_wstring(status);
        BCryptCloseAlgorithmProvider(m_hAesAlg, 0);
        m_hAesAlg = nullptr;
        return false;
    }

    return true;
}

bool CryptoEngine::DeriveKeyFromPassword(const std::wstring& password,
                                          const std::vector<uint8_t>& salt,
                                          std::vector<uint8_t>& outKey,
                                          int iterations) {
    if (!m_hShaAlg) {
        m_lastError = L"SHA256 algorithm not initialized";
        return false;
    }

    std::string passwordBytes = Utils::WideToUtf8(password);

    outKey.resize(AES_KEY_SIZE);

    NTSTATUS status = BCryptDeriveKeyPBKDF2(
        m_hShaAlg,
        (PUCHAR)passwordBytes.data(),
        (ULONG)passwordBytes.size(),
        (PUCHAR)salt.data(),
        (ULONG)salt.size(),
        iterations,
        outKey.data(),
        AES_KEY_SIZE,
        0
    );

    if (status != 0) {
        m_lastError = L"PBKDF2 key derivation failed, status: " + std::to_wstring(status);
        SecureClear(outKey);
        return false;
    }

    return true;
}

bool CryptoEngine::GenerateSalt(std::vector<uint8_t>& salt, size_t size) {
    salt.resize(size);

    NTSTATUS status = BCryptGenRandom(
        nullptr,
        salt.data(),
        (ULONG)size,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (status != 0) {
        m_lastError = L"Failed to generate random salt";
        return false;
    }

    return true;
}

bool CryptoEngine::GenerateIV(std::vector<uint8_t>& iv, size_t size) {
    iv.resize(size);

    NTSTATUS status = BCryptGenRandom(
        nullptr,
        iv.data(),
        (ULONG)size,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (status != 0) {
        m_lastError = L"Failed to generate random IV";
        return false;
    }

    return true;
}

bool CryptoEngine::CreateAesKey(BCRYPT_KEY_HANDLE& hKey, const std::vector<uint8_t>& key) {
    NTSTATUS status = BCryptGenerateSymmetricKey(
        m_hAesAlg,
        &hKey,
        nullptr,
        0,
        (PUCHAR)key.data(),
        (ULONG)key.size(),
        0
    );

    if (status != 0) {
        m_lastError = L"Failed to create AES key";
        return false;
    }

    return true;
}

bool CryptoEngine::Encrypt(const std::vector<uint8_t>& plaintext,
                           const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& iv,
                           std::vector<uint8_t>& ciphertext,
                           std::vector<uint8_t>& authTag) {
    BCRYPT_KEY_HANDLE hKey = nullptr;

    if (!CreateAesKey(hKey, key)) {
        return false;
    }

    // Make copies since BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO requires non-const pointers
    std::vector<uint8_t> ivCopy = iv;
    authTag.resize(AES_TAG_SIZE);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

    authInfo.pbNonce = ivCopy.data();
    authInfo.cbNonce = (ULONG)ivCopy.size();
    authInfo.pbTag = authTag.data();
    authInfo.cbTag = AES_TAG_SIZE;

    ciphertext.resize(plaintext.size());

    ULONG resultLen = 0;

    // Make a copy since BCryptEncrypt requires non-const
    std::vector<uint8_t> plainCopy = plaintext;

    NTSTATUS status = BCryptEncrypt(
        hKey,
        plainCopy.data(),
        (ULONG)plainCopy.size(),
        &authInfo,
        nullptr, 0,
        ciphertext.data(),
        (ULONG)ciphertext.size(),
        &resultLen,
        0
    );

    BCryptDestroyKey(hKey);
    SecureClear(plainCopy);
    SecureClear(ivCopy);

    if (status != 0) {
        m_lastError = L"AES-GCM encryption failed";
        SecureClear(ciphertext);
        SecureClear(authTag);
        return false;
    }

    return true;
}

bool CryptoEngine::Decrypt(const std::vector<uint8_t>& ciphertext,
                           const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& iv,
                           const std::vector<uint8_t>& authTag,
                           std::vector<uint8_t>& plaintext) {
    BCRYPT_KEY_HANDLE hKey = nullptr;

    if (!CreateAesKey(hKey, key)) {
        return false;
    }

    // Make copies since BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO requires non-const pointers
    std::vector<uint8_t> ivCopy = iv;
    std::vector<uint8_t> tagCopy = authTag;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

    authInfo.pbNonce = ivCopy.data();
    authInfo.cbNonce = (ULONG)ivCopy.size();
    authInfo.pbTag = tagCopy.data();
    authInfo.cbTag = (ULONG)tagCopy.size();

    plaintext.resize(ciphertext.size());

    ULONG resultLen = 0;

    // Make a copy since BCryptDecrypt requires non-const
    std::vector<uint8_t> cipherCopy = ciphertext;

    NTSTATUS status = BCryptDecrypt(
        hKey,
        cipherCopy.data(),
        (ULONG)cipherCopy.size(),
        &authInfo,
        nullptr, 0,
        plaintext.data(),
        (ULONG)plaintext.size(),
        &resultLen,
        0
    );

    BCryptDestroyKey(hKey);
    SecureClear(cipherCopy);
    SecureClear(ivCopy);
    SecureClear(tagCopy);

    if (status != 0) {
        m_lastError = L"AES-GCM decryption failed (auth tag mismatch or wrong key)";
        SecureClear(plaintext);
        return false;
    }

    return true;
}

bool CryptoEngine::EncryptFile(const std::wstring& inputPath,
                                const std::wstring& outputPath,
                                const std::vector<uint8_t>& key,
                                IProgressCallback* callback) {
    HANDLE hInput = CreateFileW(inputPath.c_str(), GENERIC_READ,
                                FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hInput == INVALID_HANDLE_VALUE) {
        m_lastError = L"Cannot open input file: " + inputPath;
        return false;
    }

    LARGE_INTEGER fileSize;
    GetFileSizeEx(hInput, &fileSize);

    std::vector<uint8_t> iv;
    if (!GenerateIV(iv)) {
        CloseHandle(hInput);
        return false;
    }

    HANDLE hOutput = CreateFileW(outputPath.c_str(), GENERIC_WRITE,
                                 0, nullptr, CREATE_ALWAYS,
                                 FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hOutput == INVALID_HANDLE_VALUE) {
        m_lastError = L"Cannot create output file: " + outputPath;
        CloseHandle(hInput);
        return false;
    }

    EncryptedFileHeader header;
    header.originalSize = fileSize.QuadPart;

    // Get file name and encrypt it
    std::wstring fileName = std::filesystem::path(inputPath).filename().wstring();
    std::string nameBytes = Utils::WideToUtf8(fileName);
    header.originalNameLen = (uint32_t)nameBytes.size();

    std::vector<uint8_t> nameIV, nameTag, nameCipher;
    GenerateIV(nameIV, AES_IV_SIZE);
    std::vector<uint8_t> nameData(nameBytes.begin(), nameBytes.end());
    Encrypt(nameData, key, nameIV, nameCipher, nameTag);

    DWORD written = 0;
    WriteFile(hOutput, &header, sizeof(header), &written, nullptr);

    WriteFile(hOutput, nameIV.data(), (DWORD)nameIV.size(), &written, nullptr);
    WriteFile(hOutput, nameTag.data(), (DWORD)nameTag.size(), &written, nullptr);
    uint32_t nameCipherLen = (uint32_t)nameCipher.size();
    WriteFile(hOutput, &nameCipherLen, sizeof(nameCipherLen), &written, nullptr);
    WriteFile(hOutput, nameCipher.data(), (DWORD)nameCipher.size(), &written, nullptr);

    WriteFile(hOutput, iv.data(), (DWORD)iv.size(), &written, nullptr);

    std::vector<uint8_t> buffer(CHUNK_SIZE);
    std::vector<uint8_t> cipherBuffer;
    std::vector<uint8_t> authTagOut;
    uint64_t totalRead = 0;

    while (totalRead < (uint64_t)fileSize.QuadPart) {
        if (callback && callback->ShouldCancel()) {
            CloseHandle(hInput);
            CloseHandle(hOutput);
            DeleteFileW(outputPath.c_str());
            m_lastError = L"User cancelled operation";
            return false;
        }

        DWORD toRead = (DWORD)min(CHUNK_SIZE, fileSize.QuadPart - totalRead);
        DWORD bytesRead = 0;

        if (!ReadFile(hInput, buffer.data(), toRead, &bytesRead, nullptr) || bytesRead == 0) {
            m_lastError = L"Failed to read file";
            CloseHandle(hInput);
            CloseHandle(hOutput);
            DeleteFileW(outputPath.c_str());
            return false;
        }

        std::vector<uint8_t> chunkIV;
        GenerateIV(chunkIV, AES_IV_SIZE);

        std::vector<uint8_t> plainChunk(buffer.begin(), buffer.begin() + bytesRead);
        if (!Encrypt(plainChunk, key, chunkIV, cipherBuffer, authTagOut)) {
            CloseHandle(hInput);
            CloseHandle(hOutput);
            DeleteFileW(outputPath.c_str());
            return false;
        }

        WriteFile(hOutput, chunkIV.data(), (DWORD)chunkIV.size(), &written, nullptr);
        uint32_t cipherLen = (uint32_t)cipherBuffer.size();
        WriteFile(hOutput, &cipherLen, sizeof(cipherLen), &written, nullptr);
        WriteFile(hOutput, cipherBuffer.data(), (DWORD)cipherBuffer.size(), &written, nullptr);
        WriteFile(hOutput, authTagOut.data(), (DWORD)authTagOut.size(), &written, nullptr);

        totalRead += bytesRead;

        SecureClear(buffer);
        SecureClear(chunkIV);
        SecureClear(cipherBuffer);
        SecureClear(authTagOut);

        if (callback) {
            callback->OnProgress((int)totalRead, (int)fileSize.QuadPart, inputPath);
        }
    }

    CloseHandle(hInput);
    CloseHandle(hOutput);

    return true;
}

bool CryptoEngine::DecryptFile(const std::wstring& inputPath,
                                const std::wstring& outputPath,
                                const std::vector<uint8_t>& key,
                                uint64_t* originalSize) {
    HANDLE hInput = CreateFileW(inputPath.c_str(), GENERIC_READ,
                                FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hInput == INVALID_HANDLE_VALUE) {
        m_lastError = L"Cannot open encrypted file: " + inputPath;
        return false;
    }

    EncryptedFileHeader header;
    DWORD bytesRead = 0;
    if (!ReadFile(hInput, &header, sizeof(header), &bytesRead, nullptr) || bytesRead != sizeof(header)) {
        m_lastError = L"Cannot read file header";
        CloseHandle(hInput);
        return false;
    }

    if (header.magic[0] != 'E' || header.magic[1] != 'N' || header.magic[2] != 'C' || header.magic[3] != 'F') {
        m_lastError = L"Invalid encrypted file format";
        CloseHandle(hInput);
        return false;
    }

    if (originalSize) *originalSize = header.originalSize;

    std::vector<uint8_t> nameIV(AES_IV_SIZE);
    std::vector<uint8_t> nameTag(AES_TAG_SIZE);
    uint32_t nameCipherLen = 0;

    ReadFile(hInput, nameIV.data(), (DWORD)nameIV.size(), &bytesRead, nullptr);
    ReadFile(hInput, nameTag.data(), (DWORD)nameTag.size(), &bytesRead, nullptr);
    ReadFile(hInput, &nameCipherLen, sizeof(nameCipherLen), &bytesRead, nullptr);

    std::vector<uint8_t> nameCipher(nameCipherLen);
    ReadFile(hInput, nameCipher.data(), (DWORD)nameCipherLen, &bytesRead, nullptr);

    std::vector<uint8_t> namePlain;
    Decrypt(nameCipher, key, nameIV, nameTag, namePlain);

    std::vector<uint8_t> mainIV(AES_IV_SIZE);
    ReadFile(hInput, mainIV.data(), (DWORD)mainIV.size(), &bytesRead, nullptr);

    HANDLE hOutput = CreateFileW(outputPath.c_str(), GENERIC_WRITE,
                                 0, nullptr, CREATE_ALWAYS,
                                 FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hOutput == INVALID_HANDLE_VALUE) {
        m_lastError = L"Cannot create output file: " + outputPath;
        CloseHandle(hInput);
        return false;
    }

    uint64_t totalWritten = 0;

    while (totalWritten < header.originalSize) {
        std::vector<uint8_t> chunkIV(AES_IV_SIZE);
        DWORD bytesReadNow = 0;
        if (!ReadFile(hInput, chunkIV.data(), (DWORD)chunkIV.size(), &bytesReadNow, nullptr) || bytesReadNow == 0) {
            break;
        }

        uint32_t cipherLen = 0;
        ReadFile(hInput, &cipherLen, sizeof(cipherLen), &bytesReadNow, nullptr);

        std::vector<uint8_t> cipherBuffer(cipherLen);
        ReadFile(hInput, cipherBuffer.data(), (DWORD)cipherLen, &bytesReadNow, nullptr);

        std::vector<uint8_t> authTag(AES_TAG_SIZE);
        ReadFile(hInput, authTag.data(), (DWORD)authTag.size(), &bytesReadNow, nullptr);

        std::vector<uint8_t> plainBuffer;
        if (!Decrypt(cipherBuffer, key, chunkIV, authTag, plainBuffer)) {
            CloseHandle(hInput);
            CloseHandle(hOutput);
            DeleteFileW(outputPath.c_str());
            return false;
        }

        DWORD toWrite = (DWORD)min(plainBuffer.size(), header.originalSize - totalWritten);
        WriteFile(hOutput, plainBuffer.data(), toWrite, &bytesReadNow, nullptr);

        totalWritten += toWrite;

        SecureClear(chunkIV);
        SecureClear(cipherBuffer);
        SecureClear(authTag);
        SecureClear(plainBuffer);
    }

    CloseHandle(hInput);
    CloseHandle(hOutput);

    return true;
}

void CryptoEngine::SecureClear(std::vector<uint8_t>& data) {
    if (!data.empty()) {
        SecureClear(data.data(), data.size());
        data.clear();
    }
}

void CryptoEngine::SecureClear(uint8_t* data, size_t size) {
    if (data && size > 0) {
        SecureZeroMemory(data, size);
    }
}

} // namespace SecureFolder