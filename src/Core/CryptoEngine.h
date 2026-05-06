#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <Windows.h>
#include <bcrypt.h>
#include "Types.h"

#pragma comment(lib, "bcrypt.lib")

namespace SecureFolder {

class CryptoEngine {
public:
    CryptoEngine();
    ~CryptoEngine();

    // Key derivation (PBKDF2)
    bool DeriveKeyFromPassword(const std::wstring& password, const std::vector<uint8_t>& salt,
                                std::vector<uint8_t>& outKey, int iterations = 100000);

    // Generate random salt
    bool GenerateSalt(std::vector<uint8_t>& salt, size_t size = SALT_SIZE);

    // Generate random IV
    bool GenerateIV(std::vector<uint8_t>& iv, size_t size = AES_IV_SIZE);

    // AES-GCM encrypt
    bool Encrypt(const std::vector<uint8_t>& plaintext,
                 const std::vector<uint8_t>& key,
                 const std::vector<uint8_t>& iv,
                 std::vector<uint8_t>& ciphertext,
                 std::vector<uint8_t>& authTag);

    // AES-GCM decrypt
    bool Decrypt(const std::vector<uint8_t>& ciphertext,
                 const std::vector<uint8_t>& key,
                 const std::vector<uint8_t>& iv,
                 const std::vector<uint8_t>& authTag,
                 std::vector<uint8_t>& plaintext);

    // File encrypt
    bool EncryptFile(const std::wstring& inputPath,
                     const std::wstring& outputPath,
                     const std::vector<uint8_t>& key,
                     IProgressCallback* callback = nullptr);

    // File decrypt
    bool DecryptFile(const std::wstring& inputPath,
                     const std::wstring& outputPath,
                     const std::vector<uint8_t>& key,
                     uint64_t* originalSize = nullptr);

    // Secure clear memory
    void SecureClear(std::vector<uint8_t>& data);
    void SecureClear(uint8_t* data, size_t size);

    // Get last error
    std::wstring GetLastError() const { return m_lastError; }

    // Check if initialized successfully
    bool IsInitialized() const { return m_hAesAlg != nullptr && m_hShaAlg != nullptr; }

private:
    std::wstring m_lastError;
    BCRYPT_ALG_HANDLE m_hAesAlg = nullptr;
    BCRYPT_ALG_HANDLE m_hShaAlg = nullptr;

    bool InitializeAlgorithms();
    bool CreateAesKey(BCRYPT_KEY_HANDLE& hKey, const std::vector<uint8_t>& key);
};

} // namespace SecureFolder