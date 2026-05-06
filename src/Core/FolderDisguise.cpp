#include "FolderDisguise.h"
#include "Utils.h"
#include <AclAPI.h>
#include <Sddl.h>

namespace SecureFolder {

FolderDisguise::FolderDisguise() {
}

std::wstring FolderDisguise::GetRandomCLSID() {
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        BYTE b = 0;
        CryptGenRandom(hProv, 1, &b);
        CryptReleaseContext(hProv, 0);
        return CLSID_LIST[b % CLSID_LIST.size()];
    }
    return CLSID_LIST[0];
}

Result FolderDisguise::ApplyDisguise(const std::wstring& folderPath, const std::wstring& clsid) {
    Result result;

    if (!Utils::FolderExists(folderPath)) {
        result.message = L"Folder does not exist: " + folderPath;
        result.errorCode = ERROR_PATH_NOT_FOUND;
        return result;
    }

    std::wstring disguisedName = folderPath + L"." + clsid;

    m_originalPath = folderPath;

    if (!MoveFileW(folderPath.c_str(), disguisedName.c_str())) {
        DWORD err = ::GetLastError();
        result.message = L"Failed to rename folder, error code: " + std::to_wstring(err);
        result.errorCode = err;
        m_lastError = result.message;
        return result;
    }

    Result attrResult = SetHiddenAttributes(disguisedName);
    if (!attrResult.success) {
        MoveFileW(disguisedName.c_str(), folderPath.c_str());
        result.message = attrResult.message;
        result.errorCode = attrResult.errorCode;
        return result;
    }

    result.success = true;
    result.message = L"Disguise applied: " + disguisedName;
    return result;
}

Result FolderDisguise::RemoveDisguise(const std::wstring& disguisedPath) {
    Result result;

    if (!IsDisguised(disguisedPath)) {
        result.message = L"This folder is not disguised";
        result.errorCode = 0;
        return result;
    }

    std::wstring originalName = GetOriginalName(disguisedPath);

    RestoreAttributes(disguisedPath);

    RestorePermission(disguisedPath);

    if (!MoveFileW(disguisedPath.c_str(), originalName.c_str())) {
        DWORD err = ::GetLastError();
        result.message = L"Failed to remove disguise, error code: " + std::to_wstring(err);
        result.errorCode = err;
        m_lastError = result.message;
        return result;
    }

    result.success = true;
    result.message = L"Disguise removed: " + originalName;
    return result;
}

bool FolderDisguise::IsDisguised(const std::wstring& folderPath) {
    return Utils::IsCLSIDFolder(folderPath);
}

std::wstring FolderDisguise::GetOriginalName(const std::wstring& disguisedPath) {
    return Utils::ExtractOriginalName(disguisedPath);
}

Result FolderDisguise::SetHiddenAttributes(const std::wstring& folderPath) {
    Result result;

    DWORD currentAttr = GetFileAttributesW(folderPath.c_str());
    if (currentAttr == INVALID_FILE_ATTRIBUTES) {
        result.message = L"Cannot get folder attributes";
        result.errorCode = ::GetLastError();
        return result;
    }

    m_originalAttributes = currentAttr;

    DWORD newAttr = currentAttr | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
    if (!SetFileAttributesW(folderPath.c_str(), newAttr)) {
        result.message = L"Failed to set hidden attributes";
        result.errorCode = ::GetLastError();
        return result;
    }

    result.success = true;
    return result;
}

Result FolderDisguise::RestoreAttributes(const std::wstring& folderPath) {
    Result result;

    DWORD currentAttr = GetFileAttributesW(folderPath.c_str());
    if (currentAttr == INVALID_FILE_ATTRIBUTES) {
        result.message = L"Cannot get folder attributes";
        result.errorCode = ::GetLastError();
        return result;
    }

    DWORD newAttr = currentAttr & ~(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    if (!SetFileAttributesW(folderPath.c_str(), newAttr)) {
        result.message = L"Failed to restore attributes";
        result.errorCode = ::GetLastError();
        return result;
    }

    result.success = true;
    return result;
}

Result FolderDisguise::SetDenyPermission(const std::wstring& folderPath) {
    Result result;

    PACL pOldDacl = nullptr;
    PSECURITY_DESCRIPTOR pOldSd = nullptr;

    DWORD res = GetNamedSecurityInfoW(
        folderPath.c_str(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        &pOldDacl,
        nullptr,
        &pOldSd
    );

    if (res != ERROR_SUCCESS) {
        result.message = L"Failed to get security descriptor";
        result.errorCode = res;
        return result;
    }

    m_originalDacl = pOldDacl;
    m_originalSd = pOldSd;

    EXPLICIT_ACCESS_W ea;
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = DENY_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;

    // Get Everyone SID
    PSID pEveryoneSid = nullptr;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSid);
    ea.Trustee.ptstrName = (LPWSTR)pEveryoneSid;

    PACL pNewDacl = nullptr;
    res = SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);

    if (pEveryoneSid) FreeSid(pEveryoneSid);

    if (res != ERROR_SUCCESS) {
        LocalFree(pOldSd);
        result.message = L"Failed to create new DACL";
        result.errorCode = res;
        return result;
    }

    res = SetNamedSecurityInfoW(
        (LPWSTR)folderPath.c_str(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        pNewDacl,
        nullptr
    );

    LocalFree(pNewDacl);

    if (res != ERROR_SUCCESS) {
        LocalFree(pOldSd);
        result.message = L"Failed to set permissions";
        result.errorCode = res;
        return result;
    }

    result.success = true;
    return result;
}

Result FolderDisguise::RestorePermission(const std::wstring& folderPath) {
    Result result;

    if (m_originalSd) {
        PACL pDacl = nullptr;
        BOOL bDaclPresent = FALSE;
        BOOL bDaclDefaulted = FALSE;

        GetSecurityDescriptorDacl(m_originalSd, &bDaclPresent, &pDacl, &bDaclDefaulted);

        if (bDaclPresent && pDacl) {
            DWORD res = SetNamedSecurityInfoW(
                (LPWSTR)folderPath.c_str(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                nullptr,
                nullptr,
                pDacl,
                nullptr
            );

            if (res != ERROR_SUCCESS) {
                result.message = L"Failed to restore permissions";
                result.errorCode = res;
                LocalFree(m_originalSd);
                m_originalSd = nullptr;
                m_originalDacl = nullptr;
                return result;
            }
        }

        LocalFree(m_originalSd);
        m_originalSd = nullptr;
        m_originalDacl = nullptr;
    }

    result.success = true;
    return result;
}

Result FolderDisguise::CreateLockFile(const std::wstring& folderPath,
                                       const std::vector<uint8_t>& passwordHash,
                                       const std::vector<uint8_t>& salt) {
    Result result;

    std::wstring lockFilePath = folderPath + L"\\" + LOCK_FILE_NAME;

    HANDLE hFile = CreateFileW(
        lockFilePath.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        result.message = L"Failed to create lock file";
        result.errorCode = ::GetLastError();
        return result;
    }

    DWORD written = 0;
    uint32_t magic = 0x534C434B;
    uint32_t version = 1;
    uint32_t saltLen = (uint32_t)salt.size();
    uint32_t hashLen = (uint32_t)passwordHash.size();

    WriteFile(hFile, &magic, sizeof(magic), &written, nullptr);
    WriteFile(hFile, &version, sizeof(version), &written, nullptr);
    WriteFile(hFile, &saltLen, sizeof(saltLen), &written, nullptr);
    WriteFile(hFile, salt.data(), saltLen, &written, nullptr);
    WriteFile(hFile, &hashLen, sizeof(hashLen), &written, nullptr);
    WriteFile(hFile, passwordHash.data(), hashLen, &written, nullptr);

    CloseHandle(hFile);

    result.success = true;
    return result;
}

bool FolderDisguise::VerifyLockFile(const std::wstring& folderPath,
                                     const std::vector<uint8_t>& passwordHash) {
    std::wstring lockFilePath = folderPath + L"\\" + LOCK_FILE_NAME;

    HANDLE hFile = CreateFileW(
        lockFilePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        m_lastError = L"Cannot open lock file";
        return false;
    }

    DWORD bytesRead = 0;
    uint32_t magic = 0;
    uint32_t version = 0;
    uint32_t saltLen = 0;
    uint32_t hashLen = 0;

    ReadFile(hFile, &magic, sizeof(magic), &bytesRead, nullptr);
    ReadFile(hFile, &version, sizeof(version), &bytesRead, nullptr);

    if (magic != 0x534C434B) {
        CloseHandle(hFile);
        m_lastError = L"Invalid lock file format";
        return false;
    }

    ReadFile(hFile, &saltLen, sizeof(saltLen), &bytesRead, nullptr);
    std::vector<uint8_t> storedSalt(saltLen);
    ReadFile(hFile, storedSalt.data(), saltLen, &bytesRead, nullptr);

    ReadFile(hFile, &hashLen, sizeof(hashLen), &bytesRead, nullptr);
    std::vector<uint8_t> storedHash(hashLen);
    ReadFile(hFile, storedHash.data(), hashLen, &bytesRead, nullptr);

    CloseHandle(hFile);

    if (passwordHash.size() != storedHash.size()) {
        return false;
    }

    bool match = true;
    for (size_t i = 0; i < passwordHash.size(); i++) {
        if (passwordHash[i] != storedHash[i]) {
            match = false;
            break;
        }
    }

    return match;
}

bool FolderDisguise::ReadLockFileSalt(const std::wstring& folderPath,
                                       std::vector<uint8_t>& salt) {
    std::wstring lockFilePath = folderPath + L"\\" + LOCK_FILE_NAME;

    HANDLE hFile = CreateFileW(
        lockFilePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        m_lastError = L"Cannot open lock file";
        return false;
    }

    DWORD bytesRead = 0;
    uint32_t magic = 0;
    uint32_t version = 0;
    uint32_t saltLen = 0;

    ReadFile(hFile, &magic, sizeof(magic), &bytesRead, nullptr);
    ReadFile(hFile, &version, sizeof(version), &bytesRead, nullptr);

    if (magic != 0x534C434B) {
        CloseHandle(hFile);
        m_lastError = L"Invalid lock file format";
        return false;
    }

    ReadFile(hFile, &saltLen, sizeof(saltLen), &bytesRead, nullptr);
    salt.resize(saltLen);
    ReadFile(hFile, salt.data(), saltLen, &bytesRead, nullptr);

    CloseHandle(hFile);
    return true;
}

} // namespace SecureFolder