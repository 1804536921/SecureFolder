// Shell Extension DLL - Intercept double-click on encrypted folders
// When user double-clicks encrypted folder, show password dialog

#include <Windows.h>
#include <ShlObj.h>
#include <Shlwapi.h>
#include <shellapi.h>
#include <string>
#include "UI/GUIDialog.h"
#include "Common/Utils.h"
#include "Common/Types.h"

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")

// CLSID for our shell extension
static const CLSID CLSID_SecureFolderShellExt =
{ 0xA1B2C3D4, 0xE5F6, 0x7890, { 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90 } };

// ==================== Shell Extension Class ====================

class CSecureFolderShellExt : public IContextMenu, public IShellExtInit {
public:
    CSecureFolderShellExt();
    virtual ~CSecureFolderShellExt();

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv);
    STDMETHODIMP_(ULONG) AddRef();
    STDMETHODIMP_(ULONG) Release();

    // IShellExtInit
    STDMETHODIMP Initialize(LPCITEMIDLIST pidlFolder, IDataObject* pDataObj, HKEY hKeyProgID);

    // IContextMenu
    STDMETHODIMP QueryContextMenu(HMENU hMenu, UINT indexMenu, UINT idCmdFirst, UINT idCmdLast, UINT uFlags);
    STDMETHODIMP InvokeCommand(LPCMINVOKECOMMANDINFO pici);
    STDMETHODIMP GetCommandString(UINT_PTR idCmd, UINT uType, UINT* pReserved, CHAR* pszName, UINT cchMax);

private:
    ULONG m_cRef;
    std::wstring m_folderPath;
    bool m_isEncryptedFolder;

    bool CheckIfEncrypted(const std::wstring& path);
};

// ==================== Class Implementation ====================

CSecureFolderShellExt::CSecureFolderShellExt() : m_cRef(1), m_isEncryptedFolder(false) {
}

CSecureFolderShellExt::~CSecureFolderShellExt() {
}

STDMETHODIMP CSecureFolderShellExt::QueryInterface(REFIID riid, void** ppv) {
    if (ppv == nullptr) return E_POINTER;

    if (riid == IID_IUnknown || riid == IID_IContextMenu) {
        *ppv = static_cast<IContextMenu*>(this);
    } else if (riid == IID_IShellExtInit) {
        *ppv = static_cast<IShellExtInit*>(this);
    } else {
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    AddRef();
    return S_OK;
}

STDMETHODIMP_(ULONG) CSecureFolderShellExt::AddRef() {
    return InterlockedIncrement(&m_cRef);
}

STDMETHODIMP_(ULONG) CSecureFolderShellExt::Release() {
    ULONG cRef = InterlockedDecrement(&m_cRef);
    if (cRef == 0) {
        delete this;
    }
    return cRef;
}

STDMETHODIMP CSecureFolderShellExt::Initialize(LPCITEMIDLIST pidlFolder, IDataObject* pDataObj, HKEY hKeyProgID) {
    if (pDataObj == nullptr) return E_INVALIDARG;

    FORMATETC fmt = { CF_HDROP, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
    STGMEDIUM stg = { TYMED_HGLOBAL };

    if (FAILED(pDataObj->GetData(&fmt, &stg))) {
        return E_INVALIDARG;
    }

    HDROP hDrop = static_cast<HDROP>(GlobalLock(stg.hGlobal));
    if (hDrop == nullptr) {
        ReleaseStgMedium(&stg);
        return E_INVALIDARG;
    }

    UINT count = DragQueryFileW(hDrop, 0xFFFFFFFF, nullptr, 0);
    if (count == 0) {
        GlobalUnlock(stg.hGlobal);
        ReleaseStgMedium(&stg);
        return E_INVALIDARG;
    }

    wchar_t path[MAX_PATH] = {0};
    DragQueryFileW(hDrop, 0, path, MAX_PATH);

    GlobalUnlock(stg.hGlobal);
    ReleaseStgMedium(&stg);

    m_folderPath = path;
    m_isEncryptedFolder = CheckIfEncrypted(path);

    // For non-encrypted folders, still allow the shell extension to show "Lock" option
    // We'll check in QueryContextMenu what options to show
    // Don't return E_FAIL here - let QueryContextMenu decide

    return S_OK;
}

STDMETHODIMP CSecureFolderShellExt::QueryContextMenu(HMENU hMenu, UINT indexMenu,
                                                       UINT idCmdFirst, UINT idCmdLast, UINT uFlags) {
    UINT idCmd = idCmdFirst;

    if (m_isEncryptedFolder) {
        // Show unlock options for encrypted items
        InsertMenuW(hMenu, indexMenu, MF_BYPOSITION, idCmd, L"Unlock with SecureFolder");
        idCmd++;
        InsertMenuW(hMenu, indexMenu + 1, MF_BYPOSITION, idCmd, L"Unlock and Open Folder");
        idCmd++;
    } else {
        // Check if it's a regular folder - show lock option
        DWORD attr = GetFileAttributesW(m_folderPath.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
            InsertMenuW(hMenu, indexMenu, MF_BYPOSITION, idCmd, L"Lock with SecureFolder");
            idCmd++;
        }
    }

    if (idCmd == idCmdFirst) {
        return E_FAIL;  // No menu items added
    }

    return MAKE_HRESULT(SEVERITY_SUCCESS, 0, idCmd - idCmdFirst);
}

STDMETHODIMP CSecureFolderShellExt::InvokeCommand(LPCMINVOKECOMMANDINFO pici) {
    if (pici == nullptr) return E_INVALIDARG;

    int cmd = LOWORD(pici->lpVerb);
    std::wstring password;

    if (m_isEncryptedFolder) {
        // Unlock commands - unified handling
        bool openAfterUnlock = false;
        if (SecureFolder::RequestPassword(m_folderPath, password, openAfterUnlock)) {
            SecureFolder::SecureFolderManager manager;
            SecureFolder::Result result = manager.UnlockFolder(m_folderPath, password, nullptr);
            if (result.success) {
                MessageBoxW(pici->hwnd, result.message.c_str(), L"Success", MB_ICONINFORMATION);
                if (openAfterUnlock) {
                    // User clicked "Unlock and Open" - open the folder
                    std::wstring openPath = SecureFolder::Utils::ExtractOriginalName(m_folderPath);
                    ShellExecuteW(nullptr, L"open", openPath.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
                }
            } else {
                MessageBoxW(pici->hwnd, result.message.c_str(), L"Error", MB_ICONERROR);
            }
        }
        return S_OK;
    } else {
        // Lock command for regular folder
        if (cmd == 0) {
            if (SecureFolder::RequestPasswordForLock(m_folderPath, password)) {
                SecureFolder::SecureFolderManager manager;
                SecureFolder::EncryptConfig config;
                SecureFolder::Result result = manager.LockFolder(m_folderPath, password,
                    SecureFolder::EncryptMode::FullEncrypt, config, nullptr);
                if (result.success) {
                    MessageBoxW(pici->hwnd, result.message.c_str(), L"Success", MB_ICONINFORMATION);
                } else {
                    MessageBoxW(pici->hwnd, result.message.c_str(), L"Error", MB_ICONERROR);
                }
            }
            return S_OK;
        }
    }

    return E_INVALIDARG;
}

STDMETHODIMP CSecureFolderShellExt::GetCommandString(UINT_PTR idCmd, UINT uType,
                                                       UINT* pReserved, CHAR* pszName, UINT cchMax) {
    if (m_isEncryptedFolder) {
        switch (idCmd) {
            case 0:
                if (uType == GCS_HELPTEXTW) {
                    wcsncpy_s((wchar_t*)pszName, cchMax, L"Enter password to unlock", cchMax);
                }
                return S_OK;

            case 1:
                if (uType == GCS_HELPTEXTW) {
                    wcsncpy_s((wchar_t*)pszName, cchMax, L"Unlock and open folder", cchMax);
                }
                return S_OK;
        }
    } else {
        if (idCmd == 0 && uType == GCS_HELPTEXTW) {
            wcsncpy_s((wchar_t*)pszName, cchMax, L"Encrypt and lock this folder", cchMax);
            return S_OK;
        }
    }

    return E_INVALIDARG;
}

bool CSecureFolderShellExt::CheckIfEncrypted(const std::wstring& path) {
    // Check if this is a SecureFolder package file (new format: .securefolder file)
    if (SecureFolder::Utils::IsSecureFolderPackage(path)) {
        return true;
    }

    // Check if folder has lock file (legacy format)
    std::wstring lockFilePath = path + L"\\" + SecureFolder::LOCK_FILE_NAME;

    if (SecureFolder::Utils::FileExists(lockFilePath)) {
        return true;
    }

    // Check if folder is inaccessible (permission denied = locked)
    DWORD attr = GetFileAttributesW(path.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES) {
        HANDLE hTest = CreateFileW(path.c_str(), GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   nullptr, OPEN_EXISTING,
                                   FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (hTest == INVALID_HANDLE_VALUE) {
            return true;
        }
        CloseHandle(hTest);
    }

    // Also check CLSID for backward compatibility
    if (SecureFolder::Utils::IsCLSIDFolder(path)) {
        return true;
    }

    return false;
}

// ==================== DLL Exports ====================

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (ppv == nullptr) return E_POINTER;

    if (rclsid == CLSID_SecureFolderShellExt) {
        CSecureFolderShellExt* pExt = new CSecureFolderShellExt();
        if (pExt == nullptr) return E_OUTOFMEMORY;

        HRESULT hr = pExt->QueryInterface(riid, ppv);
        pExt->Release();
        return hr;
    }

    return CLASS_E_CLASSNOTAVAILABLE;
}

STDAPI DllCanUnloadNow() {
    return S_OK;
}

STDAPI DllRegisterServer() {
    wchar_t szModulePath[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, szModulePath, MAX_PATH);

    wchar_t szKey[MAX_PATH] = {0};
    wsprintfW(szKey, L"CLSID\\%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
              CLSID_SecureFolderShellExt.Data1, CLSID_SecureFolderShellExt.Data2,
              CLSID_SecureFolderShellExt.Data3,
              CLSID_SecureFolderShellExt.Data4[0], CLSID_SecureFolderShellExt.Data4[1],
              CLSID_SecureFolderShellExt.Data4[2], CLSID_SecureFolderShellExt.Data4[3],
              CLSID_SecureFolderShellExt.Data4[4], CLSID_SecureFolderShellExt.Data4[5],
              CLSID_SecureFolderShellExt.Data4[6], CLSID_SecureFolderShellExt.Data4[7]);

    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, szKey, 0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, nullptr, 0, REG_SZ, (BYTE*)L"SecureFolder Shell Extension", sizeof(wchar_t) * 28);
        RegCloseKey(hKey);

        wchar_t szSubKey[MAX_PATH + 20] = {0};
        wsprintfW(szSubKey, L"%s\\InprocServer32", szKey);

        if (RegCreateKeyExW(HKEY_CLASSES_ROOT, szSubKey, 0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, nullptr, 0, REG_SZ, (BYTE*)szModulePath, sizeof(wchar_t) * wcslen(szModulePath));
            RegSetValueExW(hKey, L"ThreadingModel", 0, REG_SZ, (BYTE*)L"Apartment", sizeof(wchar_t) * 10);
            RegCloseKey(hKey);
        }
    }

    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, L"Folder\\shellex\\ContextMenuHandlers\\SecureFolder", 0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
        wchar_t szClsid[64] = {0};
        wsprintfW(szClsid, L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                  CLSID_SecureFolderShellExt.Data1, CLSID_SecureFolderShellExt.Data2,
                  CLSID_SecureFolderShellExt.Data3,
                  CLSID_SecureFolderShellExt.Data4[0], CLSID_SecureFolderShellExt.Data4[1],
                  CLSID_SecureFolderShellExt.Data4[2], CLSID_SecureFolderShellExt.Data4[3],
                  CLSID_SecureFolderShellExt.Data4[4], CLSID_SecureFolderShellExt.Data4[5],
                  CLSID_SecureFolderShellExt.Data4[6], CLSID_SecureFolderShellExt.Data4[7]);
        RegSetValueExW(hKey, nullptr, 0, REG_SZ, (BYTE*)szClsid, sizeof(wchar_t) * wcslen(szClsid));
        RegCloseKey(hKey);
    }

    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, L"Directory\\shellex\\ContextMenuHandlers\\SecureFolder", 0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
        wchar_t szClsid[64] = {0};
        wsprintfW(szClsid, L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                  CLSID_SecureFolderShellExt.Data1, CLSID_SecureFolderShellExt.Data2,
                  CLSID_SecureFolderShellExt.Data3,
                  CLSID_SecureFolderShellExt.Data4[0], CLSID_SecureFolderShellExt.Data4[1],
                  CLSID_SecureFolderShellExt.Data4[2], CLSID_SecureFolderShellExt.Data4[3],
                  CLSID_SecureFolderShellExt.Data4[4], CLSID_SecureFolderShellExt.Data4[5],
                  CLSID_SecureFolderShellExt.Data4[6], CLSID_SecureFolderShellExt.Data4[7]);
        RegSetValueExW(hKey, nullptr, 0, REG_SZ, (BYTE*)szClsid, sizeof(wchar_t) * wcslen(szClsid));
        RegCloseKey(hKey);
    }

    // Register for .securefolder package files (new format)
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, L"SecureFolder.LockedFolder\\shellex\\ContextMenuHandlers\\SecureFolder", 0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
        wchar_t szClsid[64] = {0};
        wsprintfW(szClsid, L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                  CLSID_SecureFolderShellExt.Data1, CLSID_SecureFolderShellExt.Data2,
                  CLSID_SecureFolderShellExt.Data3,
                  CLSID_SecureFolderShellExt.Data4[0], CLSID_SecureFolderShellExt.Data4[1],
                  CLSID_SecureFolderShellExt.Data4[2], CLSID_SecureFolderShellExt.Data4[3],
                  CLSID_SecureFolderShellExt.Data4[4], CLSID_SecureFolderShellExt.Data4[5],
                  CLSID_SecureFolderShellExt.Data4[6], CLSID_SecureFolderShellExt.Data4[7]);
        RegSetValueExW(hKey, nullptr, 0, REG_SZ, (BYTE*)szClsid, sizeof(wchar_t) * wcslen(szClsid));
        RegCloseKey(hKey);
    }

    MessageBoxW(nullptr, L"Shell extension registered!\nRight-click encrypted folder to see unlock options.", L"Success", MB_ICONINFORMATION);

    return S_OK;
}

STDAPI DllUnregisterServer() {
    wchar_t szKey[MAX_PATH] = {0};

    wsprintfW(szKey, L"CLSID\\%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
              CLSID_SecureFolderShellExt.Data1, CLSID_SecureFolderShellExt.Data2,
              CLSID_SecureFolderShellExt.Data3,
              CLSID_SecureFolderShellExt.Data4[0], CLSID_SecureFolderShellExt.Data4[1],
              CLSID_SecureFolderShellExt.Data4[2], CLSID_SecureFolderShellExt.Data4[3],
              CLSID_SecureFolderShellExt.Data4[4], CLSID_SecureFolderShellExt.Data4[5],
              CLSID_SecureFolderShellExt.Data4[6], CLSID_SecureFolderShellExt.Data4[7]);

    RegDeleteTreeW(HKEY_CLASSES_ROOT, szKey);

    RegDeleteTreeW(HKEY_CLASSES_ROOT, L"Folder\\shellex\\ContextMenuHandlers\\SecureFolder");
    RegDeleteTreeW(HKEY_CLASSES_ROOT, L"Directory\\shellex\\ContextMenuHandlers\\SecureFolder");
    RegDeleteTreeW(HKEY_CLASSES_ROOT, L"SecureFolder.LockedFolder\\shellex\\ContextMenuHandlers\\SecureFolder");

    MessageBoxW(nullptr, L"Shell extension unregistered!", L"Success", MB_ICONINFORMATION);

    return S_OK;
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            SecureFolder::InitGUI(hModule);
            break;

        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}