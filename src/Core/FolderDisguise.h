#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <Windows.h>
#include "Types.h"

namespace SecureFolder {

// CLSID伪装锁模块
// 通过修改文件夹名称添加CLSID后缀，使系统将其识别为特殊对象
class FolderDisguise {
public:
    FolderDisguise();

    // 应用CLSID伪装
    Result ApplyDisguise(const std::wstring& folderPath, const std::wstring& clsid);

    // 解除CLSID伪装
    Result RemoveDisguise(const std::wstring& disguisedPath);

    // 检查文件夹是否已伪装
    bool IsDisguised(const std::wstring& folderPath);

    // 获取原始文件夹名（去除CLSID）
    std::wstring GetOriginalName(const std::wstring& disguisedPath);

    // 设置文件夹属性（隐藏+系统）
    Result SetHiddenAttributes(const std::wstring& folderPath);

    // 恢复文件夹属性
    Result RestoreAttributes(const std::wstring& folderPath);

    // 设置NTFS权限（拒绝访问）
    Result SetDenyPermission(const std::wstring& folderPath);

    // 恢复NTFS权限
    Result RestorePermission(const std::wstring& folderPath);

    // 创建锁文件（存储密码验证信息）
    Result CreateLockFile(const std::wstring& folderPath,
                          const std::vector<uint8_t>& passwordHash,
                          const std::vector<uint8_t>& salt);

    // 验证锁文件
    bool VerifyLockFile(const std::wstring& folderPath,
                        const std::vector<uint8_t>& passwordHash);

    // 读取锁文件中的盐值
    bool ReadLockFileSalt(const std::wstring& folderPath,
                          std::vector<uint8_t>& salt);

    // 获取随机CLSID
    std::wstring GetRandomCLSID();

    // 获取上次错误信息
    std::wstring GetLastError() const { return m_lastError; }

private:
    std::wstring m_lastError;
    std::wstring m_originalPath;     // 保存原始路径用于恢复
    DWORD m_originalAttributes;      // 保存原始属性

    // 保存原始安全描述符
    PACL m_originalDacl = nullptr;
    PSECURITY_DESCRIPTOR m_originalSd = nullptr;
};

} // namespace SecureFolder