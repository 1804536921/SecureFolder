#pragma once

#include <string>
#include <cstdint>
#include <Windows.h>

namespace SecureFolder {

// 安全擦除模块
// 多次覆写文件数据后删除，防止数据恢复
class SecureDelete {
public:
    // 安全擦除文件（覆写后删除）
    static bool DeleteFileSecure(const std::wstring& filePath, int overwritePasses = 3);

    // 安全擦除文件夹内所有文件
    static bool DeleteFolderSecure(const std::wstring& folderPath, int overwritePasses = 3);

    // 仅覆写文件内容（不删除）
    static bool OverwriteFile(const std::wstring& filePath, int passes = 3);

    // 获取上次错误
    static std::wstring GetLastError() { return s_lastError; }

private:
    static std::wstring s_lastError;

    static bool OverwriteFileContent(HANDLE hFile, uint64_t fileSize, int passes);
};

} // namespace SecureFolder