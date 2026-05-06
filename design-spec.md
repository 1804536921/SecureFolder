# SecureFolder 技术设计方案

## 一、需求概述

### 核心需求
- 平台：Windows 系统
- 功能：选择文件夹 → 加密保护 → 双击触发密码验证 → 密码解锁
- 设计理念：类似 .zip 文件，通过扩展名标识加密状态

### 实现方案
采用 `.securefolder` 单文件打包方案，结合 AES-256-GCM 加密：
- 加密文件夹打包成单个 `.securefolder` **文件**（类似 .zip）
- 双击触发密码验证（通过注册表文件类型关联）
- Windows 注册表文件关联只对**文件**生效，不对文件夹生效
- 内部文件使用 AES-256-GCM 加密

---

## 二、系统架构

### 2.1 项目结构

```
SecureFolder/
├── CMakeLists.txt              # CMake 构建配置
├── build.bat                   # 编译脚本
├── install.bat                 # 安装脚本（注册DLL、注册表）
├── uninstall.bat               # 卸载脚本
├── src/
│   ├── Core/
│   │   ├── CryptoEngine.cpp    # AES-GCM 加密引擎
│   │   ├── CryptoEngine.h      # 加密引擎头文件
│   │   ├── SecureFolderManager.cpp  # 主管理器
│   │   ├── SecureFolderManager.h    # 管理器头文件
│   │   ├── FolderDisguise.cpp  # CLSID 伪装模块
│   │   ├── FolderDisguise.h    # 伪装模块头文件
│   │   ├── SecureDelete.cpp    # 安全擦除模块
│   │   └── SecureDelete.h      # 安全擦除头文件
│   ├── Common/
│   │   ├── Types.h             # 类型定义和常量
│   │   ├── Utils.h             # 工具函数
│   │   └── Logger.h            # 日志模块
│   ├── UI/
│   │   ├── GUIDialog.cpp       # 密码对话框 GUI
│   │   ├── GUIDialog.h         # GUI 头文件
│   │   └── MainWindow.cpp      # 主窗口
│   ├── ShellExt/
│   │   ├── ShellExtension.cpp  # 右键菜单扩展
│   │   └── ShellExtension.h    # Shell 扩展头文件
│   └── main.cpp                # 主入口
├── USER_GUIDE.md               # 用户指南
└── design-spec.md              # 技术设计文档
```

### 2.2 模块职责

| 模块 | 职责 | 关键技术 |
|------|------|----------|
| CryptoEngine | AES-GCM 加密/解密、PBKDF2 密钥派生 | Windows CNG (bcrypt) |
| SecureFolderManager | 加密流程管理、单文件打包 | 文件系统操作 |
| FolderDisguise | CLSID 伪装（可选） | 文件重命名 |
| SecureDelete | 安全擦除原文件 | 多次覆写+删除 |
| ShellExtension | 右键菜单集成 | COM/Shell 扩展 |
| GUIDialog | 密码输入界面 | Win32 GUI |

---

## 三、加密方案详细设计

### 3.1 文件夹加密流程

```
加密流程：
1. 用户选择文件夹 D:\Secret
2. 生成随机盐值 (32字节)
3. 用户密码 + 盐值 → PBKDF2 → AES-256 密钥
4. 遍历文件夹，获取所有文件信息
5. 构建加密索引（文件列表）
6. 逐文件分块加密（1MB/chunk）
7. 打包成单文件 D:\Secret.securefolder
8. 安全擦除原文件夹
```

解密流程：
```
1. 用户双击 D:\Secret.securefolder
2. Windows 查询注册表 → 启动 SecureFolder.exe unlock-gui
3. 弹出密码输入对话框
4. 读取包文件头，获取盐值
5. 密码 + 盐值 → PBKDF2 → AES-256 密钥
6. 验证密码哈希
7. 解密索引，获取文件列表
8. 逐文件解密恢复
9. 生成 D:\Secret\ 文件夹
10. 删除 .securefolder 文件
```

### 3.2 密钥派生方案

```
用户密码 → PBKDF2-HMAC-SHA256 → 256位加密密钥

参数：
- 算法：PBKDF2-HMAC-SHA256
- 盐值(Salt)：随机生成 32 字节，存储于包文件头
- 迭代次数：100,000 次（可配置，抗暴力破解）
- 输出长度：32 字节（AES-256）
```

**核心代码：**
```cpp
bool CryptoEngine::DeriveKeyFromPassword(
    const std::wstring& password,
    const std::vector<uint8_t>& salt,
    std::vector<uint8_t>& outKey,
    int iterations
) {
    // Convert password to UTF-8
    std::string pwd = Utils::WideToUtf8(password);
    
    // PBKDF2 using BCrypt
    NTSTATUS status = BCryptDeriveKeyPBKDF2(
        m_hShaAlg,                    // HMAC-SHA256 algorithm
        (PUCHAR)pwd.data(), pwd.size(), // Password
        salt.data(), salt.size(),      // Salt
        iterations,                    // Iterations
        outKey.data(), outKey.size(),  // Output key
        0
    );
    
    return status == 0;
}
```

### 3.3 AES-GCM 加密方案

采用 AES-256-GCM 认证加密模式：
- 密钥：256位（由 PBKDF2 派生）
- IV：12字节（GCM推荐长度，每次加密随机生成）
- AuthTag：16字节（用于验证密文完整性）

**加密过程：**
```cpp
bool CryptoEngine::Encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    std::vector<uint8_t>& ciphertext,
    std::vector<uint8_t>& authTag
) {
    // Set GCM chaining mode
    BCryptSetProperty(m_hAesAlg, BCRYPT_CHAINING_MODE, 
                      BCRYPT_CHAIN_MODE_GCM);
    
    // Create key handle
    BCRYPT_KEY_HANDLE hKey;
    CreateAesKey(hKey, key);
    
    // Prepare GCM auth info
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = iv.data();
    authInfo.cbNonce = iv.size();
    authInfo.pbTag = authTag.data();
    authInfo.cbTag = AES_TAG_SIZE;  // 16 bytes
    
    // Encrypt
    BCryptEncrypt(hKey, plaintext.data(), plaintext.size(),
                  &authInfo, nullptr, 0,
                  ciphertext.data(), ciphertext.size(),
                  &cbResult, 0);
    
    BCryptDestroyKey(hKey);
    return true;
}
```

### 3.4 包文件格式

加密后的 `.securefolder` 文件结构：

```
┌────────────────────────────────────────────────────────────────────────────┐
│  文件头 SecurePackageHeader (未加密)                                       │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │ Magic: "SFPK" (4 bytes)                                                ││
│  │ Version: 1 (4 bytes)                                                   ││
│  │ Flags: 0 (4 bytes)                                                     ││
│  │ OriginalFolderNameLen: N (4 bytes)                                     ││
│  │ OriginalFolderName: UTF-8 string (N bytes)                             ││
│  │ OriginalFileCount: M (4 bytes)                                         ││
│  │ SaltLength: 32 (4 bytes)                                               ││
│  │ Salt: 32 bytes                                                         ││
│  │ PasswordVerifyHashLength: 32 (4 bytes)                                 ││
│  │ PasswordVerifyHash: SHA256(key) (32 bytes)                             ││
│  │ IndexIVLength: 12 (4 bytes)                                            ││
│  │ IndexIV: 12 bytes                                                      ││
│  │ IndexCipherLength: X (4 bytes)                                         ││
│  │ IndexAuthTagLength: 16 (4 bytes)                                       ││
│  └────────────────────────────────────────────────────────────────────────┘│
├────────────────────────────────────────────────────────────────────────────┤
│  加密索引数据 (X bytes)                                                     │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │ IndexCipherData (加密的文件列表)                                        ││
│  │ IndexAuthTag (16 bytes)                                                ││
│  └────────────────────────────────────────────────────────────────────────┘│
├────────────────────────────────────────────────────────────────────────────┤
│  文件数据区 (每个文件)                                                       │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │ FileEntryHeader:                                                        ││
│  │   RelativePathLength: P (4 bytes)                                       ││
│  │   RelativePath: UTF-8 string (P bytes)                                  ││
│  │   OriginalSize: 8 bytes                                                 ││
│  │   [Chunk 数据 (重复)]                                                    ││
│  │     ChunkIV: 12 bytes                                                   ││
│  │     ChunkCipherLength: C (4 bytes)                                      ││
│  │     ChunkCipherData: C bytes                                            ││
│  │     ChunkAuthTag: 16 bytes                                              ││
│  │   ChunkCount: 4 bytes (文件完整性校验)                                  ││
│  └────────────────────────────────────────────────────────────────────────┘│
└────────────────────────────────────────────────────────────────────────────┘
```

### 3.5 索引文件格式

解密后的索引数据格式：
```
relativePath|fileSize|isDirectory
relativePath|fileSize|isDirectory
...

例：
docs/report.docx|45678|0
images/photo.jpg|2345678|0
subdir|0|1
```

---

## 四、文件类型关联设计

### 4.1 注册表配置

通过注册表关联 `.securefolder` 文件扩展名：

```batch
# 注册 .securefolder 扩展名
reg add "HKCR\.securefolder" /ve /d "SecureFolder.LockedFolder" /f

# 注册文件类型
reg add "HKCR\SecureFolder.LockedFolder" /ve /d "SecureFolder Locked Folder" /f
reg add "HKCR\SecureFolder.LockedFolder\DefaultIcon" /ve /d "\"%EXE_PATH%\",0" /f

# 双击打开动作
reg add "HKCR\SecureFolder.LockedFolder\shell" /ve /d "open" /f
reg add "HKCR\SecureFolder.LockedFolder\shell\open" /ve /d "Unlock" /f
reg add "HKCR\SecureFolder.LockedFolder\shell\open\command" /ve /d "\"%EXE_PATH%\" unlock-gui \"%%1\"" /f

# 右键菜单项
reg add "HKCR\SecureFolder.LockedFolder\shell\unlock" /ve /d "Unlock with SecureFolder" /f
reg add "HKCR\SecureFolder.LockedFolder\shell\unlock\command" /ve /d "\"%EXE_PATH%\" unlock-gui \"%%1\"" /f

# 普通文件夹右键菜单
reg add "HKCR\Folder\shell\SecureFolderEncrypt" /ve /d "Lock with SecureFolder" /f
reg add "HKCR\Folder\shell\SecureFolderEncrypt\command" /ve /d "\"%EXE_PATH%\" lock-gui \"%%1\"" /f
```

**关键点**：`.securefolder` 必须是**真正的文件**（不是文件夹），注册表文件关联才能生效。

### 4.2 双击触发流程

```
用户双击 D:\Secret.securefolder
    ↓
Windows 查询注册表 HKCR\.securefolder
    ↓
找到关联类型 SecureFolder.LockedFolder
    ↓
执行 open\command: SecureFolder.exe unlock-gui "D:\Secret.securefolder"
    ↓
程序弹出密码对话框
    ↓
密码验证成功 → 解密 → 打开 D:\Secret\
```

---

## 五、三种加密模式

### 5.1 模式对比

| 模式 | 后缀 | 加密 | 打包 | 安全性 | 速度 |
|------|------|------|------|--------|------|
| FullEncrypt | .securefolder | AES-256-GCM | 单文件 | 最高 | 较慢 |
| QuickLock | .{CLSID} | 无 | 无 | 较低 | 极快 |
| CryptoOnly | 无 | AES-256-GCM | 无 | 高 | 较慢 |

### 5.2 模式选择建议

- **日常使用**：推荐 `FullEncrypt`，兼顾安全性和双击解锁体验
- **快速保护**：`QuickLock` 适合临时隐藏，防普通用户
- **专业加密**：`CryptoOnly` 仅加密文件，不打包

---

## 六、核心技术实现

### 6.1 Windows CNG 加密 API

使用 Windows CryptoAPI Next Gen (CNG)：

```cpp
// 初始化算法
BCryptOpenAlgorithmProvider(&m_hAesAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
BCryptOpenAlgorithmProvider(&m_hShaAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);

// 设置 GCM 模式
BCryptSetProperty(m_hAesAlg, BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_GCM);

// 生成随机数
BCryptGenRandom(nullptr, buffer, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
```

### 6.2 流式加密实现

分块加密，避免内存爆炸：

```cpp
// 每块 1MB
const uint32_t CHUNK_SIZE = 1024 * 1024;

while (remaining > 0) {
    uint32_t readSize = min(CHUNK_SIZE, remaining);
    
    // 读取块
    ReadFile(hInput, buffer.data(), readSize, &bytesRead);
    
    // 生成块 IV
    GenerateIV(chunkIV);
    
    // 加密块
    Encrypt(buffer, key, chunkIV, cipherBuffer, authTag);
    
    // 写入: IV + cipherLen + cipherData + tag
    WriteFile(hOutput, chunkIV.data(), AES_IV_SIZE);
    WriteFile(hOutput, &cipherLen, sizeof(cipherLen));
    WriteFile(hOutput, cipherBuffer.data(), cipherLen);
    WriteFile(hOutput, authTag.data(), AES_TAG_SIZE);
    
    remaining -= bytesRead;
}
```

### 6.3 安全擦除实现

```cpp
bool SecureDelete::DeleteFileSecure(const std::wstring& path) {
    // 1. 获取文件大小
    uint64_t fileSize = Utils::GetFileSize(path);
    
    // 2. 覆写随机数据 3 次
    for (int i = 0; i < 3; i++) {
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, ...);
        std::vector<uint8_t> randomData(fileSize);
        BCryptGenRandom(nullptr, randomData.data(), fileSize, ...);
        WriteFile(hFile, randomData.data(), fileSize, ...);
        FlushFileBuffers(hFile);
        CloseHandle(hFile);
    }
    
    // 3. 重命名为随机名称
    std::wstring tempName = path + L"." + Utils::GenerateRandomString(8);
    MoveFileW(path.c_str(), tempName.c_str());
    
    // 4. 删除文件
    DeleteFileW(tempName.c_str());
    
    return true;
}
```

### 6.4 文件遍历与相对路径

使用 `std::filesystem` 遍历文件：

```cpp
std::vector<FileInfo> GetAllFiles(const std::wstring& folderPath) {
    std::vector<FileInfo> files;
    std::filesystem::path root(folderPath);
    
    for (auto& entry : std::filesystem::recursive_directory_iterator(root)) {
        if (!entry.is_directory()) {
            FileInfo info;
            info.path = entry.path().wstring();
            info.relativePath = entry.path().lexically_relative(root).wstring();
            info.size = entry.file_size();
            files.push_back(info);
        }
    }
    return files;
}
```

---

## 七、Shell 扩展设计

### 7.1 COM 接口实现

右键菜单通过 Shell 扩展 DLL 实现：

```cpp
class CSecureFolderShellExt : public IContextMenu, public IShellExtInit {
public:
    // IShellExtInit - 初始化
    STDMETHODIMP Initialize(LPCITEMIDLIST pidlFolder, IDataObject* pDataObj, HKEY hKeyProgID);
    
    // IContextMenu - 添加菜单项
    STDMETHODIMP QueryContextMenu(HMENU hMenu, UINT indexMenu, 
                                   UINT idCmdFirst, UINT idCmdLast, UINT uFlags);
    
    // IContextMenu - 执行命令
    STDMETHODIMP InvokeCommand(LPCMINVOKECOMMANDINFO pCmdInfo);
};
```

### 7.2 菜单项逻辑

```cpp
STDMETHODIMP QueryContextMenu(...) {
    UINT idCmd = idCmdFirst;
    
    if (m_isEncryptedFolder) {
        // 加密文件：显示解锁选项
        InsertMenuW(hMenu, indexMenu, MF_BYPOSITION, idCmd++, L"Unlock with SecureFolder");
        InsertMenuW(hMenu, indexMenu + 1, MF_BYPOSITION, idCmd++, L"Unlock and Open Folder");
    } else {
        // 普通文件夹：显示加密选项
        DWORD attr = GetFileAttributesW(m_folderPath.c_str());
        if (attr & FILE_ATTRIBUTE_DIRECTORY) {
            InsertMenuW(hMenu, indexMenu, MF_BYPOSITION, idCmd++, L"Lock with SecureFolder");
        }
    }
    
    return MAKE_HRESULT(SEVERITY_SUCCESS, 0, idCmd - idCmdFirst);
}
```

---

## 八、安全设计

### 8.1 密码安全

- 密码不存储明文，仅存储 SHA256(key) 验证哈希
- 使用 PBKDF2，迭代次数 ≥ 100,000
- 每次加密使用不同的随机盐值
- 密码错误增加延迟（可选）

### 8.2 内存安全

```cpp
void CryptoEngine::SecureClear(std::vector<uint8_t>& data) {
    if (!data.empty()) {
        SecureZeroMemory(data.data(), data.size());
        data.clear();
    }
}
```

### 8.3 数据保护

- 加密前备份文件索引
- 支持加密中断恢复（通过索引文件）
- 错误处理不暴露敏感信息
- 日志不记录密码和密钥

---

## 九、编译与部署

### 9.1 编译配置

```cmake
cmake_minimum_required(VERSION 3.15)
project(SecureFolder VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)

# 主程序
add_executable(SecureFolder
    src/main.cpp
    src/Core/CryptoEngine.cpp
    src/Core/SecureFolderManager.cpp
    src/UI/GUIDialog.cpp
)

# Shell 扩展 DLL
add_library(SecureFolderShellExt SHARED
    src/ShellExt/ShellExtension.cpp
    src/Core/CryptoEngine.cpp
    src/UI/GUIDialog.cpp
)

# 链接库
target_link_libraries(SecureFolder bcrypt user32 gdi32 shell32 ole32)
target_link_libraries(SecureFolderShellExt bcrypt user32 shell32 ole32)
```

### 9.2 安装流程

1. 编译项目：`build.bat`
2. 复制文件到 `C:\Program Files\SecureFolder`
3. 注册 DLL：`regsvr32 SecureFolderShellExt.dll`
4. 注册文件类型关联（需管理员权限）
5. 创建桌面快捷方式

---

## 十、关键设计决策

### 10.1 为什么用单文件而不是文件夹？

**问题**：Windows 注册表文件关联只对**文件**生效，不对**文件夹**生效。

如果加密后仍是一个文件夹（即使添加 `.securefolder` 后缀），双击时 Windows 会直接打开文件夹，不会触发注册表中 `.securefolder` 的关联命令。

**解决方案**：将整个文件夹打包成单个 `.securefolder` 文件，类似 `.zip` 的设计。

### 10.2 为什么用 AES-GCM？

- 提供机密性（加密）和完整性（认证）双重保护
- 认证标签确保数据未被篡改
- 无需额外的 HMAC 层

---

## 十一、总结

### 设计特点

1. **类似 .zip 的用户体验**：单文件打包，双击触发解锁
2. **AES-256-GCM 加密**：专业级安全，支持认证加密
3. **PBKDF2 密钥派生**：抗暴力破解
4. **注册表关联正确生效**：`.securefolder` 是真正的文件
5. **完整的 Shell 集成**：右键菜单、双击解锁

### 技术选型

- 加密库：Windows CNG (bcrypt) - 无需额外依赖
- 文件操作：std::filesystem (C++17)
- GUI：Win32 API - 轻量级
- Shell 扩展：COM/IShellExt - 系统原生

---

*文档版本：v4.0*
*适用版本：SecureFolder 1.0.0*
*更新日期：2026年5月6日*