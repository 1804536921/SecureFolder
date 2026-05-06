# SecureFolder 技术设计方案

## 一、需求概述

### 核心需求
- 平台：Windows 系统
- 功能：选择文件夹 → 加密保护 → 双击触发密码验证 → 密码解锁
- 设计理念：类似 .zip 文件，通过后缀标识加密状态

### 实现方案
采用 `.securefolder` 后缀标识方案，结合 AES-256-GCM 文件加密：
- 加密文件夹可见，通过后缀 `.securefolder` 标识
- 双击触发密码验证（通过注册表文件类型关联）
- 内部文件使用 AES-256-GCM 加密，添加 `.encf` 扩展名

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
| SecureFolderManager | 加密流程管理、状态检测 | 文件系统操作 |
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
4. 重命名文件夹：D:\Secret → D:\Secret.securefolder
5. 遍历文件夹，加密每个文件：
   - filename.xlsx → filename.xlsx.encf
6. 创建索引文件（记录原始文件信息）
7. 创建锁文件（存储盐值、密码验证哈希）
8. 安全擦除原文件（可选）

解密流程：
1. 用户双击 D:\Secret.securefolder
2. 弹出密码输入对话框
3. 读取锁文件，获取盐值
4. 密码 + 盐值 → PBKDF2 → AES-256 密钥
5. 验证密码哈希
6. 读取索引文件，获取文件列表
7. 解密每个文件：
   - filename.xlsx.encf → filename.xlsx
8. 重命名文件夹：D:\Secret.securefolder → D:\Secret
9. 删除锁文件和索引文件
```

### 3.2 密钥派生方案

```
用户密码 → PBKDF2-HMAC-SHA256 → 256位加密密钥

参数：
- 算法：PBKDF2-HMAC-SHA256
- 盐值(Salt)：随机生成 32 字节，存储于锁文件
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

### 3.4 加密文件格式

每个加密文件 (`.encf`) 采用以下格式：

```
┌─────────────────────────────────────────┐
│  文件头 (EncryptedFileHeader)           │
│  ┌─────────────┬────────────┬──────────┐ │
│  │ Magic       │ Version    │ Flags    │ │
│  │ "ENCF"      │ 1          │ 0        │ │
│  │ (4 bytes)   │ (4 bytes)  │ (4 bytes)│ │
│  ├─────────────┴────────────┴──────────┤ │
│  │ OriginalSize (8 bytes)              │ │
│  │ OriginalNameLen (4 bytes)           │ │
│  │ OriginalName (UTF-8, variable)      │ │
│  └─────────────────────────────────────┘ │
├─────────────────────────────────────────┤
│  IV (12 bytes for GCM)                   │
├─────────────────────────────────────────┤
│  密文 (Ciphertext)                       │
├─────────────────────────────────────────┤
│  AuthTag (16 bytes)                      │
└─────────────────────────────────────────┘

总大小 = 原始文件大小 + 28 + nameLen + 12 + 16
```

### 3.5 锁文件格式

锁文件 `.securelock` 存储加密元数据：

```
┌─────────────────────────────────────────┐
│  Magic: 0x534C434B ("SCLK") (4 bytes)   │
│  Version: 1 (4 bytes)                    │
│  LockMode: 0/1/2 (4 bytes)               │
│  SaltLength: 32 (4 bytes)                │
│  Salt: 32 bytes                          │
│  HashLength: 32 (4 bytes)                │
│  PasswordVerifyHash: 32 bytes            │
│  OriginalNameLength: N (4 bytes)         │
│  OriginalName: UTF-8 bytes               │
└─────────────────────────────────────────┘

密码验证哈希 = SHA256(AES密钥)
用于快速验证密码正确性，不存储密码明文
```

### 3.6 索引文件格式

索引文件 `.securelock.idx` 记录加密文件列表：

```
┌─────────────────────────────────────────┐
│  Magic: 0x494E4458 ("INDX") (4 bytes)   │
│  Version: 1 (4 bytes)                    │
│  IVLength: 12 (4 bytes)                  │
│  IV: 12 bytes                            │
│  CipherLength: N (4 bytes)               │
│  CipherData: N bytes (加密的索引数据)    │
│  TagLength: 16 (4 bytes)                 │
│  AuthTag: 16 bytes                       │
└─────────────────────────────────────────┘

解密后的索引数据格式：
relativePath|fileSize
relativePath|fileSize
...

例：
file1.xlsx|12345
subdir/file2.doc|67890
```

---

## 四、文件类型关联设计

### 4.1 注册表配置

通过注册表关联 `.securefolder` 后缀：

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

| 模式 | 后缀 | 加密 | 伪装 | 安全性 | 速度 |
|------|------|------|------|--------|------|
| FullEncrypt | .securefolder | AES-256-GCM | 无 | 最高 | 较慢 |
| QuickLock | .{CLSID} | 无 | CLSID | 较低 | 极快 |
| CryptoOnly | 无 | AES-256-GCM | 无 | 高 | 较慢 |

### 5.2 模式选择建议

- **日常使用**：推荐 `FullEncrypt`，兼顾安全性和易用性
- **快速保护**：`QuickLock` 适合临时隐藏，防普通用户
- **专业加密**：`CryptoOnly` 仅加密文件，不改变文件夹外观

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

### 6.2 安全擦除实现

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

### 6.3 文件遍历与相对路径

使用 `std::filesystem` 遍历文件：

```cpp
std::vector<FileInfo> GetAllFiles(const std::wstring& folderPath) {
    std::vector<FileInfo> files;
    std::filesystem::path root(folderPath);
    
    for (auto& entry : std::filesystem::recursive_directory_iterator(root)) {
        if (!entry.is_directory()) {
            FileInfo info;
            info.path = entry.path().wstring();
            // 使用 lexically_relative 获取相对于 folderPath 的路径
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
class ShellExtension : public IContextMenu, public IShellExtInit {
public:
    // IShellExtInit - 初始化
    STDMETHODIMP Initialize(LPCITEMIDLIST pidlFolder, IDataObject* pDataObj, HKEY hKeyProgID);
    
    // IContextMenu - 添加菜单项
    STDMETHODIMP QueryContextMenu(HMENU hMenu, UINT indexMenu, 
                                   UINT idCmdFirst, UINT idCmdLast, UINT uFlags);
    
    // IContextMenu - 执行命令
    STDMETHODIMP InvokeCommand(LPCMINVOKECOMMANDINFO pCmdInfo);
    
    // IContextMenu - 获取命令帮助
    STDMETHODIMP GetCommandString(UINT_PTR idCmd, UINT uFlags,
                                  UINT* pwReserved, LPSTR pszName, UINT cchMax);
};
```

### 7.2 菜单项注册

```cpp
STDMETHODIMP ShellExtension::QueryContextMenu(...) {
    // 添加加密菜单项
    InsertMenuW(hMenu, indexMenu++, MF_STRING, idCmdFirst++, L"Lock with SecureFolder");
    
    // 添加解密菜单项（仅加密文件夹显示）
    if (IsLockedFolder(m_selectedPath)) {
        InsertMenuW(hMenu, indexMenu++, MF_STRING, idCmdFirst++, L"Unlock with SecureFolder");
    }
    
    return MAKE_HRESULT(SEVERITY_SUCCESS, 0, idCmdFirst - idCmdFirst);
}
```

---

## 八、安全设计

### 8.1 密码安全

- 密码不存储明文，仅存储验证哈希
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
# CMakeLists.txt
cmake_minimum_required(VERSION 3.15)
project(SecureFolder VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 主程序
add_executable(SecureFolder
    src/main.cpp
    src/Core/CryptoEngine.cpp
    src/Core/SecureFolderManager.cpp
    src/Core/FolderDisguise.cpp
    src/Core/SecureDelete.cpp
    src/UI/GUIDialog.cpp
)

# Shell 扩展 DLL
add_library(SecureFolderShellExt SHARED
    src/ShellExt/ShellExtension.cpp
    src/Core/CryptoEngine.cpp
    src/UI/GUIDialog.cpp
)

# 链接库
target_link_libraries(SecureFolder bcrypt.lib user32.lib gdi32.lib shell32.lib ole32.lib)
target_link_libraries(SecureFolderShellExt bcrypt.lib user32.lib shell32.lib ole32.lib)
```

### 9.2 安装流程

1. 编译项目：`build.bat`
2. 复制文件到 `C:\Program Files\SecureFolder`
3. 注册 DLL：`regsvr32 SecureFolderShellExt.dll`
4. 注册文件类型关联（需管理员权限）
5. 创建桌面快捷方式

---

## 十、总结

### 设计特点

1. **类似 .zip 的用户体验**：通过后缀标识加密状态，双击触发解锁
2. **AES-256-GCM 加密**：专业级安全，支持认证加密
3. **PBKDF2 密钥派生**：抗暴力破解
4. **无需隐藏文件夹**：加密文件夹可见，通过后缀识别
5. **完整的 Shell 集成**：右键菜单、双击解锁

### 技术选型

- 加密库：Windows CNG (bcrypt) - 无需额外依赖
- 文件操作：std::filesystem (C++17)
- GUI：Win32 API - 轻量级
- Shell 扩展：COM/IShellExt - 系统原生

### 开发周期

- 核心加密模块：2周
- Shell 扩展：1周
- 用户界面：1周
- 测试与优化：1周
- **总计：约5周**

---

*文档版本：v3.0*
*适用版本：SecureFolder 1.0.0*
*更新日期：2026年5月6日*