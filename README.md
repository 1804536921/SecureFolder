# SecureFolder

一个 Windows 文件夹加密工具，提供 AES-256-GCM 加密保护，支持双击解锁。

## 功能特点

- **类似 .zip 的用户体验**：加密后生成 `.securefolder` 单文件包，双击触发密码验证
- **AES-256-GCM 加密**：专业级认证加密，保护文件机密性和完整性
- **PBKDF2 密钥派生**：100,000 次迭代，抗暴力破解
- **完整的 Shell 集成**：右键菜单加密/解密，双击解锁
- **流式处理**：分块加密大文件，内存占用低

---

## 快速开始

### 安装

```batch
# 1. 编译项目
build.bat

# 2. 安装（需管理员权限）
install.bat
```

安装后：
- 双击 `.securefolder` 文件 → 弹出密码框解锁
- 右键任意文件夹 → "Lock with SecureFolder"
- 右键 `.securefolder` 文件 → "Unlock with SecureFolder"
- 桌面快捷方式 → 打开图形界面

### 使用

**加密文件夹**：
```batch
# 命令行
SecureFolder.exe lock "D:\Secret"

# 或右键文件夹 → Lock with SecureFolder
```

**解密文件**：
```batch
# 命令行
SecureFolder.exe unlock "D:\Secret.securefolder"

# 或双击 .securefolder 文件
```

---

## 加密原理

### 工作流程

```
加密前：D:\Secret\           (普通文件夹)
加密后：D:\Secret.securefolder (单个加密文件包)

双击 D:\Secret.securefolder → 密码验证 → 解密 → 恢复为 D:\Secret\
```

**重要**：加密后的 `.securefolder` 是一个真正的**文件**（不是文件夹），这确保了 Windows 文件关联能正确触发密码对话框。

### 密钥派生

```
用户密码 + 32字节随机盐值
    ↓
PBKDF2-HMAC-SHA256 (100,000 次迭代)
    ↓
256位 AES 密钥
    ↓
AES-256-GCM 加密文件
```

### 包文件格式

加密后的 `.securefolder` 文件结构：

```
┌─────────────────────────────────────────────┐
│  文件头 SecurePackageHeader                  │
│  Magic: "SFPK"                               │
│  Version: 1                                  │
│  OriginalFolderName                          │
│  Salt (32 bytes)                             │
│  PasswordVerifyHash (SHA256 of key)          │
│  EncryptedIndex (加密的文件列表)             │
├─────────────────────────────────────────────┤
│  文件数据区                                   │
│  [FileEntry: Path + Size + Chunks]           │
│  Chunk: IV(12) + CipherData + AuthTag(16)    │
└─────────────────────────────────────────────┘
```

### 加密索引格式

解密后的索引内容：
```
relativePath|fileSize|isDirectory
docs/report.docx|45678|0
images/photo.jpg|2345678|0
```

---

## 命令行使用

### 基本命令

```batch
SecureFolder.exe lock "D:\Secret"           # 加密文件夹
SecureFolder.exe unlock "D:\Secret.securefolder"  # 解密
SecureFolder.exe status "D:\Secret.securefolder"  # 查看状态
SecureFolder.exe scan "D:\"                 # 扫描加密文件
SecureFolder.exe gui                        # 打开图形界面
SecureFolder.exe help                       # 显示帮助
```

### 参数选项

| 参数 | 说明 |
|------|------|
| `-m <mode>` | 加密模式：quick/full/crypto |
| `-p <password>` | 指定密码 |
| `-i <count>` | PBKDF2 迭代次数（默认 100,000） |
| `-n` | 不安全删除原文件 |

---

## 三种加密模式

| 模式 | 说明 | 安全性 | 速度 |
|------|------|--------|------|
| **完整加密 (FullEncrypt)** | AES 加密 + 单文件打包 | 最高 | 较慢 |
| **快速伪装 (QuickLock)** | 仅 CLSID 伪装 | 较低 | 极快 |
| **仅加密 (CryptoOnly)** | 仅 AES 加密文件 | 高 | 较慢 |

**推荐使用"完整加密"模式。**

---

## 技术架构

### 项目结构

```
SecureFolder/
├── CMakeLists.txt              # CMake 构建配置
├── build.bat                   # 编译脚本
├── install.bat                 # 安装脚本
├── uninstall.bat               # 卸载脚本
├── src/
│   ├── Core/
│   │   ├── CryptoEngine.cpp    # AES-GCM 加密引擎
│   │   ├── SecureFolderManager.cpp  # 主管理器
│   │   ├── FolderDisguise.cpp  # CLSID 伪装模块
│   │   └── SecureDelete.cpp    # 安全擦除模块
│   ├── Common/
│   │   ├── Types.h             # 类型定义
│   │   └ Utils.h               # 工具函数
│   ├── UI/
│   │   ├── GUIDialog.cpp       # 密码对话框
│   │   └ MainWindow.cpp       # 主窗口
│   ├── ShellExt/
│   │   ├── ShellExtension.cpp  # 右键菜单扩展
│   └── main.cpp                # 主入口
└── design-spec.md              # 技术设计文档
```

### 模块职责

| 模块 | 职责 | 关键技术 |
|------|------|----------|
| CryptoEngine | AES-GCM 加密/解密、PBKDF2 | Windows CNG (bcrypt) |
| SecureFolderManager | 加密流程管理、单文件打包 | 文件系统操作 |
| FolderDisguise | CLSID 伪装 | 文件重命名 |
| SecureDelete | 安全擦除原文件 | 多次覆写+删除 |
| ShellExtension | 右键菜单集成 | COM/Shell 扩展 |
| GUIDialog | 密码输入界面 | Win32 GUI |

### 核心技术

**加密 API**：Windows CNG (bcrypt)
```cpp
BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM);
BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_GCM);
BCryptDeriveKeyPBKDF2(...);  // PBKDF2 密钥派生
BCryptEncrypt/Decrypt(...);  // AES-GCM 加解密
```

**流式处理**：分块加密（1MB/chunk），支持大文件

**安全擦除**：
```cpp
// 覆写随机数据 3 次 → 重命名 → 删除
SecureZeroMemory(data, size);
```

---

## 安全设计

- 密码不存储明文，仅存储 SHA256(key) 验证哈希
- PBKDF2 迭代 ≥ 100,000 次，抗暴力破解
- 每次加密使用不同的随机盐值
- AES-GCM 提供机密性和完整性保护
- 内存安全清除（SecureZeroMemory）
- 日志不记录密码和密钥

---

## 编译要求

- Visual Studio 2022（C++ 桌面开发）
- CMake 3.15+
- Windows 10+

---

## 常见问题

### Q: 双击加密文件没有弹出密码窗口？

1. 确认已以管理员身份运行 `install.bat`
2. 重启资源管理器（或重启电脑）
3. 检查 `.securefolder` 文件类型是否已注册

### Q: 密码忘记了怎么办？

**警告：密码无法恢复！文件将永久无法解密。**

建议：牢记密码，或加密前保留备份。

### Q: 加密后文件夹是什么样的？

- 生成 `.securefolder` **文件**（不是文件夹）
- 文件可见，不隐藏
- 双击触发密码验证

### Q: 旧版本加密的文件夹能解密吗？

旧版本（文件夹+锁文件格式）仍支持解密，但建议重新加密以使用新格式。

---

## 安全建议

1. **密码强度**：至少 8 位，包含大小写、数字、符号
2. **密码备份**：牢记密码，丢失无法恢复
3. **重要文件**：加密前保留备份
4. **共享文件**：不要将密码与加密文件一起存储

---

## 许可证

MIT License

---

*版本: 1.0.0*
*更新日期: 2026年5月6日*