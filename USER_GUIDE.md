# SecureFolder 使用指南

## 一、快速开始

### 1.1 一键安装（推荐）

**步骤：**
```
1. 双击运行 build.bat 编译程序
2. 右键 install.bat → 以管理员身份运行
3. 重启资源管理器（脚本会提示）
```

安装后功能：
- ✅ **双击 .securefolder 文件** → 弹出密码输入窗口解锁
- ✅ **右键任意文件夹** → 显示"Lock with SecureFolder"选项
- ✅ **右键加密文件** → 显示"Unlock with SecureFolder"选项
- ✅ **桌面快捷方式** → 打开图形界面

---

## 二、加密原理说明

### 2.1 类似 .zip 文件的设计

SecureFolder 采用类似压缩包的设计理念：

```
加密前：D:\Secret\           (普通文件夹)
加密后：D:\Secret.securefolder (单个加密文件包)

双击 D:\Secret.securefolder → 弹出密码对话框 → 解密 → 恢复为 D:\Secret\
```

**特点：**
- 加密后是**真正的文件**（不是文件夹），确保双击能正确触发密码框
- 通过 `.securefolder` 扩展名标识加密状态
- Windows 注册表文件关联正确工作
- 解密后自动恢复原始文件夹名称

### 2.2 文件加密方式

内部文件采用 AES-256-GCM 加密：

```
加密流程：
文件夹 → 遍历所有文件 → 分块加密 → 打包成单文件 → 安全擦除原文件

解密流程：
读取包文件 → 验证密码 → 解密索引 → 逐文件解密 → 恢复文件夹结构
```

---

## 三、图形界面使用

### 3.1 打开主界面

**方式1：** 双击桌面 `SecureFolder` 快捷方式

**方式2：** 直接运行 `SecureFolder.exe`

**方式3：** 命令行运行 `SecureFolder.exe gui`

### 3.2 加密文件夹（GUI）

```
步骤1：点击"浏览..."按钮
步骤2：弹出选择对话框：
       - 选择 [Yes] → 选择文件夹进行加密
       - 选择 [No] → 选择 .securefolder 文件进行解密
步骤3：选择要加密的文件夹
步骤4：输入加密密码（两次确认）
步骤5：选择加密模式：
       ○ 快速伪装 (秒级完成，仅CLSID)
       ● 完整加密 (AES加密+单文件打包) ← 推荐
       ○ 仅加密 (仅AES加密文件)
步骤6：点击"加密锁定"
步骤7：等待进度条完成
```

加密完成后：
- 生成 `原名称.securefolder` **文件**
- 原文件夹被安全擦除
- 双击该文件会弹出密码对话框

### 3.3 解密文件夹（GUI）

```
步骤1：点击"浏览..."按钮
步骤2：选择 [No] → 选择 .securefolder 文件
步骤3：选择加密文件
步骤4：输入密码
步骤5：点击"解密解锁"
步骤6：等待进度条完成
```

解密完成后：
- 恢复原始文件夹
- 所有文件恢复原始格式
- 可正常访问所有文件

---

## 四、右键菜单使用

### 4.1 加密文件夹

```
1. 在资源管理器中右键点击任意文件夹
2. 选择 "Lock with SecureFolder"
3. 程序弹出密码输入窗口（含确认密码）
4. 输入密码完成加密
5. 生成 .securefolder 文件
```

### 4.2 解密文件

```
1. 右键点击 .securefolder 文件
2. 选择 "Unlock with SecureFolder" 或 "Unlock and Open Folder"
3. 输入密码
4. 解密成功后：
   - "Unlock": 仅解密
   - "Unlock and Open": 解密并自动打开文件夹
```

---

## 五、双击解锁功能

### 5.1 双击加密文件

安装后，双击 `.securefolder` 文件会触发密码验证：

```
双击 D:\Secret.securefolder →

┌─────────────────────────────────────┐
│  SecureFolder - Unlock Folder       │
├─────────────────────────────────────┤
│  Encrypted: D:\Secret.securefolder  │
│                                     │
│  Password: [**********]             │
│                                     │
│  [Unlock]  [Unlock & Open]  [Cancel]│
│                                     │
│  Tip: Enter correct password to     │
│  unlock and restore folder.         │
└─────────────────────────────────────┘

密码正确 → 解密 → 自动打开 D:\Secret\
```

---

## 六、命令行使用

### 6.1 基本命令

```batch
# 加密文件夹
SecureFolder.exe lock "D:\Secret"

# 解密文件
SecureFolder.exe unlock "D:\Secret.securefolder"

# 查看文件状态
SecureFolder.exe status "D:\Secret.securefolder"

# 扫描已加密文件
SecureFolder.exe scan "D:\"

# 打开GUI
SecureFolder.exe gui

# 显示帮助
SecureFolder.exe help
```

### 6.2 命令参数

```batch
# 指定加密模式
SecureFolder.exe lock "D:\Secret" -m quick     # 快速伪装
SecureFolder.exe lock "D:\Secret" -m full      # 完整加密(默认)
SecureFolder.exe lock "D:\Secret" -m crypto    # 仅加密

# 指定密码
SecureFolder.exe lock "D:\Secret" -p "mypassword"

# 指定PBKDF2迭代次数
SecureFolder.exe lock "D:\Secret" -i 200000

# 不安全删除原文件
SecureFolder.exe lock "D:\Secret" -n
```

---

## 七、三种加密模式

| 模式 | 说明 | 安全性 | 速度 |
|------|------|--------|------|
| **完整加密 (FullEncrypt)** | AES加密文件 + 打包成单文件 | 最高 | 较慢 |
| **快速伪装 (QuickLock)** | 仅CLSID伪装 | 较低 | 极快 |
| **仅加密 (CryptoOnly)** | 仅AES加密文件，不打包 | 高 | 较慢 |

**推荐使用"完整加密"模式，提供最高安全性和正确的双击解锁体验。**

---

## 八、安装与卸载

### 8.1 安装（需管理员权限）

```batch
# 右键 install.bat → 以管理员身份运行
install.bat
```

安装内容：
- 复制程序到 `C:\Program Files\SecureFolder`
- 注册 Shell 扩展 DLL
- 注册 `.securefolder` 文件类型关联
- 创建右键菜单项
- 创建桌面快捷方式

### 8.2 卸载

```batch
# 右键 uninstall.bat → 以管理员身份运行
uninstall.bat
```

卸载内容：
- 注销 Shell 扩展 DLL
- 移除 `.securefolder` 文件类型关联
- 移除右键菜单项
- 移除桌面快捷方式
- 删除安装目录

---

## 九、编译步骤

### 9.1 编译要求

- Visual Studio 2022（选择"C++桌面开发"）
- CMake 3.15+
- Windows 10+

### 9.2 编译命令

```batch
cd e:\A-Job\scert
build.bat
```

编译输出：
```
build\Release\SecureFolder.exe       ← 主程序
build\Release\SecureFolderShellExt.dll ← Shell扩展
```

---

## 十、常见问题

### Q1: 双击加密文件没有弹出密码窗口？

```
解决：
1. 确认已以管理员身份运行 install.bat
2. 重启资源管理器（或重启电脑）
3. 检查 .securefolder 文件类型是否已注册
4. 确认加密文件是真正的文件（不是文件夹）
```

### Q2: 右键菜单没有加密选项？

```
解决：
1. 以管理员身份运行 install.bat
2. 重启资源管理器
3. 对于加密文件，右键应显示 "Unlock" 选项
4. 对于普通文件夹，右键应显示 "Lock" 选项
```

### Q3: 密码忘记了怎么办？

```
警告：密码无法恢复！文件将永久无法解密。
建议：记住密码，或备份加密前的原始文件
```

### Q4: 加密后的文件是什么样的？

```
加密文件特征：
- 生成 .securefolder 文件（真正的文件，类似 .zip）
- 文件可见，不隐藏
- 双击会弹出密码验证窗口
- 右键显示解密选项
```

### Q5: 解密失败显示"Decryption error"？

```
可能原因：
- 密码不正确
- 文件损坏
- 版本不兼容

解决：
- 确认密码正确
- 重新加密测试
```

---

## 十一、技术原理

### 加密流程
```
用户密码 → PBKDF2-HMAC-SHA256 → AES-256密钥 → AES-GCM加密 → 打包成单文件
```

### 密钥派生参数
```
算法: PBKDF2-HMAC-SHA256
盐值: 32字节随机数
迭代次数: 100,000次（可调整）
密钥长度: 256位（AES-256）
```

### 文件格式
```
┌─────────────────────────────────────────┐
│  SecurePackageHeader                     │
│  Magic: "SFPK" (4 bytes)                 │
│  Version: 1 (4 bytes)                    │
│  OriginalFolderName (UTF-8)              │
│  Salt (32 bytes)                         │
│  PasswordVerifyHash (32 bytes)           │
│  EncryptedIndex                          │
├─────────────────────────────────────────┤
│  FileEntry (per file)                    │
│  PathLen + Path                          │
│  OriginalSize (8 bytes)                  │
│  [Chunk: IV + Cipher + Tag] (repeated)   │
└─────────────────────────────────────────┘
```

### 双击解锁原理
```
注册表关联 .securefolder → SecureFolder.exe unlock-gui → 密码验证 → 解密
```

---

## 十二、安全建议

1. **密码强度**：至少8位，包含大小写字母、数字和符号
2. **密码备份**：牢记密码，丢失无法恢复
3. **重要文件**：加密前建议保留一份备份
4. **共享文件**：不要将密码与加密文件一起存储

---

*文档版本: v4.0*
*适用版本: SecureFolder 1.0.0*
*更新日期: 2026年5月6日*