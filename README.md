# S-AES 加密解密工具 - README

## 项目简介
S-AES（简化版高级加密标准）加密解密工具是一个基于Python和PyQt5开发的图形化应用程序，实现了16位简化AES算法。该工具提供完整的加密解密功能，支持多种操作模式，适合教学演示和基础加密需求。

## 主要特性
- ✅ **基础加密解密**：支持16位二进制数据的S-AES加密解密
- ✅ **ASCII文本支持**：可将文本转换为ASCII码进行加密解密
- ✅ **多种操作模式**：支持ECB、CBC等加密模式
- ✅ **多重加密**：支持双重加密和三重加密增强安全性
- ✅ **图形化界面**：基于PyQt5的友好用户界面
- ✅ **实时验证**：输入格式实时检查和错误提示
- ✅ **密钥管理**：完整的密钥生成和轮密钥展示

## 系统要求
- **Python版本**：3.6或更高版本
- **依赖库**：PyQt5
- **操作系统**：Windows、macOS、Linux

## 快速安装

### 1. 克隆或下载项目
```bash
git clone <项目地址>
cd s-aes
```

### 2. 安装依赖
```bash
pip install PyQt5
```

### 3. 运行应用
```bash
python s_aes.py
```

## 项目结构
```
s-aes/
├── core/                 # 核心算法模块
│   ├── s_aes.py         # S-AES算法实现
│   ├── modes.py         # 操作模式实现
│   └── converters.py    # 数据转换工具
├── ui/                  # 用户界面模块
│   └── main_window.py   # 主窗口实现
├── tests/               # 测试模块
│   └── test_s_aes.py    # 单元测试
├── s_aes.py        # 主程序入口
├── requirements.txt     # 依赖列表
└── README.md           # 项目说明
```

## 使用指南

### 基本加密解密
1. **设置密钥**：在密钥设置标签页输入16位二进制密钥
2. **加密操作**：在加密标签页输入16位二进制明文，点击加密按钮
3. **解密操作**：在解密标签页输入16位二进制密文，点击解密按钮

### 文本加密解密
1. **ASCII加密**：在ASCII加密标签页输入文本，系统自动转换为ASCII码并加密
2. **ASCII解密**：在ASCII解密标签页输入密文块（每行一个16位二进制），系统解密并还原为文本

### 高级功能
- **CBC模式**：使用初始向量(IV)增强加密安全性
- **多重加密**：支持双重和三重加密模式
- **中间相遇攻击**：演示双重加密的安全性分析

## 算法说明

### S-AES算法特点
- **密钥长度**：16位（基础模式）
- **块大小**：16位
- **加密轮数**：2轮
- **操作步骤**：字节替换、行移位、列混淆、轮密钥加

### 支持的加密模式
- **ECB模式**：电子密码本模式（默认）
- **CBC模式**：密码块链接模式
- **多重加密**：双重加密、三重加密

## 开发指南

### 代码结构
```python
# 核心算法类
class S_AES:
    def encrypt_block(self, plaintext): ...
    def decrypt_block(self, ciphertext): ...
    def key_expansion(self, key): ...

# 操作模式类  
class EncryptionModes:
    def encrypt_ecb(self, plaintext_blocks): ...
    def encrypt_cbc(self, plaintext_blocks, iv): ...
    def double_encrypt(self, plaintext, key1, key2): ...

# 用户界面类
class S_AES_UI(QMainWindow):
    def setup_ui(self): ...
    def setup_key_tab(self): ...
    def setup_encrypt_tab(self): ...
```

### 扩展开发
要添加新的加密模式或功能：
1. 在`core/modes.py`中实现新算法
2. 在`ui/main_window.py`中添加对应的界面元素
3. 添加相应的事件处理函数

## 测试运行

### 单元测试
```bash
python -m unittest tests/test_s_aes.py
```

### 功能测试用例
- 基本加密解密功能测试
- ASCII文本转换测试
- CBC模式加密测试
- 多重加密功能测试

## 打包部署

### 创建可执行文件
使用PyInstaller打包为独立可执行文件：
```bash
pyinstaller --onefile --windowed s_aes.py
```

### 依赖管理
项目依赖详见`requirements.txt`文件：
```
PyQt5>=5.15.0
```

## 故障排除

### 常见问题
1. **导入错误**：确保已正确安装PyQt5
2. **界面显示异常**：检查系统兼容性和字体设置
3. **加密结果异常**：验证输入数据格式是否正确

### 调试模式
启用详细日志输出：
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```


## 贡献指南
欢迎提交问题和改进建议！请确保：
1. 代码符合PEP8规范
2. 新增功能包含相应测试用例
3. 更新相关文档说明



## 相关资源
- user_guide.md - 详细使用说明
- development_manual.md - 技术实现细节
- docs/api.md - 接口说明文档

---
