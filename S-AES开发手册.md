# 开发手册 (development_manual.md)
```
# S-AES 加密解密工具 - 开发手册

## 项目概述
本项目实现了简化版AES（S-AES）算法，提供完整的加密解密功能集，包括图形用户界面和多种操作模式。

## 系统架构

### 核心模块结构
```
s_aes/
├── core/           # 核心算法模块
│   ├── s_aes.py    # S-AES算法实现
│   ├── modes.py    # 操作模式实现
│   └── converters.py # 数据转换工具
├── ui/             # 用户界面模块
│   └── main_window.py # 主窗口实现
└── tests/          # 测试模块
    └── test_s_aes.py # 单元测试
```

## 核心算法详解

### S-AES类结构
```python
class S_AES:
    # 常量定义
    S_BOX = [...]        # S盒替换表
    INV_S_BOX = [...]    # 逆S盒
    RCON = [...]         # 轮常数
    
    def __init__(self, key): pass
    def encrypt_block(self, plaintext): pass
    def decrypt_block(self, ciphertext): pass
    # ... 其他方法
```

### 加密流程
1. **初始轮密钥加**：明文与第一轮密钥异或
2. **第一轮操作**：
   - S盒替换（SubNibbles）
   - 行移位（ShiftRows）
   - 列混淆（MixColumns）
   - 轮密钥加
3. **第二轮操作**：
   - S盒替换
   - 行移位
   - 最终轮密钥加

### 有限域运算
使用GF(2^4)有限域，本原多项式为x^4 + x + 1 (0x13)
```python
def _gf_mult(self, a, b):
    # 有限域乘法实现
```

## 关键算法实现

### 密钥扩展
```python
def key_expansion(self, key):
    w0 = (key >> 8) & 0xFF
    w1 = key & 0xFF
    
    # 第一轮扩展
    w2 = w0 ^ self._g_function(w1, self.RCON[0])
    w3 = w2 ^ w1
    
    # 第二轮扩展  
    w4 = w2 ^ self._g_function(w3, self.RCON[1])
    w5 = w4 ^ w3
    
    return [(w0<<8)|w1, (w2<<8)|w3, (w4<<8)|w5]
```

### S盒替换
```python
def _sub_nibbles(self, state, s_box):
    n0 = s_box[(state >> 12) & 0xF]
    n1 = s_box[(state >> 8) & 0xF]
    n2 = s_box[(state >> 4) & 0xF] 
    n3 = s_box[state & 0xF]
    return (n0 << 12) | (n1 << 8) | (n2 << 4) | n3
```

## 操作模式实现

### ECB模式（默认）
- 每个数据块独立加密
- 实现简单，但安全性较低

### CBC模式
```python
def encrypt_cbc(self, plaintext_blocks, iv):
    cipher_blocks = []
    previous = iv
    for block in plaintext_blocks:
        xored = block ^ previous
        encrypted = self.encrypt_block(xored)
        cipher_blocks.append(encrypted)
        previous = encrypted
    return cipher_blocks
```

### 多重加密
- **双重加密**：E_K2(E_K1(P))
- **三重加密**：E_K1(D_K2(E_K1(P)))

## 用户界面设计

### 主窗口类
```python
class S_AES_UI(QMainWindow):
    def __init__(self): pass
    def init_ui(self): pass
    # 标签页初始化方法
    def setup_key_tab(self, tab_widget): pass
    def setup_encrypt_tab(self, tab_widget): pass
    # ... 其他标签页
```

### 界面布局
- **标签页设计**：密钥设置、加密、解密、ASCII操作、多重加密、CBC模式
- **输入验证**：实时格式检查和错误提示
- **结果展示**：二进制和十六进制格式显示

## 数据转换模块

### ASCII转换器
```python
class ASCIIConverter:
    @staticmethod
    def text_to_binary(text): pass
    @staticmethod 
    def binary_to_text(binary_blocks): pass
```

### 转换流程
```
文本 → ASCII码 → 16位二进制块 → 加密 → 密文块
密文块 → 解密 → 16位二进制块 → ASCII码 → 文本
```

## 安全特性

### 算法特性
- **密钥长度**：16位（基础），32位（多重加密）
- **轮数**：2轮加密
- **块大小**：16位

### 安全考虑
- 支持CBC模式防止模式分析
- 提供多重加密增强安全性
- 实现中间相遇攻击演示

## 扩展开发

### 添加新操作模式
1. 在S_AES类中添加新方法
2. 在UI类中创建对应的界面元素
3. 添加事件处理函数

### 示例：CTR模式实现
```python
def encrypt_ctr(self, plaintext_blocks, nonce):
    cipher_blocks = []
    for i, block in enumerate(plaintext_blocks):
        counter = nonce + i
        encrypted_counter = self.encrypt_block(counter)
        cipher_blocks.append(block ^ encrypted_counter)
    return cipher_blocks
```

## 测试指南

### 单元测试
```python
import unittest
from core.s_aes import S_AES

class TestS_AES(unittest.TestCase):
    def test_encryption(self):
        key = 0b1010101010101010
        plaintext = 0b1100110011001100
        cipher = S_AES(key)
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        self.assertEqual(plaintext, decrypted)
```

### 测试用例
- 基本加密解密测试
- 边界值测试
- 模式操作测试
- 错误处理测试

## 性能优化

### 算法优化建议
1. **预计算**：S盒查找表优化
2. **并行处理**：多块同时加密
3. **内存优化**：减少临时变量

### 代码优化示例
```python
# 优化前的S盒替换
def slow_sub_nibbles(state, s_box):
    # 逐个半字节处理
    
# 优化后的S盒替换  
def fast_sub_nibbles(state, s_box):
    # 使用查找表或位运算优化
```

## 部署说明

### 打包为可执行文件
使用PyInstaller打包：
```bash
pyinstaller --onefile --windowed s_aes.py
```

### 依赖管理
创建requirements.txt：
```
PyQt5==5.15.7
```

## 故障排除

### 常见问题
1. **导入错误**：检查PyQt5安装
2. **界面显示异常**：检查系统字体设置
3. **加密结果错误**：验证输入数据格式

### 调试技巧
- 启用详细日志输出
- 使用调试器单步执行
- 检查中间计算结果

