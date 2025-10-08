
```markdown
# S-DES 加解密工具开发手册

## 核心函数说明

### 置换函数
```python
def permute(input_bits, table):
    """
    通用置换函数
    :param input_bits: 输入位字符串
    :param table: 置换表
    :return: 置换后的位字符串
    """
    return ''.join(input_bits[i - 1] for i in table)
```

### 循环左移函数
```python
def left_shift(bits, n):
    """
    循环左移操作
    :param bits: 输入位字符串
    :param n: 左移位数
    :return: 移位后的位字符串
    """
    return bits[n:] + bits[:n]
```

### 密钥生成函数
```python
def generate_keys(key):
    """
    生成子密钥k1和k2
    :param key: 10位主密钥
    :return: 元组(k1, k2)
    :raises ValueError: 密钥长度不正确时抛出
    """
    if len(key) != 10:
        raise ValueError("密钥必须是10位二进制字符串")

    key_perm = permute(key, P10)
    
    left = left_shift(key_perm[:5], 1)
    right = left_shift(key_perm[5:], 1)
    
    # k1生成
    k1 = permute(left + right, P8)
    
    left1 = left_shift(left, 2)
    right1 = left_shift(right, 2)
    
    # k极速生成
    k2 = permute(left1 + right1, P8)
    
    return k1, k2
```

### 轮函数
```python
def f_k(bits, key):
    """
    轮函数实现
    :param bits: 8位输入数据
    :param key: 8位轮密钥
    :return: 8位输出数据
    """
    left, right = bits[:4], bits[4:]
    
    expanded = permute(right, EP)
    
    # 与子密钥异或
    xor_result = ''.join(str(int(a) ^ int(b)) for a, b in zip(expanded, key))
    
    s0_in = xor_result[:4]
    s1_in = xor_result[4:]
    
    # S0盒处理
    row0 = int(s0_in[0] + s0_in[3], 2)
    col0 = int(s0_in极速1] + s0_in[2], 2)
    s0_out = bin(S0[row0][col0])[2:].zfill(2)
    
    # S1盒处理
    row1 = int(s1_in[0] + s1_in[3], 2)
    col1 = int(s1_in[1] + s1极速[2], 2)
    s1_out = bin(S1[row1][col1])[2:].zfill(2)
    
    # P4置换
    s_out = s0_out + s1_out
    p4_result = permute(s_out, P4)
    
    new_left = ''.join(str(int(a) ^ int(b)) for a, b in zip(left, p4_result))
    
    return new_left + right
```

### 加密函数
```python
def encrypt(plaintext, key):
    """
    S-DES加密函数
    :param plaintext: 8位明文
    :param key: 10位密钥
    :return: 8位密文
    :raises ValueError: 输入长度不正确时抛出
    """
    if len(plaintext) != 8:
        raise ValueError("明文必须是8位二进制字符串")
    
    # 生成子密钥
    k1, k2 = generate_keys(key)
    
    # 初始置换
    permuted = permute(plaintext, IP)
    
    # 第一轮
    round1 = f_k(permuted, k1)
    
    swapped = round1[4:] + round1[:4]
    
    # 第二轮
    round2 = f_k(swapped, k2)
    
    # 最终置换
    ciphertext = permute(round2, IP_INV)
    
    return ciphertext
```

### 解密函数
```python
def decrypt(ciphertext, key):
    """
    S-DES解密函数
    :param ciphertext: 8位极速文
    :param key: 10位密钥
极速 :return: 8位明文
    :raises ValueError: 输入长度不正确时抛出
    """
    if len(ciphertext) != 8:
        raise ValueError("密文必须是8位二进制字符串")
    
    k1, k2 = generate_keys(key)
    
    permuted = permute(ciphertext, IP)
    
    # 第一轮
    round1 = f_k(permuted, k2)
    
    swapped = round1[4:] + round1[:4]
    
    # 第二轮
    round2 = f_k(swapped, k1)
    
    # 最终置换
    plaintext = permute(round2, IP_INV)
    
    return plaintext
```

### ASCII转换函数
```python
def ascii_to_binary(text):
    """
    将ASCII字符串转换为二进制字符串
    :param text: ASCII字符串
    :return: 二进制字符串
    """
    binary_result = ""
    for char in text:
        # 将每个字符转换为8位二进制
        binary_char = bin(ord(char))[2:].zfill(8)
        binary_result += binary_char
    return binary_result
```

```python
def binary_to_ascii(binary_text):
    """
    将二进制字符串转换为ASCII字符串
    :param binary_text: 二进制字符串
    :return: ASCII字符串
    """
    ascii_result = ""
    # 每8位一组处理
    for i in range(0, len(binary_text), 8):
        binary_char = binary_text[i:i + 8]
        if len(binary_char) == 8:
            ascii_char = chr(int(binary_char, 2))
            ascii_result += ascii_char
    return ascii_result
```

### ASCII加解密函数
```python
def encrypt_ascii(plaintext_ascii, key):
    """
    加密ASCII字符串
    :param plaintext_ascii: ASCII明文
    :param key: 10位密钥
    :return: 元组(ASCII密文, 二进制密文)
    """
    # 将明文转换为二进制
    binary_plaintext = ascii_to_binary(plaintext_ascii)
    
    # 分组加密（每8位一组）
    ciphertext_binary = ""
    for i in range(0, len(binary极速laintext), 8):
        block = binary_plaintext[i:i + 8]
        if len(block) == 8:
            encrypted_block = encrypt(block, key)
            ciphertext_binary += encrypted_block
    
    # 将二进制密文转换为ASCII（可能是乱码）
    ciphertext_asci极速 = binary_to_ascii(cipher极速t_binary)
    return ciphertext_ascii, ciphertext_binary
```

```python
def decrypt_ascii(ciphertext_ascii, key):
    """
    解密密文ASCII字符串
    :param ciphertext_ascii: ASCII密文
    :param key: 10位密钥
    :return: 元组(ASCII明文, 二进制明文)
    """
    # 将密文转换为二进制
    binary_ciphertext = ascii_to_binary(ciphertext_ascii)
    
    # 分组解密（每8位一组）
    plaintext_binary = ""
    for i in range(0, len(binary_ciphertext), 8):
        block = binary_ciphertext[i:i + 8]
        if len(block) == 8:
            decrypted_block = decrypt(block, key)
            plaintext_binary += decrypted_block
    
    # 将二进制明文转换为ASCII
    plaintext_ascii = binary_to_ascii(plaintext_binary)
    return plaintext_ascii, plaintext_binary
```

### 暴力破解函数
```python
def brute_force_attack(known_plaintext, known_ciphertext):
    """
    暴力破解S-DES密钥（二进制模式）
    :param known_plaintext: 已知明文(8位二进制)
    :param known_ciphertext: 已知密文(8位二进制)
    :return: 可能密钥列表
    """
    possible_keys = []
    
    # 生成所有可能的10位二进制密钥
    for i in range(1024):  # 2^10 = 1024
        key = bin(i)[2:].zfill(10)
        
        try:
            # 尝试用当前密钥加密已知明文
            test_ciphertext = encrypt(known_plaintext, key)
            
            # 如果加密结果匹配已知密文，则找到可能密钥
            if test_ciphertext == known_ciphertext:
                possible_keys.append(key)
                
        except:
            # 跳过无效密钥
            continue
            
    return possible_keys
```

```python
def brute_force_attack_ascii(known_plaintext_ascii, known_ciphertext_ascii):
    """
    暴力破解S-DES密钥（ASCII模式）
    :param known_plaintext_ascii: 已知明文(ASCII)
    :param known_ciphertext_ascii: 已知密文(ASCII)
    :return: 可能密钥列表
    """
    possible_keys = []
    
    # 将已知明文和密文转换为二进制
    binary_plaintext = ascii_to_binary(known_plaintext_ascii)
    binary_ciphertext = ascii_to_binary(known_ciphertext_ascii)
    
    # 只处理第一个8位块进行匹配（简化计算）
    plaintext_block = binary_plaintext[:8]
    ciphertext_block = binary_ciphertext[:8]
    
    if len(plaintext_block) == 8 and len(ciphertext_block) == 8:
        for i in range(1024):  # 2^10 = 1024
            key = bin(i)[2:].zfill(10)
            
            try:
                test_ciphertext = encrypt(plaintext_block, key)
                if test_ciphertext == ciphertext_block:
                    possible_keys.append(key)
            except:
                continue
                
    return possible_keys
```

