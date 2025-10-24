import sys

class S_AES:
    S_BOX = [
        0x9, 0x4, 0xA, 0xB,
        0xD, 0x1, 0x8, 0x5,
        0x6, 0x2, 0x0, 0x3,
        0xC, 0xE, 0xF, 0x7
    ]
    INV_S_BOX = [
        0xA, 0x5, 0x9, 0xB,
        0x1, 0x7, 0x8, 0xF,
        0x6, 0x0, 0x2, 0x3,
        0xC, 0x4, 0xD, 0xE
    ]

    # 轮常数
    RCON = [0x80, 0x30]

    # 列混淆矩阵
    MIX_COLUMNS_MATRIX = [
        [0x1, 0x4],
        [0x4, 0x1]
    ]

    # 逆列混淆矩阵
    INV_MIX_COLUMNS_MATRIX = [
        [0x9, 0x2],
        [0x2, 0x9]
    ]

    # 初始化A-AES实例
    def __init__(self, key):
        if not (0 <= key < 0x10000):
            raise ValueError("密钥必须是16位二进制数")
        self.master_key = key
        self.round_keys = self.key_expansion(key)

    @staticmethod
    # 将16位整数转换为2✖2状态矩阵
    def int_to_state(value):
        return [[(value >> 12) & 0xF, (value >> 8) & 0xF],
                [(value >> 4) & 0xF, value & 0xF]
                ]

    @staticmethod
    # 将2✖2状态矩阵转化为16位整数
    def state_to_int(state):
        return (state[0][0] << 12) | (state[0][1] << 8) | (state[1][0] << 4) | state[1][1]

    @staticmethod
    # 旋转半字节（用于密钥扩展）
    def rot_nibble(nibble):
        return ((nibble & 0xF) << 4 | (nibble >> 4) & 0xF)

    @staticmethod
    # 半字节替代
    def sub_nibble(nibble, s_box):
        return s_box[nibble]

    # 密钥扩展
    def key_expansion(self, key):
        # 初始密钥
        w0 = (key >> 8) & 0xF
        w1 = key & 0xF

        # 第一轮密钥扩展
        temp = self.rot_nibble(w1)
        temp = (self.sub_nibble((temp >> 4) & 0xF, self.S_BOX) << 4) | self.sub_nibble(temp & 0xF, self.S_BOX)

        w2 = w0 ^ temp ^ self.RCON[0]
        w3 = w2 ^ w1

        # 第二轮密钥扩展
        temp = self.rot_nibble(w1)
        temp = (self.sub_nibble((temp >> 4) & 0xF, self.S_BOX) << 4) | self.sub_nibble(temp & 0xF, self.S_BOX)
        w4 = w2 ^ temp ^ self.RCON[1]
        w5 = w4 ^ w3

        # 生成16位轮密钥
        round_key0 = (w0 << 8) | w1
        round_key1 = (w2 << 8) | w3
        round_key2 = (w4 << 8) | w5

        return [round_key0, round_key1, round_key2]

    # 轮密钥加
    def add_round_key(self, state, round_key):
        round_key_state = self.int_to_state(round_key)
        new_state = [[0, 0], [0, 0]]

        for i in range(2):
            for j in range(2):
                new_state[i][j] = state[i][j] ^ round_key_state[i][j]

        return new_state

    # 半字节替代*
    def sub_nibbles(self, state, s_box):
        new_state = [[0, 0], [0, 0]]

        for i in range(2):
            for j in range(2):
                new_state[i][j] = self.sub_nibble(state[i][j], s_box)

        return new_state

    # 行移位
    def shift_rows(self, state):
        # 第一行不变，第二行交换
        return [
            [state[0][0], state[0][1]],
            [state[1][1], state[1][0]]
        ]

    # GF(2^4)乘法
    def gf_mult(self, a, b):
        p = 0
        for _ in range(4):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x8
            a <<= 1
            a &= 0xF
            if hi_bit_set:
                a ^= 0x3
            b >>= 1
        return p

    # 列混淆
    def mix_columns(self, state, matrix):
        new_state = [[0, 0], [0, 0]]

        for j in range(2):
            s0 = state[0][j]
            s1 = state[1][j]

            new_state[0][j] = self.gf_mult(matrix[0][0], s0) ^ self.gf_mult(matrix[0][1], s1)
            new_state[1][j] = self.gf_mult(matrix[1][0], s0) ^ self.gf_mult(matrix[1][1], s1)

        return new_state

    # 加密单个16位分组
    # 加密单个16位分组
    def encrypt_block(self, plaintext):  # 明文分组是16位二进制字符串，密钥是16位
        state = self.int_to_state(plaintext)
        # 轮密钥加
        state_matrix = self.add_round_key(state, self.round_keys[0])
        # 半字节替换
        state_matrix = self.sub_nibbles(state_matrix, self.S_BOX)
        # 行移位
        state_matrix = self.shift_rows(state_matrix)
        # 列混淆
        state_matrix = self.mix_columns(state_matrix, self.MIX_COLUMNS_MATRIX)
        # 第二次轮密钥加
        state_matrix = self.add_round_key(state_matrix, self.round_keys[1])
        # 第二轮
        # 半字节替换
        state_matrix = self.sub_nibbles(state_matrix, self.S_BOX)
        # 行位移
        state_matrix = self.shift_rows(state_matrix)
        # 第三次轮密钥加
        state_matrix = self.add_round_key(state_matrix, self.round_keys[2])
        ciphertext = self.state_to_int(state_matrix)
        return ciphertext

    # 解密单个16位分组
    def decrypt_block(self, ciphertext):
        state = self.int_to_state(ciphertext)
        # 轮密钥加
        state_matrix = self.add_round_key(state, self.round_keys[2])
        # 逆行移位
        state_matrix = self.shift_rows(state_matrix)
        # 逆半字节代替
        state_matrix = self.sub_nibbles(state_matrix, self.INV_S_BOX)
        # 轮密钥加
        state_matrix = self.add_round_key(state_matrix, self.round_keys[1])
        # 逆列混淆
        state_matrix = self.mix_columns(state_matrix, self.INV_MIX_COLUMNS_MATRIX)
        # 第二轮
        # 逆行移位
        state_matrix = self.shift_rows(state_matrix)
        # 逆半字节代替
        state_matrix = self.sub_nibbles(state_matrix, self.INV_S_BOX)
        state_matrix = self.add_round_key(state_matrix, self.round_keys[0])
        plaintext = self.state_to_int(state_matrix)
        return plaintext

    # 加密数据
    def encrypt(self, plaintext):
        # 16位二进制字符串
        if isinstance(plaintext, str):  # 如果是二进制字符串
            if len(plaintext) != 16:
                raise ValueError('明文必须是16位二进制字符串')
            plaintext = int(plaintext, 2)
        return self.encrypt_block(plaintext)

    # 解密数据
    def decrypt(self, ciphertext):
        if isinstance(ciphertext, str):
            if len(ciphertext) != 16:
                raise ValueError('密文必须是16位二进制字符串')
            ciphertext = int(ciphertext, 2)
        return self.decrypt_block(ciphertext)


class DoubleS_AES:
    def __init__(self, key):
        if not (0 <= key < 0x100000000):
            raise ValueError("密钥必须是32位二进制数")
        self.key1 = (key >> 16) & 0xFFFF  # 高16位
        self.key2 = key & 0xFFFF          # 低16位
        self.cipher1 = S_AES(self.key1)
        self.cipher2 = S_AES(self.key2)
    
    def encrypt(self, plaintext):
        """双重加密：先用K1加密，再用K2加密"""
        middle = self.cipher1.encrypt(plaintext)
        return self.cipher2.encrypt(middle)
    
    def decrypt(self, ciphertext):
        """双重解密：先用K2解密，再用K1解密"""
        middle = self.cipher2.decrypt(ciphertext)
        return self.cipher1.decrypt(middle)


class MeetInMiddleAttack:
    def __init__(self, known_pairs):
        """
        known_pairs: 已知的明密文对列表，每个元素为(plaintext, ciphertext)
        plaintext和ciphertext都是16位整数
        """
        self.known_pairs = known_pairs
    
    def find_key(self):
        """使用中间相遇攻击找到可能的密钥对(K1, K2)"""
        # 如果没有已知对，无法攻击
        if not self.known_pairs:
            return []
        
        # 使用第一对来构建表并查找候选密钥
        plain, cipher = self.known_pairs[0]
        
        # 构建加密表：K1 -> 中间密文
        encrypt_table = {}
        for k1 in range(0x10000):  # 遍历所有可能的K1
            cipher1 = S_AES(k1)
            mid = cipher1.encrypt(plain)
            if mid not in encrypt_table:
                encrypt_table[mid] = []
            encrypt_table[mid].append(k1)
        
        # 查找候选密钥
        candidate_keys = []
        for k2 in range(0x10000):  # 遍历所有可能的K2
            cipher2 = S_AES(k2)
            mid = cipher2.decrypt(cipher)
            if mid in encrypt_table:
                for k1 in encrypt_table[mid]:
                    candidate_keys.append((k1, k2))
        
        # 如果有多个已知对，验证候选密钥
        if len(self.known_pairs) > 1:
            verified_keys = []
            for k1, k2 in candidate_keys:
                double_aes = DoubleS_AES((k1 << 16) | k2)
                valid = True
                for plain, cipher in self.known_pairs[1:]:
                    if double_aes.encrypt(plain) != cipher:
                        valid = False
                        break
                if valid:
                    verified_keys.append((k1, k2))
            return verified_keys
        
        return candidate_keys


class TripleS_AES:
    def __init__(self, key):
        """
        使用32位密钥(K1+K2)的三重加密
        加密：E_K1 -> D_K2 -> E_K1
        解密：D_K1 -> E_K2 -> D_K1
        """
        if not (0 <= key < 0x100000000):
            raise ValueError("密钥必须是32位二进制数")
        self.key1 = (key >> 16) & 0xFFFF  # 高16位
        self.key2 = key & 0xFFFF          # 低16位
        self.cipher1 = S_AES(self.key1)
        self.cipher2 = S_AES(self.key2)
    
    def encrypt(self, plaintext):
        """三重加密：E_K1 -> D_K2 -> E_K1"""
        temp = self.cipher1.encrypt(plaintext)
        temp = self.cipher2.decrypt(temp)
        return self.cipher1.encrypt(temp)
    
    def decrypt(self, ciphertext):
        """三重解密：D_K1 -> E_K2 -> D_K1"""
        temp = self.cipher1.decrypt(ciphertext)
        temp = self.cipher2.encrypt(temp)
        return self.cipher1.decrypt(temp)
    




def test_double_aes():
    print("="*50)
    print("测试双重加密")
    print("="*50)
    
    # 测试用例1
    key = 0x1234ABCD  # 32位密钥
    plaintext = 0xABCD
    double_aes = DoubleS_AES(key)
    ciphertext = double_aes.encrypt(plaintext)
    decrypted = double_aes.decrypt(ciphertext)
    
    print(f"密钥: 0x{key:08X}")
    print(f"明文: 0x{plaintext:04X}")
    print(f"密文: 0x{ciphertext:04X}")
    print(f"解密: 0x{decrypted:04X}")
    print(f"测试 {'通过' if plaintext == decrypted else '失败'}")
    
    # 测试用例2
    key = 0x5678EF01
    plaintext = 0x1234
    double_aes = DoubleS_AES(key)
    ciphertext = double_aes.encrypt(plaintext)
    decrypted = double_aes.decrypt(ciphertext)
    
    print(f"\n密钥: 0x{key:08X}")
    print(f"明文: 0x{plaintext:04X}")
    print(f"密文: 0x{ciphertext:04X}")
    print(f"解密: 0x{decrypted:04X}")
    print(f"测试 {'通过' if plaintext == decrypted else '失败'}")
    
    print("\n")


def test_meet_in_middle_attack():
    print("="*50)
    print("测试中间相遇攻击")
    print("="*50)
    
    # 使用双重加密生成已知明密文对
    true_key = 0x1234ABCD
    double_aes = DoubleS_AES(true_key)
    
    # 创建多个明密文对
    known_pairs = []
    for plaintext in [0xABCD, 0x1234, 0x5678, 0x9ABC]:
        ciphertext = double_aes.encrypt(plaintext)
        known_pairs.append((plaintext, ciphertext))
    
    print(f"真实密钥: 0x{true_key:08X}")
    print(f"生成 {len(known_pairs)} 个明密文对")
    
    # 执行中间相遇攻击
    attack = MeetInMiddleAttack(known_pairs)
    possible_keys = attack.find_key()
    
    print(f"找到 {len(possible_keys)} 个候选密钥:")
    for i, (k1, k2) in enumerate(possible_keys):
        key = (k1 << 16) | k2
        print(f"候选密钥 {i+1}: 0x{key:08X} (K1=0x{k1:04X}, K2=0x{k2:04X})")
    
    # 验证候选密钥
    if possible_keys:
        print(f"\n真实密钥 {'在' if true_key in [(k1 << 16) | k2 for k1, k2 in possible_keys] else '不在'}候选列表中")
    
    # 测试只有一个明密文对的情况
    print("\n测试只有一个明密文对的情况:")
    attack_single = MeetInMiddleAttack([known_pairs[0]])
    possible_keys_single = attack_single.find_key()
    print(f"找到 {len(possible_keys_single)} 个候选密钥")
    
    print("\n")


def test_triple_aes():
    print("="*50)
    print("测试三重加密")
    print("="*50)
    
    # 测试用例1
    key = 0x5678EF01
    plaintext = 0xCDEF
    triple_aes = TripleS_AES(key)
    ciphertext = triple_aes.encrypt(plaintext)
    decrypted = triple_aes.decrypt(ciphertext)
    
    print(f"密钥: 0x{key:08X}")
    print(f"明文: 0x{plaintext:04X}")
    print(f"密文: 0x{ciphertext:04X}")
    print(f"解密: 0x{decrypted:04X}")
    print(f"测试 {'通过' if plaintext == decrypted else '失败'}")
    
    # 测试用例2
    key = 0x9ABCDEF0
    plaintext = 0x2468
    triple_aes = TripleS_AES(key)
    ciphertext = triple_aes.encrypt(plaintext)
    decrypted = triple_aes.decrypt(ciphertext)
    
    print(f"\n密钥: 0x{key:08X}")
    print(f"明文: 0x{plaintext:04X}")
    print(f"密文: 0x{ciphertext:04X}")
    print(f"解密: 0x{decrypted:04X}")
    print(f"测试 {'通过' if plaintext == decrypted else '失败'}")
    
    


if __name__ == "__main__":
    # 运行所有测试
    test_double_aes()
    test_meet_in_middle_attack()
    test_triple_aes()