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

    #轮常数
    RCON = [0x80, 0x30]

    #列混淆矩阵
    MIX_COLUMNS_MATRIX = [
        [0x1, 0x4],
        [0x4, 0x1]
    ]

    #逆列混淆矩阵
    INV_MIX_COLUMNS_MATRIX = [
        [0x9, 0x2],
        [0x2, 0x9]
    ]
    # 初始化A-AES实例
    def __init__(self, key):
        if not (0 <= key < 0x10000):
            raise ValueError("密钥必须是16位整数")
        self.master_key = key
        self.round_keys = self.key_expansion(key)

    # 将16位整数转换为2✖2状态矩阵
    @staticmethod
    def int_to_state(value):
        return [[(value >> 12) & 0xF, (value >> 8) & 0xF],
                [(value >> 4) & 0xF, value & 0xF]
                ]

    # 将2✖2状态矩阵转化为16位整数
    @staticmethod
    def state_to_int(state):
        return (state[0][0] << 12) | (state[0][1] << 8) | (state[1][0] << 4) | state[1][1]

    # 旋转半字节（用于密钥扩展）
    @staticmethod
    def rot_nibble(nibble):

    # 半字节替代
    @staticmethod
    def sub_nibble(nibble, s_box):

    # 密钥扩展
    def key_expansion(self, key):

    # 轮密钥加
    def add_round_key(self, state, round_key):
        # 判断明文是否满足16位
        if len(state) != 16:
            raise ValueError("明文必须是16bits")

        new_state = state ^ round_key
        return new_state

    # 半字节替代*
    def sub_nibbles(self, state, s_box):

    # 行移位
    def shift_rows(self, state):

    # GF(2^4)乘法
    def gf_mult(self, a, b):

    # 列混淆
    def mix_columns(self, state, matrix):

    # 加密单个16位分组
    def encrypt_block(self,plaintext):#明文分组是16位二进制字符串，密钥是16位
        state= self.int_to_state(plaintext)
        #轮密钥加
        state_matrix = self.add_round_key(state,self.round_keys[0])
        #半字节替换
        state_matrix = self.sub_nibbles(state_matrix,self.S_BOX)
        #行移位
        state_matrix = self.shift_rows(state_matrix)
        #列混淆
        state_matrix = self.mix_columns(state_matrix,self.MIX_COLUMNS_MATRIX)
        #第二次轮密钥加
        state_matrix = self.add_round_key(state_matrix,self.round_keys[1])
        #第二轮
        #半字节替换
        state_matrix = self.sub_nibbles(state_matrix)
        #行位移
        state_matrix = self.shift_rows(state_matrix)
        #第三次轮密钥加
        ciphertext = self.add_round_key(state_matrix,self.round_keys[2])
        return ciphertext

    # 解密单个16位分组
    def decrypt_block(self, ciphertext):
        state = self.int_to_state(ciphertext)
        #轮密钥加
        state_matrix = self.add_round_key(state,self.round_keys[2])
        #逆行移位
        state_matrix = self.shift_rows(state_matrix)
        #逆半字节代替
        state_matrix = self.sub_nibbles(state_matrix,self.INV_S_BOX)
        #轮密钥加
        state_matrix = self.add_round_key(state_matrix,self.round_keys[1])
        #逆列混淆
        state_matrix = self.mix_columns(state_matrix,self.INV_MIX_COLUMNS_MATRIX)
        #第二轮
        #逆行移位
        state_matrix = self.shift_rows(state_matrix)
        #逆半字节代替
        state_matrix = self.sub_nibbles(state_matrix,self.INV_S_BOX)
        plaintext = self.add_round_key(state_matrix,self.round_keys[0])
        return plaintext

    # 加密数据
    def encrypt(self, plaintext):
        #16位二进制字符串
        if isinstance(plaintext, str):#如果是二进制字符串
            if len(plaintext) != 16:
                raise ValueError('明文必须是16位二进制字符串')
            plaintext = int(plaintext,2)
        return self.encrypt_block(plaintext)

    # 解密数据
    def decrypt(self, ciphertext):
        if isinstance(ciphertext, str):
            if len(ciphertext) != 16:
                raise ValueError('密文必须是16位二进制字符串')
            ciphertext = int(ciphertext,2)
        return self.decrypt_block(ciphertext)