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



    #初始化A-AES实例
    def __init__(self,key):
        if not (0 <= key < 0x10000):
            raise ValueError("密钥必须是16位二进制数")
        self.master_key = key
        self.round_keys = self.key_expansion(key)

    @staticmethod
    #将16位整数转换为2✖2状态矩阵
    def int_to_state(value):
        return [[(value>>12) & 0xF,(value>>8) & 0xF],
                [(value>>4) & 0xF,value & 0xF]
                ]

    @staticmethod
    #将2✖2状态矩阵转化为16位整数
    def state_to_int(state):
        return (state[0][0] << 12) | (state[0][1] << 8) | (state[1][0] << 4) | state[1][1]


    @staticmethod
    #旋转半字节（用于密钥扩展）
    def rot_nibble(nibble):
        return ((nibble & 0xF) << 4 | (nibble >> 4) & 0xF)

    @staticmethod
    #半字节替代
    def sub_nibble(nibble, s_box):
        return s_box[nibble]

    #密钥扩展
    def key_expansion(self, key):
        #初始密钥
        w0 = (key >> 8) & 0xF
        w1 = key & 0xF

        #第一轮密钥扩展
        temp = self.rot_nibble(w1)
        temp = (self.sub_nibble((temp >> 4) & 0xF, self.S_BOX)  << 4) | self.sub_nibble(temp & 0xF,self.S_BOX)

        w2 = w0 ^ temp ^ self.RCON[0]
        w3 = w2 ^ w1

        #第二轮密钥扩展
        temp = self.rot_nibble(w1)
        temp = (self.sub_nibble((temp >> 4) & 0xF, self.S_BOX)  << 4) | self.sub_nibble(temp & 0xF,self.S_BOX)
        w4 = w2 ^ temp ^ self.RCON[1]
        w5 = w4 ^ w3

        #生成16位轮密钥
        round_key0 = (w0 << 8) | w1
        round_key1 = (w2 << 8) | w3
        round_key2 = (w4 << 8) | w5

        return [round_key0,round_key1,round_key2]



    #轮密钥加
    def add_round_key(self, state, round_key):
        round_key_state = self.int_to_state(round_key)
        new_state = [[0,0],[0,0]]

        for i in range(2):
            for j in range(2):
                new_state[i][j] = state[i][j] ^ round_key_state[i][j]
                
        return new_state
    

    #半字节替代*    
    def sub_nibbles(self, state, s_box):
        new_state = [[0,0],[0,0]]

        for i in range(2):
            for j in range(2):
                new_state[i][j] = self.sub_nibble(state[i][j],s_box)

        return new_state
        
        
    #行移位
    def shift_rows(self, state):
        #第一行不变，第二行交换
        return[
            [state[0][0],state[0][1]],
            [state[1][1],state[1][0]]
        ]


    #GF(2^4)乘法
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


    #列混淆
    def mix_columns(self, state, matrix):
        new_state = [[0,0],[0,0]]

        for j in range(2):
            s0 = state[0][j]
            s1 = state[1][j]

            new_state[0][j] = self.gf_mult(matrix[0][0],s0) ^ self.gf_mult(matrix[0][1], s1)
            new_state[1][j] = self.gf_mult(matrix[1][0],s0) ^ self.gf_mult(matrix[1][1], s1)

        return new_state


    #加密单个16位分组
    def encrypt_block(self, plaintext):
        if not (0 <= plaintext <= 0xFFFF):
            raise ValueError("明文必须是16位二进制数")
        



    #解密单个16位分组
    def decrypt_block(self, ciphertext):


    #加密数据
    def encrypt(self, plaintext):


    #解密数据
    def decrypt(self, ciphertext):
        




    