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

    #初始化A-AES实例
    def __init__(self,key):
        if not (0 <= key < 0x10000):
            raise ValueError("密钥必须是16位整数")
        self.master_key = key
        self.round_keys = self.key_expansion(key)


    #将16位整数转换为2✖2状态矩阵
    def int_to_state(value):
        return [[(value>>12) & 0xF,(value>>8) & 0xF],
                [(value>>4) & 0xF,value & 0xF]
                ]

    #将2✖2状态矩阵转化为16位整数
    def state_to_int(state):
        return (state[0][0] << 12) | (state[0][1] << 8) | (state[1][0] << 4) | state[1][1]



    #旋转半字节（用于密钥扩展）
    def rot_nibble(nibble):

    #半字节替代
    def sub_nibble(nibble, s_box):

    #密钥扩展
    def key_expansion(self, key):


    #轮密钥加
    def add_round_key(self, state, round_key):
        #判断明文是否满足16位
        if len(state) != 16:
            raise ValueError("明文必须是16bits")
        
        new_state = state^roundkey
        return new_state

    #半字节替代*    
    def sub_nibbles(self, state, s_box):
        
        
    #行移位
    def shift_rows(self, state):


    #GF(2^4)乘法
    def gf_mult(self, a, b):


    #列混淆
    def mix_columns(self, state, matrix):


    #加密单个16位分组
    def encrypt_block(self, plaintext):


    #解密单个16位分组
    def decrypt_block(self, ciphertext):


    #加密数据
    def encrypt(self, plaintext):


    #解密数据
    def decrypt(self, ciphertext):
        




    