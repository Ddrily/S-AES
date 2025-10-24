import numpy as np
s_box = [[9,4,10,11],[13,1,8,5],[6,2,0,3],[12,14,15,7]]
s_box_inv = [[10,5,9,11],[1,7,8,15],[6,0,2,3],[12,4,13,14]]
def AddRoundKey(state_matrix,round_key):
    return
def SubBytes(key):
    key2= None
    key3= None
    return key2,key3
def ShiftRows(state_matrix):
    return
def MixColumns(state_matrix):
    return


def encrypt(plaintext,key):#明文分组是16位二进制字符串，密钥是16位
    p = plaintext
    state_matrix=[[p[0],p[1],p[2],p[3]],
                   [p[4],p[5],p[6],p[7]],
                  [p[8],p[9],p[10],p[11]],
                  [p[12],p[13],p[14],p[15]]]
    #轮密钥加
    state_matrix = AddRoundKey(state_matrix,key)
    #扩展轮密钥
    key2,key3 = SubBytes(key)
    #半字节替换
    state_matrix = SubBytes(state_matrix)
    #行移位
    state_matrix = ShiftRows(state_matrix)
    #列混淆
    state_matrix = MixColumns(state_matrix)
    #第二次轮密钥加
    state_matrix = AddRoundKey(state_matrix,key2)
    #第二轮
    #半字节替换
    state_matrix = SubBytes(state_matrix)
    #行位移
    state_matrix = ShiftRows(state_matrix)
    #第三次轮密钥加
    ciphertext = AddRoundKey(state_matrix,key3)
    return ciphertext


