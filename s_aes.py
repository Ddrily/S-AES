import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QLabel, QLineEdit, QPushButton,
                             QTextEdit, QGroupBox, QTabWidget, QMessageBox,
                             QFormLayout)
from PyQt5.QtGui import QFont


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

    # # 列混淆矩阵
    # MIX_COLUMNS_MATRIX = [
    #     [0x1, 0x4],
    #     [0x4, 0x1]
    # ]
    #
    # # 逆列混淆矩阵
    # INV_MIX_COLUMNS_MATRIX = [
    #     [0x9, 0x2],
    #     [0x2, 0x9]
    # ]

    # 初始化A-AES实例
    def __init__(self, key):
        if not (0 <= key < 0x10000):
            raise ValueError("密钥必须是16位二进制数")
        self.master_key = key
        self.round_keys = self.key_expansion(key)

    def _gf_mult(self, a, b):
        """GF(2^4)有限域乘法，使用本原多项式 x^4 + x + 1 (0x13)"""
        a &= 0xF
        b &= 0xF
        p = 0
        for _ in range(4):
            if b & 1:
                p ^= a
            carry = a & 0x8
            a = (a << 1) & 0x1F
            if carry:
                a ^= 0x13
            a &= 0xF
            b >>= 1
        return p & 0xF

    def _sub_nibble(self, nibble, s_box):
        return s_box[nibble & 0xF]

    def _sub_nibbles(self, state, s_box):
        """对整个状态进行S盒替换"""
        n0 = self._sub_nibble((state >> 12) & 0xF, s_box)
        n1 = self._sub_nibble((state >> 8) & 0xF, s_box)
        n2 = self._sub_nibble((state >> 4) & 0xF, s_box)
        n3 = self._sub_nibble(state & 0xF, s_box)
        return (n0 << 12) | (n1 << 8) | (n2 << 4) | n3

    def _shift_rows(self, state):
        """行移位：交换s1和s3"""
        s0 = (state >> 12) & 0xF
        s1 = (state >> 8) & 0xF
        s2 = (state >> 4) & 0xF
        s3 = state & 0xF
        # 交换s1和s3
        return (s0 << 12) | (s3 << 8) | (s2 << 4) | s1

    def _mix_columns(self, state):
        """列混淆"""
        s0 = (state >> 12) & 0xF
        s1 = (state >> 8) & 0xF
        s2 = (state >> 4) & 0xF
        s3 = state & 0xF

        # 第一列: [s0, s1]
        s0_new = s0 ^ self._gf_mult(4, s1)
        s1_new = self._gf_mult(4, s0) ^ s1

        # 第二列: [s2, s3]
        s2_new = s2 ^ self._gf_mult(4, s3)
        s3_new = self._gf_mult(4, s2) ^ s3

        return (s0_new << 12) | (s1_new << 8) | (s2_new << 4) | s3_new

    def _inv_mix_columns(self, state):
        """逆列混淆"""
        s0 = (state >> 12) & 0xF
        s1 = (state >> 8) & 0xF
        s2 = (state >> 4) & 0xF
        s3 = state & 0xF

        # 第一列: [s0, s1]
        s0_new = self._gf_mult(9, s0) ^ self._gf_mult(2, s1)
        s1_new = self._gf_mult(2, s0) ^ self._gf_mult(9, s1)

        # 第二列: [s2, s3]
        s2_new = self._gf_mult(9, s2) ^ self._gf_mult(2, s3)
        s3_new = self._gf_mult(2, s2) ^ self._gf_mult(9, s3)

        return (s0_new << 12) | (s1_new << 8) | (s2_new << 4) | s3_new

    def _rot_nib(self, byte_val):
        """旋转字节中的半字节"""
        return ((byte_val & 0x0F) << 4) | ((byte_val & 0xF0) >> 4)

    def _g_function(self, word, rcon):
        """密钥扩展中的g函数"""
        # RotNib: 交换两个半字节
        rotated = self._rot_nib(word)
        # SubNib: 对每个半字节进行S盒替换
        high = self._sub_nibble((rotated >> 4) & 0xF, self.S_BOX)
        low = self._sub_nibble(rotated & 0xF, self.S_BOX)
        subbed = (high << 4) | low
        # 异或轮常数
        return subbed ^ rcon

    def key_expansion(self, key):
        """密钥扩展"""
        w0 = (key >> 8) & 0xFF
        w1 = key & 0xFF

        # 第一轮扩展
        w2 = w0 ^ self._g_function(w1, self.RCON[0])
        w3 = w2 ^ w1

        # 第二轮扩展
        w4 = w2 ^ self._g_function(w3, self.RCON[1])
        w5 = w4 ^ w3

        # 生成轮密钥
        round_key0 = (w0 << 8) | w1
        round_key1 = (w2 << 8) | w3
        round_key2 = (w4 << 8) | w5

        return [round_key0, round_key1, round_key2]

    def encrypt_block(self, plaintext):
        """加密单个16位分组"""
        state = plaintext & 0xFFFF

        # 初始轮密钥加
        state ^= self.round_keys[0]

        # 第一轮
        state = self._sub_nibbles(state, self.S_BOX)
        state = self._shift_rows(state)
        state = self._mix_columns(state)
        state ^= self.round_keys[1]

        # 第二轮
        state = self._sub_nibbles(state, self.S_BOX)
        state = self._shift_rows(state)
        state ^= self.round_keys[2]

        return state

    def decrypt_block(self, ciphertext):
        """解密单个16位分组"""
        state = ciphertext & 0xFFFF

        # 初始轮密钥加
        state ^= self.round_keys[2]

        # 第一轮逆运算
        state = self._shift_rows(state)
        state = self._sub_nibbles(state, self.INV_S_BOX)
        state ^= self.round_keys[1]
        state = self._inv_mix_columns(state)

        # 第二轮逆运算
        state = self._shift_rows(state)
        state = self._sub_nibbles(state, self.INV_S_BOX)
        state ^= self.round_keys[0]

        return state

    def encrypt(self, plaintext):
        if isinstance(plaintext, str):
            if len(plaintext) != 16:
                raise ValueError('明文必须是16位二进制字符串')
            plaintext = int(plaintext, 2)
        return self.encrypt_block(plaintext)

    def decrypt(self, ciphertext):
        if isinstance(ciphertext, str):
            if len(ciphertext) != 16:
                raise ValueError('密文必须是16位二进制字符串')
            ciphertext = int(ciphertext, 2)
        return self.decrypt_block(ciphertext)

    # CBC模式加密
    def encrypt_cbc(self, plaintext_blocks, iv):
        """
        CBC模式加密
        plaintext_blocks: 16位二进制字符串列表
        iv: 16位初始向量（二进制字符串或整数）
        返回密文块列表
        """
        if isinstance(iv, str):
            iv = int(iv, 2)

        cipher_blocks = []
        previous = iv

        for block in plaintext_blocks:
            if isinstance(block, str):
                block_int = int(block, 2)
            else:
                block_int = block

            # 与前一个密文块（或IV）异或
            xored = block_int ^ previous
            # 加密
            encrypted = self.encrypt_block(xored)
            cipher_blocks.append(encrypted)
            previous = encrypted

        return cipher_blocks

    # CBC模式解密
    def decrypt_cbc(self, ciphertext_blocks, iv):
        """
        CBC模式解密
        ciphertext_blocks: 16位二进制字符串列表
        iv: 16位初始向量（二进制字符串或整数）
        返回明文块列表
        """
        if isinstance(iv, str):
            iv = int(iv, 2)

        plain_blocks = []
        previous = iv

        for block in ciphertext_blocks:
            if isinstance(block, str):
                block_int = int(block, 2)
            else:
                block_int = block

            # 解密
            decrypted = self.decrypt_block(block_int)
            # 与前一个密文块（或IV）异或
            xored = decrypted ^ previous
            plain_blocks.append(xored)
            previous = block_int

        return plain_blocks
#ASCII码转换
class ASCIIConverter:
    @staticmethod
    def text_to_binary(text):
        #将文本转换为16位二进制字符串列表
        binary_blocks = []
        for char in text:
            # 将每个字符转换为8位ASCII码
            ascii_value = ord(char)
            # 将8位ASCII码转换为16位二进制（高位补0）
            binary_block = format(ascii_value, '016b')
            binary_blocks.append(binary_block)
        return binary_blocks

    @staticmethod
    def binary_to_text(binary_blocks):
        #将16位二进制字符串列表转换为文本
        text = ""
        for binary_block in binary_blocks:
            if len(binary_block) == 16:
                # 将16位二进制转换为整数
                ascii_value = int(binary_block, 2)
                # 只处理有效的ASCII字符（0-127）
                if 0 <= ascii_value <= 127:
                    text += chr(ascii_value)
                else:
                    text += '?'  # 无效字符用?代替
        return text
    @staticmethod
    def encrypt_text(text,s_aes):
        #加密文本
        binary_blocks = ASCIIConverter.text_to_binary(text)
        encrypted_blocks = []

        for block in binary_blocks:
            encrypted_block = s_aes.encrypt(int(block,2))
            encrypted_blocks.append(format(encrypted_block, '016b'))

        return encrypted_blocks

    @staticmethod
    def decrypt_text(binary_blocks,s_aes):
        #解密ASCII密文
        decrypted_blocks = []

        for block in binary_blocks:
            if len(block) == 16:
                decrypted_block = s_aes.decrypt(int(block,2))
                decrypted_blocks.append(format(decrypted_block, '016b'))

        return ASCIIConverter.binary_to_text(decrypted_blocks)

    @staticmethod
    def encrypt_text_cbc(text, s_aes, iv):
        """CBC模式加密文本"""
        binary_blocks = ASCIIConverter.text_to_binary(text)
        encrypted_blocks = s_aes.encrypt_cbc(binary_blocks, iv)
        return [format(block, '016b') for block in encrypted_blocks]

    @staticmethod
    def decrypt_text_cbc(binary_blocks, s_aes, iv):
        """CBC模式解密文本"""
        decrypted_blocks = s_aes.decrypt_cbc(binary_blocks, iv)
        return ASCIIConverter.binary_to_text([format(block, '016b') for block in decrypted_blocks])
class DoubleS_AES:
    def __init__(self, key):
        if not (0 <= key < 0x100000000):
            raise ValueError("密钥必须是32位二进制数")
        self.key1 = (key >> 16) & 0xFFFF  # 高16位
        self.key2 = key & 0xFFFF  # 低16位
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
        self.key2 = key & 0xFFFF  # 低16位
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
#UI
class S_AES_UI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.s_aes = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("S-AES 加密解密工具")
        self.setGeometry(100, 100, 800, 700)

        # 设置样式
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 5px;
                margin-top: 1ex;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QPushButton {
                background-color: #4CAF50;
                border: none;
                color: white;
                padding: 8px 16px;
                text-align: center;
                text-decoration: none;
                font-size: 14px;
                margin: 4px 2px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3d8b40;
            }
            QLineEdit, QTextEdit {
                border: 1px solid #cccccc;
                border-radius: 3px;
                padding: 5px;
                font-family: Consolas, monospace;
            }
            QLabel {
                font-weight: bold;
            }
        """)

        # 创建中心部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # 主布局
        main_layout = QVBoxLayout(central_widget)

        # 创建标签页
        tab_widget = QTabWidget()
        main_layout.addWidget(tab_widget)

        # 密钥设置标签页
        self.setup_key_tab(tab_widget)

        # 加密标签页
        self.setup_encrypt_tab(tab_widget)

        # 解密标签页
        self.setup_decrypt_tab(tab_widget)

        #ASCII加密标签页
        self.setup_ascii_encrypt_tab(tab_widget)

        #ASCII解密标签页
        self.setup_ascii_decrypt_tab(tab_widget)

        #多重加密标签页
        self.setup_multi_encryption_tab(tab_widget)
        #cbc模式标签页
        self.setup_cbc_tab(tab_widget)

    def setup_key_tab(self, tab_widget):
        key_tab = QWidget()
        layout = QVBoxLayout(key_tab)

        # 密钥输入组
        key_group = QGroupBox("密钥设置")
        key_layout = QFormLayout(key_group)

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("输入16位二进制密钥，如：1010101010101010")
        self.key_input.textChanged.connect(self.validate_key_input)
        key_layout.addRow("密钥:", self.key_input)

        self.key_status = QLabel("等待输入...")
        self.key_status.setStyleSheet("color: gray;")
        key_layout.addRow("状态:", self.key_status)

        # 密钥操作按钮
        key_btn_layout = QHBoxLayout()
        self.set_key_btn = QPushButton("设置密钥")
        self.set_key_btn.clicked.connect(self.set_key)
        self.clear_key_btn = QPushButton("清空")
        self.clear_key_btn.clicked.connect(self.clear_key)

        key_btn_layout.addWidget(self.set_key_btn)
        key_btn_layout.addWidget(self.clear_key_btn)
        key_layout.addRow("操作:", key_btn_layout)

        # 轮密钥显示
        round_key_group = QGroupBox("轮密钥信息")
        round_key_layout = QVBoxLayout(round_key_group)

        self.round_key_display = QTextEdit()
        self.round_key_display.setReadOnly(True)
        self.round_key_display.setMaximumHeight(150)
        round_key_layout.addWidget(self.round_key_display)

        layout.addWidget(key_group)
        layout.addWidget(round_key_group)
        layout.addStretch()

        tab_widget.addTab(key_tab, "密钥设置")

    def setup_encrypt_tab(self, tab_widget):
        encrypt_tab = QWidget()
        layout = QVBoxLayout(encrypt_tab)

        # 明文输入组
        plaintext_group = QGroupBox("明文输入")
        plaintext_layout = QVBoxLayout(plaintext_group)

        self.plaintext_input = QTextEdit()
        self.plaintext_input.setPlaceholderText("输入16位二进制明文，如：1100110011001100")
        self.plaintext_input.setMaximumHeight(100)
        plaintext_layout.addWidget(self.plaintext_input)

        # 加密操作
        encrypt_btn_layout = QHBoxLayout()
        self.encrypt_btn = QPushButton("加密")
        self.encrypt_btn.clicked.connect(self.encrypt)
        self.clear_encrypt_btn = QPushButton("清空")
        self.clear_encrypt_btn.clicked.connect(self.clear_encrypt)

        encrypt_btn_layout.addWidget(self.encrypt_btn)
        encrypt_btn_layout.addWidget(self.clear_encrypt_btn)
        plaintext_layout.addLayout(encrypt_btn_layout)

        # 密文输出组
        ciphertext_group = QGroupBox("密文输出")
        ciphertext_layout = QVBoxLayout(ciphertext_group)

        self.ciphertext_output = QTextEdit()
        self.ciphertext_output.setReadOnly(True)
        ciphertext_layout.addWidget(self.ciphertext_output)

        layout.addWidget(plaintext_group)
        layout.addWidget(ciphertext_group)
        layout.addStretch()

        tab_widget.addTab(encrypt_tab, "加密")

    def setup_decrypt_tab(self, tab_widget):
        decrypt_tab = QWidget()
        layout = QVBoxLayout(decrypt_tab)

        # 密文输入组
        ciphertext_group = QGroupBox("密文输入")
        ciphertext_layout = QVBoxLayout(ciphertext_group)

        self.ciphertext_input = QTextEdit()
        self.ciphertext_input.setPlaceholderText("输入16位二进制密文")
        self.ciphertext_input.setMaximumHeight(100)
        ciphertext_layout.addWidget(self.ciphertext_input)

        # 解密操作
        decrypt_btn_layout = QHBoxLayout()
        self.decrypt_btn = QPushButton("解密")
        self.decrypt_btn.clicked.connect(self.decrypt)
        self.clear_decrypt_btn = QPushButton("清空")
        self.clear_decrypt_btn.clicked.connect(self.clear_decrypt)

        decrypt_btn_layout.addWidget(self.decrypt_btn)
        decrypt_btn_layout.addWidget(self.clear_decrypt_btn)
        ciphertext_layout.addLayout(decrypt_btn_layout)

        # 明文输出组
        plaintext_group = QGroupBox("明文输出")
        plaintext_layout = QVBoxLayout(plaintext_group)

        self.plaintext_output = QTextEdit()
        self.plaintext_output.setReadOnly(True)
        plaintext_layout.addWidget(self.plaintext_output)

        layout.addWidget(ciphertext_group)
        layout.addWidget(plaintext_group)
        layout.addStretch()

        tab_widget.addTab(decrypt_tab, "解密")

    def setup_ascii_encrypt_tab(self, tab_widget):
        ascii_encrypt_tab = QWidget()
        layout = QVBoxLayout(ascii_encrypt_tab)
        #ASCII文本输入组
        ascii_input_group = QGroupBox('ASCII文本输入')
        ascii_input_layout = QVBoxLayout(ascii_input_group)

        self.ascii_plaintext_input = QTextEdit()
        self.ascii_plaintext_input.setPlaceholderText("输入要加密的文本")
        self.ascii_plaintext_input.setMaximumHeight(100)
        ascii_input_layout.addWidget(self.ascii_plaintext_input)

        #ASCII加密操作
        ascii_encrypt_btn_layout = QHBoxLayout()
        self.ascii_encrypt_btn = QPushButton("加密文本")
        self.ascii_encrypt_btn.clicked.connect(self.encrypt_ascii)
        self.clear_ascii_encrypt_btn = QPushButton("清空")
        self.clear_ascii_encrypt_btn.clicked.connect(self.clear_ascii_encrypt)

        ascii_encrypt_btn_layout.addWidget(self.ascii_encrypt_btn)
        ascii_encrypt_btn_layout.addWidget(self.clear_ascii_encrypt_btn)
        ascii_input_layout.addLayout(ascii_encrypt_btn_layout)

        # ASCII密文输出组
        ascii_output_group = QGroupBox("加密结果")
        ascii_output_layout = QVBoxLayout(ascii_output_group)

        self.ascii_ciphertext_output = QTextEdit()
        self.ascii_ciphertext_output.setReadOnly(True)
        ascii_output_layout.addWidget(self.ascii_ciphertext_output)

        layout.addWidget(ascii_input_group)
        layout.addWidget(ascii_output_group)
        layout.addStretch()

        tab_widget.addTab(ascii_encrypt_tab, "ASCII加密")

    def setup_ascii_decrypt_tab(self, tab_widget):
        ascii_decrypt_tab = QWidget()
        layout = QVBoxLayout(ascii_decrypt_tab)

        # ASCII密文输入组
        ascii_ciphertext_group = QGroupBox("ASCII密文输入")
        ascii_ciphertext_layout = QVBoxLayout(ascii_ciphertext_group)

        self.ascii_ciphertext_input = QTextEdit()
        self.ascii_ciphertext_input.setPlaceholderText("每行输入一个16位二进制密文块")
        self.ascii_ciphertext_input.setMaximumHeight(100)
        ascii_ciphertext_layout.addWidget(self.ascii_ciphertext_input)

        # ASCII解密操作
        ascii_decrypt_btn_layout = QHBoxLayout()
        self.ascii_decrypt_btn = QPushButton("解密文本")
        self.ascii_decrypt_btn.clicked.connect(self.decrypt_ascii)
        self.clear_ascii_decrypt_btn = QPushButton("清空")
        self.clear_ascii_decrypt_btn.clicked.connect(self.clear_ascii_decrypt)

        ascii_decrypt_btn_layout.addWidget(self.ascii_decrypt_btn)
        ascii_decrypt_btn_layout.addWidget(self.clear_ascii_decrypt_btn)
        ascii_ciphertext_layout.addLayout(ascii_decrypt_btn_layout)

        # ASCII解密输出组
        ascii_decrypt_output_group = QGroupBox("解密结果")
        ascii_decrypt_output_layout = QVBoxLayout(ascii_decrypt_output_group)

        self.ascii_decrypt_output = QTextEdit()
        self.ascii_decrypt_output.setReadOnly(True)
        ascii_decrypt_output_layout.addWidget(self.ascii_decrypt_output)

        layout.addWidget(ascii_ciphertext_group)
        layout.addWidget(ascii_decrypt_output_group)
        layout.addStretch()

        tab_widget.addTab(ascii_decrypt_tab, "ASCII解密")
    def setup_multi_encryption_tab(self, tab_widget):
        multi_tab = QWidget()
        layout = QVBoxLayout(multi_tab)

        # 双重加密组
        double_group = QGroupBox("双重S-AES加密")
        double_layout = QFormLayout(double_group)

        self.double_key_input = QLineEdit()
        self.double_key_input.setPlaceholderText("输入32位二进制密钥，如：10101010101010101010101010101010")
        double_layout.addRow("双重加密密钥:", self.double_key_input)

        self.double_plaintext_input = QLineEdit()
        self.double_plaintext_input.setPlaceholderText("输入16位二进制明密文")
        double_layout.addRow("明密文:", self.double_plaintext_input)

        double_btn_layout = QHBoxLayout()
        self.double_encrypt_btn = QPushButton("双重加密")
        self.double_encrypt_btn.clicked.connect(self.double_encrypt)
        self.double_decrypt_btn = QPushButton("双重解密")
        self.double_decrypt_btn.clicked.connect(self.double_decrypt)

        double_btn_layout.addWidget(self.double_encrypt_btn)
        double_btn_layout.addWidget(self.double_decrypt_btn)
        double_layout.addRow("操作:", double_btn_layout)

        self.double_result_output = QTextEdit()
        self.double_result_output.setReadOnly(True)
        self.double_result_output.setMaximumHeight(100)
        double_layout.addRow("结果:", self.double_result_output)

        # 三重加密组
        triple_group = QGroupBox("三重S-AES加密")
        triple_layout = QFormLayout(triple_group)

        self.triple_key_input = QLineEdit()
        self.triple_key_input.setPlaceholderText("输入32位二进制密钥")
        triple_layout.addRow("三重加密密钥:", self.triple_key_input)

        self.triple_plaintext_input = QLineEdit()
        self.triple_plaintext_input.setPlaceholderText("输入16位二进制明密文")
        triple_layout.addRow("明密文:", self.triple_plaintext_input)

        triple_btn_layout = QHBoxLayout()
        self.triple_encrypt_btn = QPushButton("三重加密")
        self.triple_encrypt_btn.clicked.connect(self.triple_encrypt)
        self.triple_decrypt_btn = QPushButton("三重解密")
        self.triple_decrypt_btn.clicked.connect(self.triple_decrypt)

        triple_btn_layout.addWidget(self.triple_encrypt_btn)
        triple_btn_layout.addWidget(self.triple_decrypt_btn)
        triple_layout.addRow("操作:", triple_btn_layout)

        self.triple_result_output = QTextEdit()
        self.triple_result_output.setReadOnly(True)
        self.triple_result_output.setMaximumHeight(100)
        triple_layout.addRow("结果:", self.triple_result_output)

        # 中间相遇攻击组
        attack_group = QGroupBox("中间相遇攻击")
        attack_layout = QVBoxLayout(attack_group)

        attack_input_layout = QHBoxLayout()
        self.attack_plaintext_input = QLineEdit()
        self.attack_plaintext_input.setPlaceholderText("已知明文")
        self.attack_ciphertext_input = QLineEdit()
        self.attack_ciphertext_input.setPlaceholderText("对应密文")

        attack_input_layout.addWidget(QLabel("明文:"))
        attack_input_layout.addWidget(self.attack_plaintext_input)
        attack_input_layout.addWidget(QLabel("密文:"))
        attack_input_layout.addWidget(self.attack_ciphertext_input)

        self.attack_btn = QPushButton("执行中间相遇攻击")
        self.attack_btn.clicked.connect(self.meet_in_middle_attack)

        self.attack_result_output = QTextEdit()
        self.attack_result_output.setReadOnly(True)
        self.attack_result_output.setMaximumHeight(150)

        attack_layout.addLayout(attack_input_layout)
        attack_layout.addWidget(self.attack_btn)
        attack_layout.addWidget(self.attack_result_output)

        layout.addWidget(double_group)
        layout.addWidget(triple_group)
        layout.addWidget(attack_group)
        layout.addStretch()

        tab_widget.addTab(multi_tab, "多重加密")

    def setup_cbc_tab(self, tab_widget):
        cbc_tab = QWidget()
        layout = QVBoxLayout(cbc_tab)

        # CBC加密组
        cbc_encrypt_group = QGroupBox("CBC模式加密")
        cbc_encrypt_layout = QFormLayout(cbc_encrypt_group)

        self.cbc_iv_input = QLineEdit()
        self.cbc_iv_input.setPlaceholderText("输入16位二进制初始向量(IV)")
        cbc_encrypt_layout.addRow("初始向量(IV):", self.cbc_iv_input)

        self.cbc_plaintext_input = QTextEdit()
        self.cbc_plaintext_input.setPlaceholderText("输入要加密的文本")
        self.cbc_plaintext_input.setMaximumHeight(80)
        cbc_encrypt_layout.addRow("明文:", self.cbc_plaintext_input)

        cbc_encrypt_btn_layout = QHBoxLayout()
        self.cbc_encrypt_btn = QPushButton("CBC加密")
        self.cbc_encrypt_btn.clicked.connect(self.cbc_encrypt)
        self.clear_cbc_encrypt_btn = QPushButton("清空")
        self.clear_cbc_encrypt_btn.clicked.connect(self.clear_cbc_encrypt)

        cbc_encrypt_btn_layout.addWidget(self.cbc_encrypt_btn)
        cbc_encrypt_btn_layout.addWidget(self.clear_cbc_encrypt_btn)
        cbc_encrypt_layout.addRow("操作:", cbc_encrypt_btn_layout)

        self.cbc_ciphertext_output = QTextEdit()
        self.cbc_ciphertext_output.setReadOnly(True)
        self.cbc_ciphertext_output.setMaximumHeight(120)
        cbc_encrypt_layout.addRow("加密结果:", self.cbc_ciphertext_output)

        # CBC解密组
        cbc_decrypt_group = QGroupBox("CBC模式解密")
        cbc_decrypt_layout = QFormLayout(cbc_decrypt_group)

        self.cbc_decrypt_iv_input = QLineEdit()
        self.cbc_decrypt_iv_input.setPlaceholderText("输入16位二进制初始向量(IV)")
        cbc_decrypt_layout.addRow("初始向量(IV):", self.cbc_decrypt_iv_input)

        self.cbc_ciphertext_input = QTextEdit()
        self.cbc_ciphertext_input.setPlaceholderText("每行输入一个16位二进制密文块")
        self.cbc_ciphertext_input.setMaximumHeight(80)
        cbc_decrypt_layout.addRow("密文块:", self.cbc_ciphertext_input)

        cbc_decrypt_btn_layout = QHBoxLayout()
        self.cbc_decrypt_btn = QPushButton("CBC解密")
        self.cbc_decrypt_btn.clicked.connect(self.cbc_decrypt)
        self.clear_cbc_decrypt_btn = QPushButton("清空")
        self.clear_cbc_decrypt_btn.clicked.connect(self.clear_cbc_decrypt)

        cbc_decrypt_btn_layout.addWidget(self.cbc_decrypt_btn)
        cbc_decrypt_btn_layout.addWidget(self.clear_cbc_decrypt_btn)
        cbc_decrypt_layout.addRow("操作:", cbc_decrypt_btn_layout)

        self.cbc_decrypt_output = QTextEdit()
        self.cbc_decrypt_output.setReadOnly(True)
        self.cbc_decrypt_output.setMaximumHeight(120)
        cbc_decrypt_layout.addRow("解密结果:", self.cbc_decrypt_output)

        layout.addWidget(cbc_encrypt_group)
        layout.addWidget(cbc_decrypt_group)
        layout.addStretch()

        tab_widget.addTab(cbc_tab, "CBC模式")
    def validate_key_input(self, text):
        if not text:
            self.key_status.setText("等待输入...")
            self.key_status.setStyleSheet("color: gray;")
            return

        if len(text) != 16:
            self.key_status.setText("密钥长度必须为16位")
            self.key_status.setStyleSheet("color: red;")
            return

        if all(c in '01' for c in text):
            self.key_status.setText("格式正确")
            self.key_status.setStyleSheet("color: green;")
        else:
            self.key_status.setText("只能包含0和1")
            self.key_status.setStyleSheet("color: red;")

    def set_key(self):
        key_text = self.key_input.text().strip()

        if len(key_text) != 16:
            QMessageBox.warning(self, "错误", "密钥长度必须为16位！")
            return

        if not all(c in '01' for c in key_text):
            QMessageBox.warning(self, "错误", "密钥只能包含0和1！")
            return

        try:
            key_int = int(key_text, 2)
            self.s_aes = S_AES(key_int)

            # 显示轮密钥信息
            round_keys = self.s_aes.round_keys
            key_info = f"主密钥: {key_text}\n\n"
            key_info += f"轮密钥 0: {format(round_keys[0], '016b')}\n"
            key_info += f"轮密钥 1: {format(round_keys[1], '016b')}\n"
            key_info += f"轮密钥 2: {format(round_keys[2], '016b')}"

            self.round_key_display.setText(key_info)
            QMessageBox.information(self, "成功", "密钥设置成功！")

        except Exception as e:
            QMessageBox.critical(self, "错误", f"设置密钥时发生错误：{str(e)}")

    def clear_key(self):
        self.key_input.clear()
        self.round_key_display.clear()
        self.s_aes = None
        self.key_status.setText("等待输入...")
        self.key_status.setStyleSheet("color: gray;")

    def encrypt(self):
        if self.s_aes is None:
            QMessageBox.warning(self, "错误", "请先设置密钥！")
            return

        plaintext = self.plaintext_input.toPlainText().strip()

        if len(plaintext) != 16:
            QMessageBox.warning(self, "错误", "明文长度必须为16位！")
            return

        if not all(c in '01' for c in plaintext):
            QMessageBox.warning(self, "错误", "明文只能包含0和1！")
            return

        try:
            ciphertext = self.s_aes.encrypt(plaintext)
            ciphertext_bin = format(ciphertext, '016b')
            ciphertext_hex = format(ciphertext, '04X')

            result = f"明文: {plaintext}\n"
            result += f"密文(二进制): {ciphertext_bin}\n"
            result += f"密文(十六进制): {ciphertext_hex}"

            self.ciphertext_output.setText(result)

        except Exception as e:
            QMessageBox.critical(self, "错误", f"加密时发生错误：{str(e)}")

    def decrypt(self):
        if self.s_aes is None:
            QMessageBox.warning(self, "错误", "请先设置密钥！")
            return

        ciphertext = self.ciphertext_input.toPlainText().strip()

        if len(ciphertext) != 16:
            QMessageBox.warning(self, "错误", "密文长度必须为16位！")
            return

        if not all(c in '01' for c in ciphertext):
            QMessageBox.warning(self, "错误", "密文只能包含0和1！")
            return

        try:
            plaintext = self.s_aes.decrypt(ciphertext)
            plaintext_bin = format(plaintext, '016b')
            plaintext_hex = format(plaintext, '04X')

            result = f"密文: {ciphertext}\n"
            result += f"明文(二进制): {plaintext_bin}\n"
            result += f"明文(十六进制): {plaintext_hex}"

            self.plaintext_output.setText(result)

        except Exception as e:
            QMessageBox.critical(self, "错误", f"解密时发生错误：{str(e)}")

    def encrypt_ascii(self):
        if self.s_aes is None:
            QMessageBox.warning(self, "错误", "请先设置密钥！")
            return

        text = self.ascii_plaintext_input.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, "错误", "请输入要加密的文本！")
            return

        try:
            encrypted_blocks = ASCIIConverter.encrypt_text(text, self.s_aes)

            result = f"原始文本: {text}\n"
            result += f"文本长度: {len(text)} 字符\n\n"
            result += "加密后的二进制块:\n"
            for i, block in enumerate(encrypted_blocks):
                result += f"块 {i + 1}: {block}\n"

            result += f"\n所有块连接: {''.join(encrypted_blocks)}"

            self.ascii_ciphertext_output.setText(result)

        except Exception as e:
            QMessageBox.critical(self, "错误", f"加密文本时发生错误：{str(e)}")

    def decrypt_ascii(self):
        if self.s_aes is None:
            QMessageBox.warning(self, "错误", "请先设置密钥！")
            return

        ciphertext_input = self.ascii_ciphertext_input.toPlainText().strip()
        if not ciphertext_input:
            QMessageBox.warning(self, "错误", "请输入要解密的密文块！")
            return

        try:
            # 处理输入：可以是多行或单个长字符串
            if '\n' in ciphertext_input:
                # 多行输入，每行一个16位块
                binary_blocks = [line.strip() for line in ciphertext_input.split('\n') if line.strip()]
            else:
                # 单个长字符串，按16位分割
                binary_blocks = [ciphertext_input[i:i + 16] for i in range(0, len(ciphertext_input), 16)]

            # 验证所有块都是16位二进制
            for block in binary_blocks:
                if len(block) != 16 or not all(c in '01' for c in block):
                    QMessageBox.warning(self, "错误", f"无效的二进制块: {block}")
                    return

            decrypted_text = ASCIIConverter.decrypt_text(binary_blocks, self.s_aes)

            result = f"解密结果: {decrypted_text}\n\n"
            result += f"处理的块数量: {len(binary_blocks)}\n"
            result += "处理的块:\n"
            for i, block in enumerate(binary_blocks):
                result += f"块 {i + 1}: {block}\n"

            self.ascii_decrypt_output.setText(result)

        except Exception as e:
            QMessageBox.critical(self, "错误", f"解密文本时发生错误：{str(e)}")

    def double_encrypt(self):
        key_text = self.double_key_input.text().strip()
        plaintext = self.double_plaintext_input.text().strip()

        if len(key_text) != 32:
            QMessageBox.warning(self, "错误", "双重加密密钥必须是32位！")
            return

        if len(plaintext) != 16:
            QMessageBox.warning(self, "错误", "明文必须是16位！")
            return

        try:
            key_int = int(key_text, 2)
            plaintext_int = int(plaintext, 2)

            double_aes = DoubleS_AES(key_int)
            ciphertext = double_aes.encrypt(plaintext_int)

            result = f"双重加密结果:\n"
            result += f"密钥: {key_text}\n"
            result += f"明文: {plaintext}\n"
            result += f"密文(二进制): {format(ciphertext, '016b')}\n"
            result += f"密文(十六进制): {format(ciphertext, '04X')}"

            self.double_result_output.setText(result)

        except Exception as e:
            QMessageBox.critical(self, "错误", f"双重加密失败: {str(e)}")

    def double_decrypt(self):
        key_text = self.double_key_input.text().strip()
        ciphertext = self.double_plaintext_input.text().strip()  # 这里应该是密文输入

        if len(key_text) != 32:
            QMessageBox.warning(self, "错误", "双重加密密钥必须是32位！")
            return

        if len(ciphertext) != 16:
            QMessageBox.warning(self, "错误", "密文必须是16位！")
            return

        try:
            key_int = int(key_text, 2)
            ciphertext_int = int(ciphertext, 2)

            double_aes = DoubleS_AES(key_int)
            plaintext = double_aes.decrypt(ciphertext_int)

            result = f"双重解密结果:\n"
            result += f"密钥: {key_text}\n"
            result += f"密文: {ciphertext}\n"
            result += f"明文(二进制): {format(plaintext, '016b')}\n"
            result += f"明文(十六进制): {format(plaintext, '04X')}"

            self.double_result_output.setText(result)

        except Exception as e:
            QMessageBox.critical(self, "错误", f"双重解密失败: {str(e)}")

    def triple_encrypt(self):
        key_text = self.triple_key_input.text().strip()
        plaintext = self.triple_plaintext_input.text().strip()

        if len(key_text) != 32:
            QMessageBox.warning(self, "错误", "三重加密密钥必须是32位！")
            return

        if len(plaintext) != 16:
            QMessageBox.warning(self, "错误", "明文必须是16位！")
            return

        try:
            key_int = int(key_text, 2)
            plaintext_int = int(plaintext, 2)

            triple_aes = TripleS_AES(key_int)
            ciphertext = triple_aes.encrypt(plaintext_int)

            result = f"三重加密结果:\n"
            result += f"密钥: {key_text}\n"
            result += f"明文: {plaintext}\n"
            result += f"密文(二进制): {format(ciphertext, '016b')}\n"
            result += f"密文(十六进制): {format(ciphertext, '04X')}"

            self.triple_result_output.setText(result)

        except Exception as e:
            QMessageBox.critical(self, "错误", f"三重加密失败: {str(e)}")

    def triple_decrypt(self):
        key_text = self.triple_key_input.text().strip()
        ciphertext = self.triple_plaintext_input.text().strip()  # 这里应该是密文输入

        if len(key_text) != 32:
            QMessageBox.warning(self, "错误", "三重加密密钥必须是32位！")
            return

        if len(ciphertext) != 16:
            QMessageBox.warning(self, "错误", "密文必须是16位！")
            return

        try:
            key_int = int(key_text, 2)
            ciphertext_int = int(ciphertext, 2)

            triple_aes = TripleS_AES(key_int)
            plaintext = triple_aes.decrypt(ciphertext_int)

            result = f"三重解密结果:\n"
            result += f"密钥: {key_text}\n"
            result += f"密文: {ciphertext}\n"
            result += f"明文(二进制): {format(plaintext, '016b')}\n"
            result += f"明文(十六进制): {format(plaintext, '04X')}"

            self.triple_result_output.setText(result)

        except Exception as e:
            QMessageBox.critical(self, "错误", f"三重解密失败: {str(e)}")

    def meet_in_middle_attack(self):
        plaintext = self.attack_plaintext_input.text().strip()
        ciphertext = self.attack_ciphertext_input.text().strip()

        if len(plaintext) != 16 or len(ciphertext) != 16:
            QMessageBox.warning(self, "错误", "明文和密文都必须是16位！")
            return

        try:
            plaintext_int = int(plaintext, 2)
            ciphertext_int = int(ciphertext, 2)

            # 执行中间相遇攻击
            known_pairs = [(plaintext_int, ciphertext_int)]
            attack = MeetInMiddleAttack(known_pairs)
            candidate_keys = attack.find_key()

            result = f"中间相遇攻击结果:\n"
            result += f"已知明文: {plaintext}\n"
            result += f"已知密文: {ciphertext}\n\n"
            result += f"找到 {len(candidate_keys)} 个可能的密钥对:\n"

            for i, (k1, k2) in enumerate(candidate_keys):
                result += f"密钥对 {i + 1}: K1={format(k1, '016b')}, K2={format(k2, '016b')}\n"

            self.attack_result_output.setText(result)

        except Exception as e:
            QMessageBox.critical(self, "错误", f"中间相遇攻击失败: {str(e)}")

    # CBC加密方法
    def cbc_encrypt(self):
        if self.s_aes is None:
            QMessageBox.warning(self, "错误", "请先设置密钥！")
            return

        iv_text = self.cbc_iv_input.text().strip()
        text = self.cbc_plaintext_input.toPlainText().strip()

        if not iv_text:
            QMessageBox.warning(self, "错误", "请输入初始向量(IV)！")
            return

        if len(iv_text) != 16:
            QMessageBox.warning(self, "错误", "初始向量必须是16位二进制！")
            return

        if not all(c in '01' for c in iv_text):
            QMessageBox.warning(self, "错误", "初始向量只能包含0和1！")
            return

        if not text:
            QMessageBox.warning(self, "错误", "请输入要加密的文本！")
            return

        try:
            encrypted_blocks = ASCIIConverter.encrypt_text_cbc(text, self.s_aes, iv_text)

            result = f"原始文本: {text}\n"
            result += f"初始向量: {iv_text}\n"
            result += f"文本长度: {len(text)} 字符\n\n"
            result += "CBC加密后的二进制块:\n"
            for i, block in enumerate(encrypted_blocks):
                result += f"块 {i + 1}: {block}\n"

            result += f"\n所有块连接: {''.join(encrypted_blocks)}"

            self.cbc_ciphertext_output.setText(result)

        except Exception as e:
            QMessageBox.critical(self, "错误", f"CBC加密时发生错误：{str(e)}")

    # CBC解密方法
    def cbc_decrypt(self):
        if self.s_aes is None:
            QMessageBox.warning(self, "错误", "请先设置密钥！")
            return

        iv_text = self.cbc_decrypt_iv_input.text().strip()
        ciphertext_input = self.cbc_ciphertext_input.toPlainText().strip()

        if not iv_text:
            QMessageBox.warning(self, "错误", "请输入初始向量(IV)！")
            return

        if len(iv_text) != 16:
            QMessageBox.warning(self, "错误", "初始向量必须是16位二进制！")
            return

        if not all(c in '01' for c in iv_text):
            QMessageBox.warning(self, "错误", "初始向量只能包含0和1！")
            return

        if not ciphertext_input:
            QMessageBox.warning(self, "错误", "请输入要解密的密文块！")
            return

        try:
            # 处理输入：可以是多行或单个长字符串
            if '\n' in ciphertext_input:
                # 多行输入，每行一个16位块
                binary_blocks = [line.strip() for line in ciphertext_input.split('\n') if line.strip()]
            else:
                # 单个长字符串，按16位分割
                binary_blocks = [ciphertext_input[i:i + 16] for i in range(0, len(ciphertext_input), 16)]

            # 验证所有块都是16位二进制
            for block in binary_blocks:
                if len(block) != 16 or not all(c in '01' for c in block):
                    QMessageBox.warning(self, "错误", f"无效的二进制块: {block}")
                    return

            decrypted_text = ASCIIConverter.decrypt_text_cbc(binary_blocks, self.s_aes, iv_text)

            result = f"解密结果: {decrypted_text}\n\n"
            result += f"初始向量: {iv_text}\n"
            result += f"处理的块数量: {len(binary_blocks)}\n"
            result += "处理的块:\n"
            for i, block in enumerate(binary_blocks):
                result += f"块 {i + 1}: {block}\n"

            self.cbc_decrypt_output.setText(result)

        except Exception as e:
            QMessageBox.critical(self, "错误", f"CBC解密时发生错误：{str(e)}")

    def clear_encrypt(self):
        self.plaintext_input.clear()
        self.ciphertext_output.clear()

    def clear_decrypt(self):
        self.ciphertext_input.clear()
        self.plaintext_output.clear()

    def clear_ascii_encrypt(self):
        self.ascii_plaintext_input.clear()
        self.ascii_ciphertext_output.clear()

    def clear_ascii_decrypt(self):
        self.ascii_ciphertext_input.clear()
        self.ascii_decrypt_output.clear()

    # 清空CBC加密输入输出
    def clear_cbc_encrypt(self):
        self.cbc_iv_input.clear()
        self.cbc_plaintext_input.clear()
        self.cbc_ciphertext_output.clear()

    # 清空CBC解密输入输出
    def clear_cbc_decrypt(self):
        self.cbc_decrypt_iv_input.clear()
        self.cbc_ciphertext_input.clear()
        self.cbc_decrypt_output.clear()


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # 设置应用程序字体
    font = QFont("Microsoft YaHei", 10)
    app.setFont(font)

    window = S_AES_UI()
    window.show()

    sys.exit(app.exec_())


    
