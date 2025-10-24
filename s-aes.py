import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QLabel, QLineEdit, QPushButton,
                             QTextEdit, QGroupBox, QTabWidget, QMessageBox,
                             QFormLayout, QComboBox)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QPalette, QColor


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


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # 设置应用程序字体
    font = QFont("Microsoft YaHei", 10)
    app.setFont(font)

    window = S_AES_UI()
    window.show()

    sys.exit(app.exec_())


    