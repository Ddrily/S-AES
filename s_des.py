"""
DES加密算法过程：
1.任意长度明文按64bit分块，不足则填充
2.分块明文进行初始置换，输出新的64位数据块
3.加密轮次（共16次），每个轮次包含四个步骤
    a.将64位数据块分为左右两个32位块
    b.右侧32位块作为输入，经过扩展、异或、置换等操作生成一个48位数据块（轮密钥），这是根据加密算法的主密钥生成的子密钥
    c.将左侧32位块和轮密钥进行异或运算，输出作为右侧新的32位块
    d.将右侧32位块与原来的左侧32位块进行连接，生存一个新的64位数据块，作为下一轮的输入
4.在最后一个轮次完成后，将经过加密的数据块进行末置换，得到64位密文
"""
import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
                             QGroupBox, QRadioButton, QLineEdit, QPushButton,
                             QTextEdit, QLabel, QWidget, QMessageBox)

# 置换表
IP = [2, 6, 3, 1, 4, 8, 5, 7]  # 初始
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]  # 最终
EP = [4, 1, 2, 3, 2, 3, 4, 1]  # 扩展
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]  # 密钥置换1
P8 = [6, 3, 7, 4, 8, 5, 10, 9]  # 密钥置换2
P4 = [2, 4, 3, 1]  # 轮内置换

# S盒定义
S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
]

S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
]


# 通用置换函数
def permute(input_bits, table):
    return ''.join(input_bits[i - 1] for i in table)


# 循环左移
def left_shift(bits, n):
    return bits[n:] + bits[:n]


# 密钥生成
def generate_keys(key):
    if len(key) != 10:
        raise ValueError("密钥必须是10位二进制字符串")

    key_perm = permute(key, P10)

    left = left_shift(key_perm[:5], 1)
    right = left_shift(key_perm[5:], 1)

    # k1生成
    k1 = permute(left + right, P8)

    left1 = left_shift(left, 2)
    right1 = left_shift(right, 2)

    # k2生成
    k2 = permute(left1 + right1, P8)

    return k1, k2


# 轮函数
def f_k(bits, key):
    left, right = bits[:4], bits[4:]

    expanded = permute(right, EP)

    # 与子密钥异或
    xor_result = ''.join(str(int(a) ^ int(b)) for a, b in zip(expanded, key))

    s0_in = xor_result[:4]
    s1_in = xor_result[4:]

    # S0盒处理 - 修正索引计算
    row0 = int(s0_in[0] + s0_in[3], 2)  # 修正：使用s0_in而不是s1_in
    col0 = int(s0_in[1] + s0_in[2], 2)
    s0_out = bin(S0[row0][col0])[2:].zfill(2)

    # S1盒处理
    row1 = int(s1_in[0] + s1_in[3], 2)
    col1 = int(s1_in[1] + s1_in[2], 2)
    s1_out = bin(S1[row1][col1])[2:].zfill(2)

    # P4置换
    s_out = s0_out + s1_out
    p4_result = permute(s_out, P4)

    new_left = ''.join(str(int(a) ^ int(b)) for a, b in zip(left, p4_result))

    return new_left + right


# S_DES加密函数
def encrypt(plaintext, key):
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


# S_DES解密函数
def decrypt(ciphertext, key):
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


class SDESGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('S-DES加解密工具')
        self.setGeometry(100, 100, 600, 500)

        # 中央窗口部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # 主布局
        layout = QVBoxLayout()

        # 模式选择
        mode_group = QGroupBox("选择模式")
        mode_layout = QHBoxLayout()

        self.encrypt_radio = QRadioButton("加密")
        self.decrypt_radio = QRadioButton("解密")
        self.encrypt_radio.setChecked(True)

        mode_layout.addWidget(self.encrypt_radio)
        mode_layout.addWidget(self.decrypt_radio)
        mode_group.setLayout(mode_layout)

        # 输入区域
        input_group = QGroupBox("输入")
        input_layout = QVBoxLayout()

        # 明文/密文输入
        text_layout = QHBoxLayout()
        text_layout.addWidget(QLabel("输入文本 (8位二进制):"))
        self.text_input = QLineEdit()
        self.text_input.setPlaceholderText("例如: 10101010")
        text_layout.addWidget(self.text_input)

        # 密钥输入
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("密钥 (10位二进制):"))
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("例如: 1010101010")
        key_layout.addWidget(self.key_input)

        input_layout.addLayout(text_layout)
        input_layout.addLayout(key_layout)
        input_group.setLayout(input_layout)

        # 按钮区域
        button_layout = QHBoxLayout()
        self.execute_btn = QPushButton("执行")
        self.clear_btn = QPushButton("清空")

        button_layout.addWidget(self.execute_btn)
        button_layout.addWidget(self.clear_btn)

        # 输出区域
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout()
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        output_layout.addWidget(self.output_text)
        output_group.setLayout(output_layout)

        # 将所有组件添加到主布局
        layout.addWidget(mode_group)
        layout.addWidget(input_group)
        layout.addLayout(button_layout)
        layout.addWidget(output_group)

        central_widget.setLayout(layout)

        # 连接信号和槽
        self.execute_btn.clicked.connect(self.execute_operation)
        self.clear_btn.clicked.connect(self.clear_all)

    def execute_operation(self):
        try:
            # 获取输入
            input_text = self.text_input.text().strip()
            key = self.key_input.text().strip()

            # 验证输入
            if not input_text:
                QMessageBox.warning(self, "输入错误", "请输入文本!")
                return

            if not key:
                QMessageBox.warning(self, "输入错误", "请输入密钥!")
                return

            # 验证二进制格式
            if not all(bit in '01' for bit in input_text):
                QMessageBox.warning(self, "输入错误", "文本必须是二进制格式(只包含0和1)!")
                return

            if not all(bit in '01' for bit in key):
                QMessageBox.warning(self, "输入错误", "密钥必须是二进制格式(只包含0和1)!")
                return

            # 执行加密或解密
            if self.encrypt_radio.isChecked():
                # 加密模式
                if len(input_text) != 8:
                    QMessageBox.warning(self, "输入错误", "明文必须是8位二进制!")
                    return

                if len(key) != 10:
                    QMessageBox.warning(self, "输入错误", "密钥必须是10位二进制!")
                    return

                result = encrypt(input_text, key)
                operation = "加密"
                input_type = "明文"
                output_type = "密文"
            else:
                # 解密模式
                if len(input_text) != 8:
                    QMessageBox.warning(self, "输入错误", "密文必须是8位二进制!")
                    return

                if len(key) != 10:
                    QMessageBox.warning(self, "输入错误", "密钥必须是10位二进制!")
                    return

                result = decrypt(input_text, key)
                operation = "解密"
                input_type = "密文"
                output_type = "明文"

            # 显示结果
            output = f"{operation}结果:\n"
            output += f"{input_type}: {input_text}\n"
            output += f"密钥: {key}\n"
            output += f"{output_type}: {result}\n"
            output += "-" * 50

            current_output = self.output_text.toPlainText()
            if current_output:
                self.output_text.setText(current_output + "\n" + output)
            else:
                self.output_text.setText(output)

        except Exception as e:
            QMessageBox.critical(self, "错误", f"处理过程中发生错误: {str(e)}")

    def clear_all(self):
        self.text_input.clear()
        self.key_input.clear()
        self.output_text.clear()


def main():
    app = QApplication(sys.argv)
    window = SDESGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()