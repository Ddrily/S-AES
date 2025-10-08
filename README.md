<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>S-DES加解密工具</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f8fa;
            padding: 20px;
            max-width: 1200px;
            margin: 0 auto;
        }
        
        header {
            text-align: center;
            margin-bottom: 40px;
            padding: 30px;
            background: linear-gradient(135deg, #6e8efb 0%, #a777e3 100%);
            color: white;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        h1 {
            font-size: 2.8rem;
            margin-bottom: 15px;
        }
        
        .subtitle {
            font-size: 1.2rem;
            opacity: 0.9;
            max-width: 800px;
            margin: 0 auto;
        }
        
        .badges {
            margin: 20px 0;
        }
        
        .badge {
            display: inline-block;
            background-color: #5c6bc0;
            color: white;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.9rem;
            margin: 0 5px 5px 0;
        }
        
        section {
            background-color: white;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }
        
        h2 {
            color: #5c6bc0;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e8eaf6;
        }
        
        h3 {
            color: #3f51b5;
            margin: 20px 0 10px;
        }
        
        p {
            margin-bottom: 15px;
        }
        
        code {
            background-color: #f5f5f5;
            padding: 2px 5px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
        }
        
        pre {
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 20px 0;
            border-left: 4px solid #5c6bc0;
        }
        
        .algorithm-steps {
            background-color: #e8eaf6;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
        
        .algorithm-steps ol {
            padding-left: 25px;
        }
        
        .algorithm-steps li {
            margin-bottom: 10px;
        }
        
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .feature {
            background-color: #e8eaf6;
            padding: 20px;
            border-radius: 8px;
            transition: transform 0.3s ease;
        }
        
        .feature:hover {
            transform: translateY(-5px);
        }
        
        .feature h3 {
            color: #3f51b5;
            margin-top: 0;
        }
        
        .screenshot {
            text-align: center;
            margin: 30px 0;
        }
        
        .screenshot img {
            max-width: 100%;
            border: 1px solid #ddd;
            border-radius: 5px;
            box-shadow: 0 3px 10px rgba(0, 0, 0, 0.1);
        }
        
        .caption {
            font-style: italic;
            margin-top: 10px;
            color: #666;
        }
        
        .installation-steps {
            background-color: #e8eaf6;
            padding: 20px;
            border-radius: 5px;
        }
        
        .installation-steps ol {
            padding-left: 25px;
        }
        
        .installation-steps li {
            margin-bottom: 15px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        th {
            background-color: #e8eaf6;
            color: #3f51b5;
        }
        
        tr:hover {
            background-color: #f5f5f5;
        }
        
        footer {
            text-align: center;
            margin-top: 50px;
            padding: 20px;
            color: #666;
            border-top: 1px solid #ddd;
        }
        
        @media (max-width: 768px) {
            .features {
                grid-template-columns: 1fr;
            }
            
            h1 {
                font-size: 2.2rem;
            }
        }
    </style>
</head>
<body>
    <header>
        <h1>S-DES加解密工具</h1>
        <p class="subtitle">一个基于Python和PyQt5实现的简化版DES加密算法图形界面工具</p>
        <div class="badges">
            <span class="badge">Python</span>
            <span class="badge">PyQt5</span>
            <span class="badge">密码学</span>
            <span class="badge">S-DES</span>
            <span class="badge">GUI应用</span>
        </div>
    </header>
    
    <section id="overview">
        <h2>项目概述</h2>
        <p>S-DES（Simplified Data Encryption Standard）是DES加密算法的简化版本，主要用于教学目的，帮助理解DES加密的基本原理。本项目实现了一个完整的S-DES加解密工具，提供直观的图形用户界面，使用户能够轻松地进行加密和解密操作。</p>
        
        <div class="algorithm-steps">
            <h3>S-DES算法步骤</h3>
            <ol>
                <li>任意长度明文按64bit分块，不足则填充</li>
                <li>分块明文进行初始置换，输出新的64位数据块</li>
                <li>加密轮次（共16次），每个轮次包含四个步骤</li>
                <li>在最后一个轮次完成后，将经过加密的数据块进行末置换，得到64位密文</li>
            </ol>
        </div>
    </section>
    
    <section id="features">
        <h2>功能特点</h2>
        <div class="features">
            <div class="feature">
                <h3>🔒 加密功能</h3>
                <p>支持8位二进制明文的加密操作，使用10位二进制密钥生成加密后的密文。</p>
            </div>
            <div class="feature">
                <h3>🔓 解密功能</h3>
                <p>支持8位二进制密文的解密操作，使用加密时相同的密钥恢复原始明文。</p>
            </div>
            <div class="feature">
                <h3>🎨 直观界面</h3>
                <p>基于PyQt5开发的图形界面，操作简单直观，无需命令行操作。</p>
            </div>
            <div class="feature">
                <h3>🔐 密钥生成</h3>
                <p>自动从10位主密钥生成8位轮密钥，用于加密和解密过程。</p>
            </div>
            <div class="feature">
                <h3>📋 输入验证</h3>
                <p>全面的输入验证机制，确保输入的明文、密文和密钥符合格式要求。</p>
            </div>
            <div class="feature">
                <h3>💾 结果展示</h3>
                <p>清晰的结果输出区域，显示加密或解密的过程和最终结果。</p>
            </div>
        </div>
    </section>
    
    <section id="screenshots">
        <h2>界面预览</h2>
        <div class="screenshot">
            
            <p class="caption">S-DES加解密工具主界面</p>
        </div>
    </section>
    
    <section id="installation">
        <h2>安装与运行</h2>
        
        <h3>环境要求</h3>
        <ul>
            <li>Python 3.6+</li>
            <li>PyQt5库</li>
        </ul>
        
        <h3>安装步骤</h3>
        <div class="installation-steps">
            <ol>
                <li>克隆或下载本项目到本地</li>
                <li>安装所需的依赖库：
                    <pre><code>pip install PyQt5</code></pre>
                </li>
                <li>运行程序：
                    <pre><code>python s_des_gui.py</code></pre>
                </li>
            </ol>
        </div>
    </section>
    
    <section id="usage">
        <h2>使用说明</h2>
        
        <h3>加密操作</h3>
        <ol>
            <li>选择"加密"模式</li>
            <li>在输入文本框中输入8位二进制明文（如：10101010）</li>
            <li>在密钥输入框中输入10位二进制密钥（如：1010101010）</li>
            <li>点击"执行"按钮，加密结果将显示在输出区域</li>
        </ol>
        
        <h3>解密操作</h3>
        <ol>
            <li>选择"解密"模式</li>
            <li>在输入文本框中输入8位二进制密文</li>
            <li>在密钥输入框中输入加密时使用的10位二进制密钥</li>
            <li>点击"执行"按钮，解密结果将显示在输出区域</li>
        </ol>
        
        <h3>清空操作</h3>
        <p>点击"清空"按钮可以清除所有输入和输出内容，以便进行新的加解密操作。</p>
    </section>
    
    <section id="algorithm-details">
        <h2>算法细节</h2>
        
        <h3>置换表</h3>
        <p>算法使用了多种置换表，包括初始置换(IP)、最终置换(IP_INV)、扩展置换(EP)、密钥置换(P10, P8, P4)等。</p>
        
        <h3>S盒</h3>
        <p>算法使用两个4×4的S盒进行非线性变换，增强加密强度。</p>
        
        <h3>密钥生成</h3>
        <p>从10位主密钥生成两个8位轮密钥(k1, k2)，用于加密和解密的不同轮次。</p>
        
        <h3>轮函数</h3>
        <p>轮函数f_k包含扩展、异或、S盒替换和P4置换等操作，是加密过程的核心。</p>
    </section>
    
    <section id="code-example">
        <h2>代码示例</h2>
        
        <h3>加密函数</h3>
        <pre><code>def encrypt(plaintext, key):
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

    return ciphertext</code></pre>
        
        <h3>密钥生成</h3>
        <pre><code>def generate_keys(key):
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

    return k1, k2</code></pre>
    </section>
    
    <section id="contributing">
        <h2>贡献指南</h2>
        <p>欢迎为本项目贡献代码！如果您有任何改进建议或发现了bug，请提交Issue或Pull Request。</p>
        
        <h3>开发方向</h3>
        <ul>
            <li>增加更多加密算法支持</li>
            <li>改进用户界面和用户体验</li>
            <li>添加文件加密功能</li>
            <li>增加加密过程可视化</li>
            <li>支持更多输入格式（如十六进制、ASCII等）</li>
        </ul>
    </section>
    
    <footer>
        <p>© 2023 S-DES加解密工具 | 基于MIT开源协议</p>
        <p>本项目仅用于教育和学习目的，请勿用于生产环境</p>
    </footer>
</body>
</html>
