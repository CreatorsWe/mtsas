# ==============================================
# 漏洞1：硬编码凭证（CWE-798，高危）
# 问题：密钥/密码直接写在代码中，泄露后可被恶意利用
# ==============================================
# 硬编码API密钥
API_KEY = "sk_8765432190abcdefghijklmnopqrst"
# 硬编码数据库密码
DB_PASSWORD = "MyWeakPassword123!"
# 硬编码SSH私钥（简化示例）
SSH_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nfakekey\n-----END RSA PRIVATE KEY-----"

# ==============================================
# 漏洞2：SQL注入（CWE-89，高危）
# 问题：拼接用户输入到SQL语句，攻击者可构造输入篡改SQL逻辑
# ==============================================
import sqlite3

def query_user(username):
    # 不安全：直接拼接用户输入到SQL
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    sql = f"SELECT * FROM users WHERE username = '{username}';"  # 拼接输入！
    cursor.execute(sql)  # SQL注入风险
    return cursor.fetchone()

# ==============================================
# 漏洞3：命令注入（CWE-78，高危）
# 问题：使用os.system执行拼接用户输入的系统命令，可执行任意命令
# ==============================================
import os

def ping_host(host):
    # 不安全：拼接用户输入到系统命令
    cmd = f"ping -c 4 {host}"  # 攻击者输入 "8.8.8.8; rm -rf /" 即可执行删除命令
    os.system(cmd)  # 命令注入风险

# ==============================================
# 漏洞4：路径遍历（CWE-22，中危）
# 问题：未校验用户输入的文件路径，可访问任意系统文件（如/etc/passwd）
# ==============================================
def read_file(filename):
    # 不安全：直接使用用户输入的路径，无校验
    with open(filename, "r", encoding="utf-8") as f:
        return f.read()  # 攻击者输入 "../../etc/passwd" 可读取敏感文件

# ==============================================
# 漏洞5：敏感信息泄露（CWE-200，中危）
# 问题：异常中打印完整堆栈/敏感数据，日志泄露关键信息
# ==============================================
def get_user_info(user_id):
    try:
        # 模拟查询敏感用户数据
        user_data = {"id": user_id, "phone": "13800138000", "id_card": "110101199001011234"}
        return user_data
    except Exception as e:
        # 不安全：打印完整异常堆栈+敏感数据
        print(f"Error querying user {user_id}: {e}")  # 日志泄露用户ID
        raise e  # 未过滤的异常堆栈会泄露代码结构

# ==============================================
# 漏洞6：弱密码哈希（CWE-327，中危）
# 问题：使用MD5/sha1等弱哈希算法存储密码，无加盐，易被彩虹表破解
# ==============================================
import hashlib

def hash_password(password):
    # 不安全：MD5是弱哈希，且无盐值
    return hashlib.md5(password.encode()).hexdigest()  # 弱哈希+无盐

# 存储的哈希值可被彩虹表破解
user_password_hash = hash_password("123456")

# ==============================================
# 漏洞7：不安全的反序列化（CWE-502，高危）
# 问题：使用pickle反序列化不可信数据，可执行任意代码
# ==============================================
import pickle
import base64

def deserialize_data(serialized_data):
    # 不安全：pickle反序列化不可信输入（攻击者可构造恶意pickle数据执行代码）
    data = base64.b64decode(serialized_data)
    return pickle.loads(data)  # 反序列化漏洞

# 模拟攻击者构造的恶意序列化数据（执行系统命令）
# 实际测试时不要运行这行！
# malicious_data = base64.b64encode(pickle.dumps(恶意对象)).decode()
