# monitor_7788_sqlite.py
import sqlite3
import time
import psutil
from datetime import datetime
from collections import defaultdict
import os
import sys
import smtplib
import ssl
from email.mime.text import MIMEText
from email.header import Header
from dotenv import load_dotenv

# 正确获取 .exe 或 .py 所在目录
if getattr(sys, 'frozen', False):
    # 打包成 exe 后，sys.frozen 为 True
    script_dir = os.path.dirname(sys.executable)
else:
    # 普通 Python 脚本运行
    script_dir = os.path.dirname(os.path.abspath(__file__))

env_path = os.path.join(script_dir, '.env')
load_dotenv(dotenv_path=env_path)



# 从 .env 读取配置
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
RECIPIENT_EMAIL = os.getenv("RECIPIENT_EMAIL")

# 检查是否加载成功
if not all([SMTP_SERVER, SMTP_PORT, SENDER_EMAIL, SENDER_PASSWORD, RECIPIENT_EMAIL]):
    raise ValueError("mailac.env 配置不完整，请检查文件路径和内容！")

PORT = 7788
# 正确获取 exe 或 py 所在目录（与 .env 一致）
if getattr(sys, 'frozen', False):
    app_dir = os.path.dirname(sys.executable)
else:
    app_dir = os.path.dirname(os.path.abspath(__file__))

DB_FILE = os.path.join(app_dir, "7788_connections.db")
INTERVAL = 1

def send_email(subject: str, body: str):
    """通过 163 邮箱发送告警邮件（使用 465 SSL 端口）"""
    try:
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['From'] = Header(SENDER_EMAIL)
        msg['To'] = Header(RECIPIENT_EMAIL)
        msg['Subject'] = Header(subject, 'utf-8')

        # 使用 465 端口 + SSL（无需 starttls）
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_SERVER, 465, context=context) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECIPIENT_EMAIL, msg.as_string())
        print(f"[邮件] 已发送通知: {subject}")
    except Exception as e:
        print(f"[邮件] 发送失败: {e}")

def init_db():
    """初始化数据库表：每 IP 会话独立记录（不以 remote_ip 为主键）"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            remote_ip TEXT NOT NULL,
            session_start TEXT NOT NULL,
            session_end TEXT,
            duration_seconds REAL,
            status TEXT DEFAULT '活跃中',
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def normalize_ip(ip):
    if ip.startswith('::ffff:') and '.' in ip:
        return ip.split(':')[-1]
    return ip

# ====== 修改 get_all_conns() ======
def get_all_conns(port):
    """获取当前所有活跃连接的远程 IP 集合（去重）"""
    ips = set()
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr.port == port and conn.status != 'LISTEN' and conn.raddr:
            ip = normalize_ip(conn.raddr.ip)
            if ip in ('127.0.0.1', '::1'):
                continue
            # >>>>>>>>>> 新增：控制台输出带端口（仅用于调试） <<<<<<<<<<
            #print(f"[DEBUG] 检测到连接: {ip}:{conn.raddr.port} | 状态: {conn.status}")
            ips.add(ip)  # 只存 IP
    return ips

# 初始化数据库
init_db()
print(f"开始监控 {PORT} 端口，数据保存至: {DB_FILE}")
print("按 Ctrl+C 停止")

# 内存状态：跟踪每个 IP 的当前会话
active_sessions = {}  # ip -> { 'record_id': int, 'start_time': datetime }
notified_ips = set()  # 已发送过告警的 IP（每会话只告警一次）

try:
    while True:
        current_ips = get_all_conns(PORT)
        now = datetime.now()
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")

        # 1. 处理新会话（IP 首次出现）
        for ip in current_ips:
            if ip not in active_sessions:
                # 开启新会话
                start_time = now
                start_str = now_str

                # 插入数据库
                conn = sqlite3.connect(DB_FILE)
                c = conn.cursor()
                c.execute("""
                    INSERT INTO connections (remote_ip, session_start, created_at)
                    VALUES (?, ?, ?)
                """, (ip, start_str, start_str))
                record_id = c.lastrowid
                conn.commit()
                conn.close()

                active_sessions[ip] = {
                    'record_id': record_id,
                    'start_time': start_time
                }
                print(f"[+] 新会话开始: {ip} (ID={record_id})")

                # 发送告警邮件（每会话一次）
                if ip not in notified_ips:
                    subject = f"检测到新连接访问NAS端口"
                    body = f"""发现新的外部连接尝试访问本机NAS端口:

远程 IP: {ip}
会话开始时间: {start_str}

请确认是否为合法访问！
"""
                    send_email(subject, body)
                    notified_ips.add(ip)

        # 2. 处理会话结束（IP 完全消失）
        for ip in list(active_sessions.keys()):
            if ip not in current_ips:
                # 该 IP 所有连接已断开 → 结束会话
                session_info = active_sessions.pop(ip)
                record_id = session_info['record_id']
                start_time = session_info['start_time']
                duration = (now - start_time).total_seconds()

                # 更新数据库
                conn = sqlite3.connect(DB_FILE)
                c = conn.cursor()
                c.execute("""
                    UPDATE connections
                    SET session_end = ?, duration_seconds = ?, status = '已结束'
                    WHERE id = ?
                """, (now_str, duration, record_id))
                conn.commit()
                conn.close()

                print(f"[-] 会话结束: {ip} | 持续 {duration:.1f} 秒")
                notified_ips.discard(ip)  # 允许下次会话再次告警

        time.sleep(INTERVAL)

except KeyboardInterrupt:
    print("\n正在退出... 结束所有活跃会话")
    now = datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    for ip, session_info in list(active_sessions.items()):
        record_id = session_info['record_id']
        start_time = session_info['start_time']
        duration = (now - start_time).total_seconds()

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("""
            UPDATE connections
            SET session_end = ?, duration_seconds = ?, status = '程序退出'
            WHERE id = ?
        """, (now_str, duration, record_id))
        conn.commit()
        conn.close()
    print("所有会话已标记为结束，监控结束。")
