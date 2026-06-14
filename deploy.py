#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""部署 stun 服务到远程服务器"""

import paramiko
import os
import time

# 服务器配置
HOST = "43.166.0.53"
PORT = 22
USERNAME = "root"
PASSWORD = "w753159L@@@@"

# 本地文件路径
LOCAL_FILE = r"D:\ai\ceshi\管理香港服务器\stun\stun_redirect_server.py"
REMOTE_DIR = "/root/stun"
REMOTE_FILE = f"{REMOTE_DIR}/stun_redirect_server.py"

def upload_file():
    """上传文件到远程服务器"""
    print(f"连接到 {HOST}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(HOST, port=PORT, username=USERNAME, password=PASSWORD, timeout=15)
        print("连接成功!")
        
        # 创建远程目录
        print(f"创建目录 {REMOTE_DIR}...")
        stdin, stdout, stderr = client.exec_command(f"mkdir -p {REMOTE_DIR}")
        stdout.read()
        
        # 上传文件
        print(f"上传文件到 {REMOTE_FILE}...")
        sftp = client.open_sftp()
        sftp.put(LOCAL_FILE, REMOTE_FILE)
        sftp.chmod(REMOTE_FILE, 0o755)
        sftp.close()
        print("文件上传成功!")
        
        # 停止旧服务
        print("停止旧服务...")
        stdin, stdout, stderr = client.exec_command("pkill -f stun_redirect_server.py || true")
        stdout.read()
        time.sleep(1)
        
        # 启动新服务
        print("启动新服务...")
        stdin, stdout, stderr = client.exec_command(f"cd {REMOTE_DIR} && nohup python3 stun_redirect_server.py > /dev/null 2>&1 &")
        stdout.read()
        time.sleep(2)
        
        # 检查服务状态
        print("检查服务状态...")
        stdin, stdout, stderr = client.exec_command("ps aux | grep stun_redirect_server | grep -v grep")
        output = stdout.read().decode()
        if output:
            print(f"服务已启动: {output.strip()}")
        else:
            print("警告: 服务可能未成功启动")
        
        # 检查端口
        stdin, stdout, stderr = client.exec_command("netstat -tlnp | grep 8800 || ss -tlnp | grep 8800")
        output = stdout.read().decode()
        if output:
            print(f"端口 8800 已监听: {output.strip()}")
        else:
            print("警告: 端口 8800 未监听")
        
        print("\n部署完成!")
        print(f"访问地址: http://{HOST}:8800")
        
    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.close()

if __name__ == "__main__":
    upload_file()
