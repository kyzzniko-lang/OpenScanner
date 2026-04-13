#!/usr/bin/env python3
"""
OpenScanner 一键极简部署脚本

用于快速验证环境、安装依赖、并在本地验证写入权限。
支持 Windows、Linux 及 macOS 等多平台操作。
"""

import os
import sys
import subprocess
from pathlib import Path

def print_step(msg: str):
    print(f"\n[+] {msg}")

def print_error(msg: str):
    print(f"[-] ERROR: {msg}", file=sys.stderr)

def print_success(msg: str):
    print(f"[✔] {msg}")

def check_python_version():
    """检查 Python 版本是否 >= 3.9"""
    print_step("检查 Python 版本...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 9):
        print_error(f"当前 Python 版本为 {version.major}.{version.minor}，OpenScanner 需要 Python 3.9 或更高版本。")
        sys.exit(1)
    print_success(f"Python {version.major}.{version.minor}.{version.micro} 环境适用。")

def check_permission(directory: Path):
    """
    检查指定目录是否具备读写权限。
    
    在 Windows 下部分系统盘目录可能会由于缺乏 UAC 权限导致崩溃，
    通过写入一个隐藏临时文件实现物理验证。
    """
    print_step(f"检查目录写权限: {directory.resolve()}")
    try:
        if not directory.exists():
            directory.mkdir(parents=True, exist_ok=True)
            
        test_file = directory / ".test_write"
        test_file.write_text("permission_check")
        test_file.unlink()
        print_success("读写权限校验通过。")
    except PermissionError:
        print_error("当前用户对该目录没有写权限！在 Windows 系统上，请尝试以管理员身份运行。")
        sys.exit(1)
    except Exception as e:
        print_error(f"发生意料外的权限校验错误: {e}")
        sys.exit(1)

def install_requirements(root_dir: Path):
    """安装 requirements.txt 依赖"""
    req_file = root_dir / "requirements.txt"
    if not req_file.exists():
        print_error(f"未找到 {req_file.resolve()}，请确保位于 OpenScanner 根目录。")
        sys.exit(1)
        
    print_step("开始安装 Python 依赖 (pip install -r requirements.txt)...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", str(req_file)])
        print_success("依赖安装完成！")
    except subprocess.CalledProcessError:
        print_error("pip 安装期间发生错误，请检查网络连接或手动执行 pip install。")
        sys.exit(1)

def main():
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                 ⚡ OpenScanner Bootstrap ⚡                    ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    root_dir = Path(__file__).resolve().parent
    
    check_python_version()
    
    # 构建所需的子目录
    reports_dir = root_dir / "reports"
    check_permission(root_dir)
    check_permission(reports_dir)
    
    install_requirements(root_dir)
    
    print("\n" + "="*60)
    print("🎉 极简部署成功！环境已就绪。")
    print("启动 CLI 命令行: python main.py")
    print("启动 Web 控制台: streamlit run web/app.py")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
