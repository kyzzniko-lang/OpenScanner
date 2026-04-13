"""
web/app.py — OpenScanner Streamlit Web GUI

功能：
  • 左侧边栏：扫描参数配置（并发数、超时、重试、目标 URL）
  • 右侧主面板：实时扫描状态 + 漏洞告警
  • 异步引擎集成：在 Streamlit 内运行 ScanEngine 两阶段 Pipeline
  • 可视化报表：漏洞等级饼图 + 插件检测雷达图 + WAF 拦截率
  • 一键导出：JSON 报告下载

Usage:
    cd OpenScanner
    streamlit run web/app.py
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── 确保项目根在 sys.path ──
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st

from core.engine import ScanEngine, ScanEvent, PluginCategory
from core.request import RequestConfig, AsyncRequester
from core.spider import SpiderEngine
from plugins.base import Severity
from utils.reporter import ReportGenerator

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 配置持久化
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AI_SETTINGS_FILE = ".ai_settings.json"

def load_persistent_settings() -> Dict[str, Any]:
    """从本地文件加载持久化的 AI 配置"""
    try:
        if Path(AI_SETTINGS_FILE).exists():
            with open(AI_SETTINGS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"无法加载 AI 配置文件: {e}")
    return {}

def save_persistent_settings(params: Dict[str, Any]):
    """将当前 AI 配置持久化到本地文件"""
    try:
        # 只记录 AI 相关的字段
        ai_keys = [
            "ai_mode", "ai_model_path", "ai_api_key", "ai_api_base", 
            "ai_api_model", "ai_language", "ai_trust_env", "ai_proxy"
        ]
        to_save = {k: params[k] for k in ai_keys if k in params}
        with open(AI_SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(to_save, f, indent=2, ensure_ascii=False)
        logger.info("AI 配置已持久化到本地")
    except Exception as e:
        logger.warning(f"无法保存 AI 配置文件: {e}")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 日志配置
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
logger = logging.getLogger("openscanner.web")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 异步工具组件 (解决 Event loop is closed 错误)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def get_or_create_event_loop():
    try:
        # 更加鲁棒的事件循环获取方式 (适配 Python 3.10+ & Streamlit 多线程)
        try:
            loop = asyncio.get_running_loop()
            return loop
        except RuntimeError:
            loop = asyncio.get_event_loop_policy().get_event_loop()
            if loop.is_closed():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            return loop
    except Exception:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop

def safe_async_run(coro):
    """确保在 Streamlit 多线程环境下安全运行异步任务。
    
    该函数解决了 asyncio.run() 在已关闭 loop 或多线程环境中可能导致的 'Event loop is closed' 报错。
    """
    loop = get_or_create_event_loop()
    
    if loop.is_running():
        # 如果循环已经在运行（如在某些 Webserver 或 Jupyter 中），
        # 我们不能直接运行 run_until_complete，需要使用 run_coroutine_threadsafe
        import concurrent.futures
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        return future.result()
    else:
        return loop.run_until_complete(coro)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 页面配置
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

st.set_page_config(
    page_title="OpenScanner — Web Vulnerability Scanner",
    page_icon="🔦",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 自定义 CSS — 暗色主题 + 赛博朋克风
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

st.markdown("""
<style>
    /* ── 全局字体 ── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    code, pre, .stCode {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Remove .stApp and .stSidebar explicit backgrounds to allow light/dark themes to work! */
    [data-testid="stSidebar"] {
        border-right: 1px solid var(--secondary-background-color);
        box-shadow: 2px 0 10px rgba(0,0,0,0.05);
    }

    /* ── metric 卡片 ── */
    [data-testid="stMetric"] {
        background-color: var(--secondary-background-color);
        border: 1px solid rgba(150, 150, 150, 0.15);
        border-radius: 8px;
        padding: 16px 20px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        transition: transform 0.2s ease-in-out;
    }
    [data-testid="stMetric"]:hover {
        transform: translateY(-2px);
    }
    [data-testid="stMetricLabel"] {
        font-size: 0.85rem;
        font-weight: 500;
        opacity: 0.8;
    }
    [data-testid="stMetricValue"] {
        font-weight: 700;
        color: var(--primary-color) !important;
    }

    /* ── 漏洞告警卡 ── */
    .vuln-card {
        background-color: var(--secondary-background-color);
        border: 1px solid rgba(239, 68, 68, 0.3);
        border-left: 4px solid #ef4444;
        border-radius: 8px;
        padding: 20px 24px;
        margin: 12px 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    .vuln-card p {
        white-space: pre-wrap;
    }
    .vuln-card h4 {
        margin: 0 0 8px 0;
        font-size: 1.05rem;
        color: var(--text-color);
    }
    .vuln-card .payload {
        background-color: var(--background-color);
        padding: 8px 14px;
        border-radius: 6px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.85rem;
        margin: 8px 0;
        border: 1px solid rgba(150, 150, 150, 0.15);
        word-break: break-all;
    }
    .vuln-card .evidence {
        font-size: 0.88rem;
        line-height: 1.6;
        white-space: pre-wrap;
        color: var(--text-color);
        opacity: 0.85;
    }
    .vuln-card .badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
    }
    .badge-high { background-color: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-critical { background-color: rgba(168, 85, 247, 0.15); color: #a855f7; border: 1px solid rgba(168, 85, 247, 0.3); }
    .badge-medium { background-color: rgba(249, 115, 22, 0.15); color: #f97316; border: 1px solid rgba(249, 115, 22, 0.3); }
    .badge-low { background-color: rgba(34, 197, 94, 0.15); color: #22c55e; border: 1px solid rgba(34, 197, 94, 0.3); }
    .badge-info { background-color: rgba(59, 130, 246, 0.15); color: #3b82f6; border: 1px solid rgba(59, 130, 246, 0.3); }
    .badge-warning { background-color: rgba(234, 179, 8, 0.15); color: #eab308; border: 1px solid rgba(234, 179, 8, 0.3); }

    .vuln-card-warning {
        background-color: var(--secondary-background-color);
        border: 1px solid rgba(234, 179, 8, 0.3);
        border-left: 4px solid #eab308;
        border-radius: 8px;
        padding: 20px 24px;
        margin: 12px 0;
        box-shadow: 0 4px 12px rgba(234, 179, 8, 0.1);
    }

    /* ── WAF 状态卡 ── */
    .waf-card {
        background-color: var(--secondary-background-color);
        border: 1px solid rgba(234, 179, 8, 0.2);
        border-left: 4px solid #eab308;
        border-radius: 8px;
        padding: 16px 20px;
        margin: 10px 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    .waf-card h4 { margin: 0 0 6px 0; color: var(--text-color); }

    /* ── 安全卡 ── */
    .safe-card {
        background-color: var(--secondary-background-color);
        border: 1px solid rgba(34, 197, 94, 0.2);
        border-left: 4px solid #22c55e;
        border-radius: 8px;
        padding: 16px 20px;
        margin: 10px 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    .safe-card h4 { margin: 0 0 6px 0; color: var(--text-color); }

    /* ── 标题样式 ── */
    .scanner-title {
        font-weight: 800;
        font-size: 2.4rem;
        letter-spacing: -1px;
        color: var(--text-color);
        opacity: 0.95;
    }
    .subtitle {
        font-size: 0.95rem;
        margin-top: -8px;
        opacity: 0.7;
    }

    /* ── 按钮美化 ── */
    .stButton > button {
        border-radius: 6px;
        font-weight: 600;
        transition: all 0.2s ease;
    }
    .stButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
    }

    /* ── 进度条 ── */
    .stProgress > div > div {
        background-color: var(--primary-color) !important;
        border-radius: 4px;
    }

    /* ── Divider ── */
    .cyber-divider {
        height: 1px;
        background-color: rgba(150, 150, 150, 0.2);
        margin: 24px 0;
    }
</style>
""", unsafe_allow_html=True)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 颜色配置
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SEVERITY_COLORS = {
    "info": "#3b82f6",     # Blue
    "low": "#22c55e",      # Green
    "medium": "#eab308",   # Yellow (Matches user request)
    "high": "#ef4444",     # Red
    "critical": "#a855f7", # Purple
    "warning": "#eab308",  # Yellow
}

SEVERITY_WEIGHTS = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITY_EMOJI = {
    "info": "ℹ️",
    "low": "🟢",
    "medium": "🟠",
    "high": "🔴",
    "critical": "🟣",
    "warning": "⚠️",
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Session State 初始化
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_APP_STATE_DEFAULTS = {
    "scan_running": False,
    "scan_results": [],
    "scan_summary": {},
    "scan_log": [],
    "scan_vulns": [],
    "scan_waf": {},
    "scan_warnings": [],
    "plugins_info": [],
    "engine": None,
}

def init_state():
    for k, v in _APP_STATE_DEFAULTS.items():
        if k not in st.session_state:
            st.session_state[k] = v

def clear_history():
    for k, v in _APP_STATE_DEFAULTS.items():
        st.session_state[k] = v

init_state()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 侧边栏
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def render_sidebar():
    p_config = load_persistent_settings()
    
    with st.sidebar:
        st.markdown('<p class="scanner-title">🔍 OpenScanner</p>', unsafe_allow_html=True)
        st.markdown('<p class="subtitle">⚡ Async Web Vulnerability Scanner</p>', unsafe_allow_html=True)
        st.markdown('<div class="cyber-divider"></div>', unsafe_allow_html=True)

        mode = st.radio("扫描模式", ["远程漏洞扫描 (DAST)", "本地源码审计 (SAST)"], index=0)
        st.session_state["scan_mode"] = mode

        st.markdown('<div class="cyber-divider"></div>', unsafe_allow_html=True)

        # ── 目标/路径 ──
        if mode == "远程漏洞扫描 (DAST)":
            st.markdown("### 🎯 扫描目标")
            targets_input = st.text_area(
                "输入目标 URL（每行一个）",
                value="https://httpbin.org/get?id=1&name=test",
                height=120,
                help="支持多目标扫描，每行输入一个 URL",
            )
            associated_source_dir = st.text_input(
                "📂 关联本地源码目录 (IAST联动, 可选)",
                value="",
                help="如果填写本地绝对路径，发现远程漏洞后会自动溯源该漏洞涉及的参数流向（AST级别）。"
            )

            target_param_input = st.text_input(
                "🎯 指定注入参数 (Target Param)",
                value="",
                help="如果填写，扫描引擎将不再去推测注入点，只对指定的参数进行深度检测 (例如: id)。"
            )
            cookie_input = st.text_area(
                "🍪 Cookie 身份信息",
                value="",
                height=68,
                help="将 Cookie 直接粘贴于此，扫描器将全量注入 AsyncRequester 自动继承目标系统真实权限。"
            )
            custom_headers_input = st.text_area(
                "📨 自定义 Headers",
                value="",
                height=68,
                help="每行一个 Header，格式: Key: Value。例如: Authorization: Bearer xxx",
            )
            crawl_depth = st.number_input(
                "🕸️ 爬虫深度 (0=关闭)",
                min_value=0, max_value=5, value=0, step=1,
                help="开启后扫描器将在攻击前自动爬取目标页面上的链接和表单。",
            )
            scan_intensity = st.radio(
                "🎯 扫描强度",
                ["轻度 (仅注入点)", "中度 (注入点+关键端点)", "全量 (所有页面)"],
                index=0,
                help="轻度: 只测试有参数的URL，速度最快; 中度: 增加关键端点; 全量: 测试所有发现的URL",
            ) if crawl_depth > 0 else "轻度 (仅注入点)"
            st.markdown('<div class="cyber-divider"></div>', unsafe_allow_html=True)

            # ── 扫描参数 ──
            st.markdown("### ⚙️ 扫描参数")

            col1, col2 = st.columns(2)
            with col1:
                concurrency = st.number_input("并发数", min_value=1, max_value=100, value=10, step=5)
            with col2:
                timeout = st.number_input("超时 (s)", min_value=1.0, max_value=60.0, value=15.0, step=1.0)

            col3, col4 = st.columns(2)
            with col3:
                retries = st.number_input("重试次数", min_value=0, max_value=10, value=3)
            with col4:
                http2 = st.toggle("HTTP/2", value=True)

            verify_ssl = st.toggle("SSL 验证", value=False, help="扫描场景通常关闭")
            allow_internal = st.toggle("允许内网扫描", value=True, help="开启后允许访问 192.168.x.x 等内网机，关闭后具备 SSRF 防御功能。")

        else:
            st.markdown("### 🎯 审计目录")
            targets_input = st.text_input(
                "请输入本地项目绝对路径",
                value="",
                help="例如: D:\\code\\target_project 或 /var/www/html",
            )
            # SAST 专项配置
            st.markdown("### 🤖 AI 审计增强")
            sast_ai_enabled = st.checkbox(
                "开启 AI 深度审计报告",
                value=False,
                help="启用后，引擎将把筛选出的核心源码发送给大模型进行逻辑审计。注意：这会消耗更多 Token 且耗时较长。建议本地模型分配至少 4096 上下文。"
            )
            st.session_state["sast_ai_enabled"] = sast_ai_enabled

            # 基础参数回填 (SAST 模式默认值)
            associated_source_dir = ""
            concurrency = 1
            timeout = 300.0
            retries = 0
            http2 = False
            verify_ssl = False
            allow_internal = False
            target_param_input = ""
            cookie_input = ""

            custom_headers_input = ""
            crawl_depth = 0
            scan_intensity = "轻度 (仅注入点)"

        st.markdown('<div class="cyber-divider"></div>', unsafe_allow_html=True)

        # ── 插件选择 ──
        st.markdown("### 🔌 插件")

        # 加载插件信息预览
        try:
            engine_preview = ScanEngine(config=RequestConfig())
            engine_preview.load_plugins()
            plugins_list = engine_preview.registry.list_plugins()
        except Exception as exc:
            st.error(f"插件加载失败: {exc}")
            plugins_list = []

        plugin_names = []
        for p in plugins_list:
            if mode == "本地源码审计 (SAST)" and p["category"] != "audit":
                continue
            if mode == "远程漏洞扫描 (DAST)" and p["category"] == "audit":
                continue

            if p["category"] == "audit":
                cat_icon = "🔎"
            else:
                cat_icon = "🛡️" if p["category"] == "info" else "⚔️"
                
            sev = p["severity"]
            emoji = SEVERITY_EMOJI.get(sev, "")
            # 确保新插件默认被勾选，即便 Session State 为空
            if f"plugin_{p['name']}" not in st.session_state:
                st.session_state[f"plugin_{p['name']}"] = True

            checked = st.checkbox(
                f"{cat_icon} {p['display_name']} {emoji}",
                value=st.session_state.get(f"plugin_{p['name']}", True),
                key=f"plugin_{p['name']}",
                help=f"类别: {p['category'].upper()} | 等级: {sev.upper()} | 标签: {', '.join(p['tags'])}",
            )
            if checked:
                plugin_names.append(p["name"])

        st.session_state["plugins_info"] = plugins_list
        
        # 如果开启了 AI 深度审计增强，则强制加入相应的 AI 插件
        if mode == "本地源码审计 (SAST)" and st.session_state.get("sast_ai_enabled"):
            if "ai_code_audit" not in plugin_names:
                plugin_names.append("ai_code_audit")

        st.markdown('<div class="cyber-divider"></div>', unsafe_allow_html=True)

        # ── AI 深度研判引擎 ──
        st.markdown("### 🤖 AI 深度研判")
        
        mode_options = ["off", "local", "api"]
        saved_mode = p_config.get("ai_mode", "off")
        mode_idx = mode_options.index(saved_mode) if saved_mode in mode_options else 0
        
        ai_mode = st.selectbox(
            "AI 模式",
            mode_options,
            index=mode_idx,
            format_func=lambda x: {"off": "🚫 关闭 (传统模式)", "local": "💻 本地 LLM (隐私优先)", "api": "☁️ 云端 API (精度优先)"}[x],
            help="选择 AI 推理后端。本地模式数据不离开机器；API 模式精度更高但需要网络。",
        )
        st.session_state["ai_mode"] = ai_mode

        ai_model_path = ""
        ai_api_key = ""
        ai_api_base = "https://api.openai.com/v1"
        ai_api_model = "gpt-4o-mini"

        if ai_mode == "local":
            ai_model_path = st.text_input(
                "📂 GGUF 模型路径",
                value=p_config.get("ai_model_path", ""),
                help="本地 .gguf 模型文件的绝对路径 (例如: D:\\\\models\\\\qwen2-0.5b.gguf)",
            )
            st.caption("💡 推荐模型: Qwen2-0.5B-Instruct-GGUF (~400MB)")
        elif ai_mode == "api":
            ai_api_key = st.text_input(
                "🔑 API Key",
                type="password",
                value=p_config.get("ai_api_key", ""),
                help="OpenAI / Gemini / DeepSeek 等兼容 API 的密钥",
            )
            ai_api_base = st.text_input(
                "🌐 API 端点",
                value=p_config.get("ai_api_base", "https://api.openai.com/v1"),
                help="OpenAI 兼容端点。Gemini 用: https://generativelanguage.googleapis.com/v1beta",
            )
            ai_api_model = st.text_input(
                "🧠 模型名称",
                value=p_config.get("ai_api_model", "gpt-4o-mini"),
                help="例如: gpt-4o-mini / gemini-1.5-flash / deepseek-chat",
            )
            st.caption("⚠️ API 模式会将代码片段发送至第三方服务器")

        lang_options = ["zh", "en"]
        saved_lang = p_config.get("ai_language", "zh")
        lang_idx = lang_options.index(saved_lang) if saved_lang in lang_options else 0

        ai_language = st.selectbox(
            "AI 推理语言",
            lang_options,
            index=lang_idx,
            format_func=lambda x: {"zh": "🇨🇳 中文 (Chinese)", "en": "🇺🇸 English (English)"}[x],
            help="设置 AI 思考、对话和生成报告时使用的语言。",
        )
        st.session_state["ai_language"] = ai_language

        with st.expander("🌐 AI 网络高级设置"):
            ai_trust_env = st.checkbox(
                "使用系统代理", 
                value=p_config.get("ai_trust_env", True), 
                help="是否读取系统环境变量 (HTTP_PROXY等)。如果遇到 ConnectError 建议关闭此项。"
            )
            ai_proxy = st.text_input(
                "手动代理地址 (可选)", 
                value=p_config.get("ai_proxy", ""),
                placeholder="http://127.0.0.1:7890",
                help="强制指定代理服务器。如果填写此项，将优先使用此代理。"
            )
        st.session_state["ai_trust_env"] = ai_trust_env
        st.session_state["ai_proxy"] = ai_proxy

        st.markdown('<div class="cyber-divider"></div>', unsafe_allow_html=True)

        # ── 启动按钮 ──
        scan_btn = st.button(
            "🚀 启动扫描" if not st.session_state.scan_running else "⏳ 扫描中...",
            disabled=st.session_state.scan_running,
            use_container_width=True,
            type="primary",
        )

        # ── 版本信息 ──
        st.markdown('<div class="cyber-divider"></div>', unsafe_allow_html=True)
        st.button("🧹 清空历史", on_click=clear_history, use_container_width=True)
        st.caption("OpenScanner v1.0.0 | Engine: httpx + asyncio")
        st.caption("🔧 By OpenScanner Team")

    return {
        "targets": [t.strip() for t in targets_input.strip().split("\n") if t.strip()],
        "concurrency": concurrency,
        "timeout": timeout,
        "retries": retries,
        "http2": http2,
        "verify_ssl": verify_ssl,
        "allow_internal": allow_internal,
        "plugin_names": plugin_names,
        "associated_source_dir": associated_source_dir,

        "target_param_input": target_param_input if mode == "远程漏洞扫描 (DAST)" else "",
        "cookie_input": cookie_input if mode == "远程漏洞扫描 (DAST)" else "",
        "custom_headers_input": custom_headers_input if mode == "远程漏洞扫描 (DAST)" else "",
        "crawl_depth": crawl_depth if mode == "远程漏洞扫描 (DAST)" else 0,
        "scan_intensity": scan_intensity if mode == "远程漏洞扫描 (DAST)" else "轻度 (仅注入点)",
        "scan_btn": scan_btn,
        "ai_mode": ai_mode,
        "ai_model_path": ai_model_path,
        "ai_api_key": ai_api_key,
        "ai_api_base": ai_api_base,
        "ai_api_model": ai_api_model,
        "ai_language": ai_language,
        "ai_trust_env": ai_trust_env,
        "ai_proxy": ai_proxy,
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 异步扫描执行
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def run_async_scan(params: Dict[str, Any], ai_config: Optional[AIConfig] = None, log_container=None, progress_container=None) -> Dict[str, Any]:
    """在新事件循环中运行异步扫描引擎"""

    # 解析 Cookie 和自定义 Headers 直接注入 Requester 引擎
    extra_headers = {}
    cookie_val = params.get("cookie_input", "").strip()
    if cookie_val:
        extra_headers["Cookie"] = cookie_val
    custom_h = params.get("custom_headers_input", "").strip()
    if custom_h:
        for line in custom_h.split("\n"):
            line = line.strip()
            if ":" in line:
                key, val = line.split(":", 1)
                extra_headers[key.strip()] = val.strip()

    config = RequestConfig(
        max_concurrency=params["concurrency"],
        request_timeout=params["timeout"],
        max_retries=params["retries"],
        http2=params["http2"],
        verify_ssl=params["verify_ssl"],
        allow_internal_ips=params.get("allow_internal", False),
        random_delay_range=(0.05, 0.2),
        extra_headers=extra_headers if extra_headers else None,
    )

    # 收集事件
    events_log: List[Dict] = []
    vulns_found: List[Dict] = []
    log_buffer: List[str] = []

    def event_handler(event: ScanEvent, data: Dict[str, Any]):
        events_log.append({"event": event.value, "data": data, "time": time.time()})
        if event == ScanEvent.VULN_FOUND:
            vulns_found.append(data)
            
        if progress_container is not None and event == ScanEvent.PLUGIN_END:
            curr_idx = data.get("current_idx", 1)
            total = data.get("total_tasks", 1)
            pct = min(1.0, max(0.0, curr_idx / float(total)))
            
            pname = data.get('plugin', 'unknown')
            targ = data.get('target', '')
            progress_container[0].progress(pct)
            progress_container[1].caption(f"正在扫描第 {curr_idx}/{total} 个任务: [{pname}] {targ}...")
            
        if log_container is not None:
            if event == ScanEvent.PLUGIN_START:
                pname = data.get('plugin', '')
                url = data.get('target', '')
                log_buffer.append(f"[*] 启动检测: {pname} -> {url}")
            elif event == ScanEvent.VULN_FOUND:
                pname = data.get('plugin', '')
                url = data.get('target', '')
                log_buffer.append(f"[!] 发现风险: {pname} -> {url}")
            elif event == ScanEvent.TARGET_UNREACHABLE:
                url = data.get('target', '')
                reason = data.get('reason', '')
                etype = data.get('type', 'down')
                icon = "⚠️" if etype == "blocked" else "❌"
                log_buffer.append(f"{icon} {url} -> {reason}")
                
                # 同时存入 session 供 UI 顶端告警
                if "scan_warnings" in st.session_state:
                    st.session_state.scan_warnings.append(data)

            if len(log_buffer) > 15:
                log_buffer.pop(0)
            log_container.code('\n'.join(log_buffer), language="markdown")

    # ── 构建插件级 progress_callback (细粒度到单个 Payload) ──
    def make_plugin_progress_callback(progress_bar_ref, progress_text_ref):
        """
        生成一个 progress_callback 供 SQLi 等插件使用。
        支持 3-arg 签名: callback(current, total, label)
        - current: 当前完成的 payload 序号
        - total:   总 payload 数
        - label:   动态描述标签
        """
        def plugin_progress_cb(current: int, total: int, label: str = ""):
            if total <= 0:
                return
            pct = min(1.0, max(0.0, current / float(total)))
            progress_bar_ref.progress(pct)
            if label:
                progress_text_ref.caption(f"🔬 {label}")
            else:
                progress_text_ref.caption(
                    f"🔬 Payload 探测进度: {current}/{total} "
                    f"({pct * 100:.0f}%)"
                )
        return plugin_progress_cb



    engine = ScanEngine(config=config, ai_config=ai_config)
    engine.on_event(event_handler)
    engine.load_plugins()

    initial_ctx = {
        "target_param": params.get("target_param_input", "").strip(),
    }
    if progress_container is not None:
        plugin_cb = make_plugin_progress_callback(progress_container[0], progress_container[1])
        initial_ctx["progress_callback"] = plugin_cb

    # ── 爬虫扩展阶段 ──
    crawl_depth = params.get("crawl_depth", 0)
    scan_targets = params["targets"]
    if crawl_depth > 0:
        try:
            async def _run_spider():
                async with AsyncRequester(config) as req:
                    spider = SpiderEngine(req, max_depth=crawl_depth)
                    # crawl_all 现已自动合成表单端点 + 路径 ID 为带参数的可测试 URL
                    urls = await spider.crawl_all(scan_targets)
                    # 尝试生成企业级业务逻辑流地图 (ABFD)
                    smap = await spider.build_site_map(list(urls))
                    # 返回表单元数据供后续 POST 测试使用
                    form_data = [f.to_dict() for f in spider.form_endpoints]
                    return urls, smap.to_dict(), form_data

            # 使用安全容器运行爬虫，防止异步循环报错
            scan_targets, site_map_data, form_endpoints_data = safe_async_run(_run_spider())
            initial_ctx["site_map"] = site_map_data
            initial_ctx["form_endpoints"] = form_endpoints_data

            # 按扫描强度过滤目标
            intensity_map = {
                "轻度 (仅注入点)": "light",
                "中度 (注入点+关键端点)": "medium",
                "全量 (所有页面)": "full",
            }
            intensity = intensity_map.get(params.get("scan_intensity", ""), "light")
            scan_targets = SpiderEngine.filter_targets_by_intensity(scan_targets, intensity)
        except Exception as exc:
            import logging
            logging.getLogger("openscanner.spider").warning("爬虫阶段失败: %s", exc)

        # 状态持久化
        try:
            urls_file = Path("openscanner_urls.txt")
            urls_file.write_text("\n".join(scan_targets), encoding="utf-8")
        except Exception:
            pass

    # 运行异步扫描（在独立事件循环中隔离 Streamlit 的主循环）
    try:
        p_filter = params.get("plugin_names", [])
        if p_filter is not None:
             # 仅在远程扫描模式下强制加载，源码审计模式下跳过
             if st.session_state.get("scan_mode") == "远程漏洞扫描 (DAST)":
                 if "dom_xss_scan" not in p_filter:
                     p_filter.append("dom_xss_scan")
        
        logger.info(f"[UI] Final Execution Filter: {p_filter}")

        # 使用安全容器运行扫描，防止 Event loop is closed 错误
        results = safe_async_run(
            engine.scan(
                targets=scan_targets,
                config=config,
                plugins_filter=p_filter if p_filter else None,
                associated_source_dir=params.get("associated_source_dir", ""),
                initial_context=initial_ctx,
            )
        )
    except Exception as exc:
        raise RuntimeError(f"扫描引擎执行失败: {exc}") from exc

    return {
        "results": [r.to_dict() for r in results],
        "summary": engine.summary(),
        "events": events_log,
        "vulns": vulns_found,
        "context": engine.context,
    }

def sync_ai_engine(params: Dict[str, Any]) -> Tuple[Optional[AIEngine], str]:
    """同步侧边栏配置到 AIEngine 实例
    
    如果引擎尚未创建、配置发生变化或此前处于失效状态，则尝试重新初始化。
    """
    from core.ai.base import AIConfig, AIMode
    from core.ai.engine import AIEngine

    current_mode = AIMode[params["ai_mode"].upper()]
    
    # 检查 session 中是否已有引擎
    engine = st.session_state.get("ai_engine")
    needs_init = False
    
    if engine is None:
        needs_init = True
    else:
        # 检查配置是否发生变更 (模式 / 模型路径 / API Key)
        cfg = engine._config
        if (cfg.mode != current_mode or 
            cfg.local_model_path != params.get("ai_model_path", "") or
            cfg.api_key != params.get("ai_api_key", "") or
            cfg.api_base_url != params.get("ai_api_base", "") or
            cfg.language != params.get("ai_language", "zh") or
            cfg.api_trust_env != params.get("ai_trust_env", True) or
            cfg.api_proxy != (params.get("ai_proxy") if params.get("ai_proxy") else None)):
            needs_init = True
            logger.info("[AI/Sync] 检测到 AI 配置或网络变更，准备重新初始化...")
            # 尝试关闭旧引擎资源
            safe_async_run(engine.shutdown())
        elif not engine._initialized or not engine._provider:
            # 之前初始化失败了，如果模式不是 OFF，则尝试再次初始化
            if current_mode != AIMode.OFF:
                needs_init = True

    if needs_init:
        # 🛡️ n_ctx 安全校验: 限制在 [512, 8192] 范围内
        raw_n_ctx = params.get("local_n_ctx", 4096)
        safe_n_ctx = max(512, min(raw_n_ctx, 8192))
        
        ai_config = AIConfig(
            mode=current_mode,
            local_model_path=params.get("ai_model_path", ""),
            local_n_ctx=safe_n_ctx,
            local_n_threads=params.get("local_n_threads", 4),
            api_key=params.get("ai_api_key", ""),
            api_base_url=params.get("ai_api_base", "https://api.openai.com/v1"),
            api_model=params.get("ai_api_model", "gpt-4o-mini"),
            cache_enabled=params.get("ai_cache", True),
            language=params.get("ai_language", "zh"),
            api_trust_env=params.get("ai_trust_env", True),
            api_proxy=params.get("ai_proxy") if params.get("ai_proxy") else None,
        )
        engine = AIEngine(ai_config)
        success, msg = safe_async_run(engine.initialize())
        st.session_state["ai_engine"] = engine
        return (engine if success else None), msg
    
    return engine, "AI 引擎已就绪"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 可视化图表
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def render_severity_chart(summary: Dict):
    """漏洞等级分布饼图"""
    by_severity = summary.get("by_severity", {})
    if not by_severity:
        return

    # 确保图表即使在没漏洞时也能显示三原色分类 (H/M/L)
    all_severities = ["high", "medium", "low"]
    labels = []
    values = []
    colors = []
    
    # 优先推入用户要求的 H/M/L
    for s_name in all_severities:
        count = by_severity.get(s_name, 0)
        labels.append(s_name.upper())
        values.append(count)
        colors.append(SEVERITY_COLORS.get(s_name, "#888"))

    # 其他级别 (Critical, Info 等)
    for sev, count in by_severity.items():
        if sev not in all_severities and count > 0:
            labels.append(sev.upper())
            values.append(count)
            colors.append(SEVERITY_COLORS.get(sev, "#888"))

    import plotly.graph_objects as go

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.55,
        marker=dict(colors=colors),
        hovertemplate="<b>%{label}</b><br>数量: %{value}<br>占比: %{percent}<extra></extra>",
    )])
    fig.update_layout(
        title="漏洞等级分布",
        height=350,
        margin=dict(t=50, b=30, l=30, r=30),
    )
    st.plotly_chart(fig, use_container_width=True, theme="streamlit")


def render_plugin_chart(results: List[Dict]):
    """插件检测结果柱状图 — 动态配色版本"""
    if not results:
        return

    from collections import Counter
    import plotly.graph_objects as go

    # 获取插件元信息用于查色 (从 Session State 获取)
    plugins_meta = st.session_state.get("plugins_info", [])
    severity_map = {p["name"]: p["severity"] for p in plugins_meta}

    plugin_stats: Dict[str, Dict[str, int]] = {}
    for r in results:
        name = r.get("plugin", "unknown")
        sev_str = str(r.get("severity", "info")).lower()
        if name not in plugin_stats:
            plugin_stats[name] = {"safe": 0, "vuln": 0, "max_severity": "info"}
        
        # 核心修正：只有非 INFO 的结果才计入漏洞条目
        if r.get("vulnerable") and sev_str != "info":
            plugin_stats[name]["vuln"] += 1
            # 记录该插件涉及的最大危险等级以备着色
            current_weight = SEVERITY_WEIGHTS.get(plugin_stats[name]["max_severity"], 0)
            new_weight = SEVERITY_WEIGHTS.get(sev_str, 0)
            if new_weight > current_weight:
                plugin_stats[name]["max_severity"] = sev_str
        else:
            plugin_stats[name]["safe"] += 1

    plugins = list(plugin_stats.keys())
    plugins.sort()
    
    safe_counts = [plugin_stats[p]["safe"] for p in plugins]
    vuln_counts = [plugin_stats[p]["vuln"] for p in plugins]
    
    # 动态构建漏洞部分的颜色列表 (基于结果中的实际最大严重程度)
    vuln_colors = []
    for p in plugins:
        sev = plugin_stats[p]["max_severity"]
        # 如果没有真实漏洞，降级回 metadata 定义或默认色
        if plugin_stats[p]["vuln"] == 0:
            sev = severity_map.get(p, "info")
        
        vuln_colors.append(SEVERITY_COLORS.get(sev, "#ef4444"))

    fig = go.Figure()
    # Trace 1: 安全部分 (统一绿色)
    fig.add_trace(go.Bar(
        name="✅ 安全", x=plugins, y=safe_counts,
        marker_color="rgba(34, 197, 94, 0.7)",
        marker_line=dict(color="rgba(34, 197, 94, 1)", width=1),
    ))
    # Trace 2: 漏洞部分 (按插件等级动态配色)
    fig.add_trace(go.Bar(
        name="🚨 漏洞", x=plugins, y=vuln_counts,
        marker_color=vuln_colors,
        marker_line=dict(color="rgba(50, 50, 50, 0.2)", width=1),
    ))
    
    fig.update_layout(
        title="插件检测概览",
        barmode="stack",
        height=350,
        margin=dict(t=50, b=30, l=50, r=30),
        xaxis=dict(tickangle=45),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
    )
    st.plotly_chart(fig, use_container_width=True, theme="streamlit")


def render_waf_gauge(context: Dict):
    """WAF 拦截状态仪表盘 / 多维防御能力热力图"""
    import plotly.graph_objects as go
    import html

    waf_data = context.get("waf", {})
    heatmap = context.get("waf_heatmap")
    
    # 获取检测到的 WAF 名称
    waf_names = set()
    for info in waf_data.values():
        for name in info.get("waf_list", []):
            waf_names.add(name)

    if waf_names:
        safe_waf_names = html.escape(', '.join(waf_names))
        st.markdown(
            f"<div class='waf-card'><h4>🛡️ 检测到 Web 应用防火墙 (WAF)</h4>"
            f"<p style='opacity: 0.85; margin: 0'>{safe_waf_names}</p></div>",
            unsafe_allow_html=True,
        )

    if heatmap and heatmap.get("dimensions"):
        st.markdown("<h4 style='margin-top: 10px'>🛡️ WAF 多维防御能力热力图</h4>", unsafe_allow_html=True)
        
        score = heatmap.get("overall_score", 0)
        score_color = "#22c55e" if score >= 80 else "#eab308" if score >= 50 else "#ef4444"
        safe_strongest = html.escape(str(heatmap.get('strongest_dimension', 'N/A')))
        safe_weakest = html.escape(str(heatmap.get('weakest_dimension', 'N/A')))
        
        st.markdown(
            f"<div class='waf-card' style='border-left-color: {score_color}; background-color: var(--background-color); border: 1px solid rgba(150,150,150,0.1);'>"
            f"<h4>总体防护能力评分: <span style='color: {score_color}; font-size: 1.25rem'>{score:.1f} / 100</span></h4>"
            f"<p style='font-size:0.9rem; opacity:0.8; margin-top: 6px'>最强防御维度: <b style='color:#22c55e'>{safe_strongest}</b> | "
            f"最弱盲区维度: <b style='color:#ef4444'>{safe_weakest}</b></p>"
            "</div>",
            unsafe_allow_html=True
        )

        table_html = "<table style='width: 100%; table-layout: fixed; border-collapse: collapse; margin-top: 12px; font-size: 0.9rem;'>"
        table_html += "<tr style='background: var(--secondary-background-color); border-bottom: 2px solid rgba(150,150,150,0.2)'>"
        table_html += "<th style='padding: 10px; text-align: left; width: 18%'>攻击维度</th>"
        table_html += "<th style='padding: 10px; text-align: center; width: 10%'>拦截率</th>"
        table_html += "<th style='padding: 10px; text-align: center; width: 12%'>防护等级</th>"
        table_html += "<th style='padding: 10px; text-align: left; width: 25%'>防护条</th>"
        table_html += "<th style='padding: 10px; text-align: left; width: 35%; overflow: hidden; text-overflow: ellipsis;'>绕过示例 (First Bypass)</th></tr>"

        for dim in heatmap["dimensions"]:
            rate = dim.get("block_rate", 0) * 100 
            level = dim.get("protection_level", "")
            bypassed = dim.get("bypassed_payloads", [])
            color = "#22c55e" if rate >= 80 else "#eab308" if rate >= 50 else "#ef4444"
            
            bypass_text = bypassed[0][:35] + "…" if bypassed else "—"
            bypass_text = html.escape(bypass_text)

            bar_html = f"""
            <div style="background: rgba(150,150,150,0.1); border-radius: 4px; width: 100%; max-width: 100%; height: 10px; margin-top: 2px; overflow: hidden;">
                <div style="background: {color}; border-radius: 4px; width: {rate:.0f}%; height: 100%;"></div>
            </div>
            """
            safe_dim = html.escape(str(dim['dimension']))
            safe_level = html.escape(str(level))
            table_html += "<tr style='border-bottom: 1px solid rgba(150,150,150,0.1)'>"
            table_html += f"<td style='padding: 10px; font-weight: 600'>{safe_dim}</td>"
            table_html += f"<td style='padding: 10px; text-align: center; color: {color}; font-weight: bold'>{rate:.0f}%</td>"
            table_html += f"<td style='padding: 10px; text-align: center'>{safe_level}</td>"
            table_html += f"<td style='padding: 10px'>{bar_html}</td>"
            table_html += f"<td style='padding: 10px; font-family: monospace; font-size: 0.85em; opacity: 0.8; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 0;'>{bypass_text}</td>"
            table_html += "</tr>"
        
        table_html += "</table><br>"
        st.markdown(table_html, unsafe_allow_html=True)
        
    else:
        # Fallback 到旧的 Gauge
        total_targets = max(len(context.get("_targets", [])), 1)
        waf_count = len(waf_data)
        waf_pct = (waf_count / total_targets) * 100 if total_targets > 0 else 0

        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=waf_pct,
            number=dict(suffix="%"),
            title=dict(text="WAF 检出率"),
            gauge=dict(
                axis=dict(range=[0, 100]),
                bar=dict(color="#eab308"),
                steps=[
                    dict(range=[0, 30], color="rgba(34, 197, 94, 0.1)"),
                    dict(range=[30, 70], color="rgba(234, 179, 8, 0.1)"),
                    dict(range=[70, 100], color="rgba(239, 68, 68, 0.1)"),
                ],
            ),
        ))
        fig.update_layout(
            height=280,
            margin=dict(t=60, b=20, l=30, r=30),
        )
        st.plotly_chart(fig, use_container_width=True, theme="streamlit")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 漏洞卡片渲染
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def render_ai_audit_card(vuln: Dict[str, Any]):
    """渲染 AI 专用审计报告卡片"""
    extra = vuln.get("extra", {})
    findings = extra.get("findings", [])
    total_issues = extra.get("total_issues", 0)
    failed_files = extra.get("failed_files", 0)

    # 提取危险等级
    overall_sev = vuln.get("severity", "high").lower()
    sev_colors = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#3b82f6",
        "info": "#22c55e"
    }
    border_color = sev_colors.get(overall_sev, "#8e44ad")

    # 根据是否有发现选择不同的状态标签
    if total_issues > 0:
        status_badge = f'<span style="background: #ef4444; color: white; padding: 4px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: bold; margin-left: 8px;">⚠️ 代码危险</span>'
    elif failed_files > 0:
        status_badge = f'<span style="background: #f97316; color: white; padding: 4px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: bold; margin-left: 8px;">⚠️ 部分审计失败</span>'
    else:
        status_badge = f'<span style="background: #22c55e; color: white; padding: 4px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: bold; margin-left: 8px;">✅ 审计通过</span>'

    with st.container():
        st.markdown(f"""
        <div style="background: rgba(138, 43, 226, 0.05); border-left: 5px solid {border_color}; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div>
                    <span style="background: #8e44ad; color: white; padding: 4px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: bold; margin-right: 8px;">🤖 AI ANALYSIS REPORT</span>
                    <span style="background: {border_color}; color: white; padding: 4px 12px; border-radius: 4px; font-size: 0.8rem; font-weight: bold;">危险等级: {overall_sev.upper()}</span>
                    {status_badge}
                    <h3 style="margin: 10px 0 5px 0; color: {border_color};">{vuln.get('detail', 'AI 深度审计发现')}</h3>
                    <p style="opacity: 0.7; font-size: 0.9rem;">审计路径: {vuln.get('url', 'Unknown')}</p>
                </div>
                <div style="text-align: right;">
                    <p style="margin: 0; opacity: 0.6; font-size: 0.8rem;">发现时间</p>
                    <p style="margin: 0; font-weight: bold;">{time.strftime('%H:%M:%S', time.localtime(vuln.get('timestamp', time.time())))}</p>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        if findings:
            for f in findings:
                # 根据文件扩展名推断代码语言
                file_path = f.get('file', '')
                lang_map = {'.py': 'python', '.php': 'php', '.js': 'javascript', '.go': 'go', '.java': 'java', '.sql': 'sql'}
                code_lang = 'python'
                for ext, lang in lang_map.items():
                    if file_path.endswith(ext):
                        code_lang = lang
                        break

                with st.expander(f"📌 [{f.get('severity', 'high').upper()}] {f.get('type')} - {f.get('file')}:{f.get('line')}", expanded=True):
                    col1, col2 = st.columns([2, 1])
                    with col1:
                        st.markdown("**🛡️ 漏洞成因分析**")
                        st.write(f.get("description", "未提供详细描述"))
                    with col2:
                        st.markdown("**💡 修复建议**")
                        st.info(f.get("recommendation", "暂无具体建议"))

                    evidence = f.get("evidence", "")
                    if evidence:
                        st.markdown("**🔍 相关危险代码段 (Evidence)**")
                        st.code(evidence, language=code_lang)
        elif failed_files > 0:
            st.warning(f"⚠️ 共有 {failed_files} 个文件的 AI 审计未能成功完成，请检查 AI 引擎配置或查看日志。")

def render_vuln_card(vuln: Dict[str, Any], params: Dict[str, Any]):
    """渲染单个漏洞告警卡片"""
    import html
    def safe_html(text: Any) -> str:
        if text is None:
            return ""
        return html.escape(str(text))

    sev = vuln.get("severity", "info").lower()
    plugin_name_lower = vuln.get("display_name", vuln.get("plugin", "")).lower()
    
    # 强制将 BOLA / IDOR 识别为 Warning (黄色)
    is_bola = "bola" in plugin_name_lower or "idor" in plugin_name_lower
    if is_bola:
        sev = "warning"
        
    badge_class = f"badge-{sev}"

    detail = safe_html(vuln.get("detail", ""))
    evidence_raw = vuln.get("evidence", "")
    url = safe_html(vuln.get("url", ""))
    plugin = safe_html(vuln.get("display_name", vuln.get("plugin", "")))

    # 提取 payload 与 CVSS
    extra = vuln.get("extra", {})
    findings = extra.get("findings", [])
    cvss = extra.get("cvss_score")
    
    cvss_html = f'<span style="background-color: var(--primary-color); color: white; padding: 2px 6px; border-radius: 4px; font-weight: bold; margin-left: 8px; font-size: 0.85rem">CVSS: {safe_html(cvss)}</span>' if cvss else ""


    payload_html = ""
    if findings:
        mode = st.session_state.get("scan_mode", "远程漏洞扫描 (DAST)")
        if mode == "本地源码审计 (SAST)":
            # 按照文件名对恶意发现进行编组
            from collections import defaultdict
            grouped = defaultdict(list)
            for f in findings:
                file_path = f.get("file", "Unknown File")
                grouped[file_path].append(f)
                
            payload_html = '<div style="margin-top: 12px;">'
            for file_path, file_findings in grouped.items():
                safe_fp = safe_html(file_path)
                # 为每个文件创建一个 st 内部的 HTML 展开层
                payload_html += (
                    f'<details style="margin-bottom: 8px; background: var(--secondary-background-color); border: 1px solid rgba(150,150,150,0.2); border-radius: 6px; padding: 8px;">'
                    f'<summary style="cursor: pointer; font-weight: bold; opacity: 0.9; outline: none; margin-bottom: 4px">'
                    f'📂 {safe_fp} <span style="font-size: 0.8rem; background: var(--primary-color); color: white; border-radius: 12px; padding: 2px 8px; margin-left: 6px;">{len(file_findings)} 个风险点</span>'
                    f'</summary>'
                    f'<div style="padding-left: 20px; font-size: 0.9rem; opacity: 0.85; margin-top: 6px;">'
                )
                for f in file_findings:
                    loc = f.get("line", 0)
                    loc_str = f"Line {loc}" if loc else "File-level"
                    safe_type = safe_html(f.get("type", "Unknown"))
                    safe_ev = safe_html(f.get("evidence", "没有提供详细证据"))
                    payload_html += f'<div style="margin-bottom: 6px;"><b>[{safe_type}]</b> ({loc_str})<br>↳ <i>{safe_ev}</i></div>'
                
                payload_html += "</div></details>"
            payload_html += "</div>"
        else:
            # 兼容 DAST 漏洞展示样式
            for f in findings[:5]:
                p = f.get("payload") or f.get("true_payload", "")
                db = f.get("db_type", "")
                ftype = f.get("type", "")
                if p:
                    payload_html += '<div class="payload">'
                    if f.get("browser_verified"):
                        payload_html += '<span style="color:#22c55e; border: 1px solid #22c55e; border-radius: 4px; padding: 1px 4px; font-size: 0.7em; margin-right: 6px;">✔️ POF VERIFIED</span>'
                    payload_html += f'💉 {safe_html(p)}</div>'
                if db:
                    payload_html += f'<span style="color:#facc15">🗄️ Database: {safe_html(db)}</span> '
                if ftype:
                    payload_html += f'<span style="opacity: 0.7">| Type: {safe_html(ftype)}</span><br>'

    # ── 🧪 全量探测矩阵渲染 ──
    matrix_html = ""
    attempts = extra.get("attempts", [])
    if attempts:
        rows = ""
        for att in attempts[:50]: # 最多展示50条以防撑爆页面
            p = safe_html(str(att.get("payload", "")))
            t = safe_html(str(att.get("type", "")))
            s = att.get("status", "Unknown")
            info = safe_html(str(att.get("info", "")))
            
            icon = "✅" if s == "Vulnerable" else ("❌" if s == "Safe" else "⚠️")
            color = "#22c55e" if s == "Vulnerable" else ("#94a3b8" if s == "Safe" else "#facc15")
            
            rows += (
                f'<tr style="border-bottom: 1px solid rgba(255,255,255,0.05)">'
                f'<td style="padding: 4px; font-size: 0.8em; color: {color}">{icon} {s}</td>'
                f'<td style="padding: 4px; font-size: 0.8em; opacity: 0.8">{t}</td>'
                f'<td style="padding: 4px; font-size: 0.8em; font-family: monospace; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{p}</td>'
                f'<td style="padding: 4px; font-size: 0.8em; opacity: 0.6">{info}</td>'
                f'</tr>'
            )
        
        matrix_html = (
            f'<details style="margin-top: 10px; border: 1px solid rgba(255,255,255,0.1); border-radius: 6px; padding: 8px;">'
            f'<summary style="font-size: 0.85em; cursor: pointer; color: #a855f7">🧪 完整探测矩阵 (Consensus Matrix - 共 {len(attempts)} 条记录)</summary>'
            f'<table style="width: 100%; margin-top: 8px; border-collapse: collapse;">'
            f'<thead>'
            f'<tr style="text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1); opacity: 0.7; font-size: 0.75em;">'
            f'<th style="padding: 4px">结果</th><th style="padding: 4px">类型</th><th style="padding: 4px">Payload</th><th style="padding: 4px">详情</th>'
            f'</tr>'
            f'</thead>'
            f'<tbody>{rows}</tbody>'
            f'</table>'
            f'</details>'
        )

    evidence_html = ""
    if evidence_raw:
        esc = safe_html(evidence_raw)
        evidence_html = f'<div class="evidence" style="margin-top: 10px"><strong>🔍 证据:</strong><br>{esc}</div>'

    if is_bola:
        card_html = (
            f'<div class="vuln-card-warning">'
            f'<details style="cursor: pointer; outline: none; width: 100%;" open>'
            f'<summary style="display: flex; justify-content: space-between; align-items: center; list-style: none; width: 100%;">'
            f'<div style="display: flex; align-items: center; flex: 1;">'
            f'<h4 style="display: inline-block; margin: 0; white-space: nowrap;">⚠️ {plugin}</h4>'
            f'{cvss_html}'
            f'</div>'
            f'<div style="display: flex; align-items: center; justify-content: flex-end; min-width: 180px;">'
            f'<span class="badge {badge_class}" style="margin-right: 12px;">{sev.upper()}</span>'
            f'<span style="font-size: 0.8rem; opacity: 0.6; white-space: nowrap;">点击收起/展开</span>'
            f'</div>'
            f'</summary>'
            f'<div style="margin-top: 15px; cursor: default; border-top: 1px solid rgba(234, 179, 8, 0.1); padding-top: 12px;">'
            f'<p style="opacity: 0.7; font-size: 0.85rem; margin: 4px 0">🎯 {url}</p>'
            f'<p style="opacity: 0.85; margin: 8px 0">{detail}</p>'
            f'{payload_html}{matrix_html}{evidence_html}'
            f'</div>'
            f'</details>'
            f'</div>'
        )
    else:
        card_html = (
            f'<div class="vuln-card">'
            f'<div style="display: flex; justify-content: space-between; align-items: center; width: 100%;">'
            f'<div style="display: flex; align-items: center; flex: 1;">'
            f'<h4 style="display: inline-block; margin: 0; white-space: nowrap;">🚨 {plugin}</h4>'
            f'{cvss_html}'
            f'</div>'
            f'<span class="badge {badge_class}">{sev.upper()}</span>'
            f'</div>'
            f'<div style="margin-top: 12px;">'
            f'<p style="opacity: 0.7; font-size: 0.85rem; margin: 4px 0">🎯 {url}</p>'
            f'<p style="opacity: 0.85; margin: 8px 0">{detail}</p>'
            f'{payload_html}{matrix_html}{evidence_html}'
            f'</div>'
            f'</div>'
        )
    st.markdown(card_html, unsafe_allow_html=True)

    # ━━ AI Talk-to-Vuln 与 RLHF 纠错反馈 ━━
    col_rlhf, col_chat = st.columns([1, 1])
    
    with col_rlhf:
        if st.button("👎 标记为误报 (RLHF 纠错)", key=f"rlhf_{url}_{plugin}", help="这是一个误报！将证据保存到本地大模型知识库，防止 AI 下次再犯同样的错误。"):
            from core.ai.rlhf import RLHFManager
            mgr = RLHFManager()
            # 这里的 prompt 实际上应该是引发漏洞的那一段HTTP请求，这里简单用 detail 取代
            mgr.submit_feedback(
                plugin=plugin, 
                prompt=f"Target: {url}\nDetails: {detail}\nEvidence: {evidence_raw}", 
                actual_verdict=False, 
                reason="人工现场复核确认"
            )
            st.toast("✅ 反馈已写入 RLHF 知识库，AI 将在后续扫描中主动规避此类误报。")

    with col_chat:
        with st.expander("💬 漏洞对话助手 (Talk-to-Vuln)", expanded=False):
            st.info("基于上下文的漏洞助手。你可以问：'帮我写一个Python POC', '这个洞影响大吗'")
            chat_input = st.text_input("向 AI 提问...", key=f"chat_{url}_{plugin}")
            if chat_input:
                st.write(f"**用户:** {chat_input}")
                with st.spinner("AI 正在思考..."):
                    import asyncio
                    # ── 核心修复：确保对话前同步配置 ──
                    engine, msg = sync_ai_engine(params)
                    if not engine:
                        st.error(f"⚠️ AI 引擎同步失败: {msg}")
                    else:
                        try:
                            from core.ai.base import AIRole
                            from core.ai.prompts import get_system_prompt
                            
                            lang = params.get("ai_language", "zh")
                            sys_p = get_system_prompt("CHAT_ASSISTANT", lang)
                            
                            resp = safe_async_run(
                                engine._predict(
                                    role=AIRole.CHAT_ASSISTANT,
                                    system_prompt=sys_p,
                                    user_prompt=f"Vulnerability Context: URL={url}, Plugin={plugin}, Detail={detail}\nUser Question: {chat_input}"
                                )
                            )
                            if resp.success and resp.raw_text:
                                st.write(f"**AI助手:** {resp.raw_text}")
                            elif resp.error:
                                st.error(f"AI 助手出错: {resp.error}")
                            else:
                                st.warning("AI 助手返回了空响应，请检查模型配置或网络。")
                        except Exception as e:
                            st.error(f"对话失败: {str(e)}")

    # ━━ AI 深度交叉验证 (AVA Review) ━━
    with st.expander("🕵️‍♂️ 深度交叉验证报告 (AVA Review)", expanded=False):
        st.markdown("该功能会启用自我对抗复核，从多个维度审查初始判决，量化误报风险。")
        if st.button("🚀 启动深度校验", key=f"ava_{url}_{plugin}"):
            engine, msg = sync_ai_engine(params)
            if not engine:
                st.error(f"⚠️ AI 引擎不可用: {msg}")
            else:
                with st.spinner("AI 正在执行对抗性复核 (Proposer -> Critic -> Finalizer)..."):
                    import asyncio
                    from core.ai.auditor import AIReviewer
                    from core.ai.prompts import get_user_template
                    
                    lang = params.get("ai_language", "zh")
                    context_template = get_user_template("EXPLOIT_VERIFIER", lang)
                    
                    # 构建探测矩阵字符串供 AI 参考
                    attempts_list = extra.get("attempts", [])
                    matrix_summary = ""
                    if attempts_list:
                        for a in attempts_list[:30]: # AI 只看前30条核心数据
                            res_icon = "✓" if a.get("status") == "Vulnerable" else "✗"
                            matrix_summary += f"{res_icon} [{a.get('type')}] Payload: {a.get('payload')}\n"
                    else:
                        matrix_summary = "没有可用的探测矩阵数据 (旧版探测)."

                    context_prompt = context_template.format(
                        url=url,
                        method=vuln.get("method", "GET/POST"),
                        param=vuln.get("param", "N/A"),
                        waf_detected=vuln.get("waf_detected", "Unknown"),
                        payload_matrix=matrix_summary,
                        status_code=vuln.get("status_code", "N/A"),
                        response_time=vuln.get("response_time", "N/A"),
                        content_length=vuln.get("content_length", "N/A"),
                        response_body=evidence_raw[:2000] if evidence_raw else "N/A"
                    )
                    
                    reviewer = AIReviewer(engine)
                    proposer_verdict = f"初始扫描判定此为 {sev.upper()} 级别漏洞。证据提取：{detail[:500]}..."
                    
                    ava_result = safe_async_run(reviewer.run_ava_review(context_prompt, proposer_verdict))
                    
                    if "error" in ava_result:
                        st.error(ava_result["error"])
                    else:
                        st.success(f"✅ AVA 验证完成 (耗时: {ava_result.get('latency', 0)/1000:.1f}s)")
                        
                        f_data = ava_result.get("finalizer", {})
                        c_data = ava_result.get("critic", {})
                        
                        st.markdown(f"**最终裁定:** `{f_data.get('verdict', 'Unknown')}` (信心值: {f_data.get('confidence_score', 0):.2f})")
                        st.markdown(f"**复核简报:** {f_data.get('overall_evaluation', '')}")
                        
                        st.markdown("### 📊 量化指标 (Metrics)")
                        metrics = f_data.get("metrics", {})
                        
                        m1, m2, m3, m4 = st.columns(4)
                        m1.metric("证据强度 (0-10)", metrics.get("evidence_strength", 0))
                        m2.metric("逻辑严密性 (0-10)", metrics.get("logic_cohesion", 0))
                        fp_prob = float(metrics.get("fp_probability", 0))
                        m3.metric("误报风险 (0-10)", fp_prob, delta="高风险" if fp_prob>5 else "低风险", delta_color="inverse")
                        m4.metric("行动确定性 (0-10)", metrics.get("actionability", 0))
                        
                        with st.expander("🔍 查看 Critic 反向对抗摘要"):
                            st.info(c_data.get("criticism", "无"))

    # ━━ 视觉取证截图 (Visual Proof / VEPV) ━━
    screenshots = extra.get("screenshots", [])
    # 兼容单个元素的提取
    old_screenshot = extra.get("screenshot_b64", "")
    if old_screenshot and old_screenshot not in screenshots:
        screenshots.append(old_screenshot)

    if screenshots:
        import base64 as b64_mod
        for idx, screenshot_b64 in enumerate(screenshots, 1):
            try:
                img_bytes = b64_mod.b64decode(screenshot_b64)
                st.image(img_bytes, caption=f"📸 弹窗触发瞬间截图证明 (Visual Proof #{idx})", use_container_width=True)
            except Exception:
                pass

    # ━━ 一键复现 POC 脚本 ━━
    poc_script = extra.get("poc_script", "")
    if poc_script:
        with st.expander("🛠️ 一键复现 POC 脚本 (点击展开并复制)", expanded=False):
            st.code(poc_script, language="python")

    # ━━ 代码级修复建议 (Patch Suggestions) ━━
    patches = extra.get("patch_suggestions", [])
    if patches:
        with st.expander("🩹 代码级精准修复建议 (AST-to-Patch)", expanded=False):
            for pi, patch in enumerate(patches, 1):
                p_file = patch.get("file", "unknown")
                p_line = patch.get("line", 0)
                p_conf = patch.get("confidence", 0)
                p_diff = patch.get("patch_diff", "")
                p_expl = patch.get("explanation", "")
                st.markdown(f"**Patch {pi}** — `{p_file}` (Line {p_line}) — 置信度 {p_conf:.0%}")
                st.code(p_diff, language="diff")
                if p_expl:
                    st.info(f"💡 {p_expl}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# JSON 报告导出
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def build_json_report(results: List[Dict], summary: Dict, context: Dict) -> str:
    """构建 JSON 报告"""
    report = {
        "scanner": "OpenScanner v1.0.0",
        "scan_time": datetime.now().isoformat(),
        "summary": summary,
        "waf_detection": context.get("waf", {}),
        "vulnerabilities": [r for r in results if r.get("vulnerable")],
        "all_results": results,
    }
    return json.dumps(report, indent=2, ensure_ascii=False, default=str)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 主界面
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main():
    params = render_sidebar()

    # ── 标题区 ──
    st.markdown('<h1 class="scanner-title">🔍 OpenScanner Dashboard</h1>', unsafe_allow_html=True)
    st.markdown('<p class="subtitle">OpenScanner — Async Web Vulnerability Scanner — 实时扫描控制台</p>', unsafe_allow_html=True)
    st.markdown('<div class="cyber-divider"></div>', unsafe_allow_html=True)

    # ── 扫描执行 ──
    if params["scan_btn"] and params["targets"]:
        st.session_state.scan_running = True
        st.session_state.scan_warnings = []
        
        # 记录本次使用的配置，下次自动填充
        save_persistent_settings(params)
        
        # 使用 sync_ai_engine 统一初始化入口
        engine, msg = sync_ai_engine(params)
        if not engine and params["ai_mode"] != "OFF":
            st.sidebar.warning(f"AI 预初始化提示: {msg}")

        with st.status("⚡ 扫描引擎启动中...", expanded=True) as status:
            st.write("🔌 加载插件模块...")
            st.write(f"🎯 目标: {len(params['targets'])} 个 URL")
            st.write(f"⚙️ 并发: {params['concurrency']} | 超时: {params['timeout']}s | HTTP/2: {params['http2']}")

            st.write("---")

            # HUD (Heads-Up Display) 区域
            with st.container():
                st.markdown("### 🔄 扫描状态")
                # 使用两列或容器来优化布局
                hud_col1, hud_col2 = st.columns([1, 4])
                with hud_col1:
                    st.markdown("#### **Progress**")
                with hud_col2:
                    progress_bar = st.progress(0.0)
                
                progress_text = st.empty()
                st.markdown('<div style="margin-bottom: 20px;"></div>', unsafe_allow_html=True)
            
            log_container = st.empty()
            log_container.code("[+] 引擎初始化就绪，准备扫描...\n", language="markdown")

            st.markdown('<div class="cyber-divider"></div>', unsafe_allow_html=True)

            try:
                scan_result = run_async_scan(
                    params, 
                    ai_config=engine._config if engine else None,
                    log_container=log_container, 
                    progress_container=(progress_bar, progress_text)
                )

                vulns = scan_result["vulns"]
                total = scan_result["summary"].get("total_checks", 0)
                vuln_count = scan_result["summary"].get("vulnerabilities_found", 0)

                if vuln_count > 0:
                    status.update(
                        label=f"🚨 扫描完成 — 发现 {vuln_count} 个安全问题",
                        state="error",
                        expanded=True,
                    )
                else:
                    status.update(
                        label=f"✅ 扫描完成 — {total} 项检测全部安全",
                        state="complete",
                        expanded=False,
                    )

                # 存入 session
                st.session_state.scan_results = scan_result["results"]
                st.session_state.scan_summary = scan_result["summary"]
                st.session_state.scan_vulns = vulns
                st.session_state.scan_waf = scan_result["context"]
                st.session_state.scan_log = scan_result["events"]

            except Exception as exc:
                status.update(label=f"❌ 扫描失败: {exc}", state="error")
                st.error(f"扫描引擎异常: {exc}")

            finally:
                st.session_state.scan_running = False

    # ── 结果展示 ──
    summary = st.session_state.scan_summary
    results = st.session_state.scan_results
    vulns = st.session_state.scan_vulns
    context = st.session_state.scan_waf

    if not results:
        # 空状态
        st.markdown("""
        <div style="text-align: center; padding: 60px 0; opacity: 0.6">
            <p style="font-size: 3rem; margin: 0">🔦</p>
            <p style="font-size: 1.2rem; margin-top: 12px">配置左侧参数，点击 <b>🚀 启动扫描</b> 开始漏洞检测</p>
            <p style="font-size: 0.9rem; margin-top: 8px">
                支持 WAF 探测 → SQL 注入检测 两阶段自动化扫描
            </p>
        </div>
        """, unsafe_allow_html=True)
        return

    # ── 统计指标卡 ──
    mode = st.session_state.get("scan_mode", "远程漏洞扫描 (DAST)")
    
    # 获取插件中回传的总文件数（对 SAST）
    audit_files_count = 0
    if results:
        for r in results:
            if "total_files" in r.get("extra", {}):
                audit_files_count += r["extra"]["total_files"]

    # 重计算：所有的发现问题累加    # 计数矫正：排除 INFO 级别的审计结论
    real_vuln_count = sum(
        v.get("extra", {}).get("total_issues", 1) 
        for v in vulns 
        if str(v.get("severity", "info")).lower() != "info"
    )
    
    m1, m2, m3, m4 = st.columns(4)
    if mode == "本地源码审计 (SAST)":
        with m1:
            st.metric("🔌 插件总数", summary.get("plugins_loaded", 0))
        with m2:
            st.metric("📂 审计文件总数", audit_files_count)
        with m3:
            st.metric("🚨 风险点总数", real_vuln_count, delta=f"-{real_vuln_count}" if real_vuln_count else None, delta_color="inverse")
        with m4:
            st.metric("⏱️ 审计耗时", f"{summary.get('elapsed_seconds', 0):.1f}s")
    else:
        with m1:
            st.metric("🔌 插件总数", summary.get("plugins_loaded", 0))
        with m2:
            st.metric("🎯 检测总数", summary.get("total_checks", 0))
        with m3:
            st.metric("🚨 发现漏洞", real_vuln_count, delta=f"-{real_vuln_count}" if real_vuln_count else None, delta_color="inverse")
        with m4:
            st.metric("⏱️ 扫描耗时", f"{summary.get('elapsed_seconds', 0):.1f}s")

    st.markdown('<div class="cyber-divider"></div>', unsafe_allow_html=True)
    
    # ── 连通性预警区 ──
    warnings = st.session_state.get("scan_warnings", [])
    if warnings:
        for w in warnings:
            target = w.get("target", "Unknown")
            reason = w.get("reason", "未知原因")
            etype = w.get("type", "down")
            if etype == "blocked":
                st.warning(f"🛡️ **存在 WAF 拦截**: [{target}] — {reason}")
            else:
                st.error(f"🔌 **网址不通/连接失败**: [{target}] — {reason}")

    # ── 漏洞与 AI 审计结论分流 ──
    # 核心修复：AI 审计报告即使不是“漏洞”(is_vulnerable=False) 也需要展示在审计卡片区
    standard_vulns = [v for v in vulns if not v.get("extra", {}).get("is_ai_result")]
    ai_audit_vulns = [r for r in results if r.get("extra", {}).get("is_ai_result")]

    # ── 1. 传统漏洞告警区 ──
    if standard_vulns:
        st.markdown("## 🚨 漏洞告警 (Technical Findings)")
        for v in standard_vulns:
            render_vuln_card(v, params)
    
    # ── 2. AI 深度审计报告区 (直接跟在漏洞告警下方) ──
    if ai_audit_vulns:
        if standard_vulns:
            # 如果上方有常规漏洞，加一个细长的分层提示
            st.markdown('<div style="margin: 30px 0 10px 0; border-top: 1px dashed rgba(255,255,255,0.1);"></div>', unsafe_allow_html=True)
        
        st.markdown("## 🤖 AI 源代码深度审计报告 (Deep Analysis)")
        for v in ai_audit_vulns:
            render_ai_audit_card(v)

    if not standard_vulns and not ai_audit_vulns:
        # 只有在两边都没有结果的情况下才显示“全绿”
        st.markdown(
            '<div class="safe-card"><h4>✅ 所有检测项均安全</h4>'
            '<p style="opacity: 0.85; margin: 0">未发现安全漏洞，目标通过所有检测。</p></div>',
            unsafe_allow_html=True,
        )

    st.markdown('<div class="cyber-divider"></div>', unsafe_allow_html=True)

    # ── 可视化报表 ──
    st.markdown("## 📊 可视化报表")

    chart_col1, chart_col2 = st.columns([1, 1])

    with chart_col1:
        if summary.get("by_severity"):
            render_severity_chart(summary)
        else:
            st.info("暂无漏洞等级数据")

        if results:
            render_plugin_chart(results)

    with chart_col2:
        if results:
            render_waf_gauge(context)
        else:
            st.info("暂无 WAF 数据")

    # 渲染 ABFD 的 site_map 数据
    site_map = context.get("site_map")
    if site_map:
        st.markdown('<div class="cyber-divider"></div>', unsafe_allow_html=True)
        st.markdown("## 🗺️ 业务逻辑架构发现 (ABFD)")
        with st.expander("查看自动发现的业务流聚类与 API 拓扑", expanded=True):
            st.json(site_map)

    st.markdown('<div class="cyber-divider"></div>', unsafe_allow_html=True)

    # ── 详细结果表 ──
    st.markdown("## 📋 详细结果")

    import pandas as pd
    df_data = []
    for r in results:
        sev = r.get("severity", "info").lower()
        pl = r.get("plugin", "").lower()
        
        # 统一 BOLA 逻辑
        if "bola" in pl or "idor" in pl:
            sev = "medium"
            
        emoji = SEVERITY_EMOJI.get(sev, "")
        
        is_vuln = r.get("vulnerable")
        status_text = "🚨 漏洞" if is_vuln else "✅ 安全"
        
        # 对 AI 审计报告进行特殊状态显示
        if r.get("extra", {}).get("is_ai_result"):
            if sev == "info":
                status_text = "ℹ️ 审计报告"
            elif is_vuln:
                status_text = "🚨 逻辑风险"
            else:
                status_text = "✅ 审计通过"

        df_data.append({
            "插件": r.get("plugin", ""),
            "目标 URL": r.get("url", "")[:50],
            "状态": status_text,
            "等级": f"{emoji} {sev.upper()}",
            "详情": (r.get("detail", ""))[:60],
        })

    if df_data:
        df = pd.DataFrame(df_data)
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "目标 URL": st.column_config.TextColumn(width="medium"),
                "详情": st.column_config.TextColumn(width="large"),
            },
        )

    st.markdown('<div class="cyber-divider"></div>', unsafe_allow_html=True)

    # ── 报告下载区 ──
    st.markdown("## 📥 导出报告")

    report_json = build_json_report(results, summary, context)

    # 生成 Markdown 报告
    try:
        gen = ReportGenerator(
            results=results,
            summary=summary,
            context=context,
            targets=[r.get("url", "") for r in results],
        )
        report_md = gen.to_markdown()
    except Exception:
        report_md = "报告生成失败"

    col_dl1, col_dl2, col_dl3 = st.columns(3)
    with col_dl1:
        st.download_button(
            label="📥 下载 JSON 报告",
            data=report_json,
            file_name=f"openscanner_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True,
            type="primary",
        )
    with col_dl2:
        st.download_button(
            label="📄 下载 Markdown 报告",
            data=report_md,
            file_name=f"openscanner_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            mime="text/markdown",
            use_container_width=True,
        )
    with col_dl3:
        # URL 清单导出 (状态持久化)
        all_urls = "\n".join(set(r.get("url", "") for r in results if r.get("url")))
        st.download_button(
            label="🔗 导出 URL 清单",
            data=all_urls,
            file_name="openscanner_urls.txt",
            mime="text/plain",
            use_container_width=True,
        )

    # 报告预览
    with st.expander("📄 JSON 报告预览", expanded=False):
        st.json(json.loads(report_json))
    with st.expander("📃 Markdown 报告预览", expanded=False):
        st.markdown(report_md)


if __name__ == "__main__":
    main()
