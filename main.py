#!/usr/bin/env python3
"""
main.py — OpenScanner CLI 指挥中心

工业级命令行界面:
  • Rich Console 实时渲染扫描进度
  • 两阶段可视化 (INFO 侦察 → POC 漏洞扫描)
  • 漏洞发现时红色高亮 Payload 和证据
  • 最终彩色汇总报表
  • 异步并发, 异常不崩溃

Usage:
    python main.py                          → 使用默认目标演示
    python main.py -t https://target.com    → 扫描指定目标
    python main.py -t url1 -t url2          → 批量扫描
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Windows GBK 编码兼容性修复 ──
# 中文 Windows 终端默认使用 GBK 编码，无法输出 emoji 和特殊 Unicode 字符，
# 会导致 Rich 渲染时抛出 UnicodeEncodeError。
# 在导入 Rich 之前强制切换到 UTF-8。
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        # 将 Windows 控制台代码页切换为 UTF-8 (65001)
        os.system("chcp 65001 >nul 2>&1")
        # 重新包装 stdout/stderr 为 UTF-8 编码，防止 Rich legacy renderer 使用 GBK
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# 确保项目根在 sys.path 中
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich.columns import Columns
from rich.rule import Rule
from rich.align import Align
from rich import box

from core.engine import ScanEngine, ScanEvent, PluginCategory
from core.request import RequestConfig, AsyncRequester
from core.spider import SpiderEngine
from plugins.base import Severity
from utils.reporter import ReportGenerator
from core.ai.base import AIConfig, AIMode


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Rich Console
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

console = Console()

# 配色方案
COLORS = {
    "brand": "bold cyan",
    "info": "blue",
    "low": "green",
    "medium": "yellow",
    "high": "red",
    "critical": "bold magenta",
    "success": "bold green",
    "warning": "bold yellow",
    "error": "bold red",
    "dim": "dim white",
    "accent": "bold bright_cyan",
}

SEVERITY_STYLE = {
    "info": "[blue]INFO[/blue]",
    "low": "[green]LOW[/green]",
    "medium": "[yellow]MEDIUM[/yellow]",
    "high": "[bold red]HIGH[/bold red]",
    "critical": "[bold magenta]CRITICAL[/bold magenta]",
}


def severity_badge(sev: str) -> str:
    return SEVERITY_STYLE.get(sev, sev)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Banner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

BANNER = r"""[bold cyan]
    ╔═╗╦═╗╔═╗╔╗╔╔═╗╔═╗╔═╗╔╗╔╔╗╔╔═╗╦═╗
    ║ ║╠═╝║╣ ║║║╚═╗║  ╠═╣║║║║║║║╣ ╠╦╝
    ╚═╝╩  ╚═╝╝╚╝╚═╝╚═╝╩ ╩╝╚╝╝╚╝╚═╝╩╚═
[/bold cyan][dim]    ⚡ OpenSource Async Web Vulnerability Scanner
    🔧 Engine: httpx + asyncio | UI: rich
    📌 Version: 1.0.0[/dim]
"""


def print_banner():
    console.print(Panel(
        BANNER,
        border_style="cyan",
        box=box.DOUBLE_EDGE,
        padding=(0, 2),
    ))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 扫描进度追踪器
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ScanTracker:
    """追踪扫描进度, 配合 Rich Live 实时渲染"""

    def __init__(self) -> None:
        self.targets: List[str] = []
        self.plugins_info: List[Dict] = []
        self.active_plugins: Dict[str, str] = {}   # plugin → status
        self.completed: int = 0
        self.total_tasks: int = 0
        self.vulns: List[Dict] = []
        self.stage: int = 0
        self.stage_name: str = ""
        self.errors: int = 0
        self.start_time: float = 0

    def handle_event(self, event: ScanEvent, data: Dict[str, Any]) -> None:
        """处理引擎事件"""
        if event == ScanEvent.ENGINE_START:
            self.targets = data.get("targets", [])
            self.start_time = time.time()

        elif event == ScanEvent.PLUGINS_LOADED:
            self.plugins_info = data.get("plugins", [])

        elif event == ScanEvent.STAGE_START:
            self.stage = data.get("stage", 0)
            self.stage_name = data.get("name", "")
            self.completed = 0
            self.total_tasks = data.get("plugin_count", 0) * data.get("target_count", 0)

        elif event == ScanEvent.PLUGIN_START:
            key = f"{data['plugin']}@{data['target']}"
            self.active_plugins[key] = "🔄 运行中"

        elif event == ScanEvent.PLUGIN_END:
            key = f"{data['plugin']}@{data['target']}"
            if data.get("has_result"):
                self.active_plugins[key] = "🚨 发现漏洞"
            else:
                self.active_plugins[key] = "✅ 完成"
            self.completed = data.get("current_idx", self.completed + 1)

        elif event == ScanEvent.VULN_FOUND:
            self.vulns.append(data)

        elif event == ScanEvent.ERROR:
            self.errors += 1

    def render_progress_table(self) -> Table:
        """渲染实时进度表"""
        table = Table(
            title=f"📡 {self.stage_name}",
            box=box.ROUNDED,
            border_style="cyan",
            title_style="bold cyan",
            show_lines=False,
            pad_edge=True,
        )
        table.add_column("插件", style="bold white", min_width=20)
        table.add_column("目标", style="dim", min_width=30)
        table.add_column("状态", justify="center", min_width=12)

        # 显示最近的活动插件（最多 8 条）
        items = list(self.active_plugins.items())[-8:]
        for key, status in items:
            parts = key.split("@", 1)
            plugin = parts[0] if parts else key
            url = parts[1] if len(parts) > 1 else ""
            # 截断 URL
            if len(url) > 40:
                url = url[:37] + "..."
            table.add_row(plugin, url, status)

        if self.total_tasks > 0:
            pct = (self.completed / self.total_tasks) * 100
            progress_bar = self._progress_bar(pct)
            table.add_section()
            table.add_row(
                "进度",
                progress_bar,
                f"{self.completed}/{self.total_tasks}",
            )

        return table


    def _progress_bar(self, pct: float) -> str:
        """ASCII 进度条"""
        filled = int(pct / 5)
        empty = 20 - filled
        bar = "█" * filled + "░" * empty
        color = "green" if pct > 80 else "yellow" if pct > 40 else "cyan"
        return f"[{color}]{bar}[/{color}] {pct:.0f}%"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 结果渲染
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def render_plugin_table(plugins: List[Dict]) -> Table:
    """渲染已加载插件表"""
    table = Table(
        title="🔌 已加载插件",
        box=box.SIMPLE_HEAVY,
        border_style="bright_cyan",
        title_style="bold cyan",
    )
    table.add_column("#", style="dim", width=3)
    table.add_column("插件名称", style="bold white", min_width=22)
    table.add_column("类别", justify="center", min_width=6)
    table.add_column("等级", justify="center", min_width=10)
    table.add_column("版本", style="dim", min_width=6)
    table.add_column("标签", style="dim")

    for i, p in enumerate(plugins, 1):
        cat = p.get("category", "unknown")
        cat_badge = f"[blue]INFO[/blue]" if cat == "info" else f"[red]POC[/red]"
        table.add_row(
            str(i),
            p["display_name"],
            cat_badge,
            severity_badge(p["severity"]),
            p["version"],
            ", ".join(p.get("tags", [])),
        )

    return table


def render_vuln_panel(vuln: Dict) -> Panel:
    """渲染单个漏洞发现面板"""
    sev = vuln.get("severity", "info")
    border = "red" if sev in ("high", "critical") else "yellow"

    content = Text()
    content.append("🎯 Target: ", style="bold")
    content.append(vuln.get("url", ""), style="underline cyan")
    content.append("\n")
    content.append("🔌 Plugin: ", style="bold")
    content.append(vuln.get("display_name", vuln.get("plugin", "")), style="white")
    content.append("\n")
    content.append("⚠️  Level:  ", style="bold")
    content.append(sev.upper(), style=COLORS.get(sev, "white"))
    content.append("\n")
    content.append("📋 Detail: ", style="bold")
    content.append(vuln.get("detail", ""), style="white")

    evidence = vuln.get("evidence", "")
    if evidence:
        content.append("\n\n")
        content.append("🔍 Evidence:\n", style="bold red")
        content.append(evidence, style="red")

    # 额外信息
    extra = vuln.get("extra", {})
    if extra.get("findings"):
        for finding in extra["findings"][:3]:
            content.append("\n\n")
            content.append(f"  💉 Payload: ", style="bold bright_red")
            payload = finding.get("payload") or finding.get("true_payload", "")
            content.append(payload, style="bold red underline")
            if finding.get("db_type"):
                content.append(f"\n  🗄️  Database: ", style="bold")
                content.append(finding["db_type"], style="bright_yellow")
            content.append(f"\n  🎯 Type: ", style="bold")
            content.append(finding.get("type", ""), style="bright_white")

    return Panel(
        content,
        title=f"[bold red]🚨 VULNERABILITY FOUND[/bold red]",
        border_style=border,
        box=box.HEAVY,
        padding=(1, 2),
    )


def render_summary(engine: ScanEngine) -> Panel:
    """渲染最终扫描汇总"""
    summary = engine.summary()
    results = engine.results

    # 主统计表
    stats = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    stats.add_column("Key", style="bold", min_width=18)
    stats.add_column("Value", style="bright_white")

    stats.add_row("🔌 插件总数", str(summary["plugins_loaded"]))
    stats.add_row("🎯 检测总数", str(summary["total_checks"]))
    stats.add_row(
        "🚨 发现漏洞",
        f"[bold red]{summary['vulnerabilities_found']}[/bold red]"
        if summary["vulnerabilities_found"] > 0
        else "[green]0[/green]",
    )
    stats.add_row("⏱️  耗时", f"{summary['elapsed_seconds']}s")
    stats.add_row(
        "🛡️  WAF 检测",
        "[yellow]已发现[/yellow]" if summary["waf_detected"] else "[green]未发现[/green]",
    )

    # 按等级分布
    if summary["by_severity"]:
        stats.add_section()
        stats.add_row("[bold]漏洞等级分布[/bold]", "")
        for sev, count in summary["by_severity"].items():
            stats.add_row(f"  {severity_badge(sev)}", str(count))

    # 按插件分布
    if summary["by_plugin"]:
        stats.add_section()
        stats.add_row("[bold]插件发现分布[/bold]", "")
        for plugin, count in summary["by_plugin"].items():
            stats.add_row(f"  {plugin}", str(count))

    # 详细结果表
    detail_table = Table(
        box=box.SIMPLE_HEAVY,
        border_style="dim",
        show_lines=True,
    )
    detail_table.add_column("#", style="dim", width=3)
    detail_table.add_column("插件", style="bold", min_width=16)
    detail_table.add_column("目标", style="dim", min_width=20)
    detail_table.add_column("状态", justify="center", min_width=8)
    detail_table.add_column("等级", justify="center", min_width=10)
    detail_table.add_column("详情", max_width=40)

    for i, r in enumerate(results, 1):
        status = "[bold red]🚨 漏洞[/bold red]" if r.is_vulnerable else "[green]✅ 安全[/green]"
        url_short = r.url[:35] + "..." if len(r.url) > 38 else r.url
        detail_short = r.detail[:38] + "..." if len(r.detail) > 40 else r.detail
        detail_table.add_row(
            str(i),
            r.plugin_name,
            url_short,
            status,
            severity_badge(str(r.severity)),
            detail_short,
        )

    # 组合
    content = Text()
    out = Console(record=True, width=90)
    out.print(stats)
    out.print()
    out.print(Rule("详细结果", style="cyan"))
    out.print(detail_table)

    # ═══════════════════════════════════════
    # WAF 防御能力热力图
    # ═══════════════════════════════════════
    ctx = summary.get("context", {})
    heatmap = ctx.get("waf_heatmap")
    if heatmap and heatmap.get("dimensions"):
        out.print()
        out.print(Rule("🛡️ WAF 防御能力热力图", style="bright_yellow"))
        
        hm_table = Table(
            box=box.ROUNDED,
            border_style="yellow",
            show_lines=True,
        )
        hm_table.add_column("攻击维度", style="bold", min_width=22)
        hm_table.add_column("拦截率", justify="center", min_width=8)
        hm_table.add_column("防护等级", justify="center", min_width=14)
        hm_table.add_column("防护条", min_width=12)
        hm_table.add_column("绕过 Payload", style="dim", max_width=30)

        for dim in heatmap["dimensions"]:
            rate = dim.get("block_rate", 0)
            level = dim.get("protection_level", "")
            bypassed = dim.get("bypassed_payloads", [])
            
            # 生成彩色进度条
            filled = int(rate / 10)
            empty = 10 - filled
            color = "green" if rate >= 80 else "yellow" if rate >= 50 else "red"
            bar = f"[{color}]{'█' * filled}{'░' * empty}[/{color}]"
            
            bypass_text = bypassed[0][:28] + "…" if bypassed else "—"
            
            hm_table.add_row(
                dim["dimension"],
                f"{rate:.0f}%",
                level,
                bar,
                bypass_text,
            )
        
        out.print(hm_table)
        
        score = heatmap.get("overall_score", 0)
        score_color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
        out.print(
            f"\n  📊 总体评分: [{score_color}]{score:.1f}/100[/{score_color}]"
            f" | 最强: [green]{heatmap.get('strongest_dimension', 'N/A')}[/green]"
            f" | 最弱: [red]{heatmap.get('weakest_dimension', 'N/A')}[/red]"
        )

    return Panel(
        out.export_text(styles=True),
        title="[bold bright_cyan]📊 SCAN SUMMARY[/bold bright_cyan]",
        border_style="bright_cyan",
        box=box.DOUBLE_EDGE,
        padding=(1, 2),
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CLI 参数解析
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="OpenScanner",
        description="""OpenScanner: 综合性异步安全评估工具，集成动态应用扫描 (DAST)、静态代码审计 (SAST) 及部分交互式分析 (IAST) 逻辑。

Web GUI 交互界面 (Web Graphical User Interface):
  OpenScanner 提供了功能完善的 Web 交互式面板，包含：
  - 实时可视化：扫描过程中的状态流、进度条与多维数据统计图表。
  - 安全研判：内置视觉取证、POF 复现脚本、代码级修复补丁等交互模块。
  - 启动方式：使用 'streamlit run web/app.py' 命令开启。
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用范例 / Examples:
  基础自动化扫描:
    python main.py -t http://example.com
  
  带鉴权信息的深度爬取扫描:
    python main.py -t http://example.com --crawl-depth 1 --cookie "session=hash_value"
  
  高并发模式及报告自动导出:
    python main.py -t target.com --concurrency 50 --export-md report.md
  
  指定特定插件及自定义头部信息:
    python main.py -t target.com --plugins sqli_scan xss_scan --header "X-Custom-Auth: token"

  SAST 本地源代码安全性审计:
    python main.py -t /path/to/project_root --plugins malware_scan
"""
    )

    # --- 扫描目标配置 (Scan Targets) ---
    target_group = parser.add_argument_group("扫描目标配置 (Target Configurations)")
    target_group.add_argument(
        "-t", "--target",
        action="append",
        dest="targets",
        help="指定目标 URL 或本地源代码路径 (支持多次输入以实施批量审计)",
    )
    target_group.add_argument(
        "--demo",
        action="store_true",
        help="启用演示模式，以系统默认目标 (httpbin.org) 运行流程测试",
    )
    target_group.add_argument(
        "--crawl-depth",
        type=int,
        default=0,
        help="配置爬虫探测深度。0:仅扫描给定路径; 1:同源下钻一级页面 (默认: 0)",
    )
    target_group.add_argument(
        "--scan-intensity",
        choices=["light", "medium", "full"],
        default="light",
        help="爬虫扫描强度: light=仅注入点(最快) | medium=注入点+关键端点 | full=全量(默认: light)",
    )

    # --- 性能与网络设置 (Optimization & Network) ---
    net_group = parser.add_argument_group("性能与网络设置 (Network & Performance)")
    net_group.add_argument(
        "--concurrency",
        type=int,
        default=10,
        help="配置最大并发协程数量 (默认: 10)",
    )
    net_group.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="设置单次请求的超时阈值 (秒, 默认: 15.0)",
    )
    net_group.add_argument(
        "--retries",
        type=int,
        default=3,
        help="设置网络通信失败后的重试策略 (次数, 默认: 3)",
    )
    net_group.add_argument(
        "--no-http2",
        action="store_true",
        help="强制降级使用 HTTP/1.1 协议进行通信",
    )
    net_group.add_argument(
        "--allow-internal",
        action="store_true",
        help="允许访问内部私有网段 (用于本地测试场景, 警告: 开启后无 SSRF 防护)",
    )

    # --- 插件与审计逻辑 (Plugins & Logic) ---
    plugin_group = parser.add_argument_group("插件与审计逻辑 (Plugins & Auditing)")
    plugin_group.add_argument(
        "--plugins",
        nargs="*",
        metavar="NAME",
        help="选择性执行指定插件 (例如: --plugins sqli_scan xss_scan)",
    )
    plugin_group.add_argument(
        "-p", "--params",
        metavar="QUERY",
        help="定义业务上下文参数，用于维持扫描期间的业务逻辑 (格式: 'k=v&k2=v2')",
    )

    # --- 鉴权与身份伪装 (Authentication & Stealth) ---
    auth_group = parser.add_argument_group("鉴权与身份伪装 (Authentication & Stealth)")
    auth_group.add_argument(
        "--cookie",
        type=str,
        help="配置全局 Cookie 信息以实施鉴权后的受限资源扫描",
    )
    auth_group.add_argument(
        "--header",
        action="append",
        dest="headers",
        metavar="HEADER",
        help="注入自定义 HTTP 头部信息 (支持多次指定, 例如: --header 'User-Agent: Scanner')",
    )

    # --- AI 深度研判引擎 (AI Reasoning Engine) ---
    ai_group = parser.add_argument_group("AI 深度研判引擎 (AI Reasoning Engine)")
    ai_group.add_argument(
        "--ai-mode",
        choices=["off", "local", "api"],
        default="off",
        help="AI 研判模式: off=关闭(默认) | local=本地LLM(隐私优先) | api=云端API(精度优先)",
    )
    ai_group.add_argument(
        "--ai-model",
        type=str,
        default="",
        help="本地模式: GGUF 模型文件路径 (例如: ./models/qwen2-0.5b.gguf)",
    )
    ai_group.add_argument(
        "--ai-key",
        type=str,
        default="",
        help="API 模式: API 密钥 (支持 OpenAI / Gemini / DeepSeek 等)",
    )
    ai_group.add_argument(
        "--ai-api-base",
        type=str,
        default="https://api.openai.com/v1",
        help="API 模式: API 端点地址 (默认: OpenAI, 支持 Gemini/DeepSeek 等兼容端点)",
    )
    ai_group.add_argument(
        "--ai-api-model",
        type=str,
        default="gpt-4o-mini",
        help="API 模式: 模型名称 (默认: gpt-4o-mini)",
    )

    # --- 结果处理与报告 (Output & Reporting) ---
    out_group = parser.add_argument_group("结果处理与报告 (Reporting & Output)")
    out_group.add_argument(
        "--export-md",
        metavar="FILE",
        help="将审计发现导出为标准 Markdown 格式报告文件",
    )
    out_group.add_argument(
        "--export-json",
        metavar="FILE",
        help="将审计数据导出为 JSON 结构化格式，便于第三方系统集成",
    )
    out_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="启用冗长日志输出，捕获详细的 HTTP 交互及底层调试信息",
    )

    return parser.parse_args()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 主流程
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def run_scan(
    targets: List[str],
    config: RequestConfig,
    ai_config: Optional[AIConfig] = None,
    plugin_names: Optional[List[str]] = None,
    context_params: Optional[Dict[str, str]] = None,
    crawl_depth: int = 0,
    scan_intensity: str = "light",
    export_md: Optional[str] = None,
    export_json: Optional[str] = None,
) -> ScanEngine:
    """执行完整扫描流程"""

    tracker = ScanTracker()

    # 创建引擎 (注入 AI 深度配置)
    engine = ScanEngine(config=config, ai_config=ai_config)
    engine.on_event(tracker.handle_event)

    # ── 加载插件 ──
    console.print()
    with console.status("[bold cyan]🔍 扫描插件目录...[/bold cyan]", spinner="dots"):
        loaded = engine.load_plugins()

    console.print(render_plugin_table(tracker.plugins_info))
    console.print()

    if engine.registry.count == 0:
        console.print("[bold red]❌ 未发现任何插件, 请检查 plugins/ 目录[/bold red]")
        return engine

    # ── 爬虫阶段 ──
    if crawl_depth > 0:
        console.print(Rule("[bold cyan]🕸️ 爬虫扩展收集阶段[/bold cyan]", style="cyan"))
        # 爬虫引擎与 DAST 共用全局请求池配置来防 OOM 并实现安全连接
        async with AsyncRequester(config) as req:
            spider = SpiderEngine(req, max_depth=crawl_depth)

            with console.status(f"[bold cyan]🕸️ 爬行中深度 [{crawl_depth}]...[/bold cyan]", spinner="arc"):
                # crawl_all 现已自动合成表单端点 + 路径 ID 为带参数的可测试 URL
                expanded_targets = await spider.crawl_all(targets)

            # 展示爬虫发现的表单注入点
            forms = spider.form_endpoints
            if forms:
                console.print(f"[dim]🔍 发现 {len(forms)} 个表单端点，已合成为注入测试 URL[/dim]")

            # 按扫描强度过滤目标
            intensity_label = {"light": "轻度", "medium": "中度", "full": "全量"}.get(scan_intensity, scan_intensity)
            console.print(f"[dim]🎯 扫描强度: [bold]{intensity_label}[/bold] | 爬虫发现 {len(expanded_targets)} 个 URL[/dim]")
            targets = SpiderEngine.filter_targets_by_intensity(expanded_targets, scan_intensity)
            console.print(f"[dim]🎯 强度过滤后: {len(targets)} 个目标将被测试[/dim]")

        # 状态持久化：自动导出发现的 URL 清单，以便网络中断后恢复
        urls_file = Path("openscanner_urls.txt")
        urls_file.write_text("\n".join(targets), encoding="utf-8")
        console.print(f"[dim]💾 已将 {len(targets)} 个目标持久化至 [cyan]{urls_file.absolute()}[/cyan][/dim]")
        console.print()

    # ── 扫描目标展示 ──
    target_text = Text()
    for i, t in enumerate(targets[:15], 1): # 控制最多打印 15 个，以免刷屏
        target_text.append(f"  {i}. ", style="dim")
        target_text.append(t, style="underline cyan")
        target_text.append("\n")
        
    if len(targets) > 15:
        target_text.append(f"  ... 还有 {len(targets)-15} 个目标端点隐藏显示。\n", style="dim italic")

    console.print(Panel(
        target_text,
        title=f"[bold]🎯 确定总计扫描目标 [{len(targets)}][/bold]",
        border_style="bright_cyan",
        box=box.ROUNDED,
    ))
    console.print()

    # ── 执行两阶段扫描 ──
    console.print(Rule("[bold cyan]⚡ 开始漏洞注入[/bold cyan]", style="cyan"))
    console.print()

    # 实时进度展示
    scan_start = time.time()

    # 定义渲染函数
    def make_display():
        return tracker.render_progress_table()

    with Live(make_display(), console=console, refresh_per_second=4, transient=True) as live:
        # 包装事件处理: 每次事件触发时更新 Live 显示
        original_handler = tracker.handle_event

        def live_handler(event: ScanEvent, data: Dict[str, Any]):
            original_handler(event, data)
            live.update(make_display())

            # 漏洞发现时在 Live 之外打印
            if event == ScanEvent.VULN_FOUND:
                live.console.print(render_vuln_panel(data))

            if event == ScanEvent.STAGE_END:
                stage = data.get("stage", 0)
                name = data.get("name", "")
                vulns = data.get("vulns", 0)
                checks = data.get("checks", 0)
                emoji = "🛡️" if stage == 1 else "⚔️"
                live.console.print(
                    f"\n{emoji} [bold]{name}[/bold] 完成 | "
                    f"检测 [cyan]{checks}[/cyan] | "
                    f"发现 [{'red' if vulns else 'green'}]{vulns}[/{'red' if vulns else 'green'}] 个问题\n"
                )

        # 替换回调
        engine._callbacks = [live_handler]

        # 执行扫描
        results = await engine.scan(
            targets,
            config=config,
            plugins_filter=plugin_names,
            context_params=context_params,
        )

    console.print()
    console.print(Rule("[bold cyan]📊 扫描报告[/bold cyan]", style="cyan"))
    console.print()

    # ── 漏洞详情（再次展示所有漏洞面板）──
    vuln_results = [r for r in results if r.is_vulnerable]
    if vuln_results:
        console.print(f"[bold red]🚨 发现 {len(vuln_results)} 个安全问题:[/bold red]\n")
        for r in vuln_results:
            vuln_data = {
                "plugin": r.plugin_name,
                "display_name": r.plugin_name,
                "url": r.url,
                "severity": str(r.severity),
                "detail": r.detail,
                "evidence": r.evidence,
                "extra": r.extra,
            }
            console.print(render_vuln_panel(vuln_data))
            console.print()
    else:
        console.print("[bold green]✅ 未发现安全漏洞[/bold green]\n")

    # ── 汇总报表 ──
    console.print(render_summary(engine))

    # ── 报告导出 ──
    if export_md or export_json:
        console.print(Rule("[bold cyan]💾 生成渗透测试报告[/bold cyan]", style="cyan"))
        gen = ReportGenerator(
            results=[r.to_dict() for r in results],
            summary=engine.summary(),
            context=engine._context,
            targets=targets,
        )
        try:
            if export_md:
                path = gen.save_markdown(export_md)
                console.print(f"[green]✔ Markdown[/green] 报告已保存至 [cyan]{path.absolute()}[/cyan]")
            if export_json:
                path = gen.save_json(export_json)
                console.print(f"[green]✔ JSON[/green] 报告已保存至 [cyan]{path.absolute()}[/cyan]")
        except Exception as exc:
            console.print(f"[bold red]❌ 报告导出失败: {exc}[/bold red]")

    return engine


def main():
    args = parse_args()

    # 配置日志
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler()] if args.verbose else [],
    )

    # Banner
    print_banner()

    # 目标
    if args.demo or not args.targets:
        targets = [
            "https://httpbin.org/get?id=1&name=test",
        ]
        if not args.targets:
            console.print("[dim]💡 未指定目标, 使用演示模式 (httpbin.org)[/dim]\n")
    else:
        targets = args.targets

    # 请求配置
    extra_headers = {}
    if args.cookie:
        extra_headers["Cookie"] = args.cookie
    if args.headers:
        for h in args.headers:
            if ":" in h:
                key, val = h.split(":", 1)
                extra_headers[key.strip()] = val.strip()

    config = RequestConfig(
        max_concurrency=args.concurrency,
        request_timeout=args.timeout,
        max_retries=args.retries,
        http2=not args.no_http2,
        allow_internal_ips=args.allow_internal,
        random_delay_range=(0.05, 0.2),
        extra_headers=extra_headers if extra_headers else None,
    )

    # 显示鉴权信息
    if extra_headers:
        console.print(f"[dim]🔐 鉴权 Headers 已注入: {list(extra_headers.keys())}[/dim]\n")

    # 解析业务参数
    from urllib.parse import parse_qsl
    bparams = {}
    if args.params:
        bparams = dict(parse_qsl(args.params, keep_blank_values=True))

    # 运行
    try:
        # ── 构造 AI 配置 ──
        mode_map = {"off": AIMode.OFF, "local": AIMode.LOCAL, "api": AIMode.API}
        ai_config = AIConfig(
            mode=mode_map.get(args.ai_mode, AIMode.OFF),
            local_model_path=args.ai_model,
            api_key=args.ai_key,
            api_base_url=args.ai_api_base,
            api_model=args.ai_api_model
        )

        engine = asyncio.run(run_scan(
            targets=targets,
            config=config,
            ai_config=ai_config,
            plugin_names=args.plugins,
            context_params=bparams,
            crawl_depth=args.crawl_depth,
            scan_intensity=args.scan_intensity,
            export_md=args.export_md,
            export_json=args.export_json,
        ))

        # 退出码: 有漏洞发现时返回 1
        vuln_count = sum(1 for r in engine.results if r.is_vulnerable)
        sys.exit(1 if vuln_count > 0 else 0)

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  用户中断扫描[/yellow]")
        sys.exit(130)
    except Exception as exc:
        console.print(f"\n[bold red]❌ 致命错误: {exc}[/bold red]")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(2)


if __name__ == "__main__":
    main()
