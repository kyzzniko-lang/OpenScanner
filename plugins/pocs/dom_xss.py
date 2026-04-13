"""
plugins/pocs/dom_xss.py — DOM-Based 跨站脚本攻击 (DOM XSS) 检测插件

功能：
  • 自动化 DOM-XSS 探测与验证
  • 静态 Sink 指纹爬取：分析 JS 代码中是否包含 innerHTML, document.write 等敏感目标
  • 动态浏览器验证：联动 BrowserEngine (Playwright) 捕捉真实的 JavaScript 执行弹窗
  • 全方位覆盖：支持 URL 查询参数 (?) 和 Fragment 锚点 (#) 注入
  • 视觉取证：自动保存漏洞触发时的浏览器屏幕截图
"""

from __future__ import annotations

import asyncio
import logging
import random
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlunparse

from core.request import AsyncRequester, smart_merge
from core.browser import BrowserEngine, VisualEvidence
from plugins.base import BasePlugin, PluginMeta, ScanResult, Severity

logger = logging.getLogger("openscanner.plugin.dom_xss")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 探测 Payload 集合
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_DOM_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "';alert(1);'",
    "\";alert(1);\"",
    "javascript:alert(1)",
    "javascript:alert(1)",
    "English'></option><script>confirm(1)</script>", # 针对 DVWA xss_d 的精准闭合修复
    "#'><img src=x onerror=alert(1)>", # 针对属性闭合
]

# 敏感的 JS Sinks (接收槽)
_DOM_SINKS = [
    r"\.innerHTML\s*=",
    r"\.outerHTML\s*=",
    r"document\.write\(",
    r"document\.writeln\(",
    r"eval\(",
    r"setTimeout\(",
    r"setInterval\(",
    r"\.insertAdjacentHTML\(",
    r"\.html\(",      # jQuery
    r"\.append\(",    # jQuery
    r"\.prepend\(",   # jQuery
]

# 敏感的 JS Sources (来源)
_DOM_SOURCES = [
    r"location\.search",
    r"location\.hash",
    r"document\.URL",
    r"document\.referrer",
    r"window\.name",
]

def _parse_cookie_str(cookie_str: str) -> Dict[str, str]:
    """将 Cookie 字符串解析为字典"""
    cookies = {}
    if not cookie_str:
        return cookies
    try:
        for pair in cookie_str.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k] = v
    except Exception:
        pass
    return cookies

def _extract_all_params(url: str) -> Dict[str, str]:
    """提取 URL 中的所有参数，包括 Query 和 Fragment 中的伪参数"""
    parsed = urlparse(url)
    
    # 1. 解析标准 Query 参数
    params = {k: v[0] if v else "" for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
    
    # 2. 解析 Fragment (#) 中的参数 (常见的 DOM-XSS 模式)
    # 例如 #default=English
    if parsed.fragment:
        f_params = parse_qs(parsed.fragment, keep_blank_values=True)
        for k, v in f_params.items():
            if k not in params:
                params[k] = v[0] if v else ""
    
    return params

class DomXssPlugin(BasePlugin):
    """
    DOM-Based XSS 深度探测插件
    """

    meta = PluginMeta(
        name="dom_xss_scan",
        display_name="DOM-XSS Scanner",
        description="基于无头浏览器的动态 DOM-XSS 探测与取证插件",
        severity=Severity.HIGH,
        tags=["dom-xss", "browser-verification", "owasp-top10"],
        version="1.1.0",
    )

    async def check(
        self,
        url: str,
        requester: AsyncRequester,
        context: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        try:
            return await self._check_impl(url, requester, context)
        except Exception as e:
            logger.error("[DOM-XSS] 执行失败: %s", e)
            return self.result(
                url, 
                is_vulnerable=False, 
                detail=f"检测引擎异常: {str(e)}。请确保已安装 Playwright 依赖 (playwright install chromium)。",
                extra={"error": str(e), "stack_trace": True}
            )

    async def _check_impl(
        self,
        url: str,
        requester: AsyncRequester,
        context: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        """实际的检测逻辑"""
        context = context or {}
        params = _extract_all_params(url)
        
        # 即使没有参数，也要抓取一次源码看有没有隐蔽的 Source/Sink
        try:
            resp = await requester.get(url)
            html_body = resp.text
        except Exception:
            html_body = ""

        # 阶段一：静态指纹嗅探 (Heuristic Sink Analysis)
        sink_found = False
        potential_sinks = []
        for sink in _DOM_SINKS:
            if re.search(sink, html_body, re.IGNORECASE):
                sink_found = True
                potential_sinks.append(sink.replace("\\", ""))

        source_found = False
        for src in _DOM_SOURCES:
            if re.search(src, html_body, re.IGNORECASE):
                source_found = True

        if not params and not source_found:
            return self.result(url, is_vulnerable=False, detail="未发现参数或 DOM-XSS 诱发指纹，跳过。")

        logger.info("[DOM-XSS] 🎯 发现可疑指纹 (Sinks: %s), 启动浏览器验证...", potential_sinks)

        # 阶段二：浏览器动态验证
        findings = []
        attempts = []
        payloads_checked = 0
        total_payloads = len(test_params) * len(_DOM_PAYLOADS) * 2
        
        # 测试列表：所有发现的参数
        test_params = list(params.keys())
        if not test_params and source_found:
             # 如果页面有 Source 引用但 URL 没参数，尝试猜测几个常用参数
             test_params = ["default", "lang", "id", "url"]

        # 提取身份认证 Cookie
        extra_headers = context.get("extra_headers", {})
        cookie_str = extra_headers.get("Cookie", "")
        auth_cookies = _parse_cookie_str(cookie_str)

        async with BrowserEngine(headless=True) as browser:
            if not browser.is_available:
                # 策略调整：如果浏览器不可用但发现了强特征 Sink，标记为 POTENTIAL 而不是 SAFE
                if sink_found:
                    return self.result(
                        url,
                        is_vulnerable=True,
                        severity=Severity.MEDIUM,
                        detail="发现潜在 DOM-XSS 风险 (浏览器环境缺失，无法完成动态取证)",
                        evidence=f"静态分析发现敏感接收槽: {', '.join(potential_sinks)}",
                        extra={
                            "status": "Potential",
                            "warning": "未检测到 Playwright 环境，已降级为静态扫描。建议安装环境以获取视觉取证截图。",
                            "detected_sinks": potential_sinks
                        }
                    )
                return self.result(url, is_vulnerable=False, detail="浏览器引擎不可用，且未发现明显 Sink，忽略。")

            for param in test_params:
                # 针对每个参数，优先输出一条状态日志
                logger.info("[DOM-XSS] 正在对参数 '%s' 启动深度探测...", param)

                for payload in _DOM_PAYLOADS:
                    # 分别尝试在 Query 和 Fragment 中注入
                    injection_modes = ["query", "fragment"]
                    for mode in injection_modes:
                        injected_url = self._build_injected_url(url, param, payload, mode)
                        
                        # 实时向控制台/UI 汇报进度 (让用户看到 Payloads 确实在跑)
                        msg = f"正在验证 [{param}] -> {payload[:30]}..."
                        logger.info(f"[DOM-XSS] {msg}")
                        
                        # 如果 context 提供了 progress_callback，则调用之
                        if "progress_callback" in context:
                            try:
                                context["progress_callback"](payloads_checked + 1, total_payloads, msg)
                            except Exception:
                                pass
                        
                        # 核心验证：让浏览器跑一遍，并传入身份认证信息
                        evidence = await browser.verify_xss(injected_url, payload, auth_cookies=auth_cookies)
                        payloads_checked += 1
                        
                        attempts.append({
                            "param": param,
                            "mode": mode,
                            "payload": payload,
                            "triggered": evidence.triggered,
                            "confidence": evidence.confidence
                        })

                        if evidence.triggered:
                            logger.warning("[DOM-XSS] 💥 确认漏洞! 参数: %s | Mode: %s", param, mode)
                            findings.append({
                                "type": "DOM-Based XSS",
                                "param": param,
                                "mode": mode,
                                "payload": payload,
                                "evidence": evidence.dialog_message,
                                "confidence": evidence.confidence,
                                "screenshot": evidence.screenshot_b64,
                            })
                            # 如果一个参数触发了，同参数其他 payload 可能不用全跑，但为了严谨性这里保留
                            break 
                    
                    if findings and findings[-1]["param"] == param:
                        break # 这个参数已经实锤了，换下一个参数

        if not findings:
            return self.result(
                url, 
                is_vulnerable=False, 
                detail="浏览器动态验证未触发执行，目标安全。",
                extra={"attempts": attempts, "potential_sinks": potential_sinks}
            )

        # 取置信度最高的发现
        best = max(findings, key=lambda f: f["confidence"])
        
        return self.result(
            url,
            is_vulnerable=True,
            detail=f"发现 DOM-Based XSS 注入 | 触发参数: {best['param']} ({best['mode']})",
            evidence=f"Payload: {best['payload']}\nBrowser Logic: {best['evidence'] or 'Detected via DOM Mutation'}",
            extra={
                "findings": findings,
                "attempts": attempts,
                "vulnerable_params": [f["param"] for f in findings],
                "visual_proof": best.get("screenshot"),
                "detected_sinks": potential_sinks
            }
        )

    def _build_injected_url(self, base_url: str, param: str, payload: str, mode: str) -> str:
        """根据模式构建注入后的 URL"""
        parsed = list(urlparse(base_url))
        
        if mode == "query":
            # 修改 Query String
            qs = parse_qs(parsed[4], keep_blank_values=True)
            qs[param] = [payload]
            from urllib.parse import urlencode
            parsed[4] = urlencode(qs, doseq=True)
        elif mode == "fragment":
            # 修改 Fragment (#)
            # 兼容 key=val 格式
            if "=" in parsed[5]:
                from urllib.parse import urlencode
                fs = parse_qs(parsed[5], keep_blank_values=True)
                fs[param] = [payload]
                parsed[5] = urlencode(fs, doseq=True)
            else:
                # 简单拼接
                parsed[5] = f"{param}={payload}"
        
        return urlunparse(parsed)
