"""
utils/poc_gen.py — OpenScanner 一键漏洞复现脚本生成器

为每一个扫描发现的漏洞，自动生成独立可运行的 Python 脚本。
用户只需复制粘贴该脚本到本地终端运行，即可在不依赖 OpenScanner
的情况下完美重现攻击链路。

竞争力: 市面上绝大多数扫描器 (Nuclei, Xray, Nmap) 只提供文本证据。
        本引擎从 ScanResult 元数据中自动反向推导出完整的 HTTP 请求序列，
        生成带有注释、彩色输出和智能校验逻辑的纯 Python 3 脚本。
"""

from __future__ import annotations

import html
import json
import textwrap
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse


class PocGenerator:
    """
    漏洞 POC 脚本自动生成器。

    根据漏洞类型、Payload、目标 URL 自动推导最佳复现方案，
    并生成可独立运行的 Python 3 验证脚本。
    """

    # ── 类型 → 模板映射 ──
    _TEMPLATES = {
        "sqli":    "_gen_sqli_poc",
        "xss":     "_gen_xss_poc",
        "dom_xss": "_gen_dom_xss_poc",
        "default": "_gen_generic_poc",
    }

    @classmethod
    def generate(cls, vuln: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> str:
        """
        根据漏洞结果字典生成完整的 Python POC 脚本。

        Args:
            vuln: ScanResult.to_dict() 或等效的漏洞字典
            headers: 扫描时使用的鉴权 Headers (如 Cookie, Authorization)

        Returns:
            完整的可运行 Python 脚本字符串
        """
        plugin = vuln.get("plugin", "")
        extra = vuln.get("extra", {})
        findings = extra.get("findings", [])

        # 路由到对应的模板生成器
        if "sqli" in plugin:
            return cls._gen_sqli_poc(vuln, findings, headers)
        elif "dom_xss" in plugin:
            return cls._gen_dom_xss_poc(vuln, findings, headers)
        elif "xss" in plugin:
            return cls._gen_xss_poc(vuln, findings, headers)
        else:
            return cls._gen_generic_poc(vuln, findings, headers)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # SQL Injection POC
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @classmethod
    def _gen_sqli_poc(cls, vuln: Dict, findings: List[Dict], headers: Optional[Dict]) -> str:
        url = vuln.get("url", "http://target.com")
        parsed = urlparse(url)
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        original_params = dict(parse_qsl(parsed.query, keep_blank_values=True))

        # 从 findings 中取第一个可靠的 payload
        payload = ""
        inject_type = "Unknown"
        db_type = ""
        for f in findings:
            payload = f.get("payload") or f.get("true_payload", "")
            inject_type = f.get("type", "Error-Based")
            db_type = f.get("db_type", "")
            if payload:
                break

        headers_code = cls._format_headers(headers)

        safe_url = cls._safe_doc(url[:55])
        safe_type = cls._safe_doc(inject_type)
        safe_db = cls._safe_doc(db_type or "Unknown")

        return textwrap.dedent(f'''\
#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║  OpenScanner — SQL Injection POC (Auto-Generated)      ║
║  Target : {safe_url}
║  Type   : {safe_type}
║  DB     : {safe_db}
╚══════════════════════════════════════════════════════════╝

Usage:
    python poc_sqli.py

⚠️  仅限授权安全评估使用 / For authorized security testing ONLY.
"""

import requests
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── 目标配置 ──
TARGET_URL = {json.dumps(base_url)}
ORIGINAL_PARAMS = {json.dumps(original_params)}
PAYLOAD = {json.dumps(payload)}

# ── 鉴权 Headers (扫描时使用) ──
{headers_code}

def exploit():
    """
    重放 SQL 注入 Payload 并验证响应差异。
    """
    print("\\n[*] OpenScanner SQL Injection POC")
    print(f"[*] Target: {{TARGET_URL}}")
    print(f"[*] Payload: {{PAYLOAD}}")
    print("-" * 60)

    # Step 1: 发送基线请求 (无注入)
    print("[1] 发送基线请求...")
    try:
        baseline = requests.get(TARGET_URL, params=ORIGINAL_PARAMS,
                                headers=HEADERS, verify=False, timeout=15)
        baseline_len = len(baseline.text)
        print(f"    → 状态码: {{baseline.status_code}} | 响应长度: {{baseline_len}}")
    except Exception as e:
        print(f"    ✗ 基线请求失败: {{e}}")
        sys.exit(1)

    # Step 2: 注入 Payload
    print("[2] 注入 SQL Payload...")
    injected_params = ORIGINAL_PARAMS.copy()
    # 自动识别注入参数 (取第一个参数作为默认注入点)
    inject_key = list(injected_params.keys())[0] if injected_params else "id"
    injected_params[inject_key] = PAYLOAD

    try:
        attack = requests.get(TARGET_URL, params=injected_params,
                              headers=HEADERS, verify=False, timeout=15)
        attack_len = len(attack.text)
        print(f"    → 状态码: {{attack.status_code}} | 响应长度: {{attack_len}}")
    except Exception as e:
        print(f"    ✗ 注入请求失败: {{e}}")
        sys.exit(1)

    # Step 3: 分析结果
    print("\\n[3] 分析结果...")
    diff = abs(baseline_len - attack_len)
    ratio = diff / max(baseline_len, 1) * 100

    # 检查 SQL 错误关键字
    sql_errors = ["SQL syntax", "mysql_", "ORA-", "PostgreSQL", "sqlite3",
                  "Microsoft SQL", "ODBC", "syntax error", "Unclosed quotation"]
    found_errors = [e for e in sql_errors if e.lower() in attack.text.lower()]

    print(f"    响应差异: {{diff}} bytes ({{ratio:.1f}}%)")
    if found_errors:
        print(f"    \\033[91m✓ 发现 SQL 错误关键字: {{found_errors}}\\033[0m")
        print(f"\\n\\033[91m[!] SQL 注入漏洞已确认!\\033[0m")
    elif ratio > 5:
        print(f"    \\033[93m⚠ 响应存在显著差异，可能存在盲注\\033[0m")
    else:
        print(f"    \\033[92m→ 未发现明显异常 (可能需要手动验证)\\033[0m")

    print("\\n" + "=" * 60)
    print("[*] POC 执行完毕")

if __name__ == "__main__":
    exploit()
''')

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # XSS (Reflected) POC
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @classmethod
    def _gen_xss_poc(cls, vuln: Dict, findings: List[Dict], headers: Optional[Dict]) -> str:
        url = vuln.get("url", "http://target.com")
        payload = ""
        for f in findings:
            payload = f.get("payload") or f.get("true_payload", "")
            if payload:
                break

        headers_code = cls._format_headers(headers)
        safe_url = cls._safe_doc(url[:55])

        return textwrap.dedent(f'''\
#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║  OpenScanner — XSS POC (Auto-Generated)                ║
║  Target : {safe_url}
╚══════════════════════════════════════════════════════════╝
"""
import requests
import urllib3
urllib3.disable_warnings()

TARGET_URL = {json.dumps(url)}
PAYLOAD = {json.dumps(payload)}

{headers_code}

def exploit():
    print("\\n[*] OpenScanner XSS POC")
    print(f"[*] Target: {{TARGET_URL}}")

    # 注入 Payload 到 URL 参数
    resp = requests.get(TARGET_URL, headers=HEADERS, verify=False, timeout=15)

    # 检查 Payload 是否被原样反射
    if PAYLOAD in resp.text:
        print(f"\\033[91m[!] XSS 确认: Payload 被原样反射到响应中!\\033[0m")
        # 定位上下文
        idx = resp.text.find(PAYLOAD)
        context = resp.text[max(0, idx-50):idx+len(PAYLOAD)+50]
        print(f"\\n[*] 反射上下文:\\n    ...{{context}}...")
    else:
        print(f"\\033[93m[?] Payload 未被直接反射，可能已被编码或过滤\\033[0m")

    print("\\n[*] POC 执行完毕")

if __name__ == "__main__":
    exploit()
''')

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # DOM-XSS POC (Playwright)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @classmethod
    def _gen_dom_xss_poc(cls, vuln: Dict, findings: List[Dict], headers: Optional[Dict]) -> str:
        url = vuln.get("url", "http://target.com")
        payload = ""
        for f in findings:
            payload = f.get("payload", "")
            if payload:
                break

        safe_url = cls._safe_doc(url[:55])

        return textwrap.dedent(f'''\
#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║  OpenScanner — DOM-XSS POC (Playwright)                ║
║  Target : {safe_url}
╚══════════════════════════════════════════════════════════╝

需要安装: pip install playwright && playwright install chromium
"""
import asyncio
from playwright.async_api import async_playwright

PAYLOAD_URL = {json.dumps(payload)}

async def exploit():
    print("\\n[*] OpenScanner DOM-XSS POC (Headless Browser)")
    print(f"[*] Payload URL: {{PAYLOAD_URL}}")

    triggered = False

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        page = await browser.new_page()

        async def on_dialog(dialog):
            nonlocal triggered
            triggered = True
            print(f"\\033[91m[!] 弹窗拦截成功! 内容: '{{dialog.message}}'\\033[0m")
            await dialog.dismiss()

        page.on("dialog", on_dialog)

        try:
            await page.goto(PAYLOAD_URL, wait_until="domcontentloaded", timeout=8000)
            await asyncio.sleep(1)
        except Exception as e:
            print(f"[*] Navigation: {{e}}")

        await browser.close()

    if triggered:
        print("\\n\\033[91m[!] DOM-XSS 漏洞已确认! JavaScript 弹窗被成功触发。\\033[0m")
    else:
        print("\\n\\033[93m[?] 未检测到弹窗，可能需要调整 Payload 或等待时间\\033[0m")

    print("[*] POC 执行完毕")

if __name__ == "__main__":
    asyncio.run(exploit())
''')

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Generic Fallback POC
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @classmethod
    def _gen_generic_poc(cls, vuln: Dict, findings: List[Dict], headers: Optional[Dict]) -> str:
        url = vuln.get("url", "http://target.com")
        detail = vuln.get("detail", "")
        evidence = vuln.get("evidence", "")
        headers_code = cls._format_headers(headers)
        safe_url = cls._safe_doc(url[:55])
        safe_plugin = cls._safe_doc(vuln.get("plugin", "unknown"))

        return textwrap.dedent(f'''\
#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║  OpenScanner — Vulnerability POC (Auto-Generated)       ║
║  Plugin : {safe_plugin}
║  Target : {safe_url}
╚══════════════════════════════════════════════════════════╝
"""
import requests
import urllib3
urllib3.disable_warnings()

TARGET_URL = {json.dumps(url)}

{headers_code}

def exploit():
    print("\\n[*] OpenScanner Generic POC")
    print(f"[*] Target: {{TARGET_URL}}")
    print(f"[*] Detail: {repr(detail[:100])}")

    resp = requests.get(TARGET_URL, headers=HEADERS, verify=False, timeout=15)
    print(f"\\n[*] 状态码: {{resp.status_code}}")
    print(f"[*] 响应长度: {{len(resp.text)}} bytes")

    # 检查证据关键字
    evidence_keywords = {json.dumps(evidence[:80])}
    if evidence_keywords and evidence_keywords in resp.text:
        print(f"\\033[91m[!] 漏洞证据已在响应中确认!\\033[0m")
    else:
        print(f"\\033[93m[?] 请手动检查响应内容\\033[0m")

    print("\\n[*] POC 执行完毕")

if __name__ == "__main__":
    exploit()
''')

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Helper
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @staticmethod
    def _format_headers(headers: Optional[Dict[str, str]]) -> str:
        """将鉴权 Headers 格式化为 Python 代码段"""
        if not headers:
            return 'HEADERS = {"User-Agent": "OpenScanner-POC/1.0"}'

        lines = ['HEADERS = {']
        lines.append('    "User-Agent": "OpenScanner-POC/1.0",')
        for k, v in headers.items():
            lines.append(f'    {json.dumps(k)}: {json.dumps(v)},')
        lines.append('}')
        return "\n".join(lines)

    @staticmethod
    def _safe_doc(text: Any) -> str:
        """防止跨界字符串导致的三引号注入 (Meta-Injection)"""
        if not text:
            return ""
        return str(text).replace('"""', '\\"\\"\\"').replace("'''", "\\'\\'\\'")
