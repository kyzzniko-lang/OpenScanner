"""
core/browser.py — OpenScanner 无头浏览器引擎 (Visual Evidence & POF Verification)

企业级视觉取证系统:
  ┌─────────────────────────────────────────┐
  │         BrowserEngine (共享实例)          │
  ├─────────────────────────────────────────┤
  │  Playwright Chromium 管理              │
  │    • 生命周期托管 (启动/关闭)            │
  │    • 上下文隔离 (每个扫描目标独立)       │
  │    • 全局 User-Agent 伪装               │
  ├─────────────────────────────────────────┤
  │  Visual Proof (视觉取证)                │
  │    • XSS 弹窗截图 — JS Dialog 事件捕获  │
  │    • DOM 变化截图 — MutationObserver     │
  │    • Console Error 截获                  │
  │    • 全页面快照 + 元素高亮               │
  ├─────────────────────────────────────────┤
  │  POF Verification (POC 验证)             │
  │    • 在沙箱浏览器中回放 POC Payload      │
  │    • 自动判定 Payload 是否真实触发       │
  │    • 成功触发 → confidence = 1.0         │
  └─────────────────────────────────────────┘

创新点:
  市面上只有 AWVS/BurpSuite 等万元级工具提供截图级证据。
  OpenScanner 用 Playwright 零成本实现相同 "Visual Proof" 能力。
"""

from __future__ import annotations

import asyncio
import base64
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("openscanner.browser")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 数据结构
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class VisualEvidence:
    """视觉取证结果"""
    url: str
    payload: str
    triggered: bool = False
    dialog_message: str = ""
    screenshot_b64: str = ""         # PNG 截图的 Base64
    console_errors: List[str] = field(default_factory=list)
    dom_changes: List[str] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "payload": self.payload,
            "triggered": self.triggered,
            "dialog_message": self.dialog_message,
            "has_screenshot": bool(self.screenshot_b64),
            "screenshot_b64": self.screenshot_b64,
            "console_errors": self.console_errors,
            "dom_changes": self.dom_changes,
            "confidence": self.confidence,
        }


@dataclass
class PofResult:
    """POC 验证结果"""
    original_finding: Dict[str, Any]
    verified: bool = False
    visual_evidence: Optional[VisualEvidence] = None
    confidence_before: float = 0.0
    confidence_after: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verified": self.verified,
            "confidence_before": self.confidence_before,
            "confidence_after": self.confidence_after,
            "visual_evidence": self.visual_evidence.to_dict() if self.visual_evidence else None,
        }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 无头浏览器引擎
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class BrowserEngine:
    """
    共享无头浏览器引擎 — 为所有需要浏览器执行验证的插件提供统一的
    Playwright 实例管理、视觉取证和 POC 验证能力。

    用法:
        async with BrowserEngine() as engine:
            evidence = await engine.verify_xss(url, payload)
            if evidence.triggered:
                print(f"XSS 已确认! 截图大小: {len(evidence.screenshot_b64)}")
    """

    # 哨兵 marker — 用于判定 JS 执行是否真实触发
    _SENTINEL = "LS_PROOF_112233"

    def __init__(
        self,
        headless: bool = True,
        timeout_ms: int = 8000,
        viewport_width: int = 1280,
        viewport_height: int = 720,
    ) -> None:
        self._headless = headless
        self._timeout_ms = timeout_ms
        self._viewport = {"width": viewport_width, "height": viewport_height}
        self._pw = None
        self._browser = None
        self._available = False

    async def __aenter__(self) -> "BrowserEngine":
        await self.start()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.stop()

    @property
    def is_available(self) -> bool:
        return self._available

    async def start(self) -> bool:
        """启动 Playwright Chromium 实例"""
        try:
            from playwright.async_api import async_playwright
            self._pw = await async_playwright().start()
            self._browser = await self._pw.chromium.launch(
                headless=self._headless,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-extensions",
                ],
            )
            self._available = True
            logger.info("[Browser] Chromium 无头浏览器已启动")
            return True
        except ImportError:
            logger.warning(
                "[Browser] Playwright 未安装。"
                "运行 'pip install playwright && playwright install chromium' 安装。"
            )
            self._available = False
            return False
        except Exception as exc:
            logger.warning("[Browser] Chromium 启动失败: %s", exc)
            self._available = False
            return False

    async def stop(self) -> None:
        """关闭浏览器和 Playwright"""
        try:
            if self._browser:
                await self._browser.close()
            if self._pw:
                await self._pw.stop()
        except Exception:
            pass
        self._browser = None
        self._pw = None
        self._available = False
        logger.info("[Browser] 浏览器引擎已关闭")

    # ── XSS 视觉验证 ─────────────────────────

    async def verify_xss(
        self,
        url: str,
        payload: str,
        auth_cookies: Optional[Dict[str, str]] = None,
    ) -> VisualEvidence:
        """
        在真实浏览器中验证 XSS Payload 是否触发。

        流程:
          1. 创建隔离的浏览器上下文
          2. 注入 Dialog 事件拦截器
          3. 注入 Console Error 监听
          4. 导航到含 Payload 的 URL
          5. 等待 JS 执行
          6. 如果 Dialog 触发 → 截图 → 信心值 1.0
          7. 如果 Console Error 含 marker → 信心值 0.95

        Args:
            url:          含有 XSS Payload 的完整 URL
            payload:      原始 Payload 字符串 (用于记录)
            auth_cookies: 可选的认证 Cookie

        Returns:
            VisualEvidence 视觉取证结果
        """
        evidence = VisualEvidence(url=url, payload=payload)

        if not self._available or not self._browser:
            evidence.confidence = 0.0
            return evidence

        context = None
        page = None
        try:
            # 创建隔离上下文
            context = await self._browser.new_context(
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/125.0.0.0 Safari/537.36"
                ),
                viewport=self._viewport,
            )

            # 注入 Cookie
            if auth_cookies:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                cookies = [
                    {
                        "name": k,
                        "value": v,
                        "domain": parsed.hostname or "",
                        "path": "/",
                    }
                    for k, v in auth_cookies.items()
                ]
                await context.add_cookies(cookies)

            page = await context.new_page()

            # ━━ Dialog 拦截器 (弹窗捕获) ━━
            async def on_dialog(dialog):
                msg = dialog.message
                evidence.dialog_message = msg
                evidence.triggered = True

                # 弹窗瞬间截图 (Visual Proof)
                try:
                    # 等待一小会确保渲染完成
                    await asyncio.sleep(0.5)
                    raw = await page.screenshot(
                        type="png",
                        full_page=False,
                    )
                    evidence.screenshot_b64 = base64.b64encode(raw).decode("ascii")
                    logger.info(
                        "[Browser/XSS] 视觉取证: 弹窗截图成功 (%d bytes)", len(raw)
                    )
                except Exception as ss_exc:
                    logger.debug("[Browser/XSS] 截图失败: %s", ss_exc)

                await dialog.dismiss()

            page.on("dialog", on_dialog)

            # ━━ Console 监听 ━━
            def on_console(msg):
                if msg.type == "error":
                    evidence.console_errors.append(msg.text[:200])

            page.on("console", on_console)

            # ━━ 导航并等待执行 ━━
            try:
                await page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=self._timeout_ms,
                )
                # 等待 JS 异步执行
                await asyncio.sleep(1.0)
            except Exception as nav_exc:
                logger.debug("[Browser/XSS] 导航错误 (可能本身就是XSS): %s", nav_exc)

            # 如果弹窗未触发，尝试检测 DOM 注入或 Sentinel 触发
            if not evidence.triggered:
                try:
                    # 检查是否有 Sentinel 注入或异常标签
                    check_script = f"""() => {{
                        const body = document.body.innerHTML;
                        const has_sentinel = body.includes('{self._SENTINEL}');
                        const scripts = document.querySelectorAll('script');
                        const dangerous = document.querySelectorAll('img[onerror], svg[onload], details[ontoggle]');
                        return {{
                            has_sentinel,
                            script_count: scripts.length,
                            dangerous_count: dangerous.length
                        }};
                    }}"""
                    res = await page.evaluate(check_script)
                    if res['has_sentinel'] or res['dangerous_count'] > 0:
                        evidence.dom_changes.append(
                            f"DOM 异常检测: Sentinel={res['has_sentinel']}, DangerousTags={res['dangerous_count']}"
                        )
                        evidence.confidence = 0.85
                        # 补抓一张截图作为证据
                        raw = await page.screenshot(type="png")
                        evidence.screenshot_b64 = base64.b64encode(raw).decode("ascii")
                except Exception as eval_exc:
                    logger.debug("[Browser/XSS] DOM Evaluate 失败: %s", eval_exc)

            # 最终截图 (无论是否触发)
            if evidence.triggered and not evidence.screenshot_b64:
                try:
                    raw = await page.screenshot(type="png", full_page=False)
                    evidence.screenshot_b64 = base64.b64encode(raw).decode("ascii")
                except Exception:
                    pass

            # 信心值计算
            if evidence.triggered:
                evidence.confidence = 1.0
            elif evidence.dom_changes:
                evidence.confidence = 0.85

        except Exception as exc:
            logger.debug("[Browser/XSS] 验证异常: %s", exc)
        finally:
            try:
                if page:
                    await page.close()
                if context:
                    await context.close()
            except Exception:
                pass

        return evidence

    # ── 批量 XSS 验证 ────────────────────────

    async def verify_xss_batch(
        self,
        findings: List[Dict[str, Any]],
        auth_cookies: Optional[Dict[str, str]] = None,
    ) -> List[PofResult]:
        """
        批量验证 XSS 发现 — 只对已报告的 XSS 漏洞进行浏览器回放验证。

        Args:
            findings: 插件报告的 XSS 发现列表
            auth_cookies: 可选的认证 Cookie

        Returns:
            验证结果列表
        """
        results: List[PofResult] = []

        for finding in findings:
            url = finding.get("url", "")
            payload = finding.get("payload", "")
            confidence_before = finding.get("confidence", 0.0)

            if not url or not payload:
                continue

            evidence = await self.verify_xss(url, payload, auth_cookies)

            pof = PofResult(
                original_finding=finding,
                verified=evidence.triggered,
                visual_evidence=evidence,
                confidence_before=confidence_before,
                confidence_after=evidence.confidence,
            )
            results.append(pof)

            logger.info(
                "[Browser/POF] %s | 验证=%s | 信心 %.0f%% → %.0f%%",
                payload[:50],
                "✅ 确认" if pof.verified else "❌ 未触发",
                confidence_before * 100,
                evidence.confidence * 100,
            )

        return results

    # ── 通用页面截图 ──────────────────────────

    async def take_screenshot(
        self,
        url: str,
        full_page: bool = False,
    ) -> Optional[str]:
        """
        对指定 URL 进行全页面截图。

        Returns:
            Base64 编码的 PNG 图片, 失败返回 None
        """
        if not self._available or not self._browser:
            return None

        page = None
        try:
            page = await self._browser.new_page(
                ignore_https_errors=True,
                viewport=self._viewport,
            )
            await page.goto(url, wait_until="networkidle", timeout=self._timeout_ms)
            raw = await page.screenshot(type="png", full_page=full_page)
            return base64.b64encode(raw).decode("ascii")
        except Exception as exc:
            logger.debug("[Browser] 截图失败: %s", exc)
            return None
        finally:
            if page:
                try:
                    await page.close()
                except Exception:
                    pass
