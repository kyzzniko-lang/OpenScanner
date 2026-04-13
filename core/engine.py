"""
core/engine.py — OpenScanner 两阶段扫描调度引擎

架构设计：
  ┌─────────────────────────────────────────────────────┐
  │               ScanEngine (指挥中心)                  │
  ├─────────────────────────────────────────────────────┤
  │  PluginRegistry  — 自动发现, 分类注册               │
  │  SharedContext    — 跨插件状态传递                   │
  │  AsyncRequester   — 连接池管理                      │
  ├─────────────────────────────────────────────────────┤
  │  Stage 1: INFO 侦察  →  WAF / 指纹 / 技术栈探测     │
  │      ↓ (结果写入 SharedContext)                      │
  │  Stage 2: POC 漏洞扫描  →  SQLi / XSS / Dir 等      │
  │      ↑ (读取 SharedContext 动态调整策略)              │
  └─────────────────────────────────────────────────────┘

关键特性：
  • 智能插件加载：importlib 动态发现, 自动区分 info/pocs
  • 两阶段扫描流：info 侦察优先, 漏洞扫描自适应 WAF
  • 事件回调系统：支持 CLI / GUI 实时更新进度
  • 工业级异常隔离：单插件崩溃不影响全局
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import logging
import pkgutil
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Type

from core.request import AsyncRequester, RequestConfig
from core.reasoner import DeepReasoner, ReasoningVerdict
from core.browser import BrowserEngine
from core.ai.base import AIConfig
from core.ai.engine import AIEngine
from plugins.base import BasePlugin, PluginMeta, ScanResult, Severity
from utils.poc_gen import PocGenerator
from utils.patch_advisor import PatchAdvisor
from utils.mutator import AdaptiveMutator

logger = logging.getLogger("openscanner.engine")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 插件分类
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class PluginCategory(Enum):
    """插件类别 — 根据所在目录自动分类"""
    INFO = "info"      # 信息收集 / 侦察类
    POC = "poc"        # 漏洞检测类
    AUDIT = "audit"    # 源码审计 / 局域类
    UNKNOWN = "unknown"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 扫描事件（用于 CLI / GUI 回调）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ScanEvent(Enum):
    ENGINE_START = "engine_start"
    PLUGINS_LOADED = "plugins_loaded"
    STAGE_START = "stage_start"
    STAGE_END = "stage_end"
    PLUGIN_START = "plugin_start"
    PLUGIN_END = "plugin_end"
    VULN_FOUND = "vuln_found"
    ENGINE_END = "engine_end"
    ERROR = "error"
    TARGET_UNREACHABLE = "target_unreachable"


# 回调函数类型
EventCallback = Callable[[ScanEvent, Dict[str, Any]], None]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 插件注册表
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class PluginRegistry:
    """
    智能插件注册表

    功能:
      • 递归扫描 plugins/ 下所有 Python 模块
      • 自动区分 info 类和 pocs 类插件
      • 按 severity 排序, 按 category 分组
    """

    def __init__(self) -> None:
        self._plugins: Dict[str, BasePlugin] = {}
        self._categories: Dict[str, PluginCategory] = {}  # plugin_name → category
        self._module_map: Dict[str, str] = {}  # plugin_name → module_path

    @property
    def plugins(self) -> Dict[str, BasePlugin]:
        return dict(self._plugins)

    @property
    def count(self) -> int:
        return len(self._plugins)

    # ── 自动发现 ─────────────────────────────

    def discover(self, *scan_dirs: Path) -> int:
        """
        自动扫描并注册所有插件

        Returns:
            新发现的插件数量
        """
        before = self.count
        plugins_root = Path(__file__).resolve().parent.parent / "plugins"

        if not scan_dirs:
            scan_dirs = tuple(
                d for d in [plugins_root / "info", plugins_root / "pocs", plugins_root / "audit"]
                if d.is_dir()
            )

        for scan_dir in scan_dirs:
            scan_dir = Path(scan_dir).resolve()
            if not scan_dir.is_dir():
                logger.warning("插件目录不存在: %s", scan_dir)
                continue

            # 根据目录名自动判断类别
            category = self._infer_category(scan_dir, plugins_root)
            self._scan_directory(scan_dir, plugins_root, category)

        discovered = self.count - before
        logger.info(
            "插件发现完成 | 新增 %d | 总计 %d (info=%d, poc=%d)",
            discovered,
            self.count,
            len(self.get_info_plugins()),
            len(self.get_poc_plugins()),
        )
        return discovered

    def _infer_category(self, directory: Path, root: Path) -> PluginCategory:
        """根据目录路径推断插件类别"""
        try:
            rel = directory.relative_to(root)
            parts = rel.parts
            if "info" in parts:
                return PluginCategory.INFO
            if "pocs" in parts or "poc" in parts:
                return PluginCategory.POC
            if "audit" in parts:
                return PluginCategory.AUDIT
        except ValueError:
            pass
        return PluginCategory.UNKNOWN

    def _scan_directory(
        self, directory: Path, plugins_root: Path, category: PluginCategory
    ) -> None:
        """递归扫描目录中的 Python 模块"""
        try:
            rel = directory.relative_to(plugins_root)
            package_name = "plugins." + ".".join(rel.parts)
        except ValueError:
            package_name = "plugins"

        for importer, module_name, is_pkg in pkgutil.walk_packages(
            path=[str(directory)],
            prefix=package_name + ".",
        ):
            if module_name.endswith("__init__"):
                continue
            try:
                module = importlib.import_module(module_name)
                self._extract_plugins(module, category, module_name)
            except Exception as exc:
                logger.error("模块加载失败 [%s]: %s", module_name, exc)

    def _extract_plugins(
        self, module: Any, category: PluginCategory, module_path: str
    ) -> None:
        """提取模块中的 BasePlugin 子类"""
        for name in dir(module):
            obj = getattr(module, name)
            if not (inspect.isclass(obj) and issubclass(obj, BasePlugin)):
                continue
            if obj is BasePlugin or inspect.isabstract(obj):
                continue
            if not hasattr(obj, "meta") or not isinstance(obj.meta, PluginMeta):
                continue
            if obj.meta.name in self._plugins:
                continue
            if not obj.meta.enabled:
                logger.debug("跳过禁用插件: %s", obj.meta.name)
                continue

            try:
                instance = obj()
                self._plugins[instance.meta.name] = instance
                self._categories[instance.meta.name] = category
                self._module_map[instance.meta.name] = module_path
                logger.info(
                    "  ✔ [%s] %s v%s (%s)",
                    category.value.upper(),
                    instance.meta.display_name,
                    instance.meta.version,
                    instance.meta.severity,
                )
            except Exception as exc:
                logger.error("插件实例化失败 [%s]: %s", name, exc)

    # ── 分类查询 ──────────────────────────────

    def get(self, name: str) -> Optional[BasePlugin]:
        return self._plugins.get(name)

    def get_category(self, name: str) -> PluginCategory:
        return self._categories.get(name, PluginCategory.UNKNOWN)

    def get_info_plugins(self) -> List[BasePlugin]:
        """获取所有 INFO 类插件（侦察用）"""
        return [
            p for p in self._plugins.values()
            if self._categories.get(p.meta.name) == PluginCategory.INFO
        ]

    def get_poc_plugins(self) -> List[BasePlugin]:
        """获取所有 POC 类插件（漏洞检测用）"""
        return [
            p for p in self._plugins.values()
            if self._categories.get(p.meta.name) == PluginCategory.POC
        ]

    def get_audit_plugins(self) -> List[BasePlugin]:
        """获取所有 AUDIT 类插件（源码审计用）"""
        return [
            p for p in self._plugins.values()
            if self._categories.get(p.meta.name) == PluginCategory.AUDIT
        ]

    def get_by_severity(self, severity: Severity) -> List[BasePlugin]:
        return [p for p in self._plugins.values() if p.meta.severity == severity]

    def get_by_tag(self, tag: str) -> List[BasePlugin]:
        return [p for p in self._plugins.values() if tag in p.meta.tags]

    def sorted_plugins(self) -> List[BasePlugin]:
        order = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
                 Severity.HIGH: 3, Severity.CRITICAL: 4}
        return sorted(self._plugins.values(), key=lambda p: order.get(p.meta.severity, 99))

    def list_plugins(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": p.meta.name,
                "display_name": p.meta.display_name,
                "severity": str(p.meta.severity),
                "category": self._categories.get(p.meta.name, PluginCategory.UNKNOWN).value,
                "version": p.meta.version,
                "tags": p.meta.tags,
                "module": self._module_map.get(p.meta.name, ""),
            }
            for p in self.sorted_plugins()
        ]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 两阶段扫描引擎
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ScanEngine:
    """
    OpenScanner 两阶段扫描调度引擎

    Workflow:
        engine = ScanEngine(config)
        engine.load_plugins()
        results = await engine.scan(targets)
        print(engine.summary())

    Two-Stage Pipeline:
        Stage 1: INFO 插件侦察 (WAF / 指纹 / 技术栈)
            ↓ shared_context
        Stage 2: POC 插件漏洞扫描 (SQLi / XSS / ...)
    """

    def __init__(
        self,
        config: Optional[RequestConfig] = None,
        ai_config: Optional[AIConfig] = None,
        plugin_dirs: Optional[List[Path]] = None,
    ) -> None:
        self._config = config or RequestConfig()
        self._registry = PluginRegistry()
        self._ai_engine = AIEngine(ai_config)
        self._requester: Optional[AsyncRequester] = None
        self._results: List[ScanResult] = []
        self._plugin_dirs = plugin_dirs
        self._scan_start: float = 0
        self._scan_end: float = 0
        self._context: Dict[str, Any] = {}
        self._down_targets: Set[str] = set()
        self._callbacks: List[EventCallback] = []

    # ── 属性 ─────────────────────────────────

    @property
    def registry(self) -> PluginRegistry:
        return self._registry

    @property
    def results(self) -> List[ScanResult]:
        return list(self._results)

    @property
    def context(self) -> Dict[str, Any]:
        return dict(self._context)

    @property
    def elapsed(self) -> float:
        if self._scan_end > 0:
            return self._scan_end - self._scan_start
        elif self._scan_start > 0:
            return time.time() - self._scan_start
        return 0.0

    # ── 事件回调 ──────────────────────────────

    def on_event(self, callback: EventCallback) -> None:
        """注册事件回调（CLI / GUI 用）"""
        self._callbacks.append(callback)

    def _emit(self, event: ScanEvent, data: Optional[Dict[str, Any]] = None) -> None:
        """触发事件通知"""
        payload = data or {}
        for cb in self._callbacks:
            try:
                cb(event, payload)
            except Exception as exc:
                logger.debug("事件回调异常: %s", exc)

    # ── 插件加载 ──────────────────────────────

    def load_plugins(self) -> int:
        if self._plugin_dirs:
            count = self._registry.discover(*self._plugin_dirs)
        else:
            count = self._registry.discover()

        self._emit(ScanEvent.PLUGINS_LOADED, {
            "count": count,
            "total": self._registry.count,
            "info_count": len(self._registry.get_info_plugins()),
            "poc_count": len(self._registry.get_poc_plugins()),
            "plugins": self._registry.list_plugins(),
        })
        return count

    # ── 两阶段扫描 ────────────────────────────

    async def scan(
        self,
        targets: List[str],
        config: Optional[RequestConfig] = None,
        plugins_filter: Optional[List[str]] = None,
        associated_source_dir: str = "",
        context_params: Optional[Dict[str, str]] = None,
        initial_context: Optional[Dict[str, Any]] = None,
    ) -> List[ScanResult]:
        """
        同步入口，启动异步事件循环

        Args:
            targets: 目标 URL 或路径列表
            config: 请求超时和并发配置
            plugins_filter: 限定运行的插件列表
            associated_source_dir: 可选的本地源码路径（用于 IAST 联动追踪）
            context_params: 可选的附加业务参数，传递给所有插件作为注入时的上下文参考
            initial_context: 引擎初始化时的全局上下文 (如 cookie, progress_callback)
        """
        self._results.clear()
        self._context.clear()
        self._down_targets.clear()
        if initial_context:
            self._context.update(initial_context)
        self._context["business_params"] = context_params or {}
        
        # AIPM Context Isolation: One mutator per target
        mutators = {target: AdaptiveMutator() for target in targets}
        self._context["mutators"] = mutators
        
        self._scan_start = time.time()
        
        # ── 启动 AI 研判大脑 ──
        await self._ai_engine.initialize()

        self._emit(ScanEvent.ENGINE_START, {
            "targets": targets,
            "plugin_count": self._registry.count,
            "config": {
                "concurrency": self._config.max_concurrency,
                "timeout": self._config.request_timeout,
                "http2": self._config.http2,
            },
        })

        # 按类别和过滤器选择插件
        info_plugins = self._filter_plugins(
            self._registry.get_info_plugins(), plugins_filter, None, None
        )
        poc_plugins = self._filter_plugins(
            self._registry.get_poc_plugins(), plugins_filter, None, None
        )
        audit_plugins = self._filter_plugins(
            self._registry.get_audit_plugins(), plugins_filter, None, None
        )

        async with AsyncRequester(self._config) as requester:
            self._requester = requester

            # ═══════════════════════════════════
            # Pre-Stage: 连通性与 WAF 基础探测
            # ═══════════════════════════════════
            await self._check_connectivity(targets, requester)

            # ═══════════════════════════════════
            # Stage 1: INFO 侦察
            # ═══════════════════════════════════
            if info_plugins:
                await self._run_stage(
                    stage_name="Stage 1: 信息侦察",
                    stage_num=1,
                    plugins=info_plugins,
                    targets=targets,
                    requester=requester,
                )

            # 输出 WAF 状态摘要
            waf_data = self._context.get("waf", {})
            if waf_data:
                for url, info in waf_data.items():
                    logger.info(
                        "🛡️ WAF 状态: %s → %s",
                        url,
                        ", ".join(info.get("waf_list", ["Unknown"])),
                    )

            # ═══════════════════════════════════
            # Stage 2: POC 漏洞扫描
            # ═══════════════════════════════════
            if poc_plugins:
                await self._run_stage(
                    stage_name="Stage 2: 漏洞扫描",
                    stage_num=2,
                    plugins=poc_plugins,
                    targets=targets,
                    requester=requester,
                )

            # ═══════════════════════════════════
            # Stage 3: 代码审计 (SAST)
            # ═══════════════════════════════════
            if audit_plugins:
                await self._run_stage(
                    stage_name="Stage 3: 源码审计",
                    stage_num=3,
                    plugins=audit_plugins,
                    targets=targets,
                    requester=requester,
                )

            # ═══════════════════════════════════
            # Stage 4: IAST 溯源联动 (DAST -> SAST)
            # ═══════════════════════════════════
            if associated_source_dir and Path(associated_source_dir).is_dir():
                malware_plugin = self._registry.get("malware_scan")
                if malware_plugin and hasattr(malware_plugin, "trace_variable"):
                    reasoner = DeepReasoner()
                    src_path = Path(associated_source_dir)

                    for r in list(self._results):
                        vparams = r.extra.get("vulnerable_params", [])
                        for param in vparams:
                            # 过滤非预期字符，防止日志注入或通过正则/路径引发的意外情况
                            import re
                            safe_param = re.sub(r'[^a-zA-Z0-9_$\[\]-]', '', param)
                            if not safe_param:
                                continue

                            logger.info("[IAST] 发现外部污染参数 '%s'，触发源码溯源...", safe_param)

                            # ── 4a: 变量追踪 (Sink 定位) ──
                            trace_findings = await malware_plugin.trace_variable(safe_param, src_path)

                            # ── 4b: 净化函数检查 ──
                            sanitizer_status = None
                            if hasattr(malware_plugin, "check_sanitizers"):
                                sanitizer_status = await malware_plugin.check_sanitizers(safe_param, src_path)
                                logger.info(
                                    "[IAST] 参数 '%s' 净化状态: has_sanitizer=%s, found=%s",
                                    param,
                                    sanitizer_status.get("has_sanitizer"),
                                    sanitizer_status.get("sanitizers_found", []),
                                )

                            # ── 4c: 深度研判 (Reasoner) ──
                            verdict = reasoner.evaluate(r, self._context, sanitizer_status)
                            logger.info(
                                "[Reasoner] 参数 '%s' 信心值: %.1f%% | 建议覆写: %s",
                                param, verdict.confidence * 100, verdict.severity_override,
                            )

                            # 如果无净化函数 → 自动提升至 CRITICAL
                            final_severity = Severity.CRITICAL
                            if sanitizer_status and sanitizer_status.get("has_sanitizer"):
                                final_severity = verdict.severity_override or r.severity
                            elif verdict.severity_override:
                                final_severity = verdict.severity_override

                            if trace_findings:
                                trace_res = malware_plugin.result(
                                    url=associated_source_dir,
                                    is_vulnerable=True,
                                    detail=(
                                        f"IAST 联动: 参数 '{param}' 在后台代码中流入危险 Sink。"
                                        f" 信心值: {verdict.confidence*100:.1f}%。"
                                        f" 净化函数: {'未发现 → 自动升级 CRITICAL' if not (sanitizer_status and sanitizer_status.get('has_sanitizer')) else '已发现'}。"
                                    ),
                                    extra={
                                        "findings": trace_findings,
                                        "cvss_score": 10.0 if final_severity == Severity.CRITICAL else 7.5,
                                        "total_issues": len(trace_findings),
                                        "reasoning": verdict.to_dict(),
                                        "sanitizer_status": sanitizer_status,
                                    }
                                )
                                self._results.append(trace_res)

            # ═══════════════════════════════════
            # Stage 5: 深度研判 (Medium/Low 不确定结果)
            # ═══════════════════════════════════
            reasoner = DeepReasoner()
            reasoning_tasks = []
            # 使用信号量控制 AI 并发，防止触发 API 速率限制
            ai_sem = asyncio.Semaphore(4) 

            async def _reason_one(r: ScanResult):
                async with ai_sem:
                    sanitizer_status = None
                    if associated_source_dir and Path(associated_source_dir).is_dir():
                        malware_plugin = self._registry.get("malware_scan")
                        if malware_plugin and hasattr(malware_plugin, "check_sanitizers"):
                            # 只巡检第一个存在漏洞的参数以节省资源
                            target_param = r.extra.get("vulnerable_params", [None])[0]
                            if target_param:
                                sanitizer_status = await malware_plugin.check_sanitizers(
                                    target_param, Path(associated_source_dir)
                                )

                    # ── AI 共识研判 (Exhaustive Consensus) ──
                    ai_response = None
                    if self._ai_engine and self._ai_engine.is_enabled:
                        attempts = r.extra.get("attempts", [])
                        if attempts:
                            logger.info("[Engine] 启动 AI 并行共识研判: %s", r.plugin_name)
                            ai_response = await self._ai_engine.verify_consensus(
                                url=r.url,
                                method=r.extra.get("method", "GET"),
                                param=r.extra.get("param", ""),
                                attempts=attempts,
                                waf_detected=r.extra.get("waf_detected", False)
                            )

                    # 提交 Reasoner 综合判定
                    verdict = reasoner.evaluate(
                        r, self._context, 
                        sanitizer_status=sanitizer_status,
                        ai_response=ai_response
                    )
                    r.extra["reasoning"] = verdict.to_dict()

                    if verdict.severity_override and verdict.confidence >= 0.65:
                        logger.warning(
                            "[Reasoner] 升级漏洞等级: %s → %s (confidence=%.1f%%)",
                            r.severity, verdict.severity_override, verdict.confidence * 100,
                        )
                        r.severity = verdict.severity_override

            # 筛选需要研判的结果
            targets_for_reasoning = [
                r for r in self._results 
                if r.is_vulnerable and r.severity in (Severity.MEDIUM, Severity.LOW)
            ]
            
            if targets_for_reasoning:
                logger.info("[Engine] Stage 5: 对 %d 个结果启动异步研判并行流...", len(targets_for_reasoning))
                await asyncio.gather(*[_reason_one(r) for r in targets_for_reasoning], return_exceptions=True)

            # ═══════════════════════════════════
            # Stage 6: 视觉取证 POF 验证 (XSS Browser Verification)
            # ═══════════════════════════════════
            xss_results = [
                r for r in self._results
                if r.is_vulnerable and r.plugin_name in ("xss_scan", "dom_xss_headless")
                and r.extra.get("findings")
            ]
            if xss_results:
                logger.info("[Engine] 启动 Stage 6: 视觉取证验证 (%d 个 XSS 发现)", len(xss_results))
                try:
                    async with BrowserEngine() as browser:
                        if browser.is_available:
                            for r in xss_results:
                                for finding in r.extra.get("findings", []):
                                    payload = finding.get("payload", "")
                                    if not payload:
                                        continue
                                    # 构建验证 URL
                                    verify_url = r.url
                                    if "?" in verify_url:
                                        verify_url += f"&xss_verify={payload}"
                                    else:
                                        verify_url += f"?xss_verify={payload}"

                                    evidence = await browser.verify_xss(verify_url, payload)
                                    if evidence.triggered:
                                        finding["browser_verified"] = True
                                        finding["confidence"] = 1.0
                                        finding["visual_proof"] = evidence.dialog_message
                                        if evidence.screenshot_b64:
                                            r.extra.setdefault("screenshots", []).append(
                                                evidence.screenshot_b64
                                            )
                                        logger.info(
                                            "[POF] ✅ XSS 浏览器确认: %s", payload[:60],
                                        )
                                    else:
                                        finding["browser_verified"] = False
                except Exception as browser_exc:
                    logger.debug("[Engine] 浏览器验证跳过: %s", browser_exc)

        self._scan_end = time.time()

        # 将 WAF Heatmap 写入上下文 (供报告使用)
        for r in self._results:
            if r.plugin_name == "waf_check" and r.extra.get("heatmap"):
                self._context["waf_heatmap"] = r.extra["heatmap"]
                break

        vuln_count = sum(1 for r in self._results if r.is_vulnerable)
        self._emit(ScanEvent.ENGINE_END, {
            "total_checks": len(self._results),
            "vulnerabilities": vuln_count,
            "elapsed": self.elapsed,
        })

        return self.results

    async def _check_connectivity(self, targets: List[str], requester: AsyncRequester) -> None:
        """预扫描连通性检查，支持远程 URL 和本地文件路径 (SAST)"""
        logger.info("📡 正在检查目标连通性...")
        for target in targets:
            # 识别本地路径 (SAST 模式)
            is_local = False
            # 简单启发式：包含盘符 (D:\) 或 绝对路径 (/) 且不含 http
            if (":" in target or target.startswith("/") or target.startswith("\\")) and "://" not in target:
                is_local = True

            if is_local:
                path = Path(target)
                if path.exists():
                    logger.info("[✓] 本地路径有效: %s", target)
                    continue
                else:
                    msg = f"本地路径不存在或无法访问: {target}"
                    logger.error("[x] %s -> %s", target, msg)
                    self._down_targets.add(target)
                    self._emit(ScanEvent.TARGET_UNREACHABLE, {
                        "target": target,
                        "type": "path_missing",
                        "reason": msg
                    })
                    continue

            # 远程 URL 探测 (DAST 模式)
            try:
                # 使用极短超时进行初步探测
                resp = await requester.get(target, timeout=10.0)
                if resp.status_code in (403, 406, 999):
                    msg = f"目标存在 WAF/防火墙拦截 (Status: {resp.status_code})"
                    logger.warning("[!] %s -> %s", target, msg)
                    self._emit(ScanEvent.TARGET_UNREACHABLE, {
                        "target": target,
                        "type": "blocked",
                        "reason": msg
                    })
            except Exception as exc:
                exc_str = str(exc)
                if not exc_str:
                    exc_str = repr(exc)

                # 解压缩错误说明 TCP/TLS 连接成功，只是响应体编码异常，
                # 不应视为目标不可达 — 后续插件可能使用不同参数成功解析
                if "decompressing" in exc_str.lower() or "zlib" in exc_str.lower():
                    logger.info("[✓] %s -> 连接成功 (响应体解压缩异常，不影响扫描)", target)
                    continue
                
                if "SSRF" in exc_str:
                    msg = f"安全引擎拦截 (SSRF): {exc_str}"
                    err_type = "ssrf_block"
                elif "Timeout" in exc_str:
                    msg = f"网络请求超时: {exc_str}"
                    err_type = "timeout"
                elif "gaierror" in exc_str or "DNS" in exc_str:
                    msg = f"DNS 解析失败: {exc_str}"
                    err_type = "dns_error"
                else:
                    msg = f"目标地址无法访问: {exc_str}"
                    err_type = "down"
                
                logger.error("[x] %s -> %s", target, msg)
                self._down_targets.add(target)
                self._emit(ScanEvent.TARGET_UNREACHABLE, {
                    "target": target,
                    "type": err_type,
                    "reason": msg
                })

    async def _run_stage(
        self,
        stage_name: str,
        stage_num: int,
        plugins: List[BasePlugin],
        targets: List[str],
        requester: AsyncRequester,
    ) -> None:
        """执行单个扫描阶段"""
        total_tasks = len(plugins) * len(targets)
        
        self._emit(ScanEvent.STAGE_START, {
            "stage": stage_num,
            "name": stage_name,
            "plugin_count": len(plugins),
            "target_count": len(targets),
            "total_tasks": total_tasks,
            "plugins": [p.meta.name for p in plugins],
        })

        logger.info("═══ %s ═══ 插件 %d 个 | 目标 %d 个", stage_name, len(plugins), len(targets))

        # Setup
        for plugin in plugins:
            try:
                await plugin.setup()
            except Exception as exc:
                logger.error("setup 失败 [%s]: %s", plugin.meta.name, exc)

        tasks = []
        task_idx = 0
        for plugin in plugins:
            for target in targets:
                task_idx += 1
                tasks.append(
                    self._run_plugin(plugin, target, requester, task_idx, total_tasks)
                )

        results = await asyncio.gather(*tasks, return_exceptions=True)
        # 记录任何插件异常 (超时/崩溃) 但不阻塞其他插件
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                logger.error("插件任务 %d/%d 异常: %s", i + 1, len(results), r)

        # Teardown
        for plugin in plugins:
            try:
                await plugin.teardown()
            except Exception as exc:
                logger.error("teardown 失败 [%s]: %s", plugin.meta.name, exc)

        self._emit(ScanEvent.STAGE_END, {
            "stage": stage_num,
            "name": stage_name,
        })

        logger.info("═══ %s 完成 ═══", stage_name)

    async def _run_plugin(
        self, plugin: BasePlugin, target: str, requester: AsyncRequester, current_idx: int, total_tasks: int
    ) -> None:
        """单个插件的沙箱执行环境"""
        start_time = time.time()
        result = None
        
        # 连通性检查过滤
        if target in self._down_targets:
            logger.debug("[Engine] 跳过不可访问目标: %s", target)
            return

        self._emit(ScanEvent.PLUGIN_START, {
            "plugin": plugin.meta.name,
            "display_name": plugin.meta.display_name,
            "target": target,
            "current_idx": current_idx,
            "total_tasks": total_tasks,
        })

        try:
            # 单插件 30 分钟超时保护 + 隔离的上下文
            # v1.0: 从 300s 提升至 1800s，适配穷举式共识模型的全量 payload 探测
            local_context = self._context.copy()
            local_context["current_target"] = target
            local_context["ai_engine"] = self._ai_engine  # 允许插件调用 AI 能力

            result = await asyncio.wait_for(
                plugin.check(target, requester, context=local_context),
                timeout=1800.0,
            )
            self._results.append(result)

            # WAF 结果自动写入 shared_context
            if result.plugin_name == "waf_check" and result.is_vulnerable:
                self._context.setdefault("waf", {})
                self._context["waf"][target] = {
                    "detected": True,
                    "waf_list": result.extra.get("waf_list", []),
                }

            if result.is_vulnerable:
                # ── 自动生成 POC 复现脚本 ──
                try:
                    auth_headers = None
                    if self._config.extra_headers:
                        auth_headers = dict(self._config.extra_headers)
                    poc_code = PocGenerator.generate(result.to_dict(), headers=auth_headers)
                    result.extra["poc_script"] = poc_code
                except Exception as poc_exc:
                    logger.debug("POC 生成失败: %s", poc_exc)

                # ── 自动生成修复补丁建议 ──
                try:
                    iast_findings = result.extra.get("findings", [])
                    if iast_findings:
                        patches = PatchAdvisor.advise_batch(iast_findings)
                        if patches:
                            result.extra["patch_suggestions"] = patches
                except Exception as patch_exc:
                    logger.debug("修复建议生成失败: %s", patch_exc)

                self._emit(ScanEvent.VULN_FOUND, {
                    "plugin": plugin.meta.name,
                    "display_name": plugin.meta.display_name,
                    "url": target,
                    "severity": str(result.severity),
                    "detail": result.detail,
                    "evidence": result.evidence,
                    "extra": result.extra,
                })

        except Exception as exc:
            logger.error("插件异常 [%s] %s: %s", plugin.meta.name, target, exc)
            
            # 记录异常结果，确保插件在报表中可见
            error_result = ScanResult(
                plugin_name=plugin.meta.name,
                url=target,
                is_vulnerable=False,
                severity=Severity.INFO,
                detail=f"系统异常: {str(exc)}",
                extra={"error": True, "exception": str(exc)}
            )
            self._results.append(error_result)

            self._emit(ScanEvent.ERROR, {
                "plugin": plugin.meta.name,
                "target": target,
                "error": str(exc),
            })
        finally:
            # 记录执行耗时
            elapsed = time.time() - start_time
            self._emit(ScanEvent.PLUGIN_END, {
                "plugin": plugin.meta.name,
                "target": target,
                "elapsed": elapsed,
                "has_result": result is not None,
                "current_idx": current_idx,
                "total_tasks": total_tasks,
            })

    def _filter_plugins(
        self,
        candidates: List[BasePlugin],
        names: Optional[List[str]],
        tags: Optional[List[str]],
        severities: Optional[List[Severity]],
    ) -> List[BasePlugin]:
        """按条件过滤插件"""
        if names:
            name_set = set(names)
            candidates = [p for p in candidates if p.meta.name in name_set]
        if tags:
            tag_set = set(tags)
            candidates = [p for p in candidates if tag_set.intersection(p.meta.tags)]
        if severities:
            sev_set = set(severities)
            candidates = [p for p in candidates if p.meta.severity in sev_set]
        return candidates

    # ── 结果汇总 ──────────────────────────────

    def summary(self) -> Dict[str, Any]:
        vuln_results = [r for r in self._results if r.is_vulnerable]
        by_severity: Dict[str, int] = {}
        by_plugin: Dict[str, int] = {}
        
        for r in self._results:
            sev_str = str(r.severity).lower()
            if r.is_vulnerable:
                by_severity[sev_str] = by_severity.get(sev_str, 0) + 1
                by_plugin[r.plugin_name] = by_plugin.get(r.plugin_name, 0) + 1
            else:
                # 核心修复：如果是安全的 INFO 审计结果，计入 info 而非强制 low
                if sev_str == "info":
                    by_severity["info"] = by_severity.get("info", 0) + 1
                else:
                    # 其他非审计类（如探测项）安全结果计入 low
                    by_severity["low"] = by_severity.get("low", 0) + 1
        
        # 重新校准漏洞计数：INFO 级别的审计结论不应计入“漏洞已发现”总数
        real_vulns = [r for r in self._results if r.is_vulnerable and str(r.severity).lower() != "info"]

        return {
            "total_checks": len(self._results),
            "vulnerabilities_found": len(real_vulns),
            "by_severity": by_severity,
            "by_plugin": by_plugin,
            "elapsed_seconds": round(self.elapsed, 2),
            "plugins_loaded": self._registry.count,
            "waf_detected": bool(self._context.get("waf")),
            "context": dict(self._context),
        }

    def __repr__(self) -> str:
        return (
            f"<ScanEngine plugins={self._registry.count} "
            f"results={len(self._results)} "
            f"info={len(self._registry.get_info_plugins())} "
            f"poc={len(self._registry.get_poc_plugins())}>"
        )
