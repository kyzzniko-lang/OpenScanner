"""
plugins/base.py — OpenScanner 插件基类

所有漏洞检测插件（POC）必须继承 BasePlugin 并实现 check() 方法。
插件通过 PluginMeta 声明元信息，便于引擎调度、报告生成和 UI 展示。
"""

from __future__ import annotations

import abc
import enum
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.request import AsyncRequester


# ─────────────────────────────────────────────
# 漏洞等级枚举
# ─────────────────────────────────────────────
class Severity(enum.Enum):
    """CVSS-aligned severity levels"""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __str__(self) -> str:
        return self.value

    @property
    def color(self) -> str:
        """供 Streamlit / 报告使用的配色"""
        return {
            "info": "#3498db",
            "low": "#2ecc71",
            "medium": "#f39c12",
            "high": "#e74c3c",
            "critical": "#8e44ad",
        }[self.value]


# ─────────────────────────────────────────────
# 插件元信息
# ─────────────────────────────────────────────
@dataclass
class PluginMeta:
    """插件元数据 — 每个插件必须声明"""

    name: str  # 英文标识, e.g. "sql_injection"
    display_name: str  # 展示名称, e.g. "SQL Injection"
    description: str  # 简短描述
    severity: Severity = Severity.INFO  # 漏洞等级
    cve: Optional[str] = None  # CVE 编号 (可选)
    tags: List[str] = field(default_factory=list)  # 标签, e.g. ["sqli", "owasp-top10"]
    author: str = "OpenScanner"
    version: str = "1.0.0"
    enabled: bool = True  # 是否启用


# ─────────────────────────────────────────────
# 扫描结果
# ─────────────────────────────────────────────
@dataclass
class ScanResult:
    """单项漏洞扫描的结果"""

    plugin_name: str
    url: str
    is_vulnerable: bool
    severity: Severity = Severity.INFO
    detail: str = ""  # 漏洞描述
    evidence: str = ""  # 证据 / payload / 关键响应片段
    extra: Dict[str, Any] = field(default_factory=dict)  # 扩展字段
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plugin": self.plugin_name,
            "url": self.url,
            "vulnerable": self.is_vulnerable,
            "severity": str(self.severity),
            "detail": self.detail,
            "evidence": self.evidence,
            "extra": self.extra,
            "timestamp": self.timestamp,
        }


# ─────────────────────────────────────────────
# 插件异步基类
# ─────────────────────────────────────────────
class BasePlugin(abc.ABC):
    """
    所有漏洞插件的抽象基类

    子类需要：
        1. 定义 meta 类属性  → PluginMeta 实例
        2. 实现 check()      → 异步检测入口

    Example::

        class SqliPlugin(BasePlugin):
            meta = PluginMeta(
                name="sqli_error_based",
                display_name="Error-Based SQLi",
                description="通过错误回显检测 SQL 注入",
                severity=Severity.HIGH,
            )

            async def check(self, url, requester):
                resp = await requester.get(url, params={"id": "1' OR 1=1--"})
                if "SQL syntax" in resp.text:
                    return self.result(url, True, detail="发现错误回显型 SQL 注入")
                return self.result(url, False)
    """

    # 子类必须覆盖
    meta: PluginMeta

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        # 确保所有非抽象子类都声明了 meta
        if not getattr(cls, "__abstractmethods__", None):
            if not hasattr(cls, "meta") or not isinstance(cls.meta, PluginMeta):
                raise TypeError(
                    f"插件 {cls.__name__} 必须定义 `meta: PluginMeta` 类属性"
                )

    # ── 核心接口 ──────────────────────────────

    @abc.abstractmethod
    async def check(
        self,
        url: str,
        requester: AsyncRequester,
        context: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        """
        执行漏洞检测

        Args:
            url:       待检测的目标 URL
            requester: 已初始化的异步请求器
            context:   跨插件共享上下文（如 WAF 检测结果）

        Returns:
            ScanResult 扫描结果
        """
        ...

    # ── 工具方法 ──────────────────────────────

    def result(
        self,
        url: str,
        is_vulnerable: bool,
        *,
        detail: str = "",
        evidence: str = "",
        extra: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        """快捷构建 ScanResult — 自动填充插件元信息"""
        return ScanResult(
            plugin_name=self.meta.name,
            url=url,
            is_vulnerable=is_vulnerable,
            severity=self.meta.severity if is_vulnerable else Severity.INFO,
            detail=detail or self.meta.description,
            evidence=evidence,
            extra=extra or {},
        )

    # ── 生命周期钩子（可选覆盖）──────────────

    async def setup(self) -> None:
        """插件初始化钩子（引擎在扫描前调用）"""

    async def teardown(self) -> None:
        """插件清理钩子（引擎在扫描后调用）"""

    # ── Dunder ────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"<Plugin [{self.meta.severity}] {self.meta.display_name} "
            f"v{self.meta.version}>"
        )
