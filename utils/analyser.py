"""
utils/analyser.py — OpenScanner 报告热分析引擎

功能：
  • CWE 自动关联   — 根据漏洞类型自动映射 CWE 编号和描述
  • 风险评级矩阵   — 结合 CWE 影响因子和检测信心值计算综合风险分
  • 修复建议生成   — 基于 CWE 自动推荐合规修复方案
  • 报告增强       — 对 ScanResult 列表注入 CWE 元数据

Usage:
    from utils.analyser import Analyser

    analyser = Analyser()
    enriched = analyser.enrich_results(scan_results)
    report = analyser.generate_summary(enriched)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("openscanner.analyser")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CWE 知识库
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass(frozen=True)
class CWEEntry:
    """CWE 条目"""
    cwe_id: str           # 如 "CWE-89"
    name: str             # 如 "SQL Injection"
    description: str      # 简述
    severity_weight: float  # 影响因子 0.0 ~ 1.0
    remediation: str      # 修复建议


# CWE 映射表 — 按插件名和漏洞类型关联
_CWE_DATABASE: Dict[str, CWEEntry] = {
    # ── SQL 注入 ──
    "sqli_scan": CWEEntry(
        cwe_id="CWE-89",
        name="Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
        description=(
            "应用程序在构造 SQL 查询时未对用户输入进行充分过滤，"
            "攻击者可注入恶意 SQL 语句来操纵数据库。"
        ),
        severity_weight=0.95,
        remediation=(
            "1. 使用参数化查询 (Prepared Statements / Parameterized Queries)\n"
            "2. 使用 ORM 框架自动转义\n"
            "3. 输入验证 — 白名单校验参数类型和范围\n"
            "4. 最小权限原则 — 数据库账户仅授予必要权限\n"
            "5. 部署 WAF 作为纵深防御层"
        ),
    ),
    # ── XSS ──
    "xss_scan": CWEEntry(
        cwe_id="CWE-79",
        name="Improper Neutralization of Input During Web Page Generation (XSS)",
        description=(
            "应用程序未对用户输入进行编码即输出到 HTML 页面，"
            "攻击者可注入恶意脚本窃取 Cookie 或劫持会话。"
        ),
        severity_weight=0.80,
        remediation=(
            "1. 输出编码 — 使用 htmlspecialchars / DOMPurify\n"
            "2. Content-Security-Policy (CSP) 头限制脚本来源\n"
            "3. HttpOnly / Secure Cookie 属性\n"
            "4. 输入验证 — 过滤 <script> / on* 事件属性"
        ),
    ),
    # ── 代码注入 / WebShell ──
    "malware_scan": CWEEntry(
        cwe_id="CWE-94",
        name="Improper Control of Generation of Code (Code Injection)",
        description=(
            "应用程序允许执行动态生成的代码（eval/exec/system），"
            "或存在已植入的 WebShell/后门程序。"
        ),
        severity_weight=1.00,
        remediation=(
            "1. 禁止使用 eval / exec / system 等危险函数\n"
            "2. 文件完整性监控 (FIM) — 检测未授权文件变更\n"
            "3. 代码审计 — 定期 AST 级深度扫描\n"
            "4. 最小权限 — Web 服务器进程降权运行"
        ),
    ),
    # ── WAF 探测 (信息泄露) ──
    "waf_check": CWEEntry(
        cwe_id="CWE-200",
        name="Exposure of Sensitive Information to an Unauthorized Actor",
        description=(
            "目标暴露了 WAF 指纹信息，攻击者可据此定制绕过策略。"
        ),
        severity_weight=0.30,
        remediation=(
            "1. 隐藏 WAF 指纹 — 移除 Server / X-Powered-By 响应头\n"
            "2. 自定义 WAF 错误页面 — 避免暴露产品名称\n"
            "3. 配置 WAF 拦截模式而非仅检测模式"
        ),
    ),
    # ── 目录遍历 ──
    "dir_traversal": CWEEntry(
        cwe_id="CWE-22",
        name="Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
        description=(
            "应用程序未校验文件路径参数，攻击者可使用 ../ 访问任意文件。"
        ),
        severity_weight=0.85,
        remediation=(
            "1. 规范化路径 — os.path.realpath 后校验前缀\n"
            "2. 白名单限制可访问的目录\n"
            "3. chroot / 容器隔离 Web 进程"
        ),
    ),
    # ── SSRF ──
    "ssrf_scan": CWEEntry(
        cwe_id="CWE-918",
        name="Server-Side Request Forgery (SSRF)",
        description=(
            "应用程序允许用户控制的 URL 被服务器端请求，"
            "攻击者可探测内网服务或读取云元数据。"
        ),
        severity_weight=0.90,
        remediation=(
            "1. URL 白名单 — 仅允许请求可信域名\n"
            "2. 禁止请求私有 IP 段 (10.0.0.0/8, 169.254.169.254)\n"
            "3. 网络层隔离 — 限制 Web 服务器出口网络"
        ),
    ),
}

# 默认 CWE (未知插件类型的兜底)
_DEFAULT_CWE = CWEEntry(
    cwe_id="CWE-20",
    name="Improper Input Validation",
    description="应用程序未对输入进行充分验证，可能导致安全漏洞。",
    severity_weight=0.50,
    remediation="1. 实施全面的输入验证\n2. 遵循安全编码最佳实践",
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 分析器
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class EnrichedResult:
    """增强后的扫描结果 — 包含 CWE 关联和风险评分"""
    original: Dict[str, Any]          # 原始 ScanResult.to_dict()
    cwe: CWEEntry                     # 关联的 CWE 条目
    risk_score: float = 0.0           # 综合风险分 (0.0 ~ 10.0)
    remediation: str = ""             # 修复建议

    def to_dict(self) -> Dict[str, Any]:
        return {
            **self.original,
            "cwe": {
                "id": self.cwe.cwe_id,
                "name": self.cwe.name,
                "description": self.cwe.description,
            },
            "risk_score": round(self.risk_score, 2),
            "remediation": self.remediation,
        }


class Analyser:
    """
    OpenScanner 报告热分析引擎

    功能:
        1. CWE 自动关联 — 根据插件名 → CWE 映射
        2. 风险评分计算 — CWE 影响因子 × 检测信心值 × 10
        3. 修复建议注入 — 按 CWE 推荐合规修复方案
        4. 统计汇总     — 按 CWE 分类统计漏洞分布

    Usage::

        analyser = Analyser()
        enriched = analyser.enrich_results(scan_results_dicts)
        summary = analyser.generate_summary(enriched)
    """

    def __init__(
        self,
        cwe_database: Optional[Dict[str, CWEEntry]] = None,
    ) -> None:
        self._db = cwe_database or _CWE_DATABASE

    def lookup_cwe(self, plugin_name: str) -> CWEEntry:
        """根据插件名查找关联的 CWE 条目"""
        return self._db.get(plugin_name, _DEFAULT_CWE)

    def calculate_risk_score(
        self,
        cwe: CWEEntry,
        confidence: float = 0.85,
        has_waf: bool = False,
        has_sanitizer: bool = False,
    ) -> float:
        """
        计算综合风险分 (0.0 ~ 10.0)

        公式: base = cwe.severity_weight × confidence × 10
        调节:
          - WAF 存在  → ×0.85 (有防护层降低利用概率)
          - 有净化函数 → ×0.70 (有编码输出降低影响)
        """
        base = cwe.severity_weight * confidence * 10.0

        if has_waf:
            base *= 0.85
        if has_sanitizer:
            base *= 0.70

        return min(10.0, max(0.0, round(base, 2)))

    def enrich_results(
        self,
        results: List[Dict[str, Any]],
    ) -> List[EnrichedResult]:
        """
        对扫描结果列表注入 CWE 元数据和风险评分

        Args:
            results: ScanResult.to_dict() 列表

        Returns:
            EnrichedResult 列表 (仅含 vulnerable=True 的结果)
        """
        enriched: List[EnrichedResult] = []

        for r in results:
            if not r.get("vulnerable"):
                continue

            plugin_name = r.get("plugin", "")
            cwe = self.lookup_cwe(plugin_name)

            # 从 extra 中提取信心值
            extra = r.get("extra", {})
            findings = extra.get("findings", [])
            confidence = 0.85  # 默认
            if findings:
                max_conf = max(f.get("confidence", 0) for f in findings)
                if max_conf > 0:
                    confidence = max_conf

            has_waf = extra.get("waf_detected", False)
            sanitizer_status = extra.get("sanitizer_status", {})
            has_sanitizer = sanitizer_status.get("has_sanitizer", False) if sanitizer_status else False

            risk_score = self.calculate_risk_score(
                cwe, confidence, has_waf, has_sanitizer
            )

            enriched.append(EnrichedResult(
                original=r,
                cwe=cwe,
                risk_score=risk_score,
                remediation=cwe.remediation,
            ))

        logger.info(
            "[Analyser] 分析完成 | 漏洞数: %d | CWE 类型: %s",
            len(enriched),
            list(set(e.cwe.cwe_id for e in enriched)),
        )

        return enriched

    def generate_summary(
        self,
        enriched: List[EnrichedResult],
    ) -> Dict[str, Any]:
        """
        生成分析报告摘要

        Returns:
            {
                "total_vulnerabilities": int,
                "max_risk_score": float,
                "by_cwe": {cwe_id: {"count": int, "name": str, "avg_risk": float}},
                "top_remediations": [{"cwe_id": str, "remediation": str}],
            }
        """
        if not enriched:
            return {
                "total_vulnerabilities": 0,
                "max_risk_score": 0.0,
                "by_cwe": {},
                "top_remediations": [],
            }

        # 按 CWE 分组统计
        by_cwe: Dict[str, Dict[str, Any]] = {}
        for e in enriched:
            cid = e.cwe.cwe_id
            if cid not in by_cwe:
                by_cwe[cid] = {
                    "count": 0,
                    "name": e.cwe.name,
                    "total_risk": 0.0,
                    "remediation": e.remediation,
                }
            by_cwe[cid]["count"] += 1
            by_cwe[cid]["total_risk"] += e.risk_score

        # 计算平均风险分
        for cid, info in by_cwe.items():
            info["avg_risk"] = round(info["total_risk"] / info["count"], 2)
            del info["total_risk"]

        # 按风险分排序的修复建议
        top_remediations = sorted(
            [
                {"cwe_id": cid, "name": info["name"], "remediation": info["remediation"]}
                for cid, info in by_cwe.items()
            ],
            key=lambda x: by_cwe[x["cwe_id"]]["avg_risk"],
            reverse=True,
        )

        return {
            "total_vulnerabilities": len(enriched),
            "max_risk_score": max(e.risk_score for e in enriched),
            "by_cwe": {
                cid: {"count": info["count"], "name": info["name"], "avg_risk": info["avg_risk"]}
                for cid, info in by_cwe.items()
            },
            "top_remediations": top_remediations,
        }
