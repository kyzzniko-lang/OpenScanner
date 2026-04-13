"""
utils/reporter.py — OpenScanner 专业报告引擎

功能:
  • Markdown 格式报告导出（漏洞摘要 / 等级统计 / 技术证据 / 修复建议）
  • JSON 结构化报告导出
  • 性能分析（RPS / 扫描时长 / WAF 命中率）
  • 多语言支持（中文 + 英文标题）
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 修复建议知识库
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_REMEDIATION_DB: Dict[str, Dict[str, str]] = {
    "sqli_scan": {
        "title": "SQL Injection — 修复建议 / Remediation",
        "advice": (
            "1. **使用参数化查询 (Parameterized Queries)** — 永远不要拼接 SQL 字符串。\n"
            "   ```python\n"
            "   # ❌ 危险\n"
            "   cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n"
            "   # ✅ 安全\n"
            "   cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n"
            "   ```\n"
            "2. **使用 ORM 框架** — SQLAlchemy / Django ORM / Prisma 等，自动参数化。\n"
            "3. **输入验证 (Input Validation)** — 白名单过滤，拒绝特殊字符。\n"
            "4. **最小权限原则** — 数据库账号仅授予必需的读写权限。\n"
            "5. **部署 WAF** — 作为纵深防御层，配合 ModSecurity / Cloudflare 规则集。\n"
            "6. **错误处理** — 生产环境禁用详细数据库错误输出，使用统一错误页。"
        ),
    },
    "waf_check": {
        "title": "WAF Detection — 安全建议 / Security Notes",
        "advice": (
            "1. WAF 被检测到表示目标有一定防护能力，但 WAF 不是万能的。\n"
            "2. 确保 WAF 规则集保持更新，覆盖 OWASP Top 10。\n"
            "3. WAF 仅是纵深防御的一层，不应替代安全编码实践。\n"
            "4. 监控 WAF 日志，及时发现扫描和攻击行为。"
        ),
    },
    "xss_scan": {
        "title": "XSS — 修复建议 / Remediation",
        "advice": (
            "1. **输出编码 (Output Encoding)** — 根据上下文转义 HTML / JS / URL。\n"
            "2. **CSP (Content-Security-Policy)** — 配置严格的 CSP 头。\n"
            "3. **HttpOnly Cookie** — 防止 JavaScript 窃取 session。\n"
            "4. **DOM 净化** — 使用 DOMPurify 等库清理用户输入。"
        ),
    },
}

_DEFAULT_REMEDIATION = {
    "title": "General — 安全建议",
    "advice": (
        "1. 参考 OWASP Testing Guide 进行全面安全评估。\n"
        "2. 实施纵深防御策略。\n"
        "3. 定期进行安全扫描和渗透测试。"
    ),
}

# 等级配色与 emoji
_SEV_DISPLAY = {
    "info":     {"emoji": "ℹ️",  "label": "Info",     "bar": "🟦"},
    "low":      {"emoji": "🟢", "label": "Low",      "bar": "🟩"},
    "medium":   {"emoji": "🟡", "label": "Medium",   "bar": "🟨"},
    "high":     {"emoji": "🔴", "label": "High",     "bar": "🟥"},
    "critical": {"emoji": "🟣", "label": "Critical", "bar": "🟪"},
}


class ReportGenerator:
    """
    OpenScanner 专业报告引擎

    Usage:
        gen = ReportGenerator(results, summary, context)
        md = gen.to_markdown()
        js = gen.to_json()
        gen.save_markdown("report.md")
    """

    def __init__(
        self,
        results: List[Dict[str, Any]],
        summary: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        targets: Optional[List[str]] = None,
    ) -> None:
        self._results = results
        self._summary = summary
        self._context = context or {}
        self._targets = targets or []
        self._generated_at = datetime.now()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Markdown 报告
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def to_markdown(self) -> str:
        """生成完整 Markdown 报告"""
        sections = [
            self._md_header(),
            self._md_executive_summary(),
            self._md_severity_stats(),
            self._md_performance_analysis(),
            self._md_waf_analysis(),
            self._md_vulnerability_details(),
            self._md_remediation(),
            self._md_all_results_table(),
            self._md_footer(),
        ]
        return "\n\n".join(s for s in sections if s)

    def _sanitize_path(self, filepath: str) -> Path:
        """安全路径控制：限制报告仅被写入到安全目录"""
        import os
        base_dir = Path.cwd() / "report"
        
        # 强制只选取基本文件名，丢弃所有父级回溯或绝对根目录标记
        safe_name = os.path.basename(filepath)
        if not safe_name:
            safe_name = f"scan_report_{int(time.time())}.txt"
            
        target = (base_dir / safe_name).resolve()
        return target

    def save_markdown(self, filepath: str) -> Path:
        """保存 Markdown 报告到文件"""
        path = self._sanitize_path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_markdown(), encoding="utf-8")
        return path

    # ── Header ──

    def _md_header(self) -> str:
        return (
            "# 🔍 OpenScanner — 安全扫描报告\n"
            "# 🔍 OpenScanner — Security Scan Report\n\n"
            "---\n\n"
            f"| 字段 / Field | 值 / Value |\n"
            f"|---|---|\n"
            f"| 生成时间 / Generated | `{self._generated_at.strftime('%Y-%m-%d %H:%M:%S')}` |\n"
            f"| 扫描器版本 / Scanner | OpenScanner v1.0.0 |\n"
            f"| 目标数 / Targets | {len(self._targets)} |\n"
            f"| 插件数 / Plugins | {self._summary.get('plugins_loaded', 0)} |\n"
        )

    # ── Executive Summary ──

    def _md_executive_summary(self) -> str:
        total = self._summary.get("total_checks", 0)
        vulns = self._summary.get("vulnerabilities_found", 0)
        elapsed = self._summary.get("elapsed_seconds", 0)
        waf = self._summary.get("waf_detected", False)

        risk_level = "✅ LOW" if vulns == 0 else "🔴 HIGH" if vulns > 3 else "🟡 MEDIUM"

        lines = [
            "## 📋 执行概要 / Executive Summary\n",
            f"| 指标 / Metric | 值 / Value |",
            f"|---|---|",
            f"| 总检测数 / Total Checks | **{total}** |",
            f"| 发现漏洞 / Vulnerabilities | **{vulns}** |",
            f"| 风险等级 / Risk Level | **{risk_level}** |",
            f"| 扫描耗时 / Elapsed | **{elapsed}s** |",
            f"| WAF 检测 / WAF Detected | **{'🛡️ Yes' if waf else '❌ No'}** |",
        ]

        # 目标列表
        if self._targets:
            lines.append("\n### 🎯 扫描目标 / Scan Targets\n")
            for i, t in enumerate(self._targets, 1):
                lines.append(f"{i}. `{t}`")

        return "\n".join(lines)

    # ── Severity Stats ──

    def _md_severity_stats(self) -> str:
        by_sev = self._summary.get("by_severity", {})
        if not by_sev:
            return ""

        lines = [
            "## 📊 漏洞等级分布 / Severity Distribution\n",
            "| 等级 / Severity | 数量 / Count | 占比 / Ratio | 分布 / Bar |",
            "|---|---|---|---|",
        ]

        total_vulns = sum(by_sev.values())
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = by_sev.get(sev, 0)
            if count == 0:
                continue
            pct = (count / total_vulns * 100) if total_vulns > 0 else 0
            disp = _SEV_DISPLAY.get(sev, _SEV_DISPLAY["info"])
            bar = disp["bar"] * min(count * 3, 20)
            lines.append(
                f"| {disp['emoji']} **{disp['label']}** | {count} | {pct:.0f}% | {bar} |"
            )

        return "\n".join(lines)

    # ── Performance Analysis ──

    def _md_performance_analysis(self) -> str:
        elapsed = self._summary.get("elapsed_seconds", 0)
        total_checks = self._summary.get("total_checks", 0)
        plugins = self._summary.get("plugins_loaded", 0)

        # 估算 RPS (每个 check 约含多次 HTTP 请求)
        rps = (total_checks / elapsed) if elapsed > 0 else 0

        # WAF 命中统计
        waf_data = self._context.get("waf", {})
        total_targets = max(len(self._targets), 1)
        waf_hits = len(waf_data)
        waf_rate = (waf_hits / total_targets * 100) if total_targets > 0 else 0

        # 插件分布
        by_plugin = self._summary.get("by_plugin", {})

        lines = [
            "## ⚡ 性能分析 / Performance Analysis\n",
            "| 指标 / Metric | 值 / Value |",
            "|---|---|",
            f"| 总扫描时长 / Total Duration | **{elapsed}s** |",
            f"| 检测吞吐量 / Check Throughput | **{rps:.2f} checks/s** |",
            f"| 已加载插件 / Plugins Loaded | **{plugins}** |",
            f"| WAF 命中率 / WAF Hit Rate | **{waf_rate:.0f}%** ({waf_hits}/{total_targets}) |",
        ]

        if by_plugin:
            lines.append(f"\n### 🔌 插件发现分布 / Findings by Plugin\n")
            lines.append("| 插件 / Plugin | 发现数 / Findings |")
            lines.append("|---|---|")
            for name, count in by_plugin.items():
                lines.append(f"| `{name}` | {count} |")

        return "\n".join(lines)

    # ── WAF Analysis ──

    def _md_waf_analysis(self) -> str:
        waf_data = self._context.get("waf", {})
        if not waf_data:
            return ""

        lines = [
            "## 🛡️ WAF 分析 / WAF Analysis\n",
        ]

        all_wafs = set()
        for url, info in waf_data.items():
            wafs = info.get("waf_list", [])
            all_wafs.update(wafs)
            waf_str = ", ".join(wafs) if wafs else "Unknown"
            lines.append(f"- **`{url}`** → {waf_str}")

        if all_wafs:
            lines.append(f"\n> 🛡️ **检测到的 WAF 类型**: {', '.join(sorted(all_wafs))}")

        return "\n".join(lines)

    # ── Vulnerability Details ──

    def _md_vulnerability_details(self) -> str:
        vulns = [r for r in self._results if r.get("vulnerable")]
        if not vulns:
            return (
                "## 🔍 漏洞详情 / Vulnerability Details\n\n"
                "> ✅ **未发现安全漏洞。** No vulnerabilities found.\n"
            )

        lines = [
            "## 🔍 漏洞详情 / Vulnerability Details\n",
        ]

        for i, v in enumerate(vulns, 1):
            sev = v.get("severity", "info")
            disp = _SEV_DISPLAY.get(sev, _SEV_DISPLAY["info"])
            plugin = v.get("plugin", "unknown")
            url = v.get("url", "")
            detail = v.get("detail", "")
            evidence = v.get("evidence", "")
            extra = v.get("extra", {})

            lines.append(f"### {disp['emoji']} 漏洞 #{i}: {plugin}")
            lines.append("")
            lines.append(f"| 字段 | 值 |")
            lines.append(f"|---|---|")
            lines.append(f"| 等级 / Severity | **{disp['label'].upper()}** |")
            lines.append(f"| 插件 / Plugin | `{plugin}` |")
            lines.append(f"| 目标 / Target | `{url}` |")
            lines.append(f"| 详情 / Detail | {detail} |")

            # Findings
            findings = extra.get("findings", [])
            for fi, f in enumerate(findings, 1):
                payload = f.get("payload") or f.get("true_payload", "")
                db_type = f.get("db_type", "")
                ftype = f.get("type", "")
                confidence = f.get("confidence", 0)

                lines.append(f"\n**Finding {fi}:**\n")
                lines.append(f"- **Type**: {ftype}")
                if db_type:
                    lines.append(f"- **Database**: {db_type}")
                if payload:
                    lines.append(f"- **Payload**: `{payload}`")
                lines.append(f"- **Confidence**: {confidence:.0%}")

                # Metrics
                metrics = f.get("metrics", {})
                if metrics:
                    lev = metrics.get("levenshtein", {})
                    sim = metrics.get("simhash", {})
                    if lev:
                        lines.append(
                            f"- **Levenshtein**: base↔true={lev.get('base_true', 0):.4f} "
                            f"base↔false={lev.get('base_false', 0):.4f} "
                            f"diff={lev.get('diff', 0):.4f}"
                        )
                    if sim:
                        lines.append(
                            f"- **SimHash**: base↔true={sim.get('base_true', 0):.4f} "
                            f"base↔false={sim.get('base_false', 0):.4f}"
                        )

            # Evidence block
            if evidence:
                lines.append(f"\n<details><summary>📎 技术证据 / Evidence</summary>\n")
                lines.append(f"```")
                lines.append(evidence)
                lines.append(f"```\n")
                lines.append(f"</details>")

            # ── 视觉取证 (Visual Proof Screenshot) ──
            screenshot_b64 = extra.get("screenshot_b64", "")
            if screenshot_b64:
                lines.append(f"\n**📸 视觉取证 / Visual Proof:**\n")
                lines.append(f"![DOM-XSS 弹窗截图](data:image/png;base64,{screenshot_b64[:60]}...)")
                lines.append(f"\n> ℹ️ 截图为弹窗触发瞬间的浏览器快照，完整图像已嵌入 JSON 报告中。")

            # ── 一键复现 POC 脚本 ──
            poc_script = extra.get("poc_script", "")
            if poc_script:
                lines.append(f"\n<details><summary>🛠️ 一键复现脚本 / Exploit POC</summary>\n")
                lines.append(f"```python")
                lines.append(poc_script)
                lines.append(f"```\n")
                lines.append(f"</details>")

            # ── 代码级修复补丁建议 ──
            patches = extra.get("patch_suggestions", [])
            if patches:
                lines.append(f"\n**🩹 代码级修复建议 / Patch Suggestions:**\n")
                for pi, patch in enumerate(patches, 1):
                    p_file = patch.get("file", "unknown")
                    p_line = patch.get("line", 0)
                    p_conf = patch.get("confidence", 0)
                    p_diff = patch.get("patch_diff", "")
                    p_expl = patch.get("explanation", "")
                    lines.append(f"**Patch {pi}** — `{p_file}` (Line {p_line}) — 置信度 {p_conf:.0%}")
                    lines.append(f"\n```diff")
                    lines.append(p_diff)
                    lines.append(f"```\n")
                    if p_expl:
                        lines.append(f"> 💡 {p_expl}\n")

            lines.append("\n---\n")

        return "\n".join(lines)

    # ── Remediation ──

    def _md_remediation(self) -> str:
        vuln_plugins = set(
            r.get("plugin", "") for r in self._results if r.get("vulnerable")
        )
        if not vuln_plugins:
            return ""

        lines = [
            "## 🛠️ 修复建议 / Remediation\n",
        ]

        for plugin in sorted(vuln_plugins):
            remed = _REMEDIATION_DB.get(plugin, _DEFAULT_REMEDIATION)
            lines.append(f"### {remed['title']}\n")
            lines.append(remed["advice"])
            lines.append("")

        return "\n".join(lines)

    # ── Full Results Table ──

    def _md_all_results_table(self) -> str:
        if not self._results:
            return ""

        lines = [
            "## 📋 完整结果 / All Results\n",
            "| # | Plugin | Target | Status | Severity | Detail |",
            "|---|---|---|---|---|---|",
        ]

        for i, r in enumerate(self._results, 1):
            sev = r.get("severity", "info")
            disp = _SEV_DISPLAY.get(sev, _SEV_DISPLAY["info"])
            status = "🚨" if r.get("vulnerable") else "✅"
            url = r.get("url", "")
            url_short = url[:40] + "..." if len(url) > 43 else url
            detail = r.get("detail", "")
            detail_short = detail[:50] + "..." if len(detail) > 53 else detail
            lines.append(
                f"| {i} | `{r.get('plugin', '')}` | `{url_short}` | {status} "
                f"| {disp['emoji']} {disp['label']} | {detail_short} |"
            )

        return "\n".join(lines)

    # ── Footer ──

    def _md_footer(self) -> str:
        return (
            "---\n\n"
            f"> 📅 报告生成于 / Generated at: {self._generated_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"> 🔍 OpenScanner v1.0.0 — Async Web Vulnerability Scanner\n"
            f"> ⚠️ 本报告仅供授权安全评估使用。/ This report is for authorized security assessments only.\n"
        )

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # JSON 报告
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def to_json(self) -> str:
        """生成 JSON 结构化报告"""
        report = {
            "scanner": "OpenScanner v1.0.0",
            "generated_at": self._generated_at.isoformat(),
            "targets": self._targets,
            "summary": self._summary,
            "performance": self._calc_performance(),
            "waf_analysis": self._context.get("waf", {}),
            "vulnerabilities": [r for r in self._results if r.get("vulnerable")],
            "all_results": self._results,
        }
        return json.dumps(report, indent=2, ensure_ascii=False, default=str)

    def save_json(self, filepath: str) -> Path:
        """保存 JSON 报告到文件"""
        path = self._sanitize_path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), encoding="utf-8")
        return path

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 性能计算
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def _calc_performance(self) -> Dict[str, Any]:
        elapsed = self._summary.get("elapsed_seconds", 0)
        total = self._summary.get("total_checks", 0)
        waf_data = self._context.get("waf", {})
        total_targets = max(len(self._targets), 1)

        return {
            "elapsed_seconds": elapsed,
            "checks_per_second": round(total / elapsed, 2) if elapsed > 0 else 0,
            "total_checks": total,
            "plugins_loaded": self._summary.get("plugins_loaded", 0),
            "waf_hit_rate": round(len(waf_data) / total_targets * 100, 1),
            "waf_hits": len(waf_data),
            "total_targets": total_targets,
        }
