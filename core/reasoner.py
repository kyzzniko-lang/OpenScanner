"""
core/reasoner.py — 漏洞深度研判引擎 (Deep Reasoning Engine)

当 DAST 扫描结果处于不确定状态（Medium/Low 置信度）时，该模块自动介入，
通过多维度概率推理计算出漏洞存在的"信心值" (Confidence Score)。

推理维度:
  1. WAF 阻断特征分析 — 检查 WAF 是否在干扰判定
  2. 响应语义偏差分析 — 对比 Payload 前后响应的结构性变化
  3. 时间侧信道分析   — 检测响应延迟是否存在统计学显著偏差
  4. SAST 净化函数缺失 — 灰盒联动判定目标参数是否被过滤
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from plugins.base import ScanResult, Severity
from core.ai.base import AIResponse

logger = logging.getLogger("openscanner.reasoner")


# ─────────────────────────────────────────────
# 研判信号 (Evidence Signal)
# ─────────────────────────────────────────────

@dataclass
class ReasoningSignal:
    """单个研判维度的信号。

    Attributes:
        dimension: 信号来源维度名称。
        weight: 该维度在最终评分中的归一化权重 [0.0, 1.0]。
        score: 该维度的原始得分 [0.0, 1.0]，1.0 表示强阳性。
        evidence: 人类可读的判定依据。
    """
    dimension: str
    weight: float
    score: float
    evidence: str


@dataclass
class ReasoningVerdict:
    """最终研判结论。

    Attributes:
        confidence: 综合信心值 [0.0, 1.0]。
        severity_override: 如果信心值足够高，建议的等级覆写。
        signals: 所有参与计算的推理信号列表。
        recommendation: 最终建议文本。
    """
    confidence: float
    severity_override: Optional[Severity]
    signals: List[ReasoningSignal] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典，便于 JSON 报告与 UI 渲染。"""
        return {
            "confidence": round(self.confidence, 4),
            "severity_override": str(self.severity_override) if self.severity_override else None,
            "recommendation": self.recommendation,
            "signals": [
                {
                    "dimension": s.dimension,
                    "weight": s.weight,
                    "score": round(s.score, 4),
                    "evidence": s.evidence,
                }
                for s in self.signals
            ],
        }


# ─────────────────────────────────────────────
# 深度研判引擎
# ─────────────────────────────────────────────

class DeepReasoner:
    """漏洞深度研判器。

    在 DAST 发现 Medium/Low 不确定漏洞时自动启动，
    结合 WAF 特征、响应语义变化、SAST 净化状态进行多维概率推理。

    使用方式:
        reasoner = DeepReasoner()
        verdict = reasoner.evaluate(scan_result, context)
    """

    # 各维度默认权重 (可通过构造函数覆盖)
    DEFAULT_WEIGHTS = {
        "waf_interference": 0.15,
        "response_semantic": 0.25,
        "confidence_baseline": 0.15,
        "sanitizer_absence": 0.15,
        "ai_intent": 0.30,
    }

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        """初始化研判器。

        Args:
            weights: 自定义维度权重字典。未提供则使用默认权重。
        """
        self._weights = weights or self.DEFAULT_WEIGHTS.copy()

    def evaluate(
        self,
        result: ScanResult,
        context: Dict[str, Any],
        sanitizer_status: Optional[Dict[str, Any]] = None,
        ai_response: Optional[AIResponse] = None,
    ) -> ReasoningVerdict:
        """对单个扫描结果执行多维度深度研判。

        Args:
            result: DAST 扫描产出的 ScanResult 对象。
            context: 引擎共享上下文 (包含 WAF 信息等)。
            sanitizer_status: SAST 净化函数检测结果 (可选)。

        Returns:
            ReasoningVerdict: 包含信心值、建议覆写等级和推理链的研判结论。
        """
        signals: List[ReasoningSignal] = []

        # ── 维度 1: WAF 阻断干扰分析 ──
        signals.append(self._analyze_waf_interference(result, context))

        # ── 维度 2: 响应语义偏差分析 ──
        signals.append(self._analyze_response_semantics(result))

        # ── 维度 3: 原始置信度基线 ──
        signals.append(self._analyze_confidence_baseline(result))

        # ── 维度 4: SAST 净化函数缺失判定 (可选) ──
        san_signal = self._analyze_sanitizer_absence(sanitizer_status)
        if san_signal:
            signals.append(san_signal)

        # ── 维度 5: AI 意图推理分析 (可选) ──
        ai_signal = self._analyze_ai_intent(ai_response)
        if ai_signal:
            signals.append(ai_signal)

        # ── 加权概率计算 ──
        total_weight = sum(s.weight for s in signals)
        if total_weight == 0:
            total_weight = 1.0

        confidence = sum(s.score * s.weight for s in signals) / total_weight

        # ── 研判结论 ──
        severity_override = None
        recommendation = ""

        if confidence >= 0.85:
            severity_override = Severity.CRITICAL
            recommendation = "高信心漏洞确认：多维度信号强阳性。建议立即修复并进行人工复验。"
        elif confidence >= 0.65:
            severity_override = Severity.HIGH
            recommendation = "中高信心漏洞：建议人工复验确认，优先修复。"
        elif confidence >= 0.45:
            severity_override = Severity.MEDIUM
            recommendation = "信心值中等：具有一定的误报可能，建议人工辅助研判。"
        elif confidence >= 0.25:
            severity_override = Severity.LOW
            recommendation = "信心值偏低：可能为干扰或业务特性导致的误判，已降级为 LOW。"
        else:
            severity_override = Severity.INFO
            recommendation = "极低可信度：疑似完全误报或确切存在净化防护，已降级为 INFO 仅供观测。"

        verdict = ReasoningVerdict(
            confidence=confidence,
            severity_override=severity_override,
            signals=signals,
            recommendation=recommendation,
        )

        logger.info(
            "[Reasoner] %s → confidence=%.2f%% | override=%s",
            result.plugin_name,
            confidence * 100,
            severity_override,
        )

        return verdict

    # ─────────────────────────────────────────
    # 各维度分析器
    # ─────────────────────────────────────────

    def _analyze_waf_interference(
        self, result: ScanResult, context: Dict[str, Any]
    ) -> ReasoningSignal:
        """维度 1: WAF 干扰分析。

        如果目标存在 WAF 且 DAST 仍然报出漏洞，说明 Payload 绕过了 WAF，
        漏洞真实性大幅提升；反之如果没有 WAF，失去了一层佐证。
        """
        weight = self._weights.get("waf_interference", 0.20)
        waf_data = context.get("waf", {})
        waf_detected = result.extra.get("waf_detected", False)

        # 全局 WAF 检查
        if not waf_detected:
            for _, info in waf_data.items():
                if info.get("detected", False):
                    waf_detected = True
                    break

        if waf_detected and result.is_vulnerable:
            return ReasoningSignal(
                dimension="WAF 阻断绕过",
                weight=weight,
                score=0.90,
                evidence="目标存在 WAF 拦截，但 Payload 仍触发漏洞特征 → 高真实性",
            )
        elif not waf_detected and result.is_vulnerable:
            return ReasoningSignal(
                dimension="无 WAF 环境",
                weight=weight,
                score=0.50,
                evidence="目标无 WAF 拦截，漏洞发现缺少 WAF 绕过佐证",
            )
        else:
            return ReasoningSignal(
                dimension="WAF 阻断",
                weight=weight,
                score=0.10,
                evidence="WAF 可能完全拦截了探测 Payload → 低可信",
            )

    def _analyze_response_semantics(self, result: ScanResult) -> ReasoningSignal:
        """维度 2: 响应语义偏差分析。

        从插件报告的 metrics 中提取 Levenshtein/SimHash 差值，
        差值越大表明 TRUE/FALSE 响应差异越显著，漏洞越真实。
        """
        weight = self._weights.get("response_semantic", 0.35)
        findings = result.extra.get("findings", [])

        best_diff = 0.0
        best_confidence = result.extra.get("confidence", 0.0)

        for f in findings:
            metrics = f.get("metrics", {})
            lev = metrics.get("levenshtein", {})
            diff = lev.get("diff", 0.0)
            if diff > best_diff:
                best_diff = diff

        # 差值转换为信心分
        if best_diff >= 0.30:
            score = 0.95
            evidence = f"响应语义差异极显著 (diff={best_diff:.4f}) → 强阳性"
        elif best_diff >= 0.15:
            score = 0.70
            evidence = f"响应语义差异中等 (diff={best_diff:.4f}) → 中等阳性"
        elif best_confidence >= 0.60:
            score = 0.55
            evidence = f"原始插件置信度={best_confidence:.2f}，语义差异数据不足"
        else:
            score = 0.25
            evidence = f"响应语义差异微弱 (diff={best_diff:.4f}) → 疑似误报"

        return ReasoningSignal(
            dimension="响应语义偏差",
            weight=weight,
            score=score,
            evidence=evidence,
        )

    def _analyze_confidence_baseline(self, result: ScanResult) -> ReasoningSignal:
        """维度 3: 原始置信度基线。

        直接继承 DAST 插件报告的原始 confidence 值作为基线参考。
        """
        weight = self._weights.get("confidence_baseline", 0.20)
        findings = result.extra.get("findings", [])

        max_confidence = 0.0
        for f in findings:
            c = f.get("confidence", 0.0)
            if c > max_confidence:
                max_confidence = c

        return ReasoningSignal(
            dimension="插件原始置信度",
            weight=weight,
            score=max_confidence,
            evidence=f"DAST 插件报告的最大置信度: {max_confidence:.2f}",
        )

    def _analyze_sanitizer_absence(
        self, sanitizer_status: Optional[Dict[str, Any]]
    ) -> Optional[ReasoningSignal]:
        """维度 4: SAST 净化函数缺失分析。"""
        if sanitizer_status is None:
            return None

        weight = self._weights.get("sanitizer_absence", 0.25)

        has_sanitizer = sanitizer_status.get("has_sanitizer", False)
        sanitizer_names = sanitizer_status.get("sanitizers_found", [])

        if has_sanitizer:
            return ReasoningSignal(
                dimension="净化函数存在",
                weight=weight,
                score=0.0,
                evidence=f"SAST 在源码中发现净化函数: {', '.join(sanitizer_names)} → 漏洞存在极大概率已被防御，执行研判惩罚",
            )
        else:
            return ReasoningSignal(
                dimension="净化函数缺失",
                weight=weight,
                score=0.95,
                evidence="SAST 确认源码中无任何已知净化/转义函数 → 漏洞利用畅通无阻，极高风险",
            )

    def _analyze_ai_intent(
        self, ai_response: Optional[AIResponse]
    ) -> Optional[ReasoningSignal]:
        """维度 5: AI 意图推理分析。"""
        if ai_response is None or not ai_response.success:
            return None

        weight = self._weights.get("ai_intent", 0.30)

        ai_confidence = ai_response.confidence
        parsed = ai_response.parsed

        # 根据 AI 判定结果生成信号
        is_exploited = parsed.get("is_exploited", parsed.get("is_malicious", False))
        reasoning = parsed.get("reasoning", parsed.get("evidence", "无详细推理"))

        if is_exploited and ai_confidence >= 0.80:
            return ReasoningSignal(
                dimension="AI 深度确认",
                weight=weight,
                score=ai_confidence,
                evidence=f"AI 高信心确认漏洞存在 (confidence={ai_confidence:.2f}): {reasoning}",
            )
        elif is_exploited:
            return ReasoningSignal(
                dimension="AI 倾向确认",
                weight=weight,
                score=ai_confidence * 0.8,
                evidence=f"AI 倾向认为漏洞存在但信心不足 (confidence={ai_confidence:.2f}): {reasoning}",
            )
        else:
            fp_reason = parsed.get("false_positive_reason", reasoning)
            return ReasoningSignal(
                dimension="AI 误报判定",
                weight=weight,
                score=max(0.0, 1.0 - ai_confidence),
                evidence=f"AI 认为此为误报 (confidence={ai_confidence:.2f}): {fp_reason}",
            )
