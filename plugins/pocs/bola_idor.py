"""
plugins/pocs/bola_idor.py — 越权访问检测插件 (BOLA / IDOR / 业务逻辑漏洞)

OWASP API Top 1: Broken Object Level Authorization (BOLA)

核心创新:
  普通扫描器只测 SQLi/XSS 等"技术型漏洞"，OpenScanner 独创性地
  扫描"业务逻辑漏洞"——这是企业级安全最头疼、最难自动化的领域。

检测方法 (三层递进):
  ① Endpoint Pattern Discovery (端点模式发现)
     → 自动识别 RESTful 资源路径中的 ID 参数
     → /api/user/123   →  /api/user/{id}
     → /order/456/detail → /order/{id}/detail

  ② IDOR Probe (越权探测)
     → 替换 ID 为其他值 (±1, 0, 999999, 负数)
     → 比对原始响应与探测响应的差异
     → 如果替换 ID 后仍返回有效数据 → 疑似 IDOR

  ③ Authorization Bypass Check (鉴权绕过检查)
     → 移除 Cookie/Authorization Header 后重放
     → 如果无鉴权仍返回相同内容 → 确认未授权访问

  ④ HTTP Method Tampering (HTTP 方法篡改)
     → 对 GET 端点尝试 PUT/DELETE/PATCH
     → 检测是否存在方法级访问控制缺失

检测覆盖:
  • BOLA  (Broken Object Level Authorization)
  • IDOR  (Insecure Direct Object Reference)
  • 水平越权 (Horizontal Privilege Escalation)
  • 未授权访问 (Missing Authentication)
  • HTTP 方法篡改 (Method Tampering)
"""

from __future__ import annotations

import asyncio
import logging
import random
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from core.request import AsyncRequester
from plugins.base import BasePlugin, PluginMeta, ScanResult, Severity

logger = logging.getLogger("openscanner.plugin.bola_idor")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ID 模式识别
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# URL 路径中的 ID 模式
_PATH_ID_PATTERNS = [
    # 纯数字 ID: /user/123
    re.compile(r'/(\d+)(?=/|$)'),
    # UUID: /order/550e8400-e29b-41d4-a716-446655440000
    re.compile(r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$)', re.I),
    # 短 Hash: /file/a1b2c3d4
    re.compile(r'/([0-9a-f]{6,32})(?=/|$)', re.I),
]

# 查询参数中的 ID 模式
_PARAM_ID_NAMES = [
    re.compile(r'^id$', re.I),
    re.compile(r'^user_?id$', re.I),
    re.compile(r'^uid$', re.I),
    re.compile(r'^order_?id$', re.I),
    re.compile(r'^item_?id$', re.I),
    re.compile(r'^account_?id$', re.I),
    re.compile(r'^profile_?id$', re.I),
    re.compile(r'^doc_?id$', re.I),
    re.compile(r'^file_?id$', re.I),
    re.compile(r'^record_?id$', re.I),
    re.compile(r'^obj_?id$', re.I),
    re.compile(r'^pid$', re.I),
    re.compile(r'^rid$', re.I),
    re.compile(r'^tid$', re.I),
    re.compile(r'^no$', re.I),
    re.compile(r'^number$', re.I),
    re.compile(r'^index$', re.I),
]

# IDOR 探测用的替代 ID 值
_PROBE_IDS_NUMERIC = [
    "0", "1", "2", "-1", "999999", "99999999",
    "100", "1000",
]

_PROBE_IDS_STRING = [
    "admin", "test", "guest", "null", "undefined",
    "00000000-0000-0000-0000-000000000000",
]

# 敏感数据指示符 (如果探测响应中包含这些，说明返回了真实数据)
_SENSITIVE_DATA_INDICATORS = [
    r'"email"\s*:\s*"[^"]+@[^"]+"',
    r'"password"',
    r'"phone"\s*:\s*"[^"]+"',
    r'"address"',
    r'"credit_card"',
    r'"ssn"',
    r'"token"\s*:\s*"[^"]+"',
    r'"secret"',
    r'"private"',
    r'"name"\s*:\s*"[^"]+"',
    r'"username"\s*:\s*"[^"]+"',
    r'"balance"',
    r'"amount"',
]

# Soft-404 关键字 (用于识别即使返回 200 OK 也是错误提示的情况)
_SOFT_404_INDICATORS = [
    r"not found", r"不存在", r"未找到", r"无效", r"invalid", r"error",
    r"permission denied", r"拒绝访问", r"没有权限", r"unauthorized",
    r"failed", r"失败", r"找不到", r"does not exist", r"forbidden",
]

# 确认为空的 ID 探测值 (用于构建负基线)
_NEGATIVE_IDS = {
    "numeric": "-9999999",
    "uuid_or_hash": "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "string": "no_exists_resource_name_123",
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 端点分析器
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class EndpointAnalyzer:
    """分析 URL 结构，识别潜在的 IDOR 注入点"""

    @staticmethod
    def find_path_ids(url: str) -> List[Tuple[str, str, int]]:
        """
        查找 URL 路径中的 ID 参数。

        Returns:
            [(original_id, pattern_type, position_in_path), ...]
        """
        parsed = urlparse(url)
        path = parsed.path
        results = []

        for pattern in _PATH_ID_PATTERNS:
            for match in pattern.finditer(path):
                original_id = match.group(1)
                start = match.start(1)
                id_type = "numeric" if original_id.isdigit() else "uuid_or_hash"
                results.append((original_id, id_type, start))

        return results

    @staticmethod
    def find_param_ids(url: str) -> List[Tuple[str, str]]:
        """
        查找查询参数中的 ID 参数。

        Returns:
            [(param_name, param_value), ...]
        """
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        results = []

        for param_name, param_value in params.items():
            for pattern in _PARAM_ID_NAMES:
                if pattern.search(param_name):
                    results.append((param_name, param_value))
                    break
            else:
                # 如果参数名没匹配, 但值是纯数字且合理长度
                if param_value.isdigit() and 1 <= len(param_value) <= 10:
                    results.append((param_name, param_value))

        return results

    @staticmethod
    def replace_path_id(url: str, original_id: str, new_id: str, pos: int = -1) -> str:
        """替换路径中的 ID"""
        parsed = urlparse(url)
        path = parsed.path
        if pos >= 0 and path[pos:pos+len(original_id)] == original_id:
            new_path = path[:pos] + new_id + path[pos+len(original_id):]
        else:
            new_path = parsed.path.replace(f"/{original_id}", f"/{new_id}", 1)
        return urlunparse(parsed._replace(path=new_path))

    @staticmethod
    def replace_param_id(url: str, param_name: str, new_value: str) -> str:
        """替换查询参数中的 ID"""
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        params[param_name] = new_value
        new_query = urlencode(params)
        return urlunparse(parsed._replace(query=new_query))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# BOLA/IDOR 检测插件
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class BolaIdorPlugin(BasePlugin):
    """
    越权访问 (BOLA/IDOR) 检测插件 — OWASP API Security Top 1

    检测策略:
      1. 自动识别 URL 中的资源 ID (路径 + 查询参数)
      2. 用其他 ID 替换探测 → 检查是否返回有效数据
      3. 移除认证信息重放 → 检查未授权访问
      4. HTTP 方法篡改 → 检查方法级访问控制
    """

    meta = PluginMeta(
        name="bola_idor",
        display_name="BOLA / IDOR Scanner",
        description="越权访问和不安全直接对象引用检测 (OWASP API Top 1)",
        severity=Severity.MEDIUM,
        tags=["bola", "idor", "authorization", "owasp-top10", "api"],
        version="1.0.0",
    )

    # 相似度阈值
    SIMILARITY_MATCH_THRESHOLD = 0.82   # 必须与基线足够像 (证明是同类资源)
    SIMILARITY_NEG_THRESHOLD = 0.65     # 必须与负基线足够不像 (证明不是报错页面)
    UNAUTH_SIMILARITY_THRESHOLD = 0.60
    # 内容漂移最小新特征数 (防止公共列表页面因标题/日期差异而误报)
    MIN_NEW_FEATURES_HTML = 5
    MIN_NEW_FEATURES_JSON = 2
    
    def _compute_similarity(self, text1: str, text2: str) -> float:
        """高性能文本相似度计算 (带截断过滤噪音)"""
        from difflib import SequenceMatcher
        # 由于现代页面较大，截断增至 15000 字符，但先去掉标签可增加密度
        clean1 = re.sub(r'<[^>]+>', '', text1[:30000])[:15000]
        clean2 = re.sub(r'<[^>]+>', '', text2[:30000])[:15000]
        return SequenceMatcher(None, clean1, clean2).ratio()

    def _extract_core_features(self, text: str, content_type: str) -> set:
        """从响应中提取核心数据特征集合，用于精准计算内容漂移"""
        import json
        
        # JSON 处理
        if "application/json" in content_type.lower():
            try:
                data = json.loads(text)
                features = set()
                
                def _flatten(obj):
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            features.add(f"K:{k}")
                            _flatten(v)
                    elif isinstance(obj, list):
                        for item in obj:
                            _flatten(item)
                    else:
                        features.add(f"V:{str(obj).strip()}")
                
                _flatten(data)
                return features
            except:
                pass
                
        # HTML/文本处理 
        # 去除 script/style
        text = re.sub(r'<script.*?>.*?</script>', ' ', text, flags=re.IGNORECASE | re.DOTALL)
        text = re.sub(r'<style.*?>.*?</style>', ' ', text, flags=re.IGNORECASE | re.DOTALL)
        # 去除 HTML 标签
        text = re.sub(r'<[^>]+>', ' ', text)
        # 提取单词 (长度>=3)
        words = set(re.findall(r'\b\w{3,}\b', text))
        return words

    async def _get_negative_baseline(
        self,
        requester: AsyncRequester,
        url: str,
        id_type: str,
        original_id: str,
        inject_location: str,
        param_name: Optional[str] = None,
        pos: int = -1,
    ) -> Optional[Tuple[int, str, int, str]]:
        """获取资源不存在时的响应特征 (负基线)"""
        neg_id = _NEGATIVE_IDS.get(id_type, _NEGATIVE_IDS["string"])
        analyzer = EndpointAnalyzer()
        
        if inject_location == "path":
            neg_url = analyzer.replace_path_id(url, original_id, neg_id, pos)
        else:
            neg_url = analyzer.replace_param_id(url, param_name, neg_id)
            
        try:
            resp = await requester.get(neg_url)
            return resp.status_code, resp.text, len(resp.text), resp.headers.get("Content-Type", "")
        except Exception:
            return None

    async def check(
        self,
        url: str,
        requester: AsyncRequester,
        context: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        context = context or {}
        analyzer = EndpointAnalyzer()
        findings: List[Dict[str, Any]] = []

        # ── Step 0: 获取基线响应 ──
        try:
            baseline_resp = await requester.get(url)
            baseline_status = baseline_resp.status_code
            baseline_text = baseline_resp.text
            baseline_length = len(baseline_text)
            baseline_content_type = baseline_resp.headers.get("Content-Type", "")
            baseline_features = self._extract_core_features(baseline_text, baseline_content_type)
        except Exception as exc:
            return self.result(
                url, is_vulnerable=False,
                detail=f"基线请求失败: {exc}",
            )

        # 只对 2xx/3xx 响应进行 IDOR 测试
        if baseline_status >= 400:
            return self.result(
                url, is_vulnerable=False,
                detail=f"基线状态码 {baseline_status}, 跳过 IDOR 测试",
            )

        # ── Step 1: 识别 ID 注入点 ──
        path_ids = analyzer.find_path_ids(url)
        param_ids = analyzer.find_param_ids(url)

        findings: List[Dict[str, Any]] = []
        attempts: List[Dict[str, Any]] = []

        if not path_ids and not param_ids:
            return self.result(
                url, is_vulnerable=False,
                detail="URL 中未发现资源 ID 模式, 跳过 IDOR 测试",
            )

        logger.info(
            "[BOLA] 发现 %d 个路径 ID + %d 个参数 ID: %s",
            len(path_ids), len(param_ids), url,
        )

        # ── Step 2: IDOR 探测 (路径 ID) ── 并行优化 ──
        sem = asyncio.Semaphore(8)  # 限制并发度防止压垂目标

        async def _probe_path(original_id, id_type, pos, probe_id):
            async with sem:
                probe_url = analyzer.replace_path_id(url, original_id, probe_id, pos)
                finding = await self._probe_idor(
                    requester, probe_url, baseline_text,
                    baseline_status, baseline_features, baseline_content_type,
                    neg_baseline,
                    f"路径ID:{original_id}→{probe_id}", "path",
                    attempts
                )
                if finding:
                    findings.append(finding)

        for original_id, id_type, pos in path_ids:
            neg_baseline = await self._get_negative_baseline(
                requester, url, id_type, original_id, "path", pos=pos
            )
            if not neg_baseline: continue
            
            probes = _PROBE_IDS_NUMERIC if id_type == "numeric" else _PROBE_IDS_STRING
            path_tasks = [
                _probe_path(original_id, id_type, pos, pid)
                for pid in probes if pid != original_id
            ]
            await asyncio.gather(*path_tasks)

        # ── Step 3: IDOR 探测 (查询参数 ID) ── 并行优化 ──
        async def _probe_param(param_name, param_value, probe_id, neg_baseline):
            async with sem:
                probe_url = analyzer.replace_param_id(url, param_name, probe_id)
                finding = await self._probe_idor(
                    requester, probe_url, baseline_text,
                    baseline_status, baseline_features, baseline_content_type,
                    neg_baseline,
                    f"参数{param_name}:{param_value}→{probe_id}", "param",
                    attempts
                )
                if finding:
                    findings.append(finding)

        for param_name, param_value in param_ids:
            id_type = "numeric" if param_value.isdigit() else "string"
            neg_baseline = await self._get_negative_baseline(
                requester, url, id_type, param_value, "param", param_name=param_name
            )
            if not neg_baseline: continue

            probes = _PROBE_IDS_NUMERIC if param_value.isdigit() else _PROBE_IDS_STRING
            param_tasks = [
                _probe_param(param_name, param_value, pid, neg_baseline)
                for pid in probes if pid != param_value
            ]
            await asyncio.gather(*param_tasks)

        # ── Step 4: 未授权访问检测 ──
        unauth_finding = await self._check_unauthorized(
            url, requester, baseline_text, baseline_status, baseline_length,
        )
        if unauth_finding:
            findings.append(unauth_finding)

        # ── Step 5: HTTP 方法篡改 ──
        method_finding = await self._check_method_tampering(
            url, requester, baseline_status,
        )
        if method_finding:
            findings.append(method_finding)

        # ── 汇总结果 ──
        if not findings:
            return self.result(
                url, is_vulnerable=False,
                detail="BOLA/IDOR 检测完成, 未发现越权漏洞",
                extra={"attempts": attempts}
            )

        best = max(findings, key=lambda f: f.get("confidence", 0))
        vuln_types = list({f["type"] for f in findings})

        return self.result(
            url,
            is_vulnerable=True,
            detail=(
                f"发现越权访问漏洞 | 类型: {', '.join(vuln_types)} "
                f"| 发现 {len(findings)} 个问题点"
            ),
            evidence=best.get("evidence", ""),
            extra={
                "findings": findings,
                "attempts": attempts,
                "path_ids_found": len(path_ids),
                "param_ids_found": len(param_ids),
            },
        )

    # ── 内部方法 ──────────────────────────────

    async def _probe_idor(
        self,
        requester: AsyncRequester,
        probe_url: str,
        baseline_text: str,
        baseline_status: int,
        baseline_features: set,
        baseline_content_type: str,
        neg_baseline: Tuple[int, str, int, str],
        probe_desc: str,
        inject_location: str,
        attempts: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """三向对比探测是否存在真正的 BOLA/IDOR"""
        neg_status, neg_text, neg_len, neg_content_type = neg_baseline
        try:
            resp = await requester.get(probe_url)
        except Exception:
            return None

        # 1. 基础硬性过滤
        if resp.status_code >= 400 or len(resp.text) < 20:
            return None

        probe_text = resp.text
        probe_len = len(probe_text)

        # 2. Soft-404 关键字过滤 (排除 "Error 200" 误报)
        if any(re.search(pat, probe_text, re.IGNORECASE) for pat in _SOFT_404_INDICATORS):
            return None

        # 3. 三向相似度计算
        sim_to_base = self._compute_similarity(probe_text, baseline_text)
        sim_to_neg = self._compute_similarity(probe_text, neg_text)
        
        # 4. 企业级核心判定逻辑
        # 条件 A: 探测结果必须非常像基线 (说明回显的是同类资源页面)
        pass_base = sim_to_base >= self.SIMILARITY_MATCH_THRESHOLD
        
        # 条件 B: 相对距离算法 (必须比错误页面更像成功页面)
        pass_neg = True
        if sim_to_base <= sim_to_neg * 1.05 and sim_to_base < 0.98: 
            pass_neg = False

        # 条件 C: 关键属性增量分析 (内容漂移检查)
        probe_ct = resp.headers.get("Content-Type", baseline_content_type)
        probe_features = self._extract_core_features(probe_text, probe_ct)
        new_features = probe_features - baseline_features
        # 排除空数据(如 [] {})
        new_features = {f for f in new_features if len(f) > 2 and f not in {"V:None", "V:[]", "V:{}"}}
        # JSON API 接口用较低阈值; HTML 列表页容易因标题/日期差异产生少量新词, 阈值更高
        is_json = "application/json" in probe_ct.lower()
        min_drift = self.MIN_NEW_FEATURES_JSON if is_json else self.MIN_NEW_FEATURES_HTML
        pass_drift = len(new_features) >= min_drift

        # 5. 敏感特征加分
        has_sensitive = any(re.search(pat, probe_text, re.IGNORECASE) for pat in _SENSITIVE_DATA_INDICATORS)

        # 最终判断: (A AND B AND C) OR (A AND 敏感数据)
        if (pass_base and pass_neg and pass_drift) or (pass_base and has_sensitive):
            confidence = 0.95 if has_sensitive else 0.85
            evidence = (
                f"BOLA/IDOR 越权确认 | {probe_desc}\n"
                f"  探测 URL: {probe_url}\n"
                f"  判定依据: 相对距离算法 & 增量特征分析\n"
                f"    - 与正向基线相似度: {sim_to_base:.2%}\n"
                f"    - 与负向基线相似度: {sim_to_neg:.2%}\n"
                f"    - 发现新业务特征数: {len(new_features)}\n"
                f"  敏感特征: {'✅ 命中' if has_sensitive else '❌ 未命中'}"
            )
            logger.warning("[BOLA] %s", evidence)
            
            res = {
                "type": "IDOR",
                "probe": probe_desc,
                "probe_url": probe_url,
                "confidence": confidence,
                "evidence": evidence,
                "metrics": {
                    "sim_base": sim_to_base,
                    "sim_neg": sim_to_neg,
                    "new_features_count": len(new_features)
                }
            }
            attempts.append({
                "payload": probe_url, 
                "type": f"IDOR ({inject_location})", 
                "status": "Vulnerable", 
                "status_code": resp.status_code,
                "info": f"Sim:{sim_to_base:.2%}"
            })
            return res

        attempts.append({
            "payload": probe_url, 
            "type": f"IDOR ({inject_location})", 
            "status": "Safe", 
            "status_code": resp.status_code,
            "info": f"Sim:{sim_to_base:.2%}"
        })
        return None

    async def _check_unauthorized(
        self,
        url: str,
        requester: AsyncRequester,
        baseline_text: str,
        baseline_status: int,
        baseline_length: int,
    ) -> Optional[Dict[str, Any]]:
        """检测未授权访问 — 移除认证信息后是否仍可访问"""
        # 基线请求本身就不携带用户认证信息 (扫描器不登录)，
        # 所以 "移除认证后仍一样" 只是因为页面本身就是公开的，不是漏洞。
        # 只有当 URL 包含典型的需要鉴权的路径模式时才进行此检测。
        _AUTH_PATH_PATTERNS = [
            r'/api/', r'/admin', r'/user', r'/account', r'/profile',
            r'/dashboard', r'/settings', r'/order', r'/payment',
            r'/manage', r'/member', r'/private', r'/internal',
        ]
        parsed_path = urlparse(url).path.lower()
        needs_auth = any(re.search(p, parsed_path) for p in _AUTH_PATH_PATTERNS)
        if not needs_auth:
            return None

        try:
            # 发送不带 Cookie/Auth 的请求
            resp = await requester.get(
                url,
                headers={
                    "Cookie": "",
                    "Authorization": "",
                },
            )
        except Exception:
            return None

        if resp.status_code >= 400:
            return None  # 有权限控制, 正常

        # 分析无认证响应是否包含有效内容
        unauth_text = resp.text
        if len(unauth_text) < 50:
            return None

        from difflib import SequenceMatcher
        similarity = SequenceMatcher(
            None,
            baseline_text[:3000],
            unauth_text[:3000],
        ).ratio()

        # 高相似度且包含敏感数据特征才报告
        if similarity >= self.UNAUTH_SIMILARITY_THRESHOLD:
            has_sensitive = any(
                re.search(pat, unauth_text, re.IGNORECASE)
                for pat in _SENSITIVE_DATA_INDICATORS
            )
            if not has_sensitive:
                return None

            evidence = (
                f"未授权访问确认 | 移除认证后仍返回有效数据\n"
                f"  URL: {url}\n"
                f"  无认证状态码: {resp.status_code}\n"
                f"  与认证响应相似度: {similarity:.2%}\n"
                f"  响应长度: {len(unauth_text)}"
            )
            logger.warning("[BOLA/Unauth] %s", evidence)

            return {
                "type": "Unauthorized Access",
                "probe": "移除 Cookie/Authorization",
                "probe_url": url,
                "status_code": resp.status_code,
                "similarity": round(similarity, 4),
                "confidence": 0.85,
                "evidence": evidence,
            }

        return None

    async def _check_method_tampering(
        self,
        url: str,
        requester: AsyncRequester,
        baseline_status: int,
    ) -> Optional[Dict[str, Any]]:
        """HTTP 方法篡改检测 — 对 GET 端点尝试 PUT/DELETE"""
        # 静态资源和公开内容页面不需要测试方法篡改
        parsed_path = urlparse(url).path.lower()
        _STATIC_EXTS = (
            '.htm', '.html', '.js', '.css', '.png', '.jpg', '.gif',
            '.svg', '.ico', '.pdf', '.doc', '.xls', '.zip', '.txt',
        )
        if parsed_path.endswith(_STATIC_EXTS):
            return None

        # 只对可能是 API 或动态端点的 URL 测试
        _API_INDICATORS = ['/api/', '/v1/', '/v2/', '/rest/', '/graphql']
        is_api = any(ind in parsed_path for ind in _API_INDICATORS)
        has_query = bool(urlparse(url).query)
        if not is_api and not has_query:
            return None

        dangerous_methods = ["PUT", "DELETE", "PATCH"]

        for method in dangerous_methods:
            try:
                resp = await requester.request(method, url)
            except Exception:
                continue

            # 只有真正的 2xx (非重定向) 且响应体有内容才报告
            if 200 <= resp.status_code < 300 and resp.status_code != 405:
                # 过滤: 许多服务器对任何 method 都返回 200 + 相同首页
                if len(resp.text) < 50:
                    continue
                evidence = (
                    f"HTTP 方法篡改 | {method} 请求未被拒绝\n"
                    f"  URL: {url}\n"
                    f"  {method} 状态码: {resp.status_code}\n"
                    f"  GET 基线状态码: {baseline_status}\n"
                    f"  风险: 可能允许未授权的数据修改/删除"
                )
                logger.warning("[BOLA/Method] %s", evidence)

                return {
                    "type": "Method Tampering",
                    "probe": f"{method} 方法未被拒绝",
                    "probe_url": url,
                    "method": method,
                    "status_code": resp.status_code,
                    "confidence": 0.70,
                    "evidence": evidence,
                }

        return None
