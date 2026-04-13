"""
core/spider.py — OpenScanner 异步爬虫组件 + 自主业务流发现 (ABFD)

基于 BeautifulSoup 解析 HTML，支持广度优先 (BFS) 队列，
提取 <a>, <form>, <area> 等包含有效路径的资源。
为防止扫描越界，默认受到 Same-Origin 同源保护约束。

性能特性:
  • collections.deque 双端队列 — O(1) 弹出，万级链接无卡顿
  • URL 规范化 — 参数字典序排序去重，杜绝冗余发包
  • 最大收集数上限 — 防止无限膨胀导致 OOM

企业级增强 (ABFD):
  • Functional Clustering — 将 /user/1, /user/2 归为 /user/{id} 模板
  • Form Action Discovery — 提取 <form> 的 method/action 供 POST 测试
  • LogicalSiteMap — 生成结构化站点地图，供 BOLA/IDOR 插件消费
  • State Tracking — 识别改变 Cookie/Session 的端点
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

from bs4 import BeautifulSoup

from core.request import AsyncRequester

logger = logging.getLogger("openscanner.spider")

# 单个种子的绝对收集上限，防止巨型站点撑爆内存
_MAX_URLS_PER_SEED = 500
# 跨种子的全局绝对收集上限，防止被无尽链接拖垮扫描器
_MAX_GLOBAL_URLS = 5_000


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 业务流数据结构
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class FormEndpoint:
    """表单端点信息"""
    action: str          # 表单提交目标
    method: str          # GET/POST
    inputs: List[Dict[str, str]] = field(default_factory=list)  # 输入字段
    page_url: str = ""   # 所在页面

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "method": self.method,
            "inputs": self.inputs,
            "page_url": self.page_url,
        }


@dataclass
class EndpointCluster:
    """URL 功能聚类"""
    template: str          # /api/user/{id}
    urls: List[str] = field(default_factory=list)
    id_values: List[str] = field(default_factory=list)
    method: str = "GET"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "template": self.template,
            "url_count": len(self.urls),
            "sample_urls": self.urls[:5],
            "id_values": self.id_values[:10],
        }


@dataclass
class LogicalSiteMap:
    """
    逻辑站点地图 — 供安全插件消费的结构化站点信息

    包含:
      • endpoint_clusters: URL 功能聚类 (自动识别 RESTful 模式)
      • form_endpoints:    表单端点 (POST 测试面)
      • state_endpoints:   改变状态的端点 (登录/注销/修改)
      • api_endpoints:     API 端点 (JSON 响应)
    """
    endpoint_clusters: List[EndpointCluster] = field(default_factory=list)
    form_endpoints: List[FormEndpoint] = field(default_factory=list)
    state_endpoints: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    total_urls: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_urls": self.total_urls,
            "clusters": [c.to_dict() for c in self.endpoint_clusters],
            "forms": [f.to_dict() for f in self.form_endpoints],
            "state_endpoints": self.state_endpoints[:20],
            "api_endpoints": self.api_endpoints[:20],
        }


class SpiderEngine:
    """
    轻量级异步爬虫抓取器。

    用于在扫描前自动扩充目标探测面，发现隐藏链接。
    """

    def __init__(self, requester: AsyncRequester, max_depth: int = 1):
        """
        初始化 Spider 引擎。

        Args:
            requester: 复用主引擎并发与防 OOM 功能的 AsyncRequester
            max_depth: 爬行深度，0 表示无操作，1 表示探测本页面的下级节点
        """
        self.requester = requester
        self.max_depth = max_depth
        self._visited: Set[str] = set()
        self._form_endpoints: List[FormEndpoint] = []

    async def crawl_all(self, seed_urls: List[str]) -> List[str]:
        """
        全量爬取给定的种子 URL 并聚合结果。

        Args:
            seed_urls: 初始扫描目标列表

        Returns:
            去重并包含种子节点在内的全域目标 URL 列表
        """
        if self.max_depth <= 0:
            return seed_urls

        logger.info("[Spider] 启动爬虫，深度: %d，种子数: %d", self.max_depth, len(seed_urls))

        all_targets: Set[str] = set()
        for seed in seed_urls:
            all_targets.add(self._normalize_url(seed))

        for seed in seed_urls:
            if len(all_targets) >= _MAX_GLOBAL_URLS:
                logger.warning("[Spider] 达到全局总收集上限 %d，中止爬虫扩展", _MAX_GLOBAL_URLS)
                break
            discovered = await self._bfs_crawl(seed, global_pool=all_targets)
            all_targets.update(discovered)

        # 稳定去重排序
        result = sorted(all_targets)

        # 将表单端点合成为带参数的可测试 URL 并合入目标集
        form_urls = self.synthesize_form_urls()
        if form_urls:
            before = len(result)
            merged = set(result)
            merged.update(form_urls)
            result = sorted(merged)
            logger.info(
                "[Spider] 表单注入点合成: %d 个表单 → %d 个新目标 URL",
                len(form_urls), len(result) - before,
            )

        # 从 URL 路径中提取数字 ID 段，合成为查询参数注入测试 URL
        path_id_urls = self.synthesize_path_id_urls(result)
        if path_id_urls:
            before = len(result)
            merged = set(result)
            merged.update(path_id_urls)
            result = sorted(merged)
            logger.info(
                "[Spider] 路径 ID 注入点合成: %d 个路径参数 → %d 个新目标 URL",
                len(path_id_urls), len(result) - before,
            )

        logger.info("[Spider] 爬取结束，扩展后总目标数: %d", len(result))
        return result

    def synthesize_form_urls(self) -> List[str]:
        """
        将爬虫发现的表单端点合成为带查询参数的可测试 URL。

        对每个 FormEndpoint，提取其 input 字段名称作为参数，
        填充默认测试值，拼接到 action URL 上，使 SQLi / XSS 等
        插件能够识别并测试这些注入点。

        Returns:
            合成后的 URL 列表（已去重）
        """
        seen: Set[str] = set()
        urls: List[str] = []

        for form in self._form_endpoints:
            if not form.inputs:
                continue

            # 提取表单中有 name 属性的输入字段
            params: Dict[str, str] = {}
            for inp in form.inputs:
                name = inp.get("name", "").strip()
                if not name:
                    continue
                # 使用表单预设的 value，无则填充默认测试值
                value = inp.get("value", "").strip() or "1"
                params[name] = value

            if not params:
                continue

            # 将参数拼接到 action URL 上
            parsed = urlparse(form.action)
            query = urlencode(sorted(params.items()))
            synthesized = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, query, "",
            ))

            if synthesized not in seen:
                seen.add(synthesized)
                urls.append(synthesized)
                logger.debug(
                    "[Spider] 表单合成: %s %s → %s (参数: %s)",
                    form.method, form.action, synthesized, list(params.keys()),
                )

        return urls

    @staticmethod
    def synthesize_path_id_urls(urls: List[str]) -> List[str]:
        """
        从 URL 路径中提取数字 ID 段，合成为带查询参数的注入测试 URL。

        例如:
            https://example.com/297/list.htm        → ?id=297
            https://example.com/user/12345/profile   → ?id=12345
            https://example.com/2026/0413/c127a95622/page.htm
                → 排除日期段 2026/0413，提取 c127a95622 → ?id=c127a95622

        对于已经有查询参数的 URL 则跳过（它们已经可以被插件测试）。
        """
        # 匹配业务 ID: 纯数字 / 包含字母和数字的混合 ID (如 c127a95622)
        _BIZ_ID = re.compile(
            r'^(?:\d+|[a-zA-Z]\d+[a-zA-Z0-9]*|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$',
            re.IGNORECASE,
        )
        # 匹配日期段: 4位年份
        _YEAR = re.compile(r'^(19|20)\d{2}$')
        # 匹配日期段: 2位月/日 (01-31)
        _MONTH_DAY = re.compile(r'^(0[1-9]|1[0-2]|[12]\d|3[01])$')

        seen: Set[str] = set()
        result: List[str] = []

        for url in urls:
            parsed = urlparse(url)
            # 已经有查询参数的 URL 跳过（插件能直接测试）
            if parsed.query:
                continue

            segments = [s for s in parsed.path.strip("/").split("/") if s]
            if not segments:
                continue

            # 识别并排除日期段序列 (如 /2026/0413/ 或 /2026/04/13/)
            date_indices: Set[int] = set()
            for i, seg in enumerate(segments):
                if _YEAR.match(seg):
                    date_indices.add(i)
                    # 紧跟年份后面的 2-4 位数字也视为日期组成部分
                    for j in range(i + 1, min(i + 3, len(segments))):
                        if _MONTH_DAY.match(segments[j]) or re.fullmatch(r'\d{4}', segments[j]):
                            date_indices.add(j)
                        else:
                            break

            # 提取非日期的 ID 段
            id_segments: List[tuple[int, str]] = []
            for i, seg in enumerate(segments):
                if i in date_indices:
                    continue
                # 纯数字（非日期）
                if re.fullmatch(r'\d+', seg):
                    id_segments.append((i, seg))
                # 混合 ID (如 c132a90603) — 字母开头 + 数字混合，至少含一个数字
                elif _BIZ_ID.match(seg) and not seg.endswith(('.htm', '.html', '.jsp', '.php', '.asp')):
                    id_segments.append((i, seg))

            if not id_segments:
                continue

            # 为每个 ID 段合成一个注入测试 URL
            base_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, "", "",
            ))
            for _idx, id_value in id_segments:
                synthesized = f"{base_url}?id={id_value}"
                if synthesized not in seen:
                    seen.add(synthesized)
                    result.append(synthesized)
                    logger.debug(
                        "[Spider] 路径 ID 合成: %s → ?id=%s", url, id_value,
                    )

        return result

    @property
    def form_endpoints(self) -> List[FormEndpoint]:
        """公开访问已发现的表单端点列表"""
        return list(self._form_endpoints)

    async def _bfs_crawl(self, start_url: str, global_pool: Set[str]) -> Set[str]:
        """对单种子进行 BFS 限定范围爬取（使用 deque 实现 O(1) 弹出）"""
        normalized_start = self._normalize_url(start_url)
        queue: deque[tuple[str, int]] = deque([(start_url, 0)])
        extracted: Set[str] = {normalized_start}
        self._visited.add(normalized_start)

        # 提取基准域名以保证同源约束
        base_domain = urlparse(start_url).netloc
        if not base_domain:
            return extracted

        while queue:
            current_url, depth = queue.popleft()  # O(1) 双端队列弹出

            # 达到深度上限则不再解析下一层
            if depth >= self.max_depth:
                continue

            # 检查收集上限
            if len(extracted) >= _MAX_URLS_PER_SEED:
                logger.warning("[Spider] 达到单种子收集上限 %d，停止扩展", _MAX_URLS_PER_SEED)
                break
            
            if len(global_pool) + len(extracted) >= _MAX_GLOBAL_URLS:
                logger.warning("[Spider] 触碰全局收集上限基线，强制熔断当前种子扩展")
                break

            try:
                resp = await self.requester.get(current_url)
                # 不是 HTML 就跳过
                content_type = resp.headers.get("content-type", "").lower()
                if "text/html" not in content_type:
                    continue
                
                # 提取表单与链接（将 CPU 密集型操作剥离至独立线程池避免阻塞 AsyncIO）
                links = await asyncio.to_thread(self._extract_links, current_url, resp.text, base_domain)
                forms = await asyncio.to_thread(self._extract_forms, current_url, resp.text)
                
                if forms:
                    self._form_endpoints.extend(forms)

                for link in links:
                    normalized = self._normalize_url(link)
                    if normalized not in self._visited:
                        self._visited.add(normalized)
                        extracted.add(normalized)
                        queue.append((link, depth + 1))

            except Exception as exc:
                if depth == 0:
                    logger.warning("[Spider] 初始种子 URL '%s' 无法访问: %s", current_url, exc)
                else:
                    logger.debug("[Spider] 下级页面 '%s' 爬取失败: %s", current_url, exc)

        return extracted

    @staticmethod
    def _normalize_url(url: str) -> str:
        """
        URL 规范化：将查询参数按字典序排序，去除 fragment。

        这防止了 ?a=1&b=2 和 ?b=2&a=1 被视为不同 URL 而导致的重复扫描。
        """
        parsed = urlparse(url)
        # 解析查询参数并按 key 排序
        params = parse_qsl(parsed.query, keep_blank_values=True)
        sorted_query = urlencode(sorted(params, key=lambda x: x[0]))
        # 去掉 fragment
        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            sorted_query,
            "",  # 清除 fragment
        ))
        return normalized

    def _extract_links(self, page_url: str, html: str, allowed_domain: str) -> Set[str]:
        """
        解析并过滤 HTML 中的端点。

        Args:
            page_url: 解析基地址，用于补全相对路径
            html: HTML 文本内容
            allowed_domain: 白名单域名 (Host:Port)
        """
        discovered: Set[str] = set()
        soup = BeautifulSoup(html, "html.parser")

        # 扫描 <a> 标签
        for a_tag in soup.find_all("a", href=True):
            link = a_tag["href"].strip()
            self._process_raw_link(page_url, link, allowed_domain, discovered)

        # 扫描 <form> 动作 (GET端点对于弱点扫描极具价值)
        for form_tag in soup.find_all("form", action=True):
            action = form_tag["action"].strip()
            self._process_raw_link(page_url, action, allowed_domain, discovered)

        # 扫描 <area> 热区
        for area_tag in soup.find_all("area", href=True):
            href = area_tag["href"].strip()
            self._process_raw_link(page_url, href, allowed_domain, discovered)

        return discovered

    def _process_raw_link(self, base: str, href: str, allowed_domain: str, output_set: Set[str]) -> None:
        """剥杂、清洗并进行越界审计"""
        # 忽略空锚点、JS执行或邮件链接
        if href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return

        # 拼接修复相对路径
        try:
            absolute_url = urljoin(base, href)
            parsed = urlparse(absolute_url)

            # 安全检查: Scheme 必须为 HTTP/S，并且满足 Same-Origin policy
            if parsed.scheme not in ("http", "https"):
                return
            if parsed.netloc != allowed_domain:
                return

            # 我们清理掉末尾的 hash anchor 防止冗余爬取
            clean_url = absolute_url.split("#")[0]
            output_set.add(clean_url)

        except Exception:
            pass

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 自主业务流发现 (ABFD) — 企业级增强
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def _extract_forms(self, page_url: str, html: str) -> List[FormEndpoint]:
        """
        深度提取 HTML 中的表单端点及其输入字段。

        Returns:
            FormEndpoint 列表，包含 action/method/inputs 信息
        """
        forms: List[FormEndpoint] = []
        soup = BeautifulSoup(html, "html.parser")

        for form_tag in soup.find_all("form"):
            action = form_tag.get("action", "").strip()
            method = form_tag.get("method", "GET").upper()

            if not action:
                action = page_url  # 无 action 时默认提交到当前页

            # 补全相对路径
            abs_action = urljoin(page_url, action)

            # 提取所有输入字段
            inputs: List[Dict[str, str]] = []
            for inp in form_tag.find_all(["input", "select", "textarea"]):
                inp_name = inp.get("name", "")
                inp_type = inp.get("type", "text")
                inp_value = inp.get("value", "")
                if inp_name:
                    inputs.append({
                        "name": inp_name,
                        "type": inp_type,
                        "value": inp_value,
                    })

            forms.append(FormEndpoint(
                action=abs_action,
                method=method,
                inputs=inputs,
                page_url=page_url,
            ))

        return forms

    @staticmethod
    def cluster_urls(urls: List[str]) -> List[EndpointCluster]:
        """
        URL 功能聚类 — 将结构相似的 URL 归类为模板。

        例如:
            /api/user/1, /api/user/2, /api/user/100
            → 聚类为 /api/user/{id} (包含 id_values=[1,2,100])

        算法:
            1. 解析每个 URL 的路径段
            2. 将纯数字/UUID 段替换为 {id} 占位符
            3. 按模板分组
        """
        # 模式: 纯数字 / UUID / 短哈希
        _ID_PATTERN = re.compile(
            r'^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{6,32})$',
            re.IGNORECASE,
        )

        template_map: Dict[str, EndpointCluster] = {}

        for url in urls:
            parsed = urlparse(url)
            segments = parsed.path.strip("/").split("/")

            template_segments = []
            id_values = []

            for seg in segments:
                if _ID_PATTERN.match(seg):
                    template_segments.append("{id}")
                    id_values.append(seg)
                else:
                    template_segments.append(seg)

            template = "/" + "/".join(template_segments) if template_segments else "/"

            base = f"{parsed.scheme}://{parsed.netloc}"
            full_template = f"{base}{template}"

            if full_template not in template_map:
                template_map[full_template] = EndpointCluster(
                    template=full_template,
                )

            cluster = template_map[full_template]
            cluster.urls.append(url)
            cluster.id_values.extend(id_values)

        # 只返回有多个 URL 或包含 {id} 的聚类 (这些才是有价值的)
        return [
            c for c in template_map.values()
            if len(c.urls) > 1 or "{id}" in c.template
        ]

    @staticmethod
    def _detect_state_endpoints(urls: List[str]) -> List[str]:
        """
        识别可能改变应用状态的端点 (登录/注销/修改/删除)。

        基于路径和参数名模式匹配。
        """
        state_patterns = [
            re.compile(r'(login|signin|sign_in)', re.I),
            re.compile(r'(logout|signout|sign_out)', re.I),
            re.compile(r'(register|signup|sign_up)', re.I),
            re.compile(r'(delete|remove)', re.I),
            re.compile(r'(update|modify|edit)', re.I),
            re.compile(r'(create|add|new)', re.I),
            re.compile(r'(reset|change).*?(password|pwd)', re.I),
            re.compile(r'(admin|manage|dashboard)', re.I),
            re.compile(r'(upload|import)', re.I),
            re.compile(r'(checkout|payment|pay)', re.I),
        ]

        results = []
        for url in urls:
            parsed = urlparse(url)
            path = parsed.path.lower()
            if any(pat.search(path) for pat in state_patterns):
                results.append(url)

        return results

    @staticmethod
    def _detect_api_endpoints(urls: List[str]) -> List[str]:
        """识别可能的 API 端点 (基于路径模式)"""
        api_patterns = [
            re.compile(r'/api/', re.I),
            re.compile(r'/v\d+/', re.I),          # /v1/, /v2/
            re.compile(r'/rest/', re.I),
            re.compile(r'/graphql', re.I),
            re.compile(r'\.json$', re.I),
            re.compile(r'\.xml$', re.I),
        ]
        results = []
        for url in urls:
            parsed = urlparse(url)
            if any(pat.search(parsed.path) for pat in api_patterns):
                results.append(url)
        return results

    @staticmethod
    def filter_targets_by_intensity(
        urls: List[str],
        intensity: str = "light",
    ) -> List[str]:
        """
        按扫描强度过滤目标 URL 列表。

        Args:
            urls:       爬虫扩展后的完整 URL 列表
            intensity:  扫描强度 — "light" | "medium" | "full"

        Returns:
            过滤后的 URL 列表

        策略:
            light:  只保留有查询参数的 URL，并对同模板聚类只取 1 个代表;
                    同一 host 最多保留 3 个目标（取参数最多样的代表）
            medium: 有参数的 URL 聚类取 3 个代表 + 状态端点 + API 端点
            full:   不做任何过滤，返回全部
        """
        if intensity == "full":
            return urls

        max_per_cluster = 1 if intensity == "light" else 3
        result_set: Set[str] = set()

        # 1. 筛选有查询参数的 URL（表单合成 / 路径 ID 合成 / 原生带参数的）
        parameterized = [u for u in urls if urlparse(u).query]

        # 2. 对有参数的 URL 做聚类去重 — 同模板只保留有限代表
        #    例如 /297/list.htm?id=297 和 /298/list.htm?id=298 属于同一模板
        clusters = SpiderEngine.cluster_urls(parameterized)
        clustered_urls: Set[str] = set()
        for cluster in clusters:
            for sample_url in cluster.urls[:max_per_cluster]:
                result_set.add(sample_url)
                clustered_urls.add(sample_url)

        # 3. 未被聚类命中的有参数 URL 直接保留（独特端点，如搜索接口）
        for url in parameterized:
            if url not in clustered_urls:
                # 检查是否已被某个聚类包含
                in_cluster = any(url in c.urls for c in clusters)
                if not in_cluster:
                    result_set.add(url)

        # 4. medium 模式额外保留状态端点和 API 端点（即使无参数）
        if intensity == "medium":
            state_eps = SpiderEngine._detect_state_endpoints(urls)
            api_eps = SpiderEngine._detect_api_endpoints(urls)
            result_set.update(state_eps)
            result_set.update(api_eps)

        # 5. light 模式下做二次精简: 按 host 限制最大目标数（防止单站点刷屏）
        if intensity == "light" and len(result_set) > 3:
            host_buckets: Dict[str, List[str]] = {}
            for u in result_set:
                h = urlparse(u).netloc
                host_buckets.setdefault(h, []).append(u)
            trimmed: Set[str] = set()
            for host, host_urls in host_buckets.items():
                # 优先选参数名不同的 URL（测试不同注入点），最多 3 个
                seen_params: Set[str] = set()
                for u in sorted(host_urls):
                    param_key = frozenset(dict(parse_qsl(urlparse(u).query)).keys())
                    param_str = str(param_key)
                    if param_str not in seen_params:
                        seen_params.add(param_str)
                        trimmed.add(u)
                    if len(trimmed) >= 3 and len(host_buckets) == 1:
                        break
            result_set = trimmed

        filtered = sorted(result_set)
        logger.info(
            "[Spider] 扫描强度 [%s]: %d → %d 个目标 (过滤 %d 个)",
            intensity, len(urls), len(filtered), len(urls) - len(filtered),
        )
        return filtered

    async def build_site_map(
        self,
        urls: List[str],
    ) -> LogicalSiteMap:
        """
        构建逻辑站点地图 — 企业级 ABFD 核心接口。

        Args:
            urls:       已爬取的 URL 列表

        Returns:
            LogicalSiteMap 结构化站点信息
        """
        site_map = LogicalSiteMap(total_urls=len(urls))

        # 1. URL 功能聚类
        site_map.endpoint_clusters = self.cluster_urls(urls)
        logger.info(
            "[ABFD] 功能聚类: %d 个模板 (含 {id} 占位符)",
            len(site_map.endpoint_clusters),
        )

        # 2. 表单端点发现 (从缓存的 Form 中直接获取)
        site_map.form_endpoints.extend(self._form_endpoints)
        if self._form_endpoints:
            logger.info(
                "[ABFD] 表单发现: %d 个表单端点", len(site_map.form_endpoints),
            )

        # 3. 状态端点识别
        site_map.state_endpoints = self._detect_state_endpoints(urls)
        logger.info(
            "[ABFD] 状态端点: %d 个 (登录/注销/修改等)",
            len(site_map.state_endpoints),
        )

        # 4. API 端点识别
        site_map.api_endpoints = self._detect_api_endpoints(urls)
        logger.info(
            "[ABFD] API 端点: %d 个", len(site_map.api_endpoints),
        )

        return site_map

