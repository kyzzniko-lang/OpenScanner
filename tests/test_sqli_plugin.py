"""
tests/test_sqli_plugin.py — SQLi 插件单元测试

验证内容：
  1. Levenshtein 编辑距离算法正确性
  2. SimHash 模糊哈希算法正确性
  3. 报错注入特征码匹配
  4. 插件加载与元信息
  5. WAF 联动逻辑
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from plugins.pocs.sqli_scan import (
    SqliScanPlugin,
    levenshtein_distance,
    similarity_ratio,
    SimHash,
    _DB_ERROR_SIGNATURES,
    _extract_params,
    _inject_param,
    _sql_safe_encode_payload,
    _strip_dynamic_content,
    _strip_html_tags,
    _discover_injection_points,
    InjectionPoint,
    mutate_payload,
    ResponseFingerprint,
    _TIME_BASED_PAYLOADS,
)
from plugins.base import Severity
import re


def test_levenshtein():
    """验证 Levenshtein 编辑距离"""
    assert levenshtein_distance("", "") == 0
    assert levenshtein_distance("abc", "abc") == 0
    assert levenshtein_distance("abc", "") == 3
    assert levenshtein_distance("kitten", "sitting") == 3
    assert levenshtein_distance("saturday", "sunday") == 3
    print("✅ Test 1 PASSED: Levenshtein 编辑距离算法正确")


def test_similarity_ratio():
    """验证相似度计算"""
    assert similarity_ratio("hello", "hello") == 1.0
    assert similarity_ratio("", "") == 1.0

    sim = similarity_ratio("hello world", "hello world!")
    assert 0.9 < sim < 1.0, f"Expected ~0.92, got {sim}"

    sim_diff = similarity_ratio("aaaa", "zzzz")
    assert sim_diff < 0.5, f"Expected low similarity, got {sim_diff}"
    print(f"✅ Test 2 PASSED: similarity_ratio 正确 (similar={sim:.4f}, diff={sim_diff:.4f})")


def test_simhash():
    """验证 SimHash 模糊哈希"""
    text1 = "The quick brown fox jumps over the lazy dog"
    text2 = "The quick brown fox jumps over the lazy cat"
    text3 = "Completely different text about SQL injection vulnerabilities"

    h1 = SimHash(text1)
    h2 = SimHash(text2)
    h3 = SimHash(text3)

    sim_similar = h1.similarity(h2)
    sim_different = h1.similarity(h3)

    assert sim_similar > sim_different, (
        f"Similar texts should have higher SimHash similarity: "
        f"{sim_similar:.4f} vs {sim_different:.4f}"
    )

    hamming = h1.hamming_distance(h2)
    assert 0 <= hamming <= 64
    print(
        f"✅ Test 3 PASSED: SimHash 正确 | "
        f"similar={sim_similar:.4f}, different={sim_different:.4f}, "
        f"hamming(fox↔cat)={hamming}"
    )


def test_error_signatures():
    """验证数据库错误特征码匹配"""
    test_cases = [
        (
            "You have an error in your SQL syntax; check the manual that "
            "corresponds to your MySQL server version",
            "MySQL",
        ),
        ("ERROR:  syntax error at or near \"SELECT\"", "PostgreSQL"),
        ("Unclosed quotation mark after the character string", "MSSQL"),
        ("ORA-01756: quoted string not properly terminated", "Oracle"),
        ("Warning: SQLite3::query(): Unable to prepare statement", "SQLite"),
    ]

    for response_text, expected_db in test_cases:
        matched = False
        for sig in _DB_ERROR_SIGNATURES:
            if sig.db_type != expected_db:
                continue
            for pattern in sig.patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    matched = True
                    break
            if matched:
                break
        assert matched, f"未匹配到 {expected_db} 错误: {response_text[:60]}"

    print(f"✅ Test 4 PASSED: 数据库错误特征码匹配正确 ({len(test_cases)} 个数据库)")


def test_url_utilities():
    """验证 URL 工具函数 — 参数保留、优先级合并、SQL 安全编码"""

    # ── 基础提取 ──
    url = "https://example.com/page?id=1&name=test"
    params = _extract_params(url)
    assert params == {"id": "1", "name": "test"}, f"Got: {params}"

    # ── 全量参数保留 ──
    # 注入 id 参数时，name 参数必须保留
    injected = _inject_param(url, "id", "' OR 1=1")
    assert "name=test" in injected, f"name 参数丢失: {injected}"

    # ── DVWA 场景: Submit 参数保留 ──
    dvwa_url = "http://dvwa/vuln.php?id=1&Submit=Submit"
    injected_dvwa = _inject_param(dvwa_url, "id", "' OR 1=1#")
    assert "Submit=Submit" in injected_dvwa, (
        f"Submit 参数在 # payload 后丢失: {injected_dvwa}"
    )
    assert "#" not in injected_dvwa.split("?", 1)[-1].split("%23")[0].rpartition("&")[2], (
        f"裸 # 未被编码为 %23: {injected_dvwa}"
    )

    # ── business_params 优先级覆盖 ──
    url_with_submit = "http://target.com/page?id=1&Submit=Old"
    injected_override = _inject_param(
        url_with_submit, "id", "' AND 1=1",
        context_params={"Submit": "Submit"}
    )
    assert "Submit=Submit" in injected_override, (
        f"business_params 未覆盖 URL 同名参数: {injected_override}"
    )
    assert "Submit=Old" not in injected_override, (
        f"URL 原始值未被 business_params 覆盖: {injected_override}"
    )

    # ── SQL 注释符 -- 安全化 ──
    injected_comment = _inject_param(url, "id", "' AND 1=1--")
    # -- 后应有空格编码 (%20 或 +)
    query_part = injected_comment.split("?", 1)[-1]
    assert "--%20" in query_part or "--+" in query_part, (
        f"SQL 注释符 -- 后未补空格: {injected_comment}"
    )

    # ── _sql_safe_encode_payload 单元测试 ──
    # # 保留原样（由 _sql_safe_urlencode 后续处理）
    assert _sql_safe_encode_payload("' OR 1=1#") == "' OR 1=1#"
    # -- 末尾追加真实空格
    assert _sql_safe_encode_payload("' AND 1=1--").endswith("-- ")

    print(f"✅ Test 5 PASSED: URL 工具函数正确 (参数保留 + 优先级合并 + 安全编码)")


def test_dynamic_content_strip():
    """验证动态内容去除"""
    html = '''
    <input name="csrf_token" value="abc123xyz"/>
    <span>Time: 1718000000</span>
    <div data-session="a1b2c3d4e5f6"></div>
    <p>550e8400-e29b-41d4-a716-446655440000</p>
    <p>Static content remains</p>
    '''
    stripped = _strip_dynamic_content(html)
    assert "abc123xyz" not in stripped or "csrf" not in stripped
    assert "Static content remains" in stripped
    print("✅ Test 6 PASSED: 动态内容去除正确")


def test_plugin_meta():
    """验证插件元信息"""
    plugin = SqliScanPlugin()
    assert plugin.meta.name == "sqli_scan"
    assert plugin.meta.severity == Severity.HIGH
    assert "sqli" in plugin.meta.tags
    assert "owasp-top10" in plugin.meta.tags
    print(f"✅ Test 7 PASSED: 插件元信息正确 → {plugin}")


def test_waf_linkage():
    """验证 WAF 联动逻辑"""
    plugin = SqliScanPlugin()

    # 无 WAF 数据
    assert plugin._check_waf_status("https://example.com/test", {}) is False

    # 精确匹配
    ctx = {
        "waf": {
            "https://example.com/test": {"detected": True, "waf_list": ["Cloudflare"]},
        }
    }
    assert plugin._check_waf_status("https://example.com/test", ctx) is True

    # 域名级匹配
    assert plugin._check_waf_status("https://example.com/other?id=1", ctx) is True

    # 不同域名
    assert plugin._check_waf_status("https://other.com/page", ctx) is False

    print("✅ Test 8 PASSED: WAF 联动逻辑正确")


def test_boolean_blind_logic():
    """验证布尔盲注判定逻辑（模拟）"""
    # 模拟: baseline 和 TRUE 响应完全一致, FALSE 响应有差异
    baseline = "Welcome user! Here are your results: Item A, Item B, Item C."
    true_resp = "Welcome user! Here are your results: Item A, Item B, Item C."
    false_resp = "Welcome user! No results found."

    sim_bt = similarity_ratio(baseline, true_resp)
    sim_bf = similarity_ratio(baseline, false_resp)
    diff = sim_bt - sim_bf

    hash_b = SimHash(baseline)
    hash_t = SimHash(true_resp)
    hash_f = SimHash(false_resp)

    print(
        f"  模拟布尔盲注:\n"
        f"    Levenshtein: base↔true={sim_bt:.4f}  base↔false={sim_bf:.4f}  diff={diff:.4f}\n"
        f"    SimHash:     base↔true={hash_b.similarity(hash_t):.4f}  "
        f"base↔false={hash_b.similarity(hash_f):.4f}"
    )

    assert sim_bt > 0.9, f"TRUE 应高度相似: {sim_bt}"
    assert diff > 0.1, f"差异应显著: {diff}"

    print("✅ Test 9 PASSED: 布尔盲注判定逻辑验证通过")


def test_html_tag_stripping():
    """验证 HTML 标签剔除"""
    html = '<html><head><title>Test</title><style>body{color:red}</style></head>'
    html += '<body><div class="content"><p>Hello World</p>'
    html += '<script>var x=1;</script></div></body></html>'

    stripped = _strip_html_tags(html)

    assert '<' not in stripped, f"不应包含 HTML 标签: {stripped}"
    assert 'script' not in stripped.lower() or 'var x=1' not in stripped
    assert 'Hello World' in stripped
    assert 'style' not in stripped.lower() or 'color:red' not in stripped
    assert 'Test' in stripped

    print("✅ Test 10 PASSED: HTML 标签剔除正确")


def test_response_fingerprint():
    """验证响应指纹比对"""
    class MockResponse:
        def __init__(self, text, status_code=200):
            self.text = text
            self.status_code = status_code

    # 相同内容 → 高相似度
    fp1 = ResponseFingerprint.from_response(MockResponse("<p>Hello World</p>"))
    fp2 = ResponseFingerprint.from_response(MockResponse("<p>Hello World</p>"))
    assert fp1.similarity_to(fp2) > 0.95, f"相同内容应高度相似: {fp1.similarity_to(fp2)}"

    # 不同内容 → 低相似度
    fp3 = ResponseFingerprint.from_response(MockResponse("<p>Totally different page</p>"))
    sim_diff = fp1.similarity_to(fp3)
    assert sim_diff < fp1.similarity_to(fp2), f"不同内容相似度应更低: {sim_diff}"

    # 状态码不同 → 拉低分数
    fp4 = ResponseFingerprint.from_response(MockResponse("<p>Hello World</p>", 404))
    sim_status = fp1.similarity_to(fp4)
    assert sim_status < fp1.similarity_to(fp2), f"状态码不同应拉低分数: {sim_status}"

    # 自适应差值模型验证
    baseline = ResponseFingerprint.from_response(MockResponse(
        "Welcome user! Here are your results: Item A, Item B, Item C."
    ))
    true_fp = ResponseFingerprint.from_response(MockResponse(
        "Welcome user! Here are your results: Item A, Item B, Item C."
    ))
    false_fp = ResponseFingerprint.from_response(MockResponse(
        "Welcome user! No results found."
    ))

    sim_bt = baseline.similarity_to(true_fp)
    sim_bf = baseline.similarity_to(false_fp)
    diff = sim_bt - sim_bf

    assert diff >= 0.05, f"差值应 >= 0.05 以触发自适应判定: {diff}"
    print(f"  指纹比对: base↔true={sim_bt:.4f}  base↔false={sim_bf:.4f}  diff={diff:.4f}")

    print("✅ Test 11 PASSED: 响应指纹比对正确")


def test_injection_point_discovery():
    """验证智能注入点嗅探"""
    # DVWA 场景: Submit 应识别为业务背景
    url = "http://dvwa/vuln.php?id=1&Submit=Submit&user=admin"
    result = _discover_injection_points(url)

    assert "id" in result.test_params, f"id 应为测试点: {result.test_params}"
    assert "user" in result.test_params, f"user 应为测试点: {result.test_params}"
    assert "Submit" not in result.test_params, f"Submit 不应为测试点: {result.test_params}"
    assert "Submit" in result.background_params, f"Submit 应为背景参数: {result.background_params}"
    assert result.background_params["Submit"] == "Submit"

    # context 显式声明覆盖
    result2 = _discover_injection_points(url, {"user": "forced"})
    assert "user" not in result2.test_params, f"user 应被 context 强制为背景: {result2.test_params}"
    assert result2.background_params["user"] == "forced"

    # token 参数应自动识别
    url2 = "http://target.com/?q=search&token=abc123&_method=PUT"
    result3 = _discover_injection_points(url2)
    assert "q" in result3.test_params
    assert "token" in result3.background_params
    assert "_method" in result3.background_params

    print("✅ Test 12 PASSED: 智能注入点嗅探正确")


def test_mutate_payload():
    """验证动态变异引擎"""
    base = ["' OR '1'='1", "' AND 1=1--"]
    context = {"detected_db_type": "MySQL", "waf": {}}

    mutated = mutate_payload(base, context)

    # 应生成变异体
    assert len(mutated) > 0, f"变异引擎未生成任何变体: {mutated}"

    # 变异体不应包含原始 payload
    for original in base:
        assert original not in mutated, f"变异体中不应包含原始 payload: {original}"

    # MySQL 模式下应有 # 注释替代
    has_hash_variant = any("#" in p for p in mutated)
    assert has_hash_variant, f"MySQL 模式下应生成 # 注释变体"

    # 空 context 也应能工作
    mutated_empty = mutate_payload(base, {})
    assert len(mutated_empty) > 0

    print(f"✅ Test 13 PASSED: 动态变异引擎正确 (生成 {len(mutated)} 个变体)")


def test_cwe_analyser():
    """验证 CWE 自动关联分析器"""
    from utils.analyser import Analyser

    analyser = Analyser()

    # CWE 查找
    cwe = analyser.lookup_cwe("sqli_scan")
    assert cwe.cwe_id == "CWE-89", f"SQLi 应关联 CWE-89: {cwe.cwe_id}"

    cwe_xss = analyser.lookup_cwe("xss_scan")
    assert cwe_xss.cwe_id == "CWE-79"

    cwe_unknown = analyser.lookup_cwe("nonexistent_plugin")
    assert cwe_unknown.cwe_id == "CWE-20", f"未知插件应回退到 CWE-20: {cwe_unknown.cwe_id}"

    # 风险评分
    score = analyser.calculate_risk_score(cwe, confidence=0.95)
    assert 8.0 <= score <= 10.0, f"SQLi 高信心值应得高分: {score}"

    score_waf = analyser.calculate_risk_score(cwe, confidence=0.95, has_waf=True)
    assert score_waf < score, f"有 WAF 应降低分数: {score_waf} vs {score}"

    # 完整流程
    fake_results = [
        {"plugin": "sqli_scan", "vulnerable": True, "extra": {"findings": [{"confidence": 0.95}]}},
        {"plugin": "waf_check", "vulnerable": True, "extra": {}},
        {"plugin": "sqli_scan", "vulnerable": False, "extra": {}},  # 不应出现在结果中
    ]
    enriched = analyser.enrich_results(fake_results)
    assert len(enriched) == 2, f"应有 2 个漏洞结果: {len(enriched)}"

    summary = analyser.generate_summary(enriched)
    assert summary["total_vulnerabilities"] == 2
    assert "CWE-89" in summary["by_cwe"]

    print("✅ Test 14 PASSED: CWE 自动关联分析器正确")


def main():
    print("=" * 60)
    print(" OpenScanner SQLi 插件测试 (v3.0)")
    print("=" * 60)

    test_levenshtein()
    test_similarity_ratio()
    test_simhash()
    test_error_signatures()
    test_url_utilities()
    test_dynamic_content_strip()
    test_plugin_meta()
    test_waf_linkage()
    test_boolean_blind_logic()
    test_html_tag_stripping()
    test_response_fingerprint()
    test_injection_point_discovery()
    test_mutate_payload()
    test_cwe_analyser()

    print("\n" + "=" * 60)
    print(" 🎉 所有 14 项测试通过!")
    print("=" * 60)


if __name__ == "__main__":
    main()
