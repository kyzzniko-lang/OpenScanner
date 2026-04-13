"""
tests/test_reporter.py — ReportGenerator 验证

验证:
  1. Markdown 报告生成（含漏洞 / 修复建议 / 性能分析）
  2. JSON 报告结构
  3. 空结果集处理
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.reporter import ReportGenerator


def test_full_report():
    """验证完整报告生成"""
    results = [
        {
            "plugin": "waf_check",
            "url": "https://example.com",
            "vulnerable": True,
            "severity": "info",
            "detail": "检测到 WAF: Cloudflare",
            "evidence": "Header [server: cloudflare]",
            "extra": {"waf_list": ["Cloudflare"]},
        },
        {
            "plugin": "sqli_scan",
            "url": "https://example.com/page?id=1",
            "vulnerable": True,
            "severity": "high",
            "detail": "发现 SQL 注入 | 类型: Error-Based | 数据库: MySQL",
            "evidence": "参数 [id] | Payload: ' OR '1'='1 | 数据库: MySQL",
            "extra": {
                "findings": [{
                    "type": "Error-Based",
                    "param": "id",
                    "payload": "' OR '1'='1",
                    "db_type": "MySQL",
                    "confidence": 0.95,
                }],
                "vulnerable_params": ["id"],
            },
        },
        {
            "plugin": "sqli_scan",
            "url": "https://example.com/safe?q=hello",
            "vulnerable": False,
            "severity": "info",
            "detail": "未发现 SQL 注入",
        },
    ]

    summary = {
        "total_checks": 3,
        "vulnerabilities_found": 2,
        "by_severity": {"info": 1, "high": 1},
        "by_plugin": {"waf_check": 1, "sqli_scan": 1},
        "elapsed_seconds": 12.34,
        "plugins_loaded": 2,
        "waf_detected": True,
    }

    context = {
        "waf": {
            "https://example.com": {
                "detected": True,
                "waf_list": ["Cloudflare"],
            },
        },
    }

    targets = [
        "https://example.com",
        "https://example.com/page?id=1",
        "https://example.com/safe?q=hello",
    ]

    gen = ReportGenerator(results, summary, context, targets)

    # ── Markdown 报告 ──
    md = gen.to_markdown()
    assert "OpenScanner" in md
    assert "Executive Summary" in md
    assert "Severity Distribution" in md
    assert "Performance Analysis" in md
    assert "WAF Analysis" in md
    assert "Cloudflare" in md
    assert "SQL Injection" in md
    assert "Remediation" in md
    assert "MySQL" in md
    assert "参数化查询" in md
    assert "Error-Based" in md
    assert "checks/s" in md
    print(f"✅ Test 1 PASSED: Markdown 报告 ({len(md)} 字符)")

    # ── JSON 报告 ──
    import json
    js = gen.to_json()
    data = json.loads(js)
    assert data["scanner"] == "OpenScanner v1.0.0"
    assert data["summary"]["total_checks"] == 3
    assert len(data["vulnerabilities"]) == 2
    assert "performance" in data
    assert data["performance"]["checks_per_second"] > 0
    print(f"✅ Test 2 PASSED: JSON 报告结构正确")

    # ── 打印报告片段 ──
    lines = md.split("\n")
    print(f"\n  📝 报告预览 (前 30 行):")
    for line in lines[:30]:
        print(f"    {line}")


def test_empty_results():
    """验证空结果集"""
    gen = ReportGenerator([], {"total_checks": 0, "vulnerabilities_found": 0}, {})
    md = gen.to_markdown()
    assert "未发现安全漏洞" in md
    js = gen.to_json()
    assert '"vulnerabilities": []' in js
    print("✅ Test 3 PASSED: 空结果集处理正确")


def main():
    print("=" * 60)
    print(" OpenScanner ReportGenerator 测试")
    print("=" * 60)
    test_full_report()
    test_empty_results()
    print("\n" + "=" * 60)
    print(" 🎉 所有 3 项测试通过!")
    print("=" * 60)


if __name__ == "__main__":
    main()
