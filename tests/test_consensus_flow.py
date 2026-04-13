"""
tests/test_consensus_flow.py — 验证“共识研判”全链路逻辑
"""
import sys
import asyncio
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock

# 确保项目根在路径中
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.engine import ScanEngine
from core.request import RequestConfig
from core.ai.base import AIResponse, AIConfig, AIMode
from core.ai.engine import AIEngine
from plugins.base import ScanResult, Severity

async def test_consensus_logic():
    print("[*] Testing Exhaustive Consensus Flow...")

    # 1. Mock AI 引擎
    mock_ai = MagicMock(spec=AIEngine)
    mock_ai.is_enabled = True
    
    # 模拟 AI 返回一个“确认注入”的共识结果
    mock_ai.verify_consensus = AsyncMock(return_value=AIResponse(
        success=True,
        confidence=0.98, # 极高信心
        parsed={
            "is_exploited": True,
            "vuln_type": "sqli",
            "evidence": "Matrix shows 5 consistent SQLi hits.",
            "reasoning": "Strong signal."
        }
    ))

    # 2. 构造 ScanEngine
    config = RequestConfig()
    engine = ScanEngine(config=config)
    engine._ai_engine = mock_ai
    
    # 3. 构造一个包含强信号的结果
    r = ScanResult(
        plugin_name="sqli_scan",
        url="http://test.com/api?id=1",
        is_vulnerable=True,
        severity=Severity.MEDIUM,
        extra={
            "param": "id",
            "method": "GET",
            "findings": [
                {
                    "confidence": 0.85,
                    "metrics": {"levenshtein": {"diff": 0.45}} # 强语义偏差信号
                }
            ],
            "attempts": [
                {"type": "Time", "payload": "SLEEP(5)", "status": "Vulnerable", "elapsed": 5.1},
                {"type": "Time", "payload": "SLEEP(5)", "status": "Vulnerable", "elapsed": 5.2},
                {"type": "Time", "payload": "SLEEP(0)", "status": "Safe", "elapsed": 0.1},
            ]
        }
    )
    engine._results.append(r)

    # 4. 执行 Stage 5 (推理阶段)
    print("   [*] Running Stage 5 Reasoning simulation...")
    
    from core.reasoner import DeepReasoner
    reasoner = DeepReasoner()
    
    ai_resp = await engine._ai_engine.verify_consensus(
        url=r.url,
        method="GET",
        param="id",
        attempts=r.extra["attempts"]
    )
    
    verdict = reasoner.evaluate(r, engine._context, ai_response=ai_resp)
    r.extra["reasoning"] = verdict.to_dict()
    
    if verdict.severity_override and verdict.confidence >= 0.65:
        r.severity = verdict.severity_override

    # 5. 断言验证
    print(f"   [*] Result Severity: {r.severity}")
    print(f"   [*] AI Confidence (Overall): {verdict.confidence:.2f}")
    
    # 预期: 语义偏差 (0.95) * 0.25 + AI (0.98) * 0.30 + 基线 (0.85) * 0.15 + WAF (0.50) * 0.15
    # = 0.2375 + 0.294 + 0.1275 + 0.075 = 0.734
    # 0.734 / 0.85 = 0.86
    assert verdict.confidence >= 0.80, "Overall confidence should be high"
    assert r.severity == Severity.CRITICAL, "Vulnerability should be upgraded to CRITICAL"
    print("\n[OK] Consensus Flow Validation PASSED!")

if __name__ == "__main__":
    asyncio.run(test_consensus_logic())
