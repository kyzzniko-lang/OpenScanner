from __future__ import annotations

import logging
import json
from typing import Dict, Any, Optional

from core.ai.base import AIRole, AIResponse
from core.ai.prompts import get_system_prompt

logger = logging.getLogger("openscanner.ai.auditor")


class AIReviewer:
    """AVA (AI-Verify-AI) 深度查杀与交叉验证引擎"""

    def __init__(self, engine: Any):
        """
        初始化审查器。
        Args:
            engine: 实例化的 AIEngine 対象。
        """
        self.engine = engine

    async def run_ava_review(
        self, context_prompt: str, proposer_resp_raw: str
    ) -> Dict[str, Any]:
        """
        根据初始提案 (Proposer) 与上下文，执行质疑 (Critic) 与定音 (Finalizer)。

        Args:
            context_prompt: 提供给 AI 的原始上下文特征包 (通常包含了漏洞 HTTP 响应)
            proposer_resp_raw: Proposer Agent 产生的最初一轮判定日志或 JSON 报告

        Returns:
            Dict: 包含完整交叉验证和四大 Metrics 评估的数据字典。可以用于前端 UI 渲染。
        """
        logger.info("[AI/AVA] 🕵️‍♂️ 启动深度交叉验证架构...")

        # 1. 质疑者 (Critic) 阶段
        logger.info("[AI/AVA] 正在进行针对性反向质疑 (Critic)...")
        critic_prompt = f"""
## 原始探测数据 / Context
{context_prompt}

## 提案者(Proposer)的初步判定
{proposer_resp_raw}

请寻找一切可能证明这是误报的证据，严格审视上面的判定内容。
"""
        system_prompt = get_system_prompt("CRITIC", self.engine._config.language)
        critic_resp = await self.engine._predict(
            role=AIRole.CRITIC,
            system_prompt=system_prompt,
            user_prompt=critic_prompt,
        )

        if not critic_resp.success:
            logger.error(f"[AI/AVA] 质疑者节点异常: {critic_resp.error}")
            return {"error": f"Critic Agent Failed: {critic_resp.error}"}

        critic_raw = critic_resp.raw_text

        # 2. 复核者 (Finalizer) 阶段
        logger.info("[AI/AVA] 正在请求最高裁决者进行逻辑综合 (Finalizer)...")
        finalizer_prompt = f"""
## 原始探测数据 / Context
{context_prompt}

## 提案者(Proposer)的初步判定
{proposer_resp_raw}

## 质疑者(Critic)的反方意见
{critic_raw}

请作为最终裁决者综合评估，并给出精准的评价分析结果。
"""
        system_prompt = get_system_prompt("FINALIZER", self.engine._config.language)
        finalizer_resp = await self.engine._predict(
            role=AIRole.FINALIZER,
            system_prompt=system_prompt,
            user_prompt=finalizer_prompt,
        )

        if not finalizer_resp.success:
            logger.error(f"[AI/AVA] 评判者节点异常: {finalizer_resp.error}")
            return {"error": f"Finalizer Agent Failed: {finalizer_resp.error}"}

        # 构建最终报告产出对象
        final_verdict = finalizer_resp.parsed
        
        # 为了防止模型输出不符合预期，添加一个空值垫底
        if not final_verdict:
            final_verdict = {
                "verdict": "Unknown",
                "confidence_score": 0.0,
                "critic_response": "评判节点未产生标准JSON",
                "overall_evaluation": "推理引擎解析失败",
                "metrics": {
                    "evidence_strength": 0,
                    "logic_cohesion": 0,
                    "fp_probability": 0,
                    "actionability": 0
                }
            }

        return {
            "critic": critic_resp.parsed,
            "finalizer": final_verdict,
            "latency": critic_resp.latency_ms + finalizer_resp.latency_ms
        }
