"""
core/ai/debate.py — 多智能体辩论机制 (Dual-Agent Debate)

机制说明:
对于高危且中等信心(e.g., 0.5-0.9)的漏洞判断，启用多智能体辩论。
- 攻击者 Agent A：极力证明是真实漏洞。
- 防守者 Agent B：极力证明是误报。
- 裁判 Agent Judge：综合两方意见给出最终判决。
"""

from __future__ import annotations

import logging
from typing import Dict, Any, Optional

from core.ai.base import AIRole, AIResponse
from core.ai.prompts import get_system_prompt

logger = logging.getLogger("openscanner.ai.debate")

class DebateOrchestrator:
    def __init__(self, engine: 'AIEngine'): # type: ignore
        self.engine = engine

    async def conduct_debate(self, context_prompt: str) -> Optional[AIResponse]:
        """执行三方辩论并返回最终裁判结果"""
        logger.info("[AI/Debate] ⚔️ 触发多智能体辩论机制")

        # 1. 攻击者发言
        attacker_resp = await self.engine._predict(
            role=AIRole.DEBATE_ATTACKER,
            system_prompt=get_system_prompt("DEBATE_ATTACKER", self.engine._config.language),
            user_prompt=context_prompt
        )
        if not attacker_resp.success:
            return None
            
        # 2. 防守者发言
        defender_resp = await self.engine._predict(
            role=AIRole.DEBATE_DEFENDER,
            system_prompt=get_system_prompt("DEBATE_DEFENDER", self.engine._config.language),
            user_prompt=context_prompt
        )
        if not defender_resp.success:
            return None

        attacker_arg = attacker_resp.parsed.get("argument", "")
        defender_arg = defender_resp.parsed.get("argument", "")

        # 3. 裁判总结判决
        judge_prompt = f"""
## 原始案卷数据
{context_prompt}

## 红方攻击者的论据 (证明存在漏洞)
{attacker_arg}

## 蓝方防守者的论据 (证明是误报)
{defender_arg}

请作为主裁判，权衡双方论点，给出最终裁决。
"""
        judge_resp = await self.engine._predict(
            role=AIRole.DEBATE_JUDGE,
            system_prompt=get_system_prompt("DEBATE_JUDGE", self.engine._config.language),
            user_prompt=judge_prompt
        )
        
        logger.info(
            "[AI/Debate] ⚔️ 辩论结束 | 最终判决: %s | Winner: %s", 
            judge_resp.parsed.get("is_exploited"),
            judge_resp.parsed.get("winning_argument")
        )
        
        return judge_resp
