"""
core/ai/rlhf.py — 人类反馈强化学习与微调控制 (RLHF)

在 OpenScanner 中，我们通过保存用户标记的 False Positives / True Positives
到本地 rlhf_db.json，并在预测时通过 Few-Shot In-Context Learning 注入这些经验，
让 AI “越扫越准”。
"""

import json
import logging
from pathlib import Path
from typing import List, Dict

logger = logging.getLogger("openscanner.ai.rlhf")

class RLHFManager:
    DB_PATH = Path(".rlhf_db.json")

    def __init__(self):
        # 预先加载到内存，避免后续扫描中重复读取磁盘
        self._db = self._load_db()

    def _load_db(self) -> List[Dict]:
        if self.DB_PATH.exists():
            try:
                return json.loads(self.DB_PATH.read_text("utf-8"))
            except Exception:
                return []
        return []

    def _save_db(self):
        try:
            self.DB_PATH.write_text(json.dumps(self._db, ensure_ascii=False, indent=2), "utf-8")
        except Exception:
            pass

    def submit_feedback(self, plugin: str, prompt: str, actual_verdict: bool, reason: str):
        """用户提交误报反馈"""
        record = {
            "plugin": plugin,
            "prompt_hash": hash(prompt),
            "prompt": prompt,
            "actual_is_exploited": actual_verdict,
            "correction_reason": reason
        }
        self._db.append(record)
        self._save_db()
        logger.info("[AI/RLHF] 收到人工反馈: plugin=%s, verdict=%s", plugin, actual_verdict)

    def get_few_shot_examples(self, plugin: str) -> str:
        """从内存缓存中获取 Few-Shot 案例"""
        relevant = [r for r in self._db if r.get("plugin") == plugin]
        if not relevant:
            return ""
            
        # 取最新的2条
        examples = relevant[-2:]
        
        text = "\n\n### [❗重要提示: 历史经验学习] ###\n"
        text += "过去在类似场景中，你曾做出错误判断，请根据以下人类反馈进行纠正：\n"
        
        for idx, ex in enumerate(examples):
            text += f"\n--- 历史案例 {idx+1} ---\n"
            text += f"场景:\n{ex['prompt'][:500]}...\n"
            text += f"真实情况 (人类纠正): is_exploited = {ex['actual_is_exploited']}\n"
            text += f"人类解释: {ex['correction_reason']}\n"
            
        text += "基于上述教训，请在本次分析中避免相同错误。\n"
        return text
