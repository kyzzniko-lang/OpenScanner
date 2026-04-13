"""
core/ai/base.py — AI Provider 抽象基类

所有 AI 提供者 (Local LLM / Cloud API) 都必须继承此接口。
这是 Hybrid AI Engine 的抽象层基石，确保上层逻辑对底层实现透明。
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional

logger = logging.getLogger("openscanner.ai.base")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AI 模式枚举
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class AIMode(Enum):
    """AI 引擎运行模式"""
    OFF = auto()      # 关闭 AI (传统模式)
    LOCAL = auto()    # 本地 LLM (隐私优先)
    API = auto()      # 云端 API  (精度优先)


class AIRole(Enum):
    """AI 专家角色"""
    AUDITOR = "auditor"                    # 代码审计专家
    EXPLOIT_VERIFIER = "exploit_verifier"  # 漏洞验证专家
    BYPASS_EXPERT = "bypass_expert"        # WAF 绕过专家
    DEBATE_ATTACKER = "debate_attacker"    # 辩论红方
    DEBATE_DEFENDER = "debate_defender"    # 辩论蓝方
    DEBATE_JUDGE = "debate_judge"          # 辩论裁判
    CRITIC = "critic"                      # 质疑专家 (AVA)
    FINALIZER = "finalizer"                # 定音专家 (AVA)
    CHAT_ASSISTANT = "chat_assistant"      # 助手专家
    SAST_AI_AUDITOR = "sast_ai_auditor"    # SAST 深度审计专家


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AI 响应数据结构
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class AIResponse:
    """AI 推理的标准响应结构"""
    success: bool = False                         # 推理是否成功
    raw_text: str = ""                            # 原始模型输出文本
    parsed: Dict[str, Any] = field(default_factory=dict)  # 解析后的结构化 JSON
    confidence: float = 0.0                       # 信心值 [0.0, 1.0]
    role: Optional[AIRole] = None                 # 使用的角色
    provider: str = ""                            # 提供者标识 ("local" / "api")
    latency_ms: float = 0.0                       # 推理耗时 (ms)
    error: str = ""                               # 错误信息

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "parsed": self.parsed,
            "confidence": self.confidence,
            "role": self.role.value if self.role else None,
            "provider": self.provider,
            "latency_ms": round(self.latency_ms, 1),
            "error": self.error,
        }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AI Provider 配置
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class AIConfig:
    """AI 引擎全局配置"""
    mode: AIMode = AIMode.OFF

    # ── 本地模式配置 ──
    local_model_path: str = ""                     # GGUF 模型文件路径
    local_n_ctx: int = 4096                        # 上下文窗口大小 (从 2048 提升，支撑深度审计)
    local_n_threads: int = 4                       # CPU 推理线程数
    local_temperature: float = 0.1                 # 采样温度 (低 = 更确定性)
    local_max_tokens: int = 512                    # 最大生成 token 数

    # ── API 模式配置 ──
    api_key: str = ""                              # API 密钥
    api_base_url: str = "https://api.openai.com/v1"  # API 端点 (OpenAI 兼容)
    api_model: str = "gpt-4o-mini"                 # 模型名称
    api_timeout: float = 30.0                      # API 超时 (秒)
    api_temperature: float = 0.1                   # 采样温度

    # ── 网络与通用配置 ──
    language: str = "zh"                           # AI 语言设置 ("zh" 或 "en")
    cache_enabled: bool = True                     # 是否启用研判缓存
    api_trust_env: bool = True                     # 是否使用系统/环境变量代理 (HTTP_PROXY等)
    api_proxy: Optional[str] = None                # 手动指定代理地址 (例如 http://127.0.0.1:7890)
    
    cache_file: str = ".ai_cache.json"             # 缓存文件路径
    max_code_length: int = 4000                    # 发送给 AI 的最大代码长度 (防止 OOM)
    idle_unload_seconds: int = 300                 # 本地模型空闲卸载时间 (秒)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Provider 抽象基类
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class AbstractAIProvider(ABC):
    """AI 提供者抽象基类。

    所有提供者必须实现:
      - generate(): 给定 system prompt + user prompt，返回模型生成文本
      - is_available(): 检查提供者是否可用
      - shutdown(): 释放资源 (模型内存 / 连接池)
    """

    @abstractmethod
    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 512,
    ) -> str:
        """执行 LLM 推理

        Args:
            system_prompt: 系统角色提示
            user_prompt:   用户输入提示
            temperature:   采样温度
            max_tokens:    最大生成长度

        Returns:
            模型输出的原始文本
        """
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """检查提供者是否就绪"""
        ...

    @abstractmethod
    async def shutdown(self) -> None:
        """释放资源"""
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """提供者标识名 (e.g., 'local', 'openai', 'gemini')"""
        ...
