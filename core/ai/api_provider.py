"""
core/ai/api_provider.py — 云端 API 推理引擎 (Plan B)

基于 httpx 异步 HTTP 的云端 AI 提供者:
  • 支持 OpenAI 兼容协议 (GPT-4o-mini, DeepSeek, Qwen-Plus 等)
  • 支持 Google Gemini 原生协议
  • 自动重试与超时控制
  • 异步非阻塞，不影响扫描主循环

性能优势: 无需本地硬件，推理速度快，模型能力强。
隐私注意: 代码片段和 HTTP 报文将发送至第三方 API 服务器。
"""

from __future__ import annotations

import json
import logging
import time
from typing import Optional

import httpx

from core.ai.base import AbstractAIProvider, AIConfig

logger = logging.getLogger("openscanner.ai.api")


class APIProvider(AbstractAIProvider):
    """云端 API 推理提供者

    支持两种协议:
      1. OpenAI 兼容 (/v1/chat/completions) — 适用于 GPT、DeepSeek、Qwen-Plus 等
      2. Google Gemini (/v1beta/models/...:generateContent) — 适用于 Gemini 1.5 Flash/Pro

    根据 api_base_url 自动判定协议类型。

    Usage:
        provider = APIProvider(config)
        text = await provider.generate(system_prompt, user_prompt)
    """

    def __init__(self, config: AIConfig) -> None:
        self._config = config
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def provider_name(self) -> str:
        if "generativelanguage.googleapis.com" in self._config.api_base_url:
            return "gemini"
        return "openai_compatible"

    @property
    def _is_gemini(self) -> bool:
        return "generativelanguage.googleapis.com" in self._config.api_base_url

    def is_available(self) -> bool:
        """检查 API 密钥和端点是否已配置"""
        return bool(self._config.api_key) and bool(self._config.api_base_url)

    async def _ensure_client(self) -> httpx.AsyncClient:
        """延迟创建 HTTP 客户端"""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._config.api_timeout),
                follow_redirects=True,
                http2=True,
                trust_env=self._config.api_trust_env,
                proxy=self._config.api_proxy if self._config.api_proxy else None,
            )
        return self._client

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 512,
    ) -> str:
        """调用云端 API 执行推理"""
        if self._is_gemini:
            return await self._generate_gemini(system_prompt, user_prompt, temperature, max_tokens)
        else:
            return await self._generate_openai(system_prompt, user_prompt, temperature, max_tokens)

    # ── OpenAI 兼容协议 ──────────────────────

    async def _generate_openai(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        max_tokens: int,
    ) -> str:
        """OpenAI /v1/chat/completions 协议"""
        client = await self._ensure_client()

        url = f"{self._config.api_base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._config.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self._config.api_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "top_p": 0.9,
        }

        try:
            resp = await client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()

            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "")
            return ""

        except httpx.HTTPStatusError as exc:
            try:
                error_data = exc.response.json()
                # 尝试提取 OpenAI 风格的错误信息: {"error": {"message": "..."}}
                error_msg = error_data.get("error", {}).get("message", str(exc))
            except Exception:
                error_msg = exc.response.text[:200] or str(exc)

            logger.error(
                "[AI/API] OpenAI 请求失败 (%d): %s",
                exc.response.status_code,
                error_msg,
            )
            # 重新抛出一个带有更清晰描述的异常
            raise RuntimeError(f"Cloud API Error ({exc.response.status_code}): {error_msg}")
        except Exception as exc:
            logger.error("[AI/API] OpenAI 请求异常: %s", exc)
            raise

    # ── Google Gemini 协议 ────────────────────

    async def _generate_gemini(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        max_tokens: int,
    ) -> str:
        """Google Gemini generateContent 协议"""
        client = await self._ensure_client()

        model_name = self._config.api_model or "gemini-1.5-flash"
        url = (
            f"{self._config.api_base_url.rstrip('/')}"
            f"/models/{model_name}:generateContent"
            f"?key={self._config.api_key}"
        )

        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": f"[System Instructions]\n{system_prompt}\n\n[User Query]\n{user_prompt}"}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
                "topP": 0.9,
            },
        }

        try:
            resp = await client.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()

            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    return parts[0].get("text", "")
            return ""

        except httpx.HTTPStatusError as exc:
            try:
                error_data = exc.response.json()
                # 尝试提取 Gemini 风格的错误信息: {"error": {"message": "..."}}
                error_msg = error_data.get("error", {}).get("message", str(exc))
            except Exception:
                error_msg = exc.response.text[:200] or str(exc)

            logger.error(
                "[AI/API] Gemini 请求失败 (%d): %s",
                exc.response.status_code,
                error_msg,
            )
            raise RuntimeError(f"Cloud API Error ({exc.response.status_code}): {error_msg}")
        except Exception as exc:
            logger.error("[AI/API] Gemini 请求异常: %s", exc)
            raise

    async def shutdown(self) -> None:
        """关闭 HTTP 客户端连接池"""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
            logger.info("[AI/API] HTTP 客户端已关闭")
