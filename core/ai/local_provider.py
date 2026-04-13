"""
core/ai/local_provider.py — 本地 LLM 推理引擎 (Enterprise Hardened)

基于 llama-cpp-python 的本地化 AI 提供者:
  • 加载 GGUF 格式量化模型 (Qwen2-0.5B / Llama-3.2-1B 等)
  • 纯 CPU 推理，无需 GPU
  • 延迟加载 + 空闲自动卸载，最小化内存占用
  • 线程安全的异步推理 (asyncio.to_thread)

企业级加固:
  • Token 预飞检查: 推理前估算总 Token，超出上下文时拒绝发送而非崩溃
  • 推理互斥锁: 确保 llama.cpp 同一时刻只处理一个请求
  • 崩溃自恢复: 推理异常时自动卸载并标记重载
  • n_ctx 安全裁剪: 限制最大上下文窗口，防止 OOM

隐私保证: 所有推理在本地完成，代码和扫描数据不会离开用户机器。
"""

from __future__ import annotations

import asyncio
import atexit
import logging
import threading
import time
import os
import gc
from typing import Optional, Dict, Any, List
from pathlib import Path

from core.ai.base import AbstractAIProvider, AIConfig

logger = logging.getLogger("openscanner.ai.local")

# ── 安全常量 ──
MAX_SAFE_N_CTX = 8192   # 小型 GGUF 模型的安全上限 (防止 OOM)
MIN_RESPONSE_BUDGET = 64  # 最少预留给模型响应的 Token 数


class LocalAIProvider(AbstractAIProvider):
    """本地 LLM 推理提供者 (企业级加固版)

    使用 llama-cpp-python 加载 GGUF 模型并执行推理。
    模型在首次调用时延迟加载，通过 asyncio.to_thread 在独立线程运行。

    关键安全特性:
      - Token 预飞检查: 防止上下文溢出导致 C++ abort()
      - 推理互斥锁: 防止并发调用导致 GGML 状态断言失败
      - 崩溃自恢复: 异常后自动重载模型
    """

    def __init__(self, config: AIConfig) -> None:
        self._config = config
        self._model = None              # 缓存 llama_cpp.Llama 实例
        self._available = False
        self._last_used: float = 0.0    # 上次使用时间戳
        self._load_lock = asyncio.Lock()
        
        # 🔒 推理互斥锁 (threading.Lock): 
        # llama.cpp 的 Llama 实例不是线程安全的。
        # asyncio.gather + to_thread 会产生真正的多线程并发。
        # 必须用原生线程锁保护 C++ 层面的 KV Cache 和内存调度器。
        self._infer_lock = threading.Lock()
        
        # 崩溃恢复标记
        self._needs_reload = False
        
        # 实际生效的 n_ctx (可能被裁剪)
        self._effective_n_ctx: int = 0
        
        # 注册清理钩子
        atexit.register(self._cleanup_on_exit)

    def _cleanup_on_exit(self):
        """Python 退出时强制释放模型内存"""
        if self._model is not None:
            print("[AI/Local] 检测到系统退出，正在释放本地模型内存...")
            self._model = None
            gc.collect()

    @property
    def provider_name(self) -> str:
        return "local"

    def _get_normalized_path(self) -> Optional[Path]:
        """获取并规范化用户提供的模型路径"""
        path_str = self._config.local_model_path
        if not path_str:
            return None
        
        # 1. 展开用户目录 (~/...)
        path_str = os.path.expanduser(path_str)
        # 2. 展开环境变量 (%USERPROFILE%/... 或 $HOME/...)
        path_str = os.path.expandvars(path_str)
        
        p = Path(path_str).resolve()
        return p

    def is_available(self) -> bool:
        """检查 llama-cpp-python 是否可用且模型文件是否存在"""
        try:
            import llama_cpp  # noqa: F401
        except ImportError:
            logger.error("[AI/Local] 未检测到 llama-cpp-python 库，请先安装。")
            return False

        path = self._get_normalized_path()
        if path is None or not path.is_file():
            logger.warning("[AI/Local] 模型文件不存在或不是有效文件: %s", self._config.local_model_path)
            return False
        
        return True

    def _load_model_sync(self, path: str):
        """同步加载模型（由 asyncio.to_thread 调用）"""
        from llama_cpp import Llama
        
        # 🛡️ 安全裁剪: 用户可能设置了远超模型能力的 n_ctx (如 160000)
        # 小型量化模型 (0.5B-3B) 的实际可用上下文通常不超过 8192
        requested_n_ctx = self._config.local_n_ctx
        safe_n_ctx = min(requested_n_ctx, MAX_SAFE_N_CTX)
        
        if requested_n_ctx != safe_n_ctx:
            logger.warning(
                "[AI/Local] ⚠️ n_ctx 安全裁剪: 用户请求 %d → 实际使用 %d (上限 %d)",
                requested_n_ctx, safe_n_ctx, MAX_SAFE_N_CTX
            )
        
        self._effective_n_ctx = safe_n_ctx
        
        return Llama(
            model_path=path,
            n_ctx=safe_n_ctx,
            n_threads=self._config.local_n_threads,
            verbose=False,
        )

    async def _ensure_loaded(self) -> bool:
        """延迟初始化模型实例 (线程安全)"""
        # 如果标记需要重载，先卸载
        if self._needs_reload and self._model is not None:
            logger.info("[AI/Local] 检测到崩溃恢复标记，正在重载模型...")
            await self.shutdown()
            self._needs_reload = False
        
        if self._model is not None:
            self._last_used = time.time()
            return True

        async with self._load_lock:
            # 双重检查
            if self._model is not None:
                return True

            path = self._get_normalized_path()
            if not path or not path.is_file():
                logger.error("[AI/Local] 模型路径无效，无法加载: %s", self._config.local_model_path)
                return False

            logger.info("[AI/Local] 正在加载本地模型 | 目标路径: %s | 原始输入: %s", path, self._config.local_model_path)
            start = time.time()

            try:
                # 在独立线程中加载，防止阻塞 Streamlit 事件轮询
                self._model = await asyncio.to_thread(self._load_model_sync, str(path))
                
                elapsed = time.time() - start
                self._available = True
                self._last_used = time.time()
                logger.info("[AI/Local] 模型加载完成 (%.1fs) | 生效 n_ctx: %d", elapsed, self._effective_n_ctx)
                return True
            except Exception as exc:
                logger.error("[AI/Local] 模型加载崩溃: %s", exc)
                self._model = None
                self._available = False
                return False

    def _estimate_tokens(self, text: str) -> int:
        """使用 llama.cpp 内置 tokenizer 精确估算 Token 数量
        
        如果 tokenizer 不可用，退回字符级粗估 (1 token ≈ 3 chars)
        """
        if self._model is not None:
            try:
                tokens = self._model.tokenize(text.encode("utf-8", errors="ignore"))
                return len(tokens)
            except Exception:
                pass
        
        # 粗估回退: 中文约 1 token/字，英文约 1 token/4字符，混合取 1:3
        return len(text) // 3

    def _preflight_check(self, system_prompt: str, user_prompt: str, max_tokens: int) -> Optional[str]:
        """🛡️ Token 预飞检查: 在发送给 C++ 前验证总 Token 不超出上下文
        
        Returns:
            None: 检查通过
            str: 拒绝原因 (人类可读)
        """
        if self._model is None:
            return "模型未加载"
        
        sys_tokens = self._estimate_tokens(system_prompt)
        usr_tokens = self._estimate_tokens(user_prompt)
        total_input = sys_tokens + usr_tokens
        total_required = total_input + max_tokens
        
        available = self._effective_n_ctx
        
        if total_required > available:
            return (
                f"Token 预算溢出: 输入 {total_input} ({sys_tokens} system + {usr_tokens} user) "
                f"+ 响应预留 {max_tokens} = {total_required} > 上下文窗口 {available}。"
                f"请减少代码长度或增加 n_ctx。"
            )
        
        # 检查响应空间是否足够
        remaining_for_response = available - total_input
        if remaining_for_response < MIN_RESPONSE_BUDGET:
            return (
                f"响应空间不足: 输入占用 {total_input} Token，"
                f"仅剩余 {remaining_for_response} Token 给模型响应 (最低需要 {MIN_RESPONSE_BUDGET})。"
            )
        
        logger.debug(
            "[AI/Local] 预飞检查通过: %d + %d + %d = %d / %d",
            sys_tokens, usr_tokens, max_tokens, total_required, available
        )
        return None

    def _infer_sync(self, system_prompt: str, user_prompt: str, temperature: float, max_tokens: int) -> str:
        """同步推理逻辑 (带互斥锁 + 预飞检查)"""
        if self._model is None:
            return ""
        
        # 🛡️ 预飞检查: 在 C++ 调用前拦截溢出
        preflight_error = self._preflight_check(system_prompt, user_prompt, max_tokens)
        if preflight_error:
            logger.warning("[AI/Local] 预飞检查拦截: %s", preflight_error)
            # 抛出异常让上层 AIEngine._predict 的 except 块捕获
            # 而非返回伪装安全的 JSON（之前返回 is_vulnerable=false 会导致危险代码被误判为安全）
            raise RuntimeError(f"预飞检查失败: {preflight_error}")
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        
        # 🔒 互斥锁: 确保 llama.cpp 同一时刻只处理一个请求
        # 这是防止 GGML_ASSERT(!sched->is_alloc) 断言失败的核心防线
        with self._infer_lock:
            try:
                response = self._model.create_chat_completion(
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    top_p=0.9,
                    repeat_penalty=1.1,
                )
            except Exception as e:
                # 🔄 崩溃恢复: 标记模型需要重载
                logger.error("[AI/Local] C++ 推理层异常，标记模型重载: %s", e)
                self._needs_reload = True
                raise
        
        choices = response.get("choices", [])
        if choices:
            return choices[0].get("message", {}).get("content", "")
        return ""

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 512,
    ) -> str:
        """执行本地 LLM 推理 (企业级加固)"""
        
        if not await self._ensure_loaded():
            raise RuntimeError("本地模型加载失败，请检查模型路径配置。")
            
        try:
            # 在独立线程执行推理，避开 GIL 限制且不阻塞渲染
            result = await asyncio.to_thread(
                self._infer_sync,
                system_prompt,
                user_prompt,
                temperature,
                max_tokens
            )
            
            self._last_used = time.time()
            if not result:
                logger.warning("[AI/Local] 推理返回空结果，疑似模型生成异常")
                return "AI 助手暂时无法生成回复。"
            
            return result
        except Exception as e:
            logger.error("[AI/Local] 推理过程中出错: %s", e)
            # 不再返回错误字符串让上层误判为有效输出
            # 而是抛出异常让 AIEngine._predict 的 except 块捕获
            raise RuntimeError(f"本地推理出错: {str(e)}")

    async def shutdown(self) -> None:
        """卸载模型，释放物理内存"""
        if self._model is not None:
            logger.info("[AI/Local] 正在卸载模型，释放物理内存...")
            # 显式置空并触发 GC 强制回收
            self._model = None
            gc.collect()
            self._available = False
            self._effective_n_ctx = 0
            logger.info("[AI/Local] 模型已卸载")

    async def check_idle_unload(self) -> None:
        """检查是否需要因空闲超时而卸载模型"""
        if self._model is None:
            return

        idle_seconds = time.time() - self._last_used
        if idle_seconds > self._config.idle_unload_seconds:
            logger.info(
                "[AI/Local] 模型空闲 %.0fs, 自动启动降温卸载",
                idle_seconds,
            )
            await self.shutdown()
