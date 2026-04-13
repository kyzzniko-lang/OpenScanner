"""
core/ai/engine.py — OpenScanner Hybrid AI 指挥引擎

核心枢纽 — 管理 Provider 生命周期、Prompt 路由、结果缓存和自动降级：

  ┌──────────────────────────────────────────────────────┐
  │                    AIEngine (Singleton)                │
  ├──────────────────────────────────────────────────────┤
  │  Factory Pattern:                                     │
  │    mode=OFF   → NullProvider (无操作)                  │
  │    mode=LOCAL → LocalAIProvider (llama-cpp-python)     │
  │    mode=API   → APIProvider (OpenAI / Gemini)          │
  ├──────────────────────────────────────────────────────┤
  │  高级功能:                                             │
  │    • JSON 响应自动解析 + 容错                          │
  │    • 研判结果文件缓存 (hash-based dedup)               │
  │    • 空闲模型自动卸载 (idle_unload_seconds)            │
  │    • API 异常时静默降级为 OFF                           │
  └──────────────────────────────────────────────────────┘

Usage:
    from core.ai.engine import AIEngine
    from core.ai.base import AIConfig, AIMode

    config = AIConfig(mode=AIMode.LOCAL, local_model_path="./models/qwen.gguf")
    engine = AIEngine(config)

    result = await engine.audit_code("eval($_POST['cmd'])", language="php")
    result = await engine.verify_exploit(request_data, response_data)
    result = await engine.suggest_bypass(payload, waf_info)
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.ai.base import (
    AbstractAIProvider,
    AIConfig,
    AIMode,
    AIResponse,
    AIRole,
)
from core.ai.preprocessor import AIPreprocessor
from core.ai.debate import DebateOrchestrator
from core.ai.rlhf import RLHFManager
from core.ai.prompts import (
    get_system_prompt,
    get_user_template,
)

logger = logging.getLogger("openscanner.ai.engine")


class AIEngine:
    """OpenScanner Hybrid AI 指挥引擎

    根据 AIConfig.mode 动态选择推理后端，
    并提供三个面向业务的高层 API：audit_code / verify_exploit / suggest_bypass。
    """

    def __init__(self, config: Optional[AIConfig] = None) -> None:
        self._config = config or AIConfig()
        self._provider: Optional[AbstractAIProvider] = None
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._initialized = False
        self._total_calls = 0
        self._total_latency = 0.0
        
        self.rlhf_manager = RLHFManager()
        self.debate_orchestrator = DebateOrchestrator(self)

    @property
    def mode(self) -> AIMode:
        return self._config.mode

    @property
    def is_enabled(self) -> bool:
        return self._config.mode != AIMode.OFF

    @property
    def stats(self) -> Dict[str, Any]:
        """AI 引擎运行统计"""
        avg_latency = (
            self._total_latency / self._total_calls if self._total_calls > 0 else 0
        )
        return {
            "mode": self._config.mode.name,
            "provider": self._provider.provider_name if self._provider else "none",
            "total_calls": self._total_calls,
            "avg_latency_ms": round(avg_latency, 1),
            "cache_size": len(self._cache),
            "initialized": self._initialized,
        }

    # ── 初始化与生命周期 ──────────────────────

    async def initialize(self) -> Tuple[bool, str]:
        """根据配置初始化对应的 AI Provider
        
        Returns:
            (success, message)
        """
        # 如果已经初始化且配置未变，直接返回
        if self._initialized and self._provider:
            return True, "AI 引擎已就绪"

        if self._config.mode == AIMode.OFF:
            logger.info("[AI] AI 引擎已关闭 (mode=OFF)")
            self._initialized = True
            self._provider = None
            return True, "AI 引擎已关闭"

        if self._config.mode == AIMode.LOCAL:
            from core.ai.local_provider import LocalAIProvider
            self._provider = LocalAIProvider(self._config)

            if not self._provider.is_available():
                msg = (
                    f"本地模型不可用 (路径: {self._config.local_model_path})。\n"
                    "请确保: 1. 已安装 llama-cpp-python; 2. GGUF 文件路径正确且可读。"
                )
                logger.warning("[AI] %s", msg)
                self._provider = None
                return False, msg

        elif self._config.mode == AIMode.API:
            from core.ai.api_provider import APIProvider
            self._provider = APIProvider(self._config)

            if not self._provider.is_available():
                self._provider = None
                return False, "API 配置不完整，请检查 api_key 和 api_base_url"
        
        # 加载缓存
        self._load_cache()
        self._initialized = True
        msg = f"AI 引擎已就绪 (mode={self._config.mode.name})"
        logger.info("[AI] %s", msg)
        return True, msg

    async def shutdown(self) -> None:
        """释放所有资源"""
        if self._provider:
            await self._provider.shutdown()
            self._provider = None

        # 持久化缓存
        self._save_cache()
        self._initialized = False
        logger.info("[AI] AI 引擎已关闭")

    # ── 高层业务 API ─────────────────────────

    async def audit_code(
        self,
        code: str,
        language: str = "python",
        filepath: str = "unknown",
        reason: str = "suspicious pattern detected",
    ) -> AIResponse:
        """使用 AUDITOR 角色分析代码片段是否包含恶意行为

        Args:
            code:     代码片段文本
            language: 编程语言 ("python" / "php")
            filepath: 代码文件路径 (用于上下文)
            reason:   静态分析标记原因

        Returns:
            AIResponse: 包含 is_malicious / confidence / category / reasoning
        """
        if not self.is_enabled or not self._provider:
            return AIResponse(success=False, error="AI 引擎未启用")

        # 截断过长代码
        truncated = code[: self._config.max_code_length]

        user_template = get_user_template("AUDITOR", self._config.language)
        user_prompt = user_template.format(
            language=language,
            code=truncated,
            filepath=filepath,
            reason=reason,
        )

        system_prompt = get_system_prompt("AUDITOR", self._config.language)
        return await self._predict(
            role=AIRole.AUDITOR,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

    async def analyze_code_deeply(
        self,
        code: str,
        language: str = "python",
        filepath: str = "unknown",
    ) -> AIResponse:
        """使用 SAST_AI_AUDITOR 角色，对源文件执行深度安全逻辑审计
        
        企业级加固:
          - 动态 Token 预算管理: 根据 n_ctx 反算可用空间
          - 自适应截断: 确保 system + user + response 不超出上下文
          - 预算不足时优雅降级: 返回明确错误而非崩溃
        
        Args:
            code:     代码文本
            language: 编程语言
            filepath: 文件路径
            
        Returns:
            AIResponse: 包含 findings (逻辑漏洞列表) / summary / is_vulnerable
        """
        if not self.is_enabled or not self._provider:
            return AIResponse(success=False, error="AI 引擎未启用")

        system_prompt = get_system_prompt("SAST_AI_AUDITOR", self._config.language)
        user_template = get_user_template("SAST_AI_AUDITOR", self._config.language)
        
        # ── Token 预算管理 ──
        # 粗估各部分 Token 数 (1 token ≈ 3 chars 混合文本)
        CHARS_PER_TOKEN = 3
        SAFETY_MARGIN = 100  # 安全边际 Token 数
        
        system_tokens = len(system_prompt) // CHARS_PER_TOKEN
        template_overhead = len(user_template) // CHARS_PER_TOKEN  # 模板自身的固定文本
        response_tokens = self._config.local_max_tokens
        
        # 获取实际可用的 n_ctx
        n_ctx = self._config.local_n_ctx
        if hasattr(self._provider, '_effective_n_ctx') and self._provider._effective_n_ctx > 0:
            n_ctx = self._provider._effective_n_ctx
        
        # 计算代码可用的 Token 预算
        code_budget_tokens = n_ctx - system_tokens - template_overhead - response_tokens - SAFETY_MARGIN
        
        if code_budget_tokens < 100:
            return AIResponse(
                success=False,
                error=f"Token 预算不足: 上下文 {n_ctx} - 系统提示 {system_tokens} - "
                      f"模板 {template_overhead} - 响应预留 {response_tokens} = "
                      f"{code_budget_tokens} Token，无法容纳有效代码。请增大 n_ctx 或使用 API 模式。"
            )
        
        # 反算字符截断长度
        max_code_chars = min(
            code_budget_tokens * CHARS_PER_TOKEN,
            self._config.max_code_length,
            len(code),
        )
        
        truncated = code[:max_code_chars]
        
        if len(code) > max_code_chars:
            logger.info(
                "[AI] 代码截断: %s 原始 %d 字符 → %d 字符 (预算 %d tokens)",
                filepath, len(code), max_code_chars, code_budget_tokens
            )

        user_prompt = user_template.format(
            language=language,
            code=truncated,
            filepath=filepath,
        )

        return await self._predict(
            role=AIRole.SAST_AI_AUDITOR,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )


    async def verify_consensus(
        self,
        url: str,
        method: str,
        param: str,
        attempts: List[Dict[str, Any]],
        waf_detected: bool = False,
    ) -> AIResponse:
        """使用 EXPLOIT_VERIFIER 角色，基于全量证据矩阵 (Attempts Matrix) 进行共识研判。
        
        Args:
            url: 目标 URL
            method: 请求方法
            param: 探测参数
            attempts: 探测记录列表 (Matrix)
            waf_detected: WAF 检测状态
            
        Returns:
            AIResponse: 包含最终共识判定。
        """
        if not self.is_enabled or not self._provider:
            return AIResponse(success=False, error="AI 引擎未启用")

        # 1. 格式化证据矩阵
        matrix_rows = []
        for i, att in enumerate(attempts[:20], 1):  # 限制前 20 条，防止超长
            row = f"[{i}] Type:{att.get('type','?')} | Status:{att.get('status','?')} | Payload:{att.get('payload', att.get('payload_true','?'))}"
            if "fingerprint_diff" in att:
                row += f" | Diff:{att['fingerprint_diff']:.4f}"
            if "elapsed" in att:
                row += f" | Delay:{att['elapsed']:.2f}s"
            matrix_rows.append(row)
        
        matrix_text = "\n".join(matrix_rows)
        if len(attempts) > 20:
            matrix_text += f"\n... (还有 {len(attempts)-20} 条记录已隐藏)"

        # 2. 找到最成功的请求作为主证据样本
        best_hit = next((a for a in attempts if a.get("status") in ("Vulnerable", "Suspicious")), attempts[0] if attempts else {})
        
        user_template = get_user_template("EXPLOIT_VERIFIER", self._config.language)
        user_prompt = user_template.format(
            url=url,
            method=method,
            param=param,
            waf_detected=waf_detected,
            payload_matrix=matrix_text,
            status_code=best_hit.get("status_code", 200),
            response_time=best_hit.get("elapsed", 0) * 1000,
            content_length=0,  # 矩阵模式下此项通过 payload_matrix 体现
            response_body="[见证据矩阵详述]",
        )

        system_prompt = get_system_prompt("EXPLOIT_VERIFIER", self._config.language)
        return await self._predict(
            role=AIRole.EXPLOIT_VERIFIER,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

    async def suggest_bypass(
        self,
        payload: str = "",
        waf_type: str = "Unknown",
        status_code: int = 403,
        attempted_techniques: str = "",
        blocked_chars: str = "",
        db_type: str = "Unknown",
        vuln_type: str = "sqli",
    ) -> AIResponse:
        """使用 BYPASS_EXPERT 角色生成 WAF 绕过建议

        Returns:
            AIResponse: 包含 suggestions[{payload, technique, explanation}]
        """
        if not self.is_enabled or not self._provider:
            return AIResponse(success=False, error="AI 引擎未启用")

        user_template = get_user_template("BYPASS_EXPERT", self._config.language)
        user_prompt = user_template.format(
            payload=payload,
            waf_type=waf_type,
            status_code=status_code,
            attempted_techniques=attempted_techniques,
            blocked_chars=blocked_chars,
            db_type=db_type,
            vuln_type=vuln_type,
        )

        system_prompt = get_system_prompt("BYPASS_EXPERT", self._config.language)
        return await self._predict(
            role=AIRole.BYPASS_EXPERT,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

    # ── 核心推理调度 ─────────────────────────

    async def _predict(
        self,
        role: AIRole,
        system_prompt: str,
        user_prompt: str,
    ) -> AIResponse:
        """统一的推理调度入口

        流程:
          1. 检查缓存
          2. 调用 Provider 推理
          3. 解析 JSON 响应
          4. 写入缓存
          5. 返回结构化结果
        """
        response = AIResponse(role=role)

        if not self._provider:
            response.error = "AI Provider 不可用"
            return response

        response.provider = self._provider.provider_name

        # ── 检查缓存 ──
        cache_key = self._cache_key(role.value, user_prompt)
        if self._config.cache_enabled and cache_key in self._cache:
            cached = self._cache[cache_key]
            response.success = True
            response.parsed = cached.get("parsed", {})
            response.confidence = cached.get("confidence", 0.0)
            response.raw_text = cached.get("raw_text", "")
            response.latency_ms = 0.0  # 缓存命中
            logger.debug("[AI] 缓存命中 (role=%s)", role.value)
            return response

        # ── 执行推理 ──
        start = time.time()
        try:
            raw_text = await self._provider.generate(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=self._config.local_temperature
                if self._config.mode == AIMode.LOCAL
                else self._config.api_temperature,
                max_tokens=self._config.local_max_tokens,
            )
            elapsed_ms = (time.time() - start) * 1000

            response.raw_text = raw_text
            response.latency_ms = elapsed_ms
            self._total_calls += 1
            self._total_latency += elapsed_ms

            # ── 解析 JSON ──
            # CHAT_ASSISTANT 角色通常返回纯文本，不需要 JSON 解析
            if role == AIRole.CHAT_ASSISTANT:
                response.success = True
                response.parsed = {}
                response.confidence = 1.0
            else:
                parsed = self._parse_json_response(raw_text)
                if parsed is not None:
                    response.success = True
                    response.parsed = parsed
                    response.confidence = parsed.get("confidence", 0.0)

                    # 写入缓存
                    if self._config.cache_enabled:
                        self._cache[cache_key] = {
                            "parsed": parsed,
                            "confidence": response.confidence,
                            "raw_text": raw_text,
                            "timestamp": time.time(),
                        }
                else:
                    # 判定为推理成功但格式不对，设置为 success 为 False 以触发重新推理或警告
                    response.success = False
                    response.error = f"JSON 解析失败。模型返回可能不符合预期格式。原始输出前 100 字: {raw_text[:100]}..."
                    logger.warning("[AI] JSON 解析失败，原始输出: %s", raw_text[:200])

            logger.info(
                "[AI] 推理完成 (role=%s, provider=%s, %.0fms, confidence=%.2f)",
                role.name,  # 改为 name 提高可读性
                response.provider,
                elapsed_ms,
                response.confidence,
            )

        except Exception as exc:
            # 强化异常转义
            err_msg = str(exc)
            if not err_msg and hasattr(exc, "__class__"):
                err_msg = exc.__class__.__name__
            
            response.error = err_msg
            response.success = False
            response.latency_ms = (time.time() - start) * 1000
            logger.error("[AI] 推理失败 (role=%s): %s", role.name, err_msg)

        return response

    # ── JSON 解析 ────────────────────────────

    @staticmethod
    def _parse_json_response(text: str) -> Optional[Dict[str, Any]]:
        """从 LLM 输出中提取并修复 JSON (强化版：支持探测全文本中的所有候选块)"""
        if not text:
            return None
        
        text = text.strip()

        # 1. 尝试直接清理 HTML/Markdown 包装
        import re
        clean_text = re.sub(r"```(?:json)?\s*\n?(.*?)\n?```", r"\1", text, flags=re.DOTALL).strip()
        try:
            return json.loads(clean_text)
        except Exception:
            pass

        # 辅助清理函数: 修复单引号、末尾逗号等常见 LLM 错误
        def clean_json_str(s: str) -> str:
            # 将 'key': 'value' 转换为 "key": "value"
            s = re.sub(r"\'(\w+)\'\s*:", r'"\1":', s)
            s = re.sub(r":\s*\'(.*?)\'", r': "\1"', s)
            # 常见末尾逗号修复
            s = re.sub(r",\s*([\]}])", r"\1", s)
            return s

        # 2. 启发式遍历：寻找所有 '{' 并尝试匹配平衡括号
        brace_indices = [i for i, char in enumerate(text) if char == '{']
        
        candidates = []
        for start_idx in brace_indices:
            depth = 0
            for i in range(start_idx, len(text)):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        substring = text[start_idx : i + 1]
                        try:
                            # 尝试多种解析策略
                            parsed = None
                            try:
                                parsed = json.loads(substring)
                            except json.JSONDecodeError:
                                try:
                                    # 尝试自动修复语法错误
                                    parsed = json.loads(clean_json_str(substring))
                                except Exception:
                                    pass
                            
                            if isinstance(parsed, dict):
                                # 对识别出的字典进行权重评分 (含有业务关键字段的优先)
                                score = 0
                                p_keys = list(parsed.keys())
                                # 漏洞研判关键词
                                if "is_exploited" in p_keys or "is_malicious" in p_keys: score += 10
                                if "confidence" in p_keys: score += 5
                                if "reasoning" in p_keys or "evidence" in p_keys: score += 5
                                # 绕过建议关键词
                                if "suggestions" in p_keys: score += 10
                                # SAST 深度审计关键词
                                if "findings" in p_keys: score += 10
                                if "is_vulnerable" in p_keys: score += 10
                                if "summary" in p_keys: score += 3
                                
                                candidates.append((score, len(substring), parsed))
                        except Exception:
                            pass
                        # 找到第一个平衡块后即可跳出内循环，继续下一个起始点
                        break
        
        if candidates:
            # 返回评分最高且内容最丰富的候选者
            candidates.sort(key=lambda x: (-x[0], -x[1]))
            return candidates[0][2]

        return None

    # ── 缓存管理 ─────────────────────────────

    @staticmethod
    def _cache_key(role: str, prompt: str) -> str:
        """生成基于内容哈希的缓存键"""
        content = f"{role}:{prompt}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]

    def _load_cache(self) -> None:
        """从文件加载缓存"""
        if not self._config.cache_enabled:
            return
        cache_path = Path(self._config.cache_file)
        if cache_path.exists():
            try:
                data = json.loads(cache_path.read_text(encoding="utf-8"))
                self._cache = data
                logger.info("[AI] 已加载 %d 条缓存记录", len(self._cache))
            except Exception as exc:
                logger.debug("[AI] 缓存文件读取失败: %s", exc)

    def _save_cache(self) -> None:
        """持久化缓存到文件"""
        if not self._config.cache_enabled or not self._cache:
            return
        try:
            cache_path = Path(self._config.cache_file)
            cache_path.write_text(
                json.dumps(self._cache, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            logger.info("[AI] 已保存 %d 条缓存记录", len(self._cache))
        except Exception as exc:
            logger.debug("[AI] 缓存保存失败: %s", exc)
