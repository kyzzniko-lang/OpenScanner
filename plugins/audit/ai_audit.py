"""
plugins/audit/ai_audit.py — 基于 AI 的深度源码审计插件 (Enterprise Hardened)

该插件不同于常规的基于正则和 AST 的扫描，它直接将筛选后的敏感代码文件
发送给 AI 模型（LLM），利用模型的大规模推理能力发现逻辑漏洞、
鉴权缺陷以及复杂的攻击链映射。

企业级加固:
  • 串行化审计: 逐文件发送给 AI (避免并发争夺本地模型)
  • 单文件超时: 60 秒超时保护，防止单文件卡死全流程
  • 优雅降级: AI 引擎不可用时不阻塞常规审计
  • 进度日志: 每个文件审计完成后输出进度
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.request import AsyncRequester
from plugins.base import BasePlugin, PluginMeta, ScanResult, Severity

logger = logging.getLogger("openscanner.plugin.ai_audit")

# ── 安全常量 ──
SINGLE_FILE_TIMEOUT = 120      # 单文件 AI 审计超时 (秒)
MAX_FILES_TO_AUDIT = 30        # 最大审计文件数 (提高审计覆盖深度)
MAX_FILE_SIZE_BYTES = 70_000   # 最大文件大小 70KB (自适应 Token 预算)


class AICodeAuditPlugin(BasePlugin):
    """
    AI 驱动的深度代码审计插件 (企业级加固版)
    
    关键安全特性:
      - 串行化审计: 逐文件处理，避免并发争夺底层 C++ 资源
      - Token 预算感知: 与 AIEngine 配合，动态限制代码长度
      - 优雅降级: 单文件失败不影响后续文件
    """

    meta = PluginMeta(
        name="ai_code_audit",
        display_name="AI Deep Code Auditor",
        description="利用大模型 (LLM) 进行深度逻辑漏洞与架构安全审计",
        severity=Severity.HIGH,
        tags=["sast", "ai", "audit", "logic-vulnerability"],
        version="2.0.0",
    )

    async def check(
        self,
        url: str,
        requester: AsyncRequester,
        context: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        """在这里 url 被复用做为本地路径"""
        
        target_path = Path(url).resolve()
        if not target_path.exists() or not target_path.is_dir():
            return self.result(url, is_vulnerable=False, detail="非本地目录")

        ai_engine = context.get("ai_engine") if context else None
        if not ai_engine or not getattr(ai_engine, "is_enabled", False):
            logger.warning("AI 引擎未启用或不可用，跳过 AI 审计插件。")
            return ScanResult(
                plugin_name=self.meta.name,
                url=url,
                is_vulnerable=False,
                severity=Severity.INFO,
                detail="🤖 AI 深度审计已跳过：AI 引擎未启用。",
                evidence="未检测到活动的 AI 配置。请在侧边栏中开启 AI 支持以运行深度逻辑审计。",
                extra={
                    "is_ai_result": True,
                    "total_issues": 0,
                    "findings": []
                }
            )

        logger.info("🤖 AI 审计插件启动，正在分析目录: %s", target_path)

        # 1. 筛选敏感文件 (避免扫描 node_modules, .git 等)
        EXT_MAP = {
            ".py": "python",
            ".php": "php",
            ".js": "javascript",
            ".go": "go",
            ".java": "java",
            ".sql": "sql",
        }
        
        # 排除目录关键词 (必须是目录名的精确匹配)
        EXCLUDE_DIRS = [
            "node_modules", "vendor", ".git", "static", "tests",
            "env", "__pycache__", ".venv", "venv", "dist", "build",
        ]
        
        # 优先扫描这些关键词相关的文件
        priority_keywords = [
            "ctrl", "route", "api", "auth", "login", "user",
            "db", "logic", "service", "admin", "payment", "session",
            "shell", "backdoor", "upload", "cmd", "exec",
        ]
        
        files_to_audit: List[Tuple[Path, str]] = []
        try:
            for ext, lang in EXT_MAP.items():
                for f in target_path.rglob(f"*{ext}"):
                    # 核心修正：仅排除特定名称的整个目录，防止误杀 "test_01" 等
                    if any(p in f.parts for p in EXCLUDE_DIRS):
                        continue
                    
                    # 文件大小限制
                    try:
                        fsize = f.stat().st_size
                    except OSError:
                        continue
                    
                    if fsize > MAX_FILE_SIZE_BYTES or fsize == 0:
                        continue
                        
                    files_to_audit.append((f, lang))
        except Exception as e:
            logger.error("文件筛选失败: %s", e)

        if not files_to_audit:
            return ScanResult(
                plugin_name=self.meta.name,
                url=url,
                is_vulnerable=False,
                severity=Severity.INFO,
                detail="🤖 AI 深度审计完成：未发现可审计的敏感源文件。",
                evidence="当前目录未包含匹配的源代码文件，或文件大小超出预设阈值。",
                extra={
                    "is_ai_result": True,
                    "total_issues": 0,
                    "findings": []
                }
            )

        # 2. 排序：将包含优先关键词的文件排在前面
        def priority_sort(item):
            path_str = str(item[0]).lower()
            for i, kw in enumerate(priority_keywords):
                if kw in path_str:
                    return i
            return len(priority_keywords)
        
        files_to_audit.sort(key=priority_sort)
        files_to_audit = files_to_audit[:MAX_FILES_TO_AUDIT]

        # 3. 🔒 串行逐文件审计 (关键修复: 不再使用 asyncio.gather)
        #    本地 llama.cpp 不是线程安全的，并行会导致 GGML 断言失败
        all_ai_findings = []
        total_vulnerable_files = 0
        total_files = len(files_to_audit)
        failed_files = 0

        for idx, (filepath, lang) in enumerate(files_to_audit, 1):
            logger.info(
                "🤖 AI 审计进度 [%d/%d]: %s",
                idx, total_files, filepath.name
            )

            try:
                # 单文件超时保护: 防止单个文件的 AI 推理卡死整个流程
                res = await asyncio.wait_for(
                    self._audit_single_file(ai_engine, filepath, lang),
                    timeout=SINGLE_FILE_TIMEOUT,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "⏱️ AI 审计文件 %s 超时 (%ds)，跳过",
                    filepath.name, SINGLE_FILE_TIMEOUT
                )
                failed_files += 1
                continue
            except Exception as e:
                logger.error("AI 审计文件 %s 异常: %s", filepath.name, e)
                failed_files += 1
                continue

            # res 为 None 表示 AI 调用失败，无法判定
            if res is None:
                failed_files += 1
                continue

            if res and res.get("is_vulnerable"):
                total_vulnerable_files += 1
                try:
                    f_path = str(filepath.relative_to(target_path))
                except ValueError:
                    f_path = str(filepath.name)

                for finding in res.get("findings", []):
                    finding["file"] = f_path
                    all_ai_findings.append(finding)

        # 4. 汇总结果
        if not all_ai_findings:
            return ScanResult(
                plugin_name=self.meta.name,
                url=url,
                is_vulnerable=False,
                severity=Severity.INFO,
                detail="🤖 AI 深度审计完成：未发现显著安全逻辑风险。",
                evidence="审计已覆盖筛选的核心业务文件，当前逻辑未见异常。",
                extra={
                    "is_ai_result": True,
                    "total_issues": 0,
                    "findings": []
                }
            )

        # 计算最高等级
        severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_sev_str = "low"
        max_val = 0
        for f in all_ai_findings:
            s = f.get("severity", "low").lower()
            val = severity_map.get(s, 1)
            if val > max_val:
                max_val = val
                max_sev_str = s

        sev = Severity(max_sev_str) if max_sev_str in [s.value for s in Severity] else Severity.HIGH

        # 构建展示证据
        evidence_lines = [f"🤖 AI 在 {total_vulnerable_files} 个文件中发现了 {len(all_ai_findings)} 个逻辑安全点:"]
        for f in all_ai_findings[:5]:
            evidence_lines.append(f"- [{f.get('type')}] {f.get('file')}:{f.get('line')} -> {f.get('description')}")
        
        if len(all_ai_findings) > 5:
            evidence_lines.append(f"... 等共计 {len(all_ai_findings)} 处发现")

        extra_data = {
            "findings": all_ai_findings,
            "total_issues": len(all_ai_findings),
            "is_ai_result": True,
        }

        return ScanResult(
            plugin_name=self.meta.name,
            url=url,
            is_vulnerable=max_val >= 3,  # 只有 High 或 Critical 才认定为传统“漏洞”
            severity=sev,
            detail=f"🤖 AI 深度审计报告: 发现 {len(all_ai_findings)} 个潜在安全逻辑风险",
            evidence="\n".join(evidence_lines),
            extra=extra_data
        )

    async def _audit_single_file(self, ai_engine: Any, filepath: Path, language: str) -> Dict[str, Any]:
        """调用 AI 引擎审计单个文件

        返回值约定:
          - {"is_vulnerable": True, "findings": [...]} — AI 发现了问题
          - {"is_vulnerable": False} — AI 明确判定安全 (仅当 AI 成功返回且主动声明安全时)
          - None — AI 调用失败/超时，无法判定，交由上层决定是否跳过
        """
        try:
            content = await asyncio.to_thread(filepath.read_text, encoding="utf-8", errors="ignore")

            if not content.strip():
                return {"is_vulnerable": False}

            # 使用 AIEngine 提供的高级业务接口 analyze_code_deeply
            # 该方法内部会做 Token 预算管理并动态截断代码
            ai_response = await ai_engine.analyze_code_deeply(
                code=content,
                language=language,
                filepath=str(filepath.name)
            )

            if ai_response.success:
                parsed = ai_response.parsed
                # 安全校验: 确保返回的结构包含必要字段
                if not isinstance(parsed, dict):
                    logger.warning("AI 审计文件 %s 返回非字典结构，视为失败", filepath.name)
                    return None

                # 如果 AI 返回了 findings 列表且非空，强制设 is_vulnerable=True
                # 防止模型返回了 findings 但 is_vulnerable 却设为 false 的矛盾情况
                findings = parsed.get("findings", [])
                if findings and isinstance(findings, list) and len(findings) > 0:
                    parsed["is_vulnerable"] = True

                return parsed
            else:
                logger.warning("AI 审计文件 %s 未成功: %s", filepath.name, ai_response.error)
                # 返回 None 表示"无法判定"，而非 is_vulnerable=False（即不伪装安全）
                return None
        except Exception as e:
            logger.error("AI 文件审计异常 %s: %s", filepath.name, e)
            return None
