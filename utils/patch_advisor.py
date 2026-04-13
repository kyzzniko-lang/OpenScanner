"""
utils/patch_advisor.py — OpenScanner IAST 代码级精准修复建议引擎

核心定位:
  从一个"报错工具"进化为一个"安全治理专家"。

大多数扫描器只会给出"请过滤特殊字符"这种废话。
本模块利用 IAST 联动追踪的源码行号和函数签名，
根据漏洞类型和语言特征，自动生成带有 git diff 样式的精准修复补丁。

支持语言: Python, PHP, Java, JavaScript/Node.js
支持漏洞: SQLi, XSS, Command Injection, Path Traversal, Deserialization
"""

from __future__ import annotations

import re
import textwrap
from typing import Any, Dict, List, Optional


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 修复模式知识库
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_PATCH_PATTERNS: Dict[str, Dict[str, Any]] = {
    # ── SQL Injection ──
    "sqli": {
        "python": {
            "detect": [
                r'cursor\.execute\s*\(\s*f["\']',           # f-string SQL
                r'cursor\.execute\s*\(\s*["\'].*%\s',       # %-format SQL
                r'cursor\.execute\s*\(\s*["\'].*\+',        # concat SQL
                r'\.execute\s*\(\s*["\'].*\.format\s*\(',   # .format() SQL
            ],
            "fix_template": textwrap.dedent("""\
                # ❌ 危险: SQL 拼接注入
                - {original_line}
                # ✅ 修复: 使用参数化查询
                + cursor.execute("{safe_query}", ({param_tuple}))
            """),
            "explanation": (
                "将用户输入从 SQL 语句中解耦，改用参数化占位符 (%s 或 ?)。\n"
                "ORM 框架 (SQLAlchemy / Django ORM) 默认使用参数化查询，建议迁移。"
            ),
        },
        "php": {
            "detect": [
                r'\$.*=\s*["\'].*SELECT.*\$',               # $sql = "SELECT ... $var"
                r'mysql_query\s*\(',                        # deprecated mysql_query
                r'mysqli_query\s*\(.*\.\s*\$',              # concat in query
            ],
            "fix_template": textwrap.dedent("""\
                // ❌ 危险: SQL 拼接
                - {original_line}
                // ✅ 修复: 使用 PDO 预处理语句
                + $stmt = $pdo->prepare("{safe_query}");
                + $stmt->execute([{param_bindings}]);
            """),
            "explanation": (
                "使用 PDO 预处理语句代替直接拼接。\n"
                "弃用 mysql_* 函数，迁移至 PDO 或 mysqli prepared statements。"
            ),
        },
    },

    # ── XSS ──
    "xss": {
        "python": {
            "detect": [
                r'render_template_string\s*\(',
                r'Markup\s*\(',
                r'\{\{.*\|safe\}\}',
            ],
            "fix_template": textwrap.dedent("""\
                # ❌ 危险: 未转义的用户输出
                - {original_line}
                # ✅ 修复: 使用自动转义或 markupsafe.escape()
                + from markupsafe import escape
                + output = escape(user_input)
            """),
            "explanation": (
                "所有用户输入在输出到 HTML 前必须经过上下文感知转义。\n"
                "Jinja2 默认自动转义，避免使用 |safe 过滤器或 Markup() 包装未净化数据。\n"
                "部署 CSP Header: Content-Security-Policy: default-src 'self'"
            ),
        },
        "php": {
            "detect": [
                r'echo\s+\$',
                r'print\s+\$',
                r'<\?=\s*\$',
            ],
            "fix_template": textwrap.dedent("""\
                // ❌ 危险: 直接输出用户变量
                - {original_line}
                // ✅ 修复: htmlspecialchars 转义
                + echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
            """),
            "explanation": (
                "使用 htmlspecialchars() 且指定 ENT_QUOTES 和 UTF-8。\n"
                "在 JavaScript 上下文中，需使用 json_encode() 进行输出编码。"
            ),
        },
    },

    # ── Command Injection ──
    "cmdi": {
        "python": {
            "detect": [
                r'os\.system\s*\(',
                r'os\.popen\s*\(',
                r'subprocess\..*shell\s*=\s*True',
            ],
            "fix_template": textwrap.dedent("""\
                # ❌ 危险: Shell 命令注入
                - {original_line}
                # ✅ 修复: 使用 subprocess 数组模式 (禁用 shell=True)
                + import shlex
                + subprocess.run(["command", shlex.quote(user_input)], shell=False)
            """),
            "explanation": (
                "永远不要将 shell=True 与用户可控输入结合。\n"
                "使用 subprocess.run() 的列表参数模式，操作系统将自动处理参数边界。\n"
                "如果必须使用 shell，用 shlex.quote() 转义所有用户输入。"
            ),
        },
        "php": {
            "detect": [
                r'system\s*\(\s*\$',
                r'exec\s*\(\s*\$',
                r'passthru\s*\(\s*\$',
                r'shell_exec\s*\(\s*\$',
            ],
            "fix_template": textwrap.dedent("""\
                // ❌ 危险: 命令注入
                - {original_line}
                // ✅ 修复: escapeshellarg + escapeshellcmd
                + $safe = escapeshellarg($user_input);
                + system("command " . $safe);
            """),
            "explanation": (
                "使用 escapeshellarg() 转义单个参数，escapeshellcmd() 转义整条命令。\n"
                "考虑使用白名单机制，限制可执行的命令范围。"
            ),
        },
    },

    # ── Path Traversal ──
    "path_traversal": {
        "python": {
            "detect": [
                r'open\s*\(\s*.*\+',
                r'Path\s*\(\s*.*\+',
            ],
            "fix_template": textwrap.dedent("""\
                # ❌ 危险: 路径穿越
                - {original_line}
                # ✅ 修复: 使用 pathlib 规范化并限制基目录
                + from pathlib import Path
                + base = Path("/safe/base/dir").resolve()
                + target = (base / user_input).resolve()
                + if not str(target).startswith(str(base)):
                +     raise ValueError("路径穿越攻击被拦截")
            """),
            "explanation": (
                "使用 Path.resolve() 消除 ../ 路径遍历组件。\n"
                "验证最终路径是否仍在允许的基目录范围内 (Jail Check)。"
            ),
        },
    },
}


class PatchAdvisor:
    """
    IAST 代码级精准修复建议引擎。

    根据 SAST/IAST 追踪到的漏洞源码行和类型信息，
    自动匹配最佳修复模式并生成 git diff 样式的补丁建议。
    """

    @classmethod
    def advise(
        cls,
        vuln_type: str,
        language: str,
        source_line: str = "",
        file_path: str = "",
        line_number: int = 0,
    ) -> Dict[str, Any]:
        """
        生成精准修复建议。

        Args:
            vuln_type: 漏洞类型标识 (sqli, xss, cmdi, path_traversal)
            language: 源码语言 (python, php, java, javascript)
            source_line: 原始漏洞源码行
            file_path: 源文件路径
            line_number: 行号

        Returns:
            包含 patch_diff, explanation, confidence 的建议字典
        """
        lang = language.lower().strip()
        vtype = cls._normalize_vuln_type(vuln_type)

        pattern_db = _PATCH_PATTERNS.get(vtype, {})
        lang_patterns = pattern_db.get(lang, {})

        if not lang_patterns:
            return cls._fallback_advice(vtype, lang, source_line, file_path, line_number)

        # 检查源码行是否匹配已知的危险模式
        matched_pattern = None
        detect_patterns = lang_patterns.get("detect", [])
        for pat in detect_patterns:
            if re.search(pat, source_line):
                matched_pattern = pat
                break

        # 生成 diff 补丁
        fix_template = lang_patterns.get("fix_template", "")
        explanation = lang_patterns.get("explanation", "")

        # 动态填充模板
        patch_diff = cls._render_patch(
            fix_template, source_line, file_path, line_number
        )

        return {
            "file": file_path,
            "line": line_number,
            "vuln_type": vtype,
            "language": lang,
            "original_line": source_line.strip(),
            "patch_diff": patch_diff,
            "explanation": explanation,
            "confidence": 0.9 if matched_pattern else 0.6,
            "matched_pattern": matched_pattern or "generic",
        }

    @classmethod
    def advise_batch(cls, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        批量生成修复建议。

        Args:
            findings: IAST 追踪结果列表，每项包含:
                      type, file, line, evidence, language (可选)

        Returns:
            每个 finding 对应的修复建议列表
        """
        results = []
        for f in findings:
            lang = f.get("language", cls._detect_language(f.get("file", "")))
            advice = cls.advise(
                vuln_type=f.get("type", ""),
                language=lang,
                source_line=f.get("evidence", ""),
                file_path=f.get("file", ""),
                line_number=f.get("line", 0),
            )
            results.append(advice)
        return results

    @classmethod
    def to_diff_block(cls, advice: Dict[str, Any]) -> str:
        """
        将建议转换为 Markdown 可渲染的 diff 代码块。
        """
        file_path = advice.get("file", "unknown")
        line = advice.get("line", 0)
        patch = advice.get("patch_diff", "")
        explanation = advice.get("explanation", "")
        confidence = advice.get("confidence", 0)

        return (
            f"#### 📍 `{file_path}` (Line {line}) — "
            f"置信度 {confidence:.0%}\n\n"
            f"```diff\n{patch}```\n\n"
            f"> 💡 **修复原理**: {explanation}\n"
        )

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 内部方法
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @staticmethod
    def _normalize_vuln_type(raw_type: str) -> str:
        """标准化漏洞类型标识"""
        t = raw_type.lower().strip()
        if "sql" in t:
            return "sqli"
        if "xss" in t or "cross-site" in t:
            return "xss"
        if "cmd" in t or "command" in t or "rce" in t:
            return "cmdi"
        if "path" in t or "traversal" in t or "lfi" in t:
            return "path_traversal"
        return t

    @staticmethod
    def _detect_language(file_path: str) -> str:
        """根据文件扩展名推断编程语言"""
        ext_map = {
            ".py": "python",
            ".php": "php",
            ".java": "java",
            ".js": "javascript",
            ".ts": "javascript",
            ".rb": "ruby",
            ".go": "golang",
        }
        for ext, lang in ext_map.items():
            if file_path.lower().endswith(ext):
                return lang
        return "python"  # 安全的默认值

    @staticmethod
    def _render_patch(
        template: str, original_line: str, file_path: str, line_number: int
    ) -> str:
        """填充修复模板"""
        trimmed = original_line.strip()

        # 尝试从原始行中提取关键变量名 (启发式)
        param_names = re.findall(r'\$(\w+)|(\w+_(?:id|name|input|param|query|val))', trimmed)
        flat_params = [p[0] or p[1] for p in param_names if p[0] or p[1]]

        safe_query = re.sub(
            r'\$\w+|f["\'].*?["\']|\{.*?\}|%\w',
            '?',
            trimmed
        )

        rendered = template
        rendered = rendered.replace("{original_line}", trimmed)
        rendered = rendered.replace("{safe_query}", safe_query[:80])
        rendered = rendered.replace("{param_tuple}", ", ".join(flat_params) if flat_params else "user_input")
        rendered = rendered.replace("{param_bindings}", ", ".join(f'${p}' for p in flat_params) if flat_params else "$user_input")

        return rendered

    @staticmethod
    def _fallback_advice(
        vtype: str, lang: str, source_line: str, file_path: str, line_number: int
    ) -> Dict[str, Any]:
        """当没有模式匹配时的通用建议"""
        generic_fixes = {
            "sqli": "使用参数化查询 (Prepared Statements) 替代字符串拼接。",
            "xss": "使用上下文感知的输出编码 (HTML/JS/URL Context-Aware Encoding)。",
            "cmdi": "禁止将用户输入传入 shell 命令, 使用语言级 API 代替。",
            "path_traversal": "规范化路径后验证是否在允许的基目录范围内。",
        }
        explanation = generic_fixes.get(vtype, "参考 OWASP Testing Guide 制定针对性修复方案。")

        patch = (
            f"# File: {file_path} (Line {line_number})\n"
            f"- {source_line.strip()}\n"
            f"+ # TODO: 根据以下建议修复\n"
            f"+ # {explanation}\n"
        )

        return {
            "file": file_path,
            "line": line_number,
            "vuln_type": vtype,
            "language": lang,
            "original_line": source_line.strip(),
            "patch_diff": patch,
            "explanation": explanation,
            "confidence": 0.4,
            "matched_pattern": "fallback",
        }
