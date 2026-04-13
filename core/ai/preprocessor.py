"""
core/ai/preprocessor.py — 数据脱敏与智能截断引擎 (DLP & Smart Truncation)

功能:
  1. DLP (Data Loss Prevention): 匹配并掩码 PII 数据 (Cookie, Authorization, IP, 邮箱), 保护隐私不泄露到云端大模型。
  2. Smart Truncation: 丢弃庞大的 HTML body 冗余标签，只提取关键文本和头部，极大节省 Token 开销。
"""

from __future__ import annotations

import re
import logging
from typing import Dict, Any

logger = logging.getLogger("openscanner.ai.dlp")


class AIPreprocessor:
    """处理送入 AI 引擎前的数据"""

    # 常见敏感信息正则字典
    DLP_PATTERNS = {
        "cookie": re.compile(r"(Cookie:\s*)([^\r\n]+)", re.IGNORECASE),
        "auth_bearer": re.compile(r"(Authorization:\s*Bearer\s+)([A-Za-z0-9\-\._~\+\/]+=*)", re.IGNORECASE),
        "basic_auth": re.compile(r"(Authorization:\s*Basic\s+)([A-Za-z0-9\+\/]+=*)", re.IGNORECASE),
        "email": re.compile(r"([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"),
    }

    @classmethod
    def apply_dlp(cls, text: str) -> str:
        """应用自动化脱敏掩码"""
        if not text:
            return text

        masked_text = text

        # 掩盖 Cookie
        masked_text = cls.DLP_PATTERNS["cookie"].sub(r"\1[MASKED_COOKIE_DATA]", masked_text)
        
        # 掩盖 JWT / Token
        masked_text = cls.DLP_PATTERNS["auth_bearer"].sub(r"\1[MASKED_JWT_TOKEN]", masked_text)
        masked_text = cls.DLP_PATTERNS["basic_auth"].sub(r"\1[MASKED_BASIC_AUTH]", masked_text)
        
        # 掩盖邮箱
        masked_text = cls.DLP_PATTERNS["email"].sub(r"[MASKED_EMAIL]", masked_text)

        return masked_text

    @classmethod
    def smart_truncate_html(cls, html_content: str, max_length: int = 4000) -> str:
        """智能截断 HTML: 提取文本，去掉冗长 script/style"""
        if len(html_content) <= max_length:
            return html_content

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, "html.parser")
            
            # 删除无用标签
            for element in soup(["script", "style", "svg", "img"]):
                element.decompose()
                
            # 提取文本，保留少量结构
            text = soup.get_text(separator="\n", strip=True)
            
            # 如果清理后还是很长，就硬截断，并加上省略标记
            if len(text) > max_length:
                return text[:max_length] + "\n...[CONTENT TRUNCATED FOR AI]..."
            return text
        except Exception as e:
            logger.debug("[DLP] BeautifulSoup 解析失败退化为硬截断: %s", str(e))
            return html_content[:max_length] + "\n...[CONTENT TRUNCATED FOR AI]..."
