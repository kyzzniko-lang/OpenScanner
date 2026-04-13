# -*- coding: utf-8 -*-
"""
core/request.py - OpenScanner Async Request Engine

High-performance async HTTP requests based on httpx.
Features:
  - Random User-Agent rotation
  - Exponential backoff retries
  - Global timeout control
  - HTTP/2 & Session reuse
  - Random header ordering
  - Random request delay for stealth
"""

from __future__ import annotations

import asyncio
import logging
import random
import socket
import ipaddress
import re
import ssl
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlparse, parse_qsl, urlencode, urlunparse, urljoin, unquote


def _ensure_ascii_url(url: str) -> str:
    """
    确保 URL 中的非 ASCII 字符被正确 percent-encode。

    httpx 内部要求 URL 可以用 ASCII 编码。当爬虫发现的 URL 路径中
    包含中文等非 ASCII 字符时 (如 /上传/文件.pdf)，直接传入会导致:
      'ascii' codec can't encode characters in position ...

    此函数保留已有的 percent-encoding，仅对未编码的非 ASCII 字符进行编码。
    """
    try:
        url.encode("ascii")
        return url
    except UnicodeEncodeError:
        pass

    parsed = urlparse(url)
    # quote(safe=...) 保留 URL 结构字符，只编码非 ASCII 字符
    safe_path = quote(parsed.path, safe="/:@!$&'()*+,;=-._~")
    safe_query = quote(parsed.query, safe="/:@!$&'()*+,;=-._~=?")
    safe_fragment = quote(parsed.fragment, safe="/:@!$&'()*+,;=-._~")
    return urlunparse((
        parsed.scheme, parsed.netloc, safe_path,
        parsed.params, safe_query, safe_fragment,
    ))

import httpx

logger = logging.getLogger("openscanner.request")

def _sql_safe_urlencode(params: Dict[str, str]) -> str:
    """
    URL encode parameters with special handling for SQL payloads
    to prevent HTTP library misparsing items like '#' or '--'.
    """
    encoded = urlencode(params, quote_via=quote)
    encoded = encoded.replace("#", "%23")
    encoded = re.sub(r'--(?!%20)(&|$)', r'--%20\1', encoded)
    return encoded


def smart_merge(
    base_url: str,
    context_params: Dict[str, str],
    test_param: str,
    test_payload: str,
) -> str:
    """
    Smart merge of URL parameters and business context parameters.
    Priority: test_payload > context_params > base_url params.
    """
    parsed = urlparse(base_url)
    existing_qsl = parse_qsl(parsed.query, keep_blank_values=True)
    params_dict = dict(existing_qsl)

    for k, v in context_params.items():
        if k != test_param:
            params_dict[k] = v

    if test_param in params_dict or test_param in context_params:
        params_dict[test_param] = test_payload

    new_query = _sql_safe_urlencode(params_dict)
    return urlunparse(parsed._replace(query=new_query))

_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
]

@dataclass
class RequestConfig:
    """Configuration for the request engine."""
    max_concurrency: int = 50
    request_timeout: float = 15.0
    connect_timeout: float = 10.0
    max_retries: int = 3
    retry_delay: float = 1.0
    follow_redirects: bool = True
    verify_ssl: bool = False
    http2: bool = True
    random_user_agent: bool = True
    random_delay_range: tuple[float, float] = (0.1, 0.5)
    header_order_shuffle: bool = True
    extra_headers: Optional[Dict[str, str]] = None
    max_response_size: int = 10 * 1024 * 1024
    allow_internal_ips: bool = False

class AsyncRequester:
    """Core async request class for OpenScanner."""

    def __init__(self, config: Optional[RequestConfig] = None) -> None:
        self._config = config or RequestConfig()
        self._client: Optional[httpx.AsyncClient] = None
        self._semaphore = asyncio.Semaphore(self._config.max_concurrency)

    async def __aenter__(self) -> "AsyncRequester":
        await self.open()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def open(self) -> None:
        if self._client is not None:
            return

        # 1. 构造兼容性 TLS 上下文
        # 使用 SSLContext 而非 create_default_context，后者会附加额外限制
        # (OP_NO_SSLv3/TLSv1 等)，导致与部分老旧服务器 (如高校/政府网站) 握手失败。
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if not self._config.verify_ssl:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        # 加密套件策略:
        # 使用 DEFAULT 套件集 (包含所有 OpenSSL 推荐的加密套件) 确保最大兼容性，
        # @SECLEVEL=0 放宽安全级别限制，兼容老旧服务器 (如高校/政府网站的弱 cipher)。
        # 注意: 不能在 DEFAULT 前列出具体 cipher，否则 OpenSSL 会忽略 DEFAULT 追加，
        # 导致只有少量强 cipher 可用，与老旧服务器握手失败。
        # DEFAULT 内部已按安全强度排序 (GCM/CHACHA20 优先于 CBC/SHA)，无需手动指定。
        CIPHERS = "DEFAULT:@SECLEVEL=0"
        try:
            ssl_context.set_ciphers(CIPHERS)
        except ssl.SSLError:
            pass  # 降级到默认套件

        ssl_context.set_alpn_protocols(["h2", "http/1.1"])

        timeout = httpx.Timeout(
            timeout=self._config.request_timeout,
            connect=self._config.connect_timeout,
        )

        # 2. 检测系统代理并修正协议前缀
        # Windows 注册表中的代理配置通常不带协议前缀 (如 "127.0.0.1:7897")，
        # httpx 对 HTTPS 请求会将其解释为 https:// 代理，导致尝试与 HTTP 代理
        # 建立 TLS 连接，从而握手失败。此处手动检测并强制使用 http:// 协议。
        proxy_url = self._detect_system_proxy()

        # 3. 初始化核心客户端 (如果未初始化或因 fallback 需要重建)
        if self._client is None:
            client_kwargs = dict(
                http2=self._config.http2,
                verify=ssl_context,
                follow_redirects=self._config.follow_redirects,
                timeout=timeout,
                limits=httpx.Limits(
                    max_connections=self._config.max_concurrency,
                    max_keepalive_connections=self._config.max_concurrency // 2,
                ),
            )
            if proxy_url:
                # 使用手动检测的代理，禁用 trust_env 防止 httpx 再次误读
                client_kwargs["proxy"] = proxy_url
                client_kwargs["trust_env"] = False
                logger.info("系统代理已检测: %s", proxy_url)
            self._client = httpx.AsyncClient(**client_kwargs)
        logger.info("AsyncRequester Hardened | HTTP/2 (Init)=%s | Cipher=Chrome125+DEFAULT", self._config.http2)

    @staticmethod
    def _detect_system_proxy() -> Optional[str]:
        """
        检测 Windows 系统代理设置并返回正确的代理 URL。

        Windows 注册表中 ProxyServer 通常是 "host:port" 格式（无协议前缀），
        httpx trust_env 会将其误读为 https:// 代理。此方法强制使用 http:// 协议，
        因为绝大多数本地代理工具 (Clash, V2Ray, Surge 等) 提供的是 HTTP 代理协议。
        """
        if sys.platform != "win32":
            return None
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            )
            proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
            if not proxy_enable:
                winreg.CloseKey(key)
                return None
            proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
            winreg.CloseKey(key)

            if not proxy_server:
                return None

            # 如果已有协议前缀则保留，否则加 http://
            proxy_server = proxy_server.strip()
            if not proxy_server.startswith(("http://", "https://", "socks5://", "socks4://")):
                proxy_server = f"http://{proxy_server}"

            return proxy_server
        except Exception:
            return None

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _build_headers(self, extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "User-Agent": self._random_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        if self._config.extra_headers:
            headers.update(self._config.extra_headers)
        if extra_headers:
            headers.update(extra_headers)
        if self._config.header_order_shuffle:
            items = list(headers.items())
            random.shuffle(items)
            headers = dict(items)
        return headers

    def _random_ua(self) -> str:
        return random.choice(_USER_AGENTS) if self._config.random_user_agent else _USER_AGENTS[0]

    def _format_httpx_exc(self, exc: Exception, url: str) -> str:
        etype = type(exc).__name__
        emsg = str(exc)
        if not emsg or emsg == "()":
            if "ConnectTimeout" in etype:
                emsg = "TCP connection timeout"
            elif "ReadTimeout" in etype:
                emsg = "Read response timeout"
            elif "ConnectError" in etype:
                emsg = "Connection failed (Target down or IP blocked)"
            else:
                emsg = "Network error"
        return f"[{etype}] {emsg}"

    def _is_really_private(self, ip: Any) -> bool:
        """Enhanced private IP check allowing benchmark ranges often used as cloud relays."""
        if ip.is_loopback or ip.is_link_local:
            return True
        private_networks = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('127.0.0.0/8'),
            ipaddress.ip_network('169.254.0.0/16'),
        ]
        return any(ip in net for net in private_networks)

    def _is_internal(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname: return False
            hostname_lower = hostname.lower().strip(".")

            if hostname_lower in {"localhost", "127.0.0.1", "0.0.0.0"}: return True
            if any(hostname_lower.endswith(s) for s in (".internal", ".local")): return True

            # Integer/Hex IP
            if re.fullmatch(r'\d+', hostname) or re.fullmatch(r'0x[0-9a-fA-F]+', hostname):
                try:
                    ip = ipaddress.ip_address(int(hostname, 0))
                    return self._is_really_private(ip)
                except: pass

            # Standard IP
            try:
                ip = ipaddress.ip_address(hostname)
                return self._is_really_private(ip)
            except: pass

            # DNS Resolution
            try:
                addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
                for res in addr_info:
                    ip = ipaddress.ip_address(res[4][0])
                    if self._is_really_private(ip): return True
            except: pass
            return False
        except: return False

    async def request(
        self, method: str, url: str, *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        **kwargs: Any
    ) -> httpx.Response:
        if self._client is None: raise RuntimeError("Requester not opened")

        url = _ensure_ascii_url(url)
        merged_headers = self._build_headers(headers)
        last_exc = httpx.RequestError(f"Request failed: {url}")
        
        for attempt in range(1, self._config.max_retries + 1):
            async with self._semaphore:
                try:
                    lo, hi = self._config.random_delay_range
                    await asyncio.sleep(random.uniform(lo, hi))

                    if not self._config.allow_internal_ips:
                        parsed = urlparse(url)
                        if parsed.hostname:
                            try:
                                addr_info = socket.getaddrinfo(parsed.hostname, None, socket.AF_UNSPEC)
                                for res in addr_info:
                                    ip = ipaddress.ip_address(res[4][0])
                                    if self._is_really_private(ip):
                                        raise httpx.RequestError(f"SSRF blocked: {parsed.hostname} -> {ip}")
                            except (socket.gaierror, ValueError) as e:
                                if isinstance(e, httpx.RequestError): raise

                    async with self._client.stream(method, url, headers=merged_headers, params=params, data=data, json=json, **kwargs) as response:
                        if response.is_redirect and not self._config.allow_internal_ips:
                            if self._is_internal(urljoin(url, response.headers.get("Location", ""))):
                                raise httpx.RequestError("SSRF blocked redirect")

                        content_length = response.headers.get("Content-Length")
                        if content_length and int(content_length) > self._config.max_response_size:
                            raise httpx.RequestError("Response too large")

                        content = b""
                        async for chunk in response.aiter_bytes():
                            content += chunk
                            if len(content) > self._config.max_response_size:
                                raise httpx.RequestError("Response body too large")

                        # aiter_bytes() 已完成解压缩，需要剥离 content-encoding
                        # 头部，否则 httpx.Response() 构造时会尝试二次解压导致
                        # "Error -3 while decompressing data" 错误
                        resp_headers = httpx.Headers(
                            {k: v for k, v in response.headers.items()
                             if k.lower() not in ("content-encoding", "content-length")}
                        )

                        return httpx.Response(status_code=response.status_code, headers=resp_headers, content=content, request=response.request)

                except (httpx.TimeoutException, httpx.NetworkError, httpx.ProtocolError) as exc:
                    # 3. HTTP/2 降级策略 (Resilience)
                    # 如果疑似 HTTP/2 握手或协议错误，且配置中开启了 H2，尝试在下一次重试中禁用 H2
                    if self._config.http2 and ("h2" in str(exc).lower() or isinstance(exc, httpx.ProtocolError)):
                        logger.warning("HTTP/2 failure detected for %s, activating HTTP/1.1 fallback for next attempt...", url)
                        # 为了极速响应，我们直接重置 client 以便下次 attempt 使用 H1
                        await self._client.aclose()
                        self._client = None
                        self._config.http2 = False # 强制全局降级
                    
                    last_exc = exc
                    wait = self._config.retry_delay * (2 ** (attempt - 1))
                    await asyncio.sleep(wait)
                    
                    # 在下一次 attempt 之前确保 client 已重建为降级后的状态
                    if self._client is None:
                        await self.open()
                except Exception as exc:
                    raise exc

        raise httpx.RequestError(self._format_httpx_exc(last_exc, url))

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)
