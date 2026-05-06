<h1 align="center">OpenScanner</h1>

<p align="center">
  <b>混合安全评估平台 — DAST | SAST | IAST | AI 深度研判</b>
</p>

<p align="center">
  <a href="./README_EN.md">English</a> | <a href="./README_CN.md">中文</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-3776ab?style=flat-square&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/github/actions/workflow/status/kyzzniko-lang/OpenScanner/CI?branch=main&style=flat-square&label=CI" alt="CI" />
  <img src="https://img.shields.io/badge/tests-271%20passing-22c55e?style=flat-square" alt="Tests" />
  <img src="https://img.shields.io/badge/coverage-21%20plugins-red?style=flat-square" alt="Coverage" />
  <img src="https://img.shields.io/badge/AI-Hybrid%20LLM-blueviolet?style=flat-square&logo=openai" alt="AI" />
  <img src="https://img.shields.io/github/license/kyzzniko-lang/OpenScanner?style=flat-square" alt="License" />
  <img src="https://img.shields.io/badge/Status-v1.5.0-22c55e?style=flat-square" alt="Status" />
</p>

---

<p align="center">
  <img src="docs/demo_terminal.png" alt="OpenScanner 终端演示" width="720" />
</p>

> **30 秒体验**：`docker run --rm -p 8501:8501 openscanner/openscanner` 或 `python main.py --demo`

---

## 为什么选择 OpenScanner？

| | **OpenScanner** | **Nuclei** | **OWASP ZAP** | **SQLMap** |
|---|---|---|---|---|
| **DAST (Web)** | 16 种漏洞类型，穷举 Payload | 模板驱动，社区模板 | 代理爬虫 | 仅 SQLi |
| **SAST (代码)** | 内置 AST 分析 + AI 审计 | 无 | 插件 (beta) | 无 |
| **IAST (运行时)** | Sink 追踪 + 污点分析 | 无 | 无 | 无 |
| **AI 研判** | 本地 LLM + 云端 API (OpenAI/Gemini/DeepSeek) | 无 | 无 | 无 |
| **WAF 绕过** | 9 策略变异引擎 | 基础编码 | 无 | Tamper 脚本 |
| **盲注 SQLi** | 自适应布尔 + 时间盲注 + SimHash | 无 | 插件 | 有 (专精) |
| **IDOR/BOLA** | 三向对比检测 | 通过模板 | 基础认证测试 | 无 |
| **报告格式** | MD/JSON/CSV/SARIF/JUnit/PDF/HTML/合规 | SARIF, Markdown | HTML, JSON, XML | Dump 格式 |
| **合规报告** | OWASP Top 10 + PCI-DSS + SOC2 + HIPAA | 无 | 插件 | 无 |
| **CI/CD** | 原生退出码 + GitHub Action + Docker | 原生 + GitHub Action | Docker + CLI | CLI |
| **离线运行** | 完整功能 (本地 AI 模式) | 是 (模板) | 部分 | 是 |
| **开发语言** | Python (async) | Go | Java | Python |

## 概述

OpenScanner 是一款从零构建的模块化安全评估平台。v1.5 版本提供：

- **混合 AI 引擎** -- 本地大语言模型（隐私优先，离线执行）与云端 API 后端（DeepSeek / OpenAI / Gemini，精度优先）无缝切换
- **穷举式共识检测模型** -- 全量 payload 测试，汇总证据矩阵，AI 综合研判，消除攻击向量遗漏
- **高性能并发扫描** -- 基于 `asyncio.gather` + `Semaphore` 的并行 payload 探测，5--10 倍吞吐提升
- **六阶段流水线** -- INFO 侦察、DAST 漏洞扫描、SAST 代码审计、IAST 联动、深度研判、CWE 分析
- **21 个插件 (19 种漏洞类型)** -- SQLi、XSS、DOM XSS、BOLA/IDOR、SSRF、LFI、命令注入、SSTI、CSRF、JWT、文件上传、逻辑漏洞、API Fuzzing、GraphQL、Auth Bypass、信息泄露、WAF 检测、恶意代码审计、AI 代码审计

---

## 核心能力

### 混合 AI 深度研判引擎

```
                       +----------------------------+
                       |    AIEngine (Orchestrator)  |
                       +----------------------------+
                       |  Factory Pattern:           |
                       |    mode=OFF   -> Null       |
                       |    mode=LOCAL -> llama.cpp  |
                       |    mode=API   -> OpenAI/    |
                       |                 Gemini      |
                       +---------+------------------+
                                 |
          +----------------------+----------------------+
          |                      |                      |
    +-----v------+      +-------v-------+      +-------v------+
    |  AUDITOR   |      | EXPLOIT_VERIF |      | BYPASS_EXPERT|
    | 代码审计    |      | 漏洞验证       |      | WAF 绕过     |
    +------------+      +---------------+      +--------------+
```

- **3 种 AI 专家角色** -- 代码审计 (SAST) / 漏洞验证 (DAST) / WAF 绕过 (Mutation)
- **双模式架构** -- `LOCAL`: Qwen2-0.5B/Llama-3.2-1B via llama-cpp-python（纯 CPU，离线）/ `API`: OpenAI，Google Gemini，DeepSeek（云端，高精度）
- **智能缓存** -- 基于哈希的推理结果缓存（`.ai_cache.json`），消除重复推理
- **延迟加载与自动卸载** -- 模型首次使用时加载，空闲 5 分钟自动卸载以节省内存
- **配置持久化** -- 云端服务器地址、API Key 及本地模型路径在首次配置后持久化至 `.ai_settings.json`

### 自适应变异对抗引擎

- **9 种变异策略** -- 大小写随机变异 / 内联注释 / Hex 双编码 / 空格替代 / 数据库特化注释 / CHAR() / HPP / AI 绕过
- **上下文感知** -- 基于 `detected_db_type` 和 WAF 指纹实时生成混淆 Payload

### SQL 注入 -- 五层递进检测

| 阶段 | 方法 | 说明 |
|------|------|------|
| 1 | 智能注入点嗅探 | 19 种正则模式，区分测试参数与业务上下文（Submit/token） |
| 2 | 报错注入 | MySQL / PostgreSQL / MSSQL / Oracle / SQLite 错误特征码匹配 |
| 3 | 动态变异引擎 | 基于数据库类型 + WAF 指纹生成混淆 Payload |
| 4 | 自适应布尔盲注 | 响应指纹 + SimHash 双重验证 + 二次确认排除抖动 |
| 5 | 时间盲注 | 预采样网络校准 + 反向验证 SLEEP(0) |

### BOLA/IDOR 越权检测

- **三向对比** -- 正向基线 + 负向基线 + 探测结果三角验证
- **核心特征增量分析** -- 防止空数据误判
- **未授权访问 + HTTP 方法篡改** -- 全方位鉴权校验

### 跨站脚本 (XSS) 检测

- **上下文感知注入** -- 自动识别属性/脚本/标签上下文并闭合
- **WAF 规避模式** -- 大小写变异 + 编码绕过
- **反射点探测 + 真实 Payload 验证** -- 两阶段精准检测

### 性能基准测试

针对本地靶场应用 (50 个端点、120 个参数) 的测试数据：

| 插件 | Payload 数 | 并发数 | 总请求数 | 耗时 | 请求/秒 |
|------|-----------|--------|---------|------|---------|
| SQLi (报错+布尔+时间) | 150+ | Semaphore(5) | 3,200 | 47s | 68 |
| XSS (反射+上下文感知) | 90+ | Semaphore(4) | 2,800 | 38s | 74 |
| BOLA/IDOR (三向对比) | 40/参数 | Semaphore(8) | 1,600 | 12s | 133 |
| SSRF (元数据+内网) | 80+ | Semaphore(6) | 2,100 | 29s | 72 |
| LFI (穿越+包装器) | 100+ | Semaphore(6) | 2,400 | 31s | 77 |
| WAF 检测 (6 维度) | 37 | Semaphore(4) | 222 | 5s | 44 |
| 全量扫描 (所有插件) | 600+ | 最大 10 | 12,000+ | 3m 12s | 63 |

> **测试环境**：Apple M1, 16GB RAM, Python 3.11, 单目标。
> 运行你自己的基准测试：`python main.py -t TARGET --crawl-depth 1 --concurrency 20`

---

## 快速开始

### 关键 Bug 修复

| 问题 | 文件 | 修复方案 |
|------|------|---------|
| **main.py webhook NameError** | `main.py` | `run_scan` 中 `args` 未定义导致 webhook 崩溃 -- 重构为函数参数 |
| **main.py except 块 engine 未定义** | `main.py` | `engine = None` 初始化 + `if engine:` 防护 |
| **Exception 泄露 API key** | `main.py` | Traceback 输出限制为仅 verbose 模式 |
| **vuln_count 退出码不一致** | `main.py` | 简化退出码逻辑 |
| **HTTP/2 降级永久修改配置** | `core/request.py` | 改用 `_http2_enabled` 实例标志 |
| **DNS 缓存无 TTL** | `core/request.py` | 添加 60s TTL 过期机制 |
| **_request_history 无界增长** | `core/request.py` | 改用 `deque(maxlen=1000)` |
| **DOM XSS 录制名称不匹配** | `core/engine.py` | `dom_xss_headless` -> `dom_xss_scan` |
| **Gemini API key 泄露至 URL** | `core/ai/api_provider.py` | 迁移至 `params={"key": ...}` |
| **JSON 解析 O(n^2)** | `core/ai/engine.py` | 限制搜索范围至 20000 字符 + 50 候选 |
| **_load_cache 未验证格式** | `core/ai/engine.py` | 添加 `isinstance(data, dict)` 校验 |
| **RLHF _db 无界增长** | `core/ai/rlhf.py` | 添加 `MAX_RECORDS=500` |
| **Docker 服务启动失败** | `docker-compose.yml` | ENTRYPOINT 与 command 冲突 -- 通过 `entrypoint:` 覆盖解决 |
| **XSS POC payload 未注入 URL** | `utils/poc_gen.py` | 根据 param 构建 INJECT_URL |
| **SQLite 时间盲注无效** | `plugins/pocs/sqli_scan.py` | 迁移至 RANDOMBLOB |
| **爬虫表单字段提取失败** | `plugins/info/crawler.py` | 在 `<form>...</form>` 块内搜索 input 而非标签级 |

### 性能优化

| 模块 | 优化方式 | 加速比 |
|------|---------|--------|
| Stage 1+3 | INFO 侦察 + SAST 代码审计并行化 | 2x |
| Stage 5+6 | AI 研判 + 浏览器取证验证并行化 | 2x |
| Stage 7+8 | 攻击链编排 + 重演录制并行化 | 2x |
| 请求层 | DNS 缓存 60s TTL + 延迟降至 0.02--0.1s | 1.5x |
| SQLi | 参数级并发（`_test_one_param` + `asyncio.gather`） | 5--10x |
| XSS | GET/POST 参数并行探测（`_probe_param` + `asyncio.gather`） | 3--4x |

### SAST 审计引擎增强 (malware_scan.py)

新增 **16 种** 检测特征，覆盖扩展安全威胁面：

| 特征 | CVSS | 说明 |
|------|------|------|
| Unsafe Deserialization | 9.0 | `pickle`/`yaml`/`marshal`/`shelve`/`jsonpickle` |
| Hardcoded Credentials | 8.0 | 18 种变量名：password/api_key/secret_key/aws_secret 等 |
| Path Traversal | 8.5 | 文件操作函数参数来自 `request.args`/`request.form` |
| SSRF | 7.5--9.0 | HTTP 请求函数 + URL 来源追踪 |
| Weak Cryptography | 6.5 | `md5`/`sha1`/`DES`/`random.random` |
| Template Injection | 8.0 | `jinja2`/`mako`/`django.template`/`string.Template` |
| Insecure Temp File | 5.5 | `tempfile.mktemp`/`os.tmpfile`（TOCTOU） |
| chr() 混淆 | 7.0--8.5 | 单次标记 + 密集调用（>=5）标记 |
| 归档外泄链 | 9.0 | `shutil.make_archive`/`zipfile` + 网络上传 |
| 非 HTTP 外泄 | 9.0 | SMTP/FTP/SMB 通道 |
| PHP Unsafe Deserialize | 9.5 | `unserialize($_GET/POST...)` |
| PHP File Inclusion | 9.0 | `include`/`require` + 用户输入 |
| PHP SSRF | 9.0 | `curl_exec`/`file_get_contents`/`fopen` |
| PHP 6 种 WebShell 变体 | 9.5 | `assert()`/`preg_replace /e`/`create_function`/`call_user_func`/可变变量/`array_map` |
| PHP Hardcoded Credentials | 8.0 | `$db_password`/`$api_key`/`$aws_secret` |
| PHP Direct eval() RCE | 10.0 | `eval($_GET/POST...)` |

污点追踪 sink 扩展：+6（`loads`/`write`/`send`/`format` 等）
净化函数扩展：Python +10 / PHP +8

### POC 插件 Payload 扩充

| 插件 | 新增 Payload | 关键增强 |
|------|-------------|---------|
| **SQLi** | +33 | 堆叠查询 / MySQL 报错函数 / 更多时间盲注 / 布尔闭合变体 / 注释符变体 |
| **XSS** | +40 | 13 种隐蔽 payload / 上下文感知全面扩展 / DOM 动态参数提取 |
| **CMD Injection** | +31 | 换行符 / 引号包裹 / 更多输出检测（whoami/hostname/ipconfig）/ 16 种输出指标 |
| **LFI** | +43 | PHP wrapper / file:// 协议 / data:// 编码 / 15 种新路径 / 11 种敏感模式 |
| **SSRF** | +40 | 7 个云厂商元数据 / 11 个新内部服务 / IP 绕过（八进制/十六进制/IPv6）/ 4 种新协议 |
| **DOM XSS** | +30 | 11 个新 sink / 8 个新 source / 11 个新 payload |
| **WAF** | +37 | 6 种新 WAF 签名 / 新增 XXE 维度 / 各维度 payload 扩充 |
| **Info Leak** | +30 | Kubernetes/Terraform/CMS/IDE 配置 / Spring Boot 端点 / 备份扩展名 |

### 测试覆盖

- 新增 `tests/test_payload_coverage.py` -- **34 个测试**
- 覆盖：Python/PHP 恶意代码检测、XSS DOM 动态参数提取、SecurityVisitor、payload 非空验证
- 总测试数：**271**（20 个测试文件）

---

## v1.1 更新日志

### 关键 Bug 修复

| 问题 | 文件 | 修复方案 |
|------|------|---------|
| **Webhook 通知崩溃** | `main.py:1198` | `asyncio.run()` 在已运行的事件循环中调用 -- 改为 `await` |
| **DOM-XSS 浏览器验证失效** | `core/engine.py:666,772` | 插件名 `dom_xss` 与引擎引用 `dom_xss_headless` 不匹配 |
| **httpx 硬依赖** | `logic_flaw.py`, `sqli_scan.py` | 移除未使用的 `import httpx`；`waf_check.py` 添加 try/except 安全降级 |
| **裸 except 捕获** | `bola_idor.py:324` | `except:` -> `except Exception:` |

### v1.1 新功能

| 功能 | 说明 |
|------|------|
| **信息泄露检测插件** | 80+ 敏感路径：.git/.env/.svn/DS_Store/备份文件/密钥/API 文档/调试端点 |
| **OpenAPI/Swagger 解析** | 自动探测 API 文档，提取端点+参数注入扫描上下文，检测未授权敏感 API |
| **CVE/NVD 漏洞库** | SQLite 缓存 + 40+ 内置 CVE + CWE 自动关联 + NVD 在线查询 |
| **合规基线报告** | OWASP Top 10 (2021) + PCI-DSS v4.0 对照表 + 评分体系 + `--export-compliance` |
| **定时扫描调度器** | YAML 配置定时任务 + Webhook 推送 + CI/CD 阈值：`python -m utils.scheduler` |
| **SQLite 持久化** | 替代 JSON 文件存储，支持结构化查询/分页/漏洞状态管理/全文搜索 |
| **Docker 一键部署** | `Dockerfile` + `docker-compose.yml`（Web GUI + REST API + Scheduler） |
| **Per-Domain 限流** | `RequestConfig(domain_rpm=60)` 滑动窗口限速 |
| **REST API 认证** | `X-API-Key` Header 认证，支持文件/环境变量配置 |
| **合规报告导出** | CLI `--export-compliance compliance.md` 生成 OWASP/PCI-DSS 报告 |

### 新增/修改文件

```
plugins/info/
  +-- info_leak.py          # [NEW] 信息泄露检测 (80+ 敏感路径)
  +-- openapi_parser.py     # [NEW] OpenAPI/Swagger 文档解析

utils/
  +-- cve_db.py             # [NEW] CVE/NVD 漏洞库 (SQLite)
  +-- compliance.py         # [NEW] 合规基线报告 (OWASP + PCI-DSS)
  +-- scheduler.py          # [NEW] 定时扫描调度器
  +-- db.py                 # [NEW] SQLite 持久化存储

config/
  +-- scheduler.yaml        # [NEW] 调度器配置示例

Dockerfile                   # [NEW] Docker 部署
docker-compose.yml           # [NEW] 编排 (Web + API + Scheduler)
.dockerignore                # [NEW] Docker 忽略规则

tests/
  +-- test_core_upgrades.py  # 56 个测试 -- 核心升级测试
  +-- test_new_features.py   # 29 个测试 -- 新功能测试
```

---

## v1.0 核心更新日志

### 关键 Bug 修复

| 问题 | 根因 | 修复方案 |
|------|------|---------|
| **BOLA 执行完后 SQLi 不执行** | 引擎超时 (300s) 导致 BOLA 超时后 `asyncio.gather` 异常传播，取消所有并行任务 | 1. 超时提升至 **1800s** 2. `gather` 添加 `return_exceptions=True` 隔离异常 |
| **SQL 注入置信度低** | 单 payload 命中即停止测试，未穷举所有攻击向量 | 改为穷举式共识模型：全量 payload 测试 -> Evidence Matrix 汇总 -> AI 研判 |
| **BOLA 检测误报率高** | 公开页面未授权访问检测、静态页面方法篡改、内容漂移阈值过低 | 1. 未授权检测仅针对含 API/管理路径的 URL 2. 方法篡改跳过静态资源 3. HTML 内容漂移阈值提升至 5 |
| **URL 含非 ASCII 字符连接失败** | 爬虫发现的 URL 路径含中文等字符，httpx 要求 ASCII 编码 | 新增 `_ensure_ascii_url()` 自动 percent-encode 非 ASCII 字符 |
| **路径参数未被注入测试** | 爬虫 URL 如 `/297/list.htm` 无查询参数，SQLi/XSS 插件直接跳过 | 新增 `synthesize_path_id_urls()` 自动从路径提取数字 ID 合成 `?id=` 参数 |

### 新功能

| 功能 | 说明 |
|------|------|
| **扫描历史与对比** | 自动保存扫描结果，支持两次扫描 Diff 对比（新增/修复/持续漏洞） |
| **漏洞状态管理** | 每个漏洞可设置 Open -> Fixing -> Fixed / Accepted Risk / False Positive |
| **CWE/OWASP 映射** | 每个漏洞自动关联 CWE-ID + OWASP Top 10 + 修复建议链接 |
| **扫描模板** | 3 个内置模板（Quick Recon / Deep Audit / Compliance）+ 自定义模板持久化 |
| **Webhook 通知** | 自动推送飞书/钉钉/Slack，按严重度阈值触发 |
| **REST API** | FastAPI 端点：POST /scan、GET /history、GET /diff 等 CI/CD 集成端点 |
| **PDF 报告** | 一键生成合规 PDF 报告（需 `pip install reportlab`） |
| **CI/CD 就绪退出码** | `--fail-on high` 控制退出码；直接集成 GitHub Actions / GitLab CI |
| **扫描强度分级** | 轻度 / 中度 / 全量 -- CLI: `--scan-intensity` / Web UI: 侧边栏选择 |
| **路径 ID 自动合成** | URL 路径中的数字/混合 ID 自动合成为 `?id=` 注入测试 URL |
| **日期段智能排除** | 路径中的日期段不被误识别为注入 ID |

### 性能优化

| 模块 | 优化方式 | 预估加速 |
|------|---------|---------|
| SQLi 报错注入 | Error payload 逐个发送以保证精准进度跟踪 | -- |
| SQLi 布尔盲注 | `asyncio.gather` + `SimHash` 并行比对 | 2--3x |
| SQLi 时间盲注 | 反向验证 SLEEP(0) | 减少误报 |
| XSS Payload 验证 | `asyncio.gather` + `Semaphore(4)` 并发 | 3--4x |
| BOLA ID 探测 | `asyncio.gather` + `Semaphore(8)` 并发 | 5--8x |
| 引擎超时 | 300s -> 1800s | 消除截断 |
| 引擎容错 | `return_exceptions=True` | 零级联故障 |

### 功能增强

- **配置持久化** -- AI 设置（云端地址/API Key/本地模型路径）自动保存至 `.ai_settings.json`
- **穷举式共识模型** -- 所有插件穷举测试后统一输出 Evidence Matrix 供 AI 研判
- **WAF 联动增强** -- WAF 模式自动调低并发度 + 增加随机延迟

---

## 项目结构

```
OpenScanner/
+-- main.py                     # CLI 指挥中心 (Rich console)
+-- setup.py                    # 一键部署
+-- Dockerfile                  # Docker 部署
+-- docker-compose.yml          # 编排 (Web + API + Scheduler)
+-- requirements.txt            # 依赖清单
+-- .ai_settings.json           # AI 配置持久化 (自动生成)
+-- config/
|   +-- settings.yaml           # 全局配置
|   +-- scheduler.yaml          # 定时扫描调度配置
+-- data/                       # 持久化数据 (自动生成)
|   +-- scan_history/           # 扫描历史记录 (JSON)
|   +-- scan_templates/         # 自定义扫描模板
|   +-- openscanner.db          # SQLite 持久化存储
|   +-- cve_cache.db            # CVE 漏洞库缓存
|   +-- api_keys.txt            # REST API 密钥
+-- core/
|   +-- engine.py               # 六阶段扫描调度引擎 (v1.5: 并行化 + 审计增强)
|   +-- request.py              # 异步请求引擎 + smart_merge + per-domain 限流
|   +-- reasoner.py             # 5 维漏洞深度研判器 (含 AI 维度)
|   +-- browser.py              # Playwright 视觉取证引擎
|   +-- spider.py               # 异步爬虫 + ABFD 业务流发现
|   +-- validator.py            # 漏洞验证器
|   +-- attack_chain.py         # 攻击链编排
|   +-- replay_lab.py           # 重演录制实验室
|   +-- ai/                     # 混合 AI 引擎
|       +-- __init__.py
|       +-- base.py             # 抽象 Provider 接口 + 数据结构
|       +-- prompts.py          # 三角色 System Prompt 库
|       +-- local_provider.py   # 本地 LLM (llama-cpp-python / GGUF)
|       +-- api_provider.py     # 云端 API (OpenAI / Gemini / DeepSeek 兼容)
|       +-- engine.py           # AI 编排引擎 (Factory + Cache + 降级)
|       +-- auditor.py          # AVA 审查器
|       +-- rlhf.py             # RLHF 反馈管理
|       +-- debate.py           # 辩论编排器
|       +-- preprocessor.py     # AI 预处理器
+-- plugins/
|   +-- base.py                 # 插件基类 + ScanResult
|   +-- info/
|   |   +-- crawler.py          # 站点爬虫
|   |   +-- waf_check.py        # WAF 探测 + 热力图
|   |   +-- auth_session.py     # 认证会话管理
|   |   +-- info_leak.py        # 信息泄露检测 (80+ 敏感路径)
|   |   +-- openapi_parser.py   # OpenAPI/Swagger 文档解析
|   +-- pocs/
|   |   +-- sqli_scan.py        # SQLi v3.0 (五层递进 + 穷举共识)
|   |   +-- xss_scan.py         # XSS 检测 (并行优化 + 上下文感知)
|   |   +-- dom_xss.py          # DOM XSS (浏览器验证)
|   |   +-- bola_idor.py        # BOLA/IDOR (三向对比 + 并行探测)
|   |   +-- logic_flaw.py       # 业务逻辑漏洞 (价格操纵/权限提升)
|   |   +-- csrf.py             # CSRF 检测
|   |   +-- ssrf.py             # SSRF 检测
|   |   +-- lfi.py              # LFI / 路径穿越
|   |   +-- cmd_injection.py    # OS 命令注入
|   |   +-- api_fuzz.py         # API 模糊测试
|   |   +-- jwt_scan.py         # JWT 安全扫描
|   |   +-- ssti_scan.py        # 服务端模板注入检测
|   |   +-- upload_scan.py      # 文件上传漏洞检测
|   |   +-- auth_bypass.py      # 认证绕过 (JWT 弱签名 / Token 过期 / 角色提升)
|   |   +-- api_fuzz.py         # API 模糊测试
|   |   +-- graphql_scan.py     # GraphQL 安全 (内省 / 深度 DoS / 批量滥用)
|   +-- demo/
|   |   +-- vuln_app.py         # 漏洞演示应用 (测试用)
|   +-- audit/
|       +-- malware_scan.py     # SAST 审计 + 污点追踪 + AI 恶意判定
|       +-- ai_audit.py         # AI 代码深度审计
+-- web/
|   +-- app.py                  # Streamlit GUI (历史/对比/模板/通知/合规)
|   +-- api.py                  # REST API (FastAPI + API Key 认证)
|   +-- server.py               # Web 服务器启动
|   +-- history.py              # 扫描历史管理 + 漏洞状态
|   +-- scan_diff.py            # 扫描对比引擎
|   +-- templates.py            # 扫描模板管理
|   +-- dashboard.py            # 仪表盘组件
|   +-- i18n.py                 # 国际化 (en/zh)
|   +-- settings.py             # 服务端持久化设置
|   +-- frontend/               # Vue.js 前端 (独立 Web 界面)
|   +-- dist/                   # 已构建的 Vue.js 前端资源
+-- utils/
|   +-- reporter.py             # 报告引擎 (MD/JSON/CSV/SARIF/JUnit/PDF/HTML/合规)
|   +-- cwe_map.py              # CWE/OWASP 映射数据库 + 修复建议
|   +-- cve_db.py               # CVE/NVD 漏洞库 (SQLite + 在线查询)
|   +-- compliance.py           # 合规基线报告 (OWASP Top 10 + PCI-DSS)
|   +-- db.py                   # SQLite 持久化存储
|   +-- scheduler.py            # 定时扫描调度器
|   +-- notifier.py             # Webhook 通知 (飞书/钉钉/Slack)
|   +-- pdf_export.py           # PDF 报告生成 (reportlab)
|   +-- analyser.py             # CWE 关联分析器
|   +-- mutator.py              # 9 策略自适应变异引擎
|   +-- poc_gen.py              # POC 一键复现脚本生成器
|   +-- patch_advisor.py        # 自动修复建议引擎
|   +-- scan_policy.py          # 范围控制 + 抑制规则
|   +-- auth.py                 # 认证工具
|   +-- asset_manager.py        # 资产管理
|   +-- plugin_market.py        # 插件市场
|   +-- pr_generator.py         # PR 生成
|   +-- verify_fix.py           # 修复验证
|   +-- scan_queue.py           # 扫描队列管理
|   +-- security_grade.py       # 安全评级
|   +-- vuln_kb.py              # 漏洞知识库
|   +-- git_blame.py             # Git blame 分析器 (修复归属)
|   +-- ci_commenter.py          # CI/CD PR/MR 安全评论
|   +-- fix_pr_generator.py      # 自动修复 PR 生成
+-- tests/                      # 271 个测试 (20 个文件)
    +-- test_utils_modules.py    # 45 个测试 (工具模块)
    +-- test_core_upgrades.py   # 56 个测试 (核心升级)
    +-- test_ai_modules.py      # 39 个测试 (AI 模块)
    +-- test_new_features.py    # 29 个测试 (新功能)
    +-- test_payload_coverage.py # 34 个测试 (Payload 覆盖率)
    +-- test_sqli_plugin.py     # 14 个测试 (SQLi 插件)
    +-- test_security_grade.py  # 10 个测试 (安全评级)
    +-- test_ai_api_integration.py # 5 个测试 (AI API 集成)
    +-- test_demo_app.py        # 7 个测试 (演示应用)
    +-- test_github_action.py   # 5 个测试 (GitHub Action)
    +-- test_plugin_system.py   # 5 个测试 (插件系统)
    +-- test_scan_policy.py     # 3 个测试 (扫描策略)
    +-- test_phase1_mvp.py      # 3 个测试 (Phase 1 MVP)
    +-- test_plugin_additional_logic.py # 4 个测试 (插件逻辑)
    +-- test_plugin_detection_logic.py # 3 个测试 (插件检测)
    +-- test_consensus_flow.py  # 1 个测试 (共识流程)
    +-- test_reporter.py        # 2 个测试 (报告器)
    +-- test_plugin_contracts.py # 2 个测试 (插件契约)
    +-- test_plugin_more_logic.py # 2 个测试 (更多插件逻辑)
    +-- test_plugin_validation_rules.py # 2 个测试 (插件验证)
```

---

## 快速开始

### 1. Docker (最快的体验方式)

```bash
# 完整部署: Web GUI + REST API
docker-compose up -d

# 或运行单次扫描
docker run --rm openscanner/openscanner -t "http://target.com/page?id=1"
```

Web GUI: `http://localhost:8501` | REST API: `http://localhost:8000`

### 2. pip 安装

```bash
pip install openscanner
openscanner --demo                  # 零配置演示，启动内置漏洞靶场
openscanner -t "http://target.com"  # 扫描目标
```

### 3. 源码部署

```bash
python setup.py
```

### 3. Web GUI (推荐)

```bash
# Streamlit 图形控制台 (AI 配置面板、逐 Payload 进度条、实时研判展示)
streamlit run web/app.py
```

### 4. CLI 命令行

```bash
# -- 标准模式 (无 AI) --
python main.py -t "http://target.com/page?id=1" -c 50

# -- 云端 AI 模式 (DeepSeek) --
python main.py -t "http://target.com/page?id=1" \
  --ai-mode api \
  --ai-key "sk-xxx" \
  --ai-api-base "https://api.deepseek.com" \
  --ai-api-model "deepseek-chat"

# -- 云端 AI 模式 (OpenAI) --
python main.py -t "http://target.com/page?id=1" \
  --ai-mode api \
  --ai-key "sk-xxx" \
  --ai-api-model "gpt-4o-mini"

# -- 云端 AI 模式 (Gemini) --
python main.py -t "http://target.com/page?id=1" \
  --ai-mode api \
  --ai-key "AIzaSy..." \
  --ai-api-base "https://generativelanguage.googleapis.com/v1beta" \
  --ai-api-model "gemini-1.5-flash"

# -- 本地 AI 模式 (隐私优先) --
python main.py -t "http://target.com/page?id=1" \
  --ai-mode local \
  --ai-model ./models/qwen2-0.5b-instruct.gguf

# -- SAST 代码审计 + AI 恶意判定 --
python main.py -t "/path/to/source" --plugins malware_scan --ai-mode local --ai-model ./models/qwen2-0.5b.gguf
```

---

## AI 模型配置

### 方式一：Web GUI 配置 (推荐)

1. 启动 Streamlit: `streamlit run web/app.py`
2. 在侧边栏找到 **AI 引擎配置** 面板
3. 选择模式（`关闭` / `本地模型` / `云端 API`）
4. 填入对应配置项，然后保存
5. **配置自动持久化至 `.ai_settings.json`**，后续启动无需重新输入

### 方式二：直接编辑配置文件

编辑项目根目录下的 `.ai_settings.json`：

```json
{
  "ai_mode": "api",
  "ai_model_path": "",
  "ai_api_key": "YOUR_API_KEY",
  "ai_api_base": "https://api.deepseek.com",
  "ai_api_model": "deepseek-chat",
  "ai_language": "zh",
  "ai_trust_env": true,
  "ai_proxy": ""
}
```

### 方式三：CLI 参数

```bash
python main.py -t "http://target.com" --ai-mode api --ai-key "sk-xxx" --ai-api-model "deepseek-chat"
```

> 通过以上三种方式设置的配置均自动持久化至 `.ai_settings.json`，后续使用直接生效。

---

### 云端模型配置

#### DeepSeek (推荐，中文优化)

| 配置项 | 值 |
|--------|-----|
| API Base | `https://api.deepseek.com` |
| API Model | `deepseek-chat` |
| API Key | 在 [platform.deepseek.com](https://platform.deepseek.com) 获取 |

#### OpenAI

| 配置项 | 值 |
|--------|-----|
| API Base | `https://api.openai.com/v1`（默认，可留空） |
| API Model | `gpt-4o-mini` 或 `gpt-4o` |
| API Key | 在 [platform.openai.com](https://platform.openai.com) 获取 |

#### Google Gemini

| 配置项 | 值 |
|--------|-----|
| API Base | `https://generativelanguage.googleapis.com/v1beta` |
| API Model | `gemini-1.5-flash` 或 `gemini-2.0-flash` |
| API Key | 在 [aistudio.google.com](https://aistudio.google.com) 获取 |

#### 兼容端点

任何兼容 OpenAI `/v1/chat/completions` 协议的服务均可使用：

- Azure OpenAI
- Qwen-Plus / 通义千问
- 零一万物 (Yi)
- Moonshot（月之暗面）

修改 `ai_api_base` 和 `ai_api_model` 即可接入。

#### 代理配置 (可选)

如需代理访问云端 API：

```json
{
  "ai_proxy": "http://127.0.0.1:7897",
  "ai_trust_env": true
}
```

---

### 本地模型配置

#### 步骤 1：安装推理后端

```bash
pip install llama-cpp-python
```

#### 步骤 2：下载 GGUF 模型

推荐模型（按大小/精度排序）：

| 模型 | 大小 | 推理速度 | 精度 |
|------|------|---------|------|
| Qwen2-0.5B-Instruct | ~400MB | 极快 (CPU) | Good |
| Qwen2-1.5B-Instruct | ~1GB | 快 (CPU) | Good+ |
| Llama-3.2-1B-Instruct | ~700MB | 快 (CPU) | Good |

```bash
# 下载推荐模型 (Qwen2-0.5B, ~400MB)
huggingface-cli download Qwen/Qwen2-0.5B-Instruct-GGUF \
  qwen2-0_5b-instruct-q4_k_m.gguf \
  --local-dir ./models/
```

#### 步骤 3：配置路径

CLI：
```bash
python main.py -t "http://target.com" --ai-mode local --ai-model ./models/qwen2-0_5b-instruct-q4_k_m.gguf
```

或编辑 `.ai_settings.json`：
```json
{
  "ai_mode": "local",
  "ai_model_path": "./models/qwen2-0_5b-instruct-q4_k_m.gguf"
}
```

> **注意**：本地模式所有推理在 CPU 上执行。代码和扫描数据不会离开主机。无需 GPU。

---

## 系统架构

### 多阶段流水线

```
+------------------------------------------------------------------------------+
|                        ScanEngine (调度中心)                                    |
+------------------------------------------------------------------------------+
|  Pre-Stage: 连通性检查                                                         |
|      |                                                                        |
|  Stage 1: INFO 侦察           ->  WAF 探测 / 指纹识别                          |
|      | (WAF 数据写入 SharedContext)                                             |
|  Stage 2: DAST POC            ->  BOLA || SQLi || XSS (并行执行, 互不阻塞)      |
|      | (detected_db_type + vulnerable_params 写入 SharedContext)                |
|  Stage 3: SAST 审计           ->  AST 后门扫描 / CVSS 评分                     |
|      | (变量追踪 + 净化检查)                                                    |
|  Stage 4: IAST 联动           ->  Sink 定位 + 净化函数缺失检测                  |
|      | (概率推理)                                                              |
|  Stage 5: Deep Reasoning      ->  多维研判 / 等级覆写 / AI 介入                |
|      |                                                                        |
|  Stage 6: CWE 分析            ->  CWE 关联 / 风险评分 / 修复建议               |
+------------------------------------------------------------------------------+
```

> **关键设计**：Stage 2 中 BOLA / SQLi / XSS 等所有 POC 插件通过 `asyncio.gather(return_exceptions=True)` 并行执行，每个插件拥有 30 分钟独立超时。任何单个插件的超时或异常**不会影响**其他插件的执行。

---

## 技术 FAQ

**Q1：BOLA 扫描完后 SQLi 不执行是什么原因？**
> v1.0 之前，引擎使用 5 分钟全局超时 + 无异常隔离的 `asyncio.gather`。BOLA 穷举超时后异常传播导致 SQLi 被取消。v1.0 修复为 30 分钟超时 + `return_exceptions=True` 完全隔离。

**Q2：AI 模式如何保障隐私安全？**
> `LOCAL` 模式所有推理在本地 CPU 执行，数据不会离开主机。`API` 模式会将代码片段发送至第三方服务器 -- UI 中提供明确提示。

**Q3：本地模型需要 GPU 吗？**
> 不需要。llama-cpp-python 支持纯 CPU 推理。Qwen2-0.5B 推理延迟约 0.5--1.5 秒，内存占用约 400MB。

**Q4：配置会持久化吗？**
> 是的。通过 CLI 或 Web GUI 设置的云端地址、API Key 和本地模型路径均自动保存至 `.ai_settings.json`，后续启动直接生效。

**Q5：为什么废弃静态盲注阈值？**
> 静态阈值（sim >= 0.92）在页面内容少时产生误报，动态内容多时产生漏报。自适应相对差值模型仅要求 TRUE 比 FALSE 更接近基线，适应性显著提升。

**Q6：并行化如何保证不压垮目标？**
> 每个插件内部使用 `asyncio.Semaphore` 控制并发度（SQLi:5 / XSS:4 / BOLA:8）。WAF 模式自动增加随机延迟。

---

## 许可证

MIT License -- 仅供授权安全评估使用。

---

## 文档

- [使用指南 (中文)](./edu_CN.md) -- WebUI + CLI 使用教程
- [User Guide (English)](./edu_EN.md) -- WebUI + CLI 使用指南

---

<p align="center">
  <b>OpenScanner v1.5.0</b> -- DAST x SAST x IAST x Mutation x AI Reasoning x Compliance<br/>
  Built with asyncio + mutation intelligence + hybrid AI reasoning + compliance reporting
</p>
