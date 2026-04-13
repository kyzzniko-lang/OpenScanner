# 🔍 OpenScanner v1.0 — AI-Powered Hybrid Security Scanner

> **智能混合安全扫描引擎：DAST + SAST + IAST + AI 深度研判**
> 集成混合 AI 深度研判引擎、自适应变异对抗、视觉取证 (VEPV)、自主业务流发现 (ABFD) 与工业级并发扫描引擎。

[![Python](https://img.shields.io/badge/Python-3.9+-3776ab?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Security](https://img.shields.io/badge/Security-DAST%20%2B%20SAST%20%2B%20IAST%20%2B%20AI-red?style=flat-square&logo=shield)](.)
[![httpx](https://img.shields.io/badge/Engine-httpx%20%2B%20asyncio-00b4d8?style=flat-square)](https://www.python-httpx.org)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-ff4b4b?style=flat-square&logo=streamlit)](https://streamlit.io)
[![AI](https://img.shields.io/badge/AI-Hybrid%20LLM-blueviolet?style=flat-square&logo=openai)](.)
[![Status](https://img.shields.io/badge/Status-v1.0-22c55e?style=flat-square)](.)

---

## 📌 项目概述

OpenScanner 是一款从零构建的模块化安全评估平台。v1.0 版本集成：

- **混合 AI 引擎 (Hybrid AI Engine)** — 本地大模型 (隐私优先/离线运行) 与云端 API (DeepSeek / OpenAI / Gemini，精度优先) 自由切换
- **穷举式共识检测模型** — 所有 payload 全量测试后汇总结果，AI 综合研判，不遗漏任何攻击向量
- **高性能并发扫描** — 基于 `asyncio.gather` + `Semaphore` 的并行 payload 探测，5-10x 速度提升
- **六阶段流水线** — INFO 侦察 → DAST 漏洞扫描 → SAST 审计 → IAST 联动 → 深度研判 → CWE 分析

---

## 🏆 核心能力矩阵

### 🤖 混合 AI 深度研判引擎

```
                       ┌──────────────────────────┐
                       │    AIEngine (Orchestrator) │
                       ├──────────────────────────┤
                       │  Factory Pattern:          │
                       │    mode=OFF   → Null       │
                       │    mode=LOCAL → llama.cpp  │
                       │    mode=API   → OpenAI/    │
                       │                 Gemini     │
                       └────────┬─────────────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          │                     │                       │
    ┌─────▼──────┐     ┌───────▼───────┐     ┌────────▼────────┐
    │  AUDITOR    │     │ EXPLOIT_VERIF │     │ BYPASS_EXPERT   │
    │  代码审计    │     │ 漏洞验证      │     │ WAF 绕过建议    │
    └────────────┘     └───────────────┘     └─────────────────┘
```

- **3 种 AI 专家角色** — 代码审计 (SAST) / 漏洞验证 (DAST) / WAF 绕过 (Mutation)
- **双模式架构** — `LOCAL`: Qwen2-0.5B/Llama-3.2-1B via llama-cpp-python (纯 CPU, 离线) / `API`: OpenAI, Google Gemini, DeepSeek (云端, 高精度)
- **智能缓存** — 基于哈希的推理结果缓存 (`.ai_cache.json`) 消除重复推理
- **延迟加载+自动卸载** — 模型首次使用时加载, 空闲 5 分钟自动卸载节省内存
- **配置持久化** — 用户首次设置的云端服务器地址、API Key 及本地模型路径自动保存至 `.ai_settings.json`，下次使用无需重新输入

### 🧬 自适应变异对抗引擎

- **9 种变异策略** — 大小写随机 / 内联注释 / Hex 双编码 / 空格替代 / DB 特化注释 / CHAR() / HPP / AI 绕过
- **上下文感知** — 基于 `detected_db_type` 和 WAF 指纹实时生成混淆 Payload

### 💉 SQL 注入五层递进检测

| 阶段 | 检测方法 | 说明 |
|------|---------|------|
| ① | 智能注入点嗅探 | 19 种正则自动区分测试参数与业务背景 (Submit/token) |
| ② | 报错注入 | MySQL / PostgreSQL / MSSQL / Oracle / SQLite 错误特征码 |
| ③ | 动态变异引擎 | 基于 DB 类型 + WAF 指纹生成混淆 Payload |
| ④ | 自适应布尔盲注 | 响应指纹 + SimHash 双验证 + 二次确认排除抖动 |
| ⑤ | 时间盲注 | 预采样网络校准 + 反向验证 SLEEP(0) |

### 🔒 BOLA/IDOR 越权检测

- **三向对比** — 正向基线 + 负向基线 + 探测结果三角验证
- **核心特征增量分析** — 防止空数据误判
- **未授权访问 + HTTP 方法篡改** — 全方位鉴权检查

### ⚔️ XSS 跨站脚本检测

- **上下文感知注入** — 自动识别属性/脚本/标签上下文并闭合
- **WAF 隐蔽混淆模式** — 大小写变异 + 编码绕过
- **反射点探测 + 真实 Payload 验证** — 两阶段精准检测

---

## ⚡ v1.0 核心更新日志

### 🐛 重大 Bug 修复

| 问题 | 根因 | 修复方案 |
|------|------|---------|
| **BOLA 执行完后 SQLi 不执行** | 引擎超时 (300s) 导致 BOLA 超时后 `asyncio.gather` 异常传播，取消所有并行任务 | ① 超时提升至 **1800s** ② `gather` 添加 `return_exceptions=True` 隔离异常 |
| **SQL 注入置信度低** | 单 payload 命中即停止，未穷举所有攻击向量 | 改为穷举式共识模型：全量 payload 测试 → 汇总 Evidence Matrix → AI 研判 |
| **BOLA 检测误报率高** | 公开页面未授权访问检测、静态页面方法篡改、内容漂移阈值过低 | ① 未授权检测仅针对含 API/管理路径的 URL ② 方法篡改跳过静态资源 ③ HTML 内容漂移阈值提升至 5 |
| **URL 含非 ASCII 字符连接失败** | 爬虫发现的 URL 路径含中文等字符，httpx 要求 ASCII 编码 | 新增 `_ensure_ascii_url()` 自动 percent-encode 非 ASCII 字符 |
| **路径参数未被注入测试** | 爬虫 URL 如 `/297/list.htm` 无查询参数，SQLi/XSS 插件直接跳过 | 新增 `synthesize_path_id_urls()` 自动从路径提取数字 ID 合成 `?id=` 参数 |

### 🚀 新功能

| 功能 | 说明 |
|------|------|
| **扫描强度分级** | 轻度 (仅注入点) / 中度 (注入点+关键端点) / 全量 — CLI: `--scan-intensity` / Web UI: 侧边栏选择 |
| **路径 ID 自动合成** | 从 URL 路径中识别数字/混合 ID (如 `/297/`, `/c132a90603/`)，自动合成 `?id=` 注入测试 URL |
| **日期段智能排除** | 路径中的日期段 (如 `/2026/0413/`) 不会被误识别为注入 ID |

### 🚀 性能优化

| 模块 | 优化方式 | 预估加速 |
|------|---------|---------|
| SQLi 报错注入 | Error payload 依然逐个发送保证精准进度 | — |
| SQLi 布尔盲注 | `asyncio.gather` + `SimHash` 并行比对 | 2-3x |
| SQLi 时间盲注 | 反向验证 SLEEP(0) | 减少误报 |
| XSS Payload 验证 | `asyncio.gather` + `Semaphore(4)` 并发 | 3-4x |
| BOLA ID 探测 | `asyncio.gather` + `Semaphore(8)` 并发 | 5-8x |
| 引擎超时 | 300s → 1800s | 消除截断 |
| 引擎容错 | `return_exceptions=True` | 零级联故障 |

### 📋 功能增强

- **配置持久化** — AI 设置 (云端地址/API Key/本地模型路径) 自动保存至 `.ai_settings.json`
- **穷举式共识模型** — 所有插件穷举测试后统一输出 Evidence Matrix 给 AI 研判
- **WAF 联动增强** — WAF 模式自动调低并发度 + 增加随机延迟

---

## 📂 项目结构

```
OpenScanner/
├── main.py                     # 🖥️  Rich CLI 指挥中心
├── setup.py                    # 🚀 一键部署
├── requirements.txt            # 📦 依赖清单
├── .ai_settings.json           # 🔑 AI 配置持久化文件 (自动生成)
├── config/
│   └── settings.yaml           # ⚙️  全局配置
├── core/
│   ├── engine.py               # 🧠 六阶段扫描调度引擎 (v1.0: 容错 + 超时优化)
│   ├── request.py              # 💗 异步请求引擎 + smart_merge + SQL 安全编码
│   ├── reasoner.py             # 🎯 5 维漏洞深度研判器 (含 AI 维度)
│   ├── browser.py              # 🌐 Playwright 视觉取证引擎
│   ├── spider.py               # 🕷️ 异步爬虫 + ABFD 业务流发现
│   └── ai/                     # 🤖 Hybrid AI Engine
│       ├── __init__.py
│       ├── base.py             #    抽象 Provider 接口 + 数据结构
│       ├── prompts.py          #    三角色专用 System Prompt 库
│       ├── local_provider.py   #    本地 LLM (llama-cpp-python / GGUF)
│       ├── api_provider.py     #    云端 API (OpenAI / Gemini / DeepSeek 兼容)
│       └── engine.py           #    AI 指挥引擎 (Factory + Cache + 降级)
├── plugins/
│   ├── base.py                 # 🔌 插件基类 + ScanResult
│   ├── info/
│   │   └── waf_check.py        # 🛡️  WAF 探测 (指纹写入 SharedContext)
│   ├── pocs/
│   │   ├── sqli_scan.py        # 💉 SQLi v3.0 (五层递进 + 穷举共识)
│   │   ├── xss_scan.py         # ⚔️  XSS 检测 (并行优化 + 上下文感知)
│   │   └── bola_idor.py        # 🔓 BOLA/IDOR (并行 ID 探测)
│   └── audit/
│       └── malware_scan.py     # 🔎 SAST 审计 + 污点追踪 + AI 恶意判定
├── web/
│   └── app.py                  # 🌐 Streamlit GUI (AI 配置面板 + 研判展示)
├── utils/
│   ├── reporter.py             # 📝 报告引擎 (Markdown/JSON)
│   ├── analyser.py             # 📊 CWE 关联分析器
│   ├── mutator.py              # 🧬 9 策略自适应变异引擎
│   ├── poc_gen.py              # 🛠️ POC 一键复现脚本生成器
│   └── patch_advisor.py        # 💊 自动修复建议引擎
└── tests/
    └── test_sqli_plugin.py     # ✅ 单元测试
```

---

## 🚀 快速开始

### 1. 一键部署

```bash
python setup.py
```

### 2. Web GUI (推荐)

```bash
# Streamlit 图形控制台 (含 AI 配置面板、逐 Payload 进度条、实时研判展示)
streamlit run web/app.py
```

### 3. CLI 命令行

```bash
# ── 传统模式 (无 AI) ──
python main.py -t "http://target.com/page?id=1" -c 50

# ── 云端 AI 模式 (DeepSeek) ──
python main.py -t "http://target.com/page?id=1" \
  --ai-mode api \
  --ai-key "sk-xxx" \
  --ai-api-base "https://api.deepseek.com" \
  --ai-api-model "deepseek-chat"

# ── 云端 AI 模式 (OpenAI) ──
python main.py -t "http://target.com/page?id=1" \
  --ai-mode api \
  --ai-key "sk-xxx" \
  --ai-api-model "gpt-4o-mini"

# ── 云端 AI 模式 (Gemini) ──
python main.py -t "http://target.com/page?id=1" \
  --ai-mode api \
  --ai-key "AIzaSy..." \
  --ai-api-base "https://generativelanguage.googleapis.com/v1beta" \
  --ai-api-model "gemini-1.5-flash"

# ── 本地 AI 模式 (隐私优先) ──
python main.py -t "http://target.com/page?id=1" \
  --ai-mode local \
  --ai-model ./models/qwen2-0.5b-instruct.gguf

# ── SAST 代码审计 + AI 恶意判定 ──
python main.py -t "/path/to/source" --plugins malware_scan --ai-mode local --ai-model ./models/qwen2-0.5b.gguf
```

---

## 🤖 AI 模型配置指南

### 方式一：通过 Web GUI 配置 (推荐)

1. 启动 Streamlit: `streamlit run web/app.py`
2. 在侧边栏找到 **「AI 引擎配置」** 面板
3. 选择模式 (`关闭` / `本地模型` / `云端 API`)
4. 填入对应配置项 → 点击保存
5. **配置自动持久化到 `.ai_settings.json`**，下次启动无需重新输入

### 方式二：直接编辑配置文件

编辑项目根目录下的 `.ai_settings.json`:

```json
{
  "ai_mode": "api",
  "ai_model_path": "",
  "ai_api_key": "你的API密钥",
  "ai_api_base": "https://api.deepseek.com",
  "ai_api_model": "deepseek-chat",
  "ai_language": "zh",
  "ai_trust_env": true,
  "ai_proxy": ""
}
```

### 方式三：CLI 启动参数

```bash
python main.py -t "http://target.com" --ai-mode api --ai-key "sk-xxx" --ai-api-model "deepseek-chat"
```

> **所有三种方式设置的配置都会自动保存到 `.ai_settings.json`，下次使用直接生效。**

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
| API Base | `https://api.openai.com/v1` (默认，可留空) |
| API Model | `gpt-4o-mini` 或 `gpt-4o` |
| API Key | 在 [platform.openai.com](https://platform.openai.com) 获取 |

#### Google Gemini

| 配置项 | 值 |
|--------|-----|
| API Base | `https://generativelanguage.googleapis.com/v1beta` |
| API Model | `gemini-1.5-flash` 或 `gemini-2.0-flash` |
| API Key | 在 [aistudio.google.com](https://aistudio.google.com) 获取 |

#### 其他兼容端点

任何兼容 OpenAI `/v1/chat/completions` 协议的服务均可使用，包括：
- Azure OpenAI
- Qwen-Plus / 通义千问
- 零一万物 (Yi)
- Moonshot (月之暗面)

只需修改 `ai_api_base` 和 `ai_api_model` 即可。

#### 代理设置 (可选)

如果需要代理访问云端 API：

```json
{
  "ai_proxy": "http://127.0.0.1:7897",
  "ai_trust_env": true
}
```

---

### 本地模型配置

#### 步骤 1: 安装推理后端

```bash
pip install llama-cpp-python
```

#### 步骤 2: 下载 GGUF 模型

推荐模型 (按大小/精度排序):

| 模型 | 大小 | 推理速度 | 精度 |
|------|------|---------|------|
| Qwen2-0.5B-Instruct | ~400MB | 极快 (CPU) | ⭐⭐⭐ |
| Qwen2-1.5B-Instruct | ~1GB | 快 (CPU) | ⭐⭐⭐⭐ |
| Llama-3.2-1B-Instruct | ~700MB | 快 (CPU) | ⭐⭐⭐ |

```bash
# 下载推荐模型 (Qwen2-0.5B, ~400MB)
huggingface-cli download Qwen/Qwen2-0.5B-Instruct-GGUF \
  qwen2-0_5b-instruct-q4_k_m.gguf \
  --local-dir ./models/
```

#### 步骤 3: 配置路径

CLI:
```bash
python main.py -t "http://target.com" --ai-mode local --ai-model ./models/qwen2-0_5b-instruct-q4_k_m.gguf
```

或编辑 `.ai_settings.json`:
```json
{
  "ai_mode": "local",
  "ai_model_path": "./models/qwen2-0_5b-instruct-q4_k_m.gguf"
}
```

> **注意**: 本地模式所有推理在 CPU 上执行，代码和扫描数据永不离开你的机器。无需 GPU。

---

## 🏛️ 系统架构

### 多阶段流水线

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        ScanEngine (指挥中心)                                  │
├──────────────────────────────────────────────────────────────────────────────┤
│  Pre-Stage: 连通性检查                                                        │
│      ↓                                                                       │
│  Stage 1: INFO 侦察           →  WAF 探测 / 指纹识别                          │
│      ↓ (WAF 数据写入 SharedContext)                                           │
│  Stage 2: DAST POC            →  BOLA ∥ SQLi ∥ XSS (并行执行, 互不阻塞)        │
│      ↓ (detected_db_type + vulnerable_params 写入 SharedContext)             │
│  Stage 3: SAST 审计           →  AST 后门扫描 / CVSS 评分                     │
│      ↓ (变量追踪 + 净化检查)                                                  │
│  Stage 4: IAST 联动           →  Sink 定位 + 净化函数缺失检测                  │
│      ↓ (概率推理)                                                             │
│  Stage 5: Deep Reasoning      →  多维研判 / 等级覆写 / 🤖 AI 介入             │
│      ↓                                                                       │
│  Stage 6: CWE 分析            →  CWE 关联 / 风险评分 / 修复建议                │
└──────────────────────────────────────────────────────────────────────────────┘
```

> **关键设计**: Stage 2 中 BOLA / SQLi / XSS 等所有 POC 插件通过 `asyncio.gather(return_exceptions=True)` 并行执行，每个插件拥有 30 分钟独立超时。任何单个插件的超时或异常**不会影响**其他插件的执行。

---

## 🎓 技术 FAQ

**Q1: BOLA 扫描完后 SQLi 不执行是什么原因？**
> v1.0 之前引擎使用 5 分钟全局超时 + 无异常隔离的 `asyncio.gather`，BOLA 穷举超时后异常传播导致 SQLi 被取消。v1.0 修复为 30 分钟超时 + `return_exceptions=True` 完全隔离。

**Q2: AI 模式如何保障隐私安全？**
> `LOCAL` 模式所有推理在本地 CPU 执行，数据永不离开你的机器。`API` 模式会将代码片段发送至第三方服务器 — UI 中会明确提示。

**Q3: 本地模型需要 GPU 吗？**
> 不需要。llama-cpp-python 支持纯 CPU 推理。Qwen2-0.5B 推理延迟约 0.5–1.5 秒，内存约 400MB。

**Q4: 配置会持久化吗？**
> 是的。首次通过 CLI / Web GUI 设置的云端地址、API Key 和本地模型路径都会自动保存到 `.ai_settings.json`，下次启动直接生效。

**Q5: 为什么废弃静态盲注阈值？**
> 静态阈值 (sim ≥ 0.92) 在页面内容少时误报，动态内容多时漏报。自适应相对差值模型只关心 TRUE 比 FALSE 更像基线，适应性极强。

**Q6: 并行化如何保证不压垮目标？**
> 每个插件内部使用 `asyncio.Semaphore` 控制并发度 (SQLi:5 / XSS:4 / BOLA:8)，WAF 模式自动增加随机延迟。

---

## 📄 License

MIT License — For authorized security assessments only / 仅供授权安全评估使用。

---

<p align="center">
  <b>🔍 OpenScanner v1.0</b> — DAST × SAST × IAST × Mutation × AI Reasoning<br/>
  <i>Built with ⚡ asyncio + 🧬 mutation intelligence + 🤖 hybrid AI reasoning</i>
</p>
# OpenScanner
