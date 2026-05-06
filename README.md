<h1 align="center">OpenScanner</h1>

<p align="center">
  <b>Hybrid Security Assessment Platform — DAST | SAST | IAST | AI Reasoning</b>
</p>

<p align="center">
  <a href="./README_CN.md">中文</a> | <a href="./README_EN.md">English</a>
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
  
</p>

> **30-second demo**: `docker run --rm -p 8501:8501 openscanner/openscanner` or `python main.py --demo`

---

## Why OpenScanner?

| | **OpenScanner** | **Nuclei** | **OWASP ZAP** | **SQLMap** |
|---|---|---|---|---|
| **DAST (Web)** | 16 vuln types, exhaustive payloads | Template-based, community templates | Proxy-based spider | SQLi only |
| **SAST (Code)** | Built-in AST analysis + AI audit | No | Add-on (beta) | No |
| **IAST (Runtime)** | Sink tracing + taint analysis | No | No | No |
| **AI Reasoning** | Local LLM + Cloud API (OpenAI/Gemini/DeepSeek) | No | No | No |
| **WAF Bypass** | 9-strategy mutation engine | Basic encoding | No | Tamper scripts |
| **Blind SQLi** | Adaptive boolean + time-based with SimHash | No | Add-on | Yes (dedicated) |
| **IDOR/BOLA** | Tri-directional comparison | Via templates | Basic auth testing | No |
| **Reports** | MD/JSON/CSV/SARIF/JUnit/PDF/Compliance | SARIF, Markdown | HTML, JSON, XML | Dump format |
| **Compliance** | OWASP Top 10 + PCI-DSS + SOC2 + HIPAA | No | Add-on | No |
| **CI/CD** | Native exit codes + GitHub Action + Docker | Native + GitHub Action | Docker + CLI | CLI |
| **Offline** | Full functionality (local AI mode) | Yes (templates) | Partial | Yes |
| **Language** | Python (async) | Go | Java | Python |

## Overview

OpenScanner is a modular security assessment platform engineered from the ground up. The v1.5 release delivers:

- **Hybrid AI Engine** -- Seamless switching between local large language models (privacy-first, offline execution) and cloud API backends (DeepSeek / OpenAI / Gemini, precision-first)
- **Exhaustive Consensus Detection Model** -- Full-spectrum payload testing with consolidated evidence matrix and AI-driven corroboration, eliminating missed attack vectors
- **High-Performance Concurrent Scanning** -- Parallel payload probing via `asyncio.gather` + `Semaphore`, delivering 5--10x throughput improvement
- **Six-Stage Pipeline** -- INFO Reconnaissance, DAST Vulnerability Scanning, SAST Code Audit, IAST Correlation, Deep Reasoning, CWE Analysis
- **21 Plugins (19 Vulnerability Types)** -- SQLi, XSS, DOM XSS, BOLA/IDOR, SSRF, LFI, CMD Injection, SSTI, CSRF, JWT, File Upload, Logic Flaw, API Fuzzing, GraphQL, Auth Bypass, Info Leak, WAF Detection, Malware Audit, AI Code Audit

---

## Core Capabilities

### Hybrid AI Deep Reasoning Engine

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
    | Code Audit |      | Verification  |      | WAF Bypass   |
    +------------+      +---------------+      +--------------+
```

- **3 AI Expert Roles** -- Code Audit (SAST) / Vulnerability Verification (DAST) / WAF Bypass (Mutation)
- **Dual-Mode Architecture** -- `LOCAL`: Qwen2-0.5B/Llama-3.2-1B via llama-cpp-python (CPU-only, offline) / `API`: OpenAI, Google Gemini, DeepSeek (cloud, high precision)
- **Intelligent Caching** -- Hash-based inference result caching (`.ai_cache.json`) eliminating redundant computation
- **Lazy Loading with Auto-Unload** -- Models load on first use and automatically unload after 5 minutes of inactivity to conserve memory
- **Configuration Persistence** -- Cloud server address, API key, and local model path are persisted to `.ai_settings.json` on first configuration

### Adaptive Mutation Adversary Engine

- **9 Mutation Strategies** -- Random case variation / inline comments / hex double-encoding / whitespace substitution / DB-specific comments / CHAR() / HPP / AI bypass
- **Context-Aware** -- Real-time obfuscated payload generation based on `detected_db_type` and WAF fingerprinting

### SQL Injection -- Five-Layer Progressive Detection

| Stage | Method | Description |
|-------|--------|-------------|
| 1 | Intelligent Injection Point Sniffing | 19 regex patterns distinguishing test parameters from business context (Submit/token) |
| 2 | Error-Based Injection | MySQL / PostgreSQL / MSSQL / Oracle / SQLite error signature matching |
| 3 | Dynamic Mutation Engine | Obfuscated payload generation based on DB type + WAF fingerprint |
| 4 | Adaptive Boolean Blind Injection | Response fingerprint + SimHash dual verification + secondary confirmation eliminating jitter |
| 5 | Time-Based Blind Injection | Pre-sampling network calibration + reverse verification SLEEP(0) |

### BOLA/IDOR Authorization Bypass Detection

- **Tri-Directional Comparison** -- Positive baseline + negative baseline + probe result triangulated verification
- **Core Feature Incremental Analysis** -- Preventing false positives from empty data
- **Unauthorized Access + HTTP Method Tampering** -- Comprehensive authentication verification

### Cross-Site Scripting (XSS) Detection

- **Context-Aware Injection** -- Automatic attribute/script/tag context identification and closure
- **WAF Evasion Mode** -- Case mutation + encoding bypass
- **Reflection Point Probing + Real Payload Verification** -- Two-stage precise detection

### Performance Benchmarks

Tested against a local vulnerable application (DVWA-like) with 50 endpoints, 120 parameters:

| Plugin | Payloads | Concurrency | Total Requests | Time | Req/sec |
|--------|----------|-------------|----------------|------|---------|
| SQLi (error + boolean + time) | 150+ | Semaphore(5) | 3,200 | 47s | 68 |
| XSS (reflected + context-aware) | 90+ | Semaphore(4) | 2,800 | 38s | 74 |
| BOLA/IDOR (tri-directional) | 40 per param | Semaphore(8) | 1,600 | 12s | 133 |
| SSRF (metadata + internal) | 80+ | Semaphore(6) | 2,100 | 29s | 72 |
| LFI (traversal + wrappers) | 100+ | Semaphore(6) | 2,400 | 31s | 77 |
| WAF Detection (6-dimension) | 37 | Semaphore(4) | 222 | 5s | 44 |
| Full scan (all plugins) | 600+ | Max 10 | 12,000+ | 3m 12s | 63 |

> **Hardware**: Apple M1, 16GB RAM, Python 3.11, single target.
> Run your own benchmark: `python main.py -t TARGET --crawl-depth 1 --concurrency 20`

---

## Quick Start

### Critical Bug Fixes

| Issue | File | Resolution |
|-------|------|------------|
| **main.py webhook NameError** | `main.py` | `run_scan` referenced undefined `args` causing webhook crash -- refactored as function parameter |
| **main.py except block engine undefined** | `main.py` | `engine = None` initialization + `if engine:` guard |
| **Exception leaking API key** | `main.py` | Traceback output restricted to verbose mode only |
| **vuln_count exit code inconsistency** | `main.py` | Simplified exit code logic |
| **HTTP/2 downgrade permanently modifying config** | `core/request.py` | Replaced with `_http2_enabled` instance flag |
| **DNS cache without TTL** | `core/request.py` | Added 60s TTL expiration mechanism |
| **_request_history unbounded growth** | `core/request.py` | Replaced with `deque(maxlen=1000)` |
| **DOM XSS recording name mismatch** | `core/engine.py` | `dom_xss_headless` -> `dom_xss_scan` |
| **Gemini API key leaking to URL** | `core/ai/api_provider.py` | Migrated to `params={"key": ...}` |
| **JSON parsing O(n^2)** | `core/ai/engine.py` | Limited search to 20000 characters + 50 candidates |
| **_load_cache not validating format** | `core/ai/engine.py` | Added `isinstance(data, dict)` validation |
| **RLHF _db unbounded growth** | `core/ai/rlhf.py` | Added `MAX_RECORDS=500` |
| **Docker service startup failure** | `docker-compose.yml` | ENTRYPOINT/command conflict resolved via `entrypoint:` override |
| **XSS POC payload not injected into URL** | `utils/poc_gen.py` | INJECT_URL constructed from param |
| **SQLite time-based blind injection ineffective** | `plugins/pocs/sqli_scan.py` | Migrated to RANDOMBLOB |
| **Crawler form field extraction failure** | `plugins/info/crawler.py` | Search inputs within `<form>...</form>` blocks instead of tag-level |

### Performance Optimization

| Module | Optimization | Acceleration |
|--------|-------------|--------------|
| Stage 1+3 | INFO Recon + SAST audit parallelization | 2x |
| Stage 5+6 | AI reasoning + browser forensic verification parallelization | 2x |
| Stage 7+8 | Attack chain orchestration + replay recording parallelization | 2x |
| Request Layer | DNS cache 60s TTL + latency reduced to 0.02--0.1s | 1.5x |
| SQLi | Per-parameter concurrency (`_test_one_param` + `asyncio.gather`) | 5--10x |
| XSS | GET/POST parameter parallel probing (`_probe_param` + `asyncio.gather`) | 3--4x |

### SAST Audit Engine Enhancement (malware_scan.py)

**16 new detection signatures** covering expanded security threat surface:

| Signature | CVSS | Description |
|-----------|------|-------------|
| Unsafe Deserialization | 9.0 | `pickle`/`yaml`/`marshal`/`shelve`/`jsonpickle` |
| Hardcoded Credentials | 8.0 | 18 variable names: password/api_key/secret_key/aws_secret, etc. |
| Path Traversal | 8.5 | File operation functions with parameters from `request.args`/`request.form` |
| SSRF | 7.5--9.0 | HTTP request functions + URL source tracing |
| Weak Cryptography | 6.5 | `md5`/`sha1`/`DES`/`random.random` |
| Template Injection | 8.0 | `jinja2`/`mako`/`django.template`/`string.Template` |
| Insecure Temp File | 5.5 | `tempfile.mktemp`/`os.tmpfile` (TOCTOU) |
| chr() Obfuscation | 7.0--8.5 | Single mark + dense call (>=5) marking |
| Archive Exfiltration Chain | 9.0 | `shutil.make_archive`/`zipfile` + network upload |
| Non-HTTP Exfiltration | 9.0 | SMTP/FTP/SMB channels |
| PHP Unsafe Deserialize | 9.5 | `unserialize($_GET/POST...)` |
| PHP File Inclusion | 9.0 | `include`/`require` + user input |
| PHP SSRF | 9.0 | `curl_exec`/`file_get_contents`/`fopen` |
| PHP 6 WebShell Variants | 9.5 | `assert()`/`preg_replace /e`/`create_function`/`call_user_func`/variable variables/`array_map` |
| PHP Hardcoded Credentials | 8.0 | `$db_password`/`$api_key`/`$aws_secret` |
| PHP Direct eval() RCE | 10.0 | `eval($_GET/POST...)` |

Taint tracking sink extensions: +6 (`loads`/`write`/`send`/`format`, etc.)
Sanitization function extensions: Python +10 / PHP +8

### POC Plugin Payload Expansion

| Plugin | New Payloads | Key Enhancements |
|--------|-------------|-----------------|
| **SQLi** | +33 | Stacked queries / MySQL error functions / additional time-based / boolean closure variants / comment delimiter variants |
| **XSS** | +40 | 13 stealth payloads / comprehensive context-aware expansion / DOM dynamic parameter extraction |
| **CMD Injection** | +31 | Newline separators / quote wrapping / additional output detection (whoami/hostname/ipconfig) / 16 output indicators |
| **LFI** | +43 | PHP wrapper / file:// protocol / data:// encoding / 15 new paths / 11 sensitive patterns |
| **SSRF** | +40 | 7 cloud provider metadata / 11 new internal services / IP bypass (octal/hex/IPv6) / 4 new protocols |
| **DOM XSS** | +30 | 11 new sinks / 8 new sources / 11 new payloads |
| **WAF** | +37 | 6 new WAF signatures / XXE dimension added / expanded payloads per dimension |
| **Info Leak** | +30 | Kubernetes/Terraform/CMS/IDE config / Spring Boot endpoints / backup extensions |

### Test Coverage

- New `tests/test_payload_coverage.py` -- **34 tests**
- Coverage: Python/PHP malicious code detection, XSS DOM dynamic parameter extraction, SecurityVisitor, payload non-empty validation
- Total test count: **271** (across 20 test files)

---

## v1.1 Release Notes

### Critical Bug Fixes

| Issue | File | Resolution |
|-------|------|------------|
| **Webhook notification crash** | `main.py:1198` | `asyncio.run()` called within running event loop -- refactored to `await` |
| **DOM-XSS browser verification failure** | `core/engine.py:666,772` | Plugin name `dom_xss` mismatched with engine reference `dom_xss_headless` |
| **httpx hard dependency** | `logic_flaw.py`, `sqli_scan.py` | Removed unused `import httpx`; `waf_check.py` added try/except safe degradation |
| **Bare except clause** | `bola_idor.py:324` | `except:` -> `except Exception:` |

### v1.1 New Features

| Feature | Description |
|---------|-------------|
| **Information Leak Detection Plugin** | 80+ sensitive paths: .git/.env/.svn/DS_Store/backup files/keys/API documentation/debug endpoints |
| **OpenAPI/Swagger Parsing** | Auto-detect API documentation, extract endpoints + parameters for scan context injection, detect unauthorized sensitive APIs |
| **CVE/NVD Vulnerability Database** | SQLite cache + 40+ built-in CVEs + CWE auto-correlation + NVD online query |
| **Compliance Baseline Report** | OWASP Top 10 (2021) + PCI-DSS v4.0 mapping + scoring system + `--export-compliance` |
| **Scheduled Scan Scheduler** | YAML configuration for scheduled tasks + Webhook push + CI/CD thresholds: `python -m utils.scheduler` |
| **SQLite Persistence** | Replacing JSON file storage with structured query/pagination/vulnerability state management/full-text search |
| **Docker One-Click Deployment** | `Dockerfile` + `docker-compose.yml` (Web GUI + REST API + Scheduler) |
| **Per-Domain Rate Limiting** | `RequestConfig(domain_rpm=60)` sliding window rate control |
| **REST API Authentication** | `X-API-Key` header authentication with file/environment variable configuration |
| **Compliance Report Export** | CLI `--export-compliance compliance.md` generating OWASP/PCI-DSS reports |

### New/Modified Files

```
plugins/info/
  +-- info_leak.py          # [NEW] Information leak detection (80+ sensitive paths)
  +-- openapi_parser.py     # [NEW] OpenAPI/Swagger document parsing

utils/
  +-- cve_db.py             # [NEW] CVE/NVD vulnerability database (SQLite)
  +-- compliance.py         # [NEW] Compliance baseline report (OWASP + PCI-DSS)
  +-- scheduler.py          # [NEW] Scheduled scan scheduler
  +-- db.py                 # [NEW] SQLite persistent storage

config/
  +-- scheduler.yaml        # [NEW] Scheduler configuration example

Dockerfile                   # [NEW] Docker deployment
docker-compose.yml           # [NEW] Orchestration (Web + API + Scheduler)
.dockerignore                # [NEW] Docker ignore rules

tests/
  +-- test_core_upgrades.py  # 56 tests -- core upgrade tests
  +-- test_new_features.py   # 29 tests -- new feature tests
```

---

## v1.0 Core Release Notes

### Critical Bug Fixes

| Issue | Root Cause | Resolution |
|-------|-----------|------------|
| **BOLA completion preventing SQLi execution** | Engine timeout (300s) caused BOLA timeout to propagate exceptions through `asyncio.gather`, cancelling all parallel tasks | 1. Timeout increased to **1800s** 2. `gather` added `return_exceptions=True` for exception isolation |
| **Low SQL injection confidence** | Single payload match terminated testing, not exhausting all attack vectors | Migrated to exhaustive consensus model: full payload test -> Evidence Matrix aggregation -> AI reasoning |
| **High BOLA false positive rate** | Unauthorized access detection on public pages, method tampering on static pages, content drift threshold too low | 1. Unauthorized detection restricted to API/admin path URLs 2. Method tampering skips static resources 3. HTML content drift threshold raised to 5 |
| **Non-ASCII URL connection failure** | Crawler-discovered URLs with non-ASCII characters; httpx requires ASCII encoding | Added `_ensure_ascii_url()` for automatic percent-encoding of non-ASCII characters |
| **Path parameters not injected** | Crawler URLs like `/297/list.htm` without query parameters were skipped by SQLi/XSS plugins | Added `synthesize_path_id_urls()` to automatically extract numeric IDs from paths and synthesize `?id=` parameters |

### New Features

| Feature | Description |
|---------|-------------|
| **Scan History & Diff** | Automatic scan result archival with two-scan diff comparison (new/fixed/persistent vulnerabilities) |
| **Vulnerability State Management** | Per-vulnerability lifecycle: Open -> Fixing -> Fixed / Accepted Risk / False Positive |
| **CWE/OWASP Mapping** | Automatic CWE-ID + OWASP Top 10 + remediation advisory link correlation |
| **Scan Templates** | 3 built-in templates (Quick Recon / Deep Audit / Compliance) + custom template persistence |
| **Webhook Notifications** | Auto-push to Feishu/DingTalk/Slack with severity threshold triggers |
| **REST API** | FastAPI endpoints: POST /scan, GET /history, GET /diff and other CI/CD integration endpoints |
| **PDF Reports** | One-click compliant PDF report generation (requires `pip install reportlab`) |
| **CI/CD-Ready Exit Codes** | `--fail-on high` controls exit code; direct GitHub Actions / GitLab CI integration |
| **Scan Intensity Levels** | Light / Medium / Full -- CLI: `--scan-intensity` / Web UI: sidebar selection |
| **Path ID Auto-Synthesis** | Numeric/mixed IDs in URL paths automatically synthesized as `?id=` injection test URLs |
| **Date Segment Smart Exclusion** | Date segments in paths excluded from injection ID identification |

### Performance Optimization

| Module | Optimization | Estimated Acceleration |
|--------|-------------|----------------------|
| SQLi Error-Based | Error payloads sent sequentially for precise progress tracking | -- |
| SQLi Boolean Blind | `asyncio.gather` + `SimHash` parallel comparison | 2--3x |
| SQLi Time-Based | Reverse verification SLEEP(0) | Reduced false positives |
| XSS Payload Verification | `asyncio.gather` + `Semaphore(4)` concurrency | 3--4x |
| BOLA ID Probing | `asyncio.gather` + `Semaphore(8)` concurrency | 5--8x |
| Engine Timeout | 300s -> 1800s | Eliminating truncation |
| Engine Fault Tolerance | `return_exceptions=True` | Zero cascade failure |

### Feature Enhancements

- **Configuration Persistence** -- AI settings (cloud address/API key/local model path) auto-saved to `.ai_settings.json`
- **Exhaustive Consensus Model** -- All plugins exhaustively test then output unified Evidence Matrix for AI reasoning
- **WAF Integration Enhancement** -- WAF mode auto-reduces concurrency and adds randomized delay

---

## Project Structure

```
OpenScanner/
+-- main.py                     # CLI command center (Rich console)
+-- setup.py                    # One-click deployment
+-- Dockerfile                  # Docker deployment
+-- docker-compose.yml          # Orchestration (Web + API + Scheduler)
+-- requirements.txt            # Dependency manifest
+-- .ai_settings.json           # AI configuration persistence (auto-generated)
+-- config/
|   +-- settings.yaml           # Global configuration
|   +-- scheduler.yaml          # Scheduled scan configuration
+-- data/                       # Persistent data (auto-generated)
|   +-- scan_history/           # Scan history records (JSON)
|   +-- scan_templates/         # Custom scan templates
|   +-- openscanner.db          # SQLite persistent storage
|   +-- cve_cache.db            # CVE vulnerability database cache
|   +-- api_keys.txt            # REST API keys
+-- core/
|   +-- engine.py               # Six-stage scan orchestration engine (v1.5: parallelized + audit enhanced)
|   +-- request.py              # Async request engine + smart_merge + per-domain rate limiting
|   +-- reasoner.py             # 5-dimension vulnerability deep reasoner (incl. AI dimension)
|   +-- browser.py              # Playwright visual forensics engine
|   +-- spider.py               # Async crawler + ABFD business flow discovery
|   +-- validator.py            # Vulnerability validator
|   +-- attack_chain.py         # Attack chain orchestration
|   +-- replay_lab.py           # Replay recording laboratory
|   +-- ai/                     # Hybrid AI Engine
|       +-- __init__.py
|       +-- base.py             # Abstract Provider interface + data structures
|       +-- prompts.py          # Three-role System Prompt library
|       +-- local_provider.py   # Local LLM (llama-cpp-python / GGUF)
|       +-- api_provider.py     # Cloud API (OpenAI / Gemini / DeepSeek compatible)
|       +-- engine.py           # AI orchestration engine (Factory + Cache + degradation)
|       +-- auditor.py          # AVA auditor
|       +-- rlhf.py             # RLHF feedback management
|       +-- debate.py           # Debate orchestrator
|       +-- preprocessor.py     # AI preprocessor
+-- plugins/
|   +-- base.py                 # Plugin base class + ScanResult
|   +-- info/
|   |   +-- crawler.py          # Site crawler
|   |   +-- waf_check.py        # WAF detection + heatmap
|   |   +-- auth_session.py     # Authentication session management
|   |   +-- info_leak.py        # Information leak detection (80+ sensitive paths)
|   |   +-- openapi_parser.py   # OpenAPI/Swagger document parsing
|   +-- pocs/
|   |   +-- sqli_scan.py        # SQLi v3.0 (five-layer progressive + exhaustive consensus)
|   |   +-- xss_scan.py         # XSS detection (parallel optimization + context-aware)
|   |   +-- dom_xss.py          # DOM XSS (browser verification)
|   |   +-- bola_idor.py        # BOLA/IDOR (tri-directional comparison + parallel probing)
|   |   +-- logic_flaw.py       # Business logic flaws (price manipulation / privilege escalation)
|   |   +-- csrf.py             # CSRF detection
|   |   +-- ssrf.py             # SSRF detection
|   |   +-- lfi.py              # LFI / path traversal
|   |   +-- cmd_injection.py    # OS command injection
|   |   +-- api_fuzz.py         # API fuzzing
|   |   +-- jwt_scan.py         # JWT security scanning
|   |   +-- ssti_scan.py        # Server-Side Template Injection detection
|   |   +-- upload_scan.py      # File upload vulnerability detection
|   |   +-- auth_bypass.py      # Auth bypass (JWT weak sig / token expiry / role escalation)
|   |   +-- api_fuzz.py         # API fuzzing
|   |   +-- graphql_scan.py     # GraphQL security (introspection / depth DoS / batch abuse)
|   +-- demo/
|   |   +-- vuln_app.py         # Vulnerable demo app for testing
|   +-- audit/
|       +-- malware_scan.py     # SAST audit + taint tracking + AI malicious code determination
|       +-- ai_audit.py         # AI deep code audit
+-- web/
|   +-- app.py                  # Streamlit GUI (history/diff/templates/notifications/compliance)
|   +-- api.py                  # REST API (FastAPI + API Key authentication)
|   +-- server.py               # Web server launcher
|   +-- history.py              # Scan history management + vulnerability state
|   +-- scan_diff.py            # Scan diff engine
|   +-- templates.py            # Scan template management
|   +-- dashboard.py            # Dashboard components
|   +-- i18n.py                 # Internationalization (en/zh)
|   +-- settings.py             # Server-side persistent settings
|   +-- frontend/               # Vue.js frontend (standalone web interface)
|   +-- dist/                   # Built Vue.js frontend assets
+-- utils/
|   +-- reporter.py             # Report engine (MD/JSON/CSV/SARIF/JUnit/PDF/HTML/compliance)
|   +-- cwe_map.py              # CWE/OWASP mapping database + remediation advisories
|   +-- cve_db.py               # CVE/NVD vulnerability database (SQLite + online query)
|   +-- compliance.py           # Compliance baseline report (OWASP Top 10 + PCI-DSS)
|   +-- db.py                   # SQLite persistent storage
|   +-- scheduler.py            # Scheduled scan scheduler
|   +-- notifier.py             # Webhook notifications (Feishu/DingTalk/Slack)
|   +-- pdf_export.py           # PDF report generation (reportlab)
|   +-- analyser.py             # CWE correlation analyzer
|   +-- mutator.py              # 9-strategy adaptive mutation engine
|   +-- poc_gen.py              # POC one-click reproduction script generator
|   +-- patch_advisor.py        # Automated remediation advisory engine
|   +-- scan_policy.py          # Scope control + suppression rules
|   +-- auth.py                 # Authentication utilities
|   +-- asset_manager.py        # Asset management
|   +-- plugin_market.py        # Plugin marketplace
|   +-- pr_generator.py         # PR generation
|   +-- verify_fix.py           # Fix verification
|   +-- scan_queue.py           # Scan queue management
|   +-- security_grade.py       # Security grading
|   +-- vuln_kb.py              # Vulnerability knowledge base
|   +-- git_blame.py             # Git blame analyzer (fix attribution)
|   +-- ci_commenter.py          # CI/CD PR/MR security commenter
|   +-- fix_pr_generator.py      # Auto-fix PR generation
+-- tests/                      # 271 tests (20 files)
    +-- test_utils_modules.py    # 45 tests (utility modules)
    +-- test_core_upgrades.py   # 56 tests (core upgrades)
    +-- test_ai_modules.py      # 39 tests (AI modules)
    +-- test_new_features.py    # 29 tests (new features)
    +-- test_payload_coverage.py # 34 tests (payload coverage)
    +-- test_sqli_plugin.py     # 14 tests (SQLi plugin)
    +-- test_security_grade.py  # 10 tests (security grading)
    +-- test_ai_api_integration.py # 5 tests (AI API integration)
    +-- test_demo_app.py        # 7 tests (demo app)
    +-- test_github_action.py   # 5 tests (GitHub Action)
    +-- test_plugin_system.py   # 5 tests (plugin system)
    +-- test_scan_policy.py     # 3 tests (scan policy)
    +-- test_phase1_mvp.py      # 3 tests (phase 1 MVP)
    +-- test_plugin_additional_logic.py # 4 tests (plugin logic)
    +-- test_plugin_detection_logic.py # 3 tests (plugin detection)
    +-- test_consensus_flow.py  # 1 test (consensus flow)
    +-- test_reporter.py        # 2 tests (reporter)
    +-- test_plugin_contracts.py # 2 tests (plugin contracts)
    +-- test_plugin_more_logic.py # 2 tests (more plugin logic)
    +-- test_plugin_validation_rules.py # 2 tests (plugin validation)
```

---

## Quick Start

### 1. Docker (fastest way to try)

```bash
# Full stack: Web GUI + REST API
docker-compose up -d

# Or run a single scan
docker run --rm openscanner/openscanner -t "http://target.com/page?id=1"
```

Web GUI: `http://localhost:8501` | REST API: `http://localhost:8000`

### 2. pip install

```bash
pip install openscanner
openscanner --demo                  # zero-config demo with built-in vuln app
openscanner -t "http://target.com"  # scan a target
```

### 3. From source

```bash
python setup.py
```

### 3. Web GUI (Recommended)

```bash
# Streamlit graphical console (AI configuration panel, per-payload progress, real-time reasoning)
streamlit run web/app.py
```

### 4. CLI

```bash
# -- Standard mode (no AI) --
python main.py -t "http://target.com/page?id=1" -c 50

# -- Cloud AI mode (DeepSeek) --
python main.py -t "http://target.com/page?id=1" \
  --ai-mode api \
  --ai-key "sk-xxx" \
  --ai-api-base "https://api.deepseek.com" \
  --ai-api-model "deepseek-chat"

# -- Cloud AI mode (OpenAI) --
python main.py -t "http://target.com/page?id=1" \
  --ai-mode api \
  --ai-key "sk-xxx" \
  --ai-api-model "gpt-4o-mini"

# -- Cloud AI mode (Gemini) --
python main.py -t "http://target.com/page?id=1" \
  --ai-mode api \
  --ai-key "AIzaSy..." \
  --ai-api-base "https://generativelanguage.googleapis.com/v1beta" \
  --ai-api-model "gemini-1.5-flash"

# -- Local AI mode (privacy-first) --
python main.py -t "http://target.com/page?id=1" \
  --ai-mode local \
  --ai-model ./models/qwen2-0.5b-instruct.gguf

# -- SAST code audit + AI malicious code determination --
python main.py -t "/path/to/source" --plugins malware_scan --ai-mode local --ai-model ./models/qwen2-0.5b.gguf
```

---

## AI Model Configuration

### Method 1: Web GUI Configuration (Recommended)

1. Launch Streamlit: `streamlit run web/app.py`
2. Locate the **AI Engine Configuration** panel in the sidebar
3. Select mode (`Off` / `Local Model` / `Cloud API`)
4. Enter corresponding configuration items, then save
5. **Configuration auto-persists to `.ai_settings.json`**, effective on subsequent launches without re-entry

### Method 2: Direct Configuration File Editing

Edit `.ai_settings.json` in the project root:

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

### Method 3: CLI Parameters

```bash
python main.py -t "http://target.com" --ai-mode api --ai-key "sk-xxx" --ai-api-model "deepseek-chat"
```

> Configuration set through any of the three methods is automatically persisted to `.ai_settings.json` and takes effect on subsequent use.

---

### Cloud Model Configuration

#### DeepSeek (Recommended, Chinese-Optimized)

| Parameter | Value |
|-----------|-------|
| API Base | `https://api.deepseek.com` |
| API Model | `deepseek-chat` |
| API Key | Obtain at [platform.deepseek.com](https://platform.deepseek.com) |

#### OpenAI

| Parameter | Value |
|-----------|-------|
| API Base | `https://api.openai.com/v1` (default, may be left empty) |
| API Model | `gpt-4o-mini` or `gpt-4o` |
| API Key | Obtain at [platform.openai.com](https://platform.openai.com) |

#### Google Gemini

| Parameter | Value |
|-----------|-------|
| API Base | `https://generativelanguage.googleapis.com/v1beta` |
| API Model | `gemini-1.5-flash` or `gemini-2.0-flash` |
| API Key | Obtain at [aistudio.google.com](https://aistudio.google.com) |

#### Compatible Endpoints

Any service compatible with the OpenAI `/v1/chat/completions` protocol is supported, including:

- Azure OpenAI
- Qwen-Plus / Tongyi Qianwen
- Yi (01.AI)
- Moonshot

Simply modify `ai_api_base` and `ai_api_model` accordingly.

#### Proxy Configuration (Optional)

If proxy access to cloud APIs is required:

```json
{
  "ai_proxy": "http://127.0.0.1:7897",
  "ai_trust_env": true
}
```

---

### Local Model Configuration

#### Step 1: Install Inference Backend

```bash
pip install llama-cpp-python
```

#### Step 2: Download GGUF Model

Recommended models (sorted by size/precision):

| Model | Size | Inference Speed | Precision |
|-------|------|----------------|-----------|
| Qwen2-0.5B-Instruct | ~400MB | Very fast (CPU) | Good |
| Qwen2-1.5B-Instruct | ~1GB | Fast (CPU) | Good+ |
| Llama-3.2-1B-Instruct | ~700MB | Fast (CPU) | Good |

```bash
# Download recommended model (Qwen2-0.5B, ~400MB)
huggingface-cli download Qwen/Qwen2-0.5B-Instruct-GGUF \
  qwen2-0_5b-instruct-q4_k_m.gguf \
  --local-dir ./models/
```

#### Step 3: Configure Path

CLI:
```bash
python main.py -t "http://target.com" --ai-mode local --ai-model ./models/qwen2-0_5b-instruct-q4_k_m.gguf
```

Or edit `.ai_settings.json`:
```json
{
  "ai_mode": "local",
  "ai_model_path": "./models/qwen2-0_5b-instruct-q4_k_m.gguf"
}
```

> **Note**: Local mode executes all inference on CPU. Code and scan data never leave the host machine. No GPU required.

---

## System Architecture

### Multi-Stage Pipeline

```
+------------------------------------------------------------------------------+
|                        ScanEngine (Orchestration Center)                      |
+------------------------------------------------------------------------------+
|  Pre-Stage: Connectivity Check                                                |
|      |                                                                        |
|  Stage 1: INFO Recon           ->  WAF Detection / Fingerprinting            |
|      | (WAF data written to SharedContext)                                     |
|  Stage 2: DAST POC            ->  BOLA || SQLi || XSS (parallel, non-blocking)|
|      | (detected_db_type + vulnerable_params written to SharedContext)         |
|  Stage 3: SAST Audit           ->  AST backdoor scan / CVSS scoring          |
|      | (variable tracking + sanitization check)                               |
|  Stage 4: IAST Correlation     ->  Sink location + missing sanitization       |
|      | (probabilistic reasoning)                                              |
|  Stage 5: Deep Reasoning      ->  Multi-dimensional assessment / level        |
|      |                           override / AI intervention                   |
|  Stage 6: CWE Analysis         ->  CWE correlation / risk scoring / remediation|
+------------------------------------------------------------------------------+
```

> **Key Design**: In Stage 2, all POC plugins (BOLA / SQLi / XSS, etc.) execute in parallel via `asyncio.gather(return_exceptions=True)`, each with an independent 30-minute timeout. Timeout or exception in any single plugin **does not affect** execution of other plugins.

---

## Technical FAQ

**Q1: Why does SQLi not execute after BOLA completes?**
> Prior to v1.0, the engine used a 5-minute global timeout + non-isolated `asyncio.gather`. BOLA exhaustive timeout propagated exceptions, causing SQLi cancellation. v1.0 resolved this with 30-minute timeout + `return_exceptions=True` for full isolation.

**Q2: How does AI mode ensure privacy?**
> `LOCAL` mode executes all inference on the local CPU; data never leaves the host machine. `API` mode sends code snippets to third-party servers -- the UI provides explicit disclosure.

**Q3: Does the local model require a GPU?**
> No. llama-cpp-python supports CPU-only inference. Qwen2-0.5B inference latency is approximately 0.5--1.5 seconds with ~400MB memory footprint.

**Q4: Is configuration persisted?**
> Yes. Cloud server address, API key, and local model path configured via CLI or Web GUI are automatically saved to `.ai_settings.json` and take effect on subsequent launches.

**Q5: Why was the static blind injection threshold deprecated?**
> Static thresholds (sim >= 0.92) produce false positives on pages with minimal content and false negatives on pages with dynamic content. The adaptive relative delta model only requires TRUE to be more similar to baseline than FALSE, offering superior adaptability.

**Q6: How does parallelization avoid overwhelming the target?**
> Each plugin uses `asyncio.Semaphore` to control concurrency (SQLi:5 / XSS:4 / BOLA:8). WAF mode automatically adds randomized delay.

---

## License

MIT License -- For authorized security assessments only.

---

## Documentation

- [Usage Guide (Chinese)](./edu_CN.md) -- WebUI + CLI tutorial
- [User Guide (English)](./edu_EN.md) -- WebUI + CLI usage guide

---

<p align="center">
  <b>OpenScanner v1.5.0</b> -- DAST x SAST x IAST x Mutation x AI Reasoning x Compliance<br/>
  Built with asyncio + mutation intelligence + hybrid AI reasoning + compliance reporting
</p>
