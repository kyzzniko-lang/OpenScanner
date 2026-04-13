"""
tests/test_plugin_system.py — 插件系统集成验证

验证内容：
  1. BasePlugin 子类化和元信息声明
  2. PluginRegistry 自动发现机制
  3. WafCheckPlugin 可以被正确加载
  4. ScanEngine 端到端调度
"""

import asyncio
import sys
from pathlib import Path

# 确保项目根目录在 sys.path 中
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.request import AsyncRequester, RequestConfig
from core.engine import PluginRegistry, ScanEngine
from plugins.base import BasePlugin, PluginMeta, ScanResult, Severity


# ─────────────────────────────────────────────
# Test 1: BasePlugin 子类化
# ─────────────────────────────────────────────
def test_base_plugin_subclass():
    """验证通过继承 BasePlugin 定义插件"""

    class DemoPlugin(BasePlugin):
        meta = PluginMeta(
            name="demo_test",
            display_name="Demo Test Plugin",
            description="仅用于测试的示例插件",
            severity=Severity.LOW,
            tags=["test"],
        )

        async def check(self, url, requester):
            return self.result(url, False, detail="测试通过")

    plugin = DemoPlugin()
    assert plugin.meta.name == "demo_test"
    assert plugin.meta.severity == Severity.LOW
    assert plugin.meta.enabled is True

    print("✅ Test 1 PASSED: BasePlugin 子类化正常")


# ─────────────────────────────────────────────
# Test 2: 缺少 meta 的子类应该报错
# ─────────────────────────────────────────────
def test_missing_meta_raises():
    """验证缺少 meta 的子类会抛出 TypeError"""
    try:

        class BadPlugin(BasePlugin):
            async def check(self, url, requester):
                pass

        print("❌ Test 2 FAILED: 缺少 meta 的子类未报错")
    except TypeError as e:
        print(f"✅ Test 2 PASSED: 缺少 meta 正确抛出 TypeError → {e}")


# ─────────────────────────────────────────────
# Test 3: PluginRegistry 自动发现
# ─────────────────────────────────────────────
def test_plugin_registry():
    """验证自动发现机制"""
    registry = PluginRegistry()
    count = registry.discover()

    print(f"  📦 发现 {count} 个插件:")
    for info in registry.list_plugins():
        print(f"    → [{info['severity']}] {info['display_name']} v{info['version']} tags={info['tags']}")

    # 至少应发现 waf_check
    assert registry.get("waf_check") is not None, "waf_check 插件未被发现"
    print("✅ Test 3 PASSED: PluginRegistry 自动发现正常")


# ─────────────────────────────────────────────
# Test 4: ScanEngine 端到端
# ─────────────────────────────────────────────
async def test_scan_engine():
    """验证引擎能加载插件并执行扫描"""
    config = RequestConfig(
        max_concurrency=5,
        request_timeout=10.0,
        max_retries=2,
        random_delay_range=(0.0, 0.1),  # 测试时减少延迟
    )

    engine = ScanEngine(config=config)
    loaded = engine.load_plugins()
    print(f"  📦 引擎加载了 {loaded} 个插件")

    targets = ["https://httpbin.org/get"]
    results = await engine.scan(
        targets,
        plugin_names=["waf_check"],
    )

    print(f"  📊 扫描结果: {len(results)} 项")
    for r in results:
        status = "🚨 漏洞" if r.is_vulnerable else "✓ 安全"
        print(f"    → [{r.severity}] {r.plugin_name}: {status} — {r.detail}")

    summary = engine.summary()
    print(f"  📈 摘要: {summary}")

    assert len(results) > 0, "应该至少有一个结果"
    print(f"✅ Test 4 PASSED: ScanEngine 端到端正常 (耗时 {engine.elapsed:.2f}s)")


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def main():
    import logging

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    print("=" * 60)
    print(" OpenScanner 插件系统集成测试")
    print("=" * 60)

    # 同步测试
    test_base_plugin_subclass()
    test_missing_meta_raises()
    test_plugin_registry()

    # 异步测试
    print("\n--- 异步引擎测试 ---")
    asyncio.run(test_scan_engine())

    print("\n" + "=" * 60)
    print(" 🎉 所有测试通过!")
    print("=" * 60)


if __name__ == "__main__":
    main()
