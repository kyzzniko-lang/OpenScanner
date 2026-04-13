"""Quick validation script"""
import sys
sys.path.insert(0, ".")

# Test 1: Mutator
from utils.mutator import AdaptiveMutator, MutationStrategy
m = AdaptiveMutator()
v = m.mutate("' OR 1=1--")
print(f"[OK] Mutator: {len(v)} variants generated")

# Test 2: URL Clustering
from core.spider import SpiderEngine, LogicalSiteMap, EndpointCluster
c = SpiderEngine.cluster_urls([
    "http://test.com/user/1",
    "http://test.com/user/2",
    "http://test.com/user/3",
    "http://test.com/api/order/100",
    "http://test.com/api/order/200",
])
print(f"[OK] Clustering: {len(c)} clusters")
for cluster in c:
    print(f"     Template: {cluster.template} ({len(cluster.urls)} URLs)")

# Test 3: Browser Engine (import only)
from core.browser import BrowserEngine, VisualEvidence
print("[OK] BrowserEngine imported")

# Test 4: BOLA/IDOR plugin (import only)
from plugins.pocs.bola_idor import BolaIdorPlugin, EndpointAnalyzer
ids = EndpointAnalyzer.find_path_ids("http://api.test.com/user/123/orders")
print(f"[OK] BOLA plugin: found {len(ids)} path IDs in test URL")

# Test 5: WAF Heatmap (import only)
from plugins.info.waf_check import WafCheckPlugin, WafHeatmap
print("[OK] WAF Heatmap imported")

# Test 6: Engine (import only)
from core.engine import ScanEngine
print("[OK] ScanEngine imported with all new modules")

print("\n=== ALL VALIDATIONS PASSED ===")
