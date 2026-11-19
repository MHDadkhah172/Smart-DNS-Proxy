import os
import sys

# Add 'src' and root directory to path for clean imports
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from domain_loader import is_valid_domain, normalize_domain
from smart_modules.upstream_router import UpstreamRouter
from smart_modules.remote_blocklist import RemoteBlocklistSync
from smart_modules.context_ads import AdaptiveAdCache


def mock_dns_query(domain, server, port, timeout):
    """Simulated upstream DNS query for fast, offline testing of UpstreamRouter."""
    import time
    if server == "1.1.1.1":
        time.sleep(0.01)  # Fast server (~10ms)
        return "OK", "93.184.216.34", 300
    elif server == "8.8.8.8":
        time.sleep(0.05)  # Slower server (~50ms)
        return "OK", "93.184.216.34", 300
    else:
        return "SERVER_ERROR", "-", "-"  # Dead/filtered server


def test_module_1_upstream_router():
    print("--- [1] Testing UpstreamRouter ---")
    servers = ["9.9.9.9", "8.8.8.8", "1.1.1.1"]
    router = UpstreamRouter(servers)

    # 1. Startup benchmark
    router.benchmark_all(query_fn=mock_dns_query, port=53, timeout=1.0)
    print("Latencies after startup benchmark:", {k: round(v, 2) for k, v in router.latencies.items()})
    assert router.latencies["1.1.1.1"] < router.latencies["8.8.8.8"]
    assert router.latencies["9.9.9.9"] == 9999.0

    # 2. Query routing
    status, ip, ttl = router.query_smart_pool("example.com", mock_dns_query, 53, 1.0)
    print(f"Smart query result: status={status}, ip={ip}, ttl={ttl}")
    assert status == "OK" and ip == "93.184.216.34"
    print("PASS: UpstreamRouter works properly.\n")


def test_module_2_remote_blocklist():
    print("--- [2] Testing RemoteBlocklistSync ---")
    # Using lightweight AdAway list for quick test (or fallback to cache if offline)
    test_url = "https://adaway.org/hosts.txt"
    ad_set = set()

    syncer = RemoteBlocklistSync(
        url=test_url,
        validator_fn=is_valid_domain,
        normalizer_fn=normalize_domain,
        cache_file="test_ads_cache.txt"
    )

    # Test line parser directly on multiple formats
    assert syncer._parse_line("0.0.0.0 DoubleClick.NET # comment") == "doubleclick.net"
    assert syncer._parse_line("||ads.example.com^") == "ads.example.com"
    assert syncer._parse_line("! Adblock header") is None

    # Test online download (or disk fallback if offline)
    count = syncer.sync_now(ad_set, timeout=5)
    print(f"Synced {count} domains into ad_set.")
    assert count > 0 and len(ad_set) == count

    # Clean up temporary test cache files
    for suffix in ("", ".meta"):
        tmp_file = os.path.join(ROOT_DIR, "test_ads_cache.txt" + suffix)
        if os.path.exists(tmp_file):
            os.remove(tmp_file)

    print("PASS: RemoteBlocklistSync works properly.\n")
    return ad_set


def test_module_3_context_ads(ad_set):
    print("--- [3] Testing AdaptiveAdCache (Multi-Session LRU) ---")
    cache = AdaptiveAdCache(enabled=True, max_size=3)

    # User 1: gamer_user
    cache.switch_session("gamer_user")
    assert cache.is_hot_ad("ads.twitch.tv") is False  # Cold miss first time
    cache.promote("ads.twitch.tv")
    cache.promote("doubleclick.net")
    assert cache.is_hot_ad("ads.twitch.tv") is True   # L1 Hot hit!
    assert cache.hits["gamer_user"] == 1

    # User 2: dev_user (isolated cache)
    cache.switch_session("dev_user")
    assert cache.is_hot_ad("ads.twitch.tv") is False  # Must NOT leak from gamer_user
    cache.promote("analytics.github.com")
    assert cache.is_hot_ad("analytics.github.com") is True

    # Test LRU Eviction (max_size = 3)
    cache.promote("tracker1.dev")
    cache.promote("tracker2.dev")
    cache.promote("tracker3.dev")  # Evicts 'analytics.github.com'
    assert "analytics.github.com" not in cache.sessions["dev_user"]
    assert len(cache.sessions["dev_user"]) == 3

    print("Session hit stats:", cache.hits)
    print("PASS: AdaptiveAdCache works properly.\n")


if __name__ == "__main__":
    test_module_1_upstream_router()
    synced_ads = test_module_2_remote_blocklist()
    test_module_3_context_ads(synced_ads)
    print("ALL 3 MODULES PASSED SUCCESSFULLY!")