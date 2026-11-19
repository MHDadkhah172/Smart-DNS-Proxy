import gc
import os
import random
import statistics
import sys
import threading
import time
from collections import OrderedDict

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(ROOT_DIR, "src")
for p in (ROOT_DIR, SRC_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from dns_engine.benchmark import BenchmarkEngine
from dns_engine.database import DatabaseManager
from dns_engine.monitor import HealthMonitor
from dns_engine.ranking import RankingEngine
from dns_engine.registry import ResolverRegistry
from dns_engine.selector import AdaptiveSelector
from src.config import load_config
from src.dns_proxy import is_domain_matched, query_real_dns, query_text_upstream
from src.domain_loader import is_valid_domain, load_domain_list, normalize_domain

USER_PROFILES = [
    ("User_01_Dev", ["github.com", "stackoverflow.com", "python.org", "pypi.org", "docs.python.org"]),
    ("User_02_Gamer", ["steampowered.com", "discord.com", "twitch.tv", "epicgames.com", "riotgames.com"]),
    ("User_03_Social", ["instagram.com", "telegram.org", "x.com", "reddit.com", "linkedin.com"]),
    ("User_04_Stream", ["youtube.com", "googlevideo.com", "netflix.com", "spotify.com", "soundcloud.com"]),
    ("User_05_AdHeavy", ["google.com", "doubleclick.net", "googlesyndication.com", "ads.yahoo.com", "adservice.google.com"]),
    ("User_06_Research", ["wikipedia.org", "arxiv.org", "scholar.google.com", "ieee.org", "nature.com"]),
    ("User_07_Shopper", ["amazon.com", "ebay.com", "digikala.com", "aliexpress.com", "paypal.com"]),
    ("User_08_CloudOps", ["aws.amazon.com", "cloudflare.com", "docker.com", "kubernetes.io", "digitalocean.com"]),
    ("User_09_News", ["bbc.com", "cnn.com", "reuters.com", "theguardian.com", "nytimes.com"]),
    ("User_10_Mixed", ["google.com", "github.com", "youtube.com", "doubleclick.net", "wikipedia.org"]),
]


class StandaloneSmartRouter:
    """Connects directly to existing dns_engine modules without external wrapper files."""

    def __init__(self, pool_ips, db_path):
        self.db = DatabaseManager(db_path=db_path)
        self.registry = ResolverRegistry(self.db)
        self.registry.seed_defaults(custom_ips=pool_ips)

        existing_ips = {r["ip"]: r for r in self.registry.list_all()}
        for idx, ip in enumerate(pool_ips, 1):
            if ip not in existing_ips:
                self.registry.register(f"Pool DNS #{idx}", "Configured", ip, 53, "UDP", is_active=True)
            elif not existing_ips[ip]["is_active"]:
                self.registry.enable(existing_ips[ip]["id"])

        self.benchmark = BenchmarkEngine(self.db, window_size=30)
        self.ranking = RankingEngine(self.db, self.benchmark)
        self.selector = AdaptiveSelector(self.db, self.ranking)
        self.monitor = HealthMonitor(
            db=self.db,
            registry=self.registry,
            benchmark_engine=self.benchmark,
            selector=self.selector,
            probe_interval_sec=60.0,
        )

    def start(self):
        self.monitor.probe_all_now(force=True)
        self.monitor.start_background()

    def stop(self):
        self.monitor.stop_background()

    def query_smart_pool(self, domain, query_fn, port, timeout_sec):
        primary, backup = self.selector.get_primary_and_backup()
        candidates = [c for c in (primary, backup) if c is not None]
        if not candidates:
            return "SERVER_ERROR", "-", "-"

        for resolver in candidates:
            target_port = resolver["port"] if resolver.get("port") else port
            t0 = time.perf_counter()
            status, ip, ttl = query_fn(domain, resolver["ip"], target_port, timeout_sec)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0

            is_success = status in ("OK", "NOT_FOUND")
            self.monitor.record_passive(resolver["id"], elapsed_ms, is_success)

            if is_success:
                return status, ip, ttl

        return "SERVER_ERROR", "-", "-"

    def print_dashboard(self):
        status = self.selector.get_status()
        rows = self.db.get_all_metrics()
        print(f"Selector State -> Last Switch Reason: {status['last_switch_reason']}")
        print(
            f"{'ROLE':<10} | {'NAME':<18} | {'IP':<15} | {'AVG(ms)':<8} | "
            f"{'P95(ms)':<8} | {'JITTER':<7} | {'SUCC%':<6} | {'SCORE':<6}"
        )
        print("-" * 92)
        for r in rows:
            avg_lat = f"{r['avg_latency']:.1f}" if r["avg_latency"] is not None else "-"
            p95_val = f"{r['p95']:.1f}" if r["p95"] is not None else "-"
            jit_val = f"{r['jitter']:.1f}" if r["jitter"] is not None else "-"
            succ_val = f"{r['success_rate'] * 100:.0f}%" if r["success_rate"] is not None else "-"
            score_val = f"{r['score']:.2f}" if r["score"] is not None else "-"
            role_val = r["role"] or "CANDIDATE"
            print(
                f"{role_val:<10} | {r['name']:<18} | {r['ip']:<15} | {avg_lat:<8} | "
                f"{p95_val:<8} | {jit_val:<7} | {succ_val:<6} | {score_val:<6}"
            )


def cleanup_db_files(db_path):
    for suffix in ("", "-wal", "-shm"):
        target = db_path + suffix
        if os.path.exists(target):
            try:
                os.remove(target)
            except OSError:
                pass


def resolve_concurrent(raw_domain, cfg, ad_domains, sanction_domains, cache, stats, router, query_fn, lock):
    if not is_valid_domain(raw_domain):
        with lock:
            stats["Total"] += 1
            stats["ERRORS"] += 1
        return "NONE", "INVALID_INPUT"

    domain = normalize_domain(raw_domain)

    with lock:
        stats["Total"] += 1

        if is_domain_matched(domain, ad_domains):
            stats["AD_BLOCK"] += 1
            return "AD_BLOCK", "OK"

        if is_domain_matched(domain, sanction_domains):
            stats["SANCTION"] += 1
            return "SANCTION", "OK"

        now = time.time()
        if cfg["cache_enabled"] and domain in cache:
            cached_ip, expire_time = cache[domain]
            if int(expire_time - now) >= 1:
                stats["CACHE"] += 1
                return "CACHE", "OK"
            del cache[domain]

    status, ip, ttl = router.query_smart_pool(
        domain, query_fn, cfg["upstream_port"], cfg["upstream_timeout_sec"]
    )

    with lock:
        if status == "OK":
            stats["UPSTREAM"] += 1
            if cfg["cache_enabled"] and isinstance(ttl, int) and ttl > 0:
                max_cap = cfg["cache_max_entries"]
                if max_cap is not None and domain not in cache and len(cache) >= max_cap:
                    cache.popitem(last=False)
                cache[domain] = (ip, time.time() + ttl)
            return "UPSTREAM", "OK"

        if status == "NOT_FOUND":
            stats["UPSTREAM"] += 1
            return "UPSTREAM", "NOT_FOUND"

        stats["ERRORS"] += 1
        return "UPSTREAM", "SERVER_ERROR"


def run_simulation(requests_per_user=25):
    random.seed(42)

    cfg = load_config("config.txt")
    ad_domains = load_domain_list(cfg["ad_list_file"])
    sanction_domains = load_domain_list(cfg["sanction_list_file"])
    ad_domains.update({"doubleclick.net", "googlesyndication.com", "ads.yahoo.com", "adservice.google.com"})

    query_fn = query_real_dns if cfg["real_dns_enabled"] else query_text_upstream
    pool = [s.strip() for s in cfg.get("upstream_pool", cfg["upstream_ip"]).split(",") if s.strip()]

    sim_db = os.path.join(ROOT_DIR, "sim_engine.db")
    cleanup_db_files(sim_db)

    router = StandaloneSmartRouter(pool_ips=pool, db_path=sim_db)
    print("Initializing & probing resolvers via dns_engine...")
    router.start()

    cache = OrderedDict()
    stats = {"Total": 0, "AD_BLOCK": 0, "SANCTION": 0, "CACHE": 0, "UPSTREAM": 0, "ERRORS": 0}
    lock = threading.Lock()
    latencies_by_source = {"AD_BLOCK": [], "SANCTION": [], "CACHE": [], "UPSTREAM": []}

    user_queries = {}
    for uid, doms in USER_PROFILES:
        q_list = []
        for _ in range(requests_per_user):
            if random.random() < 0.8:
                q_list.append(random.choice(doms))
            else:
                q_list.append(random.choice(["google.com", "github.com", "doubleclick.net", "youtube.com", "cloudflare.com"]))
        user_queries[uid] = q_list

    def simulate_single_user(queries):
        for domain in queries:
            t0 = time.perf_counter()
            source, _ = resolve_concurrent(
                domain, cfg, ad_domains, sanction_domains, cache, stats, router, query_fn, lock
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            with lock:
                if source in latencies_by_source:
                    latencies_by_source[source].append(elapsed_ms)
            time.sleep(0.02)

    print(f"\n[SIMULATION: dns_engine] Running {len(USER_PROFILES)} users x {requests_per_user} requests...\n")
    sim_start = time.perf_counter()

    threads = [threading.Thread(target=simulate_single_user, args=(user_queries[uid],)) for uid, _ in USER_PROFILES]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    total_time_sec = time.perf_counter() - sim_start
    router.stop()

    print("=" * 78)
    print("           SIMULATION REPORT: SMART DNS ENGINE (dns_engine)")
    print("=" * 78)
    print(f"Total Execution Time : {total_time_sec:.2f} sec | Throughput: {stats['Total'] / total_time_sec:.1f} req/sec")
    print(f"Total Queries        : {stats['Total']}")
    print(f"  - Upstream Queries : {stats['UPSTREAM']} ({stats['UPSTREAM'] / stats['Total'] * 100:.1f}%)")
    print(f"  - Cache Hits       : {stats['CACHE']} ({stats['CACHE'] / stats['Total'] * 100:.1f}%)")
    print(f"  - Ads Blocked      : {stats['AD_BLOCK']} ({stats['AD_BLOCK'] / stats['Total'] * 100:.1f}%)")
    print(f"  - Errors           : {stats['ERRORS']}")

    print("\n--- LATENCY BREAKDOWN BY SOURCE (ms) ---")
    for src, vals in latencies_by_source.items():
        if vals:
            sorted_v = sorted(vals)
            p95 = sorted_v[int(0.95 * (len(sorted_v) - 1))]
            print(f"  {src:<10} | Count: {len(vals):<4} | Avg: {statistics.mean(vals):>7.3f} ms | P95: {p95:>7.3f} ms")

    print("\n--- LIVE ENGINE SCORING & TELEMETRY ---")
    router.print_dashboard()
    print("=" * 78)

    del router
    gc.collect()
    cleanup_db_files(sim_db)


if __name__ == "__main__":
    run_simulation(requests_per_user=25)