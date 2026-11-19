import time
from dns_engine.benchmark import BenchmarkEngine
from dns_engine.database import DatabaseManager
from dns_engine.monitor import HealthMonitor
from dns_engine.ranking import RankingEngine
from dns_engine.registry import ResolverRegistry
from dns_engine.selector import AdaptiveSelector


class SmartEngineRouter:
    """Drop-in replacement for UpstreamRouter powered by dns_engine."""

    def __init__(self, pool_ips, db_path="dns_engine.db", probe_interval_sec=60.0):
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
            probe_interval_sec=probe_interval_sec,
        )

    def start(self):
        self.monitor.probe_all_now(force=True)
        self.monitor.start_background()

    def stop(self):
        self.monitor.stop_background()

    def query_smart_pool(self, domain, query_fn, port, timeout_sec):
        """Query PRIMARY resolver; if it fails, immediately failover to BACKUP."""
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

    def get_dashboard_rows(self):
        return self.db.get_all_metrics()

    def get_selector_status(self):
        return self.selector.get_status()