import math


class BenchmarkEngine:
    def __init__(self, db, window_size=30, default_latency_ms=100.0):
        self.db = db
        self.window_size = int(window_size)
        self.default_latency_ms = float(default_latency_ms)

    def record_sample(self, resolver_id, latency_ms, success, source="PASSIVE"):
        """Store a single probe/query result in the benchmarks table."""
        self.db.insert_benchmark(
            resolver_id=resolver_id,
            latency_ms=latency_ms,
            success=success,
            source=source,
        )

    def compute_stats(self, resolver_id):
        """Calculate latency, success_rate, consecutive timeouts, jitter, and P95."""
        samples = self.db.get_recent_benchmarks(resolver_id, limit=self.window_size)

        if not samples:
            return {
                "resolver_id": resolver_id,
                "sample_count": 0,
                "avg_latency": self.default_latency_ms,
                "success_rate": 1.0,
                "timeout_count": 0,
                "jitter": 0.0,
                "p95": self.default_latency_ms,
            }

        total = len(samples)
        successful_latencies = [s["latency_ms"] for s in samples if s["success"] == 1]
        success_rate = len(successful_latencies) / total

        # Count consecutive failures starting from the most recent sample
        consecutive_timeouts = 0
        for s in samples:
            if s["success"] == 0:
                consecutive_timeouts += 1
            else:
                break

        if not successful_latencies:
            # All samples in the window failed
            max_penalty = max((s["latency_ms"] for s in samples), default=2000.0)
            return {
                "resolver_id": resolver_id,
                "sample_count": total,
                "avg_latency": max_penalty,
                "success_rate": 0.0,
                "timeout_count": consecutive_timeouts,
                "jitter": 0.0,
                "p95": max_penalty,
            }

        avg_latency = sum(successful_latencies) / len(successful_latencies)
        jitter = self._std_dev(successful_latencies, avg_latency)
        p95 = self._percentile(successful_latencies, 95)

        return {
            "resolver_id": resolver_id,
            "sample_count": total,
            "avg_latency": round(avg_latency, 2),
            "success_rate": round(success_rate, 4),
            "timeout_count": consecutive_timeouts,
            "jitter": round(jitter, 2),
            "p95": round(p95, 2),
        }

    @staticmethod
    def _std_dev(values, mean):
        if len(values) < 2:
            return 0.0
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return math.sqrt(variance)

    @staticmethod
    def _percentile(values, percent):
        sorted_vals = sorted(values)
        n = len(sorted_vals)
        if n == 1:
            return sorted_vals[0]
        rank = (percent / 100.0) * (n - 1)
        low = int(math.floor(rank))
        high = int(math.ceil(rank))
        if low == high:
            return sorted_vals[low]
        weight = rank - low
        return sorted_vals[low] * (1.0 - weight) + sorted_vals[high] * weight