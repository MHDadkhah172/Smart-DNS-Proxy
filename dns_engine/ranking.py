class RankingEngine:
    def __init__(
        self,
        db,
        benchmark_engine,
        weights=None,
        max_latency_ms=500.0,
        max_p95_ms=800.0,
        max_jitter_ms=150.0,
        timeout_penalty=15.0,
    ):
        self.db = db
        self.benchmark = benchmark_engine
        self.weights = weights or {
            "success_rate": 0.40,
            "avg_latency": 0.25,
            "p95": 0.20,
            "jitter": 0.15,
        }
        self.max_latency_ms = float(max_latency_ms)
        self.max_p95_ms = float(max_p95_ms)
        self.max_jitter_ms = float(max_jitter_ms)
        self.timeout_penalty = float(timeout_penalty)

    @staticmethod
    def _normalize_inverse(value, best, worst):
        if value <= best:
            return 1.0
        if value >= worst:
            return 0.0
        return (worst - value) / (worst - best)

    def calculate_score(self, stats):
        norm_success = max(0.0, min(1.0, stats["success_rate"]))
        norm_latency = self._normalize_inverse(stats["avg_latency"], best=10.0, worst=self.max_latency_ms)
        norm_p95 = self._normalize_inverse(stats["p95"], best=15.0, worst=self.max_p95_ms)
        norm_jitter = self._normalize_inverse(stats["jitter"], best=0.0, worst=self.max_jitter_ms)

        raw_score = (
            self.weights["success_rate"] * norm_success
            + self.weights["avg_latency"] * norm_latency
            + self.weights["p95"] * norm_p95
            + self.weights["jitter"] * norm_jitter
        ) * 100.0

        penalty = stats["timeout_count"] * self.timeout_penalty
        final_score = max(0.0, min(100.0, raw_score - penalty))
        return round(final_score, 2)

    def evaluate_all(self, current_roles=None):
        current_roles = current_roles or {}
        resolvers = self.db.get_resolvers(active_only=True)
        ranked = []

        for res in resolvers:
            rid = res["id"]
            stats = self.benchmark.compute_stats(rid)
            score = self.calculate_score(stats)
            role = current_roles.get(rid, "CANDIDATE")

            self.db.upsert_metrics(
                resolver_id=rid,
                avg_latency=stats["avg_latency"],
                success_rate=stats["success_rate"],
                timeout_count=stats["timeout_count"],
                jitter=stats["jitter"],
                p95=stats["p95"],
                score=score,
                role=role,
            )

            ranked.append(
                {
                    **res,
                    **stats,
                    "score": score,
                    "role": role,
                }
            )

        ranked.sort(key=lambda item: (-item["score"], item["avg_latency"], item["id"]))
        return ranked