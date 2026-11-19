import threading
import time


class AdaptiveSelector:
    def __init__(
        self,
        db,
        ranking_engine,
        hysteresis_margin=10.0,
        cooldown_sec=30.0,
        fail_threshold=3,
        min_success_rate=0.50,
    ):
        self.db = db
        self.ranking = ranking_engine
        self.hysteresis_margin = float(hysteresis_margin)
        self.cooldown_sec = float(cooldown_sec)
        self.fail_threshold = int(fail_threshold)
        self.min_success_rate = float(min_success_rate)

        self._lock = threading.Lock()
        self._primary_id = None
        self._backup_id = None
        self._last_switch_time = 0.0
        self._last_switch_reason = "INIT"

    def _is_unhealthy(self, item):
        return (
            item["timeout_count"] >= self.fail_threshold
            or item["success_rate"] < self.min_success_rate
        )

    def refresh(self):
        """Re-evaluate scores and update Primary / Backup roles safely."""
        with self._lock:
            current_roles = {}
            if self._primary_id is not None:
                current_roles[self._primary_id] = "PRIMARY"
            if self._backup_id is not None:
                current_roles[self._backup_id] = "BACKUP"

            ranked = self.ranking.evaluate_all(current_roles=current_roles)
            if not ranked:
                self._primary_id = None
                self._backup_id = None
                return []

            by_id = {item["id"]: item for item in ranked}
            now = time.time()

            # Case 1: Initial assignment or previous primary removed
            if self._primary_id not in by_id:
                self._primary_id = ranked[0]["id"]
                self._last_switch_time = now
                self._last_switch_reason = "INITIAL_ASSIGNMENT"
            else:
                current_primary = by_id[self._primary_id]
                best_candidate = ranked[0]

                # Case 2: Immediate Failover if current primary is unhealthy
                if self._is_unhealthy(current_primary):
                    healthy_candidates = [r for r in ranked if not self._is_unhealthy(r)]
                    new_primary = healthy_candidates[0] if healthy_candidates else best_candidate
                    if new_primary["id"] != self._primary_id:
                        self._primary_id = new_primary["id"]
                        self._last_switch_time = now
                        self._last_switch_reason = "FAILOVER_UNHEALTHY"

                # Case 3: Hysteresis + Cooldown upgrade
                elif best_candidate["id"] != self._primary_id:
                    score_diff = best_candidate["score"] - current_primary["score"]
                    cooldown_passed = (now - self._last_switch_time) >= self.cooldown_sec
                    if score_diff >= self.hysteresis_margin and cooldown_passed:
                        self._primary_id = best_candidate["id"]
                        self._last_switch_time = now
                        self._last_switch_reason = f"HYSTERESIS_UPGRADE (+{score_diff:.1f})"

            # Assign best remaining resolver as Backup
            backups = [r for r in ranked if r["id"] != self._primary_id]
            self._backup_id = backups[0]["id"] if backups else None

            # Persist updated roles into metrics table
            for item in ranked:
                if item["id"] == self._primary_id:
                    role = "PRIMARY"
                elif item["id"] == self._backup_id:
                    role = "BACKUP"
                else:
                    role = "CANDIDATE"
                item["role"] = role
                self.db.upsert_metrics(
                    resolver_id=item["id"],
                    avg_latency=item["avg_latency"],
                    success_rate=item["success_rate"],
                    timeout_count=item["timeout_count"],
                    jitter=item["jitter"],
                    p95=item["p95"],
                    score=item["score"],
                    role=role,
                )

            return ranked

    def get_primary_and_backup(self):
        """Return (primary_resolver_dict, backup_resolver_dict)."""
        with self._lock:
            if self._primary_id is not None:
                active = {r["id"]: r for r in self.db.get_resolvers(active_only=True)}
                primary = active.get(self._primary_id)
                backup = active.get(self._backup_id) if self._backup_id else None
                if primary:
                    return primary, backup

        ranked = self.refresh()
        if not ranked:
            return None, None
        primary = next((r for r in ranked if r["role"] == "PRIMARY"), ranked[0])
        backup = next((r for r in ranked if r["role"] == "BACKUP"), None)
        return primary, backup

    def get_status(self):
        with self._lock:
            return {
                "primary_id": self._primary_id,
                "backup_id": self._backup_id,
                "last_switch_reason": self._last_switch_reason,
                "last_switch_time": self._last_switch_time,
            }