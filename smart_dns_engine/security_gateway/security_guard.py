import queue
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from .ml_detector import AdaptiveAnomalyDetector, shannon_entropy


@dataclass
class ClientState:
    status: str = "NORMAL"          # NORMAL | THROTTLED | QUARANTINED
    strikes: int = 0                # Consecutive anomalous windows
    throttle_until: float = 0.0     # Timestamp when THROTTLED expires
    throttle_tokens: int = 5        # Allowed requests per second while throttled
    last_token_refill: float = field(default_factory=time.time)
    total_requests: int = 0
    last_seen: float = field(default_factory=time.time)


class SecurityGuard:
    """
    Asynchronous security engine for multi-client DNS traffic.
    - Hot Path: O(1) client access checks and non-blocking event enqueueing.
    - Cold Path: Windowed behavioral aggregation, ML evaluation, graduated enforcement, and SQLite logging.
    """

    def __init__(
        self,
        db_path: str = "security.db",
        window_seconds: float = 3.0,
        baseline_window_size: int = 20,
        throttle_duration: float = 15.0,
    ):
        self.db_path = db_path
        self.window_seconds = window_seconds
        self.throttle_duration = throttle_duration

        self.detector = AdaptiveAnomalyDetector(window_size=baseline_window_size)
        self.event_queue: queue.Queue = queue.Queue(maxsize=10000)

        self._lock = threading.Lock()
        self.clients: dict[str, ClientState] = {}
        self._buckets: dict[str, list[dict]] = {}

        self._running = False
        self._worker_thread: threading.Thread | None = None

        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    client_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    anomaly_score REAL NOT NULL,
                    threshold REAL NOT NULL,
                    details TEXT
                )
                """
            )
            conn.commit()

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()

    def stop(self) -> None:
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=2.0)

    # -------------------- HOT PATH --------------------

    def check_access(self, client_id: str) -> tuple[bool, str]:
        """
        Fast O(1) check called before resolving DNS.
        Returns (is_allowed, state_label).
        """
        now = time.time()
        with self._lock:
            state = self.clients.get(client_id)
            if state is None:
                state = ClientState(last_seen=now)
                self.clients[client_id] = state

            state.last_seen = now
            state.total_requests += 1

            if state.status == "QUARANTINED":
                return False, "QUARANTINED"

            if state.status == "THROTTLED":
                if now >= state.throttle_until:
                    state.status = "NORMAL"
                    return True, "NORMAL"

                # Refill 5 tokens every 1 second during throttling
                if now - state.last_token_refill >= 1.0:
                    state.throttle_tokens = 5
                    state.last_token_refill = now

                if state.throttle_tokens > 0:
                    state.throttle_tokens -= 1
                    return True, "THROTTLED"
                return False, "THROTTLED_DROP"

            return True, "NORMAL"

    def record_event(self, client_id: str, domain: str, status: str) -> None:
        """Non-blocking enqueue of a resolved DNS transaction for background analysis."""
        event = {
            "timestamp": time.time(),
            "client_id": client_id,
            "domain": domain,
            "status": status,
        }
        try:
            self.event_queue.put_nowait(event)
        except queue.Full:
            pass  # Never block the Hot Path if queue saturates

    # -------------------- COLD PATH --------------------

    def _worker_loop(self) -> None:
        last_window_eval = time.time()

        while self._running:
            try:
                event = self.event_queue.get(timeout=0.2)
                cid = event["client_id"]
                self._buckets.setdefault(cid, []).append(event)
            except queue.Empty:
                pass

            now = time.time()
            if now - last_window_eval >= self.window_seconds:
                self._evaluate_active_buckets(now - last_window_eval)
                last_window_eval = now

    def _evaluate_active_buckets(self, elapsed: float) -> None:
        if not self._buckets:
            return

        buckets_snapshot = self._buckets
        self._buckets = {}
        duration = max(elapsed, 0.5)

        for client_id, events in buckets_snapshot.items():
            if not events:
                continue

            total = len(events)
            if total < 3:
                continue

            total = len(events)
            domains = [e["domain"] for e in events]
            nx_count = sum(1 for e in events if e["status"] == "NOT_FOUND")

            req_rate = total / duration
            avg_entropy = sum(shannon_entropy(d) for d in domains) / total
            max_len = float(max(len(d) for d in domains))
            nx_ratio = nx_count / total
            unique_ratio = len(set(domains)) / total

            features = [req_rate, avg_entropy, max_len, nx_ratio, unique_ratio]
            result = self.detector.evaluate(client_id, features)

            self._apply_policy(client_id, result, features)

    def _apply_policy(self, client_id: str, result: dict, features: list[float]) -> None:
        now = time.time()
        action_logged = None

        with self._lock:
            state = self.clients.setdefault(client_id, ClientState())

            if state.status == "QUARANTINED":
                return

            if result["is_anomalous"]:
                state.strikes += 1
                if state.strikes == 1:
                    state.status = "THROTTLED"
                    state.throttle_until = now + self.throttle_duration
                    action_logged = "THROTTLED"
                elif state.strikes >= 2:
                    state.status = "QUARANTINED"
                    action_logged = "QUARANTINED"
            else:
                if state.strikes > 0:
                    state.strikes -= 1
                if state.status == "THROTTLED" and now >= state.throttle_until:
                    state.status = "NORMAL"

        if action_logged:
            details = f"rate={features[0]:.1f}/s, entropy={features[1]:.2f}, nx={features[3]:.2f}"
            self._log_alert(client_id, action_logged, result["score"], result["threshold"], details)

    def _log_alert(self, client_id: str, action: str, score: float, threshold: float, details: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO security_alerts (timestamp, client_id, action, anomaly_score, threshold, details)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (time.time(), client_id, action, score, threshold, details),
            )
            conn.commit()

    # -------------------- MANAGEMENT API --------------------

    def get_clients_summary(self) -> list[dict]:
        with self._lock:
            return [
                {
                    "client_id": cid,
                    "status": st.status,
                    "strikes": st.strikes,
                    "total_requests": st.total_requests,
                }
                for cid, st in self.clients.items()
            ]

    def unblock_client(self, client_id: str) -> bool:
        with self._lock:
            state = self.clients.get(client_id)
            if not state:
                return False
            state.status = "NORMAL"
            state.strikes = 0
            state.throttle_until = 0.0
            return True

    def get_recent_alerts(self, limit: int = 10) -> list[tuple]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT timestamp, client_id, action, anomaly_score, threshold, details "
                "FROM security_alerts ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            return cursor.fetchall()