import sqlite3
import threading
import time


class DatabaseManager:
    def __init__(self, db_path="dns_engine.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._initialize_schema()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _initialize_schema(self):
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS resolvers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL DEFAULT 53,
                    protocol TEXT NOT NULL DEFAULT 'UDP',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at REAL NOT NULL,
                    UNIQUE(ip, port, protocol)
                );

                CREATE TABLE IF NOT EXISTS benchmarks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    resolver_id INTEGER NOT NULL,
                    latency_ms REAL NOT NULL,
                    success INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    FOREIGN KEY (resolver_id) REFERENCES resolvers(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_benchmarks_res_time
                ON benchmarks(resolver_id, timestamp DESC);

                CREATE TABLE IF NOT EXISTS metrics (
                    resolver_id INTEGER PRIMARY KEY,
                    avg_latency REAL NOT NULL DEFAULT 0.0,
                    success_rate REAL NOT NULL DEFAULT 1.0,
                    timeout_count INTEGER NOT NULL DEFAULT 0,
                    jitter REAL NOT NULL DEFAULT 0.0,
                    p95 REAL NOT NULL DEFAULT 0.0,
                    score REAL NOT NULL DEFAULT 0.0,
                    role TEXT NOT NULL DEFAULT 'CANDIDATE',
                    updated_at REAL NOT NULL,
                    FOREIGN KEY (resolver_id) REFERENCES resolvers(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )

    # --- Resolvers CRUD ---
    def add_resolver(self, name, provider, ip, port=53, protocol="UDP", is_active=True):
        now = time.time()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO resolvers (name, provider, ip, port, protocol, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip, port, protocol) DO UPDATE SET
                    name = excluded.name,
                    provider = excluded.provider,
                    is_active = excluded.is_active
                """,
                (name, provider, ip, int(port), protocol.upper(), int(bool(is_active)), now),
            )
            row = conn.execute(
                "SELECT id FROM resolvers WHERE ip = ? AND port = ? AND protocol = ?",
                (ip, int(port), protocol.upper()),
            ).fetchone()
            return row["id"]

    def get_resolvers(self, active_only=True):
        query = "SELECT * FROM resolvers"
        if active_only:
            query += " WHERE is_active = 1"
        query += " ORDER BY id ASC"
        with self._lock, self._connect() as conn:
            return [dict(r) for r in conn.execute(query).fetchall()]

    def set_resolver_active(self, resolver_id, is_active):
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE resolvers SET is_active = ? WHERE id = ?",
                (int(bool(is_active)), resolver_id),
            )

    # --- Benchmarks ---
    def insert_benchmark(self, resolver_id, latency_ms, success, source="PASSIVE"):
        now = time.time()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO benchmarks (resolver_id, latency_ms, success, source, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                (resolver_id, float(latency_ms), int(bool(success)), source.upper(), now),
            )

    def get_recent_benchmarks(self, resolver_id, limit=30):
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT latency_ms, success, source, timestamp
                FROM benchmarks
                WHERE resolver_id = ?
                ORDER BY timestamp DESC, id DESC
                LIMIT ?
                """,
                (resolver_id, int(limit)),
            ).fetchall()
            return [dict(r) for r in rows]

    def prune_old_benchmarks(self, keep_per_resolver=200):
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                DELETE FROM benchmarks
                WHERE id NOT IN (
                    SELECT id FROM (
                        SELECT id, ROW_NUMBER() OVER (
                            PARTITION BY resolver_id ORDER BY timestamp DESC, id DESC
                        ) AS rn
                        FROM benchmarks
                    ) WHERE rn <= ?
                )
                """,
                (int(keep_per_resolver),),
            )

    # --- Metrics & Roles ---
    def upsert_metrics(self, resolver_id, avg_latency, success_rate, timeout_count, jitter, p95, score, role="CANDIDATE"):
        now = time.time()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO metrics (
                    resolver_id, avg_latency, success_rate, timeout_count, jitter, p95, score, role, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(resolver_id) DO UPDATE SET
                    avg_latency = excluded.avg_latency,
                    success_rate = excluded.success_rate,
                    timeout_count = excluded.timeout_count,
                    jitter = excluded.jitter,
                    p95 = excluded.p95,
                    score = excluded.score,
                    role = excluded.role,
                    updated_at = excluded.updated_at
                """,
                (
                    resolver_id,
                    float(avg_latency),
                    float(success_rate),
                    int(timeout_count),
                    float(jitter),
                    float(p95),
                    float(score),
                    role.upper(),
                    now,
                ),
            )

    def get_all_metrics(self):
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT r.id, r.name, r.provider, r.ip, r.port, r.protocol, r.is_active,
                       m.avg_latency, m.success_rate, m.timeout_count, m.jitter, m.p95, m.score, m.role, m.updated_at
                FROM resolvers r
                LEFT JOIN metrics m ON r.id = m.resolver_id
                WHERE r.is_active = 1
                ORDER BY COALESCE(m.score, 0.0) DESC, r.id ASC
                """
            ).fetchall()
            return [dict(r) for r in rows]

    # --- Settings ---
    def get_setting(self, key, default=None):
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
            return row["value"] if row else default

    def set_setting(self, key, value):
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, str(value)),
            )