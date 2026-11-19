import os
import socket
import struct
import threading
import time


def build_dns_query(domain="cloudflare.com"):
    """Build a minimal standard RFC 1035 DNS A-record query packet."""
    tx_id = os.urandom(2)
    flags = b"\x01\x00"  # Standard query, recursion desired
    counts = struct.pack("!HHHH", 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(part)]) + part.encode("ascii")
        for part in domain.strip(".").split(".")
        if part
    ) + b"\x00"
    qtype_qclass = struct.pack("!HH", 1, 1)  # Type A (1), Class IN (1)
    return tx_id + flags + counts + qname + qtype_qclass


def probe_udp_resolver(ip, port=53, timeout_sec=2.0, probe_domain="cloudflare.com"):
    """Send a real UDP DNS probe and return (latency_ms, success)."""
    packet = build_dns_query(probe_domain)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_sec)
    t0 = time.perf_counter()
    try:
        sock.sendto(packet, (ip, int(port)))
        data, _ = sock.recvfrom(512)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        if len(data) >= 12 and (data[2] & 0x80):
            return round(elapsed_ms, 2), True
        return round(elapsed_ms, 2), False
    except (socket.timeout, OSError):
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return round(elapsed_ms, 2), False
    finally:
        sock.close()


class HealthMonitor:
    def __init__(
        self,
        db,
        registry,
        benchmark_engine,
        selector,
        probe_interval_sec=60.0,
        probe_timeout_sec=2.0,
        probe_domain="cloudflare.com",
        stale_threshold_sec=45.0,
    ):
        self.db = db
        self.registry = registry
        self.benchmark = benchmark_engine
        self.selector = selector
        self.probe_interval_sec = float(probe_interval_sec)
        self.probe_timeout_sec = float(probe_timeout_sec)
        self.probe_domain = probe_domain
        self.stale_threshold_sec = float(stale_threshold_sec)

        self._stop_event = threading.Event()
        self._thread = None
        self._cycle_count = 0

    def record_passive(self, resolver_id, latency_ms, success):
        """Record real user traffic result and refresh selection immediately."""
        self.benchmark.record_sample(
            resolver_id=resolver_id,
            latency_ms=latency_ms,
            success=success,
            source="PASSIVE",
        )
        return self.selector.refresh()

    def probe_all_now(self, force=True):
        """Actively probe active resolvers (or only stale ones if force=False)."""
        now = time.time()
        resolvers = self.registry.list_active(protocol="UDP")
        for res in resolvers:
            if not force:
                recent = self.db.get_recent_benchmarks(res["id"], limit=1)
                if recent and (now - recent[0]["timestamp"]) < self.stale_threshold_sec:
                    continue
            latency_ms, success = probe_udp_resolver(
                ip=res["ip"],
                port=res["port"],
                timeout_sec=self.probe_timeout_sec,
                probe_domain=self.probe_domain,
            )
            self.benchmark.record_sample(
                resolver_id=res["id"],
                latency_ms=latency_ms,
                success=success,
                source="ACTIVE",
            )

        self._cycle_count += 1
        if self._cycle_count % 20 == 0:
            self.db.prune_old_benchmarks(keep_per_resolver=200)

        return self.selector.refresh()

    def start_background(self):
        """Start daemon thread for periodic active health checks."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, name="DNSHealthMonitor", daemon=True)
        self._thread.start()

    def stop_background(self):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _run_loop(self):
        while not self._stop_event.is_set():
            try:
                self.probe_all_now(force=False)
            except Exception:
                pass
            self._stop_event.wait(self.probe_interval_sec)