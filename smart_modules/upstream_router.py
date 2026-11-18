import json
import random
import time
import urllib.request


class UpstreamRouter:
    def __init__(self, upstream_pool):
        self.upstream_pool = upstream_pool
        # Initial baseline latency (ms) for all servers
        self.latencies = {srv: 100.0 for srv in upstream_pool}

    def query_doh(self, domain, timeout=3):
        """Send encrypted DNS-over-HTTPS (DoH) query via Cloudflare JSON API."""
        url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=A"
        req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                status = data.get("Status", 2)
                if status == 3:  # NXDOMAIN
                    return "NOT_FOUND", "-", "-"
                if status != 0:  # Upstream DNS error
                    return "SERVER_ERROR", "-", "-"

                for ans in data.get("Answer", []):
                    if ans.get("type") == 1:  # Type A (IPv4) record
                        return "OK", ans.get("data", "-"), int(ans.get("TTL", 60))
                return "NOT_FOUND", "-", "-"
        except Exception:
            return "SERVER_ERROR", "-", "-"

    def query_smart_pool(self, domain, query_fn, port, timeout):
        """Route query to lowest-latency server with automatic failover."""
        ordered_servers = sorted(self.upstream_pool, key=lambda s: self.latencies.get(s, 999.0))

        # 10% exploration chance to probe other servers and discover faster routes
        if len(ordered_servers) > 1 and random.random() < 0.10:
            probe_idx = random.randint(1, len(ordered_servers) - 1)
            ordered_servers[0], ordered_servers[probe_idx] = ordered_servers[probe_idx], ordered_servers[0]

        for srv in ordered_servers:
            t0 = time.perf_counter()
            status, ip, ttl = query_fn(domain, srv, port, timeout)
            rtt_ms = (time.perf_counter() - t0) * 1000.0

            if status in ("OK", "NOT_FOUND"):
                # Update latency using Exponential Weighted Moving Average (EWMA)
                self.latencies[srv] = 0.7 * self.latencies.get(srv, rtt_ms) + 0.3 * rtt_ms
                return status, ip, ttl

            # Penalize failed/timed-out server
            self.latencies[srv] = 9999.0

        return "SERVER_ERROR", "-", "-"