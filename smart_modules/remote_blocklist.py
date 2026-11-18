import os
import threading
import urllib.request


class RemoteBlocklistSync:
    def __init__(self, url, validator_fn, normalizer_fn, cache_file="remote_ads_cache.txt", sync_interval_sec=3600):
        self.url = url
        self.validator_fn = validator_fn
        self.normalizer_fn = normalizer_fn

        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.cache_path = os.path.join(root_dir, cache_file)
        self.sync_interval_sec = sync_interval_sec
        self._stop_event = threading.Event()
        self._thread = None

    def _parse_line(self, raw_line):
        """Extract and normalize valid domain using injected validation functions."""
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("!"):
            return None

        if line.startswith("||") and line.endswith("^"):
            line = line[2:-1]

        parts = line.split()
        candidate = parts[1] if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1") else parts[0]

        if self.validator_fn(candidate):
            return self.normalizer_fn(candidate)
        return None

    def _load_from_disk_cache(self):
        """Fallback: load previously downloaded domains from local disk cache."""
        domains = set()
        if not os.path.exists(self.cache_path):
            return domains
        with open(self.cache_path, "r", encoding="utf-8") as f:
            for line in f:
                domain = self._parse_line(line)
                if domain:
                    domains.add(domain)
        return domains

    def _save_to_disk_cache(self, domains):
        """Persist sanitized domains to local disk cache."""
        with open(self.cache_path, "w", encoding="utf-8") as f:
            for d in sorted(domains):
                f.write(f"{d}\n")

    def sync_now(self, target_set, timeout=5):
        """Download remote list, update disk cache, and atomically update target_set in RAM."""
        if not self.url:
            return 0
        try:
            req = urllib.request.Request(self.url, headers={"User-Agent": "Smart-DNS-Proxy/1.0"})
            fetched = set()
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                for raw_line in resp.read().decode("utf-8", errors="ignore").splitlines():
                    domain = self._parse_line(raw_line)
                    if domain:
                        fetched.add(domain)

            if fetched:
                self._save_to_disk_cache(fetched)
                target_set.update(fetched)
            return len(fetched)
        except Exception:
            cached = self._load_from_disk_cache()
            target_set.update(cached)
            return len(cached)

    def start_background_sync(self, target_set):
        """Start daemon thread to refresh blocklist periodically without blocking queries."""
        if not self.url or self._thread is not None:
            return

        def _worker():
            while not self._stop_event.wait(self.sync_interval_sec):
                self.sync_now(target_set)

        self._thread = threading.Thread(target=_worker, daemon=True)
        self._thread.start()

    def stop(self):
        """Signal background sync thread to terminate cleanly."""
        self._stop_event.set()