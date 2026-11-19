import os
import threading
import urllib.error
import urllib.request


class RemoteBlocklistSync:
    def __init__(self, url, validator_fn, normalizer_fn, cache_file="remote_ads_cache.txt", sync_interval_sec=86400):
        self.url = url
        self.validator_fn = validator_fn
        self.normalizer_fn = normalizer_fn

        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.cache_path = os.path.join(root_dir, cache_file)
        self.meta_path = self.cache_path + ".meta"
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
        """Load previously downloaded domains from local disk cache."""
        domains = set()
        if not os.path.exists(self.cache_path):
            return domains
        with open(self.cache_path, "r", encoding="utf-8") as f:
            for line in f:
                domain = self._parse_line(line)
                if domain:
                    domains.add(domain)
        return domains

    def _save_to_disk_cache(self, domains, etag=None, last_modified=None):
        """Persist sanitized domains and HTTP cache validators (ETag/Last-Modified)."""
        with open(self.cache_path, "w", encoding="utf-8") as f:
            for d in sorted(domains):
                f.write(f"{d}\n")
        with open(self.meta_path, "w", encoding="utf-8") as f:
            f.write(f"{etag or ''}\n{last_modified or ''}\n")

    def _load_meta(self):
        """Read saved ETag and Last-Modified headers if available."""
        if not os.path.exists(self.meta_path):
            return "", ""
        with open(self.meta_path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
            etag = lines[0] if len(lines) > 0 else ""
            last_mod = lines[1] if len(lines) > 1 else ""
            return etag, last_mod

    def sync_now(self, target_set, timeout=5):
        """Download remote list only if modified (HTTP 304 aware), else use disk cache."""
        if not self.url:
            return 0

        headers = {"User-Agent": "Smart-DNS-Proxy/1.0"}
        etag, last_mod = self._load_meta()
        if etag:
            headers["If-None-Match"] = etag
        if last_mod:
            headers["If-Modified-Since"] = last_mod

        try:
            req = urllib.request.Request(self.url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                fetched = set()
                for raw_line in resp.read().decode("utf-8", errors="ignore").splitlines():
                    domain = self._parse_line(raw_line)
                    if domain:
                        fetched.add(domain)

                if fetched:
                    new_etag = resp.headers.get("ETag")
                    new_last_mod = resp.headers.get("Last-Modified")
                    self._save_to_disk_cache(fetched, new_etag, new_last_mod)
                    target_set.update(fetched)
                return len(fetched)

        except urllib.error.HTTPError as e:
            if e.code == 304:
                # Remote file unchanged; load directly from local disk cache
                cached = self._load_from_disk_cache()
                target_set.update(cached)
                return len(cached)
            cached = self._load_from_disk_cache()
            target_set.update(cached)
            return len(cached)

        except Exception:
            cached = self._load_from_disk_cache()
            target_set.update(cached)
            return len(cached)

    def start_background_sync(self, target_set):
        """Start daemon thread to check for remote updates every 24 hours."""
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