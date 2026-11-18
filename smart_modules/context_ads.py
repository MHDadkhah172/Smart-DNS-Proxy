from collections import OrderedDict


class AdaptiveAdCache:
    def __init__(self, enabled=False, max_size=256):
        self.enabled = enabled
        self.max_size = max_size
        self.current_session = "default"
        # Separate L1 LRU Hot Cache per simulated user/session
        self.sessions = {self.current_session: OrderedDict()}
        self.hits = {self.current_session: 0}

    def switch_session(self, session_id):
        """Switch or initialize an isolated hot-ad cache for a simulated user."""
        sid = session_id.strip() or "default"
        self.current_session = sid
        if sid not in self.sessions:
            self.sessions[sid] = OrderedDict()
            self.hits[sid] = 0

    def is_hot_ad(self, domain):
        """O(1) lookup in the active user's L1 hot cache before scanning large lists."""
        if not self.enabled:
            return False
        cache = self.sessions[self.current_session]
        if domain in cache:
            cache.move_to_end(domain)
            self.hits[self.current_session] += 1
            return True
        return False

    def promote(self, domain):
        """Promote a newly blocked ad domain into the active user's L1 LRU cache."""
        if not self.enabled:
            return
        cache = self.sessions[self.current_session]
        if domain in cache:
            cache.move_to_end(domain)
            return
        if len(cache) >= self.max_size:
            cache.popitem(last=False)  # Evict least recently used ad domain
        cache[domain] = True

    def clear_all(self):
        """Reset all session caches (used when blocklists are reloaded)."""
        for sid in self.sessions:
            self.sessions[sid].clear()
            self.hits[sid] = 0