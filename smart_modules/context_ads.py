from collections import OrderedDict


class AdaptiveAdCache:
    def __init__(self, enabled=False, max_size=256):
        self.enabled = enabled
        self.max_size = max_size
        self.current_session = "default"
        self.sessions = {self.current_session: OrderedDict()}
        self.hits = {self.current_session: 0}

    def _get_session(self, session_id=None):
        sid = (session_id or self.current_session).strip() or "default"
        if sid not in self.sessions:
            self.sessions[sid] = OrderedDict()
            self.hits[sid] = 0
        return sid

    def switch_session(self, session_id):
        """Switch active session for interactive CLI usage."""
        self.current_session = self._get_session(session_id)

    def is_hot_ad(self, domain, session_id=None):
        """O(1) lookup in the specified (or active) user's L1 hot cache."""
        if not self.enabled:
            return False
        sid = self._get_session(session_id)
        cache = self.sessions[sid]
        if domain in cache:
            cache.move_to_end(domain)
            self.hits[sid] += 1
            return True
        return False

    def promote(self, domain, session_id=None):
        """Promote a newly blocked ad domain into the specified (or active) user's LRU cache."""
        if not self.enabled:
            return
        sid = self._get_session(session_id)
        cache = self.sessions[sid]
        if domain in cache:
            cache.move_to_end(domain)
            return
        if len(cache) >= self.max_size:
            cache.popitem(last=False)
        cache[domain] = True

    def clear_all(self):
        """Reset all session caches."""
        for sid in self.sessions:
            self.sessions[sid].clear()
            self.hits[sid] = 0