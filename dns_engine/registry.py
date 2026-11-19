import socket


SUPPORTED_PROTOCOLS = {"UDP", "TCP", "DOH", "DOT"}

DEFAULT_RESOLVERS = [
    {"name": "Cloudflare Primary", "provider": "Cloudflare", "ip": "1.1.1.1", "port": 53, "protocol": "UDP"},
    {"name": "Google Primary", "provider": "Google", "ip": "8.8.8.8", "port": 53, "protocol": "UDP"},
    {"name": "Quad9 Primary", "provider": "Quad9", "ip": "9.9.9.9", "port": 53, "protocol": "UDP"},
    {"name": "OpenDNS Home", "provider": "Cisco OpenDNS", "ip": "208.67.222.222", "port": 53, "protocol": "UDP"},
]


def is_valid_ipv4(ip_str):
    try:
        socket.inet_aton(ip_str)
        return len(ip_str.split(".")) == 4
    except socket.error:
        return False


class ResolverRegistry:
    def __init__(self, db):
        self.db = db

    def seed_defaults(self, custom_ips=None):
        """Populate initial resolvers if database has none yet."""
        existing = self.db.get_resolvers(active_only=False)
        if existing:
            return

        if custom_ips:
            known_map = {r["ip"]: r for r in DEFAULT_RESOLVERS}
            for idx, ip in enumerate(custom_ips, 1):
                ip = ip.strip()
                if not ip:
                    continue
                if ip in known_map:
                    meta = known_map[ip]
                    self.register(meta["name"], meta["provider"], meta["ip"], meta["port"], meta["protocol"])
                else:
                    self.register(f"Custom DNS #{idx}", "Custom", ip, 53, "UDP")
        else:
            for meta in DEFAULT_RESOLVERS:
                self.register(meta["name"], meta["provider"], meta["ip"], meta["port"], meta["protocol"])

    def register(self, name, provider, ip, port=53, protocol="UDP", is_active=True):
        """Validate and register (or update) a DNS resolver."""
        name = (name or "").strip()
        provider = (provider or "Unknown").strip()
        ip = (ip or "").strip()
        protocol = (protocol or "UDP").strip().upper()

        if not name:
            raise ValueError("Resolver name cannot be empty.")
        if not is_valid_ipv4(ip):
            raise ValueError(f"Invalid IPv4 address: '{ip}'")

        port = int(port)
        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port: {port}")
        if protocol not in SUPPORTED_PROTOCOLS:
            raise ValueError(f"Unsupported protocol '{protocol}'. Allowed: {sorted(SUPPORTED_PROTOCOLS)}")

        return self.db.add_resolver(name, provider, ip, port, protocol, is_active)

    def enable(self, resolver_id):
        self.db.set_resolver_active(resolver_id, True)

    def disable(self, resolver_id):
        self.db.set_resolver_active(resolver_id, False)

    def list_active(self, protocol=None):
        resolvers = self.db.get_resolvers(active_only=True)
        if protocol:
            proto = protocol.strip().upper()
            resolvers = [r for r in resolvers if r["protocol"] == proto]
        return resolvers

    def list_all(self):
        return self.db.get_resolvers(active_only=False)

    def get_by_id(self, resolver_id):
        for r in self.db.get_resolvers(active_only=False):
            if r["id"] == resolver_id:
                return r
        return None
