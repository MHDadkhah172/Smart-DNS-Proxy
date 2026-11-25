import os
import threading
from .security_guard import SecurityGuard
from .udp_gateway import DNSUdpGateway


class GatewayController:
    """Thin, thread-safe bridge between dns_proxy CLI and the Security Gateway."""

    def __init__(self, cfg: dict, resolve_callback, root_dir: str):
        self.enabled = str(cfg.get("enable_security_gateway", "false")).strip().lower() == "true"
        self.guard: SecurityGuard | None = None
        self.gateway: DNSUdpGateway | None = None
        self._resolve_lock = threading.Lock()

        if not self.enabled:
            return

        host = str(cfg.get("gateway_host", "127.0.0.1")).strip()
        port = int(cfg.get("gateway_port", 5353))
        window_size = int(cfg.get("baseline_window_size", 20))
        db_path = os.path.join(root_dir, "security.db")

        def safe_resolver(domain: str) -> tuple[str | None, str]:
            with self._resolve_lock:
                _, source, status, ip, _ = resolve_callback(domain)

            if source in ("AD_BLOCK", "SANCTION"):
                return (ip if ip != "-" else None), "BLOCKED"
            if status == "OK" and ip != "-":
                return ip, "OK"
            if status == "NOT_FOUND":
                return None, "NOT_FOUND"
            return None, "SERVER_ERROR"

        self.guard = SecurityGuard(db_path=db_path, baseline_window_size=window_size)
        self.gateway = DNSUdpGateway(
            resolver_fn=safe_resolver,
            guard=self.guard,
            host=host,
            port=port,
        )

    def start(self) -> None:
        if self.enabled and self.guard and self.gateway:
            self.guard.start()
            self.gateway.start()
            print(f"Security Gateway listening on {self.gateway.host}:{self.gateway.port} (UDP)")

    def stop(self) -> None:
        if self.gateway:
            self.gateway.stop()
        if self.guard:
            self.guard.stop()

    def handle_cli_command(self, raw_cmd: str) -> bool:
        """Handles 'clients', 'alerts', and 'unblock <client_id>'. Returns True if handled."""
        parts = raw_cmd.strip().split()
        if not parts:
            return False

        cmd = parts[0].lower()
        if cmd not in ("clients", "alerts", "unblock"):
            return False

        if not self.enabled or not self.guard:
            print("Security Gateway is disabled in config.txt.\n")
            return True

        if cmd == "clients":
            rows = self.guard.get_clients_summary()
            if not rows:
                print("No active gateway clients recorded yet.\n")
                return True
            print(f"{'CLIENT ID':<22} | {'STATUS':<12} | {'STRIKES':<7} | {'REQUESTS':<8}")
            print("-" * 58)
            for r in rows:
                print(f"{r['client_id']:<22} | {r['status']:<12} | {r['strikes']:<7} | {r['total_requests']:<8}")
            print()
            return True

        if cmd == "alerts":
            alerts = self.guard.get_recent_alerts(limit=10)
            if not alerts:
                print("No security alerts recorded.\n")
                return True
            for ts, cid, action, score, thresh, details in alerts:
                print(f"[{action}] {cid} | score={score:.3f} > {thresh:.3f} | {details}")
            print()
            return True

        if cmd == "unblock":
            if len(parts) < 2:
                print("Usage: unblock <client_id>\n")
                return True
            target_id = parts[1]
            if self.guard.unblock_client(target_id):
                print(f"Client '{target_id}' unblocked and reset to NORMAL.\n")
            else:
                print(f"Client '{target_id}' not found.\n")
            return True

        return False