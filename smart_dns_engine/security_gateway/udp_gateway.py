import socket
import threading
from typing import Callable
from .packet_codec import parse_dns_query, build_dns_response
from .security_guard import SecurityGuard


class DNSUdpGateway:
    """
    Multi-client UDP DNS gateway listening on an unprivileged port (default 5353).
    Bridges raw DNS packets with the core DNS engine and SecurityGuard without
    modifying the existing engine internals.
    """

    def __init__(
        self,
        resolver_fn: Callable[[str], tuple[str | None, str]],
        guard: SecurityGuard,
        host: str = "127.0.0.1",
        port: int = 5353,
    ):
        """
        resolver_fn: A callable taking (domain: str) and returning (ip_or_none, status_str)
                     where status_str is 'OK', 'BLOCKED', or 'NOT_FOUND'.
        """
        self.resolver_fn = resolver_fn
        self.guard = guard
        self.host = host
        self.port = port

        self._sock: socket.socket | None = None
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._running:
            return
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((self.host, self.port))
        self._sock.settimeout(0.5)

        self._running = True
        self._thread = threading.Thread(target=self._serve_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
        if self._sock:
            self._sock.close()

    def _serve_loop(self) -> None:
        assert self._sock is not None
        while self._running:
            try:
                packet, addr = self._sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break

            client_id = addr[0]
            threading.Thread(
                target=self._handle_packet,
                args=(packet, addr, client_id),
                daemon=True,
            ).start()

    def _handle_packet(self, packet: bytes, addr: tuple[str, int], client_id: str) -> None:
        assert self._sock is not None
        _, domain, qtype = parse_dns_query(packet)
        if not domain:
            return

        # 1. Hot-path O(1) security access check
        allowed, state_label = self.guard.check_access(client_id)
        if not allowed:
            # RCODE 5 = REFUSED
            resp = build_dns_response(packet, rcode=5)
            self._sock.sendto(resp, addr)
            return

        # 2. Only resolve Type A (1) queries via core engine; return empty NOERROR for others
        if qtype != 1:
            resp = build_dns_response(packet, ip_address=None, rcode=0)
            self._sock.sendto(resp, addr)
            return

        ip_addr, status = self.resolver_fn(domain)

        # 3. Record transaction asynchronously for Cold-Path ML analysis
        self.guard.record_event(client_id, domain, status)

        # 4. Build and send standard DNS response
        if status == "OK" and ip_addr:
            resp = build_dns_response(packet, ip_address=ip_addr, rcode=0)
        elif status == "BLOCKED":
            resp = build_dns_response(packet, rcode=5)
        else:
            resp = build_dns_response(packet, rcode=3)  # RCODE 3 = NXDOMAIN

        self._sock.sendto(resp, addr)