import socket
import sys
import time
import logging
from config import load_config
from domain_loader import load_domain_list

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("dns_proxy.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)


def extract_domain(data):
    """Extract domain name from DNS Question section."""
    if len(data) < 12:
        return None

    labels = []
    idx = 12

    while idx < len(data):
        length = data[idx]
        if length == 0:
            break
        if (length & 0xC0) == 0xC0:
            return None

        idx += 1
        if idx + length > len(data):
            return None

        labels.append(data[idx:idx + length].decode("utf-8", errors="ignore"))
        idx += length

    return ".".join(labels).lower()


def is_domain_matched(domain, domain_set):
    """Check exact match or parent domain match (Suffix Matching)."""
    parts = domain.split(".")
    for i in range(len(parts)):
        candidate = ".".join(parts[i:])
        if candidate in domain_set:
            return True
    return False


def build_response(query_data, resolved_ip, ttl_val=60):
    """Build a standard Type-A response with a specific IP."""
    tx_id = query_data[:2]
    flags = b"\x81\x80"
    counts = b"\x00\x01\x00\x01\x00\x00\x00\x00"

    idx = 12
    while idx < len(query_data) and query_data[idx] != 0:
        idx += 1 + query_data[idx]
    idx += 5

    question_section = query_data[12:idx]

    name_ptr = b"\xc0\x0c"
    type_class = b"\x00\x01\x00\x01"
    ttl = int(ttl_val).to_bytes(4, byteorder="big")
    rdlength = b"\x00\x04"
    rdata = socket.inet_aton(resolved_ip)

    answer = name_ptr + type_class + ttl + rdlength + rdata
    return tx_id + flags + counts + question_section + answer


def forward_to_upstream(query_data, upstream_ip, upstream_port, timeout=2.0):
    """Forward query to upstream DNS server and return the response."""
    upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream_sock.settimeout(timeout)

    try:
        upstream_sock.sendto(query_data, (upstream_ip, upstream_port))
        response, _ = upstream_sock.recvfrom(512)
        return response
    except socket.timeout:
        logging.warning(f"Upstream {upstream_ip}:{upstream_port} timed out.")
        return None
    except Exception as e:
        logging.error(f"Upstream communication failed: {e}")
        return None
    finally:
        upstream_sock.close()


def start_proxy(listen_ip="127.0.0.1", listen_port=8053):
    """Start the main DNS proxy server."""
    cfg = load_config()

    ad_domains = load_domain_list(cfg["ad_list_file"])
    sanction_domains = load_domain_list(cfg["sanction_list_file"])
    logging.info(f"Loaded {len(ad_domains)} ad domains, {len(sanction_domains)} sanction domains.")

    upstream_ip = cfg["upstream_ip"]
    upstream_port = cfg["upstream_port"]
    timeout_sec = float(cfg.get("upstream_timeout_sec", 2))
    sinkhole_ip = cfg["sinkhole_ip"]
    sanction_redirect_ip = cfg["proxy_ip"]
    ttl_val = int(cfg.get("local_ttl", 60))
    cache_enabled = str(cfg.get("cache_enabled", "true")).lower() == "true"

    dns_cache = {}

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server_sock.bind((listen_ip, listen_port))
        logging.info(f"DNS Proxy is running on {listen_ip}:{listen_port} (Cache: {cache_enabled}, TTL: {ttl_val}s)")
    except Exception as e:
        logging.critical(f"Failed to bind proxy to {listen_ip}:{listen_port}: {e}")
        sys.exit(1)

    try:
        while True:
            data, client_addr = server_sock.recvfrom(512)
            domain = extract_domain(data)

            if not domain:
                continue

            tx_id = data[:2]

            if is_domain_matched(domain, ad_domains):
                logging.info(f"[BLOCK - AD] {domain} -> {sinkhole_ip}")
                resp = build_response(data, sinkhole_ip, ttl_val)
                server_sock.sendto(resp, client_addr)

            elif is_domain_matched(domain, sanction_domains):
                logging.info(f"[REDIRECT - SANCTION] {domain} -> {sanction_redirect_ip}")
                resp = build_response(data, sanction_redirect_ip, ttl_val)
                server_sock.sendto(resp, client_addr)

            else:
                now = time.time()
                if cache_enabled and domain in dns_cache:
                    cached_resp, expire_time = dns_cache[domain]
                    if now < expire_time:
                        final_resp = tx_id + cached_resp[2:]
                        logging.info(f"[CACHE HIT] {domain} (Remaining TTL: {int(expire_time - now)}s)")
                        server_sock.sendto(final_resp, client_addr)
                        continue
                    else:
                        del dns_cache[domain]

                logging.info(f"[FORWARD] {domain} -> Upstream ({upstream_ip}:{upstream_port})")
                upstream_resp = forward_to_upstream(data, upstream_ip, upstream_port, timeout_sec)
                if upstream_resp:
                    if cache_enabled:
                        dns_cache[domain] = (upstream_resp, now + ttl_val)
                    server_sock.sendto(upstream_resp, client_addr)

    except KeyboardInterrupt:
        logging.info("Stopping DNS Proxy.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    start_proxy()