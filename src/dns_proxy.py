import socket
import sys
from config import load_config
from domain_loader import load_domain_list


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
        # Guard against pointer compression in queries
        if (length & 0xC0) == 0xC0:
            return None

        idx += 1
        if idx + length > len(data):
            return None

        labels.append(data[idx:idx + length].decode("utf-8", errors="ignore"))
        idx += length

    return ".".join(labels).lower()


def build_response(query_data, resolved_ip, ttl_val=60):
    """Build a standard Type-A response with a specific IP."""
    tx_id = query_data[:2]
    flags = b"\x81\x80"
    counts = b"\x00\x01\x00\x01\x00\x00\x00\x00"

    # Locate the end of QNAME
    idx = 12
    while idx < len(query_data) and query_data[idx] != 0:
        idx += 1 + query_data[idx]
    idx += 5  # Null byte (1B) + QTYPE & QCLASS (4B)

    question_section = query_data[12:idx]

    # Answer section: pointer to QNAME (0xc00c) + Type A/IN + TTL + IP
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
        print(f"[Warning] Upstream {upstream_ip}:{upstream_port} timed out.")
        return None
    except Exception as e:
        print(f"[Error] Upstream communication failed: {e}")
        return None
    finally:
        upstream_sock.close()


def start_proxy(listen_ip="127.0.0.1", listen_port=8053):
    """Start the main DNS proxy server on a non-privileged port."""
    cfg = load_config()

    # Load blocklists using config keys
    ad_domains = load_domain_list(cfg["ad_list_file"])
    sanction_domains = load_domain_list(cfg["sanction_list_file"])
    print(f"[*] Loaded {len(ad_domains)} ad domains, {len(sanction_domains)} sanction domains.")

    upstream_ip = cfg["upstream_ip"]
    upstream_port = cfg["upstream_port"]
    timeout_sec = float(cfg.get("upstream_timeout_sec", 2))
    sinkhole_ip = cfg["sinkhole_ip"]
    sanction_redirect_ip = cfg["proxy_ip"]
    ttl_val = int(cfg.get("local_ttl", 60))

    # Bind UDP server socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server_sock.bind((listen_ip, listen_port))
        print(f"[*] DNS Proxy is running on {listen_ip}:{listen_port} (UDP)")
    except Exception as e:
        print(f"[Fatal] Failed to bind proxy to {listen_ip}:{listen_port}: {e}")
        sys.exit(1)

    try:
        while True:
            data, client_addr = server_sock.recvfrom(512)
            domain = extract_domain(data)

            if not domain:
                continue

            # Route by domain policy
            if domain in ad_domains:
                print(f"[BLOCK - AD] {domain} -> {sinkhole_ip}")
                resp = build_response(data, sinkhole_ip, ttl_val)
                server_sock.sendto(resp, client_addr)

            elif domain in sanction_domains:
                print(f"[REDIRECT - SANCTION] {domain} -> {sanction_redirect_ip}")
                resp = build_response(data, sanction_redirect_ip, ttl_val)
                server_sock.sendto(resp, client_addr)

            else:
                print(f"[FORWARD] {domain} -> Upstream ({upstream_ip}:{upstream_port})")
                upstream_resp = forward_to_upstream(data, upstream_ip, upstream_port, timeout_sec)
                if upstream_resp:
                    server_sock.sendto(upstream_resp, client_addr)

    except KeyboardInterrupt:
        print("\n[*] Stopping DNS Proxy.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    start_proxy()