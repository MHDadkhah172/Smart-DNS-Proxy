import socket
import sys
import time
import struct
from datetime import datetime
from collections import OrderedDict
from config import load_config
from domain_loader import is_valid_domain, normalize_domain, load_domain_list


def is_domain_matched(domain, domain_set):
    """Exact match or label-boundary suffix match (section 4)."""
    if domain in domain_set:
        return True
    for entry in domain_set:
        if domain.endswith("." + entry):
            return True
    return False


def query_text_upstream(domain, upstream_ip, upstream_port, timeout_sec):
    """Mandatory text-based UDP protocol (section 6.2)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_sec)
    try:
        msg = f"QUERY {domain}".encode("utf-8")
        sock.sendto(msg, (upstream_ip, upstream_port))
        data, _ = sock.recvfrom(1024)
        reply = data.decode("utf-8", errors="ignore").strip()

        if reply == "NOT_FOUND":
            return "NOT_FOUND", "-", "-"

        parts = reply.split()
        if len(parts) == 3 and parts[0] == "OK":
            ip = parts[1]
            ttl = int(parts[2])
            return "OK", ip, ttl

        return "SERVER_ERROR", "-", "-"
    except Exception:
        return "SERVER_ERROR", "-", "-"
    finally:
        sock.close()


def query_real_dns(domain, upstream_ip, upstream_port, timeout_sec):
    """Bonus B6: Real binary DNS query over UDP (e.g., 8.8.8.8:53)."""
    tx_id = b"\x1a\x2b"
    flags = b"\x01\x00"  # Standard recursive query
    counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
    qname = b"".join(bytes([len(p)]) + p.encode("utf-8") for p in domain.split(".")) + b"\x00"
    packet = tx_id + flags + counts + qname + b"\x00\x01\x00\x01"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_sec)
    try:
        sock.sendto(packet, (upstream_ip, upstream_port))
        resp, _ = sock.recvfrom(512)
        if len(resp) < 12:
            return "SERVER_ERROR", "-", "-"

        rcode = resp[3] & 0x0F
        if rcode == 3:  # NXDOMAIN
            return "NOT_FOUND", "-", "-"
        if rcode != 0:
            return "SERVER_ERROR", "-", "-"

        ancount = struct.unpack("!H", resp[6:8])[0]
        if ancount == 0:
            return "NOT_FOUND", "-", "-"

        # Skip Question section
        idx = 12
        while idx < len(resp) and resp[idx] != 0:
            idx += 1 + resp[idx]
        idx += 5

        # Parse Answer records to find first Type-A (IPv4)
        for _ in range(ancount):
            if idx >= len(resp):
                break
            if (resp[idx] & 0xC0) == 0xC0:
                idx += 2
            else:
                while idx < len(resp) and resp[idx] != 0:
                    idx += 1 + resp[idx]
                idx += 1

            if idx + 10 > len(resp):
                break
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", resp[idx:idx + 10])
            idx += 10
            if rtype == 1 and rclass == 1 and rdlength == 4 and idx + 4 <= len(resp):
                ip = socket.inet_ntoa(resp[idx:idx + 4])
                return "OK", ip, ttl
            idx += rdlength

        return "NOT_FOUND", "-", "-"
    except Exception:
        return "SERVER_ERROR", "-", "-"
    finally:
        sock.close()


def append_log(domain_str, source, status, ip, ttl):
    """Bonus B4: Append structured line to log.txt."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{now_str} | {domain_str} | {source} | {status} | {ip} | {ttl}\n"
    with open("log.txt", "a", encoding="utf-8") as f:
        f.write(line)


def print_result_block(domain_str, source, status, ip, ttl):
    """Print exact 5-line output block followed by an empty line (section 6.1)."""
    print(f"Domain: {domain_str}")
    print(f"Source: {source}")
    print(f"Status: {status}")
    print(f"IP: {ip}")
    print(f"TTL: {ttl}")
    print()
    append_log(domain_str, source, status, ip, ttl)


def main():
    try:
        cfg = load_config("config.txt")
        ad_domains = load_domain_list(cfg["ad_list_file"])
        sanction_domains = load_domain_list(cfg["sanction_list_file"])
    except ValueError as e:
        print(e)
        sys.exit(1)

    # OrderedDict for FIFO eviction (Bonus B5)
    cache = OrderedDict()

    # Statistics counters (Bonus B1)
    stats = {
        "Total": 0,
        "AD_BLOCK": 0,
        "SANCTION": 0,
        "CACHE": 0,
        "UPSTREAM": 0,
        "ERRORS": 0,
    }

    print("DNS Proxy ready.")

    while True:
        try:
            raw_line = input("Enter domain (or exit): ")
        except EOFError:
            print("Bye.")
            break

        user_input = raw_line.strip()
        cmd = user_input.lower()

        # Exit command
        if cmd == "exit":
            print("Bye.")
            break

        # Bonus B1: stats command
        if cmd == "stats":
            print(
                f"Total: {stats['Total']} | AD_BLOCK: {stats['AD_BLOCK']} | "
                f"SANCTION: {stats['SANCTION']} | CACHE: {stats['CACHE']} | "
                f"UPSTREAM: {stats['UPSTREAM']} | ERRORS: {stats['ERRORS']}"
            )
            print()
            continue

        # Bonus B2: reload command
        if cmd == "reload":
            try:
                ad_domains = load_domain_list(cfg["ad_list_file"])
                sanction_domains = load_domain_list(cfg["sanction_list_file"])
                print("Lists reloaded.")
            except ValueError as e:
                print(e)
            print()
            continue

        # Bonus B3: cache command
        if cmd == "cache":
            now = time.time()
            expired_keys = [k for k, (_, exp) in cache.items() if int(exp - now) < 1]
            for k in expired_keys:
                del cache[k]

            if not cache:
                print("Cache is empty.")
            else:
                for dom, (cached_ip, exp) in cache.items():
                    rem_ttl = int(exp - now)
                    print(f"{dom} | {cached_ip} | {rem_ttl}")
            print()
            continue

        # Domain request processing
        stats["Total"] += 1

        if not is_valid_domain(user_input):
            stats["ERRORS"] += 1
            disp_name = "(empty)" if user_input == "" else user_input
            print_result_block(disp_name, "NONE", "INVALID_INPUT", "-", "-")
            continue

        domain = normalize_domain(user_input)

        # 1. Ad list check
        if is_domain_matched(domain, ad_domains):
            stats["AD_BLOCK"] += 1
            print_result_block(domain, "AD_BLOCK", "OK", cfg["sinkhole_ip"], cfg["local_ttl"])
            continue

        # 2. Sanction list check
        if is_domain_matched(domain, sanction_domains):
            stats["SANCTION"] += 1
            print_result_block(domain, "SANCTION", "OK", cfg["proxy_ip"], cfg["local_ttl"])
            continue

        # 3. Cache check (if enabled)
        now = time.time()
        if cfg["cache_enabled"] and domain in cache:
            cached_ip, expire_time = cache[domain]
            rem_ttl = int(expire_time - now)
            if rem_ttl >= 1:
                stats["CACHE"] += 1
                print_result_block(domain, "CACHE", "OK", cached_ip, rem_ttl)
                continue
            else:
                del cache[domain]

        # 4. Upstream query (Text mock or Real DNS B6)
        if cfg["real_dns_enabled"]:
            status, ip, ttl = query_real_dns(
                domain, cfg["upstream_ip"], cfg["upstream_port"], cfg["upstream_timeout_sec"]
            )
        else:
            status, ip, ttl = query_text_upstream(
                domain, cfg["upstream_ip"], cfg["upstream_port"], cfg["upstream_timeout_sec"]
            )

        if status == "OK":
            stats["UPSTREAM"] += 1
            if cfg["cache_enabled"] and isinstance(ttl, int) and ttl > 0:
                max_cap = cfg["cache_max_entries"]
                if max_cap is not None and domain not in cache and len(cache) >= max_cap:
                    cache.popitem(last=False)  # FIFO eviction (Bonus B5)
                cache[domain] = (ip, time.time() + ttl)
            print_result_block(domain, "UPSTREAM", "OK", ip, ttl)
        elif status == "NOT_FOUND":
            stats["UPSTREAM"] += 1
            print_result_block(domain, "UPSTREAM", "NOT_FOUND", "-", "-")
        else:
            stats["ERRORS"] += 1
            print_result_block(domain, "UPSTREAM", "SERVER_ERROR", "-", "-")


if __name__ == "__main__":
    main()