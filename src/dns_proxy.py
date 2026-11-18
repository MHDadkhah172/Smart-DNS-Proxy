import os
import socket
import struct
import sys
import time
from collections import OrderedDict
from datetime import datetime

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from config import load_config
from domain_loader import is_valid_domain, load_domain_list, normalize_domain
from smart_modules import AdaptiveAdCache, RemoteBlocklistSync, UpstreamRouter


def is_domain_matched(domain, domain_set):
    """Exact match or label-boundary suffix match."""
    if domain in domain_set:
        return True
    for entry in domain_set:
        if domain.endswith("." + entry):
            return True
    return False


def query_text_upstream(domain, upstream_ip, upstream_port, timeout_sec):
    """Mandatory text-based UDP protocol."""
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
    """Real binary DNS query over UDP (e.g., 8.8.8.8:53)."""
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
    """Append structured line to log.txt."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{now_str} | {domain_str} | {source} | {status} | {ip} | {ttl}\n"
    with open("log.txt", "a", encoding="utf-8") as f:
        f.write(line)


def print_result_block(domain_str, source, status, ip, ttl):
    """Print exact 5-line output block followed by an empty line."""
    print(f"Domain: {domain_str}")
    print(f"Source: {source}")
    print(f"Status: {status}")
    print(f"IP: {ip}")
    print(f"TTL: {ttl}")
    print()
    append_log(domain_str, source, status, ip, ttl)


def resolve_domain(
    raw_domain,
    cfg,
    ad_domains,
    sanction_domains,
    cache,
    stats,
    router,
    ad_cache,
    query_fn,
    session_id=None,
):
    """Core resolution pipeline usable by both CLI loop and multi-user simulator."""
    stats["Total"] += 1

    if not is_valid_domain(raw_domain):
        stats["ERRORS"] += 1
        disp_name = "(empty)" if raw_domain == "" else raw_domain
        return disp_name, "NONE", "INVALID_INPUT", "-", "-"

    domain = normalize_domain(raw_domain)

    # 1. Ad list check (L1 Hot Cache first, then full synced ad_domains)
    if ad_cache.is_hot_ad(domain, session_id=session_id) or is_domain_matched(domain, ad_domains):
        ad_cache.promote(domain, session_id=session_id)
        stats["AD_BLOCK"] += 1
        return domain, "AD_BLOCK", "OK", cfg["sinkhole_ip"], cfg["local_ttl"]

    # 2. Sanction list check
    if is_domain_matched(domain, sanction_domains):
        stats["SANCTION"] += 1
        return domain, "SANCTION", "OK", cfg["proxy_ip"], cfg["local_ttl"]

    # 3. Cache check (if enabled)
    now = time.time()
    if cfg["cache_enabled"] and domain in cache:
        cached_ip, expire_time = cache[domain]
        rem_ttl = int(expire_time - now)
        if rem_ttl >= 1:
            stats["CACHE"] += 1
            return domain, "CACHE", "OK", cached_ip, rem_ttl
        del cache[domain]

    # 4. Upstream query via Smart Latency-Aware Pool
    status, ip, ttl = router.query_smart_pool(
        domain, query_fn, cfg["upstream_port"], cfg["upstream_timeout_sec"]
    )

    if status == "OK":
        stats["UPSTREAM"] += 1
        if cfg["cache_enabled"] and isinstance(ttl, int) and ttl > 0:
            max_cap = cfg["cache_max_entries"]
            if max_cap is not None and domain not in cache and len(cache) >= max_cap:
                cache.popitem(last=False)  # FIFO eviction
            cache[domain] = (ip, time.time() + ttl)
        return domain, "UPSTREAM", "OK", ip, ttl

    if status == "NOT_FOUND":
        stats["UPSTREAM"] += 1
        return domain, "UPSTREAM", "NOT_FOUND", "-", "-"

    stats["ERRORS"] += 1
    return domain, "UPSTREAM", "SERVER_ERROR", "-", "-"


def main():
    try:
        cfg = load_config("config.txt")
        ad_domains = load_domain_list(cfg["ad_list_file"])
        sanction_domains = load_domain_list(cfg["sanction_list_file"])
    except ValueError as e:
        print(e)
        sys.exit(1)

    query_fn = query_real_dns if cfg["real_dns_enabled"] else query_text_upstream

    # 1. Initialize Smart Upstream Router & benchmark at startup
    pool_raw = cfg.get("upstream_pool", cfg["upstream_ip"])
    pool = [s.strip() for s in pool_raw.split(",") if s.strip()]
    router = UpstreamRouter(pool)
    if cfg["real_dns_enabled"]:
        router.benchmark_all(query_fn=query_fn, port=cfg["upstream_port"], timeout=1.5)

    # 2. Initialize Remote Blocklist Sync (initial sync + 24h background thread)
    remote_syncer = RemoteBlocklistSync(
        url=cfg.get("remote_ad_list_url", "").strip(),
        validator_fn=is_valid_domain,
        normalizer_fn=normalize_domain,
    )
    if remote_syncer.url:
        remote_syncer.sync_now(ad_domains)
        remote_syncer.start_background_sync(ad_domains)

    # 3. Initialize Multi-Session Adaptive Ad Cache
    ad_cache = AdaptiveAdCache(
        enabled=str(cfg.get("context_ads_enabled", "false")).lower() == "true"
    )

    cache = OrderedDict()
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
            remote_syncer.stop()
            print("Bye.")
            break

        user_input = raw_line.strip()
        cmd = user_input.lower()

        if cmd == "exit":
            remote_syncer.stop()
            print("Bye.")
            break

        if cmd == "stats":
            print(
                f"Total: {stats['Total']} | AD_BLOCK: {stats['AD_BLOCK']} | "
                f"SANCTION: {stats['SANCTION']} | CACHE: {stats['CACHE']} | "
                f"UPSTREAM: {stats['UPSTREAM']} | ERRORS: {stats['ERRORS']}"
            )
            print()
            continue

        if cmd == "reload":
            try:
                ad_domains = load_domain_list(cfg["ad_list_file"])
                sanction_domains = load_domain_list(cfg["sanction_list_file"])
                if remote_syncer.url:
                    remote_syncer.sync_now(ad_domains)
                ad_cache.clear_all()
                print("Lists reloaded.")
            except ValueError as e:
                print(e)
            print()
            continue

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

        if cmd.startswith("user "):
            ad_cache.switch_session(user_input.split(" ", 1)[1])
            print(f"Switched session to: {ad_cache.current_session}\n")
            continue

        if cmd == "smart_stats":
            print("Latencies (ms):", {k: round(v, 2) for k, v in router.latencies.items()})
            print("User Hits:", ad_cache.hits)
            print()
            continue

        domain_str, source, status, ip, ttl = resolve_domain(
            user_input, cfg, ad_domains, sanction_domains, cache, stats, router, ad_cache, query_fn
        )
        print_result_block(domain_str, source, status, ip, ttl)


if __name__ == "__main__":
    main()