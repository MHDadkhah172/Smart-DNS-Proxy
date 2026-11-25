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
from dns_engine.engine_router import SmartEngineRouter
from domain_loader import is_valid_domain, load_domain_list, normalize_domain
from security_gateway.bridge import GatewayController
from smart_modules import RemoteBlocklistSync, UpstreamRouter


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
    tx_id = os.urandom(2)
    flags = b"\x01\x00"
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
        if rcode == 3:
            return "NOT_FOUND", "-", "-"
        if rcode != 0:
            return "SERVER_ERROR", "-", "-"

        ancount = struct.unpack("!H", resp[6:8])[0]
        if ancount == 0:
            return "NOT_FOUND", "-", "-"

        idx = 12
        while idx < len(resp) and resp[idx] != 0:
            idx += 1 + resp[idx]
        idx += 5

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


def resolve_domain(raw_domain, cfg, ad_domains, sanction_domains, cache, stats, router, query_fn):
    """Core resolution pipeline."""
    stats["Total"] += 1

    if not is_valid_domain(raw_domain):
        stats["ERRORS"] += 1
        disp_name = "(empty)" if raw_domain == "" else raw_domain
        return disp_name, "NONE", "INVALID_INPUT", "-", "-"

    domain = normalize_domain(raw_domain)

    if is_domain_matched(domain, ad_domains):
        stats["AD_BLOCK"] += 1
        return domain, "AD_BLOCK", "OK", cfg["sinkhole_ip"], cfg["local_ttl"]

    if is_domain_matched(domain, sanction_domains):
        stats["SANCTION"] += 1
        return domain, "SANCTION", "OK", cfg["proxy_ip"], cfg["local_ttl"]

    now = time.time()
    if cfg["cache_enabled"] and domain in cache:
        cached_ip, expire_time = cache[domain]
        rem_ttl = int(expire_time - now)
        if rem_ttl >= 1:
            stats["CACHE"] += 1
            return domain, "CACHE", "OK", cached_ip, rem_ttl
        del cache[domain]

    status, ip, ttl = router.query_smart_pool(
        domain, query_fn, cfg["upstream_port"], cfg["upstream_timeout_sec"]
    )

    if status == "OK":
        stats["UPSTREAM"] += 1
        if cfg["cache_enabled"] and isinstance(ttl, int) and ttl > 0:
            max_cap = cfg["cache_max_entries"]
            if max_cap is not None and domain not in cache and len(cache) >= max_cap:
                cache.popitem(last=False)
            cache[domain] = (ip, time.time() + ttl)
        return domain, "UPSTREAM", "OK", ip, ttl

    if status == "NOT_FOUND":
        stats["UPSTREAM"] += 1
        return domain, "UPSTREAM", "NOT_FOUND", "-", "-"

    stats["ERRORS"] += 1
    return domain, "UPSTREAM", "SERVER_ERROR", "-", "-"


def print_engine_dashboard(router):
    """Display live DNS engine metrics table in CLI."""
    if not isinstance(router, SmartEngineRouter):
        print("Smart DNS Engine is inactive.\n")
        return

    status = router.get_selector_status()
    rows = router.get_dashboard_rows()
    print(f"Selector State -> Last Switch Reason: {status['last_switch_reason']}")
    print(
        f"{'ROLE':<10} | {'NAME':<18} | {'IP':<15} | {'AVG(ms)':<8} | "
        f"{'P95(ms)':<8} | {'JITTER':<7} | {'SUCC%':<6} | {'SCORE':<6}"
    )
    print("-" * 92)
    for r in rows:
        avg_lat = f"{r['avg_latency']:.1f}" if r["avg_latency"] is not None else "-"
        p95_val = f"{r['p95']:.1f}" if r["p95"] is not None else "-"
        jit_val = f"{r['jitter']:.1f}" if r["jitter"] is not None else "-"
        succ_val = f"{r['success_rate'] * 100:.0f}%" if r["success_rate"] is not None else "-"
        score_val = f"{r['score']:.2f}" if r["score"] is not None else "-"
        role_val = r["role"] or "CANDIDATE"
        print(
            f"{role_val:<10} | {r['name']:<18} | {r['ip']:<15} | {avg_lat:<8} | "
            f"{p95_val:<8} | {jit_val:<7} | {succ_val:<6} | {score_val:<6}"
        )
    print()


def main():
    try:
        cfg = load_config("config.txt")
        ad_domains = load_domain_list(cfg["ad_list_file"])
        sanction_domains = load_domain_list(cfg["sanction_list_file"])
    except ValueError as e:
        print(e)
        sys.exit(1)

    query_fn = query_real_dns if cfg["real_dns_enabled"] else query_text_upstream

    pool_raw = cfg.get("upstream_pool", cfg["upstream_ip"])
    pool = [s.strip() for s in pool_raw.split(",") if s.strip()]
    if cfg["real_dns_enabled"]:
        db_path = os.path.join(ROOT_DIR, "dns_engine.db")
        router = SmartEngineRouter(pool_ips=pool, db_path=db_path, probe_interval_sec=60.0)
        router.start()
    else:
        router = UpstreamRouter(pool)

    remote_syncer = RemoteBlocklistSync(
        url=cfg.get("remote_ad_list_url", "").strip(),
        validator_fn=is_valid_domain,
        normalizer_fn=normalize_domain,
    )
    if remote_syncer.url:
        remote_syncer.sync_now(ad_domains)
        remote_syncer.start_background_sync(ad_domains)

    cache = OrderedDict()
    stats = {"Total": 0, "AD_BLOCK": 0, "SANCTION": 0, "CACHE": 0, "UPSTREAM": 0, "ERRORS": 0}

    # Enable ML Security Gateway on 127.0.0.1:15353
    cfg["enable_security_gateway"] = "true"
    cfg["gateway_host"] = "127.0.0.1"
    cfg["gateway_port"] = 15353

    gw_controller = GatewayController(
        cfg=cfg,
        resolve_callback=lambda dom: resolve_domain(
            dom, cfg, ad_domains, sanction_domains, cache, stats, router, query_fn
        ),
        root_dir=ROOT_DIR,
    )
    gw_controller.start()

    def shutdown():
        gw_controller.stop()
        remote_syncer.stop()
        if isinstance(router, SmartEngineRouter):
            router.stop()

    print("DNS Proxy ready.")

    while True:
        try:
            raw_line = input("Enter domain (or exit): ")
        except EOFError:
            shutdown()
            print("Bye.")
            break

        user_input = raw_line.strip()
        cmd = user_input.lower()

        if cmd == "exit":
            shutdown()
            print("Bye.")
            break

        if gw_controller.handle_cli_command(user_input):
            continue

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

        if cmd in ("engine", "smart_stats"):
            if isinstance(router, SmartEngineRouter):
                print_engine_dashboard(router)
            else:
                sorted_lat = dict(sorted(router.latencies.items(), key=lambda x: x[1]))
                print("Latencies (ms):", {k: round(v, 2) for k, v in sorted_lat.items()})
                print()
            continue

        domain_str, source, status, ip, ttl = resolve_domain(
            user_input, cfg, ad_domains, sanction_domains, cache, stats, router, query_fn
        )
        print_result_block(domain_str, source, status, ip, ttl)


if __name__ == "__main__":
    main()