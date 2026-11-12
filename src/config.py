import os
import socket


def is_valid_ipv4(ip_str):
    try:
        socket.inet_aton(ip_str)
        return len(ip_str.split(".")) == 4
    except socket.error:
        return False


def load_config(filepath="config.txt"):
    if not os.path.exists(filepath):
        raise ValueError(f"Config error: {filepath} not found.")

    raw_cfg = {}
    with open(filepath, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ValueError(f"Config error: invalid syntax at line {line_num}.")
            key, val = line.split("=", 1)
            raw_cfg[key.strip()] = val.strip()

    required_keys = [
        "upstream_ip", "upstream_port", "sinkhole_ip",
        "proxy_ip", "ad_list_file", "sanction_list_file"
    ]
    for key in required_keys:
        if key not in raw_cfg or not raw_cfg[key]:
            raise ValueError(f"Config error: missing required key '{key}'.")

    if not is_valid_ipv4(raw_cfg["upstream_ip"]):
        raise ValueError("Config error: invalid upstream_ip.")
    if not is_valid_ipv4(raw_cfg["sinkhole_ip"]):
        raise ValueError("Config error: invalid sinkhole_ip.")
    if not is_valid_ipv4(raw_cfg["proxy_ip"]):
        raise ValueError("Config error: invalid proxy_ip.")

    try:
        upstream_port = int(raw_cfg["upstream_port"])
        if not (1 <= upstream_port <= 65535):
            raise ValueError
    except ValueError:
        raise ValueError("Config error: invalid upstream_port.")

    try:
        timeout_sec = float(raw_cfg.get("upstream_timeout_sec", "2"))
        if timeout_sec <= 0:
            raise ValueError
    except ValueError:
        raise ValueError("Config error: invalid upstream_timeout_sec.")

    try:
        local_ttl = int(raw_cfg.get("local_ttl", "60"))
        if local_ttl <= 0:
            raise ValueError
    except ValueError:
        raise ValueError("Config error: invalid local_ttl.")

    cache_str = raw_cfg.get("cache_enabled", "true").lower()
    if cache_str not in ("true", "false"):
        raise ValueError("Config error: cache_enabled must be true or false.")

    real_dns_str = raw_cfg.get("real_dns_enabled", "false").lower()
    if real_dns_str not in ("true", "false"):
        raise ValueError("Config error: real_dns_enabled must be true or false.")

    cache_max = None
    if "cache_max_entries" in raw_cfg and raw_cfg["cache_max_entries"]:
        try:
            cache_max = int(raw_cfg["cache_max_entries"])
            if cache_max <= 0:
                raise ValueError
        except ValueError:
            raise ValueError("Config error: invalid cache_max_entries.")

    return {
        "upstream_ip": raw_cfg["upstream_ip"],
        "upstream_port": upstream_port,
        "upstream_timeout_sec": timeout_sec,
        "sinkhole_ip": raw_cfg["sinkhole_ip"],
        "proxy_ip": raw_cfg["proxy_ip"],
        "local_ttl": local_ttl,
        "ad_list_file": raw_cfg["ad_list_file"],
        "sanction_list_file": raw_cfg["sanction_list_file"],
        "cache_enabled": cache_str == "true",
        "cache_max_entries": cache_max,
        "real_dns_enabled": real_dns_str == "true",
    }