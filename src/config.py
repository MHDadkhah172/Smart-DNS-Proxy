import os
import sys
import ipaddress

REQUIRED_KEYS = [
    "upstream_ip", "upstream_port", "sinkhole_ip",
    "proxy_ip", "ad_list_file", "sanction_list_file"
]


def is_valid_ipv4(ip_str):
    """Validate IPv4 address format."""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ValueError:
        return False


def load_config(file_path="config.txt"):
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(project_root)

    # Check config file existence
    if not os.path.isfile(file_path):
        print(f"Config error: File '{file_path}' not found.")
        sys.exit(1)

    # Default settings
    config = {
        "upstream_timeout_sec": 2,
        "local_ttl": 60,
        "cache_enabled": True
    }

    # Parse key-value pairs
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, val = [x.strip() for x in line.split("=", 1)]

                if key in ["upstream_port", "upstream_timeout_sec", "local_ttl"]:
                    config[key] = int(val)
                elif key == "cache_enabled":
                    config[key] = (val.lower() == "true")
                else:
                    config[key] = val

    except Exception:
        print(f"Config error: Invalid value format in '{file_path}'.")
        sys.exit(1)

    # 1. Validate required keys
    for req in REQUIRED_KEYS:
        if req not in config:
            print(f"Config error: Missing key '{req}'.")
            sys.exit(1)

    # 2. Validate port range (1-65535)
    if not (1 <= config["upstream_port"] <= 65535):
        print("Config error: Invalid upstream port range.")
        sys.exit(1)

    # 3. Validate IPv4 addresses
    for ip_key in ["upstream_ip", "sinkhole_ip", "proxy_ip"]:
        if not is_valid_ipv4(config[ip_key]):
            print(f"Config error: Invalid IPv4 address for '{ip_key}'.")
            sys.exit(1)

    # 4. Validate domain list files existence
    for list_key in ["ad_list_file", "sanction_list_file"]:
        path = config[list_key]
        if not os.path.isfile(path):
            print(f"Config error: List file '{path}' not found or is not a file.")
            sys.exit(1)

    return config


if __name__ == "__main__":
    cfg = load_config()
    print("Config loaded successfully.")