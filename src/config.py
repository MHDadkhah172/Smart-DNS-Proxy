import os
import sys
import ipaddress

# Required configuration keys
REQUIRED_KEYS = [
    "upstream_ip",
    "upstream_port",
    "sinkhole_ip",
    "proxy_ip",
    "ad_list_file",
    "sanction_list_file"
]


def is_valid_ipv4(ip_str):
    """Check if string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ValueError:
        return False


def load_config(file_path="config.txt"):
    # Ensure current working directory is the project root (one level up from src)
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(project_root)

    # Check if config file exists
    if not os.path.exists(file_path):
        print(f"Config error: File '{file_path}' not found.")
        sys.exit(1)

    # Default values
    config = {
        "upstream_timeout_sec": 2,
        "local_ttl": 60,
        "cache_enabled": True
    }

    # Read and parse key-value lines
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue

                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip()

                if key == "upstream_port":
                    config[key] = int(val)
                elif key == "upstream_timeout_sec":
                    config[key] = int(val)
                elif key == "local_ttl":
                    config[key] = int(val)
                elif key == "cache_enabled":
                    config[key] = (val.lower() == "true")
                elif key in ["upstream_ip", "sinkhole_ip", "proxy_ip"]:
                    if not is_valid_ipv4(val):
                        print(f"Config error: Invalid IPv4 address for '{key}': {val}")
                        sys.exit(1)
                    config[key] = val
                else:
                    config[key] = val

    except Exception as e:
        print(f"Config error: Failed to parse '{file_path}'. {e}")
        sys.exit(1)

    # Check for required keys
    for req in REQUIRED_KEYS:
        if req not in config:
            print(f"Config error: Missing required key '{req}'.")
            sys.exit(1)

    # Check if list files exist using relative paths
    for list_key in ["ad_list_file", "sanction_list_file"]:
        rel_path = config[list_key]
        if not os.path.exists(rel_path):
            print(f"Config error: List file '{rel_path}' not found.")
            sys.exit(1)

    return config


if __name__ == "__main__":
    # Test loading config
    cfg = load_config()
    print("Config loaded successfully.")