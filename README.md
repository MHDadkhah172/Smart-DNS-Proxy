
# Smart DNS Proxy Server
> **Project Status:** 🚧 Under Development (Phase 1)

A lightweight, configurable, and robust DNS Proxy Server implemented in Python. The proxy intercepts standard DNS queries (over UDP), validates and filters domains, and dynamically routes responses based on predefined domain lists (Ad Blocking / Sinkholing, Sanction Bypass Routing, and Upstream Resolution).

---

## Project Overview

The Smart DNS Proxy acts as an intermediary layer between local DNS clients and upstream DNS resolvers.

Its primary responsibilities include:

1. **Ad Blocking (Sinkholing):** Blocks domains listed in `ad_list.txt` by returning a sinkhole IP (e.g., `0.0.0.0`).
2. **Sanction Bypass (Proxying):** Intercepts sanctioned domains listed in `sanction_list.txt` and rewrites their resolution to a dedicated proxy/relay IP.
3. **Upstream Forwarding:** Transparently forwards non-listed domain queries to a designated upstream DNS resolver and relays the response back to the client.
4. **Resilience & Robustness:** Prevents runtime crashes through strict input validation and defensive error handling.

---

## Project Architecture & Directory Layout

```text
Smart_DNS_Proxy_Repo/
├── src/
│   ├── config.py              # Configuration loader & validation engine
│   ├── domain_loader.py       # Domain list parser & normalizer (In Progress)
│   ├── dns_proxy.py           # Core UDP DNS Proxy server (Upcoming)
│   └── mock_upstream.py       # Local mock DNS server for offline testing (Upcoming)
├── config.txt                 # Application runtime configurations
├── ad_list.txt                # List of domains to be sinkholed
├── sanction_list.txt          # List of domains mapped to the proxy IP
├── .gitignore                 # Excluded environments and IDE artifacts
└── README.md                  # Comprehensive project documentation
```

---

## Configuration (`config.txt`)

The proxy is configured via a standard key-value file (`config.txt`).

Lines starting with `#` and empty lines are ignored.

### Configuration Parameters

| Key | Type | Requirement | Default | Description |
| :--- | :---: | :---: | :---: | :--- |
| `upstream_ip` | IPv4 | Required | -- | Upstream DNS server IP address |
| `upstream_port` | Integer | Required | -- | Upstream DNS server UDP port (1–65535) |
| `sinkhole_ip` | IPv4 | Required | -- | Target IP returned for blocked ad domains |
| `proxy_ip` | IPv4 | Required | -- | Target IP returned for sanctioned domains |
| `ad_list_file` | String | Required | -- | Path to the ad domain blacklist file |
| `sanction_list_file` | String | Required | -- | Path to the sanction domain list file |
| `upstream_timeout_sec` | Integer | Optional | 2 | Upstream socket response timeout (seconds) |
| `local_ttl` | Integer | Optional | 60 | TTL value for locally generated responses |
| `cache_enabled` | Boolean | Optional | true | Enables or disables the internal DNS cache |

### Sample `config.txt`

```ini
upstream_ip = 127.0.0.1
upstream_port = 5354
sinkhole_ip = 0.0.0.0
proxy_ip = 192.0.2.10
ad_list_file = ad_list.txt
sanction_list_file = sanction_list.txt
upstream_timeout_sec = 2
local_ttl = 60
cache_enabled = true
```

---

## Modules & Implementation Status

### 1. Configuration Engine (`src/config.py`)

- **Working Directory Synchronization:**
  Automatically anchors execution scope to the project root, ensuring seamless resolution of relative paths regardless of execution origin.

- **Defensive Type & Range Checking:**
  - Converts port and timeout values to integers.
  - Enforces valid UDP port boundaries (1 to 65535).
  - Validates boolean values (`true` / `false`).
  - Employs Python's standard `ipaddress` library to enforce strict IPv4 structure.

- **File System Integrity:**
  Ensures `config.txt`, `ad_list.txt`, and `sanction_list.txt` exist as legitimate files before runtime bootstrap.

### 2. Next Milestones (Phase 1 Roadmap)

- [x] Repository setup, Git exclusions, and project directory structure.
- [x] Robust configuration loader with defensive input validation.
- [ ] Domain loader and string normalization (RFC-compliant lowercase parsing and trailing dot sanitization).
- [ ] Lightweight UDP-based `mock_upstream.py` server for offline test environments.
- [ ] Core DNS request interceptor and socket listener.

---

## Getting Started

### Prerequisites

- Python 3.8 or higher.
- Pure Python standard libraries used (`socket`, `ipaddress`, `os`, `sys`).
- No external pip packages required.

### Verification & Testing

To verify the configuration parser independently, run the following command from the project root:

```bash
python src/config.py
```

### Expected Output

On successful validation:

```text
Config loaded successfully.
```

---

## Development Progress

**Current Phase:** Phase 1 – Core Infrastructure

**Completed:**
- Project repository initialization.
- Directory structure setup.
- Configuration file design.
- Configuration validation engine.

**In Progress:**
- Domain list loading and normalization.

**Upcoming:**
- Mock upstream DNS server.
- UDP DNS proxy implementation.
- DNS query interception and response routing.
- DNS caching and error-handling improvements.

---

## License

License information has not yet been specified.
