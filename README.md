# Smart DNS Proxy (Phase 1)
> **Project Status:** ✅ Completed (Mandatory M1–M9 & Bonus B1–B6 Implemented)

A console-based, configurable, and resilient **Smart DNS Proxy** implemented in Python for the **Computer Networks** course (University of Isfahan). The application processes domain queries interactively via CLI, enforces domain validation and normalization, applies ad-blocking (sinkholing), sanction-bypass routing, local TTL-aware caching, and communicates with an upstream DNS server over UDP sockets.

---

## Project Overview

The Smart DNS Proxy acts as an intermediary decision engine between console users and upstream DNS resolvers following a strict priority pipeline:

1. **Input Validation & Normalization:** Rejects malformed inputs (`INVALID_INPUT`), converts valid domains to lowercase, and strips trailing dots.
2. **Ad Blocking (Sinkholing):** Blocks domains and subdomains matching `ad_list.txt` by returning the configured `sinkhole_ip` (e.g., `0.0.0.0`) with highest priority (`AD_BLOCK`).
3. **Sanction Bypass (Proxying):** Redirects sanctioned domains listed in `sanction_list.txt` (if not in the ad list) to a dedicated `proxy_ip` (`SANCTION`).
4. **Local TTL-Aware Cache:** Serves valid, non-expired records directly from memory (`CACHE`) without querying the upstream server.
5. **Upstream Resolution:** Queries the upstream DNS server over UDP using text-based messages (or real binary DNS packets when `real_dns_enabled=true`) and caches valid `OK` responses.

---

## Project Architecture & Directory Layout

```text
Smart_DNS_Proxy_Repo/
├── src/
│   ├── config.py              # Configuration loader & defensive validator
│   ├── domain_loader.py       # Domain validator, normalizer, and list parser
│   ├── mock_upstream.py       # Text-based UDP Mock Upstream server (Port 5354)
│   └── dns_proxy.py           # Core interactive DNS Proxy & bonus features (B1–B6)
├── config.txt                 # Application runtime configurations
├── ad_list.txt                # List of domains to be sinkholed
├── sanction_list.txt          # List of domains mapped to the proxy IP
├── test_results.txt           # Recorded console outputs for acceptance tests T1–T13
├── .gitignore                 # Excludes virtual environments, IDE files, and log.txt
└── README.md                  # Comprehensive project documentation
```

---

## Configuration (`config.txt`)

The proxy reads `config.txt` at startup using `key=value` syntax (no spaces around `=`). Empty lines and comments starting with `#` are ignored.

### Configuration Parameters

| Key | Type | Requirement | Default | Description |
| :--- | :---: | :---: | :---: | :--- |
| `upstream_ip` | IPv4 | Required | -- | Upstream DNS server IPv4 address |
| `upstream_port` | Integer | Required | -- | Upstream DNS server UDP port (1–65535) |
| `sinkhole_ip` | IPv4 | Required | -- | Target IP returned for blocked ad domains |
| `proxy_ip` | IPv4 | Required | -- | Target IP returned for sanctioned domains |
| `ad_list_file` | String | Required | -- | Path to the ad domain blacklist file |
| `sanction_list_file` | String | Required | -- | Path to the sanction domain list file |
| `upstream_timeout_sec` | Float/Int | Optional | `2` | Upstream UDP socket timeout (seconds) |
| `local_ttl` | Integer | Optional | `60` | TTL (seconds) for `AD_BLOCK` and `SANCTION` responses |
| `cache_enabled` | Boolean | Optional | `true` | Enables or disables local caching (`true`/`false`) |
| `cache_max_entries` | Integer | Optional | Unlimited | *(Bonus B5)* Maximum cache capacity with FIFO eviction |
| `real_dns_enabled` | Boolean | Optional | `false` | *(Bonus B6)* Enables real binary DNS Type-A queries over UDP |

### Sample `config.txt`

```ini
upstream_ip=127.0.0.1
upstream_port=5354
upstream_timeout_sec=2
sinkhole_ip=0.0.0.0
proxy_ip=192.0.2.10
local_ttl=60
ad_list_file=ad_list.txt
sanction_list_file=sanction_list.txt
cache_enabled=true
```

---

## Domain List Format (`ad_list.txt` & `sanction_list.txt`)

- Each line contains a single domain name (e.g., `ads.example.com`).
- Leading/trailing whitespace is stripped; empty lines and `#` comments are ignored.
- **Label-Boundary Suffix Matching:** An entry `example.com` matches both `example.com` and subdomains like `sub.example.com`, but does **not** match `notexample.com` or `example.com.org`. Wildcards (`*`) are not supported.
- **Priority Rule:** If a domain appears in both lists, `ad_list.txt` always takes precedence over `sanction_list.txt`.
- Malformed lines in list files trigger a non-fatal warning (`Warning: bad line in <file>: <line>`) without stopping execution.

---

## Getting Started & How to Run

### Prerequisites
- **Python 3.8** or higher (uses Python Standard Library only: `socket`, `struct`, `os`, `sys`, `re`, `time`, `datetime`, `collections`).
- No external `pip` dependencies required.

### Step-by-Step Execution
Open **two separate terminals** in the project root directory (`Smart_DNS_Proxy_Repo`):

1. **Terminal 1 — Start the Mock Upstream Server first:**
   ```bash
   python src/mock_upstream.py
   ```
   *Expected output:* `Mock Upstream listening on 127.0.0.1:5354...`

2. **Terminal 2 — Start the DNS Proxy:**
   ```bash
   python src/dns_proxy.py
   ```
   *Expected output:*
   ```text
   DNS Proxy ready.
   Enter domain (or exit):
   ```

3. **Querying & Exiting:**
   - Type any domain (e.g., `ads.example.com`, `service.example.org`, `normal.example.net`) to receive the standardized 5-line response block (`Domain`, `Source`, `Status`, `IP`, `TTL`).
   - Type `exit` to terminate the program cleanly (`Bye.`).

---

## Implemented Bonus Features (B1–B6)

- **B1 (`stats` command):** Prints total processed queries broken down by `AD_BLOCK`, `SANCTION`, `CACHE`, `UPSTREAM`, and `ERRORS`.
- **B2 (`reload` command):** Reloads `ad_list.txt` and `sanction_list.txt` from disk at runtime without restarting (`Lists reloaded.`).
- **B3 (`cache` command):** Evicts expired records and prints active cached domains with their IP and remaining TTL (or `Cache is empty.`).
- **B4 (`log.txt` audit logging):** Appends a structured pipe-delimited (`|`) record (`Timestamp | Domain | Source | Status | IP | TTL`) to `log.txt` for every domain query.
- **B5 (`cache_max_entries` FIFO eviction):** Enforces optional cache capacity limits using `OrderedDict` to evict the oldest inserted entry when full.
- **B6 (`real_dns_enabled` real DNS queries):** Constructs raw binary DNS Type-A packets over UDP to public resolvers (e.g., `8.8.8.8:53`), extracting real IPv4 addresses, real TTLs, and `NXDOMAIN` responses.

---

## Implementation Limitations

- **Single-Threaded Console Architecture:** Handles one interactive console query at a time without multithreading or GUI.
- **IPv4 Type-A Records Only:** IPv6 (`AAAA`), `CNAME`, `MX`, and `NS` records are out of scope.
- **No Traffic Tunneling:** For sanctioned domains, the proxy returns the configured `proxy_ip` without establishing TCP/HTTPS relay tunnels.
