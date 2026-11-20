<div align="right">

**English** | [فارسی](README.fa.md)

</div>

# 🌐 Smart DNS Proxy & Adaptive DNS Engine

**An intelligent DNS Proxy featuring ad-blocking, sanction routing, adaptive TTL caching, and an automated upstream server selection engine.**

---

## 📖 Project Overview

This project is a modular, zero-dependency Python **DNS Proxy** system that receives domain name queries, validates and normalizes them, applies prioritized security and networking policies, and returns standardized responses.

The repository is structured into two standalone versions so that both the core baseline implementation and the advanced smart engine architecture can be executed and evaluated independently:

```text
Smart_DNS_Proxy_Repo/
├── basic_proxy/                 # Core version (Text UDP protocol, Real DNS queries, Cache & Filtering)
│   ├── src/                     # dns_proxy.py, upstream_mock.py, config.py, domain_loader.py
│   ├── config.txt               # Standard configuration file
│   ├── ad_list.txt              # Ad-blocking domain list
│   └── sanction_list.txt        # Sanction routing domain list
│
├── smart_dns_engine/            # Intelligent version (Powered by dns_engine & multi-user benchmark)
│   ├── dns_engine/              # SQLite DB, Benchmarking, Scoring, Adaptive Selector & Health Monitor
│   ├── smart_modules/           # Remote blocklist synchronization & upstream router
│   ├── src/                     # Proxy core integrated with SmartEngineRouter
│   ├── simulate_users.py        # Concurrent 10-user profile simulator (250 queries)
│   └── config.txt               # Upstream server pool & remote blocklist settings
│
├── README.md                    # English Documentation
└── README.fa.md                 # Persian Documentation (مستندات فارسی)
```

---

## ⚙️ Architecture & Decision Pipeline

Every incoming query follows a strict, deterministic decision pipeline where the outcome of an earlier stage is never overridden by subsequent stages:

```text
[User Input]
      │
      ├──► exit ──────────────────────────────► Clean Exit (Bye.)
      ├──► Control Commands ──────────────────► stats / cache / reload / engine
      ├──► Invalid Input (spaces, bad chars) ─► NONE | INVALID_INPUT
      │
      ▼  (Normalize: lowercase + strip trailing dot)
      │
      ├──► Match Ad List ─────────────────────► AD_BLOCK  | sinkhole_ip | local_ttl
      ├──► Match Sanction List ───────────────► SANCTION  | proxy_ip    | local_ttl
      ├──► Valid Entry in Cache ──────────────► CACHE     | cached_ip   | remaining_ttl
      │
      ▼  (Query Upstream over UDP)
      │
      ├──► Reply: OK <ip> <ttl> ──────────────► Save to Cache (TTL > 0) ──► UPSTREAM | OK
      ├──► Reply: NOT_FOUND / NXDOMAIN ───────► Do Not Cache ──────────────► UPSTREAM | NOT_FOUND
      └──► Timeout / Network Error ───────────► No Crash ──────────────────► UPSTREAM | SERVER_ERROR
```

---

## ✨ Core Features (`basic_proxy`)

* **Domain Validation & Normalization:** Trims whitespace, converts to lowercase, strips trailing dots, and performs label-boundary suffix matching (`name == entry` or `name.endswith("." + entry)`) to automatically cover subdomains.
* **Prioritized Multi-Layer Filtering:**
  1. **Ad-Blocking (`AD_BLOCK`):** Redirects matched ad domains to `sinkhole_ip` (e.g., `0.0.0.0`).
  2. **Sanction Routing (`SANCTION`):** Routes matched domains to `proxy_ip`.
* **TTL-Aware Local Cache with Dynamic Eviction:** Caches valid upstream `OK` responses (`TTL > 0`), tracks exact remaining TTL seconds, supports configurable capacity (`cache_max_entries`) with `FIFO` eviction, and can be toggled on/off via configuration.
* **Dual UDP Protocol Support:**
  * Communicates with a local mock upstream server via a lightweight text protocol (`QUERY <domain>`).
  * Crafts and parses raw binary DNS packets (**RFC 1035**) to resolve real `A` records and authentic TTLs from public DNS resolvers (e.g., `1.1.1.1`, `8.8.8.8`).
* **Fault Tolerance:** Gracefully handles network timeouts, malformed upstream responses, and invalid console inputs without crashing.
* **Interactive Console Commands & Structured Logging:** Supports `stats`, `cache`, `reload`, and appends structured audit logs to `log.txt`.

---

## 🧠 Smart Engine Features (`smart_dns_engine`)

Building on top of the baseline core, the following modules optimize real-world network performance and reliability:

| Smart Feature | Technical Description |
| :--- | :--- |
| **SQLite Telemetry & Benchmarking (`dns_engine`)** | Persists upstream response time history in SQLite and computes `Avg Latency`, `P95 Tail Latency`, `Jitter`, and `Success Rate`. |
| **Adaptive Scoring & Selection (`AdaptiveSelector`)** | Calculates a composite score (0–100) for each resolver and dynamically assigns `PRIMARY` and `BACKUP` roles without manual intervention. |
| **Instant Failover & Background Probing (`HealthMonitor`)** | Automatically fails over to the `BACKUP` resolver upon timeout or error, while a background daemon periodically probes resolver health. |
| **Automated Remote Blocklist Sync** | Fetches up-to-date ad-blocking lists from remote URLs with local caching and automatic 24-hour background refresh cycles. |
| **10-User Concurrent Load Simulator (`simulate_users.py`)** | Simulates 250 concurrent queries across 10 distinct user profiles (Developer, Gamer, Streamer, Ad-Heavy, etc.) using non-blocking fine-grained locking. |

---

## 📊 Benchmark Results & Performance Comparison

The following metrics were captured under identical test conditions (**250 concurrent queries across 10 user profiles**):

| Metric | Baseline Router (`UpstreamRouter`) | Smart Engine (`dns_engine`) | Improvement & Technical Analysis |
| :--- | :--- | :--- | :--- |
| **Throughput** | `148.4 req/sec` | **`156.3 req/sec`** | **+5.3% higher** request processing rate |
| **Total Execution Time** | `1.68 sec` | **`1.60 sec`** | **0.08 sec faster** despite live SQLite telemetry logging |
| **Mean Upstream Latency (`Avg`)** | `86.568 ms` | **`79.687 ms`** | **~8% reduction** in external resolution latency |
| **Tail Latency (`UPSTREAM P95`)** | `192.281 ms` | **`165.630 ms`** | **~14% reduction** in worst-case latency spikes |
| **Cache Hit Latency (`CACHE Avg`)** | `0.016 ms` | **`0.014 ms`** | Sub-15 microsecond in-memory response time |
| **Errors** | `0` | **`0`** | 100% stability under concurrent load |

---

## 🚀 Installation & Usage

### 1. Prerequisites

* **Python 3.10+** (Uses only the Python Standard Library; no `pip` packages required).

### 2. Configuration (`config.txt`)

All runtime parameters are loaded from `config.txt`:

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
cache_max_entries=100
real_dns_enabled=false
```

### 3. Running the Baseline Version (`basic_proxy`)

Start the mock upstream server in the first terminal:

```bash
cd basic_proxy
python src/upstream_mock.py
```

Start the DNS proxy in a second terminal:

```bash
cd basic_proxy
python src/dns_proxy.py
```

### 4. Running the Smart Engine & 10-User Simulator (`smart_dns_engine`)

To run the smart proxy against real public DNS servers (`real_dns_enabled=true`) and inspect live resolver scores via `engine`:

```bash
cd smart_dns_engine
python src/dns_proxy.py
```

To execute the 10-user concurrent benchmark and view the statistical report:

```bash
cd smart_dns_engine
python simulate_users.py
```

---

## 🎮 Interactive Console Commands

| Command | Description |
| :--- | :--- |
| `<domain>` | Resolves the domain name and prints the standardized 5-line output block |
| `stats` | Displays real-time decision counts (`AD_BLOCK`, `SANCTION`, `CACHE`, `UPSTREAM`, `ERRORS`) |
| `cache` | Lists valid cached entries along with their remaining `TTL` |
| `reload` | Hot-reloads the ad and sanction domain lists from disk without restarting |
| `engine` | Displays live resolver scores, `PRIMARY`/`BACKUP` roles, and latency telemetry |
| `exit` | Safely shuts down background threads and exits the application |