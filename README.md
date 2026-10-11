# 🐕 ShibaCuddles — Advanced Network Scanner & Security Testing Suite

[![CI](https://github.com/TheRealJesusTheHacker/ShibaCuddles/actions/workflows/ci.yml/badge.svg)](https://github.com/TheRealJesusTheHacker/ShibaCuddles/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/TheRealJesusTheHacker/ShibaCuddles)](https://github.com/TheRealJesusTheHacker/ShibaCuddles/releases)
[![License](https://img.shields.io/github/license/TheRealJesusTheHacker/ShibaCuddles)](https://github.com/TheRealJesusTheHacker/ShibaCuddles/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)

> **Because every network needs a cuddly scanner.**

---

> ## ⚠️ AUTHORIZED USE ONLY
>
> **ShibaCuddles is a security-testing tool. Use it only on networks you own
> or have explicit, written permission to test.** Unauthorized scanning,
> wireless interference, or access to computer systems is illegal in most
> jurisdictions. The tool enforces this where it can:
>
> - **Non-private targets trigger a hard stop.** Scanning anything outside
>   RFC1918 private address space requires typing `YES` at a confirmation
>   prompt (CLI) or answering a warning dialog (GUI), unless you pass `--yes`.
> - **Wireless attack functions are scope-gated.** `deauthenticate_device`,
>   `deauthenticate_all_devices`, `create_rogue_ap`, and `jam_channel` check
>   every target against `authorized_targets.json` *before transmitting
>   anything*. A target that isn't listed is refused — there is no override
>   flag, and a malformed scope file fails closed.
> - **Destructive packet-level behavior is rate-limited by design:** thread
>   caps, configurable timeouts, and cooperative stop are built into the
>   scan engine.
>
> These gates are a safety net, not a permission slip. **You** are responsible
> for having authorization before you scan.

---

## What is ShibaCuddles?

ShibaCuddles is a **multi-threaded network scanner and security-testing
suite written in Python**. Point it at a network range and it walks through
five phases — target enumeration, device discovery, TCP port scanning,
service fingerprinting, and OS detection — then hands you the results as
structured data (JSON/CSV/XML/TXT), a live GUI dashboard, or both.

It ships with two front ends over one engine:

- **`main.py`** — a full-featured CLI for scripted scans, CI pipelines, and
  headless boxes.
- **`gui_launcher.py`** — a dark-themed PyQt6 dashboard with a live results
  table, statistics cards, a color-coded activity log, progress bar, and
  one-click export.

Around the core pipeline sits a library of security-testing modules, all
importable from the `src` package:

- **Device discovery** (`src/device.py`) — ICMP ping sweep, ARP scanning
  (via scapy), hostname resolution, and MAC address lookup.
- **Port scanning** (`src/port_scanner.py`) — threaded TCP connect scanning
  with banner grabbing, plus a UDP prober.
- **Service & OS detection** (`src/service_detector.py`) — banner-based
  service fingerprinting against 18 known service signatures, version
  extraction for SSH/HTTP/Apache/Nginx, and TTL-based OS guessing.
- **WiFi security testing** (`src/deauth.py`, `src/scope.py`) — monitor-mode
  control, nearby-network survey via `airodump-ng`, targeted and broadcast
  deauthentication, rogue-AP creation for evil-twin testing, and channel
  jamming — every attack function hard-gated behind an
  `authorized_targets.json` allowlist.
- **Results handling** (`src/results_handler.py`) — multi-format export
  with format auto-detection and a no-clobber default.

The vulnerability database bundled with the demo `VulnerabilityScanner`
class is **sample data only** (four entries) — it is not a feed, and a
clean result from it means nothing. It is clearly labeled as such in the
code; treat it as a placeholder for wiring in a real feed later.

## Who is it for?

- **Security professionals & penetration testers** running authorized
  assessments — the CLI drops straight into scripts and reports.
- **Network / systems administrators** auditing their own infrastructure —
  discovery, open-port inventory, and service versions in one pass.
- **Students & educators** learning how scanning, fingerprinting, and
  wireless testing actually work — the codebase is small, readable, and
  heavily commented.
- **Python developers** who want scanner primitives (`PortScanner`,
  `ServiceDetector`, `DeviceDiscovery`, …) as importable building blocks.

## How the pieces fit together

```
                    ┌──────────────┐      ┌──────────────────┐
                    │   main.py    │      │  gui_launcher.py │
                    │     (CLI)    │      │  (PyQt6 GUI)     │
                    └──────┬───────┘      └────────┬─────────┘
                           │                     │ QThread
                           ▼                     ▼
                    ┌────────────────────────────────┐
                    │  src/scanner.py                │
                    │  NetworkScanner (orchestrator) │
                    │                                │
                    │  1. enumerate targets (CIDR)   │
                    │  2. discovery ──► device.py     │
                    │  3. port scan ──► port_scanner │
                    │  4. services  ──► service_     │
                    │                    detector   │
                    │  5. OS detect ──► service_     │
                    │                    detector   │
                    └───────────────┬────────────────┘
                                    │ ScanResult dataclasses
                                    ▼
                    ┌────────────────────────────────┐
                    │  src/results_handler.py        │
                    │  JSON / CSV / XML / TXT export │
                    └────────────────────────────────┘

  WiFi testing (Python API only, scope-gated):
                    ┌────────────────────────────────┐
                    │  src/deauth.py  +  src/scope.py│
                    │  WiFiDeauthenticator /         │
                    │  NetworkInterruptor            │
                    │  gated by authorized_          │
                    │  targets.json allowlist        │
                    └────────────────────────────────┘
```

The CLI and GUI both drive `NetworkScanner.scan()`: discovery first (ICMP
ping sweep, skippable), then TCP port scanning of the alive hosts, then —
only if you ask — service detection and OS fingerprinting in parallel.
Progress callbacks and a cooperative stop event keep long scans observable
and interruptible. The WiFi modules are **not** exposed in the CLI or GUI;
they are Python-API-only and every attack function refuses to run unless
its target is allowlisted.

## ✨ Features

### Device discovery (`src/device.py`)

- **ICMP ping sweep** — parallel liveness checks using the system `ping`
  (platform-aware flags for Windows vs. Linux/macOS), with sub-second
  timeouts honored instead of truncated.
- **ARP scanning** — `ARPScanner` crafts ARP requests with scapy for fast
  local-network discovery; if scapy isn't installed it logs a warning and
  falls back to the ping sweep rather than crashing.
- **Hostname resolution** — reverse-DNS lookup per alive host.
- **MAC address lookup** — parses `arp -a` / `arp -n` output with a regex
  that handles both `00:11:22:33:44:55` and `00-11-22-33-44-55` formats,
  normalized to lowercase colon-separated.
- Discovery futures are submitted in chunks (1024 at a time) so a large
  range doesn't queue tens of thousands of ping subprocesses up front.

### Port scanning (`src/port_scanner.py`)

- **TCP connect scanning** (`connect_ex`) across 1–65535, with flexible
  port specs: `22,80,443`, `1-1024`, or mixed like `22,80,8000-8100`.
- **Thread pool per host** (1–100 workers), with per-port timeouts,
  optional rate limiting (`--rate-limit`), and cooperative abort via a
  shared stop event.
- **Cached address-family resolution** — `getaddrinfo` results are cached
  per (host, socket type), so thousands of port probes don't each pay for
  a fresh DNS lookup, and IPv6 targets get `AF_INET6` sockets instead of
  silently reporting every port closed.
- **Banner grabbing** helper for follow-up service identification.
- **`UDPScanner`** (Python API) — parallel UDP probing: sends an empty
  datagram and reports ports that answer. *Library-only; not wired into
  the CLI/GUI scan pipeline.*

### Service detection & OS fingerprinting (`src/service_detector.py`)

- **Banner-based fingerprinting** against 18 known service signatures
  (SSH, Telnet, SMTP, DNS, HTTP, POP3, IMAP, LDAP, HTTPS, SMB, MySQL, RDP,
  PostgreSQL, VNC, Redis, HTTP-Alt, HTTPS-Alt, MongoDB), with a port-based
  fallback when no banner is returned.
- **Version extraction** via regex for OpenSSH, HTTP `Server:` headers,
  Apache, and Nginx.
- **Polite HTTP probing** — a `HEAD` request is only sent to plaintext
  HTTP ports (80/8080); it is never sent to TLS ports (443/8443).
- **Parallelized** — the standalone `detect()` fans out across ports (up to
  20 workers); in the scan pipeline, hosts are parallelized instead and each
  host's ports are probed serially, so thread counts can't multiply
  (threads²).
- **TTL-based OS guessing** — ICMP echo via scapy, mapped to
  Windows (128), Linux/Unix (64), Cisco/network gear (255), and legacy
  Windows (32), with a confidence score. Requires scapy and raw-socket
  privileges; degrades gracefully without them.
- **`VulnerabilityScanner`** (Python API) — matches detected service
  versions against a bundled table. **The bundled table is demo data
  (four entries); it is not a vulnerability feed.** *Library-only; not
  used by the CLI/GUI.*

### GUI dashboard (`gui/`)

- Dark-themed dashboard with a brand header and version badge.
- **Target group** — network input (`192.168.1.0/24`) and port spec
  (defaults to `1-1024`).
- **Performance group** — thread count (default 10) and timeout spinners.
- **Scan Options group** — checkboxes for ping sweep (on by default),
  service detection, OS fingerprinting, and aggressive mode.
- **Three tabs** — *Results* (live table: IP Address, Status, Open Ports,
  Services, OS — with pill-style alive/down indicators, alternating rows,
  and batch insertion so large scans stay responsive), *Statistics* (cards:
  hosts scanned, hosts alive, open ports, avg ports/host), and *Activity
  Log* (color-coded, console-style).
- **Live progress bar**, a **Stop** button that interrupts mid-host via
  the cooperative stop event, and **export** to JSON/CSV/XML/TXT through
  a file dialog.
- **Non-private target warning dialog** mirrors the CLI's RFC1918
  confirmation gate.
- Scans run in a `QThread` (`ScannerThread`) so the UI never freezes.

### WiFi security testing (`src/deauth.py` + `src/scope.py`) — Python API only

Requires the `aircrack-ng` suite and Linux. **Every attack function is
gated by `authorized_targets.json` — see the Authorized Use section.**

- **Monitor mode** — `enable_monitor_mode` / `disable_monitor_mode`
  (`airmon-ng start/stop`, with interfering-process cleanup and
  networking restart on teardown).
- **Nearby-network survey** — `scan_nearby_networks` runs `airodump-ng`
  into a private temp directory (never a predictable `/tmp` path),
  parses the CSV's access-point section (BSSID, channel, privacy, power,
  SSID — comma-containing SSIDs handled), stops at the station section,
  and always cleans up afterward.
- **Targeted deauthentication** — `deauthenticate_device` sends 802.11
  deauth frames to one client (default 64 frames) via `aireplay-ng`.
- **Broadcast deauthentication** — `deauthenticate_all_devices` runs
  continuous deauth (`--deauth 0`) for a bounded duration.
- **Rogue AP** — `create_rogue_ap` stands up a WPA2 test AP via `hostapd`
  with a **fresh random passphrase generated every run** (printed once,
  never hardcoded); the config is written to a private temp file and
  always deleted.
- **Channel jamming** — `NetworkInterruptor.jam_channel` runs `mdk3`
  deauth-flood mode; it requires a configured scope (indiscriminate
  action) and the jammer process is always terminated afterward —
  never orphaned.
- **Traffic capture** — `analyze_traffic_patterns` captures with
  `tcpdump` to a private temp pcap (never a fixed path, avoiding the
  symlink-planting risk when running under sudo) and deletes it after.
  **Packet-level analysis is not implemented yet** — it returns capture
  metadata with empty protocol breakdowns. Treat it as a capture stub.

### Authorization scope gate (`src/scope.py`)

- Attack functions must call `require_authorized()` **before transmitting
  anything**; unlisted targets raise `AuthorizationError` (a
  `PermissionError`).
- The scope file is searched in a fixed order —
  `~/.config/shibacuddles/` **first** (so a planted file in a shared
  working directory can't silently widen the gate), then the working
  directory, then `src/`, then the repo root.
- SSID matching is case-sensitive; BSSIDs are normalized (lowercase,
  dashes→colons). A malformed scope file **fails closed**.
- Indiscriminate actions (channel jamming) use
  `require_scope_configured()`: they refuse to run unless the operator
  has deliberately set up a scope file at all.
- Copy `authorized_targets.example.json` → `authorized_targets.json`
  (gitignored — your scope is never committed) and list only networks you
  own or have written permission to test.

### Results & export (`src/results_handler.py`)

- **JSON, CSV, XML, and plain-text** export; the format is auto-detected
  from the output file's extension.
- **No-clobber default** — saving refuses to overwrite an existing file
  unless you pass `--force` (CLI) / `force=True` (API).
- `generate_report()` builds a human-readable summary (totals + per-host
  open ports) for pasting into reports.

### Built-in safety guardrails

- **RFC1918 confirmation gate** — non-private targets require typing
  `YES` (CLI) or a dialog confirmation (GUI); `--yes` skips it for
  scripted runs on networks you own.
- **Target-range cap** — ranges over 65,536 addresses are refused up
  front (a `0.0.0.0/0`-style mistake can't OOM the box).
- **Thread caps** (64 for the orchestrator, 100 for port scanning),
  **timeout floors** (0.2 s scan / 0.1 s socket), and **cooperative stop**
  throughout, so scans stay interruptible.
- **Output no-clobber** and **scope fail-closed** as described above.

## ⬇️ Downloads

No Python needed — grab the latest standalone build from the
[releases page](https://github.com/TheRealJesusTheHacker/ShibaCuddles/releases):

| Platform | File |
|---|---|
| Windows | `ShibaCuddles.exe` |
| Linux | `ShibaCuddles` |

Every release ships `SHA256SUMS-windows.txt` / `SHA256SUMS-linux.txt`
**and** signed build-provenance attestations. Verify before you run:

```bash
sha256sum -c SHA256SUMS-windows.txt   # Windows (Git Bash / WSL)
sha256sum -c SHA256SUMS-linux.txt     # Linux
```

> 📸 *Screenshot of the GUI dashboard coming soon.*

## 📦 Installation

Requires **Python 3.8+**.

```bash
git clone https://github.com/TheRealJesusTheHacker/ShibaCuddles.git
cd ShibaCuddles
pip install -r requirements.txt
```

Or install the package itself (provides `shiba-cuddles` and
`shiba-cuddles-gui` console commands):

```bash
pip install .
```

For WiFi features, install the aircrack-ng suite separately:

```bash
sudo apt-get install aircrack-ng   # Ubuntu/Debian
sudo dnf install aircrack-ng       # Fedora
brew install aircrack-ng           # macOS
```

## 🖥️ CLI usage

```bash
# Basic scan (ports 1-1024; ping sweep on by default)
python main.py 192.168.1.0/24

# Specific ports / port range
python main.py 192.168.1.0/24 --ports 22,80,443
python main.py 192.168.1.0/24 --ports 1-5000

# Aggressive scan: service detection + OS fingerprinting
python main.py 192.168.1.0/24 --aggressive

# Service and OS detection individually
python main.py 192.168.1.0/24 --service-detection --os-detection

# Skip the ping sweep (scan every host in the range)
python main.py 192.168.1.0/24 --no-ping

# Tune performance
python main.py 192.168.1.0/24 --threads 20 --timeout 10 --rate-limit 0.1

# Skip broadcast/network addresses, custom batch size
python main.py 192.168.1.0/24 --skip-broadcast --batch-size 100

# Non-private target: confirm non-interactively (only on networks you own)
python main.py 203.0.113.0/24 --yes

# Verbose / quiet
python main.py 192.168.1.0/24 -v
python main.py 192.168.1.0/24 -vv
python main.py 192.168.1.0/24 -q
```

### Exporting results

```bash
python main.py 192.168.1.0/24 --output results.json            # JSON (default)
python main.py 192.168.1.0/24 --output results.csv --format csv # CSV
python main.py 192.168.1.0/24 --output results.xml --format xml # XML
python main.py 192.168.1.0/24 --output results.txt --format txt # plain text

# Overwrite an existing output file (refused by default)
python main.py 192.168.1.0/24 --output results.json --force
```

### Example scans

```bash
# Small office network
python main.py 10.0.0.0/24 --threads 15 --ports 22,80,443,3306,5432

# Home network security audit
python main.py 192.168.0.0/24 --aggressive --service-detection --os-detection

# Enterprise network assessment
python main.py 172.16.0.0/16 --threads 32 --ports 1-10000 --aggressive -vv
```

### Sample JSON output

```json
[
  {
    "ip": "192.168.1.1",
    "alive": true,
    "open_ports": [22, 80, 443],
    "services": {
      "22": {"name": "SSH", "version": "OpenSSH 8.2"},
      "80": {"name": "HTTP", "version": "Apache 2.4.29"}
    },
    "os_info": {"name": "Linux/Unix", "ttl": 64, "confidence": 95},
    "scan_time": 2.34
  }
]
```

## 🖥️ GUI usage

```bash
python gui_launcher.py
```

1. Enter the target network (e.g. `192.168.1.0/24`) and the port spec.
2. Tune threads/timeout, tick the scan options you want (ping sweep,
   service detection, OS fingerprinting, aggressive).
3. Hit **Start Scan** — results stream into the table live, the progress
   bar tracks completion, and the statistics cards update at the end.
4. **Stop** interrupts the scan at the next checkpoint; **Export** saves
   the results as JSON, CSV, XML, or TXT.
5. Watch the Activity Log tab for per-phase messages and warnings.

If PyQt6 isn't installed you'll get a friendly pointer instead of a
traceback:

```bash
pip install PyQt6 PyQt6-Charts
```

## 🐍 Python API

```python
from src.scanner import NetworkScanner

# Orchestrated scan with a progress callback and cooperative stop
scanner = NetworkScanner(
    network="192.168.1.0/24",
    threads=20,
    timeout=5.0,
    progress_callback=lambda done, total: print(f"{done}/{total}"),
)
scanner.enable_service_detection = True   # or --service-detection in the CLI
scanner.enable_os_detection = True        # or --os-detection in the CLI

results = scanner.scan("22,80,443")       # port spec, same syntax as --ports
for r in results:
    print(r.ip, r.alive, r.open_ports, r.services, r.os_info)

scanner.save_results(results, "out.json", format="json", force=True)
```

Individual building blocks are importable too:

```python
from src.device import DeviceDiscovery, ARPScanner
from src.port_scanner import PortScanner, UDPScanner
from src.service_detector import ServiceDetector
from src.results_handler import ResultsHandler

discovery = DeviceDiscovery(timeout=2.0)
print(discovery.is_alive("192.168.1.1"))
print(discovery.resolve_hostname("192.168.1.1"))
print(discovery.get_mac_address("192.168.1.1"))

ports = PortScanner(threads=20, timeout=3.0)
print(ports.scan("192.168.1.1", "22,80,443"))

detector = ServiceDetector(timeout=5.0)
print(detector.detect("192.168.1.1", [22, 80]))
print(detector.detect_os("192.168.1.1"))
```

### WiFi testing (authorized use only — Python API)

```python
from src.deauth import WiFiDeauthenticator, DeauthTarget

deauth = WiFiDeauthenticator()
deauth.enable_monitor_mode("wlan0")

# Survey nearby networks (returns bssid/channel/privacy/power/ssid dicts)
networks = deauth.scan_nearby_networks("wlan0mon", duration=10)

# Every attack below raises AuthorizationError unless the target is in
# authorized_targets.json — no override exists.
target = DeauthTarget(
    mac_address="AA:BB:CC:DD:EE:FF",
    gateway_mac="11:22:33:44:55:66",
    ssid="TestNetwork",          # must be listed in authorized_targets.json
    channel=6,
    interface="wlan0mon",
)
deauth.deauthenticate_device(target)
deauth.disable_monitor_mode("wlan0mon")
```

Set up the scope file first:

```bash
cp authorized_targets.example.json authorized_targets.json
# edit authorized_targets.json — list ONLY networks you own or have
# WRITTEN permission to test
```

## 🗂️ Project layout

- `main.py` — CLI entry point (argparse; RFC1918 confirmation gate)
- `gui_launcher.py` — GUI entry point (friendly error if PyQt6 is missing)
- `src/` — scanner engine and library
  - `scanner.py` — `NetworkScanner` orchestration, `ScanResult` dataclass,
    statistics, progress callbacks, cooperative stop
  - `device.py` — `DeviceDiscovery` (ping sweep, hostname/MAC resolution),
    `ARPScanner` (scapy, optional), `Device` dataclass
  - `port_scanner.py` — `PortScanner` (threaded TCP), `UDPScanner`
    (library-only), banner grabbing
  - `service_detector.py` — `ServiceDetector` (banner fingerprinting,
    version regexes, TTL OS detection), `VulnerabilityScanner`
    (**demo data only**)
  - `deauth.py` — `WiFiDeauthenticator`, `NetworkInterruptor`
    (scope-gated, authorized use only)
  - `scope.py` — `authorized_targets.json` allowlist enforcement
    (fail-closed, no override)
  - `results_handler.py` — JSON/CSV/XML/TXT export, no-clobber default
  - `utils.py` — logging setup, network/port-spec validation, cached
    address-family resolution, helpers
- `gui/` — PyQt6 dashboard (`main_window.py`: header, config panel,
  results/statistics/log tabs, export, stop)
- `tests/` — unit test suite (64 tests)
- `authorized_targets.example.json` — scope-file template (copy to
  `authorized_targets.json`; gitignored)

## 🧪 Development

```bash
pip install -r requirements-dev.txt

# Run the test suite (64 tests)
python -m pytest tests/ -v

# Format & lint (enforced in CI)
python -m black src gui tests main.py gui_launcher.py
python -m ruff check src gui tests main.py gui_launcher.py
```

CI runs on every push/PR to `main`: byte-compile checks on Linux and
Windows, the full pytest suite, `black --check`, and `ruff check` — all
third-party GitHub Actions are pinned to commit SHAs.

## 📦 Packaging & releases

- `setup.py` — standard packaging (version read from the `VERSION` file).
  Installs `shiba-cuddles` and `shiba-cuddles-gui` console commands.
- `shibacuddles.spec` — PyInstaller spec for a standalone binary:
  `pyinstaller --noconfirm shibacuddles.spec`
- Pushing a `v*` tag triggers the Release workflow: builds the Windows
  `.exe` and Linux binary, generates `SHA256SUMS-*.txt`, attaches
  signed build-provenance attestations, and publishes the GitHub release.

## 🗺️ Roadmap (planned — not yet implemented)

- `config.yaml` default-settings loader (a sample is documented nowhere
  yet — the CLI is fully flag-driven today)
- Packet-level parsing in `analyze_traffic_patterns` (currently a
  capture stub returning empty breakdowns)
- Wiring `UDPScanner` / `VulnerabilityScanner` into the CLI/GUI pipeline
  (both exist as library classes today; `UDPScanner` has test coverage,
  `VulnerabilityScanner` is an untested demo class)
- Custom scan profiles and scheduled scans

## 🔐 Security considerations

- Always get **written permission** before scanning networks you don't own.
- Comply with local laws and regulations.
- Never use the WiFi attack functions outside your `authorized_targets.json`
  scope — unauthorized wireless interference is illegal in most places.
- Be mindful of DoS-like behavior: use `--rate-limit`, keep timeouts sane,
  and respect network resources.
- Found a vulnerability in ShibaCuddles itself? See [SECURITY.md](SECURITY.md)
  — report it privately, never as a public issue.

## 🛠️ Troubleshooting

| Issue | Fix |
|---|---|
| Permission denied (WiFi features) | `sudo chmod +u+s /usr/bin/airmon-ng /usr/bin/aireplay-ng` |
| PyQt6 not found | `pip install PyQt6 PyQt6-Charts` |
| `airodump-ng` not found | Install the aircrack-ng suite (see Installation) |
| OS detection returns Unknown | Needs scapy + raw-socket privileges (run with sudo); without them it degrades gracefully |
| Scan timeouts | Raise `--timeout`, e.g. `--timeout 15` |
| High false negatives | Try `--no-ping` to skip the ping sweep |
| Output file already exists | Add `--force` to allow overwriting |

### Performance tips

1. **Threading** — more threads for larger networks: `--threads 64`
2. **Port range** — scan common ports first: `--ports 22,80,443,3306,5432,8080`
3. **Rate limiting** — reduce network load: `--rate-limit 0.1`
4. **Timeout** — tune to your network: `--timeout 3`

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. The PR template
includes an authorized-use checklist — scope gating must stay fail-closed.

## 📄 License

MIT License — see the [LICENSE](LICENSE) file for details.

## 📬 Contact

- **Business inquiries:** Sentinelsafeguard@outlook.com
- **Security reports:** Sentinelsafeguard@outlook.com (see [SECURITY.md](SECURITY.md) — private disclosure only)

## 💰 Donations

If this tool earned its keep, BTC is welcome:

```
bc1qvydns2fmyjzj55wzxq7ta28nxdhcmu9l9m6yg0
```

## ⚠️ Disclaimer

**ShibaCuddles is provided as-is for educational and authorized security
testing purposes only.** Unauthorized access to computer systems is
illegal. Users are responsible for ensuring they have proper authorization
before using this tool on any network or system.

---

Built for security professionals and network administrators to perform
efficient, comprehensive network assessments. For more information, visit:
https://github.com/TheRealJesusTheHacker/ShibaCuddles
