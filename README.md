# 🐕 ShibaCuddles — Advanced Network Scanner & Security Testing Suite

[![CI](https://github.com/TheRealJesusTheHacker/ShibaCuddles/actions/workflows/ci.yml/badge.svg)](https://github.com/TheRealJesusTheHacker/ShibaCuddles/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/TheRealJesusTheHacker/ShibaCuddles)](https://github.com/TheRealJesusTheHacker/ShibaCuddles/releases)

A fast, multi-threaded network scanner with a PyQt6 GUI dashboard — device discovery, port scanning,
service fingerprinting, OS detection, and vulnerability checks, plus WiFi security-testing modules
for authorized assessments.

> **Because every network needs a cuddly scanner.**

## ⬇️ Downloads

No Python needed — grab the latest standalone build from the
[releases page](https://github.com/TheRealJesusTheHacker/ShibaCuddles/releases):

| Platform | File |
|---|---|
| Windows | [ShibaCuddles.exe](https://github.com/TheRealJesusTheHacker/ShibaCuddles/releases/download/v0.2.0/ShibaCuddles.exe) |
| Linux | [ShibaCuddles](https://github.com/TheRealJesusTheHacker/ShibaCuddles/releases/download/v0.2.0/ShibaCuddles) |

SHA256 checksums ship alongside each release — verify before running:

```bash
sha256sum -c SHA256SUMS-windows.txt   # Windows (Git Bash / WSL)
sha256sum -c SHA256SUMS-linux.txt     # Linux
```

## 🚀 Quick Start

```bash
# Install runtime dependencies
pip install -r requirements.txt

# Scan your network (CLI)
python main.py 192.168.1.0/24

# ...or launch the GUI dashboard
python gui_launcher.py
```

## ✨ Features

### Network Scanning
- **Device Discovery** — ICMP ping sweep, ARP scanning, hostname resolution, MAC detection
- **Port Scanning** — TCP (1–65535), UDP detection, banner grabbing, service version detection
- **Advanced Analysis** — service fingerprinting (20+ services), TTL-based OS fingerprinting,
  vulnerability detection, real-time statistics

### GUI Dashboard
- Sleek dark-themed dashboard with a brand header and version badge
- Grouped sidebar: target, performance, scan options, and actions
- Live results table with alive/down status indicators and monospace IPs
- Card-based statistics (hosts scanned, hosts alive, open ports, averages)
- Color-coded console-style activity log
- Real-time scan progress and multi-format export

### WiFi Security Testing
- Device deauthentication (requires the `aircrack-ng` suite)
- Broadcast deauth, monitor-mode control, network scanning, channel analysis

## 📦 Installation

Requires **Python 3.8+**.

```bash
git clone https://github.com/TheRealJesusTheHacker/ShibaCuddles.git
cd ShibaCuddles
pip install -r requirements.txt
```

For WiFi features, install the aircrack-ng suite separately:

```bash
sudo apt-get install aircrack-ng   # Ubuntu/Debian
sudo dnf install aircrack-ng       # Fedora
brew install aircrack-ng           # macOS
```

## 🖥️ CLI Usage

```bash
# Basic scan (ports 1-1024)
python main.py 192.168.1.0/24

# Specific ports / port range
python main.py 192.168.1.0/24 --ports 22,80,443
python main.py 192.168.1.0/24 --ports 1-5000

# Aggressive scan with service + OS detection
python main.py 192.168.1.0/24 --aggressive --service-detection --os-detection

# More threads, custom timeout
python main.py 192.168.1.0/24 --threads 20 --timeout 10

# Verbose output
python main.py 192.168.1.0/24 -vv
```

### Exporting results

```bash
python main.py 192.168.1.0/24 --output results.json            # JSON (default)
python main.py 192.168.1.0/24 --output results.csv --format csv # CSV
python main.py 192.168.1.0/24 --output results.xml --format xml # XML
python main.py 192.168.1.0/24 --output results.txt --format txt # plain text
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

## 🗂️ Project Layout

- `main.py` — CLI entry point
- `gui_launcher.py` — GUI entry point
- `src/` — scanner engine
  - `scanner.py` — scan orchestration
  - `device.py` — device discovery (ping sweep, ARP)
  - `port_scanner.py` — TCP/UDP port scanning
  - `service_detector.py` — banner grabbing, service & OS fingerprinting
  - `deauth.py` — WiFi deauthentication testing (authorized use only)
  - `results_handler.py` — multi-format result export
  - `utils.py` — logging, validation, helpers
- `gui/` — PyQt6 dashboard (`main_window.py`)
- `tests/` — unit test suite

## 🧪 Development

```bash
pip install -r requirements-dev.txt

# Run the test suite
python -m pytest tests/ -v

# Format & lint
black src/ gui/ tests/
flake8 src/ gui/ tests/
```

CI runs byte-compile checks on Linux and Windows plus the full test suite on every push to `main`.

## 📦 Packaging & Releases

- `setup.py` — standard packaging (version read from the `VERSION` file).
  Installs `shiba-cuddles` and `shiba-cuddles-gui` console commands.
- `shibacuddles.spec` — PyInstaller spec for building a standalone binary:
  `pyinstaller --noconfirm shibacuddles.spec`
- Pushing a `v*` tag triggers the Release workflow: it builds the Windows `.exe`
  and Linux binary, generates SHA256 hashes, and attaches everything to the
  GitHub release automatically.

## ⚠️ WiFi Deauthentication — Legal Warning

**Unauthorized wireless network interference is illegal in most jurisdictions.**

Only use the WiFi testing features for:
- Testing your own networks
- Authorized penetration testing
- Educational purposes

Basic usage:

```python
from src.deauth import WiFiDeauthenticator, DeauthTarget

deauth = WiFiDeauthenticator()
deauth.enable_monitor_mode('wlan0')

target = DeauthTarget(
    mac_address='AA:BB:CC:DD:EE:FF',
    gateway_mac='11:22:33:44:55:66',
    ssid='TestNetwork',
    channel=6,
    interface='wlan0mon'
)
deauth.deauthenticate_device(target)
deauth.disable_monitor_mode('wlan0mon')
```

## 🔐 Security Considerations

- Always get **written permission** before scanning networks you don't own
- Comply with local laws and regulations
- Don't use deauth features on networks you don't own or aren't authorized to test
- Be mindful of DoS-like behavior and respect network resources

## 🛠️ Troubleshooting

| Issue | Fix |
|---|---|
| Permission denied (WiFi features) | `sudo chmod +u+s /usr/bin/airmon-ng /usr/bin/aireplay-ng` |
| PyQt6 not found | `pip install PyQt6 PyQt6-Charts` |
| Scan timeouts | Raise `--timeout`, e.g. `--timeout 15` |
| High false negatives | Try `--no-ping` to skip the ping sweep |

### Performance tips

1. **Threading** — more threads for larger networks: `--threads 64`
2. **Port range** — scan common ports first: `--ports 22,80,443,3306,5432,8080`
3. **Rate limiting** — reduce network load: `--rate-limit 0.1`
4. **Timeout** — tune to your network: `--timeout 3`

## ⚙️ Configuration File (optional)

Create `config.yaml` for default settings:

```yaml
scanning:
  threads: 20
  timeout: 5.0
  rate_limit: 0.0
  batch_size: 50

features:
  ping_sweep: true
  service_detection: false
  os_detection: false
  aggressive: false

output:
  format: json
  export_path: ./results/
```

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

MIT License — see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

**ShibaCuddles is provided as-is for educational and authorized security testing purposes only.**
Unauthorized access to computer systems is illegal. Users are responsible for ensuring they have
proper authorization before using this tool on any network or system.

---

Built for security professionals and network administrators to perform efficient, comprehensive
network assessments. For more information, visit:
https://github.com/TheRealJesusTheHacker/ShibaCuddles
