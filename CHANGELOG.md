# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.3] - 2026-10-21

### Added (decision-execution wave, 2026-10-21)

- Real packet-level parsing in `NetworkInterruptor.analyze_traffic_patterns`
  (was a capture stub returning zeroed breakdowns): the capture is now
  parsed with scapy via the new `parse_pcap_file` helper in
  `src/deauth.py`, returning the actual total packet count,
  per-protocol counts (TCP/UDP/ICMP/ICMPv6/ARP/Other IP/Non-IP), and
  top talker IPs (combined, per-source, per-destination). When scapy
  is not installed the result is honest about it —
  `parsing_available: False`, `total_packets: None`, and a
  `parsing_unavailable_reason` — instead of fabricated zeros.
- `UDPScanner` and `VulnerabilityScanner` wired into the scan pipeline,
  CLI, and GUI (both were library-only): `NetworkScanner` gains
  `enable_udp_scan` / `enable_vuln_scan` flags and per-host
  `udp_open_ports` / `vulnerabilities` on `ScanResult`; the CLI gains
  `--udp` and `--vuln-scan`; the GUI gains "UDP scan" and
  "Vulnerability scan" toggles, UDP Ports and Vulnerabilities results
  columns, and matching statistics. Enabling the vulnerability scan
  also runs service detection, which its matching needs. The bundled
  vulnerability table remains **demo data (four sample entries)** —
  it is not a feed, and findings are labeled as such everywhere they
  are presented.
- UDP ports and vulnerability findings are included in TXT and XML
  exports (JSON already carried them via the result dataclass).
- 12 new tests (`tests/test_decision_wave.py`): pcap ground-truth
  breakdown (fixture with a known protocol/IP mix, verified end to
  end through the capture path), the scapy-absent honest-unavailable
  path, pipeline wiring, CLI flag parsing/delivery, and GUI toggles
  exercised offscreen — suite now 167 tests.

### Fixed (decision-execution wave, 2026-10-21)

- The CLI banner's hardcoded version string said v0.3.2; it now
  matches the release it ships in.

### Removed (retired 2026-10-21)

- README roadmap: the `config.yaml` default-settings loader line
  (S-4) — **dropped**: the CLI is flag-driven and complete; a loader
  is speculative convenience.
- README roadmap: the custom scan profiles / scheduled scans line
  (S-5) — **dropped**: profiles and scheduling are a separate
  scan-management product; a fresh greenlight if ever wanted.
- The `[Planned Releases]` section at the bottom of this file (S-6)
  — **retired**: it read as a standing commitment, including an
  unshipped web dashboard. Its shipped items (IPv6 support, the GUI,
  rate limiting, performance metrics) are historical release notes
  preserved in the version sections above; a web dashboard duplicates
  the GUI that ships today, and an honest changelog carries no
  unscheduled promises.

### Fixed (sweep #3 bug hunt, 2026-10-21)

- CLI: an invalid `--ports` spec was only logged by the engine and the
  run exited 0 looking like a completed empty scan; `main()` now
  validates the spec up front (as the GUI already did) and exits 1
- `VulnerabilityScanner` never matched OpenSSH through the real
  pipeline — `_parse_banner` names the product "SSH" while the table
  is keyed "OpenSSH"; the scanner now resolves that alias
- Vulnerability version matching was a bare prefix test, so "7.05"
  matched known-vulnerable "7.0" and "2.4.490" matched "2.4.49";
  matching now requires a non-digit boundary after the known version
  ("7.0p1" still matches "7.0")
- GUI: a user-stopped scan still emitted `finished`, and the handler
  rebranded the partial results as "Scan completed" at 100%; a
  stopped scan is now reported as stopped with partial results
- Regression tests: `tests/test_bughunt3_sweep3.py` (GUI stop behavior
  verified offscreen, not covered by the headless suite)

### Fixed (round-2 bug hunt, 2026-10-13)
- Service detection misidentified Apache and Nginx: the generic HTTP
  `Server:` pattern ran before the product patterns and captured the
  whole header value, so an Apache banner was reported as service
  "HTTP" with version "Apache/2.4.49 (Unix)" — and version-based
  consumers never saw the real product name. Product patterns
  (SSH/Apache/Nginx) are now matched first
- UDP scan counted any stray datagram reaching the probe socket as an
  open port; a reply now only counts if it comes from the probed host
  and port
- `parse_port_spec` now raises `ValueError` (its documented contract)
  for non-string input instead of leaking `AttributeError`/`TypeError`
  through callers that only catch `ValueError`
- `NetworkScanner(skip_broadcast=True)` silently erased a /32
  single-host target (zero hosts scanned) and dropped the last host
  of IPv6 ranges; the broadcast filter now applies only where a
  distinct IPv4 broadcast address exists
- `DeviceDiscovery.discover_subnet` gained the same 65,536-address
  ceiling `NetworkScanner` enforces, instead of materializing an
  unbounded host list
- XML export no longer fails outright when a service version string
  contains XML-forbidden control characters from a network banner;
  CSV/TXT/XML exports also tolerate `open_ports=None` in dict results
- `NetworkInterruptor.jam_channel` refuses non-positive durations
  before spawning: `duration=-5` previously invoked the `timeout`
  backstop as `timeout 0` (backstop disabled) and started mdk3
- GUI: a blank Ports field now uses the default range it always
  claimed to use, and an invalid port specification is reported in a
  dialog instead of looking like a completed scan with zero results

### Fixed
- `NetworkScanner` now floors its thread count at 1 (matching
  `PortScanner`/`UDPScanner`): `threads=0` or a negative count (e.g.
  CLI `--threads 0`) previously reached `ThreadPoolExecutor` unclamped
  and crashed `scan()` with `ValueError: max_workers must be greater
  than 0`
- CSV export of an empty result set now writes a header-only file
  instead of writing nothing while `save()` reported success
- The CLI no longer prints "Results saved" when the export failed:
  `NetworkScanner.save_results` returns the handler's outcome and
  `main.py` logs an error on failure
- `NetworkInterruptor.jam_channel` validates channel (integer, 1-196)
  and duration before building the `mdk3` command line, mirroring
  `_generate_hostapd_config`; a non-integer channel string could
  previously reach the subprocess argv verbatim and be parsed as an
  option
- GUI: a malformed target network is now reported as invalid instead
  of triggering the non-private-target legal warning, and activity-log
  messages are HTML-escaped before being rendered as rich text

### Performance
- Port scans (TCP and UDP) now submit probes in bounded windows of
  1,024 futures instead of queueing the entire port spec up front: a
  full-range 1-65535 scan's peak traced memory dropped from ~116 MB to
  ~7 MB with identical results, and stop/cancel now only ever holds one
  window of queued probes
- `parse_port_spec` is memoized: `PortScanner.scan()` re-parsed the
  spec for every host (~22 ms per full-range parse, ~5.6 s across a
  /24); repeat parses now cost ~1 ms
- Discovery results are sorted with a single-parse key (the old key
  parsed every address twice)
- GUI progress signals are emitted only when the percentage changes,
  instead of once per host (a /16 discovery phase could previously
  queue ~65k signals for 101 distinct values)

### Changed
- Thread-count clamping now lives in one shared helper
  (`utils.clamp_threads`); the per-class caps are unchanged
  (NetworkScanner 64, PortScanner/UDPScanner 100). Removed the unused
  `PortScanner.lock` attribute and a redundant deferred import

### Added
- 11 new unit tests: thread-count clamping and `save_results` outcome
  propagation, empty/non-empty CSV export, and `jam_channel` channel
  validation — suite now 83 tests
- 15 new regression tests for the performance pass: port-spec
  memoization (including cache-poisoning resistance), the shared
  thread clamp, windowed submission completeness/stop/cancel, and
  numeric discovery ordering — suite now 98 tests

## [0.3.2] - 2026-10-11

### Added
- 15 new unit tests covering the restored scan orchestration:
  `NetworkScanner._scan_ports` (per-host results, stop-event abort,
  graceful per-host failure, invalid port specs), progress-callback wiring
  (including a callback that raises), and the airodump-ng CSV parser
  (AP section, station-section cutoff, comma-in-SSID handling, malformed
  rows) — suite now 49 tests
- 9 new unit tests from the concurrency/edge-case audit: service detection
  no longer nests a per-port pool inside the per-host pool, Ctrl+C during
  TCP/UDP scans cancels queued probes instead of draining the queue,
  and `WiFiDeauthenticator.get_wireless_interfaces` is a real reachable
  method again (iwconfig parsing, failure and non-Linux paths) — suite now
  64 tests
- 8 new unit tests from the Windows-correctness audit: `print_banner`
  ASCII fallback on non-UTF-8 consoles, explicit UTF-8 exports,
  case-insensitive export extension detection, and airmon-ng/aireplay-ng
  detection via `shutil.which` — suite now 72 tests
- CI `lint` job: `black --check` + `ruff check` on every push/PR;
  `pyproject.toml` pins the ruff rule set (E/F/W/I) and black config
- Issue templates (bug report, feature request) and a PR template with an
  authorized-use checklist under `.github/`

### Changed
- All GitHub Actions pinned to commit SHAs (ci, release, CodeQL, PyPI
  publish) with version comments, per the supply-chain hardening standard
- `LICENSE` now carries the standard "MIT License" header
- Source formatted with black; dead imports/variables removed (ruff-clean)
- airodump-ng CSV parser preserves spaces inside SSIDs
  ("Cafe, Free, WiFi" no longer comes back as "Cafe,Free,WiFi")

### Fixed
- `create_rogue_ap` hostapd config generation rejects CR/LF in interface/SSID
  (config-line injection) and requires an integer WiFi channel (1-196);
  6 new unit tests in `tests/test_hostapd_config.py`
- `requirements.txt` bounds `PyQt6-Charts` to `<7.0.0` so a future major
  release can't silently swap in under the pinned `PyQt6==6.11.0`
- Restored the missing `NetworkScanner._scan_ports` method — every scan
  crashed without it
- Progress callbacks wired into the scan pipeline; a callback that raises
  can no longer break the scan
- DNS resolution cached per (host, socket type) so port scans no longer
  pay for a fresh `getaddrinfo` on every port
- Traffic capture uses a private `tempfile` path instead of a predictable
  `/tmp/traffic.pcap` (symlink-planting risk under sudo)
- Service detection no longer nests `ServiceDetector.detect()`'s per-port
  thread pool inside the per-host pool (`_map_parallel`) — threads^2, up to
  ~1,280 threads. The pipeline now probes each host's ports serially via
  `detect_service` while hosts stay parallel; `detect()` keeps its own pool
  for direct API use
- Ctrl+C during a TCP or UDP port scan now cancels the queued probes
  instead of letting pool teardown run every pending future to completion
  first; running probes are timeout-bounded and still close their sockets
- Restored `WiFiDeauthenticator.get_wireless_interfaces` as a real method —
  it was unreachable dead code (defined after a `return` in a
  module-level function), so any call raised `AttributeError`
- `utils.print_banner` falls back to ASCII on `UnicodeEncodeError` — the
  CLI/GUI no longer crash at startup on legacy Windows consoles
  (cp437/cp1252 can't render box-drawing glyphs or the Shiba emoji)
- Exports (JSON/CSV/XML/TXT) written as explicit UTF-8; Windows' locale
  codepage (cp1252) no longer raises `UnicodeEncodeError` on non-ASCII
  hostnames/banners and fails the whole export
- Export extension auto-detect is case-insensitive (`.CSV` works)
- airmon-ng/aireplay-ng detected via `shutil.which` instead of shelling
  out to the Unix-only `which` binary — this also fixes the tools being
  reported "found" whenever the `which` binary merely existed
- GUI export appends the chosen format's extension when the user types a
  bare filename (Windows needs extensions for file associations)

## [0.3.1] - 2026-10-10

### Security
- NEW: wireless attack functions gated behind `authorized_targets.json`
  scope file (SSID/BSSID allowlist, case-sensitive, no override);
  config dir takes precedence over cwd; malformed scope fails closed
- `deauth.py`: random WPA passphrase per run, `tempfile` instead of `/tmp`
  paths, guaranteed teardown
- Non-RFC1918 scan targets require explicit confirmation (CLI `--yes` / GUI dialog)
- Target ranges over 65,536 addresses refused (was: `0.0.0.0/0` → OOM)
- Results `--output` refuses overwrite without `--force`
- Vulnerability DB labeled as demo data

### Performance
- Service detection, OS detection, and UDP scanning parallelized
- Scan timeout floor 1.0 s → 0.2 s (device discovery keeps float precision)
- GUI progress bar live per host; results table inserted in batches;
  Stop now interrupts mid-host scans
- IPv6 targets scanned correctly (were silently reported all-closed)
- Discovery futures submitted in chunks; dead `scan_batch` removed

## [0.3.0] - 2026-09-19

### Changed
- Redesigned the PyQt6 GUI dashboard with a sleek, modern dark theme:
  brand header bar with version badge, grouped sidebar (Target / Performance /
  Scan Options / Actions), card-based statistics tab, and a color-coded
  console-style activity log
- Results table now uses pill-style alive/down status indicators, alternating
  row colors, monospace IP addresses, and truncated port lists with overflow counts

## [0.2.0] - 2026-09-19

### Added
- Initial project setup
- Core network scanning functionality
- Device discovery module
- Port scanning module
- JSON output support
- Verbose logging
- Comprehensive test suite
- PyQt6 GUI dashboard with real-time results and statistics
- WiFi deauthentication testing module (requires aircrack-ng; authorized testing only)
- Service fingerprinting (20+ services) and TTL-based OS detection
- CSV, XML, and plain-text result exports
- Packaging: `setup.py`, `MANIFEST.in`, `VERSION` file, `shibacuddles.spec` (PyInstaller)
- CI: byte-compile checks on Linux + Windows, full pytest run on every push
- Release automation: pushing a `v*` tag builds Windows `.exe` and Linux binaries
  via PyInstaller and attaches them to the GitHub release with SHA256 hashes
- Split `requirements.txt` (runtime) / `requirements-dev.txt` (test & tooling)

### Planned
_(Historical note, added 2026-10-21: this list was written before
0.2.0 shipped. IPv6 support, the GUI interface, performance metrics
and statistics, and rate limiting all shipped in later releases and
are recorded in those sections; custom scan profiles were retired
on 2026-10-21 — see the 0.3.3 "Removed" notes. Nothing in this list
is a current commitment.)_
- IPv6 support
- Custom scan profiles
- GUI interface
- Performance metrics and statistics
- Rate limiting options

## [0.1.0] - 2026-06-04

### Added
- Initial release of ShibaCuddles
- ICMP-based device discovery
- TCP port scanning (ports 1-1024 by default)
- Configurable port ranges
- JSON output support
- Verbose mode for detailed output
- Unit test suite
- Documentation (README, CONTRIBUTING)
- MIT License

### Features
- Device discovery on network subnets
- Multi-threaded port scanning
- Flexible command-line interface
- JSON result export
- Comprehensive error handling

---

## [Planned Releases] — retired 2026-10-21

This section formerly listed a "Version 0.3.0" (IPv6 support,
vulnerability scanning, web dashboard, advanced filtering) and a
"Version 1.0.0" (stable API, production-ready features,
comprehensive documentation, native binaries) as standing plans.
It was **retired on 2026-10-21**: IPv6 support shipped (recorded in
the release notes above), vulnerability scanning shipped in 0.3.3,
a GUI ships today and a web dashboard would only duplicate it, and
an honest changelog carries no unscheduled promises. The section no
longer reads as a commitment; future releases will be recorded here
when they ship, not promised in advance.

---

## Guidelines for Updating This File

- New features should be added under `[Unreleased]`
- Released versions use semantic versioning: MAJOR.MINOR.PATCH
- Include date in YYYY-MM-DD format
- Categories: Added, Changed, Deprecated, Removed, Fixed, Security
- Keep it human-readable

## How to Release

1. Move changes from `[Unreleased]` into a new version section below
2. Bump the version in the `VERSION` file (and `src/__init__.py`)
3. Commit and push to `main`
4. Create and push the tag: `git tag v0.x.x && git push origin v0.x.x`
5. The Release workflow builds the Windows `.exe` and Linux binary with
   PyInstaller, generates SHA256 hashes, and attaches everything to the
   GitHub release automatically
