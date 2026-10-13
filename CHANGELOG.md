# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

## [Planned Releases]

### Version 0.3.0
- **Target**: Q4 2026
- IPv6 support
- Vulnerability scanning
- Web dashboard
- Advanced filtering options

### Version 1.0.0
- **Target**: 2027
- Stable API
- Production-ready features
- Comprehensive documentation
- Native binaries for major platforms

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
