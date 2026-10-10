# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
