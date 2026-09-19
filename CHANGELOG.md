# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
