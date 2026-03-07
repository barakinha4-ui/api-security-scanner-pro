# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-07

### Added
- **Core Engine:** Blazing fast asynchronous HTTP engine utilizing `httpx` and `asyncio`.
- **OAST Integration:** Native out-of-band application security testing via `interact.sh` to capture blind SSRF, RCE, and SQLi.
- **Enterprise Dashboard:** Real-time web UI built with Tailwind CSS, reacting directly to the scanning engine via WebSockets.
- **Plugin System:** Dynamic `watchdog` Hot-Reload registry to create, inject, and debug custom `.py` security modules on the fly.
- **Shield Protection:** Built-in guards against SSRF loopback attacks (blocks `10.0.0.0/8`, `127.0.0.1`, etc.).
- **Global Rate Limiting:** asyncio locks preventing DoS against target infrastructure (Default: 1000 req/min).
- **CVSS 3.1 & Scoring:** Granular calculation of Confidence Scores to decrease false positive noise.
- **Reporting:** Multi-format output generation (JSON, HTML, Markdown, PDF).
- **CLI Options:** Granular control over scan scope (`--scan full|api|stealth`), thread concurrency, and stealth proxy routing.

### Changed
- Refactored entire codebase into an Enterprise Edition layout (`src/apiscanner/`).
- Updated `engine.py` to support `WAF` passive header detection and fingerprinting (e.g. Cloudflare, Akamai).
- Reconfigured global `ScannerConfig` logic using robust `pydantic-settings` typing via `.env` files.

### Fixed
- Resolved scanner application hangs during OAST polling timeouts (reduced polling friction to 1s/0.5s ticks).
- Fixed IDOR vulnerability false positives by comparing base response variations through the logic module.
- Patched sensitive header leaks in logs via regex sanitization (Tokens, JWTs, and API Keys are now redacted).

---
*Generated using conventional commits.*
