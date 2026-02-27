# Changelog

## v2.0.1 — 2026-02-27
### Added
- Cookie-based auth with refresh tokens and CSRF protection.
- Admin audit log and SIEM delivery tracking.
- Redis pub/sub for WebSocket events with Mongo fallback.
- Segment inference via `SEGMENT_MAP` and retention TTLs.

### Changed
- Python 3.12 dependency pins (`numpy`, `torch`, `bcrypt`, `httpx`).
- Time handling switched to timezone-aware UTC.
- Scan state transitions guarded for worker updates.

### Fixed
- Test client compatibility with httpx.
- Bcrypt backend stability for passlib.
