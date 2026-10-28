# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add MIT license and contributing guide.
- ASN targeting via `--mode country|asn|both` with `--asn` (comma-separated ASN numbers and/or `org:name` substrings, case-insensitive) and `--asn-file`; `both` intersects the ASN filter with a country. In Docker the ASN database is auto-downloaded (`ASN_DB_URL`/`ASN_DB_URL_EXTRA`/`ASN_DB_CACHE`, `fetch-db asn`) and `VNC_MODE`/`VNC_ASN`/`VNC_ASN_FILE` map the new flags.
- Dockerize the project: multi-stage `Dockerfile` producing a fully static Alpine binary (~19 MB image), plus `.dockerignore`, `.gitignore` and `docker-compose.yml` with a `/data` bind mount and optional `NET_RAW` capability.
- Container auto-downloads an IP-to-country database when no `-f/--file` is given, caching it under `/data`. Multiple sources (sapics/ip-location-db, datasets/geoip2-ipv4) across GitHub and the jsDelivr CDN are tried in order.
- `DB_URL`, `DB_URL_EXTRA`, `DB_HEADER`, `DB_CACHE`, `DB_REFRESH`, `DB_MAX_AGE_DAYS`, `DB_AUTO_REFRESH`, `DB_REFRESH_INTERVAL` and `DB_OUTPUT_DIR` environment variables to use a custom mirror (e.g. where GitHub is blocked) or an API-key-protected provider; `${VAR}` tokens in URLs are expanded safely and gzip responses are decompressed automatically.
- Cached database is kept on the `/data` volume and reused across runs, refreshed automatically only when older than `DB_MAX_AGE_DAYS` (default 7; `0` never expires). A refresh downloads to a temp file and atomically swaps it in, so a failed download leaves the existing cache in place.
- Optional background refresher (`DB_AUTO_REFRESH=1`) that re-checks and updates the cache on an interval during long scans, plus a `fetch-db force` form to download unconditionally.
- Default container output directory to `/data/output` so screenshots, metadata and results are written to the mounted volume unless the caller sets `-O`/`-M`.
- `fetch-db` container command to pre-seed the database cache without scanning.
- `VNC_*` environment variables mapping to every CLI flag (plus free-form `VNC_ARGS`), so the scanner can be driven entirely from a compose `environment:` block; command-line flags still override them.
- CSV parser unit tests (`tests/test_csv_parser.c`) and a `Docker` CI workflow that builds the image, checks the binary is static, runs the parser tests, and smoke-tests the auto-download.

### Changed

- Clarify libjpeg requirement for clean-room screenshots in documentation.
- Stabilize vncgrab tests with longer startup waits and clearer failures.
- Extend the CSV loader to accept quoted-decimal (IP2Location), unquoted-dotted (`from,to,CC`) and CIDR-with-columns (GeoIP2) layouts, so public country databases can be used without preprocessing.
- Harden the build CI (`apt-get update`, matrix over the default and OpenSSL builds, binary/help/clean-rebuild checks).

## [2.0.0] - 2026-01-14

### Added

- Clean-room `vncgrab` implementation with JPEG output and RFB 3.3/3.8 support.
- Password list support, metadata output, results export, and CIDR filters.
- Interactive CSV generator tool and expanded regression tests.
- Live progress UI, TCP online fallback, and improved resume behavior.

### Changed

- Default output layout to `output/CC` for screenshots and metadata.
- Raised worker cap and clarified limits in CLI help.

## [0.1] - 2025-02-04

### Added

- Initial public release.
