# Architecture

This document describes the current vncsnatch architecture and the direction
for the clean-room `vncgrab` implementation.

## Overview

vncsnatch scans IP ranges from an IP2Location CSV, probes VNC servers, and
saves screenshots of no-auth targets (and auth targets when a password list is
provided). The scanner is multi-threaded and produces a stable progress panel
unless verbose output is enabled.

High-level data flow:

1) Load IP ranges for a country from the CSV.
2) Spawn worker threads to scan ranges concurrently.
3) For each IP:
   - Optional ICMP reachability check (requires capabilities).
   - VNC security probe (ports list).
   - Screenshot capture on no-auth or auth-required with password list.
4) Update live progress metrics and periodic resume checkpoint.
5) Emit per-host metadata and optional results export.

## Modules

`vncsnatch.c`
- CLI parsing, interactive prompts, and high-level control flow.
- Range loading and scanning orchestration.
- Progress/status reporting and resume checkpointing.
- Password list handling, CIDR filtering, metadata/results output.

`network_utils.c` / `network_utils.h`
- ICMP reachability checks.
- RFB security negotiation probe (no-auth vs auth required).
- Socket I/O helpers for protocol reads/writes.

`file_utils.c` / `file_utils.h`
- File path sanitization helpers.

`misc_utils.c` / `misc_utils.h`
- Capability detection for ICMP probing.

`vncgrab.c` / `vncgrab.h`
- Clean-room VNC grabber for snapshots.
- RFB handshake, auth (DES), RAW decode, optional CopyRect handling.
- JPEG output and blank-screen filtering.

`des.c` / `des.h`
- Clean-room DES implementation for VNC auth.

`tests/`
- `fake_vnc_server.py`: local RFB test server for protocol regression tests.
- `test_security.c`: test client exercising `get_security`.
- `run_tests.sh`: test runner and build harness.
- `test_vncgrab.c`: vncgrab snapshot tests.
- `test_resume.c`: resume parsing tests.

## Threading Model

- A shared `scan_context_t` coordinates range iteration and stats.
- `range_mutex` protects the shared range cursor and next-IP allocation.
- `stats_mutex` protects counters (scanned, online, VNCs, screenshots).
- `print_mutex` serializes progress and verbose output.
- `rate_mutex` enforces global rate limiting (IPs/sec).
- `checkpoint_mutex` throttles `.line` resume checkpoint writes.
- A UI ticker thread updates the progress panel on a fixed interval.

## Progress and Resume

- Progress is printed as a two-line panel (spinner, rate, ETA, counters) unless
  `-v` or `-q`.
- Resume uses a country-scoped checkpoint in `.line`:
  `CC offset online vnc noauth auth_success auth_attempts`.
- A checkpoint is updated periodically during scanning and once at completion.
- Metadata files are written per detected VNC host (JSON).
- Optional results export emits CSV or JSONL.

## Data Formats

### Resume checkpoint (`.line`)
```
CC offset online vnc noauth auth_success auth_attempts
```
- `CC` is the country code (e.g., `SE`). Older numeric-only files still load.

### Metadata JSON (`metadata/*.json`)
Per detected VNC host:
- `ip`, `port`
- `country_code`, `country_name`
- `online` (boolean or null)
- `vnc_detected`, `auth_required`, `auth_success`
- `password_used`
- `screenshot_saved`, `screenshot_path`
- `timestamp`

### Results export (`--results`)
- CSV (default): `ip,port,country_code,country_name,online,auth_required,auth_success,password_used,screenshot_saved`
- JSONL: one JSON object per line with the same fields.

## Clean-room vncgrab Status

The clean-room grabber is now the default path. External `vncsnapshot` is
optional (`USE_VNCSNAPSHOT=1`).

Current behavior:
- RFB handshake (3.3/3.8), RAW decode, CopyRect handling.
- VNC auth via clean-room DES.
- JPEG output with adjustable quality and optional sub-rect capture.
- Blank-screen filtering with `--allowblank` / `--ignoreblank`.
