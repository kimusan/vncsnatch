# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Add MIT license and contributing guide.

### Changed
- Clarify libjpeg requirement for clean-room screenshots in documentation.
- Stabilize vncgrab tests with longer startup waits and clearer failures.

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
