# Changelog

## Unreleased

- Added the README demonstration animation `cti-hub.gif`.
- Added the merged ThreatFox and AbuseIPDB feed diagram `02_threat-intel-merge_zoomed_light.png` before the demonstration animation.

## 1.0.0 — 2026-10-04

- Prepared a history-free Version 1 source package for the organization release repository.
- Included only the standalone AbuseIPDB and ThreatFox IP-reputation staging layer used by DDoS-ML.
- Added a minimal-interaction local-source installer for supported Ubuntu hosts.
- Added IP-only filtering, validation, deduplication, evidence merging, and numeric ML-feature generation.
- Added atomic current-file publication with persistent `ddos-cti-readers:0640` access.
- Added the daily persistent systemd timer, health command, safe integration-setting rotation, and redacted error reporting.
- Added manifest/checksum validation, shell and Python syntax checks, prohibited-content scans, and a synthetic offline pipeline test.
- Removed internal development reports, demonstration media, operational data, logs, credentials, and old repository references from the distribution package.
- Kept public visibility and the `v1.0.0` tag pending clean-VM acceptance and formal approval.
