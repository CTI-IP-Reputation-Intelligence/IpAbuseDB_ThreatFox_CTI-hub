# Release manifest

| Field | Value |
|---|---|
| Product | `IpAbuseDB_ThreatFox_CTI hub` |
| Version | `1.0.0` |
| Package date | 2026-10-04 |
| Distribution repository | `CTI-IP-Reputation-Intelligence/IpAbuseDB_ThreatFox_CTI-hub` |
| Intended initial commit | `Initial public release: IpAbuseDB_ThreatFox_CTI-hub v1.0.0` |
| Git history policy | One clean initial commit; development history excluded |
| Git tag | `v1.0.0` — blocked until explicit approval |
| Repository visibility | Private during acceptance; public only after approval |
| Approval | Pending; see `docs/APPROVAL_RECORD.md` |

## Included scope

Standalone AbuseIPDB and ThreatFox collection, IP-only validation and normalization, evidence merging, ML-feature lookup generation, a local-source installer, wrappers, systemd scheduling, a redacted configuration template, offline synthetic tests, health and credential-rotation tools, documentation, and per-file integrity records.

## Excluded scope

OpenCTI, Docker, Grafana, databases, operational CTI, credentials, environment-specific infrastructure values, runtime state, models, alerts, logs, screenshots, generated production CSVs, internal development reports, and development Git history.

## Release gates still pending

- Clean Ubuntu VM installation and live-provider acceptance.
- Technical, functional, security, documentation, intellectual-property/legal, and management approvals.
- Explicit approval to make the release repository public.
- Creation of the immutable `v1.0.0` tag after approval.

The per-file source identity is recorded in `MANIFEST.txt`, `SHA256SUMS`, and `SHA256SUMS.txt`. These files must be regenerated whenever approved source content changes.
