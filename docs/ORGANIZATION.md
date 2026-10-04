# Version 1 file organization

## Objective

This layout keeps the staging component small and reviewable. These files belong at the root of `CTI-IP-Reputation-Intelligence/IpAbuseDB_ThreatFox_CTI-hub`. Runtime data and secrets remain outside the source tree.

## Source tree

```text
IpAbuseDB_ThreatFox_CTI_hub/
├── README.md
├── LICENSE
├── NOTICE
├── AUTHORS.md
├── SECURITY.md
├── CHANGELOG.md
├── CONTRIBUTIONS.md
├── VERSION
├── requirements.txt
├── .gitignore
├── src/
│   ├── collector.py
│   └── build_features.py
├── config/
│   └── stage.env.example
├── wrappers/
│   ├── ddos-cti-collect
│   └── ddos-cti-build-features
├── systemd/
│   ├── ddos-cti-stage.service
│   ├── ddos-cti-stage.timer
│   └── ddos-cti-stage.service.d/
│       └── features.conf
├── scripts/
│   ├── health_check.sh
│   ├── update_integration_settings.sh
│   └── validate_release.sh
├── tests/
│   └── test_pipeline.py
├── docs/
│   ├── ORGANIZATION.md
│   ├── GITHUB_INTEGRATION.md
│   ├── INTEGRATION_SETTINGS_AND_CREDENTIAL_ROTATION.md
│   ├── INSTALLATION_AND_OPERATIONS.md
│   ├── INSTALLER_GUIDE.md
│   ├── DATA_DICTIONARY.md
│   ├── APPROVAL_RECORD.md
│   ├── ROADMAP.md
│   └── SANITIZATION_REPORT.md
└── release/
    ├── MANIFEST.txt
    ├── RELEASE_MANIFEST.md
    ├── SHA256SUMS
    └── SHA256SUMS.txt
```

## Why each area exists

| Area | Installed or consumed as | Why separate it |
|---|---|---|
| `src/` | `/opt/ddos-cti-stage/app/` | Runtime logic can be compiled, tested, and reviewed without extracting it from shell heredocs. |
| `config/` | `/etc/ddos-cti-stage/stage.env` | The repository holds placeholders; the server holds protected values. |
| `wrappers/` | `/usr/local/bin/` | systemd and operators call stable command names while Python remains in a private virtual environment. |
| `systemd/` | `/etc/systemd/system/` | Schedule and hardening are version-controlled and independently reviewable. |
| `scripts/` | Operator/release tools | Rotation, health, and offline validation do not belong inside the data parser. |
| `tests/` | Offline only | Synthetic tests prove parsing, filtering, merging, and feature generation without consuming provider quota. |
| `docs/` | Design and operations evidence | Configuration and approval knowledge remains beside the code. |
| `release/` | Immutable release evidence | Fingerprints and file inventory identify exactly what was reviewed. |

## Runtime paths not stored in Git

```text
/etc/ddos-cti-stage/stage.env
/data/ddos-cti/raw/
/data/ddos-cti/exports/
/data/ddos-cti/features/
/data/ddos-cti/state/
```

The `.gitignore` blocks completed environment files, raw feeds, state, logs, generated CSVs, Python caches, virtual environments, and local archives.

## Deliberately absent

- OpenCTI, Docker, databases, message brokers, and connector deployment.
- Grafana code or downloaded Grafana data.
- Production CTI snapshots and generated ML lookup files.
- Credentials, internal addresses, screenshots, host backups, and authentication databases.
- Development-repository Git history and internal step/freeze reports.
