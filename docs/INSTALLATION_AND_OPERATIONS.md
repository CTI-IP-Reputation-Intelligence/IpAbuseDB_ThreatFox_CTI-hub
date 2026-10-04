# Installation and operations

## Release status

`1.0.0` includes the one-command installer that creates the accounts, virtual environment, protected configuration, installed files, timer, initial collection, and read-only DDoS-ML handoff.

Run:

```bash
sudo bash install_ipabusedb_threatfox_cti_hub.sh
```

The complete verified release must be cloned or extracted before setup. All runtime inputs are requested before host changes. Secret values are hidden, no GitHub credential is requested by the installer, and the timer is enabled only after the first collection and feature build pass. Clean-VM live acceptance is required before public visibility and tag creation. See `INSTALLER_GUIDE.md`.

## Stable installation map

| Source file | Installed path | Mode/ownership target |
|---|---|---|
| `src/collector.py` | `/opt/ddos-cti-stage/app/collector.py` | `root:cti-stage`, `0640` |
| `src/build_features.py` | `/opt/ddos-cti-stage/app/build_features.py` | `root:cti-stage`, `0640` |
| `wrappers/ddos-cti-collect` | `/usr/local/bin/ddos-cti-collect` | `root:root`, `0755` |
| `wrappers/ddos-cti-build-features` | `/usr/local/bin/ddos-cti-build-features` | `root:root`, `0755` |
| `config/stage.env.example` | `/etc/ddos-cti-stage/stage.env` after secure prompting | `root:cti-stage`, `0640` |
| `systemd/ddos-cti-stage.service` | `/etc/systemd/system/ddos-cti-stage.service` | `root:root`, `0644` |
| `systemd/ddos-cti-stage.timer` | `/etc/systemd/system/ddos-cti-stage.timer` | `root:root`, `0644` |
| `systemd/ddos-cti-stage.service.d/features.conf` | matching systemd drop-in path | `root:root`, `0644` |
| `scripts/health_check.sh` | `/usr/local/bin/ddos-cti-health` | `root:root`, `0755` |
| `scripts/update_integration_settings.sh` | `/usr/local/bin/ddos-cti-update-settings` | `root:root`, `0755` |

## Schedule and lifecycle

```text
OnCalendar=*-*-* 02:15:00
Persistent=true
AccuracySec=1min
Retention=90 days
```

The timer uses the server-local timezone. `Persistent=true` allows a missed execution to be started after the server becomes available. Evidence and feature generation occur in one service execution: the collector runs first, then the feature builder runs only after collection succeeds.

## Normal operator checks

```bash
sudo /usr/local/bin/ddos-cti-health
sudo systemctl list-timers --all ddos-cti-stage.timer --no-pager
sudo journalctl -u ddos-cti-stage.service -n 80 --no-pager
```

Healthy behavior includes an active waiting timer, non-empty current evidence and feature CSVs, state `success`, and a collection age normally under 36 hours.

## Manual collection

```bash
sudo -u cti-stage /usr/local/bin/ddos-cti-collect
```

This consumes one provider collection request. Avoid repeated manual runs on a free plan. Feature generation is automatically attached to the systemd service; when running only the wrapper manually, build features afterward if required:

```bash
sudo -u cti-stage /usr/local/bin/ddos-cti-build-features
```

## Configuration changes

Use `docs/INTEGRATION_SETTINGS_AND_CREDENTIAL_ROTATION.md` and the installed `/usr/local/bin/ddos-cti-update-settings` command. Integration secrets are configuration data, not source code. Runtime replacements are atomic and every newly published evidence/feature CSV is explicitly restored to group `ddos-cti-readers` and mode `0640`, so future inode replacement retains DDoS-ML read access.
