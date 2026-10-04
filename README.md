# IpAbuseDB_ThreatFox_CTI hub

Standalone AbuseIPDB and ThreatFox IP-intelligence collection and staging for DDoS-ML.

This history-free `1.0.0` source package contains the one-command installer, runtime source, systemd units, offline tests, documentation, and integrity records. It contains no OpenCTI server setup, Grafana integration, operational CTI data, credentials, models, alerts, logs, or internal infrastructure values.


## Prerequisites

- Create an account at `https://www.abuseipdb.com/`, accept the applicable terms, and create an API key.
- Confirm the AbuseIPDB plan and current quota. The collector uses one blacklist request during installation and normally one request per scheduled day.
- Obtain a complete ThreatFox CSV/export HTTPS URL. The public recent CSV is `https://threatfox.abuse.ch/export/csv/recent/`; a protected URL may contain an authorization value and must be treated as a secret.
- Choose the existing Linux account that will read the ML feature CSV. If it does not exist, the installer creates a restricted service-style account with that name.
- Confirm outbound DNS, HTTPS/TCP 443, CA trust, correct system time, and at least the minimum resources below.

After the inputs are entered, the installer displays a redacted summary:

```bash
Installation summary (secrets are never displayed)
  Source              : /home/<username>/IpAbuseDB_ThreatFox_CTI-hub
  AbuseIPDB API key   : <provided>
  ThreatFox feed URL  : <provided; hidden>
  ML reader account   : <Linux account that will read the ML CSV>
  Daily schedule      : 02:15 server-local time
  Retention           : 90 days
  AbuseIPDB filter    : IPv4, score 100, maximum 1,000 rows
  ThreatFox filter    : ip:port records, deduplicated by IP
  First live run      : yes (normally one request per provider)

Type INSTALL to continue:
```

## Server physical and time-synchronization requirements

| Resource | Minimum | Recommended | Why it is required |
|---|---:|---:|---|
| CPU | 2 vCPU | 4 vCPU | Runs feed parsing, validation, deduplication, merging, and feature generation. |
| Memory | 4 GB RAM | 8 GB RAM | Provides working memory for provider downloads and CSV transformation. |
| Storage | 10 GB free | 20 GB or more free | Stores the application, Python environment, current outputs, and 90 days of raw and processed snapshots. Increase capacity when raising provider limits or retention. |
| Network | Reliable outbound HTTPS | Redundant monitored Internet path where available | Requires DNS resolution and outbound TCP 443 to GitHub during installation and to the configured AbuseIPDB and ThreatFox endpoints during collection. No inbound Internet port is required by this staging layer. |
| Time source | One valid reachable NTP source | Two or more approved internal or external NTP sources | Keeps collection timestamps, IOC recency, the daily `02:15` timer, log correlation, retention cleanup, and audit evidence accurate. |

The server clock **must be synchronized before installation and remain synchronized during operation**. Use an organization-approved internal NTP service when available. Otherwise, configure valid trusted external sources in accordance with the organization's security policy. Permit NTP traffic only to those approved sources; conventional NTP normally uses UDP port 123.

Verify the clock, timezone, and synchronization state:

```bash
timedatectl status
timedatectl show -p Timezone -p NTPSynchronized -p NTP
```

Healthy output must include:

```text
System clock synchronized: yes
NTP service: active
NTPSynchronized=yes
```

If `NTPSynchronized=no`, enable the Ubuntu time service and check again:

```bash
sudo timedatectl set-ntp true
sudo systemctl restart systemd-timesyncd
timedatectl timesync-status
```

If the host uses Chrony instead of `systemd-timesyncd`, verify it with:

```bash
chronyc tracking
chronyc sources -v
```

Do not continue with installation while the clock is unsynchronized. If synchronization fails, verify DNS, the configured NTP source, routing/firewall access to the approved source, and the time-service logs. The server timezone controls when the daily `02:15` systemd timer runs; UTC timestamps remain authoritative inside state and output records.

## One-command installation

While the repository remains private for acceptance testing, install Git and GitHub CLI, authenticate as an authorized organization member, clone the release repository, and run the local installer:

```bash
sudo apt update
sudo apt install -y git gh
gh auth login --hostname github.com --git-protocol https --web
gh auth setup-git
gh repo clone CTI-IP-Reputation-Intelligence/IpAbuseDB_ThreatFox_CTI-hub
cd IpAbuseDB_ThreatFox_CTI-hub
sudo bash install_ipabusedb_threatfox_cti_hub.sh
```

After the repository is formally approved and made public, GitHub authentication is unnecessary:

```bash
sudo apt update
sudo apt install -y git
git clone https://github.com/CTI-IP-Reputation-Intelligence/IpAbuseDB_ThreatFox_CTI-hub.git
cd IpAbuseDB_ThreatFox_CTI-hub
sudo bash install_ipabusedb_threatfox_cti_hub.sh
```

The installer uses the source directory that contains it, verifies `release/SHA256SUMS`, runs offline tests, requests the AbuseIPDB key, complete ThreatFox CSV/export HTTPS URL, and ML reader account, performs one controlled live collection, validates the outputs, and enables the daily timer only when all checks pass. GitHub credentials are handled only by Git or GitHub CLI and are never requested or retained by the installer.

For an extracted release or air-gapped source transfer:

```bash
sudo bash install_ipabusedb_threatfox_cti_hub.sh --source-dir /path/to/release
```

See `docs/INSTALLER_GUIDE.md` for prerequisites, prompts, failure handling, and installed paths.

## Status

- Version: `1.0.0`.
- Distribution repository: `CTI-IP-Reputation-Intelligence/IpAbuseDB_ThreatFox_CTI-hub`.
- Source history: one clean initial release commit; development history is not imported.
- Public visibility and the `v1.0.0` tag remain blocked until clean-VM acceptance, security/legal review, and explicit approval are complete.


## Data flow

1. `src/collector.py` downloads approved AbuseIPDB and ThreatFox feeds.
2. It validates and canonicalizes IP addresses, filters ThreatFox to `ip:port`, deduplicates by IP, and publishes the evidence CSV atomically.
3. `src/build_features.py` transforms the evidence CSV into the numeric lookup used by DDoS-ML.
4. The systemd timer starts the pipeline daily at `02:15` server-local time.

The DDoS-ML input is:

```text
/data/ddos-cti/features/cti_ip_reputation_features_current.csv
```

The audit/evidence file is:

```text
/data/ddos-cti/exports/cti_ip_reputation_current.csv
```

## Package map

| Path | Purpose |
|---|---|
| `src/` | Collector and ML feature-builder source |
| `config/` | Redacted runtime configuration template |
| `wrappers/` | Stable commands invoked by systemd and operators |
| `systemd/` | Daily service, timer, and feature-generation drop-in |
| `scripts/` | Health, validation, and safe credential-rotation helpers |
| `tests/` | Offline synthetic pipeline validation |
| `docs/` | Design, operations, repository, credential, sanitization, and approval records |
| `release/` | Manifest and integrity records |
| `install_ipabusedb_threatfox_cti_hub.sh` | Single clean-Ubuntu installer |

See `docs/ORGANIZATION.md` for the full structure and `docs/INTEGRATION_SETTINGS_AND_CREDENTIAL_ROTATION.md` before changing a URL, username, API key, or token.

## Software packages and versions

Release `1.0.0` pins the application-level Python dependency. Ubuntu operating-system package revisions are intentionally obtained from supported Ubuntu repositories at installation time so the host can receive current security fixes. Their exact revision therefore depends on the installation date and selected Ubuntu release.

| Package or component | Version used by this release | Use |
|---|---|---|
| Ubuntu | `22.04 LTS` or `24.04 LTS` | Validated host operating systems |
| Python (`python3`) | Ubuntu default: `3.10.x` on 22.04 or `3.12.x` on 24.04; repository revision not pinned | Runs the collector, feature builder, and offline tests |
| Python virtual environment (`python3-venv`) | Matches the installed Ubuntu Python 3 package; revision not pinned | Isolates the application dependency under `/opt/ddos-cti-stage/venv` |
| Requests (`requests`) | **`2.34.2`**, pinned in `requirements.txt` | HTTPS requests to AbuseIPDB and ThreatFox |
| pip | Supplied by the Python virtual environment; not pinned | Installs the pinned Python requirement during setup |
| CA certificates (`ca-certificates`) | Current supported Ubuntu repository revision; not pinned | Validates provider and GitHub HTTPS certificates |
| curl | Current supported Ubuntu repository revision; not pinned | Provider connectivity preflight |
| systemd | Host version supplied by Ubuntu; normally `249.x` on 22.04 or `255.x` on 24.04 | Runs and schedules the hardened collection service |
| Bash (`bash`) | Host version supplied by Ubuntu; not pinned | Runs the installer, wrappers, validation, health, and settings scripts |
| GNU core utilities (`coreutils`) | Host version supplied by Ubuntu; not pinned | File installation, permissions, atomic replacement, timestamps, and SHA-256 checks |
| GNU find utilities (`findutils`) | Host version supplied by Ubuntu; not pinned | Snapshot-retention cleanup and release validation |
| grep | Host version supplied by Ubuntu; not pinned | Safe configuration and release checks |
| sed | Host version supplied by Ubuntu; not pinned | Standard text processing used by shell operations |
| awk (`mawk` or compatible implementation) | Host version supplied by Ubuntu; not pinned | Reads the installation record and redacted configuration fields |
| util-linux | Host version supplied by Ubuntu; not pinned | Supplies `runuser` for execution under the restricted service or reader account |
| passwd | Host version supplied by Ubuntu; not pinned | Supplies `useradd`, `usermod`, and `groupadd` for service-account setup |
| libc-bin | Host version supplied by Ubuntu; not pinned | Supplies `getent` for account and group validation |
| Git (`git`) | Current Ubuntu repository revision; not pinned; installation workstation only | Clones the private repository in the documented installation path |
| GitHub CLI (`gh`) | Current configured repository revision; not pinned; private acceptance phase only | Authenticates organization members and clones the private release repository |

Python standard-library modules are included with the selected Python interpreter and do not have independent package versions. Docker, OpenCTI, and Grafana are not installed or required by this release.

To record the exact package revisions on an installed VM, run:

```bash
dpkg-query -W -f='${binary:Package}\t${Version}\n' bash ca-certificates coreutils curl findutils grep libc-bin mawk passwd python3 python3-venv sed systemd util-linux git gh 2>/dev/null
sudo /opt/ddos-cti-stage/venv/bin/python -c 'import platform,requests; print("Python",platform.python_version()); print("requests",requests.__version__)'
```

All third-party package names, trademarks, copyrights, and other rights remain reserved to their respective owners and licensors. Each third-party component remains governed by its own license terms. Its inclusion in this project does not transfer ownership or imply endorsement. The project copyright notice applies only to the original project material; see `LICENSE` and `NOTICE`.

## Offline validation

From this directory:

```bash
bash scripts/validate_release.sh
```

The command performs no provider request and uses only synthetic IP examples.

## Security boundary

- Never commit `/etc/ddos-cti-stage/stage.env`.
- Never place a GitHub token in a Git remote URL or project configuration file.
- Treat the complete ThreatFox export URL as a secret when it contains an Auth-Key.
- Provider credentials are changed with `scripts/update_integration_settings.sh`; the file is replaced atomically and keeps restrictive ownership and permissions.
- GitHub authentication, when the repository is private, is managed by GitHub CLI outside the installer and is not a runtime CTI setting.

## SOC administrator quick integration checks

The manual collection below normally consumes one provider request per source. Do not repeat it rapidly because provider quotas apply.

| Check | Command | Healthy result | Short fix if unhealthy |
|---|---|---|---|
| AbuseIPDB and ThreatFox IOC loading | `sudo systemctl start ddos-cti-stage.service && sudo journalctl -u ddos-cti-stage.service -n 60 --no-pager` | `Collection completed successfully`; both provider counts and merged count are greater than zero; feature build succeeds. | Read the final error/code. For credentials run `sudo /usr/local/bin/ddos-cti-update-settings --abuseipdb-key` or `--threatfox-url`; for connection/TLS errors repair DNS, TCP 443, time, CA, or proxy, then retry once. |
| Full health and last successful update | `sudo /usr/local/bin/ddos-cti-health` | `PASS` lines, `State status: success`, a recent `Last completed UTC`, non-empty CSVs, group `ddos-cti-readers`, mode `0640`. | Use the reported failing path, then inspect the service journal. Do not fix only the current CSV with `chmod`; correct the reader group/configuration so future atomic replacements remain readable. |
| Schedule, previous run, and next run | `sudo systemctl list-timers --all ddos-cti-stage.timer --no-pager` | One row shows `LAST`, `NEXT`, and `LEFT`; `NEXT` is the next daily `02:15` in server-local time. | If absent/inactive: `sudo systemctl enable --now ddos-cti-stage.timer`; then run the check again. |
| File modification time and permissions | `sudo stat -c '%n | inode=%i | modified=%y | bytes=%s | owner=%U:%G | mode=%a' /data/ddos-cti/{exports/cti_ip_reputation_current.csv,features/cti_ip_reputation_features_current.csv}` | Recent modification time, non-zero bytes, group `ddos-cti-readers`, mode `640`. | If stale or missing, inspect the journal and last-error file; repair the identified integration problem before one manual collection. |
| Detect content/file replacement | `sudo sha256sum /data/ddos-cti/{exports/cti_ip_reputation_current.csv,features/cti_ip_reputation_features_current.csv}` | Save the hashes and compare after the next run. The modification time/inode should advance; a hash may stay unchanged when provider data is unchanged. | If neither time nor inode advances after a due run, check timer and service logs. |
| Redacted integration settings | `sudo /usr/local/bin/ddos-cti-update-settings --show` | AbuseIPDB key and ThreatFox URL appear as `<redacted>`; endpoints and filters are present. | Rotate only the failed value with `--abuseipdb-key` or `--threatfox-url`; never paste secrets into logs or GitHub. |

For a failed run, use `sudo journalctl -u ddos-cti-stage.service -n 80 --no-pager` and inspect `/data/ddos-cti/state/cti_ip_reputation_last_error.json`. A failed refresh preserves the last known-good current CSV.

## Last one confirmed setup

The behavior last confirmed on **30 September 2026** was promoted into this `1.0.0` source package. The build accepts a complete ThreatFox CSV/export HTTPS URL, generates the evidence and ML feature files, schedules daily collection at `02:15` server-local time, retains snapshots for 90 days, preserves `ddos-cti-readers:0640` after atomic replacement, and makes the health check automatically validate the reader account selected during installation. A new clean-VM acceptance record is still required before public visibility and tagging.

### Complete project file inventory

| # | Project file | Purpose |
|---:|---|---|
| 1 | `.gitignore` | Excludes credentials, runtime data, logs, caches, archives, and generated outputs. |
| 2 | `AUTHORS.md` | Author and ownership information. |
| 3 | `CHANGELOG.md` | Version 1 release history. |
| 4 | `CONTRIBUTIONS.md` | Contribution and review record. |
| 5 | `LICENSE` | Responsible-use license terms. |
| 6 | `NOTICE` | Copyright, approved scope, and modification disclaimer. |
| 7 | `README.md` | Primary installation, operation, and SOC quick-reference guide. |
| 8 | `SECURITY.md` | Security policy and vulnerability-reporting guidance. |
| 9 | `VERSION` | Authoritative package version. |
| 10 | `config/stage.env.example` | Redacted configuration example; never contains operational secrets. |
| 11 | `docs/APPROVAL_RECORD.md` | Approval gates and sign-off status. |
| 12 | `docs/DATA_DICTIONARY.md` | Evidence and ML-feature field definitions. |
| 13 | `docs/GITHUB_INTEGRATION.md` | History-free release-repository workflow. |
| 14 | `docs/INSTALLATION_AND_OPERATIONS.md` | Installation, scheduling, monitoring, and recovery guide. |
| 15 | `docs/INSTALLER_GUIDE.md` | Installer prompts, controls, and failure behavior. |
| 16 | `docs/INTEGRATION_SETTINGS_AND_CREDENTIAL_ROTATION.md` | Safe URL, key, and reader-setting changes. |
| 17 | `docs/ORGANIZATION.md` | Source and runtime directory organization. |
| 18 | `docs/ROADMAP.md` | Version 1 scope and later controlled improvements. |
| 19 | `docs/SANITIZATION_REPORT.md` | Public-release source-cleanliness record. |
| 20 | `install_ipabusedb_threatfox_cti_hub.sh` | One-command clean-Ubuntu installer. |
| 21 | `release/MANIFEST.txt` | Exact approved source-file inventory. |
| 22 | `release/RELEASE_MANIFEST.md` | Release identity, scope, status, and known limitations. |
| 23 | `release/SHA256SUMS` | Machine-verifiable SHA-256 integrity manifest. |
| 24 | `release/SHA256SUMS.txt` | Human-portable copy of the integrity manifest. |
| 25 | `requirements.txt` | Minimal Python runtime dependency. |
| 26 | `scripts/health_check.sh` | Checks timer, state, files, permissions, selected reader, and recent failures. |
| 27 | `scripts/update_integration_settings.sh` | Atomically rotates AbuseIPDB and ThreatFox runtime settings. |
| 28 | `scripts/validate_release.sh` | Runs manifest, checksum, syntax, cleanliness, and synthetic-pipeline validation. |
| 29 | `src/build_features.py` | Builds the numeric DDoS-ML feature lookup from merged evidence. |
| 30 | `src/collector.py` | Downloads, filters, validates, deduplicates, and merges provider data. |
| 31 | `systemd/ddos-cti-stage.service` | Hardened one-shot collection service. |
| 32 | `systemd/ddos-cti-stage.service.d/features.conf` | Adds feature generation and feature-retention cleanup. |
| 33 | `systemd/ddos-cti-stage.timer` | Persistent daily 02:15 server-local schedule. |
| 34 | `tests/test_pipeline.py` | Synthetic offline collector and feature-builder acceptance test. |
| 35 | `wrappers/ddos-cti-build-features` | Stable feature-builder launcher. |
| 36 | `wrappers/ddos-cti-collect` | Stable collector launcher. |

### Installed and runtime file destinations

| Source or generated item | Destination | Function / access |
|---|---|---|
| `src/collector.py` | `/opt/ddos-cti-stage/app/collector.py` | Installed collector; `root:cti-stage`, mode `0640`. |
| `src/build_features.py` | `/opt/ddos-cti-stage/app/build_features.py` | Installed feature builder; `root:cti-stage`, mode `0640`. |
| `requirements.txt` | `/opt/ddos-cti-stage/venv/` | Dependencies installed into the restricted Python virtual environment. |
| `wrappers/ddos-cti-collect` | `/usr/local/bin/ddos-cti-collect` | Stable collector command. |
| `wrappers/ddos-cti-build-features` | `/usr/local/bin/ddos-cti-build-features` | Stable feature-builder command. |
| `scripts/health_check.sh` | `/usr/local/bin/ddos-cti-health` | Operational health command; automatically reads the selected reader account. |
| `scripts/update_integration_settings.sh` | `/usr/local/bin/ddos-cti-update-settings` | Safe credential and feed-URL rotation command. |
| `systemd/ddos-cti-stage.service` | `/etc/systemd/system/ddos-cti-stage.service` | Collection service. |
| `systemd/ddos-cti-stage.service.d/features.conf` | `/etc/systemd/system/ddos-cti-stage.service.d/features.conf` | Feature build and retention drop-in. |
| `systemd/ddos-cti-stage.timer` | `/etc/systemd/system/ddos-cti-stage.timer` | Daily persistent timer. |
| Generated protected configuration | `/etc/ddos-cti-stage/stage.env` | Provider credentials, filters, limits, timeouts, and output group; `root:cti-stage`, mode `0640`. |
| Generated installation record | `/var/lib/ddos-cti-stage/install-record.txt` | Version, source, chosen reader, group, schedule, retention, and review dates; root-only. |
| Application root | `/opt/ddos-cti-stage/` | Installed application and virtual environment. |
| AbuseIPDB raw snapshots | `/data/ddos-cti/raw/abuseipdb/` | Timestamped JSON snapshots retained for 90 days. |
| ThreatFox raw snapshots | `/data/ddos-cti/raw/threatfox/` | Timestamped CSV/ZIP snapshots retained for 90 days. |
| Current evidence CSV | `/data/ddos-cti/exports/cti_ip_reputation_current.csv` | Merged audit/evidence dataset; group `ddos-cti-readers`, mode `0640`. |
| Evidence archive | `/data/ddos-cti/exports/archive/` | Timestamped evidence CSVs retained for 90 days. |
| Current DDoS-ML feature CSV | `/data/ddos-cti/features/cti_ip_reputation_features_current.csv` | Primary ML lookup; group `ddos-cti-readers`, mode `0640`. |
| Feature archive | `/data/ddos-cti/features/archive/` | Timestamped feature CSVs retained for 90 days. |
| Collection state | `/data/ddos-cti/state/cti_ip_reputation_state.json` | Last successful run, counts, timestamps, and raw-file references. |
| Last failure details | `/data/ddos-cti/state/cti_ip_reputation_last_error.json` | Redacted provider failure code and retry information, when a run fails. |
| Pre-change backup | `/var/backups/ipabusedb-threatfox-cti-hub/<UTC timestamp>/` | Recoverable copies of replaced installed configuration and units. |
| README, legal files, docs, tests, release records, and example config | The verified source checkout | Reference and validation content; not copied into runtime application paths. |

Copyright © 2026 Ahmed Mekky. All rights reserved. See `LICENSE` and `NOTICE`.
