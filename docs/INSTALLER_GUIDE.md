# One-command installer guide

## Purpose

`install_ipabusedb_threatfox_cti_hub.sh` installs only the standalone CTI staging layer used by DDoS-ML. It does not install OpenCTI, Grafana, Docker, a database, or an ML model.

After cloning or extracting the complete verified release, run:

```bash
sudo bash install_ipabusedb_threatfox_cti_hub.sh
```

The installer uses the directory containing the script as its source. No GitHub credential is requested or retained.

## Prepare before running

Have these values ready:

1. An active AbuseIPDB API key and knowledge of the active plan/quota.
2. A complete working ThreatFox CSV/export HTTPS URL, public or protected.
3. The Linux account that will read the ML feature CSV; the default is `ml_ai`.
4. Root/sudo access on Ubuntu 22.04 LTS or 24.04 LTS.
5. Correct time and timezone, valid NTP synchronization, DNS, CA trust, and outbound HTTPS/TCP 443.
6. At least 2 vCPU, 4 GB RAM, and 10 GB free storage; 4 vCPU, 8 GB RAM, and 20 GB free are recommended.

Treat a protected ThreatFox URL as a secret when it contains an authorization value. Provider key lifetime is controlled by the provider and account policy; do not assume it never expires or cannot be revoked.

## Prompt sequence

| Prompt | Visibility | Purpose |
|---|---|---|
| AbuseIPDB API key | Hidden | Authenticates the blacklist request. |
| ThreatFox CSV/export HTTPS URL | Hidden | Uses the exact approved feed URL without assuming an authentication format. |
| ML reader account | Visible | Receives read-only group access to the feature CSV. |
| `INSTALL` confirmation | Visible | Authorizes host changes after a redacted summary. |

## Fixed Version 1 defaults

| Setting | Value | Reason |
|---|---|---|
| Service user | `cti-stage` | Isolates collection from interactive users. |
| Reader group | `ddos-cti-readers` | Keeps DDoS-ML read access after atomic file replacement. |
| Daily start | `02:15` server-local | One predictable collection per day. |
| Persistent timer | `true` | Runs a missed collection after the VM returns. |
| Retention | 90 days | Preserves controlled evidence while limiting storage. |
| AbuseIPDB limit | 1,000 | Conservative free-plan default. |
| AbuseIPDB score | 100 | Starts with the highest-confidence blacklist entries. |
| IP version | IPv4 | Matches the initial DDoS-ML lookup scope. |
| ThreatFox type | `ip:port` | Excludes domains, URLs, email addresses, and hashes. |
| Output mode/group | `0640`, `ddos-cti-readers` | Owner writes; approved consumers read; others receive no access. |

## Installation sequence

1. Resolve the local source directory and collect all operator inputs.
2. Show a redacted summary and request one confirmation.
3. Validate Ubuntu, systemd, disk space, and required HTTPS reachability.
4. Install only `ca-certificates`, `curl`, `python3`, and `python3-venv` when needed.
5. Copy the local source to a private temporary directory.
6. Verify `release/SHA256SUMS` and run the offline release validator.
7. Create restricted service and reader identities, runtime paths, the Python virtual environment, and protected configuration.
8. Install wrappers and systemd units.
9. Run one controlled provider collection and feature build.
10. Verify non-empty CSVs, group/mode preservation, and reader access.
11. Enable the daily timer only after every earlier check passes.

## Failure behavior

The installer stops with `[ERROR]`, does not newly enable the timer, and shows the relevant log command. Atomic publication preserves the last known-good current CSV when a refresh fails.

| Code | Meaning | Action |
|---|---|---|
| `CONNECTION_FAILED` | DNS, proxy, firewall, or route prevented connection. | Restore outbound HTTPS and retry once. |
| `CONNECTION_TIMEOUT` | Connection/read exceeded the configured timeout. | Check provider/network health; avoid rapid retries. |
| `TLS_FAILED` | Certificate verification failed. | Correct time, CA trust, or proxy interception; never disable verification. |
| `AUTH_REJECTED` | Provider returned 401/403. | Rotate the named provider credential. |
| `AUTH_OR_ENDPOINT_REJECTED` | Endpoint returned 404. | Verify the complete ThreatFox URL and any embedded authorization value. |
| `RATE_LIMITED` | Provider returned 429. | Wait for the advertised retry/reset time. |
| `HTTP_FAILED` | Another HTTP error occurred. | Review provider status and the service journal. |

## Validation and alternate local-source mode

Validate the extracted release without root access or machine changes:

```bash
bash install_ipabusedb_threatfox_cti_hub.sh --validate-source "$PWD"
```

Install from another extracted directory:

```bash
sudo bash install_ipabusedb_threatfox_cti_hub.sh --source-dir /path/to/release
```

## Installed operator commands

```bash
sudo /usr/local/bin/ddos-cti-health
sudo systemctl list-timers --all ddos-cti-stage.timer --no-pager
sudo journalctl -u ddos-cti-stage.service -n 80 --no-pager
sudo /usr/local/bin/ddos-cti-update-settings --show
```

Rotate only the affected runtime value:

```bash
sudo /usr/local/bin/ddos-cti-update-settings --abuseipdb-key
sudo /usr/local/bin/ddos-cti-update-settings --threatfox-url
```

Before public visibility and tag creation, test Version 1 on a disposable supported Ubuntu VM with approved non-production credentials. Record redacted evidence for a successful first run, a second idempotent run, credential rejection, output permissions, reader access, timer behavior, and reviewer approval.
