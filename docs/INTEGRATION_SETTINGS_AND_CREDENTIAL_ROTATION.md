# Integration settings and credential rotation

## Access and credential scopes

| Scope | Values | Used when | Storage rule |
|---|---|---|---|
| Provider runtime | AbuseIPDB API key, optional AbuseIPDB API URL, complete ThreatFox CSV/export URL | Every collection | `/etc/ddos-cti-stage/stage.env`, `root:cti-stage`, mode `0640` |
| Release repository | Credential-free HTTPS URL; while private, organization authentication managed by GitHub CLI or an approved credential helper | Source clone/update only | Never stored by the installer or collector; no GitHub value belongs in `stage.env` |

Changing repository authentication does not require changing the daily CTI service. Changing a provider key or protected feed URL does not require changing the source checkout.

## Display current runtime settings safely

```bash
sudo /usr/local/bin/ddos-cti-update-settings --show
```

The helper prints normal non-secret settings and replaces sensitive values with `<redacted>`. It does not call either provider.

## Rotate an expired or revoked AbuseIPDB key

1. Create or approve a replacement key in the authorized AbuseIPDB account.
2. Record its owner, issue date, active plan, and internal review date in the controlled credential register—not in Git.
3. Run:

```bash
sudo /usr/local/bin/ddos-cti-update-settings --abuseipdb-key
```

4. Paste the new key at the hidden prompt.
5. Perform one controlled validation when quota permits:

```bash
sudo -u cti-stage /usr/local/bin/ddos-cti-collect
```

6. Confirm a successful state and check the latest logs.

## Change an AbuseIPDB endpoint URL

The normal collector uses its approved default endpoint. Use a custom URL only when the provider or authorized network design requires it:

```bash
sudo /usr/local/bin/ddos-cti-update-settings --abuseipdb-url
```

The helper accepts HTTPS only. Do not disable TLS verification to work around a certificate problem.

## Change a ThreatFox CSV/export URL

The URL may be public or protected. Because a protected URL can embed authorization, the whole value is always requested silently and treated as a secret.

```bash
sudo /usr/local/bin/ddos-cti-update-settings --threatfox-url
```

Paste the complete replacement HTTPS export URL at the hidden prompt. Then run one controlled validation when permitted.

## Why the helper is formulated this way

- It requires root because the configuration is intentionally not writable by the service account.
- It refuses to edit while the collection service is active, preventing a run from reading a partly changed configuration.
- Secret input uses `read -s`, so it is not echoed on screen.
- The secret is not supplied as a command-line argument, reducing exposure through process listings and shell history.
- It validates required keys and HTTPS URLs before publication.
- It creates the replacement in the same directory, applies `root:cti-stage` and `0640`, then uses `mv` for atomic replacement.
- It does not automatically call providers because a manual test consumes quota.
- It does not restart the timer because each oneshot run sources the configuration again.

## Expected failure indicators

| Symptom | Likely cause | Action |
|---|---|---|
| HTTP 401 or 403 | Key/token rejected, expired, revoked, pending approval, or insufficient permission | Stop retries, replace or approve the affected credential, then run one validation. |
| HTTP 429 | Free-tier quota/rate limit | Observe reset/retry headers and wait; do not repeatedly run manual tests. |
| DNS or connection timeout | Resolver, routing, firewall, proxy, or provider availability | Verify DNS and outbound TCP 443 before changing credentials. |
| TLS/certificate failure | Clock, CA bundle, proxy interception, or certificate issue | Fix trust/time/network; never disable TLS verification. |
| Download succeeds but parser rejects data | Provider schema changed | Preserve the raw response, keep the last known-good current file, and review code before publishing. |

## Repository URL or access changes

The runtime service and installer do not use GitHub credentials. While the release repository remains private, authenticate GitHub CLI or an approved credential helper before cloning or pulling:

1. Confirm the credential-free repository URL and organization ownership.
2. Authenticate only through GitHub CLI or the approved credential helper.
3. If a token is required by organization policy, restrict it to the repository and minimum permission, record its exact expiry outside Git, and revoke it when no longer needed.
4. Clone or pull the complete release source.
5. Run the installer locally; it must not request a GitHub username or token.
6. Confirm `/var/lib/ddos-cti-stage/install-record.txt` contains no repository credential.

After the repository becomes public, HTTPS clone/pull requires no token. If the repository moves, verify the new owner and URL before using the new checkout. The installed runtime has no Git remote and does not need GitHub access for daily collection.

## No source-code editing required

All provider integration values belong to protected configuration or controlled installation input. Do not edit `collector.py`, wrapper files, or systemd units to replace a URL, key, or token.
