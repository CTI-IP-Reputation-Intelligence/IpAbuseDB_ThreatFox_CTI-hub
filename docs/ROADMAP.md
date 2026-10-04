# Version 1 roadmap and release controls

## Primary purpose

Version 1 provides a small, independently deployable staging layer that:

- Maintains an up-to-date list of poorly reputed IPv4 addresses associated with malicious or suspicious activity that may contribute to denial-of-service risk.
- Collects AbuseIPDB blacklist entries and ThreatFox `ip:port` indicators.
- Validates, normalizes, and deduplicates IP addresses.
- Preserves provider evidence in an auditable merged CSV.
- Produces a numeric feature lookup for authorized DDoS-ML enrichment.
- Publishes files atomically with stable read permissions for the selected ML account.
- Runs on a controlled daily schedule and retains 90 days of snapshots.

The project is intended for defensive cybersecurity, monitoring, anomaly detection, threat-intelligence correlation, and authorized testing. It does not authorize interception, scanning, monitoring, or access without permission.

## Prerequisites

Before installation, the operator must:

1. Prepare a supported Ubuntu 22.04 LTS or 24.04 LTS host with sudo access.
2. Provide at least 2 vCPU, 4 GB RAM, and 10 GB free storage; recommended capacity is 4 vCPU, 8 GB RAM, and 20 GB free.
3. Configure correct timezone and valid NTP synchronization from an approved source.
4. Permit DNS and outbound HTTPS/TCP 443 to the configured provider endpoints.
5. Create and verify an AbuseIPDB account, accept applicable terms, create an API key, and confirm its plan/quota and organizational approval.
6. Obtain a complete ThreatFox CSV/export HTTPS URL and treat it as secret if it embeds authorization.
7. Select the Linux account that will read the DDoS-ML feature CSV.
8. Review the provider terms, project license, security policy, and approval record.

Credential lifetime depends on provider policy and account administration. Record issue and review/rotation dates in an authorized credential register outside Git. A local review date does not guarantee that a provider credential remains valid until that date.

## Version 1 limitations

- The default AbuseIPDB request is restricted to IPv4, score 100, and 1,000 blacklist rows. It is a local conservative setting, not a complete copy of AbuseIPDB.
- Free-tier quotas, eligibility, result caps, and terms can change. Operators must confirm the current provider documentation before deployment or increasing collection frequency.
- ThreatFox contributes only `ip:port` records to this IP-only dataset. Domains, URLs, email addresses, and hashes are deliberately excluded.
- One IP can occur on multiple ThreatFox ports; Version 1 deduplicates by IP and retains aggregated evidence.
- Provider records appear, change, and expire. The current CSV is a time-bounded lookup, not a permanent ground-truth label.
- Absence from a current feed does not prove that an address is benign.
- The staging layer provides reputation features; it does not itself detect, classify, block, or attribute a DDoS attack.
- Provider licensing may restrict redistribution of raw or derived data. Do not publish runtime feeds or generated CSVs in this repository.
- Long-term organizational or commercial use must be reviewed against current provider licensing and legal requirements.

## Version 1 release sequence

1. Freeze the approved staging-only implementation.
2. Export only the files listed in `release/MANIFEST.txt`; exclude development Git history.
3. Remove secrets, operational data, logs, media, internal infrastructure values, abandoned scripts, and unrelated integration content.
4. Regenerate `release/SHA256SUMS` and `release/SHA256SUMS.txt`.
5. Run `bash scripts/validate_release.sh` and preserve the result as review evidence outside the repository when necessary.
6. Create the single clean initial commit in the private distribution repository.
7. Test installation, first collection, update rotation, schedule, permissions, reader access, and failure handling on a disposable clean Ubuntu VM.
8. Complete technical, functional, security, cleanliness, documentation, legal/IP, and management review.
9. Approve or reject public visibility.
10. After approval only, create immutable tag `v1.0.0` and publish the unchanged approved artifact.

Any later source change requires a new version, regenerated fingerprints, new testing evidence, and a new approval cycle.

## Adding a future CTI source

A new provider must be added through a reviewed feature branch and must not weaken the Version 1 security boundary.

1. Document the provider's license, authentication, quota, endpoint, schema, lifecycle, and permitted redistribution.
2. Add only required redacted placeholders to `config/stage.env.example`; never commit a live credential or protected URL.
3. Implement a bounded download with TLS verification, connect/read timeouts, a maximum response size, clear authentication/rate-limit errors, and a raw timestamped snapshot.
4. Accept only IP indicators needed by the ML use case. Parse with `ipaddress.ip_address`, apply the approved IP-version rule, and reject all other indicator types.
5. Normalize the provider record into the existing per-IP merge contract. Preserve source membership, timestamps, confidence, and source-specific evidence without turning reputation into a DDoS label.
6. Deduplicate within the source by canonical IP and define deterministic aggregation for multiple records.
7. Extend `src/collector.py`, `src/build_features.py`, and `docs/DATA_DICTIONARY.md` only for reviewed fields.
8. Add synthetic, non-routable test fixtures in `tests/test_pipeline.py`; tests must make no provider request.
9. Add credentials and failure status to the health and rotation tools without printing secrets.
10. Recalculate storage, quota consumption, polling intervals, retention, and lifecycle synchronization.
11. Update the manifest, checksums, changelog, documentation, version, and approvals.

## Lifecycle and time synchronization

The host clock is authoritative for run timestamps, snapshot names, retention cleanup, and schedule evaluation. UTC is stored in state and records, while the timer starts at `02:15` in the server-local timezone.

```text
Collection: one scheduled run each day at 02:15 server-local time
Persistent: yes; a missed run is started after the host returns
Retention: 90 days for raw, evidence, and feature snapshots
Credential review reminder: 90 days after installation by default
```

Provider indicator lifecycles are independent from the timer. Synchronization means comparing provider first-seen/last-seen or status timestamps with the collection time, retaining missing-time flags, and avoiding the assumption that a record remains malicious forever. Correct NTP is mandatory so recency calculations, logs, retention, and model lookups remain comparable.

## Post-Version 1 candidates

- Configurable provider limits with quota-aware validation.
- Additional approved IP-reputation sources through the integration contract above.
- Signed release artifacts and automated CI release gates.
- Configurable freshness thresholds and lifecycle-expiry policy.
- Formal schema versioning for the evidence and feature CSVs.

New features must begin from a new branch/version; the approved Version 1 artifact and tag remain unchanged.
