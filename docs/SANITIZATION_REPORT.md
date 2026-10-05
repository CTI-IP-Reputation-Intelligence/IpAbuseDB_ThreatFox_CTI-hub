# Public-release sanitation report

Version: `1.0.0`  
Prepared: 2026-10-04  
Status: **PASS — history-free source package prepared; repository remains private pending acceptance**

## Excluded from the distribution

- The development repository's `.git` directory and commit history.
- Credentials, tokens, private keys, passwords, completed environment files, and authentication databases.
- Operational network addresses, server names, customer or employer identifiers, and environment-specific configuration.
- Raw provider downloads, generated evidence or feature CSVs, state, alerts, models, databases, logs, caches, backups, and archives.
- Internal screenshots, internal demonstration media (other than the reviewed public README image `cti-hub.gif`), internal step reports, and abandoned scripts.
- OpenCTI, Grafana, Docker deployment, and unrelated project content.
- The previous personal repository URL.

## Included by design

- Provider hostnames and endpoint examples required to configure AbuseIPDB and ThreatFox.
- IANA documentation-only address ranges generated during synthetic tests.
- Redacted placeholders in `config/stage.env.example`.
- Author and security-contact information intentionally published in the legal and security files.

## Required validation

Run from the package root:

```bash
bash scripts/validate_release.sh
```

The validator checks the exact manifest, SHA-256 values, shell/Python syntax, the synthetic pipeline, prohibited file types, secret/key signatures, private-address literals, obsolete repository references, and excluded operational artifacts. Any file change invalidates the fingerprints and requires regeneration plus a complete rerun.

The release repository must stay private and the `v1.0.0` tag must not be created until the clean-VM test and approval record are complete.
