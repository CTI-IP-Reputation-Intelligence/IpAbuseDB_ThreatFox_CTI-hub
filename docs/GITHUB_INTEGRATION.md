# Release repository integration

## Repository separation

Development history remains in the private repository:

```text
CTI-IP-Reputation-Intelligence/IpAbuseDB_ThreatFox_CTI-hub_development
```

The history-free distribution is staged in the separate release repository:

```text
https://github.com/CTI-IP-Reputation-Intelligence/IpAbuseDB_ThreatFox_CTI-hub
```

The release repository must remain private until clean-VM testing and every required approval in `APPROVAL_RECORD.md` are complete.

## Version 1 import procedure

1. Export only the approved files listed in `release/MANIFEST.txt`.
2. Do not copy the development repository's `.git` directory.
3. Run `bash scripts/validate_release.sh` from the export root.
4. Confirm the secret, private-address, hostname, personal-data, operational-data, media, and obsolete-repository scans pass.
5. Create exactly one root commit on `main`:

   ```text
   Initial public release: IpAbuseDB_ThreatFox_CTI-hub v1.0.0
   ```

6. Keep the repository private for acceptance testing.
7. Create tag `v1.0.0` only after explicit release approval. Do not backdate, replace, or move an approved tag.
8. Change repository visibility only after the tag contents, checksums, documentation, license, and approval record have been reviewed.

## Authentication boundary

Repository authentication is separate from runtime CTI integration:

- While private, authorized organization members use GitHub CLI or an approved credential helper to clone the repository.
- After publication, normal users can clone the public HTTPS URL without a GitHub token.
- The installer never asks for or stores GitHub credentials.
- The runtime collector requires only the protected AbuseIPDB key and ThreatFox feed URL.
- Never embed a username or token in a Git remote URL, script, configuration file, screenshot, issue, or log.

Verify a local remote before pushing:

```bash
git remote -v
```

A safe value resembles:

```text
https://github.com/CTI-IP-Reputation-Intelligence/IpAbuseDB_ThreatFox_CTI-hub.git
```

## Repository controls

- Protect `main` from force-push and deletion.
- Require pull-request review for later versions.
- Require the offline release validator and any approved security checks.
- Enable secret scanning and dependency alerts when available.
- Protect release tags.
- Exclude operational feeds, generated CSVs, state, logs, credentials, models, alerts, databases, and screenshots.

Version 1 is the only intentional single-commit import. All later changes should use reviewed branches, clear contribution records, a new version, regenerated fingerprints, and a new immutable tag.
