# Security policy

## Report a vulnerability

Report suspected vulnerabilities privately to `ahmedmekkyf13@gmail.com`. Do not include live API keys, tokens, production CTI rows, internal addresses, or authentication databases in the initial report.

## Secret handling

- Never commit completed `.env` files, API keys, tokens, protected export URLs, SSH keys, or certificates.
- Store runtime provider secrets only in `/etc/ddos-cti-stage/stage.env`, owned by `root:cti-stage` with mode `0640`.
- Enter replacement secrets through the hidden prompts in `scripts/update_integration_settings.sh`.
- Never put a GitHub token in a repository URL, command-line argument, log, screenshot, or release record.
- Revoke and replace a credential immediately if it may have been exposed.

## Failure behavior

Authentication, TLS, schema, empty-feed, or validation failures must not replace the last known-good current CSV. Operators should inspect `systemctl status`, journald, and the redacted state/error files before retrying.

## Supported release

Only an approved, fingerprinted release is supported. Modified versions must identify their changes and must not be represented as an official Ahmed Mekky release.
