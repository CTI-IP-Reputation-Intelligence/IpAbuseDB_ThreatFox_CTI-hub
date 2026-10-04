# Output data dictionary summary

## Evidence output

Path:

```text
/data/ddos-cti/exports/cti_ip_reputation_current.csv
```

This 24-column file preserves current-snapshot source evidence. Important fields include:

| Field group | Purpose |
|---|---|
| `ip_address`, `ip_version` | Canonical unique join key and address family |
| `source_count`, `sources`, `seen_in_both` | Current snapshot lineage; not a historical OpenCTI count |
| `abuseipdb_*` | Free-blacklist confidence, reporting, country, and membership evidence |
| `threatfox_*` | IOC count, ports, threat types, malware, tags, dates, confidence, and membership evidence |
| `merged_at_utc` | UTC publication time for the evidence row |

## ML feature lookup

Path:

```text
/data/ddos-cti/features/cti_ip_reputation_features_current.csv
```

This 22-column file is the lookup intended for DDoS-ML feature enrichment. It includes provider membership, normalized scores, missing-value flags, record and port counts, ThreatFox categories, and IOC age.

The lookup contains positive CTI matches. DDoS-ML traffic with no matching row must be assigned documented neutral/default feature values during the join. CTI membership is enrichment evidence, not the DDoS target label and not proof that an address performed an attack.

## Cardinality rules

- One row per canonical IP in each current file.
- ThreatFox `ip:port` records are deduplicated by IP; ports remain a set/count.
- Source overlap is measured only across the same current collection.
- Counts can rise or fall because feeds expire and blacklist ranking/filtering changes.
