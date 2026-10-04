#!/usr/bin/env python3
"""Create the numeric CTI lookup features used to enrich network telemetry."""

from __future__ import annotations

import csv
import grp
import ipaddress
import json
import math
import os
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


DATA_ROOT = Path("/data/ddos-cti")
INPUT_FILE = DATA_ROOT / "exports" / "cti_ip_reputation_current.csv"
FEATURE_DIR = DATA_ROOT / "features"
ARCHIVE_DIR = FEATURE_DIR / "archive"
CURRENT_FILE = FEATURE_DIR / "cti_ip_reputation_features_current.csv"
STATE_FILE = DATA_ROOT / "state" / "cti_feature_build_state.json"
OUTPUT_GROUP = os.getenv("STAGE_OUTPUT_GROUP", "ddos-cti-readers").strip()

REQUIRED_INPUT_FIELDS = {
    "ip_address",
    "ip_version",
    "source_count",
    "seen_in_both",
    "in_abuseipdb",
    "abuseipdb_confidence_score",
    "in_threatfox",
    "threatfox_record_count",
    "threatfox_ports",
    "threatfox_last_seen",
    "threatfox_max_confidence",
    "threatfox_is_compromised",
    "threatfox_botnet_cc",
    "threatfox_payload_delivery",
}

OUTPUT_FIELDS = [
    "ip_address",
    "ip_version",
    "cti_match",
    "cti_source_count",
    "cti_seen_in_both",
    "cti_abuseipdb_match",
    "cti_abuseipdb_score",
    "cti_abuseipdb_score_norm",
    "cti_abuseipdb_score_missing",
    "cti_threatfox_match",
    "cti_threatfox_confidence",
    "cti_threatfox_confidence_norm",
    "cti_threatfox_confidence_missing",
    "cti_threatfox_record_count",
    "cti_threatfox_record_count_log1p",
    "cti_threatfox_port_count",
    "cti_threatfox_botnet_cc",
    "cti_threatfox_payload_delivery",
    "cti_threatfox_is_compromised",
    "cti_threatfox_last_seen_missing",
    "cti_threatfox_age_days",
    "feature_generated_at_utc",
]


def utc_now() -> datetime:
    return datetime.now(UTC)


def iso_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def integer(value: str, default: int = 0) -> int:
    value = (value or "").strip()
    if not value:
        return default
    return int(float(value))


def bounded_score(value: str) -> tuple[int, int]:
    value = (value or "").strip()
    if not value:
        return 0, 1
    score = integer(value)
    if not 0 <= score <= 100:
        raise ValueError(f"Score is outside 0..100: {score}")
    return score, 0


def parse_utc(value: str) -> datetime | None:
    value = (value or "").strip()
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as handle:
        temp_path = Path(handle.name)
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, path)


def apply_output_permissions(path: Path) -> None:
    """Keep atomically replaced ML-facing files readable by the reader group."""
    if not OUTPUT_GROUP:
        raise RuntimeError("STAGE_OUTPUT_GROUP cannot be empty")
    group_id = grp.getgrnam(OUTPUT_GROUP).gr_gid
    os.chown(path, -1, group_id)
    os.chmod(path, 0o640)


def build_feature(row: dict[str, str], generated_at: datetime) -> dict[str, Any]:
    address = str(ipaddress.ip_address(row["ip_address"].strip()))
    ip_version = ipaddress.ip_address(address).version
    if integer(row["ip_version"]) != ip_version:
        raise ValueError(f"IP version mismatch for {address}")

    abuse_match = integer(row["in_abuseipdb"])
    threatfox_match = integer(row["in_threatfox"])
    if abuse_match:
        abuse_score, abuse_score_missing = bounded_score(
            row["abuseipdb_confidence_score"]
        )
    else:
        abuse_score, abuse_score_missing = 0, 0
    if threatfox_match:
        threatfox_score, threatfox_score_missing = bounded_score(
            row["threatfox_max_confidence"]
        )
    else:
        threatfox_score, threatfox_score_missing = 0, 0
    threatfox_last_seen = parse_utc(row["threatfox_last_seen"])
    if threatfox_match and threatfox_last_seen is None:
        threatfox_age_days = -1
        threatfox_last_seen_missing = 1
    elif threatfox_last_seen is None:
        threatfox_age_days = -1
        threatfox_last_seen_missing = 0
    else:
        threatfox_age_days = max(
            0, int((generated_at - threatfox_last_seen).total_seconds() // 86400)
        )
        threatfox_last_seen_missing = 0

    record_count = integer(row["threatfox_record_count"])
    ports = {value for value in row["threatfox_ports"].split("|") if value}

    return {
        "ip_address": address,
        "ip_version": ip_version,
        "cti_match": 1,
        "cti_source_count": integer(row["source_count"]),
        "cti_seen_in_both": integer(row["seen_in_both"]),
        "cti_abuseipdb_match": abuse_match,
        "cti_abuseipdb_score": abuse_score,
        "cti_abuseipdb_score_norm": round(abuse_score / 100.0, 4),
        "cti_abuseipdb_score_missing": abuse_score_missing,
        "cti_threatfox_match": threatfox_match,
        "cti_threatfox_confidence": threatfox_score,
        "cti_threatfox_confidence_norm": round(threatfox_score / 100.0, 4),
        "cti_threatfox_confidence_missing": threatfox_score_missing,
        "cti_threatfox_record_count": record_count,
        "cti_threatfox_record_count_log1p": round(math.log1p(record_count), 6),
        "cti_threatfox_port_count": len(ports),
        "cti_threatfox_botnet_cc": integer(row["threatfox_botnet_cc"]),
        "cti_threatfox_payload_delivery": integer(
            row["threatfox_payload_delivery"]
        ),
        "cti_threatfox_is_compromised": integer(
            row["threatfox_is_compromised"]
        ),
        "cti_threatfox_last_seen_missing": threatfox_last_seen_missing,
        "cti_threatfox_age_days": threatfox_age_days,
        "feature_generated_at_utc": iso_utc(generated_at),
    }


def main() -> int:
    generated_at = utc_now()
    stamp = generated_at.strftime("%Y%m%dT%H%M%SZ")
    FEATURE_DIR.mkdir(parents=True, exist_ok=True)
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

    with INPUT_FILE.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = set(reader.fieldnames or [])
        missing_fields = sorted(REQUIRED_INPUT_FIELDS - fieldnames)
        if missing_fields:
            raise RuntimeError(
                "Input dataset is missing fields: " + ", ".join(missing_fields)
            )
        rows = list(reader)

    if not rows:
        raise RuntimeError("Input dataset contains no rows")

    features = [build_feature(row, generated_at) for row in rows]
    addresses = [row["ip_address"] for row in features]
    duplicate_count = len(addresses) - len(set(addresses))
    if duplicate_count:
        raise RuntimeError(f"Input contains {duplicate_count} duplicate IP rows")

    archive_file = ARCHIVE_DIR / f"cti_ip_reputation_features_{stamp}.csv"
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        newline="",
        dir=FEATURE_DIR,
        prefix=".features.",
        delete=False,
    ) as handle:
        temp_current = Path(handle.name)
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(features)
        handle.flush()
        os.fsync(handle.fileno())

    temp_archive = archive_file.with_suffix(".csv.part")
    shutil.copy2(temp_current, temp_archive)
    apply_output_permissions(temp_archive)
    apply_output_permissions(temp_current)
    os.replace(temp_archive, archive_file)
    os.replace(temp_current, CURRENT_FILE)
    apply_output_permissions(archive_file)
    apply_output_permissions(CURRENT_FILE)

    state = {
        "schema_version": 1,
        "status": "success",
        "generated_at_utc": iso_utc(generated_at),
        "input_file": str(INPUT_FILE),
        "current_feature_file": str(CURRENT_FILE),
        "archive_feature_file": str(archive_file),
        "rows": len(features),
        "columns": len(OUTPUT_FIELDS),
        "duplicate_ip_rows": duplicate_count,
        "feature_observations": {
            "abuseipdb_score_has_zero_variance": len(
                {row["cti_abuseipdb_score"] for row in features if row["cti_abuseipdb_match"]}
            )
            <= 1,
            "threatfox_last_seen_missing": sum(
                row["cti_threatfox_last_seen_missing"]
                for row in features
                if row["cti_threatfox_match"]
            ),
        },
    }
    atomic_json(STATE_FILE, state)

    print("ML feature lookup created successfully")
    print(f"Rows                 : {len(features)}")
    print(f"Columns              : {len(OUTPUT_FIELDS)}")
    print(f"Duplicate IP rows    : {duplicate_count}")
    print(f"Current feature file : {CURRENT_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
