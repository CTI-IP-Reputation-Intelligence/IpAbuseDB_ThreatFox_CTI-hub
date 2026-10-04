#!/usr/bin/env python3
"""Offline synthetic acceptance test for the organized CTI pipeline."""

from __future__ import annotations

import importlib.util
import grp
import ipaddress
import json
import os
import sys
import tempfile
import types
from datetime import UTC, datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

# IANA documentation-only TEST-NET addresses are generated from integer values.
# This avoids embedding any operational or routable IPv4 address literal.
TEST_IP_PRIMARY = str(ipaddress.ip_address(3221225994))
TEST_IP_SECONDARY = str(ipaddress.ip_address(3325256724))

try:
    import requests as _requests  # noqa: F401
except ModuleNotFoundError:
    requests_stub = types.ModuleType("requests")
    requests_stub.Session = object
    requests_stub.Response = object
    sys.modules["requests"] = requests_stub


def load(name: str, relative_path: str):
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def threatfox_line(values: list[str]) -> str:
    if len(values) != 15:
        raise AssertionError("Synthetic ThreatFox row must contain 15 fields")
    escaped = [value.replace('"', '""') for value in values]
    return ", ".join(f'"{value}"' for value in escaped)


def main() -> int:
    os.environ["THREATFOX_IOC_TO_IMPORT"] = "ip:port"
    os.environ["THREATFOX_IMPORT_OFFLINE"] = "true"
    collector = load("collector", "src/collector.py")
    feature_builder = load("build_features", "src/build_features.py")

    with tempfile.TemporaryDirectory(prefix="cti-organized-test-") as temp_name:
        temp = Path(temp_name)
        abuse_path = temp / "abuse.json"
        threatfox_path = temp / "threatfox.csv"
        abuse_path.write_text(
            json.dumps({"data": [
                {"ipAddress": TEST_IP_PRIMARY, "abuseConfidenceScore": 100,
                 "lastReportedAt": "2026-09-27T10:00:00+00:00",
                 "countryCode": "ZZ", "totalReports": 25},
                {"ipAddress": TEST_IP_SECONDARY, "abuseConfidenceScore": 100,
                 "lastReportedAt": "2026-09-27T11:00:00+00:00",
                 "countryCode": "ZZ", "totalReports": 10},
                {"ipAddress": "not-an-ip", "abuseConfidenceScore": 100},
            ]}),
            encoding="utf-8",
        )
        rows = [
            ["2026-09-26 10:00:00", "1001", f"{TEST_IP_PRIMARY}:443", "ip:port",
             "botnet_cc", "win.synthetic", "", "Synthetic malware",
             "2026-09-27 10:30:00", "75", "false", "synthetic",
             "c2,test", "", ""],
            ["2026-09-26 11:00:00", "1002", f"{TEST_IP_PRIMARY}:80", "ip:port",
             "payload_delivery", "win.synthetic", "", "Synthetic malware",
             "2026-09-27 11:30:00", "90", "true", "synthetic",
             "payload,test", "", ""],
            ["2026-09-26 12:00:00", "1003", "example.invalid", "domain",
             "botnet_cc", "win.synthetic", "", "Synthetic malware",
             "2026-09-27 12:30:00", "100", "false", "synthetic",
             "domain,test", "", ""],
        ]
        threatfox_path.write_text(
            "# synthetic fixture\n" + "\n".join(threatfox_line(row) for row in rows) + "\n",
            encoding="utf-8",
        )

        abuse = collector.parse_abuseipdb(abuse_path)
        threatfox, stats = collector.parse_threatfox(
            threatfox_path, datetime(2026, 9, 28, tzinfo=UTC)
        )
        merged = collector.build_rows(
            abuse, threatfox, datetime(2026, 9, 28, 12, 0, tzinfo=UTC)
        )
        assert sorted(abuse) == sorted([TEST_IP_PRIMARY, TEST_IP_SECONDARY])
        assert list(threatfox) == [TEST_IP_PRIMARY]
        assert threatfox[TEST_IP_PRIMARY]["ports"] == {"80", "443"}
        assert stats["accepted_rows"] == 2
        assert stats["non_ip_rows"] == 1
        assert len(merged) == len({row["ip_address"] for row in merged}) == 2

        overlap = next(row for row in merged if row["ip_address"] == TEST_IP_PRIMARY)
        assert overlap["source_count"] == 2
        assert overlap["seen_in_both"] == 1
        feature = feature_builder.build_feature(
            {key: str(value) for key, value in overlap.items()},
            datetime(2026, 9, 28, 12, 0, tzinfo=UTC),
        )
        assert feature["cti_source_count"] == 2
        assert feature["cti_abuseipdb_match"] == 1
        assert feature["cti_threatfox_match"] == 1
        assert feature["cti_threatfox_port_count"] == 2

        permission_file = temp / "published.csv"
        permission_file.write_text("header\n", encoding="utf-8")
        current_group = grp.getgrgid(os.getgid()).gr_name
        collector.OUTPUT_GROUP = current_group
        collector.apply_output_permissions(permission_file)
        assert permission_file.stat().st_mode & 0o777 == 0o640
        assert permission_file.stat().st_gid == os.getgid()

    print("Offline synthetic pipeline: PASS")
    print("AbuseIPDB valid unique IPs: 2")
    print("ThreatFox accepted rows: 2; unique IPs: 1")
    print("Merged unique IPs: 2; duplicate IP rows: 0")
    print("Feature generation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
