#!/usr/bin/env python3
"""Build a normalized IP-reputation staging dataset from AbuseIPDB and ThreatFox."""

from __future__ import annotations

import csv
import fcntl
import grp
import ipaddress
import json
import os
import shutil
import sys
import tempfile
import zipfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator, TextIO

import requests


DATA_ROOT = Path("/data/ddos-cti")
ABUSE_RAW_DIR = DATA_ROOT / "raw" / "abuseipdb"
THREATFOX_RAW_DIR = DATA_ROOT / "raw" / "threatfox"
EXPORT_DIR = DATA_ROOT / "exports"
ARCHIVE_DIR = EXPORT_DIR / "archive"
STATE_DIR = DATA_ROOT / "state"
CURRENT_OUTPUT = EXPORT_DIR / "cti_ip_reputation_current.csv"
STATE_FILE = STATE_DIR / "cti_ip_reputation_state.json"
ERROR_FILE = STATE_DIR / "cti_ip_reputation_last_error.json"
LOCK_FILE = STATE_DIR / "collector.lock"

ABUSEIPDB_URL = os.getenv(
    "ABUSEIPDB_API_URL", "https://api.abuseipdb.com/api/v2/blacklist"
)
MAX_DOWNLOAD_BYTES = int(os.getenv("STAGE_MAX_DOWNLOAD_BYTES", str(512 * 1024 * 1024)))
CONNECT_TIMEOUT = int(os.getenv("STAGE_CONNECT_TIMEOUT", "15"))
READ_TIMEOUT = int(os.getenv("STAGE_READ_TIMEOUT", "180"))
OUTPUT_GROUP = os.getenv("STAGE_OUTPUT_GROUP", "ddos-cti-readers").strip()

OUTPUT_FIELDS = [
    "ip_address",
    "ip_version",
    "source_count",
    "sources",
    "seen_in_both",
    "in_abuseipdb",
    "abuseipdb_confidence_score",
    "abuseipdb_last_reported_at",
    "abuseipdb_country_code",
    "abuseipdb_total_reports",
    "in_threatfox",
    "threatfox_record_count",
    "threatfox_ioc_ids",
    "threatfox_ports",
    "threatfox_threat_types",
    "threatfox_malware_families",
    "threatfox_tags",
    "threatfox_first_seen",
    "threatfox_last_seen",
    "threatfox_max_confidence",
    "threatfox_is_compromised",
    "threatfox_botnet_cc",
    "threatfox_payload_delivery",
    "merged_at_utc",
]


class CollectionError(RuntimeError):
    """Operator-facing provider failure with a stable diagnostic code."""

    def __init__(
        self,
        code: str,
        provider: str,
        message: str,
        *,
        retry_at: str = "",
    ) -> None:
        super().__init__(message)
        self.code = code
        self.provider = provider
        self.retry_at = retry_at


def utc_now() -> datetime:
    return datetime.now(UTC)


def iso_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def env_required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Required environment variable is missing: {name}")
    return value


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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


def download(
    session: requests.Session,
    url: str,
    directory: Path,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
    provider: str = "source",
) -> tuple[Path, requests.Response]:
    directory.mkdir(parents=True, exist_ok=True)
    try:
        response = session.get(
            url,
            headers=headers,
            params=params,
            stream=True,
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
        )
    except requests.exceptions.SSLError as exc:
        raise CollectionError(
            "TLS_FAILED", provider, f"{provider} TLS verification failed: {exc}"
        ) from exc
    except requests.exceptions.Timeout as exc:
        raise CollectionError(
            "CONNECTION_TIMEOUT", provider, f"{provider} request timed out: {exc}"
        ) from exc
    except requests.exceptions.ConnectionError as exc:
        raise CollectionError(
            "CONNECTION_FAILED",
            provider,
            f"{provider} connection failed; check DNS, proxy, firewall, and routing: {exc}",
        ) from exc

    if response.status_code in {401, 403}:
        response.close()
        raise CollectionError(
            "AUTH_REJECTED",
            provider,
            f"{provider} rejected the credential (HTTP {response.status_code}); rotate or replace it",
        )
    if response.status_code == 429:
        retry_at = response.headers.get("Retry-After", "")
        response.close()
        raise CollectionError(
            "RATE_LIMITED",
            provider,
            f"{provider} rate limit was reached (HTTP 429)",
            retry_at=retry_at,
        )
    if response.status_code == 404:
        response.close()
        raise CollectionError(
            "AUTH_OR_ENDPOINT_REJECTED",
            provider,
            f"{provider} returned HTTP 404; verify the protected URL, Auth-Key, and endpoint",
        )
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        status_code = response.status_code
        response.close()
        raise CollectionError(
            "HTTP_FAILED", provider, f"{provider} returned HTTP {status_code}"
        ) from exc

    declared_size = int(response.headers.get("Content-Length", "0") or "0")
    if declared_size > MAX_DOWNLOAD_BYTES:
        response.close()
        raise RuntimeError(
            f"Download rejected: declared size {declared_size} exceeds "
            f"limit {MAX_DOWNLOAD_BYTES}"
        )

    file_descriptor, name = tempfile.mkstemp(prefix=".download-", dir=directory)
    temp_path = Path(name)
    total = 0
    try:
        with os.fdopen(file_descriptor, "wb") as handle:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise RuntimeError(
                        f"Download exceeded safety limit of {MAX_DOWNLOAD_BYTES} bytes"
                    )
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        temp_path.unlink(missing_ok=True)
        response.close()
        raise

    if total == 0:
        temp_path.unlink(missing_ok=True)
        response.close()
        raise RuntimeError(f"Source returned an empty response: {url}")
    return temp_path, response


def parse_datetime(value: str) -> datetime | None:
    value = value.strip()
    if not value:
        return None
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            parsed = datetime.strptime(value, pattern)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed.astimezone(UTC)
        except ValueError:
            continue
    return None


def canonical_ip(value: str) -> tuple[str, str | None] | None:
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value)), None
    except ValueError:
        pass

    if value.startswith("[") and "]:" in value:
        host, port = value[1:].rsplit("]:", 1)
    else:
        host, separator, port = value.rpartition(":")
        if not separator:
            return None

    try:
        address = str(ipaddress.ip_address(host))
        port_number = int(port)
    except (ValueError, TypeError):
        return None
    if not 1 <= port_number <= 65535:
        return None
    return address, str(port_number)


def parse_abuseipdb(path: Path) -> dict[str, dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    data = payload.get("data")
    if not isinstance(data, list):
        raise RuntimeError("Unexpected AbuseIPDB response: data is not a list")

    records: dict[str, dict[str, Any]] = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        raw_ip = str(item.get("ipAddress", "")).strip()
        try:
            address = str(ipaddress.ip_address(raw_ip))
        except ValueError:
            continue
        records[address] = {
            "confidence": item.get("abuseConfidenceScore", ""),
            "last_reported": item.get("lastReportedAt", "") or "",
            "country_code": item.get("countryCode", "") or "",
            "total_reports": item.get("totalReports", "") or "",
        }
    return records


@contextmanager
def threatfox_csv_stream(path: Path) -> Iterator[TextIO]:
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            candidates = [name for name in archive.namelist() if name.lower().endswith(".csv")]
            if not candidates:
                raise RuntimeError("ThreatFox ZIP contains no CSV file")
            preferred = "full.csv" if "full.csv" in candidates else candidates[0]
            info = archive.getinfo(preferred)
            if info.file_size > MAX_DOWNLOAD_BYTES:
                raise RuntimeError("ThreatFox uncompressed CSV exceeds the safety limit")
            with archive.open(preferred) as binary_handle:
                import io

                with io.TextIOWrapper(
                    binary_handle, encoding="utf-8-sig", errors="replace", newline=""
                ) as text_handle:
                    yield text_handle
    else:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            yield handle


def new_threatfox_aggregate() -> dict[str, Any]:
    return {
        "record_count": 0,
        "ioc_ids": set(),
        "ports": set(),
        "threat_types": set(),
        "malware": set(),
        "tags": set(),
        "first_seen": None,
        "last_seen": None,
        "max_confidence": 0,
        "is_compromised": False,
    }


def parse_threatfox(
    path: Path, now: datetime
) -> tuple[dict[str, dict[str, Any]], dict[str, int]]:
    allowed = {
        value.strip().lower()
        for value in os.getenv("THREATFOX_IOC_TO_IMPORT", "ip:port").split(",")
        if value.strip()
    }
    allow_all = not allowed or "all_types" in allowed
    import_offline = env_bool("THREATFOX_IMPORT_OFFLINE", False)

    records: dict[str, dict[str, Any]] = {}
    statistics = {
        "csv_rows": 0,
        "invalid_rows": 0,
        "non_ip_rows": 0,
        "offline_rows_skipped": 0,
        "accepted_rows": 0,
    }

    with threatfox_csv_stream(path) as handle:
        reader = csv.reader(
            (line for line in handle if not line.startswith("#")),
            skipinitialspace=True,
        )
        for row in reader:
            statistics["csv_rows"] += 1
            if len(row) < 15:
                statistics["invalid_rows"] += 1
                continue

            ioc_type = row[3].strip().lower()
            if ioc_type != "ip:port" or (not allow_all and ioc_type not in allowed):
                statistics["non_ip_rows"] += 1
                continue

            parsed_ioc = canonical_ip(row[2])
            if parsed_ioc is None:
                statistics["invalid_rows"] += 1
                continue
            address, port = parsed_ioc

            first_seen = parse_datetime(row[0])
            last_seen = parse_datetime(row[8])
            is_active = last_seen is not None and last_seen >= now
            if not import_offline and not is_active:
                statistics["offline_rows_skipped"] += 1
                continue

            aggregate = records.setdefault(address, new_threatfox_aggregate())
            aggregate["record_count"] += 1
            if row[1].strip():
                aggregate["ioc_ids"].add(row[1].strip())
            if port:
                aggregate["ports"].add(port)
            if row[4].strip():
                aggregate["threat_types"].add(row[4].strip())
            for malware_value in (row[5], row[7]):
                malware_value = malware_value.strip()
                if malware_value and malware_value.lower() not in {"unknown", "unknown malware"}:
                    aggregate["malware"].add(malware_value)
            for tag in row[12].split(","):
                if tag.strip():
                    aggregate["tags"].add(tag.strip())
            if first_seen is not None and (
                aggregate["first_seen"] is None or first_seen < aggregate["first_seen"]
            ):
                aggregate["first_seen"] = first_seen
            if last_seen is not None and (
                aggregate["last_seen"] is None or last_seen > aggregate["last_seen"]
            ):
                aggregate["last_seen"] = last_seen
            try:
                aggregate["max_confidence"] = max(
                    aggregate["max_confidence"], int(row[9])
                )
            except ValueError:
                pass
            aggregate["is_compromised"] = aggregate["is_compromised"] or (
                row[10].strip().lower() == "true"
            )
            statistics["accepted_rows"] += 1
    return records, statistics


def joined(values: set[str]) -> str:
    return "|".join(sorted(values))


def build_rows(
    abuse_records: dict[str, dict[str, Any]],
    threatfox_records: dict[str, dict[str, Any]],
    completed_at: datetime,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    all_addresses = set(abuse_records) | set(threatfox_records)
    ordered_addresses = sorted(
        all_addresses,
        key=lambda value: (
            ipaddress.ip_address(value).version,
            int(ipaddress.ip_address(value)),
        ),
    )

    for address in ordered_addresses:
        abuse = abuse_records.get(address)
        threatfox = threatfox_records.get(address)
        source_names = []
        if abuse:
            source_names.append("AbuseIPDB")
        if threatfox:
            source_names.append("ThreatFox")
        threat_types = threatfox["threat_types"] if threatfox else set()

        rows.append(
            {
                "ip_address": address,
                "ip_version": ipaddress.ip_address(address).version,
                "source_count": len(source_names),
                "sources": "|".join(source_names),
                "seen_in_both": int(len(source_names) == 2),
                "in_abuseipdb": int(abuse is not None),
                "abuseipdb_confidence_score": abuse["confidence"] if abuse else "",
                "abuseipdb_last_reported_at": abuse["last_reported"] if abuse else "",
                "abuseipdb_country_code": abuse["country_code"] if abuse else "",
                "abuseipdb_total_reports": abuse["total_reports"] if abuse else "",
                "in_threatfox": int(threatfox is not None),
                "threatfox_record_count": threatfox["record_count"] if threatfox else 0,
                "threatfox_ioc_ids": joined(threatfox["ioc_ids"]) if threatfox else "",
                "threatfox_ports": joined(threatfox["ports"]) if threatfox else "",
                "threatfox_threat_types": joined(threat_types) if threatfox else "",
                "threatfox_malware_families": joined(threatfox["malware"])
                if threatfox
                else "",
                "threatfox_tags": joined(threatfox["tags"]) if threatfox else "",
                "threatfox_first_seen": iso_utc(threatfox["first_seen"])
                if threatfox and threatfox["first_seen"]
                else "",
                "threatfox_last_seen": iso_utc(threatfox["last_seen"])
                if threatfox and threatfox["last_seen"]
                else "",
                "threatfox_max_confidence": threatfox["max_confidence"]
                if threatfox
                else "",
                "threatfox_is_compromised": int(threatfox["is_compromised"])
                if threatfox
                else 0,
                "threatfox_botnet_cc": int("botnet_cc" in threat_types),
                "threatfox_payload_delivery": int("payload_delivery" in threat_types),
                "merged_at_utc": iso_utc(completed_at),
            }
        )
    return rows


def write_outputs(rows: list[dict[str, Any]], stamp: str) -> Path:
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    archive_path = ARCHIVE_DIR / f"cti_ip_reputation_{stamp}.csv"

    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="", dir=EXPORT_DIR, prefix=".current.", delete=False
    ) as handle:
        temp_current = Path(handle.name)
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
        handle.flush()
        os.fsync(handle.fileno())

    temp_archive = archive_path.with_suffix(".csv.part")
    shutil.copy2(temp_current, temp_archive)
    apply_output_permissions(temp_archive)
    apply_output_permissions(temp_current)
    os.replace(temp_archive, archive_path)
    os.replace(temp_current, CURRENT_OUTPUT)
    apply_output_permissions(archive_path)
    apply_output_permissions(CURRENT_OUTPUT)
    return archive_path


def run() -> None:
    started_at = utc_now()
    stamp = started_at.strftime("%Y%m%dT%H%M%SZ")
    api_key = env_required("ABUSEIPDB_API_KEY")
    threatfox_url = env_required("THREATFOX_CSV_URL")
    score = os.getenv("ABUSEIPDB_SCORE", "75").strip() or "75"
    limit = os.getenv("ABUSEIPDB_LIMIT", "10000").strip() or "10000"
    ip_version = os.getenv("ABUSEIPDB_IPVERSION", "mixed").strip().lower()

    abuse_params = {"confidenceMinimum": score, "limit": limit}
    if ip_version in {"4", "6"}:
        abuse_params["ipVersion"] = ip_version

    session = requests.Session()
    session.headers.update({"User-Agent": "ddos-cti-stage/1.0"})

    abuse_temp: Path | None = None
    threatfox_temp: Path | None = None
    abuse_raw: Path | None = None
    threatfox_raw: Path | None = None
    try:
        abuse_temp, abuse_response = download(
            session,
            ABUSEIPDB_URL,
            ABUSE_RAW_DIR,
            headers={"Key": api_key, "Accept": "application/json"},
            params=abuse_params,
            provider="AbuseIPDB",
        )
        abuse_records = parse_abuseipdb(abuse_temp)
        abuse_raw = ABUSE_RAW_DIR / f"abuseipdb_{stamp}.json"
        os.replace(abuse_temp, abuse_raw)
        abuse_temp = None

        rate_limit = {
            "limit": abuse_response.headers.get("X-RateLimit-Limit", ""),
            "remaining": abuse_response.headers.get("X-RateLimit-Remaining", ""),
            "reset": abuse_response.headers.get("X-RateLimit-Reset", ""),
        }
        abuse_response.close()

        threatfox_temp, threatfox_response = download(
            session, threatfox_url, THREATFOX_RAW_DIR, provider="ThreatFox"
        )
        threatfox_is_zip = zipfile.is_zipfile(threatfox_temp)
        threatfox_records, threatfox_statistics = parse_threatfox(
            threatfox_temp, utc_now()
        )
        threatfox_extension = ".zip" if threatfox_is_zip else ".csv"
        threatfox_raw = THREATFOX_RAW_DIR / f"threatfox_{stamp}{threatfox_extension}"
        os.replace(threatfox_temp, threatfox_raw)
        threatfox_temp = None
        threatfox_response.close()

        completed_at = utc_now()
        rows = build_rows(abuse_records, threatfox_records, completed_at)
        archive_path = write_outputs(rows, stamp)
        seen_in_both = sum(int(row["seen_in_both"]) for row in rows)

        state = {
            "schema_version": 1,
            "status": "success",
            "run_started_at_utc": iso_utc(started_at),
            "run_completed_at_utc": iso_utc(completed_at),
            "source_counts": {
                "abuseipdb_unique_ips": len(abuse_records),
                "threatfox_unique_ips": len(threatfox_records),
                **threatfox_statistics,
            },
            "merged_unique_ips": len(rows),
            "seen_in_both": seen_in_both,
            "filters": {
                "abuseipdb_score": score,
                "abuseipdb_limit": limit,
                "abuseipdb_ipversion": ip_version,
                "threatfox_ioc_to_import": os.getenv("THREATFOX_IOC_TO_IMPORT", ""),
                "threatfox_import_offline": env_bool("THREATFOX_IMPORT_OFFLINE", False),
            },
            "abuseipdb_rate_limit": rate_limit,
            "raw_files": {
                "abuseipdb": str(abuse_raw),
                "threatfox": str(threatfox_raw),
            },
            "outputs": {
                "current": str(CURRENT_OUTPUT),
                "archive": str(archive_path),
            },
        }
        atomic_json(STATE_FILE, state)
        ERROR_FILE.unlink(missing_ok=True)

        print("Collection completed successfully")
        print(f"AbuseIPDB unique IPs : {len(abuse_records)}")
        print(f"ThreatFox unique IPs : {len(threatfox_records)}")
        print(f"Merged unique IPs    : {len(rows)}")
        print(f"Seen in both sources : {seen_in_both}")
        print(f"Current output       : {CURRENT_OUTPUT}")
    finally:
        session.close()
        if abuse_temp is not None:
            abuse_temp.unlink(missing_ok=True)
        if threatfox_temp is not None:
            threatfox_temp.unlink(missing_ok=True)


def main() -> int:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with LOCK_FILE.open("w", encoding="utf-8") as lock_handle:
        try:
            fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("ERROR: another collector run is already active", file=sys.stderr)
            return 2
        try:
            run()
            return 0
        except Exception as exc:
            code = exc.code if isinstance(exc, CollectionError) else "RUNTIME_ERROR"
            provider = exc.provider if isinstance(exc, CollectionError) else "collector"
            retry_at = exc.retry_at if isinstance(exc, CollectionError) else ""
            last_successful_run = ""
            if STATE_FILE.exists():
                try:
                    with STATE_FILE.open("r", encoding="utf-8") as handle:
                        last_successful_run = json.load(handle).get(
                            "run_completed_at_utc", ""
                        )
                except (OSError, ValueError, TypeError):
                    pass
            atomic_json(
                ERROR_FILE,
                {
                    "status": "failed",
                    "failed_at_utc": iso_utc(utc_now()),
                    "diagnostic_code": code,
                    "provider": provider,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "retry_at": retry_at,
                    "last_successful_run_utc": last_successful_run,
                },
            )
            print(f"ERROR [{code}] [{provider}]: {exc}", file=sys.stderr)
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
